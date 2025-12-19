import time
import logging
from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, Set, List, Optional

from .client import CTClient
from .state import StateManager
from .analysis import DomainAnalyzer
from .reporting import ReportGenerator
from .cert_parser import parse_leaf_input, extract_certificate_info

class CTMonitor:
    def __init__(self, config: Dict):
        self.config = config
        self.output_dir = config.get('output_dir', '.')
        self.log = logging.getLogger(__name__)
        
        # Initialize components
        self.client = CTClient(config['request_timeout'], config['fetch_batch_size'])
        self.state_manager = StateManager(config['state_file'])
        self.analyzer = DomainAnalyzer(config, self.output_dir)
        self.reporter = ReportGenerator(config, self.output_dir)

    def _parse_and_extract_worker(self, entry_data: tuple) -> List[Dict]:
        """Worker function to parse a single entry and extract domains."""
        entry, entry_index, log_url = entry_data
        leaf_input = entry.get('leaf_input')
        if leaf_input:
            cert = parse_leaf_input(leaf_input, entry_index, log_url)
            if cert:
                return extract_certificate_info(cert)
        return []

    def check_log(self, log_url: str, last_known_size: int) -> tuple:
        """Checks a single log for new entries and returns found domains."""
        new_domains_for_log = set()
        suspicious_events = []
        updated_size = last_known_size
        
        self.log.info(f"Checking log: {log_url}")
        sth = self.client.get_sth(log_url)
        if not sth:
            return new_domains_for_log, suspicious_events, updated_size

        current_tree_size = sth.get('tree_size', 0)
        self.log.info(f"  Log: {log_url} - Current size: {current_tree_size}, Last known: {last_known_size}")

        if current_tree_size > last_known_size:
            new_entry_count = current_tree_size - last_known_size
            self.log.info(f"  Log: {log_url} - Found {new_entry_count} new entries.")
            if new_entry_count > self.config.get('fetch_batch_size', 256) * 10: # If it's a large catch-up
                self.log.info(f"  This may take some time as the monitor is catching up on a large number of entries.")
            
            start_index = max(0, last_known_size)
            end_index = current_tree_size - 1

            entries = self.client.get_entries(log_url, start_index, end_index)

            if entries is not None:
                self.log.info(f"  Log: {log_url} - Parallel processing of {len(entries)} fetched entries...")
                
                total_entries = len(entries)
                processed_count = 0
                log_interval = max(1, total_entries // 10) if total_entries > 0 else 1

                with ThreadPoolExecutor(max_workers=self.config['max_workers']) as executor:
                    tasks = {
                        executor.submit(self._parse_and_extract_worker, (entry, start_index + i, log_url)): i
                        for i, entry in enumerate(entries)
                    }

                    for future in as_completed(tasks):
                        processed_count += 1
                        try:
                            cert_infos = future.result()
                            for info in cert_infos:
                                domain = info['domain']
                                new_domains_for_log.add(domain)
                                if self.analyzer.is_suspicious(domain):
                                    suspicious_events.append(info)
                        except Exception as e:
                            self.log.warning(f"Error processing an entry from {log_url}: {e}")

                        if processed_count % log_interval == 0 or processed_count == total_entries:
                            self.log.info(f"  Log: {log_url} - Processed {processed_count}/{total_entries} entries...")
                
                self.log.info(f"  Log: {log_url} - Finished processing. Found {len(new_domains_for_log)} new unique domains from this log.")
                updated_size = current_tree_size
            else:
                self.log.error(f"  Log: {log_url} - Failed to fetch new entries {start_index}-{end_index}")
        else:
            self.log.info(f"  Log: {log_url} - No new entries.")
            updated_size = current_tree_size

        return new_domains_for_log, suspicious_events, updated_size

    def run_once(self) -> int:
        """Run a single monitoring cycle."""
        log_states = self.state_manager.load_state()
        log_urls = self.config['log_urls']
        max_workers = self.config['max_workers']
        skip_catchup = self.config.get('skip_catchup', False)
        
        # Initialize state for new logs
        for url in log_urls:
            if skip_catchup or url not in log_states:
                if skip_catchup:
                     self.log.info(f"Skip catchup requested. Fast-forwarding {url} to current head.")
                else:
                     self.log.info(f"Initializing state for new log: {url}")

                sth_init = self.client.get_sth(url)
                if sth_init:
                    current_size = sth_init.get('tree_size', 0)
                    # Only update if we are skipping catchup OR it's a new log
                    if skip_catchup or url not in log_states:
                        log_states[url] = current_size
                        self.log.info(f"  Set initial size for {url}: {log_states[url]}")
                else:
                    if url not in log_states:
                        log_states[url] = 0
                        self.log.warning(f"  Failed to get initial state for {url}, starting from 0.")
                time.sleep(0.2)
        
        # Disable skip_catchup for subsequent loops if running continuously
        if skip_catchup:
             self.config['skip_catchup'] = False

        self.log.info("--- Polling Cycle Start ---")
        all_new_domains = set()
        all_suspicious_events = []

        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            tasks = {}
            
            # Submit tasks to check each log
            for url in log_urls:
                last_size = log_states.get(url, 0)
                future = executor.submit(self.check_log, url, last_size)
                tasks[future] = url

            # Process completed tasks
            for future in as_completed(tasks):
                url = tasks[future]
                try:
                    domains, suspicious, new_size = future.result()
                    all_new_domains.update(domains)
                    
                    # Print suspicious findings immediately
                    for item in suspicious:
                        print(f"\n[!] SUSPICIOUS CERTIFICATE DETECTED")
                        print(f"    Domain:    {item['domain']}")
                        print(f"    Issuer:    {item['issuer']}")
                        print(f"    Validity:  {item['not_before']} - {item['not_after']}")
                        print(f"    Log URL:   {url}")
                        print("-" * 50)
                        
                        # Add log URL to the event for JSON output
                        item['log_url'] = url
                        all_suspicious_events.append(item)

                    log_states[url] = new_size
                except Exception as exc:
                    self.log.error(f"Log {url} generated an exception: {exc}")
                    log_states[url] = log_states.get(url, 0)

        if all_new_domains:
            timestamp = datetime.now(timezone.utc).isoformat()
            self.log.info(f">>> Domains found in this cycle: {len(all_new_domains)}")
            
            if self.config.get('ai_mode'):
                max_domains = self.config.get('max_domains_for_ai', 2500)
                domains_to_analyze = list(all_new_domains)[:max_domains]
                if len(all_new_domains) > max_domains:
                    self.log.warning(f"Analyzing a sample of {max_domains} out of {len(all_new_domains)} domains due to AI mode limit.")
                self.analyzer.analyze_domains_for_phishing(set(domains_to_analyze))
            else:
                self.reporter.save_domains(all_new_domains, timestamp, all_suspicious_events)

        # Save updated state
        self.state_manager.save_state(log_states)
        self.log.info("--- Polling Cycle End ---")
        
        return len(all_new_domains)

    def run_continuous(self):
        """Run continuous monitoring."""
        poll_interval = self.config['poll_interval_seconds']
        self.log.info("Starting continuous monitoring...")
        
        try:
            while True:
                domain_count = self.run_once()
                self.log.info(f"Sleeping for {poll_interval} seconds...")
                time.sleep(poll_interval)
                
        except KeyboardInterrupt:
            self.log.info("Monitoring stopped by user.")
        except Exception as e:
            self.log.error(f"An unexpected error occurred: {e}", exc_info=True)
        finally:
            self.log.info("Monitoring script finished.")