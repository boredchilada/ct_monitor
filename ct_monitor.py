#!/usr/bin/env python3
"""
Certificate Transparency Log Monitor
====================================

A standalone tool for monitoring Certificate Transparency logs and extracting newly issued domains.

Features:
- Monitors multiple CT logs simultaneously
- Extracts domains from X.509 certificates
- Supports various output formats (JSON, CSV, text)
- Configurable polling intervals and batch sizes
- State persistence to avoid reprocessing entries
- Comprehensive logging and error handling

Author: boredchilada/pigondrugs
License: MIT
"""

import requests
import time
import base64
from cryptography import x509
from cryptography.x509.oid import ExtensionOID
import math
import json
import os
import logging
import argparse
import csv
import sys
from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Set, Dict, List, Optional
from urllib.parse import urlparse
import re
from dotenv import load_dotenv
from langchain.prompts import PromptTemplate
from langchain_google_genai import ChatGoogleGenerativeAI
from langchain_openai import ChatOpenAI

# Version information
__version__ = "1.1.0"

# Default CT Log URLs - comprehensive list of active logs
DEFAULT_LOG_URLS = [
    "https://ct.googleapis.com/logs/us1/argon2025h1/",
    "https://ct.googleapis.com/logs/us1/argon2025h2/",
    "https://ct.googleapis.com/logs/us1/argon2026h1/",
    "https://ct.googleapis.com/logs/us1/argon2026h2/",
    "https://ct.googleapis.com/logs/eu1/xenon2025h1/",
    "https://ct.googleapis.com/logs/eu1/xenon2025h2/",
    "https://ct.googleapis.com/logs/eu1/xenon2026h1/",
    "https://ct.googleapis.com/logs/eu1/xenon2026h2/",
    "https://ct.cloudflare.com/logs/nimbus2025/",
    "https://ct.cloudflare.com/logs/nimbus2026/",
    "https://yeti2025.ct.digicert.com/log/",
    "https://wyvern.ct.digicert.com/2025h2/",
    "https://wyvern.ct.digicert.com/2026h1/",
    "https://wyvern.ct.digicert.com/2026h2/",
    "https://sphinx.ct.digicert.com/2025h2/",
    "https://sphinx.ct.digicert.com/2026h1/",
    "https://sphinx.ct.digicert.com/2026h2/",
    "https://sabre2025h1.ct.sectigo.com/",
    "https://sabre2025h2.ct.sectigo.com/",
    "https://mammoth2025h1.ct.sectigo.com/",
    "https://mammoth2025h2.ct.sectigo.com/",
    "https://mammoth2026h1.ct.sectigo.com/",
    "https://mammoth2026h2.ct.sectigo.com/",
    "https://sabre2026h1.ct.sectigo.com/",
    "https://sabre2026h2.ct.sectigo.com/",
    "https://oak.ct.letsencrypt.org/2025h1/",
    "https://oak.ct.letsencrypt.org/2025h2/",
    "https://oak.ct.letsencrypt.org/2026h1/",
    "https://oak.ct.letsencrypt.org/2026h2/",
    "https://ct2025-a.trustasia.com/log2025a/",
    "https://ct2025-b.trustasia.com/log2025b/",
    "https://ct2026-a.trustasia.com/log2026a/",
    "https://ct2026-b.trustasia.com/log2026b/",
]

# Default configuration
DEFAULT_CONFIG = {
    "state_file": "ct_monitor_state.json",
    "poll_interval_seconds": 60,
    "max_workers": 10,
    "request_timeout": 20,
    "fetch_batch_size": 256,
    "output_format": "json",
    "output_file": "ct_domains.json",
    "log_level": "INFO",
    "log_urls": DEFAULT_LOG_URLS,
    "ai_provider": "google",
    "ai_model": "gemini-2.5-flash",
    "max_domains_for_ai": 1000,
    "ai_batch_size": 100,
    "monitored_keywords": ["paypal", "google", "apple", "microsoft", "bank", "login", "secure", "update", "verify"]
}


# CT Log Entry Structure Offsets (RFC 6962)
LEAF_TYPE_OFFSET = slice(10, 12)
CERT_LENGTH_OFFSET = slice(12, 15)
CERT_START_OFFSET = 15

class CTMonitor:
    def __init__(self, config: Dict):
        self.config = config
        self.output_dir = config.get('output_dir', '.')
        self.setup_logging()
        self.log = logging.getLogger(__name__)
        
    def setup_logging(self):
        """Setup logging configuration."""
        log_level = getattr(logging, self.config.get('log_level', 'INFO').upper())
        logging.basicConfig(
            level=log_level,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.StreamHandler(sys.stdout),
                logging.FileHandler('ct_monitor.log')
            ]
        )

    def normalize_url(self, url: str) -> Optional[str]:
        """Simple URL normalization for domain validation."""
        try:
            if not url.startswith(('http://', 'https://')):
                url = f"http://{url}"
            parsed = urlparse(url)
            if parsed.netloc:
                return url.lower()
            return None
        except Exception:
            return None

    def is_valid_domain(self, domain: str) -> bool:
        """Basic domain validation."""
        if not domain or len(domain) > 253:
            return False
        
        # Basic regex for domain validation
        domain_pattern = re.compile(
            r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$'
        )
        return bool(domain_pattern.match(domain))

    def load_state(self) -> Dict:
        """Loads the last known tree size for each log from a file."""
        state_file = self.config['state_file']
        if os.path.exists(state_file):
            try:
                with open(state_file, 'r') as f:
                    return json.load(f)
            except (json.JSONDecodeError, IOError) as e:
                self.log.error(f"Error loading state file {state_file}: {e}")
                return {}
        return {}

    def save_state(self, state: Dict):
        """Saves the current tree sizes to a file atomically."""
        state_file = self.config['state_file']
        temp_file = f"{state_file}.tmp"
        try:
            with open(temp_file, 'w') as f:
                json.dump(state, f, indent=4)
            os.replace(temp_file, state_file)
        except IOError as e:
            self.log.error(f"Error saving state file {state_file}: {e}")

    def get_sth(self, log_url: str) -> Optional[Dict]:
        """Fetches the Signed Tree Head (STH) for a given log."""
        try:
            timeout = self.config['request_timeout']
            response = requests.get(f"{log_url}ct/v1/get-sth", timeout=timeout)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            self.log.warning(f"Error getting STH from {log_url}: {e}")
            return None

    def get_entries(self, log_url: str, start: int, end: int) -> Optional[List]:
        """Fetches log entries in batches."""
        all_entries = []
        current_start = start
        batch_size = self.config['fetch_batch_size']
        timeout = self.config['request_timeout']
        fetch_url = None
        
        try:
            while current_start <= end:
                current_end = min(current_start + batch_size - 1, end)
                fetch_url = f"{log_url}ct/v1/get-entries?start={current_start}&end={current_end}"
                response = requests.get(fetch_url, timeout=timeout * 2)
                response.raise_for_status()
                data = response.json()
                entries_batch = data.get('entries', [])
                
                if not entries_batch:
                    self.log.warning(f"Received empty batch for {current_start}-{current_end} from {log_url}")
                    break
                    
                all_entries.extend(entries_batch)
                current_start += len(entries_batch)
                
            return all_entries
        except requests.exceptions.RequestException as e:
            self.log.error(f"Error getting entries {current_start}-{end} from {log_url}: {e}")
            return None
        except json.JSONDecodeError as e:
            self.log.error(f"Error decoding JSON from {fetch_url or log_url}: {e}")
            return None

    def parse_leaf_input(self, leaf_input_b64: str, entry_index: int, log_url: str) -> Optional[x509.Certificate]:
        """Parses the leaf input to extract an X.509 certificate."""
        try:
            decoded_leaf = base64.b64decode(leaf_input_b64)
            entry_type = int.from_bytes(decoded_leaf[LEAF_TYPE_OFFSET], byteorder='big')

            if entry_type == 0:  # x509_entry
                cert_length = int.from_bytes(decoded_leaf[CERT_LENGTH_OFFSET], byteorder='big')
                cert_end_offset = CERT_START_OFFSET + cert_length

                if cert_length <= 0 or cert_end_offset > len(decoded_leaf):
                    self.log.warning(f"Invalid cert length ({cert_length}) in entry {entry_index} from {log_url}")
                    return None

                cert_bytes = decoded_leaf[CERT_START_OFFSET:cert_end_offset]
                cert = x509.load_der_x509_certificate(cert_bytes)
                return cert
            else:
                return None

        except Exception as e:
            self.log.warning(f"Error parsing certificate for entry {entry_index} from {log_url}: {e}")
            return None

    def extract_certificate_info(self, cert: x509.Certificate) -> List[Dict]:
        """Extracts domains and metadata from certificate."""
        results = []
        if cert is None:
            return results

        domains = set()
        
        # Extract Issuer
        issuer = "Unknown"
        try:
            # Try to get CN of issuer
            issuer_cn = cert.issuer.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
            if issuer_cn:
                issuer = issuer_cn[0].value
            else:
                # Fallback to string representation
                issuer = cert.issuer.rfc4514_string()
        except Exception:
            pass

        # Extract Subject CN
        try:
            common_names = cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
            if common_names:
                cn_value = common_names[0].value
                if isinstance(cn_value, str) and '.' in cn_value:
                    cleaned_cn = cn_value.lower().strip(' *.')
                    if cleaned_cn and self.is_valid_domain(cleaned_cn):
                        domains.add(cleaned_cn)
        except Exception as e:
            self.log.debug(f"Error getting Subject CN: {e}")

        # Extract Subject Alternative Names (SANs)
        try:
            san_extension = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
            sans = san_extension.value.get_values_for_type(x509.DNSName) # type: ignore
            for domain in sans:
                cleaned_domain = domain.lower().strip(' *.')
                if cleaned_domain and self.is_valid_domain(cleaned_domain):
                    domains.add(cleaned_domain)
        except x509.ExtensionNotFound:
            pass
        except Exception as e:
            self.log.debug(f"Error processing SAN extension: {e}")

        for domain in domains:
            results.append({
                'domain': domain,
                'issuer': issuer,
                'not_before': cert.not_valid_before,
                'not_after': cert.not_valid_after
            })

        return results

    def is_suspicious(self, domain: str) -> bool:
        """Checks if a domain contains any monitored keywords."""
        keywords = self.config.get('monitored_keywords', [])
        if not keywords:
            return False
        return any(keyword in domain for keyword in keywords)

    def _parse_and_extract_worker(self, entry_data: tuple) -> List[Dict]:
        """Worker function to parse a single entry and extract domains."""
        entry, entry_index, log_url = entry_data
        leaf_input = entry.get('leaf_input')
        if leaf_input:
            cert = self.parse_leaf_input(leaf_input, entry_index, log_url)
            if cert:
                return self.extract_certificate_info(cert)
        return []

    def check_log(self, log_url: str, last_known_size: int) -> tuple:
        """Checks a single log for new entries and returns found domains."""
        new_domains_for_log = set()
        suspicious_events = []
        updated_size = last_known_size
        
        self.log.info(f"Checking log: {log_url}")
        sth = self.get_sth(log_url)
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

            entries = self.get_entries(log_url, start_index, end_index)

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
                                if self.is_suspicious(domain):
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

    def save_domains(self, domains: Set[str], timestamp: str, suspicious_events: Optional[List[Dict]] = None):
        """Save discovered domains to output file."""
        if not domains:
            return

        output_format = self.config['output_format'].lower()
        output_file = os.path.join(self.output_dir, self.config['output_file'])
        
        if output_format == 'json':
            self.save_domains_json(domains, timestamp, output_file, suspicious_events)
        elif output_format == 'csv':
            self.save_domains_csv(domains, timestamp, output_file)
        elif output_format == 'txt':
            self.save_domains_txt(domains, timestamp, output_file)
        else:
            self.log.error(f"Unknown output format: {output_format}")

    def save_domains_json(self, domains: Set[str], timestamp: str, output_file: str, suspicious_events: Optional[List[Dict]] = None):
        """Save domains in JSON format."""
        data = {
            'timestamp': timestamp,
            'domain_count': len(domains),
            'domains': sorted(list(domains))
        }
        
        if suspicious_events:
            # Convert datetime objects to strings for JSON serialization
            serializable_events = []
            for event in suspicious_events:
                event_copy = event.copy()
                if isinstance(event_copy.get('not_before'), datetime):
                    event_copy['not_before'] = event_copy['not_before'].isoformat()
                if isinstance(event_copy.get('not_after'), datetime):
                    event_copy['not_after'] = event_copy['not_after'].isoformat()
                serializable_events.append(event_copy)
            data['suspicious'] = serializable_events
        
        # Append to existing file or create new
        existing_data = []
        if os.path.exists(output_file):
            try:
                with open(output_file, 'r') as f:
                    existing_data = json.load(f)
                    if not isinstance(existing_data, list):
                        existing_data = [existing_data]
            except (json.JSONDecodeError, IOError):
                existing_data = []
        
        existing_data.append(data)
        
        try:
            with open(output_file, 'w') as f:
                json.dump(existing_data, f, indent=2)
            self.log.info(f"Saved {len(domains)} domains to {output_file}")
        except IOError as e:
            self.log.error(f"Error saving domains to {output_file}: {e}")

    def save_domains_csv(self, domains: Set[str], timestamp: str, output_file: str):
        """Save domains in CSV format."""
        file_exists = os.path.exists(output_file)
        
        try:
            with open(output_file, 'a', newline='') as f:
                writer = csv.writer(f)
                if not file_exists:
                    writer.writerow(['timestamp', 'domain'])
                
                for domain in sorted(domains):
                    writer.writerow([timestamp, domain])
            
            self.log.info(f"Saved {len(domains)} domains to {output_file}")
        except IOError as e:
            self.log.error(f"Error saving domains to {output_file}: {e}")

    def save_domains_txt(self, domains: Set[str], timestamp: str, output_file: str):
        """Save domains in plain text format."""
        try:
            with open(output_file, 'a') as f:
                f.write(f"\n# Domains discovered at {timestamp}\n")
                for domain in sorted(domains):
                    f.write(f"{domain}\n")
            
            self.log.info(f"Saved {len(domains)} domains to {output_file}")
        except IOError as e:
            self.log.error(f"Error saving domains to {output_file}: {e}")

    def analyze_domains_for_phishing(self, domains: Set[str]):
        """Analyzes a list of domains for potential phishing threats using an LLM."""
        self.log.info("--- AI Phishing Analysis Start ---")

        ai_provider = self.config.get("ai_provider", "google").lower()
        model_name = self.config.get("ai_model")
        batch_size = self.config.get("ai_batch_size", 100)
        
        llm = None

        if ai_provider == "google":
            if not model_name:
                model_name = "gemini-2.5-flash"
            
            api_key_name = "GOOGLE_API_KEY"
            if not os.getenv(api_key_name):
                self.log.error(f"{api_key_name} not found in environment or .env file.")
                return

            try:
                llm = ChatGoogleGenerativeAI(model=model_name)
            except Exception as e:
                self.log.error(f"Error initializing Google LLM: {e}")
                return

        elif ai_provider == "openrouter":
            if not model_name:
                model_name = "google/gemini-2.0-flash-001" # Default OpenRouter model
            
            api_key_name = "OPENROUTER_API_KEY"
            if not os.getenv(api_key_name):
                self.log.error(f"{api_key_name} not found in environment or .env file.")
                return

            try:
                llm = ChatOpenAI(
                    model=model_name,
                    api_key=os.getenv(api_key_name),
                    base_url="https://openrouter.ai/api/v1",
                    default_headers={
                        "HTTP-Referer": "https://github.com/boredchilada/CT_Monitor",
                        "X-Title": "CT Monitor"
                    }
                )
            except Exception as e:
                self.log.error(f"Error initializing OpenRouter LLM: {e}")
                return
        else:
            self.log.error(f"Unknown AI provider: {ai_provider}")
            return

        # Users can customize this prompt for better results.
        # For example, adding more context about common phishing patterns,
        # or providing few-shot examples of malicious and benign domains.
        prompt_template = PromptTemplate.from_template(
            """
            You are a cybersecurity analyst specializing in phishing detection.
            Analyze the following list of newly registered domain names.
            Identify any domains that are likely intended for phishing attacks.
            Consider factors like brand impersonation, urgent keywords, and unusual TLDs.

            Respond with two lists in the following format, and nothing else:
            SUSPICIOUS:
            - domain1: reason
            - domain2: reason
            SAFE:
            - domain3
            - domain4

            If a list is empty, just leave it blank after the heading.

            Domain list:
            {domains}
            """
        )
        chain = prompt_template | llm
        
        sorted_domains = sorted(list(domains))
        all_suspicious_results = []
        all_safe_domains = set()

        for i in range(0, len(sorted_domains), batch_size):
            batch = sorted_domains[i:i + batch_size]
            domain_list_str = "\n".join(batch)
            
            self.log.info(f"Analyzing batch {i//batch_size + 1}/{(len(sorted_domains) + batch_size - 1)//batch_size}...")
            
            try:
                response = chain.invoke({"domains": domain_list_str})
                analysis_result = str(response.content).strip()
                
                suspicious_part = ""
                safe_part = ""

                if "SUSPICIOUS:" in analysis_result and "SAFE:" in analysis_result:
                    suspicious_part = analysis_result.split("SUSPICIOUS:")[1].split("SAFE:")[0].strip()
                    safe_part = analysis_result.split("SAFE:")[1].strip()
                elif "SUSPICIOUS:" in analysis_result:
                    suspicious_part = analysis_result.split("SUSPICIOUS:")[1].strip()
                elif "SAFE:" in analysis_result:
                    safe_part = analysis_result.split("SAFE:")[1].strip()

                if suspicious_part:
                    suspicious_lines = [line.strip() for line in suspicious_part.split('\n') if line.strip() and line.strip().startswith('-')]
                    all_suspicious_results.extend(suspicious_lines)
                
                if safe_part:
                    safe_lines = [line.strip().lstrip('- ').strip() for line in safe_part.split('\n') if line.strip() and line.strip().startswith('-')]
                    all_safe_domains.update(safe_lines)

            except Exception as e:
                self.log.error(f"Error analyzing batch: {e}")

        # Save suspicious domains
        output_file_suspicious = os.path.join(self.output_dir, "phishing_analysis.txt")
        try:
            with open(output_file_suspicious, 'a', encoding='utf-8') as f:
                f.write(f"\n\n--- Analysis Results from {datetime.now(timezone.utc).isoformat()} ---\n")
                if all_suspicious_results:
                    for result in all_suspicious_results:
                        f.write(result + "\n")
                else:
                    f.write("No suspicious domains found in any batch.\n")
            self.log.info(f"AI analysis complete. Suspicious domains saved to {output_file_suspicious}")
        except IOError as e:
            self.log.error(f"Error saving AI analysis to {output_file_suspicious}: {e}")

        # Save safe domains
        output_file_safe = os.path.join(self.output_dir, "safe_domains.txt")
        try:
            with open(output_file_safe, 'a', encoding='utf-8') as f:
                f.write(f"\n# Safe domains discovered at {datetime.now(timezone.utc).isoformat()}\n")
                if all_safe_domains:
                    for domain in sorted(list(all_safe_domains)):
                        f.write(f"{domain}\n")
                else:
                    f.write("No new safe domains identified in this run.\n")
            self.log.info(f"Safe domains saved to {output_file_safe}")
        except IOError as e:
            self.log.error(f"Error saving safe domains to {output_file_safe}: {e}")

        self.log.info("--- AI Phishing Analysis End ---")

    def run_once(self) -> int:
        """Run a single monitoring cycle."""
        log_states = self.load_state()
        log_urls = self.config['log_urls']
        max_workers = self.config['max_workers']
        skip_catchup = self.config.get('skip_catchup', False)
        
        # Initialize state for new logs
        for url in log_urls:
            
            should_reset = skip_catchup and (url not in log_states or self.config.get('force_reset_state'))
                        
            if skip_catchup or url not in log_states:
                if skip_catchup:
                     self.log.info(f"Skip catchup requested. Fast-forwarding {url} to current head.")
                else:
                     self.log.info(f"Initializing state for new log: {url}")

                sth_init = self.get_sth(url)
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
        # We only want to skip catchup on the FIRST run of the process.
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
                domains_to_analyze = sorted(list(all_new_domains))[:max_domains]
                if len(all_new_domains) > max_domains:
                    self.log.warning(f"Analyzing the first {max_domains} of {len(all_new_domains)} domains due to AI mode limit.")
                self.analyze_domains_for_phishing(set(domains_to_analyze))
            else:
                self.save_domains(all_new_domains, timestamp, all_suspicious_events)

        # Save updated state
        self.save_state(log_states)
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


def load_config_file(config_path: str) -> Dict:
    """Load configuration from JSON file."""
    try:
        with open(config_path, 'r') as f:
            return json.load(f)
    except (json.JSONDecodeError, IOError) as e:
        print(f"Error loading config file {config_path}: {e}")
        return {}


def create_sample_config(config_path: str):
    """Create a sample configuration file."""
    try:
        with open(config_path, 'w') as f:
            json.dump(DEFAULT_CONFIG, f, indent=4)
        print(f"Sample configuration created at {config_path}")
    except IOError as e:
        print(f"Error creating config file: {e}")


def main():
    load_dotenv()
    parser = argparse.ArgumentParser(
        description="Certificate Transparency Log Monitor",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --once                           # Run once and exit
  %(prog)s --continuous                     # Run continuously
  %(prog)s --output-format csv --output-file domains.csv
  %(prog)s --config config.json            # Use custom config
  %(prog)s --create-config                 # Create sample config
  %(prog)s --ai-mode --ai-model gemini-1.5-flash-latest # Run with AI phishing detection
        """
    )
    
    parser.add_argument('--version', action='version', version=f'%(prog)s {__version__}')
    parser.add_argument('--config', help='Configuration file path')
    parser.add_argument('--create-config', metavar='FILE', help='Create sample configuration file')
    
    # Execution modes
    mode_group = parser.add_mutually_exclusive_group()
    mode_group.add_argument('--once', action='store_true', help='Run once and exit')
    mode_group.add_argument('--continuous', action='store_true', default=True, help='Run continuously (default)')
    mode_group.add_argument('--ai-mode', action='store_true', help='Run once and analyze domains with AI for phishing')
    
    # Monitoring options
    parser.add_argument('--skip-catchup', action='store_true',
                       help='Start monitoring from current log size, ignoring historical entries (useful for AI mode)')
    parser.add_argument('--keywords', help='Comma-separated list of keywords to monitor (overrides config)')

    # Output options
    parser.add_argument('--output-format', choices=['json', 'csv', 'txt'],
                       help='Output format (default: json)')
    parser.add_argument('--output-file', help='Output file path')
    parser.add_argument('--state-file', help='State file path')
    
    # Monitoring options
    parser.add_argument('--poll-interval', type=int, help='Polling interval in seconds')
    parser.add_argument('--max-workers', type=int, help='Maximum worker threads')
    parser.add_argument('--log-level', choices=['DEBUG', 'INFO', 'WARNING', 'ERROR'],
                       help='Logging level')

    # AI options
    parser.add_argument('--ai-provider', choices=['google', 'openrouter'], default='google',
                       help='AI provider to use (default: google)')
    parser.add_argument('--ai-model', help='The specific AI model to use')
    parser.add_argument('--max-domains-for-ai', type=int, help='Max domains to send to AI for analysis')
    
    args = parser.parse_args()
    
    # Handle config creation
    if args.create_config:
        create_sample_config(args.create_config)
        return
    
    # Load configuration
    config = DEFAULT_CONFIG.copy()
    
    if args.config:
        file_config = load_config_file(args.config)
        config.update(file_config)
    
    # Override with command line arguments
    if args.output_format:
        config['output_format'] = args.output_format
    if args.output_file:
        config['output_file'] = args.output_file
    if args.state_file:
        config['state_file'] = args.state_file
    if args.poll_interval:
        config['poll_interval_seconds'] = args.poll_interval
    if args.max_workers:
        config['max_workers'] = args.max_workers
    if args.log_level:
        config['log_level'] = args.log_level
        
    if args.ai_mode:
        config['ai_mode'] = True
    if args.ai_provider:
        config['ai_provider'] = args.ai_provider
    if args.ai_model:
        config['ai_model'] = args.ai_model
    if args.max_domains_for_ai:
        config['max_domains_for_ai'] = args.max_domains_for_ai
    
    if args.skip_catchup:
        config['skip_catchup'] = True

    if args.keywords:
        keywords = [k.strip() for k in args.keywords.split(',') if k.strip()]
        config['monitored_keywords'] = keywords

    # Create a unique output directory for this run
    run_mode = "continuous"
    if args.once:
        run_mode = "once"
    elif args.ai_mode:
        run_mode = "ai_mode"
    
    timestamp_str = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    output_dir_name = f"ct_run_{timestamp_str}_{run_mode}"
    
    # Create the directory if it doesn't exist
    try:
        os.makedirs(output_dir_name, exist_ok=True)
        config['output_dir'] = output_dir_name
        print(f"Output will be saved to: {output_dir_name}")
    except OSError as e:
        print(f"Error creating output directory: {e}")
        return

    # Create monitor and run
    monitor = CTMonitor(config)
    
    if args.once or config.get('ai_mode'):
        domain_count = monitor.run_once()
        if not config.get('ai_mode'):
            print(f"Found {domain_count} new domains")
    else:
        monitor.run_continuous()


if __name__ == "__main__":
    main()