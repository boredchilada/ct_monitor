import os
import json
import csv
import logging
from typing import Set, List, Dict, Optional
from datetime import datetime

class ReportGenerator:
    def __init__(self, config: Dict, output_dir: str):
        self.config = config
        self.output_dir = output_dir
        self.log = logging.getLogger(__name__)

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