import requests
import json
import logging
from typing import Optional, List, Dict

class CTClient:
    def __init__(self, request_timeout: int, fetch_batch_size: int):
        self.timeout = request_timeout
        self.batch_size = fetch_batch_size
        self.log = logging.getLogger(__name__)

    def get_sth(self, log_url: str) -> Optional[Dict]:
        """Fetches the Signed Tree Head (STH) for a given log."""
        try:
            response = requests.get(f"{log_url}ct/v1/get-sth", timeout=self.timeout)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            self.log.warning(f"Error getting STH from {log_url}: {e}")
            return None

    def get_entries(self, log_url: str, start: int, end: int) -> Optional[List]:
        """Fetches log entries in batches."""
        all_entries = []
        current_start = start
        fetch_url = None
        
        try:
            while current_start <= end:
                current_end = min(current_start + self.batch_size - 1, end)
                fetch_url = f"{log_url}ct/v1/get-entries?start={current_start}&end={current_end}"
                response = requests.get(fetch_url, timeout=self.timeout * 2)
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