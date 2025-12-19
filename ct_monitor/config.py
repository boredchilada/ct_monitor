import json
from typing import Dict
from .constants import DEFAULT_LOG_URLS

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