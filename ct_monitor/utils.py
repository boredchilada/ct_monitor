import logging
import sys
import re
from urllib.parse import urlparse
from typing import Optional

def setup_logging(log_level_str: str):
    """Setup logging configuration."""
    log_level = getattr(logging, log_level_str.upper(), logging.INFO)
    logging.basicConfig(
        level=log_level,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[
            logging.StreamHandler(sys.stdout),
            logging.FileHandler('ct_monitor.log')
        ]
    )

def normalize_url(url: str) -> Optional[str]:
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

def is_valid_domain(domain: str) -> bool:
    """Basic domain validation."""
    if not domain or len(domain) > 253:
        return False
    
    # Basic regex for domain validation
    domain_pattern = re.compile(
        r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$'
    )
    return bool(domain_pattern.match(domain))