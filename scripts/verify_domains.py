import argparse
import concurrent.futures
import logging
import socket
import sys
import time
from pathlib import Path
from typing import List, Dict, Tuple

import requests

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

PARKED_KEYWORDS = [
    "domain is for sale",
    "buy this domain",
    "parked free",
    "godaddy",
    "sedo",
    "dan.com",
    "domain parking",
    "this domain is available",
    "inquire about this domain",
    "domain name is for sale",
    "purchase this domain"
]

def is_resolvable(domain: str) -> bool:
    """Check if a domain resolves to an IP address."""
    try:
        socket.gethostbyname(domain)
        return True
    except socket.error:
        return False

def check_domain(domain: str, timeout: int = 5) -> Dict:
    """
    Check if a domain is active and if it appears to be parked.
    """
    result = {
        "domain": domain,
        "resolves": False,
        "http_status": None,
        "is_parked": False,
        "parked_reason": None,
        "error": None
    }

    # 1. DNS Check
    if not is_resolvable(domain):
        return result
    
    result["resolves"] = True

    # 2. HTTP Check
    try:
        # Try HTTPS first, then HTTP
        url = f"https://{domain}"
        try:
            response = requests.get(url, timeout=timeout, headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"})
        except requests.RequestException:
            url = f"http://{domain}"
            response = requests.get(url, timeout=timeout, headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"})
        
        result["http_status"] = response.status_code
        
        if response.status_code == 200:
            content = response.text.lower()
            for keyword in PARKED_KEYWORDS:
                if keyword in content:
                    result["is_parked"] = True
                    result["parked_reason"] = f"Found keyword: '{keyword}'"
                    break
                    
    except requests.RequestException as e:
        result["error"] = str(e)

    return result

def process_file(input_file: str, output_file: str, max_workers: int = 10):
    input_path = Path(input_file)
    if not input_path.exists():
        logger.error(f"Input file not found: {input_file}")
        return

    domains = []
    # Simple parsing: assume one domain per line, strip whitespace/comments
    try:
        with open(input_path, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#') and not line.startswith('---'):
                    # Handle "domain: reason" format from phishing_analysis.txt
                    # Also handle "- domain: reason" format
                    clean_line = line.lstrip('- ')
                    if ':' in clean_line:
                        parts = clean_line.split(':', 1)
                        # Check if the first part looks like a domain (contains dot)
                        if '.' in parts[0]:
                            domains.append(parts[0].strip())
                    else:
                        domains.append(clean_line)
    except Exception as e:
        logger.error(f"Error reading input file: {e}")
        return
    
    # Remove duplicates
    domains = list(set(domains))
    logger.info(f"Loaded {len(domains)} unique domains from {input_file}")

    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_domain = {executor.submit(check_domain, domain): domain for domain in domains}
        
        completed = 0
        for future in concurrent.futures.as_completed(future_to_domain):
            domain = future_to_domain[future]
            try:
                data = future.result()
                results.append(data)
            except Exception as exc:
                logger.error(f"{domain} generated an exception: {exc}")
            
            completed += 1
            if completed % 10 == 0:
                logger.info(f"Processed {completed}/{len(domains)} domains...")

    # Write results
    active_threats = [r for r in results if r['resolves'] and not r['is_parked']]
    parked_domains = [r for r in results if r['is_parked']]
    dead_domains = [r for r in results if not r['resolves']]

    try:
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(f"# Domain Verification Results - {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"# Total: {len(domains)} | Active Threats: {len(active_threats)} | Parked: {len(parked_domains)} | Dead: {len(dead_domains)}\n\n")
            
            f.write("## ACTIVE THREATS (Resolves + Not Parked)\n")
            f.write("# These domains are live and did not show obvious parking signatures.\n")
            for r in active_threats:
                status = r.get('http_status', 'N/A')
                f.write(f"{r['domain']} (HTTP {status})\n")
            
            f.write("\n## PARKED DOMAINS\n")
            f.write("# These domains are live but contain 'for sale' or parking keywords.\n")
            for r in parked_domains:
                f.write(f"{r['domain']} ({r['parked_reason']})\n")

            f.write("\n## DEAD / UNRESOLVABLE\n")
            f.write("# These domains do not resolve to an IP address.\n")
            for r in dead_domains:
                f.write(f"{r['domain']}\n")

        logger.info(f"Verification complete. Results saved to {output_file}")
        
    except Exception as e:
        logger.error(f"Error writing output file: {e}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Verify domains from a list (e.g., phishing_analysis.txt).")
    parser.add_argument("input_file", help="Path to input file (txt)")
    parser.add_argument("--output", "-o", default="verified_domains.txt", help="Path to output file")
    parser.add_argument("--workers", "-w", type=int, default=10, help="Number of concurrent workers")
    
    args = parser.parse_args()
    
    # If output is default, place it in the same directory as input
    output_path = args.output
    if output_path == "verified_domains.txt":
        input_path = Path(args.input_file)
        output_path = str(input_path.parent / f"verified_{input_path.name}")
        
    process_file(args.input_file, output_path, args.workers)