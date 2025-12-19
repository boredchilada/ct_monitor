import base64
import logging
from cryptography import x509
from cryptography.x509.oid import ExtensionOID
from typing import Optional, List, Dict

from .constants import LEAF_TYPE_OFFSET, CERT_LENGTH_OFFSET, CERT_START_OFFSET
from .utils import is_valid_domain

log = logging.getLogger(__name__)

def parse_leaf_input(leaf_input_b64: str, entry_index: int, log_url: str) -> Optional[x509.Certificate]:
    """Parses the leaf input to extract an X.509 certificate."""
    try:
        decoded_leaf = base64.b64decode(leaf_input_b64)
        entry_type = int.from_bytes(decoded_leaf[LEAF_TYPE_OFFSET], byteorder='big')

        if entry_type == 0:  # x509_entry
            cert_length = int.from_bytes(decoded_leaf[CERT_LENGTH_OFFSET], byteorder='big')
            cert_end_offset = CERT_START_OFFSET + cert_length

            if cert_length <= 0 or cert_end_offset > len(decoded_leaf):
                log.warning(f"Invalid cert length ({cert_length}) in entry {entry_index} from {log_url}")
                return None

            cert_bytes = decoded_leaf[CERT_START_OFFSET:cert_end_offset]
            cert = x509.load_der_x509_certificate(cert_bytes)
            return cert
        else:
            return None

    except Exception as e:
        log.warning(f"Error parsing certificate for entry {entry_index} from {log_url}: {e}")
        return None

def extract_certificate_info(cert: x509.Certificate) -> List[Dict]:
    """Extracts domains and metadata from certificate."""
    results = []
    if cert is None:
        return results

    domains = set()
    
    # Extract Issuer
    issuer = "Unknown"
    try:
        issuer_cn = cert.issuer.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
        if issuer_cn:
            issuer = issuer_cn[0].value
        else:
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
                if cleaned_cn and is_valid_domain(cleaned_cn):
                    domains.add(cleaned_cn)
    except Exception as e:
        log.debug(f"Error getting Subject CN: {e}")

    # Extract Subject Alternative Names (SANs)
    try:
        san_extension = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
        sans = san_extension.value.get_values_for_type(x509.DNSName) # type: ignore
        for domain in sans:
            cleaned_domain = domain.lower().strip(' *.')
            if cleaned_domain and is_valid_domain(cleaned_domain):
                domains.add(cleaned_domain)
    except x509.ExtensionNotFound:
        pass
    except Exception as e:
        log.debug(f"Error processing SAN extension: {e}")

    for domain in domains:
        results.append({
            'domain': domain,
            'issuer': issuer,
            'not_before': cert.not_valid_before_utc,
            'not_after': cert.not_valid_after_utc
        })

    return results