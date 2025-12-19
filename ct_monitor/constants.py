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

# CT Log Entry Structure Offsets (RFC 6962)
LEAF_TYPE_OFFSET = slice(10, 12)
CERT_LENGTH_OFFSET = slice(12, 15)
CERT_START_OFFSET = 15