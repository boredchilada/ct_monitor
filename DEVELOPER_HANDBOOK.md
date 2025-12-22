# CT Monitor Developer Handbook

This document serves as the internal reference guide for developers working on the Certificate Transparency Monitor project. It covers architecture, code organization, function documentation, and development workflows.

---

## Table of Contents

1. [Project Overview](#project-overview)
2. [Project Structure](#project-structure)
3. [Architecture](#architecture)
4. [Module Breakdown](#module-breakdown)
5. [Class Reference: CTMonitor](#class-reference-ctmonitor)
6. [Utility Functions](#utility-functions)
7. [Configuration System](#configuration-system)
8. [Data Flow](#data-flow)
9. [Environment Setup](#environment-setup)
10. [Development Notes](#development-notes)

---

## Project Overview

**Purpose**: Monitor Certificate Transparency logs for newly issued SSL/TLS certificates and extract domain names for security research, threat intelligence, and phishing detection.

**Version**: 1.1.0

**Author**: boredchilada

**License**: MIT

---

## Project Structure

```
CT_Monitor/
|
|-- ct_monitor/             # Source code package
|   |-- __init__.py
|   |-- analysis.py         # AI and keyword analysis
|   |-- cert_parser.py      # Certificate parsing logic
|   |-- client.py           # CT log API communication
|   |-- config.py           # Configuration management
|   |-- constants.py        # Application constants
|   |-- main.py             # Main application entry point
|   |-- monitor.py          # Core monitoring orchestration
|   |-- reporting.py        # Output file generation
|   |-- state.py            # State management
|   `-- utils.py            # Shared utility functions
|
|-- scripts/
|   |-- run_monitor.py      # Application runner script
|   `-- verify_domains.py   # Active domain verification tool
|
|-- config.json             # User configuration file
|-- requirements.txt        # Python dependencies (pip freeze output)
|-- .env                    # Environment variables (API keys) - NOT committed
|-- .env.sample             # Template for .env file
|-- .gitignore              # Git ignore rules
|-- LICENSE                 # MIT License
|-- README.md               # Public documentation
|-- DEVELOPER_HANDBOOK.md   # This file - internal developer guide
|
|-- ct_monitor_state.json   # Runtime: persisted log positions
|-- ct_monitor.log          # Runtime: application logs
|
|-- ct_run_<timestamp>_<mode>/    # Runtime: output directories
|   |-- ct_domains.json           # Discovered domains (json/csv/txt)
|   |-- phishing_analysis.txt     # AI-flagged suspicious domains
|   |-- safe_domains.txt          # AI-classified safe domains
```

---

## Architecture

### High-Level Design

The application follows a modular architecture, separating concerns into distinct components. The `CTMonitor` class orchestrates the monitoring process by coordinating specialized modules for API communication, parsing, analysis, and reporting. The design prioritizes:

1. **Modularity**: Clear separation of concerns for easier maintenance and testing
2. **Statelessness per cycle**: Each polling cycle is independent
3. **State persistence**: Log positions are saved atomically between cycles
4. **Parallel processing**: ThreadPoolExecutor for concurrent log/entry processing
5. **Fail-safe operation**: Individual log/entry failures don't crash the monitor

### Component Diagram

```
+------------------+     +-------------------+     +------------------+
|   CLI Parser     | --> |    CTMonitor      | --> |  Output Writers  |
|   (argparse)     |     |    (main class)   |     |  (json/csv/txt)  |
+------------------+     +-------------------+     +------------------+
                               |       |
                               |       v
                               |  +-----------------+
                               |  | AI Analyzer     |
                               |  | (LangChain +    |
                               |  |  Google Gemini) |
                               |  +-----------------+
                               v
                         +-------------------+
                         |  State Manager    |
                         |  (JSON file I/O)  |
                         +-------------------+
```

### Threading Model

```
Main Thread
    |
    +-- ThreadPoolExecutor (max_workers from config)
           |
           +-- Log Checker Threads (one per CT log URL)
                  |
                  +-- Entry Parser Threads (nested pool for certificate parsing)
```

---

## Module Breakdown

### ct_monitor Package

The application is organized into a Python package with the following modules:

#### `monitor.py`
Contains the `CTMonitor` class, which orchestrates the monitoring process. It initializes and coordinates the other components.

#### `client.py`
Handles all network communication with CT logs. Contains the `CTClient` class with:
- `get_sth(log_url)`: Fetches the Signed Tree Head (STH) for a given log.
- `get_entries(log_url, start, end)`: Fetches log entries in batches, handling pagination automatically.

#### `cert_parser.py`
Responsible for parsing X.509 certificates. Contains `parse_leaf_input` and `extract_certificate_info` functions.

#### `analysis.py`
Handles domain analysis. Contains the `DomainAnalyzer` class for keyword matching and AI-powered phishing detection.

#### `reporting.py`
Manages output generation. Contains the `ReportGenerator` class for saving domains to JSON, CSV, or TXT files.

#### `state.py`
Handles state persistence. Contains the `StateManager` class for loading and saving log positions.

#### `config.py`
Manages configuration loading and defaults. It defines `DEFAULT_CONFIG` and provides functions to load configuration from JSON files (`load_config_file`) and create sample configuration files (`create_sample_config`).

#### `utils.py`
Contains shared utility functions:
- `setup_logging(log_level_str)`: Configures logging to console and file.
- `normalize_url(url)`: Normalizes URLs for consistent processing.
- `is_valid_domain(domain)`: Validates domain names using regex.

#### `constants.py`
Stores application constants like version, default log URLs, and RFC offsets.

#### `main.py`
The entry point for the application logic, handling CLI argument parsing and startup.

### Scripts

#### `scripts/verify_domains.py`
Independent tool to verify if domains are live and check for "parked" status.
- **Input**: Text file with list of domains (e.g., `phishing_analysis.txt`)
- **Output**: `verified_<filename>.txt` with categorized results (Active Threats, Parked, Dead)
- **Usage**: `python scripts/verify_domains.py <input_file>`

---

## Class Reference: CTMonitor

### Constructor

#### [`__init__(self, config: Dict)`](ct_monitor.py:105)

**Purpose**: Initialize the monitor with configuration.

**Parameters**:
- `config` (Dict): Configuration dictionary (merged from defaults, file, and CLI)

**Side Effects**:
- Calls [`setup_logging()`](ct_monitor.py:111)
- Sets `self.output_dir` from config

---

### Logging and Validation Methods

#### [`setup_logging(self)`](ct_monitor.py:111)

**Purpose**: Configure Python logging with console and file handlers.

**Inputs**: None (reads from `self.config`)

**Outputs**: None

**Side Effects**: 
- Configures `logging.basicConfig`
- Creates `ct_monitor.log` file

---

#### [`normalize_url(self, url: str) -> Optional[str]`](ct_monitor.py:123)

**Purpose**: Normalize and validate a URL string.

**Inputs**: 
- `url` (str): URL to normalize

**Outputs**: 
- Lowercase URL string with protocol, or `None` if invalid

---

#### [`is_valid_domain(self, domain: str) -> bool`](ct_monitor.py:135)

**Purpose**: Validate domain name format using regex.

**Inputs**: 
- `domain` (str): Domain name to validate

**Outputs**: 
- `True` if domain matches RFC-compliant pattern, `False` otherwise

**Validation Rules**:
- Length <= 253 characters
- Matches regex for valid DNS labels

---

### State Management Methods

#### [`load_state(self) -> Dict`](ct_monitor.py:146)

**Purpose**: Load persisted log positions from state file.

**Inputs**: None (reads from `self.config['state_file']`)

**Outputs**: 
- Dict mapping log URLs to their last known tree sizes

**Side Effects**: 
- Logs error if file is corrupted
- Returns empty dict on failure (safe default)

---

#### [`save_state(self, state: Dict)`](ct_monitor.py:158)

**Purpose**: Atomically save log positions to state file.

**Inputs**: 
- `state` (Dict): Current log positions

**Outputs**: None

**Side Effects**: 
- Writes to temp file first, then uses `os.replace()` for atomic update
- Logs error on I/O failure

---

### CT Log API Methods

#### [`get_sth(self, log_url: str) -> Optional[Dict]`](ct_monitor.py:169)

**Purpose**: Fetch the Signed Tree Head from a CT log.

**Inputs**: 
- `log_url` (str): Base URL of the CT log

**Outputs**: 
- Dict containing `tree_size`, `timestamp`, `sha256_root_hash`, `tree_head_signature`
- `None` on error

**API Endpoint**: `{log_url}ct/v1/get-sth`

---

#### [`get_entries(self, log_url: str, start: int, end: int) -> Optional[List]`](ct_monitor.py:180)

**Purpose**: Fetch log entries in batches from a CT log.

**Inputs**: 
- `log_url` (str): Base URL of the CT log
- `start` (int): Starting entry index (0-based)
- `end` (int): Ending entry index (inclusive)

**Outputs**: 
- List of entry dicts with `leaf_input` and `extra_data` fields
- `None` on error

**API Endpoint**: `{log_url}ct/v1/get-entries?start={start}&end={end}`

**Behavior**:
- Fetches in batches of `config['fetch_batch_size']`
- Handles partial batches and empty responses

---

### Certificate Parsing Methods

#### [`parse_leaf_input(self, leaf_input_b64: str, entry_index: int, log_url: str) -> Optional[x509.Certificate]`](ct_monitor.py:212)

**Purpose**: Parse a base64-encoded Merkle Tree leaf to extract the X.509 certificate.

**Inputs**: 
- `leaf_input_b64` (str): Base64-encoded leaf data
- `entry_index` (int): Entry index for logging
- `log_url` (str): Log URL for logging

**Outputs**: 
- `x509.Certificate` object, or `None` if parsing fails or entry is a precertificate

**Implementation Details**:
- Follows RFC 6962 Merkle Tree Leaf structure
- Only processes `x509_entry` type (entry_type == 0)
- Skips precertificates (entry_type == 1)

---

#### [`extract_certificate_info(self, cert: x509.Certificate) -> List[Dict]`](ct_monitor.py:236)

**Purpose**: Extract domain names and metadata from a certificate.

**Inputs**: 
- `cert` (x509.Certificate): Parsed certificate object

**Outputs**: 
- List of dicts, each containing:
  - `domain` (str): Extracted domain name
  - `issuer` (str): Certificate issuer CN or RFC4514 string
  - `not_before` (datetime): Certificate validity start
  - `not_after` (datetime): Certificate validity end

**Domain Extraction Sources**:
1. Subject Common Name (CN)
2. Subject Alternative Names (SAN) extension

**Behavior**:
- Removes leading wildcards (`*.example.com` -> `example.com`)
- Lowercases all domains
- Validates each domain with [`is_valid_domain()`](ct_monitor.py:135)

---

#### [`is_suspicious(self, domain: str) -> bool`](ct_monitor.py:292)

**Purpose**: Check if a domain contains monitored keywords.

**Inputs**: 
- `domain` (str): Domain name to check

**Outputs**: 
- `True` if any keyword from `config['monitored_keywords']` is in the domain

---

#### [`_parse_and_extract_worker(self, entry_data: tuple) -> List[Dict]`](ct_monitor.py:299)

**Purpose**: Worker function for ThreadPoolExecutor to parse a single entry.

**Inputs**: 
- `entry_data` (tuple): `(entry_dict, entry_index, log_url)`

**Outputs**: 
- List of certificate info dicts (from [`extract_certificate_info()`](ct_monitor.py:236))

---

### Log Processing Methods

#### [`check_log(self, log_url: str, last_known_size: int) -> tuple`](ct_monitor.py:309)

**Purpose**: Check a single CT log for new entries and extract domains.

**Inputs**: 
- `log_url` (str): CT log base URL
- `last_known_size` (int): Previously processed tree size

**Outputs**: 
- Tuple of `(new_domains: Set[str], suspicious_events: List[Dict], updated_size: int)`

**Behavior**:
1. Fetch STH to get current tree size
2. If new entries exist, fetch them in batches
3. Parse certificates in parallel using ThreadPoolExecutor
4. Check each domain against suspicious keywords
5. Return aggregated results

---

### Output Methods

#### [`save_domains(self, domains: Set[str], timestamp: str, suspicious_events: Optional[List[Dict]] = None)`](ct_monitor.py:372)

**Purpose**: Dispatch domain saving to appropriate format handler.

**Inputs**: 
- `domains` (Set[str]): Domains to save
- `timestamp` (str): ISO format timestamp
- `suspicious_events` (List[Dict], optional): Suspicious certificate metadata

**Outputs**: None

**Dispatches to**: [`save_domains_json()`](ct_monitor.py:389), [`save_domains_csv()`](ct_monitor.py:429), or [`save_domains_txt()`](ct_monitor.py:446)

---

#### [`save_domains_json(self, ...)`](ct_monitor.py:389)

**Purpose**: Save domains in JSON format with metadata.

**Behavior**:
- Appends to existing JSON array if file exists
- Includes suspicious events with serialized datetime fields

---

#### [`save_domains_csv(self, ...)`](ct_monitor.py:429)

**Purpose**: Save domains in CSV format.

**Behavior**:
- Creates header row if file is new
- Appends timestamp,domain rows

---

#### [`save_domains_txt(self, ...)`](ct_monitor.py:446)

**Purpose**: Save domains in plain text format.

**Behavior**:
- Appends with comment header showing timestamp

---

### AI Analysis Methods

#### [`analyze_domains_for_phishing(self, domains: Set[str])`](ct_monitor.py:458)

**Purpose**: Use Google Gemini (or configured provider) to analyze domains for phishing indicators, specifically focusing on brand impersonation and social engineering tactics.

**Inputs**: 
- `domains` (Set[str]): Domains to analyze

**Outputs**: None (writes to files)

**Side Effects**:
- Writes to `phishing_analysis.txt` (suspicious domains with reasons)
- Writes to `safe_domains.txt` (domains classified as safe)

**Implementation**:
1. Initializes LangChain with Google Gemini
2. Batches domains according to `config['ai_batch_size']`
3. Uses a specialized prompt template focusing on:
   - **Brand Impersonation**: Checks for exact matches, typosquatting, and combosquatting of major brands.
   - **Suspicious Keywords**: Scans for high-risk terms like 'login', 'verify', 'secure'.
   - **TLD Reputation**: Considers potentially abusive TLDs.
   - **Entropy**: Checks for random character strings (DGA).
   - **Keyword Stuffing**: Identifies excessive subdomain nesting as noise.
     - Example: `pochta.pay.pochtabank...` (Too many brands)
     - Example: `sbermarket.pay...` (Excessive nesting)
4. Requests a structured SUSPICIOUS/SAFE classification with specific reasoning.
5. Parses LLM response to extract classifications
6. Appends results to output files

**Error Handling**:
- Logs error if `GOOGLE_API_KEY` not set
- Continues processing other batches if one fails

---

### Execution Methods

#### [`run_once(self) -> int`](ct_monitor.py:568)

**Purpose**: Execute a single monitoring cycle.

**Inputs**: None

**Outputs**: 
- Count of new domains discovered

**Behavior**:
1. Load persisted state
2. Initialize state for new logs (or skip catchup if configured)
3. Check all logs in parallel
4. Aggregate domains and suspicious events
5. Save outputs (AI analysis or standard)
6. Persist updated state

---

#### [`run_continuous(self)`](ct_monitor.py:661)

**Purpose**: Run monitoring in an infinite loop.

**Behavior**:
- Calls [`run_once()`](ct_monitor.py:568) repeatedly
- Sleeps for `config['poll_interval_seconds']` between cycles
- Catches KeyboardInterrupt for graceful shutdown

---

## Utility Functions

These functions are defined at module level (outside the class).

#### [`load_config_file(config_path: str) -> Dict`](ct_monitor.py:680)

**Purpose**: Load configuration from a JSON file.

**Inputs**: 
- `config_path` (str): Path to JSON config file

**Outputs**: 
- Configuration dict, or empty dict on error

---

#### [`create_sample_config(config_path: str)`](ct_monitor.py:690)

**Purpose**: Write default configuration to a file.

**Inputs**: 
- `config_path` (str): Path for new config file

**Side Effects**: 
- Creates JSON file with DEFAULT_CONFIG contents

---

#### [`main()`](ct_monitor.py:700)

**Purpose**: Application entry point.

**Behavior**:
1. Load `.env` with `python-dotenv`
2. Parse CLI arguments with `argparse`
3. Build configuration (defaults -> config file -> CLI args)
4. Create timestamped output directory
5. Instantiate `CTMonitor` and run appropriate mode

---

## Configuration System

### Priority Order (lowest to highest)

1. `DEFAULT_CONFIG` (hardcoded in `ct_monitor/config.py`)
2. Default config file (`config.json` in the working directory, if present)
3. Custom config file (specified with `--config`)
4. CLI arguments (override specific settings)

The application automatically looks for a `config.json` file in the current directory. If found, it loads settings from there, which can be overridden by command-line arguments.

### Key Configuration Interactions

| CLI Arg | Config Key | Notes |
|---------|------------|-------|
| `--ai-mode` | `ai_mode` | Enables AI analysis |
| `--skip-catchup` | `skip_catchup` | Auto-disabled after first cycle |
| `--keywords` | `monitored_keywords` | Comma-separated, overrides list |

---

## Data Flow

### Standard Mode Flow

```
1. main() parses CLI and loads config
              |
              v
2. CTMonitor instantiated
              |
              v
3. run_once() or run_continuous() called
              |
              v
4. load_state() reads ct_monitor_state.json
              |
              v
5. ThreadPoolExecutor checks each CT log:
   a. get_sth() -> current tree size
   b. get_entries() -> batch fetch
   c. parse_leaf_input() -> extract cert
   d. extract_certificate_info() -> domains
   e. is_suspicious() -> flag keywords
              |
              v
6. Aggregate results across all logs
              |
              v
7. save_domains() writes to output file
              |
              v
8. save_state() persists new positions
```

### AI Mode Flow

```
Steps 1-6 same as Standard Mode
              |
              v
7. analyze_domains_for_phishing()
   a. Determine provider (Google vs OpenRouter)
   b. Initialize LangChain LLM (ChatGoogleGenerativeAI or ChatOpenAI)
   c. Batch domains (ai_batch_size)
   d. Invoke LLM with prompt
   d. Parse SUSPICIOUS/SAFE response
   e. Write phishing_analysis.txt
   f. Write safe_domains.txt
              |
              v
8. save_state() persists new positions
```

---

## Environment Setup

### Required Environment Variables

| Variable | Required For | Description |
|----------|--------------|-------------|
| `GOOGLE_API_KEY` | AI Mode (Default) | Google AI Studio API key for Gemini |
| `OPENROUTER_API_KEY` | AI Mode (Optional) | OpenRouter API key for other models |

### .env File Template

```env
# Google Gemini API Key (Required for default AI mode)
GOOGLE_API_KEY="your_google_api_key_here"

# OpenRouter API Key (Required if using --ai-provider openrouter)
OPENROUTER_API_KEY="your_openrouter_api_key_here"
```

### Dependency Installation

```bash
# Create virtual environment
python -m venv venv

# Activate (Windows)
.\venv\Scripts\activate

# Activate (Unix)
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

### Core Dependencies

| Package | Version | Purpose |
|---------|---------|---------|
| `cryptography` | 45.0.5 | X.509 certificate parsing |
| `requests` | 2.32.4 | HTTP client |
| `python-dotenv` | 1.1.1 | Environment variable loading |
| `langchain` | 0.3.27 | LLM orchestration framework |
| `langchain-google-genai` | 2.1.8 | Google Gemini integration |
| `langchain-openai` | 0.2.14 | OpenRouter (OpenAI-compatible) integration |

---

## Development Notes

### Known Limitations

1. **Precertificates Ignored**: The parser only handles `x509_entry` (entry_type == 0). Precertificates (type 1) are skipped.

2. **AI Batch Parsing**: The LLM response parsing is regex-based and may fail on malformed responses.

3. **No Retry Logic**: Failed HTTP requests are logged but not retried.

### Potential Improvements

- Add retry logic with exponential backoff for CT log API calls
- Add unit tests for certificate parsing
- Support additional AI providers beyond Google Gemini
- Add webhook/notification support for suspicious domain alerts

### Testing Notes

The `holymoly/test_domains.txt` file contains sample domains for testing AI analysis locally.

### Code Style

- Type hints are used throughout (see imports from `typing`)
- Logging follows standard Python patterns
- Configuration is dict-based for flexibility

---

## Appendix: CT Log Protocol Reference

Certificate Transparency follows [RFC 6962](https://datatracker.ietf.org/doc/html/rfc6962).

### Key Endpoints

| Endpoint | Method | Returns |
|----------|--------|---------|
| `/ct/v1/get-sth` | GET | Signed Tree Head with current size |
| `/ct/v1/get-entries?start=N&end=M` | GET | Log entries in range |

### Merkle Tree Leaf Structure

```
struct {
    Version version;                // 1 byte
    MerkleLeafType leaf_type;       // 1 byte
    uint64 timestamp;               // 8 bytes
    LogEntryType entry_type;        // 2 bytes (offset 10-12)
    opaque signed_entry<0..2^24-1>; // variable
} MerkleTreeLeaf;
```

The code uses these offsets:
- `LEAF_TYPE_OFFSET = slice(10, 12)` - entry type
- `CERT_LENGTH_OFFSET = slice(12, 15)` - 3-byte length prefix
- `CERT_START_OFFSET = 15` - certificate data begins here

---

*Last Updated: 2025-12-08*