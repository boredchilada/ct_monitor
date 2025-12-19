# Certificate Transparency Monitor

A standalone Python tool for monitoring Certificate Transparency (CT) logs and extracting newly issued domain certificates in real-time. Includes AI-powered phishing detection capabilities using Google Gemini.

## Table of Contents

- [Features](#features)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Usage](#usage)
- [AI-Powered Phishing Detection](#ai-powered-phishing-detection)
- [Configuration](#configuration)
- [Output Formats](#output-formats)
- [Monitored CT Logs](#monitored-ct-logs)
- [Examples](#examples)
- [Performance Considerations](#performance-considerations)
- [Troubleshooting](#troubleshooting)
- [Contributing](#contributing)
- [License](#license)

---

## Features

- **Real-time CT Log Monitoring**: Continuously monitors multiple Certificate Transparency logs from major providers
- **Domain Extraction**: Extracts domains from X.509 certificates (Subject CN and SAN fields)
- **Keyword-Based Detection**: Flags suspicious certificates containing configurable keywords (e.g., "paypal", "bank", "login")
- **AI-Powered Analysis**: Integrates with Google Gemini or OpenRouter (giving access to DeepSeek, Claude, Llama, etc.) for intelligent phishing domain detection
- **Multiple Output Formats**: Supports JSON, CSV, and plain text output
- **State Persistence**: Tracks log positions to avoid reprocessing entries across restarts
- **Concurrent Processing**: Uses multi-threading for efficient parallel log monitoring
- **Configurable**: Flexible configuration via command line arguments or JSON config file
- **Timestamped Output**: Creates unique directories for each run to organize output files

---

## Future considerations

- Rebuild to use sqlite / postgres and save domains
- Centralization via DB for tasks like AI verifications 
- Speed Improvements
- Make code more modular

## Installation

### Requirements

- Python 3.7 or higher
- Internet connection for CT log access
- (Optional) Google API key or OpenRouter API key for AI-powered phishing detection

### Setup

1. **Clone the repository:**
   ```bash
   git clone https://github.com/boredchilada/ct_monitor.git
   cd CT_Monitor
   ```

2. **Create and activate a virtual environment:**
   ```bash
   # Windows
   python -m venv venv
   .\venv\Scripts\activate

   # macOS/Linux
   python3 -m venv venv
   source venv/bin/activate
   ```

3. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

4. **(Optional) Configure API keys for AI mode:**
   
   Copy the sample environment file and add your API key:
   ```bash
   cp .env.sample .env
   ```
   
   Edit `.env` and add your API keys:
   ```env
   # For Google Gemini (Default)
   GOOGLE_API_KEY="your-google-api-key-here"
   
   # For OpenRouter (Optional)
   OPENROUTER_API_KEY="your-openrouter-api-key-here"
   ```

---

## Quick Start

Use --skip-catchup with --once and --ai-mode so you don't wait for everything to update. CT Logs have lots of new entries quickly.

```bash
# Run once and save discovered domains to JSON
python scripts/run_monitor.py --once --skip-catchup

# Run AI-powered phishing analysis
python scripts/run_monitor.py --ai-mode --skip-catchup

# Run continuous monitoring
python scripts/run_monitor.py --continuous
```

---

## Usage

### Command Line Options

```
usage: run_monitor.py [-h] [--version] [--config CONFIG] [--create-config FILE]
                      [--once | --continuous | --ai-mode]
                      [--skip-catchup] [--keywords KEYWORDS]
                     [--output-format {json,csv,txt}]
                     [--output-file OUTPUT_FILE] [--state-file STATE_FILE]
                     [--poll-interval POLL_INTERVAL]
                     [--max-workers MAX_WORKERS]
                     [--log-level {DEBUG,INFO,WARNING,ERROR}]
                     [--ai-model AI_MODEL]
                     [--max-domains-for-ai MAX_DOMAINS_FOR_AI]

Certificate Transparency Log Monitor

optional arguments:
  -h, --help            Show this help message and exit
  --version             Show program's version number and exit
  --config CONFIG       Path to JSON configuration file
  --create-config FILE  Create a sample configuration file at the specified path

Execution Modes (mutually exclusive):
  --once                Run a single monitoring cycle and exit
  --continuous          Run continuously with polling interval (default)
  --ai-mode             Run once and analyze domains with AI for phishing detection

Monitoring Options:
  --skip-catchup        Start monitoring from current log size, skipping historical entries
  --keywords KEYWORDS   Comma-separated list of keywords to monitor (overrides config)
  --poll-interval N     Polling interval in seconds (default: 60)
  --max-workers N       Maximum worker threads for parallel processing (default: 10)
  --log-level LEVEL     Logging verbosity: DEBUG, INFO, WARNING, ERROR (default: INFO)

Output Options:
  --output-format FMT   Output format: json, csv, or txt (default: json)
  --output-file FILE    Output file name (default: ct_domains.json)
  --state-file FILE     State persistence file (default: ct_monitor_state.json)

AI Options:
  --ai-provider PROVIDER AI provider to use: google or openrouter (default: google)
  --ai-model MODEL      Model name to use (default: gemini-2.5-flash for google)
  --max-domains-for-ai N  Maximum domains to analyze per AI batch (default: 1000)
```

---

## AI-Powered Phishing Detection

The tool integrates with Google Gemini (default) or OpenRouter to analyze discovered domains and identify potential phishing attempts.

### Setup

1. **Google Gemini**: Obtain a key from [Google AI Studio](https://aistudio.google.com/app/apikey)
2. **OpenRouter**: Obtain a key from [OpenRouter](https://openrouter.ai/keys)

Create a `.env` file with your keys:
```env
GOOGLE_API_KEY="your-google-key"
OPENROUTER_API_KEY="your-openrouter-key"
```

### Running AI Analysis

```bash
# Basic AI analysis (Defaults to Google Gemini)
python ct_monitor.py --ai-mode

# Use OpenRouter with a specific model
python ct_monitor.py --ai-mode --ai-provider openrouter --ai-model google/gemini-2.0-flash-001

# Use a specific Gemini model
python ct_monitor.py --ai-mode --ai-model gemini-1.5-pro-latest

# Skip historical entries and only analyze new certificates
python ct_monitor.py --ai-mode --skip-catchup

# Limit the number of domains analyzed
python ct_monitor.py --ai-mode --max-domains-for-ai 500
```

### AI Output Files

When running in AI mode, the tool generates two output files in the run directory:

- **phishing_analysis.txt**: Contains domains flagged as suspicious with explanations
- **safe_domains.txt**: Contains domains classified as safe

---

## Configuration

### Configuration File

Generate a sample configuration file:
```bash
python scripts/run_monitor.py --create-config config.json
```

### Configuration Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `state_file` | string | `"ct_monitor_state.json"` | File to persist log positions |
| `poll_interval_seconds` | int | `60` | Seconds between polling cycles |
| `max_workers` | int | `10` | Thread pool size for parallel processing |
| `request_timeout` | int | `20` | HTTP request timeout in seconds |
| `fetch_batch_size` | int | `256` | Number of entries to fetch per request |
| `output_format` | string | `"json"` | Output format: json, csv, or txt |
| `output_file` | string | `"ct_domains.json"` | Output file name |
| `log_level` | string | `"INFO"` | Logging level |
| `log_urls` | array | (see below) | List of CT log URLs to monitor |
| `ai_provider` | string | `"google"` | AI Provider: `google` or `openrouter` |
| `ai_model` | string | `"gemini-2.5-flash"` | Model name for AI analysis |
| `max_domains_for_ai` | int | `1000` | Max domains per AI analysis batch |
| `ai_batch_size` | int | `100` | Domains to send per AI API call |
| `monitored_keywords` | array | (see below) | Keywords for suspicious domain detection |

### Default Monitored Keywords

```json
["paypal", "google", "apple", "microsoft", "bank", "login", "secure", "update", "verify"]
```

---

## Output Formats

Each run creates a timestamped directory (e.g., `ct_run_2025-12-08_01-19-46_once/`) containing output files.

### JSON Format

```json
[
  {
    "timestamp": "2025-12-08T06:00:00.000000+00:00",
    "domain_count": 150,
    "domains": [
      "example.com",
      "subdomain.example.org"
    ],
    "suspicious": [
      {
        "domain": "paypal-secure-login.example.com",
        "issuer": "Let's Encrypt Authority X3",
        "not_before": "2025-12-08T00:00:00",
        "not_after": "2026-03-08T00:00:00",
        "log_url": "https://ct.googleapis.com/logs/us1/argon2025h1/"
      }
    ]
  }
]
```

### CSV Format

```csv
timestamp,domain
2025-12-08T06:00:00.000000+00:00,example.com
2025-12-08T06:00:00.000000+00:00,subdomain.example.org
```

### Text Format

```
# Domains discovered at 2025-12-08T06:00:00.000000+00:00
example.com
subdomain.example.org
```

---

## Monitored CT Logs

The tool monitors Certificate Transparency logs from these providers by default:

| Provider | Logs | Years |
|----------|------|-------|
| Google | Argon (US1), Xenon (EU1) | 2025-2026 |
| Cloudflare | Nimbus | 2025-2026 |
| DigiCert | Yeti, Wyvern, Sphinx | 2025-2026 |
| Sectigo | Sabre, Mammoth | 2025-2026 |
| Let's Encrypt | Oak | 2025-2026 |
| TrustAsia | Log A/B | 2025-2026 |

---

## Examples

### One-Time Domain Collection

```bash
# Collect domains and save to JSON
python scripts/run_monitor.py --once --output-format json --output-file domains.json

# Collect domains in CSV format for spreadsheet analysis
python scripts/run_monitor.py --once --output-format csv --output-file domains.csv
```

### Continuous Monitoring

```bash
# Monitor continuously with 30-second intervals
python scripts/run_monitor.py --continuous --poll-interval 30

# High-performance monitoring with more workers
python scripts/run_monitor.py --continuous --max-workers 20 --poll-interval 10
```

### Custom Keyword Monitoring

```bash
# Monitor for specific brand impersonation
python scripts/run_monitor.py --once --keywords "amazon,netflix,facebook,instagram"
```

### AI Phishing Detection

```bash
# Run AI analysis on new certificates only
python scripts/run_monitor.py --ai-mode --skip-catchup

# Analyze with a specific model and domain limit
python scripts/run_monitor.py --ai-mode --ai-model gemini-1.5-flash-latest --max-domains-for-ai 2000

# Use OpenRouter with DeepSeek
python scripts/run_monitor.py --ai-mode --ai-provider openrouter --ai-model deepseek/deepseek-r1
```

---

## Performance Considerations

| Setting | Low Resource | Balanced | High Performance |
|---------|--------------|----------|------------------|
| `max_workers` | 5 | 10 | 20 |
| `poll_interval` | 120 | 60 | 10-30 |
| `fetch_batch_size` | 128 | 256 | 512 |

### Recommendations

- **First Run**: Use `--skip-catchup` to avoid processing historical entries
- **Memory**: Reduce `max_workers` and `fetch_batch_size` if memory limited
- **Network**: Increase `request_timeout` on slow connections
- **AI Mode**: Use `--max-domains-for-ai` to control API costs

---

## Troubleshooting

### Common Issues

**Connection Timeouts**
- Increase `request_timeout` in configuration
- Check internet connectivity
- Some CT logs may be temporarily unavailable

**High Memory Usage**
- Reduce `max_workers` and `fetch_batch_size`
- Use `--skip-catchup` for first run

**Missing API Key Error**
- Ensure `.env` file exists with `GOOGLE_API_KEY`
- Check that the key is valid and has Gemini API access

**No Domains Found**
- Check log level with `--log-level DEBUG`
- Verify CT log URLs are accessible
- Use `--skip-catchup` to start from current position

### Debug Mode

```bash
python scripts/run_monitor.py --log-level DEBUG --once
```

---

## Files Created

| File | Description |
|------|-------------|
| `ct_monitor_state.json` | Tracks last processed log positions |
| `ct_monitor.log` | Application logs |
| `ct_run_<timestamp>_<mode>/` | Timestamped output directory for each run |
| `ct_domains.json` | Discovered domains (in run directory) |
| `phishing_analysis.txt` | AI-flagged suspicious domains (AI mode) |
| `safe_domains.txt` | AI-classified safe domains (AI mode) |

---

## Security Considerations

- CT logs are public infrastructure; no sensitive data is accessed
- Output files may contain domain information - secure appropriately
- All network traffic uses HTTPS
- API keys should be stored securely in `.env` (not committed to version control)

---

## Contributing

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/your-feature`
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

---

## License

MIT License - see [LICENSE](LICENSE) file for details.

---

## Changelog

### v1.1.0
- Added AI-powered phishing detection using Google Gemini
- Added `--skip-catchup` flag for fresh monitoring
- Added `--keywords` command line option
- Timestamped output directories for each run
- Improved suspicious domain detection with keyword matching
- Enhanced JSON output with suspicious event details

### v1.0.0
- Initial release
- Support for major CT log providers
- Multiple output formats (JSON, CSV, TXT)
- Configurable monitoring parameters
- State persistence and recovery
- Concurrent log processing

---

## Author

boredchilada

---

**Note**: This tool is designed for security research, domain monitoring, and threat intelligence purposes. Always comply with applicable laws and terms of service when using CT log data.