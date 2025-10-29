# Greaper Scanner

**Greaper** is a comprehensive command-line web application security scanner designed for penetration testing and security auditing. Built with Python, it performs automated vulnerability assessments, information gathering, and security analysis on web applications and URLs.

## Overview

Greaper combines multiple security testing capabilities into a single tool, featuring asynchronous scanning for high performance, intelligent vulnerability detection with confidence scoring, and extensive information gathering from multiple sources. It's designed for security professionals, penetration testers, and bug bounty hunters who need a versatile and efficient scanning solution.

## Key Features

### Vulnerability Scanning
- **SQL Injection (`-sqli`)** - Detects error-based, union-based, time-based, and boolean-based SQLi
- **Cross-Site Scripting (`-xss`)** - Identifies reflected XSS vulnerabilities with payload reflection
- **Local File Inclusion (`-lfi`)** - Tests for LFI vulnerabilities with OS-specific patterns
- **CORS Misconfiguration (`-cors`)** - Identifies insecure CORS policies
- **Host Header Injection (`-hh`)** - Detects host header manipulation vulnerabilities

### Information Gathering
- **Subdomain Enumeration (`-s`)** - Aggregates subdomains from 11+ sources (crt.sh, AlienVault OTX, HackerTarget, VirusTotal, SecurityTrails, and more)
- **Web Crawling (`-crawl`)** - Async site crawler with configurable depth, extracts and categorizes links
- **JavaScript Analysis (`-info`)** - Scans JS files for sensitive data (API keys, AWS credentials, JWT tokens, internal IPs, S3 buckets)
- **IP Lookup & WAF Bypass (`-ip`)** - DNS resolution, reverse DNS, WHOIS/ASN info, SSL certificate inspection, IP-based access testing

### Security Auditing
- **Security Headers (`-sec`)** - Validates 14+ security headers (HSTS, CSP, X-Frame-Options, COOP, CORP, COEP, etc.)
- **CVE Scanning (`-cve`)** - Fingerprint-based CVE detection for 20+ frameworks (WordPress, Drupal, Joomla, Apache Struts, Jenkins, GitLab, Confluence, etc.)
- **WAF Detection (`-waf`)** - Identifies major WAF providers (Cloudflare, AWS WAF, Akamai, Imperva, F5 BIG-IP ASM)

### Utility Features
- **Status Code Checking (`-sc`)** - HTTP status monitoring with color-coded output
- **Directory Fuzzing (`-df`)** - Discovers common paths (1000+ default paths or custom wordlist)
- **Content Length Check (`-cl`)** - Analyzes response sizes
- **Live URL Checking (`-lv`)** - Validates subdomain/URL accessibility
- **Dynamic Payload Generation (`-dynamic`)** - Context-aware payload creation for enhanced testing

## Prerequisites

- **Python 3.6 or newer**
- pip (Python package manager)

### Required Dependencies
```
pyfiglet>=0.8.post1      # ASCII art banners
requests>=2.31.0         # HTTP client
beautifulsoup4>=4.12.0   # HTML parsing
dnspython>=2.4.0         # DNS operations
retrying>=1.3.4          # Retry mechanisms
aiohttp>=3.9.0           # Async HTTP operations
urllib3>=2.1.0           # HTTP utilities
ipwhois>=1.2.0           # IP/WHOIS lookups
packaging>=23.2          # Version comparison
python-dotenv>=1.0.0     # Environment variable management
```

## Installation

1. **Clone the repository:**
   ```bash
   git clone https://github.com/algorethmpwd/greaper.git
   cd greaper
   ```

2. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

3. **Configure environment (optional):**
   ```bash
   # Copy the example configuration file
   cp .env.example .env

   # Edit .env and add your API keys
   # nano .env  (or use your preferred editor)
   ```

4. **Verify installation:**
   ```bash
   python3 greaper.py -h
   ```

## Configuration

Greaper uses a `.env` file for configuration. This allows you to customize settings without modifying the code.

### Setting Up API Keys

Some subdomain enumeration sources require API keys. To enable them:

1. Copy `.env.example` to `.env`:
   ```bash
   cp .env.example .env
   ```

2. Edit `.env` and add your API keys:
   ```bash
   VIRUSTOTAL_API_KEY=your_api_key_here
   SECURITYTRAILS_API_KEY=your_api_key_here
   ```

3. Enable the sources in `.env`:
   ```bash
   USE_VIRUSTOTAL=true
   USE_SECURITYTRAILS=true
   ```

### Available Configuration Options

| Setting | Default | Description |
|---------|---------|-------------|
| `GREAPER_VERSION` | `v2.0` | Scanner version displayed in banner |
| `DEFAULT_TIMEOUT` | `10` | Default timeout for requests (seconds) |
| `DEFAULT_RATE_LIMIT` | `10` | Default requests per second |
| `COLOR_OUTPUT` | `true` | Enable colored terminal output |
| `VERBOSE` | `false` | Enable verbose logging |
| `USER_AGENT` | (Mozilla) | Custom User-Agent string |
| `VERIFY_SSL` | `false` | Enable SSL certificate verification |

### Subdomain Enumeration Sources

Control which sources are used for subdomain enumeration:

**Free Sources (No API Key Required):**
- `USE_CRTSH` - Certificate Transparency logs (default: `true`)
- `USE_ALIENVAULT` - AlienVault OTX (default: `true`)
- `USE_HACKERTARGET` - HackerTarget API (default: `true`)
- `USE_THREATCROWD` - ThreatCrowd (default: `true`)
- `USE_URLSCAN` - URLScan.io (default: `true`)
- `USE_CERTSPOTTER` - CertSpotter (default: `true`)
- `USE_THREATMINER` - ThreatMiner (default: `true`)

**API Key Required:**
- `USE_VIRUSTOTAL` - VirusTotal (default: `false`)
- `USE_SECURITYTRAILS` - SecurityTrails (default: `false`)

**Disabled by Default (Reliability Issues):**
- `USE_BUFFEROVER` - BufferOver DNS (default: `false`)
- `USE_RIDDLER` - Riddler.io (default: `false`)

## Usage

Greaper supports scanning single URLs or multiple URLs from a file. Combine multiple flags for comprehensive security assessments.

### Basic Syntax
```bash
# Single URL scan
python3 greaper.py -u <url> [options]

# Multiple URLs from file
python3 greaper.py -l <file_with_urls.txt> [options]

# Save results to file
python3 greaper.py -u <url> [options] -o results.txt
```

### Using Command Profiles (NEW in v2.0)

Greaper now provides predefined scanning profiles for common scenarios:

```bash
# Quick reconnaissance
python3 greaper.py -u example.com --profile recon

# Fast security check
python3 greaper.py -u example.com --profile quick

# Comprehensive assessment
python3 greaper.py -u example.com --profile full-scan

# Bug bounty hunting
python3 greaper.py -u example.com --profile bugbounty

# Stealth mode (slow, careful)
python3 greaper.py -u example.com --profile stealth
```

**Available Profiles:**
- `recon` - Subdomain enum, crawling, info gathering
- `quick` - Status codes, security headers, WAF detection
- `full-scan` - Complete vulnerability assessment
- `bugbounty` - Balanced, thorough testing
- `stealth` - Minimal footprint, slow rate

### Output Formats (NEW in v2.0)

Save results in multiple formats:

```bash
# JSON for automation/CI-CD
python3 greaper.py -u example.com --profile recon --format json -o results.json

# HTML for professional reports
python3 greaper.py -u example.com --profile full-scan --format html -o report.html

# CSV for spreadsheet analysis
python3 greaper.py -u example.com -sqli --format csv -o vulnerabilities.csv

# Markdown for documentation
python3 greaper.py -u example.com -sec --format markdown -o security.md
```

**Supported Formats**: `txt` (default), `json`, `csv`, `html`, `markdown`

### Progress Indicators & Logging (NEW in v2.0)

Greaper now provides real-time progress tracking and structured logging:

**Progress Bars**: Automatic progress visualization during scans
```bash
# Progress bars automatically appear
python3 greaper.py -u example.com --profile recon
# Shows: Processing |████████████| 45/100 [00:23<00:12, 2.3 items/s]
```

**Scan Statistics**: Comprehensive summary at completion
```
╔══════════════════════════════════════╗
║  SCAN SUMMARY STATISTICS             ║
╠══════════════════════════════════════╣
║ Total Requests:          245         ║
║ Successful Requests:     237         ║
║ Vulnerabilities Found:   3           ║
║ Scan Duration:           45.2s       ║
╚══════════════════════════════════════╝
```

**Structured Logs**: Automatic logging to `logs/` directory
```bash
# Logs automatically created during scans
logs/
├── greaper_debug.log      # All debug messages
├── greaper_info.log       # General operations
├── greaper_errors.log     # Errors only
└── greaper_findings.log   # Vulnerabilities found

# Monitor findings in real-time
tail -f logs/greaper_findings.log

# Enable verbose console logging
VERBOSE=true python3 greaper.py -u example.com -sqli
```

### Wordlist Management (NEW in v2.0)

Greaper now supports external wordlists with intelligent fallbacks:

**Directory Structure**:
```
wordlists/
├── directories/        # Directory fuzzing
│   ├── small.txt      # 50 entries (quick)
│   ├── medium.txt     # 150 entries (balanced)
│   └── large.txt      # Custom large lists
└── subdomains/        # Subdomain enumeration
    ├── small.txt
    └── medium.txt
```

**Usage Examples**:
```bash
# Use custom wordlist file
python3 greaper.py -u example.com -df --wordlist /path/to/custom.txt

# Use organized wordlist from wordlists/ directory
python3 greaper.py -u example.com -df --wordlist wordlists/directories/medium.txt

# Automatic fallback to embedded defaults
python3 greaper.py -u example.com -df
# Uses built-in wordlist if no custom list specified
```

**Popular Wordlist Sources**:
- [SecLists](https://github.com/danielmiessler/SecLists) - Comprehensive security wordlists
- dirbuster - Classic directory fuzzing lists
- Custom lists based on target technology

See [wordlists/README.md](wordlists/README.md) for detailed setup instructions.

### Quick Start Examples

#### 1. Basic Status Code Check
```bash
python3 greaper.py -u https://example.com -sc
```

#### 2. Comprehensive Vulnerability Scan (Using Profile)
```bash
python3 greaper.py -u https://example.com --profile full-scan -o report.html --format html
```

#### 3. Information Gathering & Reconnaissance
```bash
# Subdomain enumeration
python3 greaper.py -u example.com -s

# Crawl website and analyze JS files
python3 greaper.py -u https://example.com -crawl 2 -info

# IP lookup and WAF detection
python3 greaper.py -u https://example.com -ip -waf
```

#### 4. Security Audit
```bash
python3 greaper.py -u https://example.com -sec -cve -waf
```

#### 5. Directory Fuzzing with Custom Wordlist
```bash
python3 greaper.py -u https://example.com -df -p custom_paths.txt
```

#### 6. SQL Injection with Custom Payloads
```bash
python3 greaper.py -u https://example.com/page?id=1 -sqli -p sqli_payloads.txt
```

#### 7. Mass Scanning from URL List
```bash
python3 greaper.py -l targets.txt -sec -lv -cl
```

#### 8. Full Reconnaissance and Vulnerability Assessment
```bash
python3 greaper.py -u example.com -s -crawl 3 -info -sec -cve -sqli -xss -lfi -cors -o full_scan_results.txt
```

## Command-Line Options

### Core Options
| Option | Long Form | Description |
|--------|-----------|-------------|
| `-u` | `--url` | Specify a single target URL to scan |
| `-l` | `--list` | File containing multiple URLs (one per line) |
| `-p` | `--payload-file` | Custom payload file for vulnerability scans |
| `-o` | `--output` | Save scan results to output file |

### Vulnerability Scanning
| Option | Description |
|--------|-------------|
| `-sqli` | SQL Injection detection (error-based, union-based, time-based, boolean-based) |
| `-xss` | Cross-Site Scripting vulnerability scan (requires `-p` for custom payloads) |
| `-lfi` | Local File Inclusion vulnerability scan (requires `-p` for custom payloads) |
| `-cors` | Test for CORS misconfiguration vulnerabilities |
| `-hh` | Host Header Injection vulnerability detection |
| `-dynamic` | Enable dynamic payload generation for context-aware testing |

### Information Gathering
| Option | Description |
|--------|-------------|
| `-s`, `--sub-enum` | Subdomain enumeration from 11+ sources |
| `-crawl [depth]` | Crawl website and extract links (specify depth, default: 2) |
| `-info` | Scan JavaScript files for sensitive information (API keys, tokens, credentials) |
| `-ip` | Perform comprehensive IP lookup, DNS resolution, WHOIS, and bypass attempts |
| `-waf` | Detect Web Application Firewall (WAF) presence and type |

### Security Auditing
| Option | Description |
|--------|-------------|
| `-sec` | Check security headers (HSTS, CSP, X-Frame-Options, COOP, CORP, etc.) |
| `-cve` | Scan for known CVEs based on technology fingerprinting |

### Utility Functions
| Option | Description |
|--------|-------------|
| `-sc` | Check HTTP status codes with color-coded output |
| `-df` | Directory and path fuzzing (1000+ default paths or custom wordlist) |
| `-cl` | Check and compare content length of responses |
| `-lv` | Verify if URLs/subdomains are live and accessible |
| `--rate-limit` | Configure rate limiting for requests (prevent rate limiting/blocking) |

## Advanced Features

### Asynchronous Operations
Greaper uses `asyncio` and `aiohttp` for high-performance concurrent operations, particularly for:
- Subdomain enumeration across multiple sources
- Website crawling with depth control
- Parallel URL processing with ThreadPoolExecutor

### Intelligent Detection
- **Confidence Scoring**: Reduces false positives by analyzing multiple indicators
- **Pattern Matching**: Uses comprehensive regex patterns for vulnerability detection
- **Context-Aware Payloads**: Dynamic payload generation based on detected technologies
- **Error Analysis**: Analyzes error messages and response patterns for SQLi detection

### Rate Limiting & Safety
- Configurable rate limiting via `--rate-limit` to prevent overwhelming targets
- Request timeout configurations (5-10 seconds typical)
- Retry mechanisms with exponential backoff
- Session management with connection pooling

## Supported Technologies for CVE Detection

Greaper can identify and check CVEs for 20+ frameworks and technologies:
- **CMS**: WordPress, Drupal, Joomla, Magento
- **Frameworks**: Apache Struts, Spring Boot, Laravel, Django
- **CI/CD**: Jenkins, GitLab
- **Collaboration**: Confluence, Jira
- **Databases**: Elasticsearch, MongoDB
- **Web Servers**: Apache, Nginx, Tomcat
- And many more...

## Subdomain Enumeration Sources

Greaper aggregates subdomains from multiple authoritative sources:
- crt.sh (Certificate Transparency logs)
- AlienVault OTX
- HackerTarget
- Riddler.io
- BufferOver
- ThreatCrowd
- URLScan.io
- VirusTotal
- SecurityTrails
- CertSpotter
- ThreatMiner

## Output Examples

### Status Code Check
```
[200] https://example.com - OK
[404] https://example.com/notfound - Not Found
[301] https://example.com/redirect - Moved Permanently
```

### Security Headers Analysis
```
Security Headers for https://example.com:
✓ Strict-Transport-Security: max-age=31536000
✗ Content-Security-Policy: Missing
✓ X-Frame-Options: SAMEORIGIN
✗ X-Content-Type-Options: Missing
```

### JavaScript Sensitive Info Detection
```
Found sensitive information in https://example.com/app.js:
- API Key: AIzaSyD... (Google API Key pattern)
- AWS Access Key: AKIA... (AWS Credentials pattern)
- Internal IP: 192.168.1.50
```

## Best Practices

1. **Always Get Authorization**: Only scan targets you have explicit permission to test
2. **Use Rate Limiting**: Prevent overwhelming target servers with `--rate-limit`
3. **Start with Reconnaissance**: Begin with `-s`, `-crawl`, and `-info` before vulnerability scanning
4. **Combine Scans**: Use multiple flags together for comprehensive assessments
5. **Save Results**: Always use `-o` to maintain audit trails
6. **Custom Payloads**: Use `-p` with custom payload files for targeted testing
7. **Verify Findings**: Manually verify all detected vulnerabilities to avoid false positives

## Legal Disclaimer

This tool is intended for authorized security testing, penetration testing, and educational purposes only. Users must ensure they have explicit permission to test target systems. Unauthorized access to computer systems is illegal. The developers assume no liability and are not responsible for any misuse or damage caused by this tool.

## Troubleshooting

### Common Issues

**SSL Certificate Errors**
- Greaper disables SSL verification by default for testing purposes
- If you need strict SSL verification, modify the code accordingly

**Connection Timeouts**
- Increase timeout values if scanning slow-responding targets
- Check network connectivity and target availability

**Rate Limiting/Blocking**
- Use `--rate-limit` flag to slow down requests
- Some targets may block automated scanners; consider using proxy rotation

**Permission Errors**
- Ensure Python and pip are properly installed
- Run with appropriate permissions for network operations

## Contributing

Contributions are welcome! Feel free to:
- Report bugs and issues
- Suggest new features
- Submit pull requests
- Improve documentation

## Repository

GitHub: https://github.com/algorethmpwd/greaper.git

## Author

algorethm

## License

Please refer to the repository for license information.

---

**Note**: URLs in input files should include `http://` or `https://` protocol. Results display in the terminal with color-coded output and can be saved to a file using `-o` option.
