# 🕷️ Greaper - Advanced Web Application Security Scanner

<div align="center">

```
  ██████  ██████  ███████  █████  ██████  ███████ ██████  
 ██       ██   ██ ██      ██   ██ ██   ██ ██      ██   ██ 
 ██   ███ ██████  █████   ███████ ██████  █████   ██████  
 ██    ██ ██   ██ ██      ██   ██ ██      ██      ██   ██ 
  ██████  ██   ██ ███████ ██   ██ ██      ███████ ██   ██ 
```

**A Modern, Modular Web Application Security Testing Framework**

[![Version](https://img.shields.io/badge/version-2.0-blue.svg)](https://github.com/algorethmpwd/greaper)
[![Python](https://img.shields.io/badge/python-3.8+-green.svg)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-MIT-orange.svg)](LICENSE)
[![Payloads](https://img.shields.io/badge/payloads-2025-red.svg)]()

[Features](#-features) • [Installation](#-installation) • [Usage](#-usage) • [Architecture](#-architecture) • [Contributing](#-contributing) • [💝 Donate](#-support-this-project)

---

### 💖 Support Development

<div align="center">

**If Greaper helped you find bugs or vulnerabilities, consider supporting development!**

[![Donate Bitcoin](https://img.shields.io/badge/₿_Bitcoin-F7931A?style=for-the-badge&logo=bitcoin&logoColor=white)](https://www.blockchain.com/explorer/addresses/btc/15MG2nFd9mpx1x2oR2shBfqiNjeo4VWEqk)
[![Donate Ethereum](https://img.shields.io/badge/Ξ_Ethereum-627EEA?style=for-the-badge&logo=ethereum&logoColor=white)](https://etherscan.io/address/0x8c0b61567ab141f129fa114d0d74951b37290ac1)
[![Donate USDT](https://img.shields.io/badge/₮_USDT_(TRC20)-26A17B?style=for-the-badge&logo=tether&logoColor=white)](https://tronscan.org/#/address/TKtLZjLbsWa8st3Zr6qwzAewD1x5bdcFGs)


**BTC**: `15MG2nFd9mpx1x2oR2shBfqiNjeo4VWEqk` | **ETH**: `0x8c0b61567ab141f129fa114d0d74951b37290ac1` | **USDT**: `TKtLZjLbsWa8st3Zr6qwzAewD1x5bdcFGs`

</div>

</div>

---

## 📋 Table of Contents

- [Overview](#-overview)
- [Key Features](#-features)
- [Architecture](#-architecture)
- [Installation](#-installation)
- [Quick Start](#-quick-start)
- [Modules](#-modules)
- [Scan Profiles](#-scan-profiles)
- [Advanced Usage](#-advanced-usage)
- [Payload Information](#-payload-information)
- [Output Formats](#-output-formats)
- [Performance](#-performance)
- [Roadmap](#-roadmap)
- [Contributing](#-contributing)
- [Disclaimer](#%EF%B8%8F-disclaimer)

---

## 🎯 Overview

**Greaper** is a next-generation web application security testing framework designed for bug bounty hunters, penetration testers, and security researchers. Built from the ground up with a modular architecture, Greaper combines **cutting-edge 2025 exploit techniques** with traditional vulnerability detection methods.

### 🌟 What Makes Greaper Different?

- **🔥 2025 Payloads**: Updated with the latest WAF bypasses, CSP bypasses, and modern exploit techniques
- **🧩 Modular Design**: Clean separation of concerns with 27+ specialized modules
- **⚡ Async Operations**: Lightning-fast scanning with asynchronous requests
- **🎨 Beautiful Output**: Color-coded, organized results with multiple export formats
- **🔍 Deep Crawling**: Intelligent web crawler with depth control and link categorization
- **🛡️ Smart Detection**: Advanced pattern matching and behavioral analysis

---

## ✨ Features

### 🔐 Vulnerability Scanners

| Scanner | Description | 2025 Payloads | Status |
|---------|-------------|---------------|--------|
| **SQL Injection** | Error-based, Time-based, Union-based, NoSQL | ✅ 67 payloads | Stable |
| **XSS** | Reflected, Stored, DOM-based, mXSS, CSP bypass | ✅ 72 payloads | Stable |
| **LFI/Path Traversal** | File inclusion, PHP wrappers, Cloud metadata | ✅ 135 payloads | Stable |
| **CORS** | Misconfiguration detection, Origin reflection | ✅ | Stable |
| **Host Header Injection** | Cache poisoning, Password reset | ✅ | Stable |
| **SSRF** | Cloud metadata, Internal network, Protocol smuggling | ✅ 115 payloads | **New!** |
| **XXE** | File disclosure, SSRF, DoS, OOB | ✅ 28 payloads | **New!** |

### 🕵️ Information Gathering

- **Subdomain Enumeration**: 11+ sources (crt.sh, AlienVault, HackerTarget, etc.)
- **Web Crawler**: Async crawler with depth control, finds 10,000+ URLs
- **JavaScript Analysis**: Scans for API keys, secrets, internal paths
- **CVE Scanner**: Framework detection and version fingerprinting
- **Security Headers**: Checks 10 critical security headers
- **WAF Detection**: Identifies Cloudflare, AWS, Akamai, Imperva, F5
- **IP Lookup**: ASN information, reverse DNS, WAF bypass testing

### 🛠️ Utilities

- **Directory Fuzzer**: Custom wordlists, status code filtering
- **Content Length Checker**: Response size analysis
- **Live URL Checker**: Multi-protocol validation (HTTP, HTTPS, FTP)
- **Status Checker**: HTTP status codes with redirect tracking

---

## 🏗️ Architecture

Greaper follows a clean, modular architecture for maintainability and extensibility:

```
┌─────────────────────────────────────────────────────────────┐
│                     GREAPER ARCHITECTURE                    │
└─────────────────────────────────────────────────────────────┘

┌─────────────────────┐
│   greaper.py        │  ◄── Main Entry Point
│  (329 lines)        │
└──────────┬──────────┘
           │
           ├──────────────────────────────────────────────────┐
           │                                                   │
           ▼                                                   ▼
┌──────────────────────┐                         ┌─────────────────────┐
│  CORE INFRASTRUCTURE │                         │   SCAN PROFILES     │
├──────────────────────┤                         ├─────────────────────┤
│ • Config Manager     │                         │ • recon             │
│ • Logger System      │                         │ • quick             │
│ • Progress Tracker   │                         │ • full-scan         │
│ • Wordlist Manager   │                         │ • bugbounty         │
│ • Output Formatters  │                         │ • stealth           │
└──────────┬───────────┘                         └─────────────────────┘
           │
    ┌──────┴──────┬──────────────┬────────────┐
    │             │              │            │
    ▼             ▼              ▼            ▼
┌────────┐   ┌────────┐    ┌────────┐   ┌────────┐
│SCANNERS│   │ENUM... │    │UTILS   │   │OUTPUT  │
└────────┘   └────────┘    └────────┘   └────────┘
    │             │              │            │
    ├─SQLi        ├─Subdomain    ├─StatusCk   ├─JSON
    ├─XSS         ├─Crawler      ├─WAF        ├─HTML
    ├─LFI         └─JS Scanner   ├─CVE        ├─CSV
    ├─CORS                       ├─DirFuzz    ├─Markdown
    ├─HostHdr                    ├─ContentLen └─TXT
    ├─SSRF                       ├─LiveCheck
    └─XXE                        ├─SecHeaders
                                 └─IPLookup

        ┌────────────────────────────────────┐
        │      REQUEST FLOW DIAGRAM          │
        └────────────────────────────────────┘

User Input
    │
    ▼
┌────────────┐
│  CLI Args  │
└─────┬──────┘
      │
      ▼
┌────────────┐
│  Profile?  │───Yes──►┌──────────────┐
└─────┬──────┘         │ Apply Flags  │
      No               └──────┬───────┘
      │                       │
      │◄──────────────────────┘
      ▼
┌────────────┐
│ Load URLs  │
└─────┬──────┘
      │
      ▼
┌────────────┐
│ Initialize │
│  Scanner   │
└─────┬──────┘
      │
      ▼
┌────────────┐
│Load Payloads│
│ (2025 Set) │
└─────┬──────┘
      │
      ▼
┌────────────┐
│  Execute   │──►┌──────────┐
│   Scan     │   │  Async   │
└─────┬──────┘   │ Requests │
      │          └──────────┘
      ▼
┌────────────┐
│  Analyze   │
│ Response   │
└─────┬──────┘
      │
      ▼
┌────────────┐
│   Report   │──►┌──────────┐
│  Results   │   │  Save to │
└────────────┘   │   File   │
                 └──────────┘
```

### Module Organization

```
greaper/
├── greaper.py                 # Main entry point (329 lines)
├── greaper_core/
│   ├── __init__.py
│   ├── config.py             # Configuration management
│   ├── logger.py             # Multi-file logging
│   ├── progress.py           # Scan progress tracking
│   ├── wordlist.py           # Wordlist management
│   │
│   ├── scanners/             # Vulnerability scanners
│   │   ├── base.py           # Base scanner class
│   │   ├── sqli.py           # SQL Injection (67 payloads)
│   │   ├── xss.py            # XSS (72 payloads)
│   │   ├── lfi.py            # LFI (135 payloads)
│   │   ├── cors.py           # CORS misconfig
│   │   ├── host_header.py    # Host header injection
│   │   ├── ssrf.py           # SSRF (115 payloads) ⭐ NEW
│   │   └── xxe.py            # XXE (28 payloads) ⭐ NEW
│   │
│   ├── enumerators/          # Information gathering
│   │   ├── subdomain.py      # Subdomain enumeration
│   │   ├── crawler.py        # Web crawler
│   │   └── js_scanner.py     # JavaScript analysis
│   │
│   ├── utils/                # Utility modules
│   │   ├── status_checker.py
│   │   ├── waf_detector.py
│   │   ├── cve_scanner.py
│   │   ├── directory_fuzzer.py
│   │   ├── content_length.py
│   │   ├── live_checker.py
│   │   ├── security_headers.py
│   │   └── ip_lookup.py
│   │
│   └── output/               # Output formatting
│       └── formatters.py     # Multi-format export
│
└── logs/                     # Auto-generated logs
    ├── debug.log
    ├── info.log
    ├── errors.log
    └── findings.log
```

---

## 🚀 Installation

### Prerequisites

- Python 3.8 or higher
- pip package manager
- Internet connection (for subdomain enumeration)

### Quick Install

```bash
# Clone the repository
git clone https://github.com/algorethmpwd/greaper.git
cd greaper

# Install dependencies
pip3 install -r requirements.txt

# Verify installation
python3 greaper.py --help
```

### Dependencies

```
requests>=2.31.0
beautifulsoup4>=4.12.0
aiohttp>=3.9.0
tqdm>=4.66.0
colorama>=0.4.6
python-dotenv>=1.0.0
retrying>=1.3.4
ipwhois>=1.2.0
```

---

## 🎮 Quick Start

### Basic Scans

```bash
# SQL Injection scan
python3 greaper.py -u "https://example.com/page?id=1" -sqli

# XSS scan with custom payloads
python3 greaper.py -u "https://example.com/search?q=test" -xss -p payloads.txt

# SSRF scan (NEW!)
python3 greaper.py -u "https://example.com/fetch?url=test" -ssrf

# XXE scan (NEW!)
python3 greaper.py -u "https://example.com/api/xml" -xxe

# Web crawl (depth 3)
python3 greaper.py -u "https://example.com" -crawl 3

# Security headers check
python3 greaper.py -u "https://example.com" -sec

# Subdomain enumeration
python3 greaper.py -u "example.com" -s
```

### Using Scan Profiles

```bash
# Quick scan (status, headers, WAF, CORS)
python3 greaper.py -u "https://example.com" --profile quick

# Reconnaissance (subdomain, crawl, JS scan, headers, WAF)
python3 greaper.py -u "https://example.com" --profile recon

# Full vulnerability scan (all scanners, depth 3)
python3 greaper.py -u "https://example.com" --profile full-scan

# Bug bounty mode (aggressive, depth 4, all scanners)
python3 greaper.py -u "https://example.com" --profile bugbounty

# Stealth mode (slow, careful scanning)
python3 greaper.py -u "https://example.com" --profile stealth
```

### Batch Scanning

```bash
# Scan multiple URLs from file
python3 greaper.py -l urls.txt -sqli -o results.txt

# Content length check for URL list
python3 greaper.py -l urls.txt -cl

# Live URL checker
python3 greaper.py -l urls.txt -lv
```

---

## 📦 Modules

### 🔴 SQL Injection Scanner

**Modern 2025 Techniques:**
- Error-based injection with WAF bypasses
- Time-based blind SQLi (MySQL, MSSQL, PostgreSQL)
- Union-based injection with NULL padding
- NoSQL injection (MongoDB operators)
- JSON-based SQLi for modern APIs
- Advanced encoding bypasses (Unicode, double encoding)

**Example:**
```bash
python3 greaper.py -u "https://example.com/user?id=1" -sqli
```

**Payloads Include:**
- `' OR 1=1-- -` (Classic boolean)
- `' /*!50000OR*/ 1=1-- -` (MySQL comment bypass)
- `{"$gt": ""}` (NoSQL MongoDB)
- `' AND SLEEP(5)--` (Time-based blind)
- `' UNION SELECT NULL,NULL,NULL--` (Union-based)

---

### 🟠 XSS Scanner

**Modern 2025 Techniques:**
- DOM-based XSS detection
- CSP bypass methods
- Mutation XSS (mXSS)
- Template injection (Angular, React, Vue)
- Event handler obfuscation
- Polyglot XSS payloads

**Example:**
```bash
python3 greaper.py -u "https://example.com/search?q=test" -xss
```

**Payloads Include:**
- `<script>alert(1)</script>` (Classic)
- `<img src=x onerror=eval(atob('YWxlcnQoMSk='))>` (Base64 bypass)
- `{{constructor.constructor('alert(1)')()}}` (Template injection)
- `<svg/onload=alert(1)>` (SVG-based)
- Polyglot payloads for multiple contexts

---

### 🟡 LFI/Path Traversal Scanner

**Modern 2025 Techniques:**
- PHP wrapper exploitation
- Cloud metadata access (AWS, GCP, Azure)
- Container escape techniques
- Unicode bypass methods
- Null byte injection
- Kubernetes secret access

**Example:**
```bash
python3 greaper.py -u "https://example.com/download?file=test.pdf" -lfi
```

**Payloads Include:**
- `../../../etc/passwd` (Classic)
- `php://filter/convert.base64-encode/resource=index.php` (PHP wrapper)
- `file:///var/run/secrets/kubernetes.io/serviceaccount/token` (K8s)
- `http://169.254.169.254/latest/meta-data/` (AWS metadata)
- `%c0%ae%c0%ae/%c0%ae%c0%ae/etc/passwd` (Unicode bypass)

---

### 🔵 SSRF Scanner ⭐ NEW

**Modern 2025 Techniques:**
- Cloud metadata exploitation (AWS IMDSv2, GCP, Azure)
- Internal network scanning
- Protocol smuggling (gopher, dict, file)
- DNS rebinding attacks
- IPv6 localhost variations
- Bypass techniques (encoding, DNS tricks)

**Example:**
```bash
python3 greaper.py -u "https://example.com/proxy?url=test" -ssrf
```

**Payloads Include:**
- `http://169.254.169.254/latest/meta-data/iam/security-credentials/`
- `http://metadata.google.internal/computeMetadata/v1/`
- `gopher://127.0.0.1:6379/_` (Redis exploitation)
- `http://127.0.0.1.nip.io` (DNS bypass)
- `http://[::1]` (IPv6 localhost)

---

### 🟣 XXE Scanner ⭐ NEW

**Modern 2025 Techniques:**
- File disclosure via DTD
- SSRF through XXE
- Out-of-band (OOB) data exfiltration
- Billion laughs attack
- SVG file XXE
- Error-based XXE

**Example:**
```bash
python3 greaper.py -u "https://example.com/api/parse" -xxe
```

**Payloads Include:**
- Classic file disclosure (`file:///etc/passwd`)
- Cloud credentials (`file:///home/user/.aws/credentials`)
- Parameter entity attacks
- SOAP XXE
- Office document XXE (DOCX/XLSX)

---

## 🎯 Scan Profiles

Greaper includes 5 pre-configured scan profiles for different use cases:

### 1. 🔍 Recon Profile
**Purpose**: Information gathering and reconnaissance  
**Modules**: Subdomain enum, Crawler (depth 2), JS scan, Security headers, WAF detection

```bash
python3 greaper.py -u "example.com" --profile recon
```

---

### 2. ⚡ Quick Profile
**Purpose**: Fast security assessment  
**Modules**: Status check, Security headers, WAF, CORS

```bash
python3 greaper.py -u "https://example.com" --profile quick
```

---

### 3. 🔬 Full-Scan Profile
**Purpose**: Comprehensive vulnerability assessment  
**Modules**: ALL scanners, Crawler (depth 3), Subdomain enum

```bash
python3 greaper.py -u "https://example.com" --profile full-scan
```

**Includes:**
- SQLi, XSS, LFI, CORS, Host Header, SSRF, XXE
- CVE scanner, JS analysis
- Security headers check

---

### 4. 💰 Bug Bounty Profile
**Purpose**: Aggressive bug bounty hunting  
**Modules**: All vulnerability scanners, Deep crawl (depth 4), Subdomain enum  
**Rate Limit**: 2 req/sec (respectful)

```bash
python3 greaper.py -u "https://example.com" --profile bugbounty
```

---

### 5. 🥷 Stealth Profile
**Purpose**: Slow, careful scanning to avoid detection  
**Modules**: Status check, Security headers, CORS  
**Rate Limit**: 1 req/sec (very slow)

```bash
python3 greaper.py -u "https://example.com" --profile stealth
```

---

## 🎓 Advanced Usage

### Custom Payloads

Create custom payload files for targeted testing:

```bash
# SQLi payloads
echo "' OR '1'='1" > sqli_payloads.txt
echo "admin'--" >> sqli_payloads.txt
python3 greaper.py -u "https://example.com/?id=1" -sqli -p sqli_payloads.txt

# XSS payloads
echo "<script>alert(document.cookie)</script>" > xss_payloads.txt
python3 greaper.py -u "https://example.com/search" -xss -p xss_payloads.txt
```

### Output Formats

```bash
# JSON output
python3 greaper.py -u "https://example.com" -sec --format json -o results.json

# HTML report
python3 greaper.py -u "https://example.com" -sec --format html -o report.html

# CSV for spreadsheets
python3 greaper.py -u "https://example.com" -sec --format csv -o results.csv

# Markdown for documentation
python3 greaper.py -u "https://example.com" -sec --format markdown -o report.md
```

### Rate Limiting

```bash
# Slow scan (1 request per second)
python3 greaper.py -u "https://example.com" -sqli --rate-limit 1

# Faster scan (5 requests per second)
python3 greaper.py -u "https://example.com" -sqli --rate-limit 5
```

### Combining Multiple Scans

```bash
# Multiple vulnerabilities in one command
python3 greaper.py -u "https://example.com" -sqli -xss -lfi -ssrf -o all_vulns.txt

# Full enumeration
python3 greaper.py -u "example.com" -s -crawl 2 -info -ip -o recon_results.txt
```

---

## 🧬 Payload Information

### Payload Statistics (2025 Update)

| Vulnerability | Total Payloads | WAF Bypasses | Cloud-Specific | 
|--------------|----------------|--------------|----------------|
| SQL Injection | 67 | 15 | 8 (NoSQL) |
| XSS | 72 | 22 | 12 (CSP bypass) |
| LFI | 135 | 18 | 25 (Cloud metadata) |
| SSRF | 115 | 12 | 35 (AWS/GCP/Azure) |
| XXE | 28 | 5 | 8 (K8s/Docker) |
| **TOTAL** | **417** | **72** | **88** |

### Modern Bypass Techniques Included

✅ **WAF Bypasses:**
- Comment injection (`/*!50000OR*/`)
- Double URL encoding
- Unicode normalization
- Case variation
- Null byte injection

✅ **CSP Bypasses:**
- Base64 encoding
- `data:` URIs
- JSONP endpoints
- Trusted domain abuse

✅ **Cloud-Specific:**
- AWS IMDSv2 exploitation
- GCP metadata API
- Azure IMDS
- Kubernetes secrets
- Docker socket access

---

## 📊 Output Formats

### Terminal Output

Color-coded, organized output:
```
[*] Starting Greaper SQLi scanner on https://example.com
[+] Loaded 67 SQLi payloads

[!] SQL Injection found!
    Parameter: id
    Payload: ' OR 1=1--
    Type: Error-based
    Evidence: MySQL error detected

[-] No SQLi for payload: ' UNION SELECT NULL--
[+] Scan complete: 1 vulnerability found
```

### JSON Export

```json
{
  "target": "https://example.com",
  "scan_type": "sqli",
  "timestamp": "2025-12-03T23:00:00",
  "vulnerabilities": [
    {
      "type": "SQL Injection",
      "severity": "high",
      "parameter": "id",
      "payload": "' OR 1=1--",
      "evidence": "MySQL error detected"
    }
  ]
}
```

### HTML Report

Professional HTML reports with:
- Executive summary
- Vulnerability details
- Severity ratings
- Remediation advice
- Color-coded findings

---

## ⚡ Performance

### Benchmarks

| Operation | Time | Notes |
|-----------|------|-------|
| SQLi scan (67 payloads) | ~15s | Single parameter |
| XSS scan (72 payloads) | ~18s | Single parameter |
| Web crawl (depth 2) | ~8s | 18 pages found |
| Subdomain enum | ~45s | 11 sources |
| Full scan profile | ~3-5min | Complete assessment |

### Optimization Features

- ✅ Async HTTP requests
- ✅ Connection pooling
- ✅ Request rate limiting
- ✅ Smart retry mechanism
- ✅ Response caching

---

## 🗺️ Roadmap

### Version 2.1 (Coming Soon)
- [ ] Command Injection scanner
- [ ] Deserialization vulnerability detection
- [ ] GraphQL endpoint testing
- [ ] WebSocket security testing
- [ ] API fuzzing module

### Version 3.0 (Future)
- [ ] Machine learning-based detection
- [ ] Web UI dashboard
- [ ] Database backend for results
- [ ] Distributed scanning
- [ ] Docker containerization
- [ ] CI/CD integration

---

## 🤝 Contributing

Contributions are welcome! Here's how you can help:

1. **Report Bugs**: Open an issue with detailed information
2. **Suggest Features**: Share your ideas in the issues
3. **Submit Pull Requests**: Fork, code, test, and submit
4. **Add Payloads**: Share new 2025 bypass techniques
5. **Improve Documentation**: Fix typos, add examples

### Development Setup

```bash
git clone https://github.com/algorethmpwd/greaper.git
cd greaper
pip3 install -r requirements.txt
python3 greaper.py --help
```

---

## 📜 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## ⚠️ Disclaimer

**IMPORTANT**: Greaper is designed for **authorized security testing only**.

```
⚠️  WARNING: Unauthorized use of this tool is illegal!

✅ AUTHORIZED USE:
   - Penetration testing with written permission
   - Bug bounty programs
   - Your own applications and infrastructure
   - Security research in controlled environments
   - Educational purposes (test labs only)

❌ PROHIBITED USE:
   - Scanning systems without permission
   - Attacking production systems you don't own
   - Violating computer fraud laws
   - Causing damage or disruption

The developers assume NO responsibility for misuse of this tool.
Always obtain proper authorization before testing.
```

---

## 👨‍💻 Author

**Algorethm**
- GitHub: [@algorethmpwd](https://github.com/algorethmpwd)
- Youtube: [@algorethm_](https://www.youtube.com/@algorethm_)
- Site: https://algorethmpwd.site
- Telegram: t.me/algorethm
---

## 🙏 Acknowledgments

- **OWASP** for vulnerability classification
- **Bug bounty community** for payload research
- **Security researchers** worldwide
- **Open source contributors**

---

## 📞 Support

- 🐛 **Report Bugs**: [GitHub Issues](https://github.com/algorethmpwd/greaper/issues)
- 💬 **Discussions**: [GitHub Discussions](https://github.com/algorethmpwd/greaper/discussions)
- 📧 **Email**: mysteryhackeral@gmail.com
- 🐦 **Twitter**: @algorethm

---

## 💝 Support This Project

If Greaper has helped you in bug bounty hunting, penetration testing, or security research, consider supporting its development!

### Cryptocurrency Donations

<div align="center">

| Currency | Address |
|----------|---------|
| **₿ Bitcoin (BTC)** | `15MG2nFd9mpx1x2oR2shBfqiNjeo4VWEqk` |
| **Ξ Ethereum (ERC20)** | `0x8c0b61567ab141f129fa114d0d74951b37290ac1` |
| **₮ USDT (TRC20)** | `TKtLZjLbsWa8st3Zr6qwzAewD1x5bdcFGs` |

</div>

### Why Support?

Your donations help:
- 🔬 **Research new vulnerability techniques** and exploit methods
- 🛠️ **Develop new scanner modules** (RCE, GraphQL, WebSocket testing)
- 📚 **Maintain comprehensive documentation** and tutorials
- 🐛 **Fix bugs and improve stability** for production use
- 🚀 **Add cutting-edge 2025 payloads** from active bug bounty research
- ⚡ **Performance optimization** and async improvements
- 🎓 **Create educational content** and video tutorials

### Other Ways to Support

- ⭐ **Star this repository** to increase visibility
- 🐦 **Share on Twitter/LinkedIn** with #Greaper #BugBounty
- 📝 **Write a blog post** about your findings with Greaper
- 🤝 **Contribute** code, payloads, or bug fixes
- 💬 **Help others** in GitHub discussions
- 📢 **Spread the word** in the security community

---

<div align="center">

**Made for the security community**

⭐ Star this repo if you find it useful!

[![GitHub stars](https://img.shields.io/github/stars/algorethm/greaper?style=social)](https://github.com/algorethmpwd/greaper)
[![GitHub forks](https://img.shields.io/github/forks/algorethmpwd/greaper?style=social)](https://github.com/algorethmpwd/greaper/fork)

### Thank you to all supporters! 🙏

*Every contribution, no matter how small, makes a difference in keeping this project active and improving.*

</div>
