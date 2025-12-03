# Greaper Scanner - Modular Architecture

## Overview

Greaper has been refactored into a clean, modular architecture that separates concerns and improves maintainability, testability, and extensibility.

## Directory Structure

```
greaper/
├── greaper.py                      # Main entry point (streamlined)
├── greaper_old.py                  # Original monolithic version (backup)
├── greaper_core/                   # Core package
│   ├── __init__.py                # Package initialization
│   ├── config.py                  # Configuration management
│   ├── logger.py                  # Logging system
│   ├── progress.py                # Progress tracking
│   ├── wordlist.py                # Wordlist management
│   ├── scanners/                  # Vulnerability scanners
│   │   ├── __init__.py
│   │   ├── base.py               # Base scanner class
│   │   ├── sqli.py               # SQL Injection scanner
│   │   ├── xss.py                # XSS scanner
│   │   ├── lfi.py                # LFI scanner
│   │   ├── cors.py               # CORS scanner
│   │   └── host_header.py        # Host Header Injection scanner
│   ├── enumerators/               # Information gathering
│   │   ├── __init__.py
│   │   └── subdomain.py          # Subdomain enumeration
│   ├── utils/                     # Utility functions
│   │   ├── __init__.py
│   │   ├── status_checker.py     # Status code checker
│   │   └── waf_detector.py       # WAF detection
│   └── output/                    # Output formatting
│       ├── __init__.py
│       └── formatters.py         # Multi-format output
├── logs/                          # Auto-generated logs
├── wordlists/                     # External wordlists
└── requirements.txt               # Dependencies
```

## Architecture Benefits

### 1. **Separation of Concerns**
- Each module has a single, well-defined responsibility
- Scanners are isolated and independent
- Core functionality separated from specific implementations

### 2. **Maintainability**
- Easy to locate and modify specific functionality
- Changes to one scanner don't affect others
- Clear file organization

### 3. **Testability**
- Each module can be tested independently
- Mock dependencies easily
- Unit test individual components

### 4. **Extensibility**
- Add new scanners by creating new files in `scanners/`
- Inherit from `BaseScanner` for consistent behavior
- Plug-and-play architecture

### 5. **Reusability**
- Common functionality in base classes
- Shared utilities across scanners
- Configuration centralized

## Core Components

### Config (`greaper_core/config.py`)
Centralized configuration management:
- Environment variable handling
- API keys and credentials
- Network settings (timeout, rate limiting, SSL)
- Color codes for terminal output
- Feature toggles for subdomain sources

### Logger (`greaper_core/logger.py`)
Structured logging system:
- Multiple log files (debug, info, error, findings)
- Automatic log directory creation
- Configurable verbosity
- Timestamped entries

### Progress (`greaper_core/progress.py`)
Progress tracking and statistics:
- Real-time progress bars with tqdm
- Scan statistics (requests, success rate, vulnerabilities)
- Summary reports
- Performance metrics

### BaseScanner (`greaper_core/scanners/base.py`)
Base class for all vulnerability scanners:
- Session management
- Retry mechanism with exponential backoff
- Common request methods
- Result saving functionality

## Scanner Modules

### SQL Injection Scanner (`sqli.py`)
- Error-based detection
- Time-based blind SQLi
- Boolean-based detection
- Union-based detection
- Custom payload support

### XSS Scanner (`xss.py`)
- Reflected XSS detection
- Payload reflection checking
- Custom payload support
- URL encoding handling

### LFI Scanner (`lfi.py`)
- Multiple file inclusion patterns
- OS-specific detection (Unix/Windows)
- Pattern matching for common files
- Baseline comparison

### CORS Scanner (`cors.py`)
- Origin reflection detection
- Wildcard with credentials check
- Dangerous methods detection
- Multiple test origins

### Host Header Injection Scanner (`host_header.py`)
- Multiple header injection techniques
- Confidence scoring
- False positive reduction
- Baseline comparison

## Enumeration Modules

### Subdomain Enumerator (`subdomain.py`)
- Asynchronous multi-source enumeration
- 11+ enumeration sources
- DNS resolution
- Result deduplication
- Configurable source toggles

## Utility Modules

### Status Checker (`status_checker.py`)
- HTTP status code checking
- Redirect chain tracking
- Color-coded output
- File output support

### WAF Detector (`waf_detector.py`)
- Signature-based detection
- Behavioral detection
- Multiple WAF identification (Cloudflare, AWS, Akamai, etc.)
- Header fingerprinting

## Output Formatters

### OutputFormatter (`formatters.py`)
Multi-format support:
- **Text** (default): Plain text output
- **JSON**: Machine-readable, for automation
- **CSV**: Spreadsheet import
- **HTML**: Professional reports
- **Markdown**: Documentation-friendly

## Usage Examples

### Basic Scanning
```bash
# SQL Injection scan
python3 greaper.py -u "https://target.com?id=1" -sqli

# CORS misconfiguration check
python3 greaper.py -u https://target.com -cors

# WAF detection
python3 greaper.py -u https://target.com -waf

# Subdomain enumeration
python3 greaper.py -u example.com -s
```

### Using Profiles
```bash
# Quick reconnaissance
python3 greaper.py -u example.com --profile recon

# Comprehensive scan
python3 greaper.py -u example.com --profile full-scan

# Stealth mode
python3 greaper.py -u example.com --profile stealth
```

### Output Formats
```bash
# JSON output
python3 greaper.py -u example.com -cors --format json -o results.json

# HTML report
python3 greaper.py -u example.com -s --format html -o report.html
```

## Extending Greaper

### Adding a New Scanner

1. Create new file in `greaper_core/scanners/`:
```python
from .base import BaseScanner
from ..config import Config

class MyScanner(BaseScanner):
    def scan(self):
        print(f"{Config.COLOR_BLUE}[*] Starting my scan{Config.COLOR_RESET}")
        # Implement scan logic
        response = self.make_request(self.target)
        # Analyze and store results
        self.results = ["Finding 1", "Finding 2"]
        self.save_results()
```

2. Add to `greaper_core/scanners/__init__.py`:
```python
from .my_scanner import MyScanner
__all__ = [..., 'MyScanner']
```

3. Add to `greaper.py`:
```python
from greaper_core.scanners import ..., MyScanner

def run_my_scanner(url, args):
    scanner = MyScanner(target=url, output_file=args.output)
    scanner.scan()
```

### Adding a New Enumeration Source

1. Edit `greaper_core/enumerators/subdomain.py`
2. Add source to `_get_sources()` method
3. Add parsing logic to `_parse_source_data()` method

## Migration from Old Version

The original monolithic `greaper.py` has been preserved as `greaper_old.py` for:
- Reference and comparison
- Features not yet migrated (crawler, JS scanner, CVE scanner, etc.)
- Backward compatibility

To use old features:
```bash
python3 greaper_old.py -u https://example.com -cve
python3 greaper_old.py -u https://example.com -info
python3 greaper_old.py -u https://example.com -crawl 3
```

## Performance Improvements

- **Async Operations**: Subdomain enumeration uses aiohttp for concurrent requests
- **Session Reuse**: HTTP sessions prevent connection overhead
- **Retry Mechanism**: Exponential backoff for failed requests
- **Rate Limiting**: Configurable to prevent overwhelming targets

## Configuration

Create `.env` file for custom configuration:
```env
GREAPER_VERSION=v2.0
DEFAULT_TIMEOUT=10
DEFAULT_RATE_LIMIT=10
VERIFY_SSL=false
VERBOSE=false

# API Keys
VIRUSTOTAL_API_KEY=your_key_here
SECURITYTRAILS_API_KEY=your_key_here

# Source toggles
USE_VIRUSTOTAL=false
USE_CRTSH=true
USE_ALIENVAULT=true
```

## Logging

Logs are automatically created in `logs/` directory:
- `greaper_debug.log` - All debug messages
- `greaper_info.log` - General operations
- `greaper_errors.log` - Errors only
- `greaper_findings.log` - Vulnerability findings

## Best Practices

1. **Always get authorization** before scanning targets
2. **Use rate limiting** to avoid overwhelming servers
3. **Test incrementally** when developing new scanners
4. **Log findings** for audit trails
5. **Verify results manually** to avoid false positives

## Future Enhancements

Planned improvements:
- [ ] Migrate remaining scanners (CVE, JS analysis, crawler)
- [ ] Add unit tests for all modules
- [ ] Implement plugin system
- [ ] Add API mode for integration
- [ ] Create web dashboard
- [ ] Add report generation
- [ ] Improve error handling
- [ ] Add more output formats (XML, PDF)

## Contributing

To contribute:
1. Create new scanner in appropriate directory
2. Follow existing patterns and conventions
3. Add documentation
4. Test thoroughly
5. Submit pull request

## License

See main README.md for license information.
