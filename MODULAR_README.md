# Greaper Scanner v2.0 - Modular Edition

## 🎉 Major Refactoring Complete!

Greaper has been transformed from a monolithic 3,257-line script into a clean, modular architecture with **91% reduction** in main file size and proper separation of concerns.

## 📁 New Structure

```
greaper/
├── greaper.py              # Streamlined entry point (283 lines)
├── greaper_old.py          # Original version (backup)
├── greaper_core/           # Core package (19 modules)
│   ├── scanners/          # Vulnerability scanners
│   ├── enumerators/       # Information gathering
│   ├── utils/             # Utility functions
│   └── output/            # Output formatters
├── ARCHITECTURE.md         # Detailed architecture guide
├── REFACTORING_SUMMARY.md # Complete refactoring summary
└── README.md              # Original documentation
```

## 🚀 Quick Start

### Installation (unchanged)
```bash
git clone https://github.com/algorethmpwd/greaper.git
cd greaper
pip install -r requirements.txt
```

### Using the New Modular Version
```bash
# SQL Injection scan
python3 greaper.py -u "https://target.com?id=FUZZ" -sqli

# Subdomain enumeration
python3 greaper.py -u example.com -s

# CORS misconfiguration check
python3 greaper.py -u https://target.com -cors

# WAF detection
python3 greaper.py -u https://target.com -waf

# Use scan profiles
python3 greaper.py -u https://target.com --profile quick
python3 greaper.py -u https://target.com --profile full-scan
```

### Using the Original Version
For features not yet migrated (crawler, CVE scanner, etc.):
```bash
python3 greaper_old.py -u https://target.com -cve
python3 greaper_old.py -u https://target.com -info
python3 greaper_old.py -u https://target.com -crawl 3
```

## ✨ What's New in Modular Version

### Modular Scanners
- **SQLi Scanner** - Multiple detection techniques (error, time, boolean, union-based)
- **XSS Scanner** - Reflected XSS with payload reflection detection
- **LFI Scanner** - Local File Inclusion with pattern matching
- **CORS Scanner** - Misconfiguration detection with multiple origins
- **Host Header Scanner** - Injection detection with confidence scoring

### Enhanced Features
- **Async Operations** - Subdomain enumeration with concurrent requests
- **Retry Mechanism** - Exponential backoff for failed requests
- **Progress Tracking** - Real-time scan statistics and progress bars
- **Multi-Format Output** - JSON, HTML, CSV, Markdown support
- **Scan Profiles** - Predefined combinations (recon, quick, full-scan, bugbounty, stealth)
- **Structured Logging** - Separate log files for debug, info, errors, findings

### Architecture Benefits
✅ **91% smaller main file** (3,257 → 283 lines)  
✅ **19 focused modules** instead of monolithic structure  
✅ **Easy to test** - Each module independently testable  
✅ **Easy to extend** - Add scanners by creating new files  
✅ **Better organized** - Clear separation of concerns  
✅ **Session reuse** - Reduced network overhead  

## 📊 Comparison

| Feature | Old Version | New Version |
|---------|-------------|-------------|
| Main file size | 3,257 lines | 283 lines |
| Architecture | Monolithic | Modular (19 files) |
| Testability | Difficult | Easy (unit testable) |
| Maintainability | Challenging | Simple (isolated modules) |
| Extensibility | Hard | Easy (plug-and-play) |
| Code reuse | Limited | High (base classes) |

## 🛠️ Currently Migrated Features

### ✅ Fully Operational
- SQL Injection scanner
- XSS scanner
- LFI scanner  
- CORS scanner
- Host Header Injection scanner
- Subdomain enumeration
- WAF detection
- Status code checker
- Scan profiles
- Multi-format output
- Logging system
- Progress tracking

### 📝 Available in Original Version
Use `greaper_old.py` for:
- Web crawler (`-crawl`)
- JavaScript scanner (`-info`)
- CVE scanner (`-cve`)
- Directory fuzzer (`-df`)
- Content length checker (`-cl`)
- Live URL checker (`-lv`)
- Security headers (`-sec`)
- IP lookup (`-ip`)

## 📚 Documentation

- **ARCHITECTURE.md** - Complete architecture guide
- **REFACTORING_SUMMARY.md** - Refactoring details and testing results
- **README.md** - Original comprehensive documentation

## 🔧 For Developers

### Adding a New Scanner

1. Create `greaper_core/scanners/my_scanner.py`:
```python
from .base import BaseScanner
from ..config import Config

class MyScanner(BaseScanner):
    def scan(self):
        print(f"{Config.COLOR_BLUE}[*] Starting scan{Config.COLOR_RESET}")
        response = self.make_request(self.target)
        # Your scan logic here
        self.results = ["finding1", "finding2"]
        self.save_results()
```

2. Add to `greaper_core/scanners/__init__.py`:
```python
from .my_scanner import MyScanner
__all__ = [..., 'MyScanner']
```

3. Add to `greaper.py`:
```python
from greaper_core.scanners import MyScanner

def run_my_scanner(url, args):
    scanner = MyScanner(target=url, output_file=args.output)
    scanner.scan()
```

### Running Tests
```bash
# Test individual scanner
python3 greaper.py -u https://example.com -cors

# Test with output
python3 greaper.py -u https://example.com -waf -o results.txt

# Test with profile
python3 greaper.py -u https://example.com --profile quick
```

## 🎯 Usage Examples

### Basic Scans
```bash
# Quick reconnaissance
python3 greaper.py -u example.com --profile recon

# SQL Injection with custom payloads
python3 greaper.py -u "https://site.com?id=FUZZ" -sqli -p payloads.txt

# CORS check with JSON output
python3 greaper.py -u https://api.site.com -cors --format json -o cors.json
```

### Advanced Usage
```bash
# Full vulnerability scan
python3 greaper.py -u https://target.com --profile full-scan -o report.html --format html

# Stealth mode with rate limiting
python3 greaper.py -u https://target.com --profile stealth --rate-limit 1

# Multiple URLs from file
python3 greaper.py -l targets.txt -cors -o results.json --format json
```

## ⚠️ Legal Disclaimer

This tool is for **authorized security testing only**. Always obtain explicit permission before scanning targets. Unauthorized access is illegal. The developers assume no liability for misuse.

## 🤝 Contributing

Contributions welcome! The modular architecture makes it easy to:
- Add new scanners
- Improve existing modules  
- Add tests
- Enhance documentation

## 📞 Support

- **Issues**: GitHub Issues
- **Documentation**: ARCHITECTURE.md
- **Original Features**: Use greaper_old.py

## 🔮 Future Roadmap

- [ ] Migrate remaining scanners (crawler, CVE, JS, etc.)
- [ ] Add comprehensive unit tests
- [ ] Implement plugin system
- [ ] Create web dashboard
- [ ] Add CI/CD pipeline
- [ ] Generate PDF reports

## 📜 License

See original README.md for license information.

---

**Version**: 2.0 (Modular Architecture)  
**Author**: algorethm  
**Status**: ✅ Core scanners operational, tested, and documented  
**Backward Compatibility**: Original version preserved as greaper_old.py
