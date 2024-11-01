
# Greaper Scanner

**Greaper** is a multi-purpose web security scanner that performs various security checks on websites or lists of URLs. 
It includes options for checking status codes, scanning for vulnerabilities, checking content lengths, performing IP lookups, and much more.

## Features
- Status code checks (`-sc`)
- Directory fuzzing (`-df`)
- Subdomain enumeration (`-s`)
- SQL Injection, XSS, LFI vulnerability scans (`-sqli`, `-xss`, `-lfi`)
- IP lookup and bypass (`-ip`)
- Content length checks (`-cl`)
- Security header checks (`-sec`)
- CORS misconfiguration checks (`-cors`)
- Host header injection detection (`-hh`)
- Live URL checks (`-lv`)
- CVE scans by fingerprint (`-cve`)
- JavaScript files scanning for sensitive info (`-info`)

## Prerequisites
- **Python 3.6 or newer**
- Install required Python packages from `requirements.txt`.

## Installation
1. Clone the repository or download `greaper.py` and `requirements.txt`.
2. Install the dependencies listed in `requirements.txt`:
   ```bash
   pip install -r requirements.txt
   ```

## Usage

Greaper allows you to scan a single URL or a list of URLs. Each scan mode is activated using a specific flag. Here are some examples:

### Basic Syntax
```bash
python3 greaper.py -u <url> -sc
python3 greaper.py -l <file_with_urls.txt> -sc
```

### Examples

#### 1. Checking Status Codes
```bash
python3 greaper.py -u https://example.com -sc
```

#### 2. Directory Fuzzing
```bash
python3 greaper.py -u https://example.com -df
```

#### 3. CORS Misconfiguration Scan
```bash
python3 greaper.py -u https://example.com -cors
```

#### 4. SQL Injection Scan with a Payload File
```bash
python3 greaper.py -u https://example.com -sqli -p sqli_payloads.txt
```

#### 5. Scanning Multiple URLs from a File
```bash
python3 greaper.py -l urls.txt -sec
```

### Options and Flags

| Option         | Description                                             |
|----------------|---------------------------------------------------------|
| `-u`, `--url`  | Specify a single URL to scan.                           |
| `-l`, `--list` | File containing multiple URLs to scan, one URL per line.|
| `-sc`          | Check status codes.                                     |
| `-df`          | Directory fuzzing for common paths or with a custom list.|
| `-s`           | Enable subdomain enumeration.                           |
| `-sqli`        | Run SQL Injection detection. Requires `-p` for payloads.|
| `-xss`         | Enable XSS scan. Requires `-p` with payloads.           |
| `-lfi`         | Enable Local File Inclusion scan. Requires `-p`.        |
| `-cors`        | Scan for CORS misconfiguration.                         |
| `-hh`          | Scan for Host Header Injection.                         |
| `-ip`          | Perform IP lookup for the target.                       |
| `-cl`          | Check content length of the target URLs.                |
| `-lv`          | Check if the target subdomains are live.                |
| `-info`        | Scan JS files for sensitive information.                |
| `-sec`         | Check security headers on the URLs.                     |
| `-cve`         | Scan for CVEs based on server fingerprint.              |
| `-p`           | File containing payloads for scans like SQLi, XSS, etc. |
| `-o`           | Output file to save results.                            |

## Notes
- **URL Format**: URLs should include `http://` or `https://` in the file specified by `-l`.
- **Results**: Results will display in the terminal and save to an output file if specified with `-o`.
