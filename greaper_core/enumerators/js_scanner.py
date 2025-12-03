"""
JavaScript Scanner Module
Scans JS files for sensitive information
"""

import logging
import re
from urllib.parse import urljoin, urlparse

import requests
from bs4 import BeautifulSoup

from ..config import Config

logger = logging.getLogger(__name__)


class JSScanner:
    """JavaScript file scanner for sensitive information"""

    def __init__(self, target, output_file=None):
        self.target = target
        self.output_file = output_file
        self.session = self._create_session()
        self.patterns = {
            "API Key": r'(?:api[_-]?key|apikey)["\']?\s*[:=]\s*["\']([A-Za-z0-9_\-]{20,})["\']',
            "AWS Key": r"AKIA[0-9A-Z]{16}",
            "Database URL": r'(?:mongodb|mysql|postgresql|redis)://[^\s<>"\']+',
            "Internal IP": r"\b(?:127\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|10\.\d{1,3}\.\d{1,3}\.\d{1,3})\b",
            "S3 Bucket": r"[a-z0-9.-]+\.s3\.amazonaws\.com",
            "JWT Token": r"eyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*",
            "Google API Key": r"AIza[0-9A-Za-z-_]{35}",
            "Secret Key": r'(?:secret|private)[_-]?key["\']?\s*[:=]\s*["\'][^"\']+["\']',
        }

    def _create_session(self):
        """Create configured requests session"""
        session = requests.Session()
        session.verify = False
        session.headers.update(Config.get_headers())
        return session

    def is_js_file(self, url):
        """Check if URL points to a JavaScript file"""
        if not url:
            return False

        js_patterns = [
            r"\.js($|\?)",
            r"\.js/[^/]*$",
            r"/js/[^/]+$",
            r"[^/]+\.js\b",
            r"/javascript/",
            r"type=text/javascript",
        ]

        url_lower = url.lower()
        return any(re.search(pattern, url_lower) for pattern in js_patterns)

    def extract_js_urls(self, url):
        """Extract JavaScript URLs from a webpage"""
        js_urls = set()

        try:
            print(
                f"\n{Config.COLOR_BLUE}[*] Scanning {url} for JavaScript files...{Config.COLOR_RESET}"
            )
            print(f"{Config.COLOR_BLUE}{'─' * 60}{Config.COLOR_RESET}")

            response = self.session.get(url, timeout=10)
            if not response:
                return []

            soup = BeautifulSoup(response.content, "html.parser")

            for tag in soup.find_all(["script", "link", "a"]):
                js_url = tag.get("src") or tag.get("href")
                if js_url:
                    if js_url.startswith("//"):
                        js_url = "https:" + js_url
                    elif js_url.startswith("/"):
                        js_url = urljoin(url, js_url)
                    elif not js_url.startswith(("http://", "https://")):
                        js_url = urljoin(url, js_url)

                    if self.is_js_file(js_url):
                        js_urls.add(js_url)

            if js_urls:
                print(
                    f"\n{Config.COLOR_GREEN}[+] Found {len(js_urls)} JavaScript files:{Config.COLOR_RESET}"
                )
                for i, js_url in enumerate(sorted(js_urls), 1):
                    print(
                        f"{Config.COLOR_BLUE}    {i:2d}. {js_url}{Config.COLOR_RESET}"
                    )
            else:
                print(
                    f"\n{Config.COLOR_ORANGE}[!] No JavaScript files found{Config.COLOR_RESET}"
                )

            print(f"\n{Config.COLOR_BLUE}{'─' * 60}{Config.COLOR_RESET}")
            return list(js_urls)

        except Exception as e:
            logger.error(f"Error extracting JS URLs: {e}")
            print(f"{Config.COLOR_RED}[✗] Error: {str(e)}{Config.COLOR_RESET}")
            return []

    def analyze_js_file(self, js_url):
        """Analyze a JavaScript file for sensitive information"""
        try:
            response = self.session.get(js_url, timeout=10)
            response.raise_for_status()
            js_content = response.text

            findings = []
            lines = js_content.splitlines()

            for line_num, line in enumerate(lines, 1):
                for pattern_name, pattern in self.patterns.items():
                    matches = re.finditer(pattern, line)
                    for match in matches:
                        start = max(0, line_num - 1)
                        end = min(len(lines), line_num + 2)
                        context = lines[start:end]

                        findings.append(
                            {
                                "type": pattern_name,
                                "line": line_num,
                                "content": match.group(0),
                                "context": context,
                            }
                        )

            if findings:
                findings_by_type = {}
                for finding in findings:
                    if finding["type"] not in findings_by_type:
                        findings_by_type[finding["type"]] = []
                    findings_by_type[finding["type"]].append(finding)

                print(
                    f"\n{Config.COLOR_GREEN}[+] Found sensitive information in {js_url}{Config.COLOR_RESET}"
                )

                if self.output_file:
                    with open(self.output_file, "a") as f:
                        f.write(f"\n{'=' * 50}\n")
                        f.write(f"JavaScript File: {js_url}\n")
                        f.write(f"{'=' * 50}\n\n")

                        for finding_type, type_findings in findings_by_type.items():
                            f.write(f"{finding_type} ({len(type_findings)} found):\n")
                            f.write("-" * 40 + "\n")

                            for finding in type_findings:
                                f.write(f"Line {finding['line']}:\n")
                                for i, ctx_line in enumerate(finding["context"]):
                                    if i == 1:
                                        f.write(f"  → {ctx_line.strip()}\n")
                                    else:
                                        f.write(f"    {ctx_line.strip()}\n")
                                f.write("\n")
                            f.write("\n")

                for finding_type, type_findings in findings_by_type.items():
                    print(
                        f"\n{Config.COLOR_BLUE}[*] {finding_type} ({len(type_findings)} found):{Config.COLOR_RESET}"
                    )
                    for finding in type_findings[:3]:
                        print(
                            f"  Line {finding['line']}: {finding['content'][:100]}..."
                        )
                    if len(type_findings) > 3:
                        print(f"  ... and {len(type_findings) - 3} more")

                return True
            else:
                print(
                    f"{Config.COLOR_GREY}[-] No sensitive information found in {js_url}{Config.COLOR_RESET}"
                )
                return False

        except Exception as e:
            logger.error(f"Error analyzing {js_url}: {e}")
            print(
                f"{Config.COLOR_RED}[-] Error analyzing {js_url}: {str(e)}{Config.COLOR_RESET}"
            )
            return False

    def scan(self):
        """Execute the JavaScript scan"""
        print(
            f"\n{Config.COLOR_BLUE}[*] Starting JavaScript scanner for {self.target}{Config.COLOR_RESET}"
        )

        if self.is_js_file(self.target):
            # Direct JS file analysis
            self.analyze_js_file(self.target)
        else:
            # Extract and analyze JS files from webpage
            js_urls = self.extract_js_urls(self.target)
            if js_urls:
                print(
                    f"\n{Config.COLOR_BLUE}[*] Analyzing {len(js_urls)} JavaScript files{Config.COLOR_RESET}"
                )
                for js_url in js_urls:
                    self.analyze_js_file(js_url)
            else:
                print(
                    f"{Config.COLOR_RED}[-] No JavaScript files found on {self.target}{Config.COLOR_RESET}"
                )

        if self.output_file:
            print(
                f"\n{Config.COLOR_GREEN}[+] Results saved to {self.output_file}{Config.COLOR_RESET}"
            )
