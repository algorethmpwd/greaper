"""
CVE Scanner Module
Fingerprint-based CVE detection
"""

import logging
import re
from urllib.parse import urljoin

import requests
from packaging import version as pkg_version

from ..config import Config

logger = logging.getLogger(__name__)


class CVEScanner:
    """CVE vulnerability scanner based on fingerprinting"""

    def __init__(self, url, output_file=None):
        self.url = url
        self.output_file = output_file
        self.session = self._create_session()
        self.results = []

    def _create_session(self):
        """Create configured requests session"""
        session = requests.Session()
        session.verify = False
        session.headers.update(Config.get_headers())
        return session

    def detect_versions(self, response):
        """Enhanced version detection for multiple frameworks"""
        versions = {}
        headers = str(response.headers)
        body = response.text.lower()

        patterns = {
            "Django": (r"Django/(\d+\.\d+\.\d+)", headers),
            "Laravel": (r"Laravel\s?v?(\d+\.\d+\.\d+)", body),
            "Rails": (r"Rails\s?(\d+\.\d+\.\d+)", headers + body),
            "Express": (r"express/(\d+\.\d+\.\d+)", headers),
            "Spring": (r"Spring-Boot/(\d+\.\d+\.\d+)", headers),
            "WordPress": (r"WordPress/(\d+\.\d+\.\d+)", headers + body),
            "PHP": (r"PHP/(\d+\.\d+\.\d+)", headers),
            "nginx": (r"nginx/(\d+\.\d+\.\d+)", headers),
            "Apache": (r"Apache/(\d+\.\d+\.\d+)", headers),
        }

        for framework, (pattern, content) in patterns.items():
            match = re.search(pattern, content)
            if match:
                versions[framework] = match.group(1)

        return versions

    def scan(self):
        """Execute CVE scan"""
        print(
            f"\n{Config.COLOR_BLUE}[*] Starting Enhanced Greaper CVE Scanner on {self.url}{Config.COLOR_RESET}\n"
        )

        try:
            # Get baseline response
            baseline_response = self.session.get(self.url, timeout=15)
            server_info = baseline_response.headers.get("Server", "Unknown")
            print(
                f"{Config.COLOR_BLUE}[*] Server detected: {server_info}{Config.COLOR_RESET}"
            )

            # Enhanced version detection
            versions = self.detect_versions(baseline_response)
            if versions:
                print("\nDetected versions:")
                for framework, ver in versions.items():
                    print(
                        f"{Config.COLOR_BLUE}[*] {framework}: {ver}{Config.COLOR_RESET}"
                    )
                    self.results.append(f"{framework}: {ver}")

            # Simple vulnerability checks
            print(
                f"\n{Config.COLOR_BLUE}[*] Checking for common vulnerabilities...{Config.COLOR_RESET}"
            )

            # Check for exposed git
            git_check = self.session.get(urljoin(self.url, "/.git/config"), timeout=5)
            if (
                "[core]" in git_check.text
                or "repositoryformatversion" in git_check.text
            ):
                finding = "[+] Git Repository Exposed (/.git/config accessible)"
                print(f"{Config.COLOR_RED}{finding}{Config.COLOR_RESET}")
                self.results.append(finding)

            # Check for exposed env
            env_check = self.session.get(urljoin(self.url, "/.env"), timeout=5)
            if env_check.status_code == 200 and len(env_check.text) > 0:
                finding = "[+] Environment File Exposed (/.env accessible)"
                print(f"{Config.COLOR_RED}{finding}{Config.COLOR_RESET}")
                self.results.append(finding)

            # Check for directory listing
            if (
                baseline_response.status_code == 200
                and "Index of /" in baseline_response.text
            ):
                finding = "[+] Directory Listing Enabled"
                print(f"{Config.COLOR_ORANGE}{finding}{Config.COLOR_RESET}")
                self.results.append(finding)

            # Save results
            if self.results and self.output_file:
                with open(self.output_file, "w") as f:
                    f.write(f"CVE Scan Results for {self.url}\n")
                    f.write("=" * 50 + "\n\n")
                    f.write("\n".join(self.results))
                print(
                    f"\n{Config.COLOR_GREEN}[+] Results saved to {self.output_file}{Config.COLOR_RESET}"
                )
            elif not self.results:
                print(
                    f"\n{Config.COLOR_GREEN}[+] No vulnerabilities detected{Config.COLOR_RESET}"
                )

        except Exception as e:
            logger.error(f"Error scanning {self.url}: {e}")
            print(
                f"{Config.COLOR_RED}[-] Error scanning {self.url}: {str(e)}{Config.COLOR_RESET}"
            )
