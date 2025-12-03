"""
LFI Scanner
Detects Local File Inclusion vulnerabilities
"""

import logging
import re

import urllib3

from ..config import Config
from .base import BaseScanner

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
logger = logging.getLogger(__name__)


class LFIScanner(BaseScanner):
    """Local File Inclusion vulnerability scanner"""

    def __init__(self, target, payload_file, output_file=None, dynamic_payloads=None):
        super().__init__(target, output_file)
        self.payload_file = payload_file
        self.dynamic_payloads = dynamic_payloads
        self.lfi_patterns = {
            "unix_passwd": (r"root:.*:0:0:", r"nobody:\w+:\d+:\d+:"),
            "win_ini": (r"\[boot loader\]", r"timeout=\d+"),
            "proc_self": (r"Name:\s+\w+\nState:\s+[RSDZT]", r"Pid:\s+\d+"),
            "etc_hosts": (r"127\.0\.0\.1\s+localhost", r"::1\s+localhost"),
            "apache_config": (r'DocumentRoot\s+["\']/\w+', r'<Directory\s+["\']'),
            "nginx_config": (r"worker_processes\s+\w+;", r"http\s*{"),
            "ssh_config": (r"AuthorizedKeysFile", r"PasswordAuthentication\s+(yes|no)"),
        }

    def get_payloads(self):
        """Load LFI payloads"""
        if self.dynamic_payloads:
            return self.dynamic_payloads

        try:
            with open(self.payload_file, "r") as f:
                payloads = [
                    line.strip()
                    for line in f
                    if line.strip() and not line.startswith("#")
                ]
                logger.info(f"Loaded {len(payloads)} LFI payloads")
                print(
                    f"{Config.COLOR_GREEN}[*] Loaded {len(payloads)} custom payloads{Config.COLOR_RESET}\n"
                )
                return payloads
        except Exception as e:
            logger.error(f"Error reading payload file: {e}")
            print(
                f"{Config.COLOR_RED}[-] Error reading payload file: {str(e)}{Config.COLOR_RESET}"
            )
            return []

    def scan(self):
        """Execute LFI scan"""
        print(
            f"\n{Config.COLOR_BLUE}[*] Starting Greaper LFI scanner on {self.target}{Config.COLOR_RESET}"
        )

        payloads = self.get_payloads()
        if not payloads:
            return

        # Get baseline response
        try:
            baseline_response = self.make_request(
                self.target.replace("FUZZ", ""), verify=False, allow_redirects=False
            )
            baseline_length = len(baseline_response.text)
            baseline_content = baseline_response.text
        except Exception as e:
            logger.error(f"Error getting baseline response: {e}")
            print(
                f"{Config.COLOR_RED}[-] Error getting baseline response: {str(e)}{Config.COLOR_RESET}"
            )
            return

        found_vulnerabilities = []

        for payload in payloads:
            lfi_test_url = self.target.replace("FUZZ", payload)
            try:
                response = self.make_request(
                    lfi_test_url, verify=False, allow_redirects=False
                )

                # Skip if response is too similar to baseline
                if (
                    abs(len(response.text) - baseline_length) < 10
                    or response.text == baseline_content
                    or response.status_code == 404
                ):
                    print(
                        f"{Config.COLOR_RED}[-] No LFI found for payload: {payload}{Config.COLOR_RESET}"
                    )
                    continue

                # Enhanced validation with multiple pattern matching
                found_patterns = []
                for file_type, patterns in self.lfi_patterns.items():
                    if all(re.search(pattern, response.text) for pattern in patterns):
                        found_patterns.append(file_type)

                if found_patterns:
                    result = f"[+] Potential LFI found on {lfi_test_url}  With file: {payload}"
                    print(f"{Config.COLOR_GREEN}{result}{Config.COLOR_RESET}")
                    found_vulnerabilities.append(result)
                else:
                    print(
                        f"{Config.COLOR_RED}[-] No LFI found for payload: {payload}{Config.COLOR_RESET}"
                    )
            except Exception as e:
                logger.error(f"Error testing payload: {e}")
                print(
                    f"{Config.COLOR_RED}[-] No LFI found for payload: {payload}{Config.COLOR_RESET}"
                )
                continue

        self.results = found_vulnerabilities

        print(f"\n{Config.COLOR_BLUE}[*] Scan Summary:{Config.COLOR_RESET}")
        if found_vulnerabilities:
            print(
                f"{Config.COLOR_GREEN}[+] Found {len(found_vulnerabilities)} potential LFI vulnerabilities{Config.COLOR_RESET}"
            )
            self.save_results()
        else:
            print(
                f"{Config.COLOR_RED}[-] No LFI vulnerabilities found{Config.COLOR_RESET}"
            )
