"""
XSS Scanner
Detects Cross-Site Scripting vulnerabilities
"""

import logging

import urllib3

from ..config import Config
from .base import BaseScanner

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
logger = logging.getLogger(__name__)


class XSSScanner(BaseScanner):
    """Cross-Site Scripting vulnerability scanner"""

    def __init__(self, target, payload_file, output_file=None, dynamic_payloads=None):
        super().__init__(target, output_file)
        self.payload_file = payload_file
        self.dynamic_payloads = dynamic_payloads

    def get_payloads(self):
        """Load XSS payloads"""
        if self.dynamic_payloads:
            return self.dynamic_payloads

        try:
            with open(self.payload_file, "r") as f:
                payloads = [
                    line.strip()
                    for line in f
                    if line.strip() and not line.startswith("#")
                ]
                logger.info(f"Loaded {len(payloads)} XSS payloads")
                print(
                    f"{Config.COLOR_GREEN}[+] Loaded {len(payloads)} custom payloads{Config.COLOR_RESET}\n"
                )
                return payloads
        except Exception as e:
            logger.error(f"Error reading payload file: {e}")
            print(
                f"{Config.COLOR_ORANGE}[-] Error reading payload file: {str(e)}{Config.COLOR_RESET}"
            )
            return []

    def scan(self):
        """Execute XSS scan"""
        print(
            f"\n{Config.COLOR_BLUE}[*] Starting Greaper XSS scanner on {self.target}{Config.COLOR_RESET}"
        )

        payloads = self.get_payloads()
        if not payloads:
            return

        found_xss = []

        for payload in payloads:
            try:
                import requests

                test_url = self.target.replace("FUZZ", requests.utils.quote(payload))
                response = self.make_request(test_url, verify=False)

                if payload in response.text:
                    result = (
                        f"[+] Potential XSS found on {test_url} With payload: {payload}"
                    )
                    print(f"{Config.COLOR_GREEN}{result}{Config.COLOR_RESET}")
                    found_xss.append(result)
                else:
                    print(
                        f"{Config.COLOR_RED}[-] No XSS found for payload: {payload}{Config.COLOR_RESET}"
                    )
            except Exception as e:
                logger.error(f"Error testing payload: {e}")
                print(
                    f"{Config.COLOR_RED}[-] Error testing payload: {str(e)}{Config.COLOR_RESET}"
                )
                continue

        self.results = found_xss

        if found_xss:
            self.save_results()
        else:
            print(
                f"\n{Config.COLOR_RED}[-] No XSS vulnerabilities found{Config.COLOR_RESET}"
            )
