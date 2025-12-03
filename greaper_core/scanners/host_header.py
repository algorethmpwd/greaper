"""
Host Header Injection Scanner
Detects Host Header Injection vulnerabilities
"""

import logging

from ..config import Config
from .base import BaseScanner

logger = logging.getLogger(__name__)


class HostHeaderScanner(BaseScanner):
    """Host Header Injection vulnerability scanner"""

    def scan(self):
        print(
            f"\n{Config.COLOR_BLUE}[*] Starting Greaper Host Header Injection scanner on {self.target}{Config.COLOR_RESET}"
        )

        # Test multiple malicious headers and payloads
        test_cases = [
            {"Host": "evil.com", "X-Forwarded-Host": "evil.com"},
            {"X-Host": "evil.com", "X-Forwarded-Server": "evil.com"},
            {"X-Original-Host": "evil.com", "X-Rewrite-URL": "evil.com"},
        ]

        # Get baseline response for comparison
        try:
            baseline_response = self.make_request(self.target)
            baseline_content = baseline_response.text
        except Exception as e:
            logger.error(f"Error getting baseline response: {e}")
            print(
                f"{Config.COLOR_ORANGE}[-] Error getting baseline response: {str(e)}{Config.COLOR_RESET}"
            )
            return

        found_hhi = []

        for test_case in test_cases:
            try:
                response = self.make_request(
                    self.target, headers=test_case, allow_redirects=False
                )

                # Multiple validation checks to reduce false positives
                indicators = {
                    "content_changed": abs(len(response.text) - len(baseline_content))
                    > 100,
                    "headers_reflected": any(
                        "evil.com" in str(v).lower() for v in response.headers.values()
                    ),
                    "body_reflected": "evil.com" in response.text.lower(),
                    "status_changed": response.status_code
                    != baseline_response.status_code,
                    "location_header": "evil.com"
                    in response.headers.get("Location", "").lower(),
                }

                # Require multiple indicators for higher confidence
                confidence_score = sum(1 for v in indicators.values() if v)

                if confidence_score >= 2:
                    result = (
                        f"[+] Host Header Injection found on {self.target}\n"
                        f"    Confidence Score: {confidence_score}/5\n"
                        f"    Triggered Headers: {list(test_case.keys())}\n"
                        f"    Indicators: {[k for k, v in indicators.items() if v]}"
                    )
                    print(f"{Config.COLOR_GREEN}{result}{Config.COLOR_RESET}")
                    found_hhi.append(result)
                    break

            except Exception as e:
                logger.error(f"Error testing headers: {e}")
                continue

        self.results = found_hhi

        if not found_hhi:
            print(
                f"{Config.COLOR_RED}[-] No Host Header Injection vulnerabilities found{Config.COLOR_RESET}"
            )
            print(f"{Config.COLOR_RED}[-] No Host Header Injection vulnerabilities found{Config.COLOR_RESET}")
        else:
            self.save_results()
