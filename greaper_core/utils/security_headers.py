"""
Security Headers Checker Module
Validates security headers
"""

import logging

import requests

from ..config import Config

logger = logging.getLogger(__name__)


class SecurityHeadersChecker:
    """Security header scanner"""

    def __init__(self, url, output_file=None):
        self.url = url
        self.output_file = output_file
        self.required_headers = {
            "Strict-Transport-Security": {
                "description": "Enforces HTTPS connections",
                "recommended": "max-age=31536000; includeSubDomains; preload",
            },
            "Content-Security-Policy": {
                "description": "Controls resource loading",
                "recommended": "default-src 'self'",
            },
            "X-Frame-Options": {
                "description": "Prevents clickjacking attacks",
                "recommended": "SAMEORIGIN",
            },
            "X-Content-Type-Options": {
                "description": "Prevents MIME-type sniffing",
                "recommended": "nosniff",
            },
            "Referrer-Policy": {
                "description": "Controls referrer information",
                "recommended": "strict-origin-when-cross-origin",
            },
            "Permissions-Policy": {
                "description": "Controls browser features",
                "recommended": "geolocation=(), microphone=()",
            },
            "X-XSS-Protection": {
                "description": "Legacy XSS protection",
                "recommended": "1; mode=block",
            },
            "Cross-Origin-Opener-Policy": {
                "description": "Controls window.opener behavior",
                "recommended": "same-origin",
            },
            "Cross-Origin-Resource-Policy": {
                "description": "Controls resource sharing",
                "recommended": "same-origin",
            },
            "Cross-Origin-Embedder-Policy": {
                "description": "Controls resource loading",
                "recommended": "require-corp",
            },
        }

    def check(self):
        """Execute security headers check"""
        print(
            f"\n{Config.COLOR_BLUE}[*] Starting security header scanner for {self.url}{Config.COLOR_RESET}"
        )

        try:
            response = requests.get(self.url, timeout=10, verify=False)
            headers = response.headers

            results = [f"Security Header Scan Results for {self.url}\n{'=' * 50}\n"]
            found_headers = 0
            missing_headers = 0

            for header, info in self.required_headers.items():
                if header in headers:
                    found_headers += 1
                    value = headers[header]
                    result = (
                        f"[+] {header}\n"
                        f"    Value: {value}\n"
                        f"    Description: {info['description']}\n"
                        f"    Recommended: {info['recommended']}"
                    )
                    print(f"{Config.COLOR_GREEN}{result}{Config.COLOR_RESET}")
                    results.append(result)
                else:
                    missing_headers += 1
                    result = (
                        f"[-] {header} is missing\n"
                        f"    Description: {info['description']}\n"
                        f"    Recommended: {info['recommended']}"
                    )
                    print(f"{Config.COLOR_ORANGE}{result}{Config.COLOR_RESET}")
                    results.append(result)

            # Add summary
            summary = (
                f"\nScan Summary\n{'-' * 20}\n"
                f"Total Headers Checked: {len(self.required_headers)}\n"
                f"Headers Present: {found_headers}\n"
                f"Headers Missing: {missing_headers}\n"
                f"Security Score: {(found_headers / len(self.required_headers)) * 100:.1f}%"
            )
            print(f"{Config.COLOR_BLUE}{summary}{Config.COLOR_RESET}")
            results.append(summary)

            # Save results
            if self.output_file:
                with open(self.output_file, "w") as f:
                    f.write("\n\n".join(results))
                print(
                    f"\n{Config.COLOR_GREEN}[+] Results saved to {self.output_file}{Config.COLOR_RESET}"
                )

        except Exception as e:
            logger.error(f"Error checking security headers: {e}")
            print(
                f"{Config.COLOR_RED}[-] Error checking security headers: {str(e)}{Config.COLOR_RESET}"
            )
