"""
CORS Scanner
Detects CORS misconfiguration vulnerabilities
"""

import logging
from urllib.parse import urlparse

from ..config import Config
from .base import BaseScanner

logger = logging.getLogger(__name__)


class CORSScanner(BaseScanner):
    """CORS misconfiguration vulnerability scanner"""

    def scan(self):
        print(
            f"\n{Config.COLOR_BLUE}[*] Starting Greaper CORS scanner on {self.target}{Config.COLOR_RESET}"
        )

        # Test origins for CORS validation
        test_origins = [
            "evil.com",
            "null",
            "https://attacker.com",
            "http://localhost",
            self.target.replace("https://", "http://"),
            f"https://evil.{urlparse(self.target).netloc}",
        ]

        found_cors = []

        try:
            baseline = self.make_request(self.target)

            for origin in test_origins:
                headers = {"Origin": origin}
                try:
                    response = self.make_request(self.target, headers=headers)
                    cors_headers = {
                        "Access-Control-Allow-Origin": response.headers.get(
                            "Access-Control-Allow-Origin"
                        ),
                        "Access-Control-Allow-Credentials": response.headers.get(
                            "Access-Control-Allow-Credentials"
                        ),
                        "Access-Control-Allow-Methods": response.headers.get(
                            "Access-Control-Allow-Methods"
                        ),
                        "Access-Control-Allow-Headers": response.headers.get(
                            "Access-Control-Allow-Headers"
                        ),
                    }

                    vulnerabilities = []

                    if cors_headers["Access-Control-Allow-Origin"]:
                        acao = cors_headers["Access-Control-Allow-Origin"]

                        if (
                            acao == "*"
                            and cors_headers["Access-Control-Allow-Credentials"]
                            == "true"
                        ):
                            vulnerabilities.append("Wildcard origin with credentials")
                        elif origin in acao and origin != urlparse(self.target).netloc:
                            vulnerabilities.append(f"Origin reflection: {origin}")
                        elif acao == "null":
                            vulnerabilities.append("null origin allowed")
                        elif not acao.startswith(("http://", "https://")):
                            vulnerabilities.append(f"Invalid ACAO header: {acao}")

                        if cors_headers["Access-Control-Allow-Methods"]:
                            dangerous_methods = ["PUT", "DELETE", "TRACE", "CONNECT"]
                            allowed_methods = (
                                cors_headers["Access-Control-Allow-Methods"]
                                .upper()
                                .split(",")
                            )
                            dangerous_allowed = [
                                m for m in dangerous_methods if m in allowed_methods
                            ]
                            if dangerous_allowed:
                                vulnerabilities.append(
                                    f"Dangerous methods allowed: {dangerous_allowed}"
                                )

                    if vulnerabilities:
                        result = (
                            f"[+] CORS Misconfiguration found on {self.target}\n"
                            f"    Testing Origin: {origin}\n"
                            f"    Vulnerabilities:\n"
                            f"    - " + "\n    - ".join(vulnerabilities) + "\n"
                            f"    CORS Headers:\n"
                            f"    - "
                            + "\n    - ".join(
                                f"{k}: {v}" for k, v in cors_headers.items() if v
                            )
                        )
                        print(f"{Config.COLOR_GREEN}{result}{Config.COLOR_RESET}")
                        found_cors.append(result)

                except Exception as e:
                    logger.error(f"Error testing origin {origin}: {e}")
                    continue

        except Exception as e:
            logger.error(f"Error scanning {self.target}: {e}")
            print(
                f"{Config.COLOR_ORANGE}[-] Error scanning {self.target}: {str(e)}{Config.COLOR_RESET}"
            )

        self.results = found_cors

        if not found_cors:
            print(
                f"{Config.COLOR_RED}[-] No CORS Misconfiguration vulnerabilities found{Config.COLOR_RESET}"
            )
            print(f"{Config.COLOR_RED}[-] No CORS Misconfiguration vulnerabilities found{Config.COLOR_RESET}")
        else:
            self.save_results()
