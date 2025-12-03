"""
WAF Detection Module
Detect Web Application Firewalls
"""

import requests
from ..config import Config
import logging

logger = logging.getLogger(__name__)


class WAFDetector:
    """Web Application Firewall detector"""

    def __init__(self):
        self.waf_signatures = {
            'Cloudflare': ['cf-ray', '__cfduid', 'cf-cache-status'],
            'AWS WAF': ['x-amzn-RequestId', 'x-amz-cf-id', 'x-amz-id'],
            'Akamai': ['akamai-origin-hop', 'aka-cdn-cache-status'],
            'Imperva': ['x-iinfo', 'x-cdn', 'incap_ses'],
            'F5 BIG-IP ASM': ['x-cnection', 'x-wa-info']
        }

    def detect(self, url):
        """Detect WAF for a URL"""
        print(f"\n{Config.COLOR_BLUE}[*] Starting WAF detection for {url}{Config.COLOR_RESET}")

        try:
            headers = Config.get_headers()
            response = requests.get(url, headers=headers, verify=False, timeout=10)
            detected_wafs = []

            for waf_name, signatures in self.waf_signatures.items():
                for signature in signatures:
                    if signature.lower() in str(response.headers).lower():
                        detected_wafs.append(waf_name)
                        break

            if response.status_code == 403:
                malicious_url = f"{url}?id=1' OR '1'='1"
                mal_response = requests.get(malicious_url, headers=headers, verify=False, timeout=10)

                if mal_response.status_code in [403, 406, 501]:
                    detected_wafs.append("Generic WAF (Behavioral Detection)")

            if detected_wafs:
                print(f"{Config.COLOR_GREEN}[+] WAF(s) Detected: {', '.join(set(detected_wafs))}{Config.COLOR_RESET}")
                return list(set(detected_wafs))
            else:
                print(f"{Config.COLOR_ORANGE}[-] No WAF detected{Config.COLOR_RESET}")
                return []

        except Exception as e:
            logger.error(f"Error during WAF detection: {e}")
            print(f"{Config.COLOR_RED}[-] Error during WAF detection: {str(e)}{Config.COLOR_RESET}")
            return []
