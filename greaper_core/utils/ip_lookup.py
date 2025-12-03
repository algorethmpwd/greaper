"""
IP Lookup Module
Comprehensive IP lookup and WAF bypass attempts
"""

import logging
import socket
from urllib.parse import urlparse

import dns.resolver
import requests
import urllib3
from ipwhois import IPWhois

from ..config import Config

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
logger = logging.getLogger(__name__)


class IPLookup:
    """Advanced IP lookup with ASN information"""

    def __init__(self, target, output_file=None):
        self.target = target
        self.output_file = output_file
        self.results = []

    def get_asn_info(self, domain):
        """Get ASN information for a domain"""
        try:
            ip = socket.gethostbyname(domain)
            obj = IPWhois(ip)
            asn_info = [
                {
                    "asn": results.get("asn"),
                    "org": results.get("network", {}).get("name"),
                    "network": results.get("network", {}).get("cidr"),
                    "country": results.get("asn_country_code"),
                }
            ]

            return asn_info
        except Exception as e:
            logger.error(f"Error getting ASN info: {e}")
            return None

    def validate_bypass_response(self, response, domain):
        """Validate if response indicates successful WAF bypass"""
        try:
            if response.status_code in [200, 301, 302, 307, 308]:
                if domain.lower() in response.text.lower():
                    if len(response.content) > 1000:
                        return True

            server_header = response.headers.get("Server", "").lower()
            if any(
                indicator in server_header
                for indicator in ["nginx", "apache", "cloudflare-nginx"]
            ):
                return True
        except Exception:
            pass

        return False

    def lookup(self):
        """Execute IP lookup"""
        print(
            f"\n{Config.COLOR_BLUE}[*] Starting Greaper advanced IP lookup for {self.target}{Config.COLOR_RESET}"
        )

        # Clean up target
        target = self.target.strip().lower()
        if not target.startswith(("http://", "https://")):
            target = f"https://{target}"

        parsed_url = urlparse(target)
        domain = parsed_url.netloc.split(":")[0]

        try:
            # Get ASN information
            print(
                f"\n{Config.COLOR_BLUE}[*] Looking up ASN information...{Config.COLOR_RESET}"
            )
            asn_info = self.get_asn_info(domain)
            if asn_info:
                for asn_data in asn_info:
                    result = (
                        f"[+] Found ASN: {asn_data['asn']}\n"
                        f"    Organization: {asn_data['org']}\n"
                        f"    Network Range: {asn_data['network']}\n"
                        f"    Country: {asn_data['country']}"
                    )
                    print(f"{Config.COLOR_GREEN}{result}{Config.COLOR_RESET}")
                    self.results.append(result)

            # Get IPs
            print(
                f"\n{Config.COLOR_BLUE}[*] Gathering IP addresses...{Config.COLOR_RESET}"
            )
            ip_addresses = set()

            try:
                answers = dns.resolver.resolve(domain, "A")
                for rdata in answers:
                    ip_addresses.add(str(rdata))
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
                print(f"{Config.COLOR_RED}[-] No A records found{Config.COLOR_RESET}")

            if ip_addresses:
                ip_result = f"\n[+] Found {len(ip_addresses)} unique IP addresses:"
                print(f"{Config.COLOR_GREEN}{ip_result}{Config.COLOR_RESET}")
                self.results.append(ip_result)

                for ip in sorted(ip_addresses):
                    print(f"{Config.COLOR_GREEN}    - {ip}{Config.COLOR_RESET}")
                    self.results.append(f"    - {ip}")

                # Test each IP for WAF bypass
                for ip in ip_addresses:
                    print(
                        f"\n{Config.COLOR_BLUE}[*] Testing IP: {ip}{Config.COLOR_RESET}"
                    )

                    headers = {"Host": domain, "User-Agent": Config.USER_AGENT}

                    for protocol in ["https", "http"]:
                        try:
                            url = f"{protocol}://{ip}"
                            response = requests.get(
                                url,
                                headers=headers,
                                timeout=10,
                                verify=False,
                                allow_redirects=False,
                            )

                            if self.validate_bypass_response(response, domain):
                                bypass_result = (
                                    f"[+] Potential WAF bypass found!\n"
                                    f"    IP: {ip}\n"
                                    f"    Protocol: {protocol.upper()}\n"
                                    f"    Status Code: {response.status_code}"
                                )
                                print(
                                    f"{Config.COLOR_GREEN}{bypass_result}{Config.COLOR_RESET}"
                                )
                                self.results.append(bypass_result)
                        except Exception:
                            continue

            # Save results
            if self.output_file and self.results:
                with open(self.output_file, "w") as f:
                    f.write("\n".join(self.results))
                print(
                    f"\n{Config.COLOR_GREEN}[+] Results saved to {self.output_file}{Config.COLOR_RESET}"
                )

            if self.results:
                print(
                    f"\n{Config.COLOR_GREEN}[+] Found {len(self.results)} results{Config.COLOR_RESET}"
                )
            else:
                print(f"\n{Config.COLOR_RED}[-] No results found{Config.COLOR_RESET}")

        except Exception as e:
            logger.error(f"Error during lookup: {e}")
            print(
                f"\n{Config.COLOR_RED}[-] Error during lookup: {str(e)}{Config.COLOR_RESET}"
            )
            logger.error(f"Error during lookup: {e}")
            print(f"\n{Config.COLOR_RED}[-] Error during lookup: {str(e)}{Config.COLOR_RESET}")
