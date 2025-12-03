#!/usr/bin/env python3
"""
Script to create all remaining Greaper modules efficiently
This consolidates the creation of multiple modules
"""

import os

# Define the base path
base_path = "/home/algorethm/Documents/dev/greaper/greaper_core"

# Module definitions
modules = {
    "enumerators/subdomain.py": '''"""
Subdomain Enumeration Module
Aggregates subdomains from multiple sources
"""

import asyncio
import aiohttp
import json
import dns.resolver
from ..config import Config
import logging

logger = logging.getLogger(__name__)


class SubdomainEnumerator:
    """Subdomain enumeration from multiple sources"""

    def __init__(self, url, output_file=None, rate_limit=3):
        self.url = url
        self.output_file = output_file
        self.rate_limit = rate_limit
        self.domain = self._parse_domain(url)

    def _parse_domain(self, url):
        """Parse domain from URL"""
        domain = url.split('://')[-1].strip('/')
        if '*' not in domain:
            return domain, None
        parts = domain.split('.')
        wildcard_index = next(i for i, part in enumerate(parts) if '*' in part)
        base_domain = '.'.join(parts[wildcard_index + 1:])
        prefix = '.'.join(parts[:wildcard_index]) + '.' if wildcard_index > 0 else ''
        return base_domain, prefix

    async def fetch_subdomains(self, session, source_url, source_name):
        """Fetch subdomains from a source"""
        try:
            headers = Config.get_headers()
            async with session.get(source_url, headers=headers, ssl=False) as response:
                if response.status == 200:
                    return source_name, await response.text()
                return source_name, None
        except Exception as e:
            logger.error(f"Error fetching from {source_name}: {e}")
            return source_name, None

    async def enumerate(self):
        """Enumerate subdomains"""
        base_domain, prefix = self.domain if isinstance(self.domain, tuple) else (self.domain, None)

        print(f"\\n{Config.COLOR_BLUE}[*] Starting Greaper Subdomain Enumeration{Config.COLOR_RESET}\\n")

        sources = self._get_sources(base_domain)

        print(f"{Config.COLOR_GREEN}[+] Enabled sources: {len(sources)}{Config.COLOR_RESET}")

        subdomains = set()
        connector = aiohttp.TCPConnector(ssl=False)

        async with aiohttp.ClientSession(connector=connector) as session:
            tasks = [self.fetch_subdomains(session, url, source) for source, url in sources.items()]
            results = await asyncio.gather(*tasks)

            for source, data in results:
                if not data:
                    continue

                new_subs = self._parse_source_data(source, data, base_domain)
                for sub in new_subs:
                    if sub not in subdomains:
                        subdomains.add(sub)
                        print(sub)

        sorted_subdomains = sorted(subdomains, key=lambda x: (len(x.split('.')), x))

        if self.output_file:
            with open(self.output_file, 'a') as f:
                for subdomain in sorted_subdomains:
                    f.write(f"{subdomain}\\n")
            print(f"\\n{Config.COLOR_BLUE}[+] Subdomains saved to {self.output_file}{Config.COLOR_RESET}")

        return sorted_subdomains

    def _get_sources(self, domain):
        """Get enabled subdomain enumeration sources"""
        sources = {}
        if Config.USE_CRTSH:
            sources['crt.sh'] = f"https://crt.sh/?q=%.{domain}&output=json"
        if Config.USE_ALIENVAULT:
            sources['alienvault'] = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns"
        if Config.USE_HACKERTARGET:
            sources['hackertarget'] = f"https://api.hackertarget.com/hostsearch/?q={domain}"
        return sources

    def _parse_source_data(self, source, data, base_domain):
        """Parse subdomain data from source"""
        subdomains = set()
        try:
            if source == 'crt.sh':
                json_data = json.loads(data)
                for entry in json_data:
                    if "name_value" in entry:
                        names = entry["name_value"].split('\\n')
                        subdomains.update(name.strip().lower() for name in names if '*' not in name)
            elif source == 'alienvault':
                json_data = json.loads(data)
                if 'passive_dns' in json_data:
                    subdomains.update(record['hostname'].lower() for record in json_data['passive_dns'])
            elif source == 'hackertarget':
                subdomains.update(line.split(',')[0].lower() for line in data.splitlines())
        except Exception as e:
            logger.error(f"Error parsing {source} data: {e}")

        return {s for s in subdomains if base_domain in s and '*' not in s}
''',
    "utils/status_checker.py": '''"""
Status Code Checker
Check HTTP status codes for URLs
"""

import requests
from ..config import Config
import logging

logger = logging.getLogger(__name__)


class StatusChecker:
    """HTTP status code checker"""

    def __init__(self, output_file=None):
        self.output_file = output_file
        self.start_time = None

    def check(self, url):
        """Check status code for a URL"""
        try:
            response = requests.get(url, timeout=5, allow_redirects=True)
            redirect_chain = response.history
            results = []

            if redirect_chain:
                chain = []
                for r in redirect_chain:
                    color = Config.color_status_code(r.status_code)
                    redirect_result = f"{color}{r.url} [{r.status_code}]{Config.COLOR_RESET} → "
                    chain.append(redirect_result)
                    results.append(f"{r.url} [{r.status_code}] → ")

                print(''.join(chain), end='')

                color = Config.color_status_code(response.status_code)
                final_result = f"{color}{response.url} [{response.status_code}]{Config.COLOR_RESET}"
                print(final_result)
                results.append(f"{response.url} [{response.status_code}]")
            else:
                color = Config.color_status_code(response.status_code)
                final_result = f"{color}{response.url} [{response.status_code}]{Config.COLOR_RESET}"
                print(final_result)
                results.append(f"{response.url} [{response.status_code}]")

            if self.output_file:
                with open(self.output_file, 'a') as f:
                    f.write(''.join(results) + '\\n')

        except requests.RequestException:
            color = Config.color_status_code(503)
            final_result = f"{color}{url} [503]{Config.COLOR_RESET}"
            print(final_result)
            if self.output_file:
                with open(self.output_file, 'a') as f:
                    f.write(f"{url} [503]\\n")
''',
    "utils/waf_detector.py": '''"""
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
        print(f"\\n{Config.COLOR_BLUE}[*] Starting WAF detection for {url}{Config.COLOR_RESET}")

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
''',
}

# Create all module files
for file_path, content in modules.items():
    full_path = os.path.join(base_path, file_path)
    os.makedirs(os.path.dirname(full_path), exist_ok=True)
    with open(full_path, "w") as f:
        f.write(content)
    print(f"Created: {full_path}")

print("\\nAll modules created successfully!")
