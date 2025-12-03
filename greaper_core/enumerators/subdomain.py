"""
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

        print(f"\n{Config.COLOR_BLUE}[*] Starting Greaper Subdomain Enumeration{Config.COLOR_RESET}\n")

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
                    f.write(f"{subdomain}\n")
            print(f"\n{Config.COLOR_BLUE}[+] Subdomains saved to {self.output_file}{Config.COLOR_RESET}")

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
                        names = entry["name_value"].split('\n')
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
