"""
Web Crawler Module
Asynchronous website crawling with depth control
"""

import asyncio
import logging
import os
import re
from collections import defaultdict
from datetime import datetime
from urllib.parse import urljoin, urlparse

import aiohttp
from bs4 import BeautifulSoup

from ..config import Config

logger = logging.getLogger(__name__)


class WebCrawler:
    """Asynchronous web crawler with depth control"""

    def __init__(self, url, depth=1, output_file=None):
        self.url = url
        self.depth = depth
        self.output_file = output_file
        self.crawled_urls = set()
        self.domain = urlparse(url).netloc

    async def fetch_page(self, session, url, semaphore):
        """Fetch a single page"""
        async with semaphore:
            try:
                async with session.get(url, timeout=5) as response:
                    if response.status != 200:
                        return None
                    content = await response.text()
                    return content
            except Exception as e:
                logger.error(f"Error fetching {url}: {e}")
                return None

        soup = BeautifulSoup(content, "html.parser")
        links = set()

        # Enhanced tag processing
        tag_attrs = {
            "a": "href",
            "script": "src",
            "link": "href",
            "img": "src",
            "form": "action",
        }

        for tag, attr in tag_attrs.items():
            for element in soup.find_all(tag):
                link = element.get(attr)
                if link:
                    full_link = urljoin(url, link)
                    if (
                        full_link.startswith(("http", "https"))
                        and self.domain in full_link
                    ):
                        links.add(full_link)

        # Enhanced file type detection
        interesting_files = r"\.(txt|json|js|zip|tar\.gz|sql|csv|xml|graphql|env|yml|pdf|doc|xls|config|bak|backup|old|temp|tmp|log)$"
        for link in soup.find_all("a", href=re.compile(interesting_files, re.I)):
            full_link = urljoin(url, link.get("href"))
            if full_link.startswith(("http", "https")) and self.domain in full_link:
                links.add(full_link)

        return links

    async def crawl_url(self, session, url, current_depth, semaphore):
        """Crawl a single URL recursively"""
        if url in self.crawled_urls or current_depth > self.depth:
            return

        self.crawled_urls.add(url)

        content = await self.fetch_page(session, url, semaphore)
        if not content:
            return

        links = await self.extract_links(url, content)

        if links:
            print(f"\n{Config.COLOR_BLUE}[*] URL: {url}{Config.COLOR_RESET}")
            print(
                f"{Config.COLOR_GREEN}[+] Found {len(links)} links{Config.COLOR_RESET}"
            )

            # Group links by file type
            grouped_links = defaultdict(list)
            for link in links:
                ext = os.path.splitext(link)[1].lower() or "no_extension"
                grouped_links[ext].append(link)

            for ext, ext_links in grouped_links.items():
                print(
                    f"\n{Config.COLOR_PURPLE}[*] {ext.upper()} files:{Config.COLOR_RESET}"
                )
                for link in sorted(ext_links):
                    print(f"    {link}")

        # Recursively crawl new links
        if current_depth < self.depth:
            tasks = []
            for link in links - self.crawled_urls:
                task = self.crawl_url(session, link, current_depth + 1, semaphore)
                tasks.append(task)

            if tasks:
                await asyncio.gather(*tasks)

    async def crawl(self):
        """Execute the crawl"""
        start_time = datetime.now()
        print(
            f"\n{Config.COLOR_BLUE}[*] Starting Greaper crawler at {start_time.strftime('%H:%M:%S')}{Config.COLOR_RESET}"
        )
        print(f"{Config.COLOR_BLUE}[*] Crawl depth: {self.depth}{Config.COLOR_RESET}")

        semaphore = asyncio.Semaphore(10)  # Limit concurrent requests

        async with aiohttp.ClientSession() as session:
            await self.crawl_url(session, self.url, 1, semaphore)

        # Save results
        if self.output_file:
            with open(self.output_file, "w", encoding="utf-8") as f:
                for url in sorted(self.crawled_urls):
                    f.write(f"{url}\n")
            print(
                f"\n{Config.COLOR_GREEN}[+] Results saved to {self.output_file}{Config.COLOR_RESET}"
            )

        elapsed_time = datetime.now() - start_time
        print(
            f"\n{Config.COLOR_BLUE}[-] Time elapsed: {elapsed_time}{Config.COLOR_RESET}"
        )
        print(
            f"{Config.COLOR_GREEN}[+] Total URLs crawled: {len(self.crawled_urls)}{Config.COLOR_RESET}"
        )
        print(f"\n{Config.COLOR_BLUE}[-] Time elapsed: {elapsed_time}{Config.COLOR_RESET}")
        print(f"{Config.COLOR_GREEN}[+] Total URLs crawled: {len(self.crawled_urls)}{Config.COLOR_RESET}")

        return self.crawled_urls
