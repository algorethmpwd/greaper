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
                headers = {"User-Agent": Config.USER_AGENT}
                async with session.get(
                    url, timeout=10, ssl=False, headers=headers, allow_redirects=True
                ) as response:
                    print(
                        f"{Config.COLOR_BLUE}[*] Crawling: {url} [{response.status}]{Config.COLOR_RESET}"
                    )
                    if response.status in [200, 301, 302]:
                        content = await response.text()
                        return content
                    return None
            except Exception as e:
                logger.error(f"Error fetching {url}: {e}")
                print(
                    f"{Config.COLOR_RED}[-] Error: {url} - {str(e)[:50]}{Config.COLOR_RESET}"
                )
                return None

    def extract_links(self, url, content):
        """Extract links from page content"""
        soup = BeautifulSoup(content, "html.parser")
        links = set()

        # Extract from all common tags
        tag_attrs = {
            "a": "href",
            "script": "src",
            "link": "href",
            "img": "src",
            "form": "action",
            "iframe": "src",
            "embed": "src",
            "object": "data",
        }

        for tag, attr in tag_attrs.items():
            for element in soup.find_all(tag):
                link = element.get(attr)
                if link and link.strip():
                    # Skip javascript:, mailto:, tel:, data: URIs
                    if link.startswith(
                        ("javascript:", "mailto:", "tel:", "data:", "#")
                    ):
                        continue

                    # Convert to absolute URL
                    full_link = urljoin(url, link.strip())

                    # Only keep links from same domain
                    if (
                        full_link.startswith(("http", "https"))
                        and self.domain in full_link
                    ):
                        # Remove fragments
                        full_link = full_link.split("#")[0]
                        if full_link:
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

        links = self.extract_links(url, content)

        # Print found links
        new_links = links - self.crawled_urls
        if new_links:
            print(
                f"{Config.COLOR_GREEN}[+] Found {len(new_links)} new links on {url}{Config.COLOR_RESET}"
            )

            # Group by file extension
            grouped_links = defaultdict(list)
            for link in new_links:
                ext = os.path.splitext(urlparse(link).path)[1].lower()
                if ext:
                    grouped_links[ext].append(link)
                else:
                    grouped_links["pages"].append(link)

            # Display grouped links
            for ext, ext_links in sorted(grouped_links.items()):
                if ext == "pages":
                    print(f"  {Config.COLOR_PURPLE}Pages:{Config.COLOR_RESET}")
                else:
                    print(f"  {Config.COLOR_PURPLE}{ext} files:{Config.COLOR_RESET}")

                for link in sorted(ext_links)[:10]:  # Show first 10
                    print(f"    {link}")
                if len(ext_links) > 10:
                    print(
                        f"    {Config.COLOR_BLUE}... and {len(ext_links) - 10} more{Config.COLOR_RESET}"
                    )

        # Recursively crawl new links at next depth level
        if current_depth < self.depth and new_links:
            tasks = []
            # Prioritize pages over static resources for crawling
            pages_to_crawl = [
                l
                for l in new_links
                if not os.path.splitext(urlparse(l).path)[1]
                or os.path.splitext(urlparse(l).path)[1].lower()
                in [".html", ".htm", ".php", ".asp", ".aspx", ".jsp"]
            ]

            for link in list(pages_to_crawl)[:20]:  # Limit to 20 links per depth
                task = self.crawl_url(session, link, current_depth + 1, semaphore)
                tasks.append(task)

            if tasks:
                await asyncio.gather(*tasks, return_exceptions=True)

    async def crawl(self):
        """Execute the crawl"""
        start_time = datetime.now()
        print(
            f"\n{Config.COLOR_BLUE}[*] Starting Greaper crawler at {start_time.strftime('%H:%M:%S')}{Config.COLOR_RESET}"
        )
        print(f"{Config.COLOR_BLUE}[*] Crawl depth: {self.depth}{Config.COLOR_RESET}")

        semaphore = asyncio.Semaphore(10)  # Limit concurrent requests

        connector = aiohttp.TCPConnector(ssl=False)
        async with aiohttp.ClientSession(connector=connector) as session:
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
        print(
            f"\n{Config.COLOR_BLUE}[-] Time elapsed: {elapsed_time}{Config.COLOR_RESET}"
        )
        print(
            f"{Config.COLOR_GREEN}[+] Total URLs crawled: {len(self.crawled_urls)}{Config.COLOR_RESET}"
        )

        return self.crawled_urls
