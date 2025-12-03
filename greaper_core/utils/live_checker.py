"""
Live URL Checker Module
Check if URLs are live and responding
"""

import logging
import time

import requests
import urllib3

from ..config import Config

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
logger = logging.getLogger(__name__)


class LiveURLChecker:
    """Live URL checker with protocol testing"""

    def __init__(self, output_file=None):
        self.output_file = output_file
        self.start_time = None
        self.header_printed = False
        self.results = []

    def check(self, url):
        """Check if URL is live"""
        if not self.header_printed:
            print(
                f"\n{Config.COLOR_BLUE}[*] Starting Greaper HTTP probing{Config.COLOR_RESET}\n"
            )
            self.header_printed = True
            self.start_time = time.time()

        headers = Config.get_headers()

        for protocol in ["https://", "http://", "ftp://"]:
            try:
                full_url = protocol + url.strip("/")
                response = requests.get(
                    full_url,
                    timeout=3,
                    headers=headers,
                    verify=False,
                    allow_redirects=True,
                )

                if 200 <= response.status_code < 400:
                    result = f"{Config.COLOR_GREEN}{full_url}{Config.COLOR_RESET}"
                    print(result)

                    if self.output_file:
                        self.results.append(full_url)
                    break
            except Exception:
                continue

    def save_results(self):
        """Save results to file"""
        if self.output_file and self.results:
            with open(self.output_file, "w") as f:
                for result in self.results:
                    f.write(result + "\n")

    def print_summary(self):
        """Print total time elapsed"""
        if self.start_time:
            elapsed_time = time.time() - self.start_time
            print(
                f"\n{Config.COLOR_BLUE}[*] Total time elapsed: {elapsed_time:.2f} seconds{Config.COLOR_RESET}"
            )
