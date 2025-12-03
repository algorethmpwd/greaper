"""
Content Length Checker Module
Check and compare content length of responses
"""

import logging
import time

import requests

from ..config import Config

logger = logging.getLogger(__name__)


class ContentLengthChecker:
    """HTTP content length checker"""

    def __init__(self, output_file=None):
        self.output_file = output_file
        self.start_time = None
        self.header_printed = False

    def check(self, url):
        """Check content length for a URL"""
        if not self.header_printed:
            print(
                f"\n{Config.COLOR_BLUE}[*] Greaper Content Length Checker{Config.COLOR_RESET}\n"
            )
            self.header_printed = True
            self.start_time = time.time()

        try:
            headers = Config.get_headers()
            response = requests.get(
                url, timeout=10, headers=headers, allow_redirects=True
            )
            content_length = response.headers.get("Content-Length")
            actual_size = len(response.content)

            size = int(content_length) if content_length else actual_size

            terminal_output = f"{Config.COLOR_GREEN}{url} [{size}b]{Config.COLOR_RESET}"
            file_output = f"{url} [{size}b]"

            print(terminal_output)

            if self.output_file:
                with open(self.output_file, "a") as f:
                    f.write(file_output + "\n")

            return True

        except requests.RequestException as e:
            logger.error(f"Error checking {url}: {e}")
            return False

    def print_summary(self):
        """Print total time elapsed"""
        if self.start_time:
            elapsed_time = time.time() - self.start_time
            print(
                f"\n{Config.COLOR_BLUE}[*] Total time elapsed: {elapsed_time:.2f} seconds{Config.COLOR_RESET}"
            )
