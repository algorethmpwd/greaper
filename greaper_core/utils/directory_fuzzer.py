"""
Directory Fuzzer Module
Directory and path fuzzing
"""

import logging

import requests

from ..config import Config
from ..wordlist import load_wordlist

logger = logging.getLogger(__name__)


class DirectoryFuzzer:
    """Directory and path fuzzing scanner"""

    def __init__(self, target, payload_file=None, output_file=None):
        self.target = target
        self.payload_file = payload_file
        self.output_file = output_file
        self.results = []

    def fuzz(self):
        """Execute directory fuzzing"""
        print(f"[*] Starting directory fuzzing on {self.target}")

        # Load wordlist
        if self.payload_file:
            directories = load_wordlist(self.payload_file, "directory", "medium")
        else:
            directories = load_wordlist(None, "directory", "medium")

        if not directories:
            print(f"{Config.COLOR_RED}[-] No directories to test{Config.COLOR_RESET}")
            return

        print(
            f"{Config.COLOR_PURPLE}[*] Testing {len(directories)} directories{Config.COLOR_RESET}"
        )

        for directory in directories:
            url = f"{self.target.rstrip('/')}/{directory}"
            try:
                response = requests.get(url, timeout=5, allow_redirects=False)
                status_code = response.status_code
                color = Config.color_status_code(status_code)

                result = f"{url} [Status {status_code}]"
                self.results.append(result)

                if status_code != 404:
                    print(f"{color}{result}{Config.COLOR_RESET}")

            except requests.RequestException as e:
                logger.error(f"Error accessing {url}: {e}")

        # Save results
        if self.output_file and self.results:
            with open(self.output_file, "w") as f:
                f.write("\n".join(self.results))
            print(
                f"\n{Config.COLOR_GREEN}[+] Results saved to {self.output_file}{Config.COLOR_RESET}"
            )

        print(
            f"\n{Config.COLOR_BLUE}[*] Fuzzing complete. Found {len([r for r in self.results if '404' not in r])} accessible paths{Config.COLOR_RESET}"
        )
