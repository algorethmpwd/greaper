"""
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
                    f.write(''.join(results) + '\n')

        except requests.RequestException:
            color = Config.color_status_code(503)
            final_result = f"{color}{url} [503]{Config.COLOR_RESET}"
            print(final_result)
            if self.output_file:
                with open(self.output_file, 'a') as f:
                    f.write(f"{url} [503]\n")
