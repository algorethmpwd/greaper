"""
Base Scanner Class
All scanners inherit from this base class
"""

import logging

import requests
from retrying import retry

from ..config import Config

logger = logging.getLogger(__name__)


class BaseScanner:
    """Base class for all vulnerability scanners"""

    def __init__(self, target, output_file=None):
        self.target = target
        self.output_file = output_file
        self.session = self._create_session()
        self.results = []

    def _create_session(self):
        """Create configured requests session"""
        session = requests.Session()
        session.verify = Config.VERIFY_SSL
        session.headers.update(Config.get_headers())
        return session

    @retry(stop_max_attempt_number=3, wait_exponential_multiplier=1000)
    def make_request(self, url, method="GET", data=None, timeout=None, **kwargs):
        """Make HTTP request with retry mechanism"""
        if timeout is None:
            timeout = Config.DEFAULT_TIMEOUT

        try:
            if method == "GET":
                return self.session.get(url, timeout=timeout, **kwargs)
            elif method == "POST":
                return self.session.post(url, data=data, timeout=timeout, **kwargs)
            elif method == "PUT":
                return self.session.put(url, data=data, timeout=timeout, **kwargs)
        except requests.Timeout:
            logger.warning(f"Request timed out, retrying: {url}")
            raise
        except requests.RequestException as e:
            logger.error(f"Request error: {str(e)}")
            raise

    def save_results(self):
        """Save results to output file"""
        if self.output_file and self.results:
            try:
                with open(self.output_file, "w", encoding="utf-8") as f:
                    f.write("\n".join(self.results))
                logger.info(f"Results saved to {self.output_file}")
                print(
                    f"{Config.COLOR_GREEN}[+] Results saved to {self.output_file}{Config.COLOR_RESET}"
                )
            except Exception as e:
                logger.error(f"Error saving results: {e}")
                print(
                    f"{Config.COLOR_RED}[-] Error saving results: {str(e)}{Config.COLOR_RESET}"
                )

    def scan(self):
        """Main scan method - to be implemented by subclasses"""
        raise NotImplementedError("Subclasses must implement scan() method")
