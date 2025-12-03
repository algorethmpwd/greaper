"""
Configuration Management for Greaper Scanner
Handles environment variables and default settings
"""

import os

from dotenv import load_dotenv

# Load environment variables
load_dotenv()


class Config:
    """Centralized configuration management"""

    # Version
    GREAPER_VERSION = os.getenv("GREAPER_VERSION", "v2.0")

    # Network Settings
    DEFAULT_TIMEOUT = int(os.getenv("DEFAULT_TIMEOUT", "10"))
    DEFAULT_RATE_LIMIT = int(os.getenv("DEFAULT_RATE_LIMIT", "10"))
    VERIFY_SSL = os.getenv("VERIFY_SSL", "false").lower() == "true"

    # User Agent
    USER_AGENT = os.getenv(
        "USER_AGENT",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    )

    # Output Settings
    COLOR_OUTPUT = os.getenv("COLOR_OUTPUT", "true").lower() == "true"
    VERBOSE = os.getenv("VERBOSE", "false").lower() == "true"
    QUIET = os.getenv("QUIET", "false").lower() == "true"

    # API Keys for subdomain enumeration
    VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "")
    SECURITYTRAILS_API_KEY = os.getenv("SECURITYTRAILS_API_KEY", "")

    # Subdomain enumeration source toggles
    USE_VIRUSTOTAL = os.getenv("USE_VIRUSTOTAL", "false").lower() == "true"
    USE_SECURITYTRAILS = os.getenv("USE_SECURITYTRAILS", "false").lower() == "true"
    USE_BUFFEROVER = os.getenv("USE_BUFFEROVER", "false").lower() == "true"
    USE_RIDDLER = os.getenv("USE_RIDDLER", "false").lower() == "true"
    USE_CRTSH = os.getenv("USE_CRTSH", "true").lower() == "true"
    USE_ALIENVAULT = os.getenv("USE_ALIENVAULT", "true").lower() == "true"
    USE_HACKERTARGET = os.getenv("USE_HACKERTARGET", "true").lower() == "true"
    USE_THREATCROWD = os.getenv("USE_THREATCROWD", "true").lower() == "true"
    USE_URLSCAN = os.getenv("USE_URLSCAN", "true").lower() == "true"
    USE_CERTSPOTTER = os.getenv("USE_CERTSPOTTER", "true").lower() == "true"
    USE_THREATMINER = os.getenv("USE_THREATMINER", "true").lower() == "true"

    # ANSI Color Codes
    COLOR_GREEN = "\033[92m"
    COLOR_RED = "\033[91m"
    COLOR_ORANGE = "\033[93m"
    COLOR_PURPLE = "\033[95m"
    COLOR_YELLOW = "\033[93m"
    COLOR_BLUE = "\033[94m"
    COLOR_GREY = "\033[90m"
    COLOR_RESET = "\033[0m"

    @classmethod
    def get_headers(cls):
        """Get standard HTTP headers"""
        return {
            "User-Agent": cls.USER_AGENT,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Accept-Encoding": "gzip, deflate",
            "Connection": "keep-alive",
        }

    @classmethod
    def color_status_code(cls, status_code):
        """Return color based on status code"""
        if 200 <= status_code < 300:
            return cls.COLOR_GREEN
        elif 300 <= status_code < 400:
            return cls.COLOR_PURPLE
        elif 400 <= status_code < 500:
            return cls.COLOR_BLUE
        elif 500 <= status_code < 600:
            return cls.COLOR_RED
        return cls.COLOR_GREY
