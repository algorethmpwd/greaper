"""
Wordlist Management System for Greaper Scanner
Handles loading and managing wordlists for various scan types
"""

import logging
import os

logger = logging.getLogger(__name__)


def load_wordlist(wordlist_path=None, wordlist_type="directory", size="medium"):
    """
    Load wordlist from file or use default embedded wordlists

    Args:
        wordlist_path: Custom wordlist file path
        wordlist_type: Type of wordlist (directory, subdomain, sqli, xss, lfi)
        size: Size category (small, medium, large) for default wordlists

    Returns:
        list: Wordlist entries
    """
    logger.info(
        f"Loading wordlist: type={wordlist_type}, size={size}, custom_path={wordlist_path}"
    )

    # If custom wordlist provided, load it
    if wordlist_path and os.path.isfile(wordlist_path):
        try:
            with open(wordlist_path, "r", encoding="utf-8", errors="ignore") as f:
                wordlist = [
                    line.strip()
                    for line in f
                    if line.strip() and not line.startswith("#")
                ]
            logger.info(
                f"Loaded {len(wordlist)} entries from custom wordlist: {wordlist_path}"
            )
            return wordlist
        except Exception as e:
            logger.error(f"Error loading custom wordlist: {e}")
            print(f"[-] Error loading wordlist {wordlist_path}: {e}")
            return []

    # Otherwise, check for wordlist files in wordlists/ directory
    wordlist_dir = os.path.join(os.getcwd(), "wordlists")
    if os.path.isdir(wordlist_dir):
        wordlist_file = os.path.join(wordlist_dir, f"{wordlist_type}_{size}.txt")
        if os.path.isfile(wordlist_file):
            try:
                with open(wordlist_file, "r", encoding="utf-8", errors="ignore") as f:
                    wordlist = [
                        line.strip()
                        for line in f
                        if line.strip() and not line.startswith("#")
                    ]
                logger.info(f"Loaded {len(wordlist)} entries from {wordlist_file}")
                return wordlist
            except Exception as e:
                logger.error(f"Error loading wordlist file: {e}")

    # Fallback to embedded defaults
    logger.debug(f"Using embedded default wordlist for {wordlist_type}")
    return get_default_wordlist(wordlist_type, size)


def get_default_wordlist(wordlist_type, size="medium"):
    """Get embedded default wordlists"""
    defaults = {
        "directory_small": [
            "admin",
            "login",
            "test",
            "backup",
            "api",
            "config",
            "uploads",
            "images",
            "files",
            "docs",
        ],
        "directory_medium": [
            "admin",
            "login",
            "test",
            "backup",
            "api",
            "config",
            "uploads",
            "images",
            "files",
            "docs",
            "assets",
            "static",
            "public",
            "private",
            "system",
            "includes",
            "db",
            "database",
            "sql",
            "download",
            "media",
            "data",
            "tmp",
            "temp",
            "cache",
            "logs",
            "old",
            "new",
            "dev",
            "prod",
        ],
        "subdomain_small": [
            "www",
            "mail",
            "ftp",
            "admin",
            "test",
            "dev",
            "api",
            "staging",
            "blog",
        ],
        "subdomain_medium": [
            "www",
            "mail",
            "ftp",
            "admin",
            "test",
            "dev",
            "api",
            "staging",
            "blog",
            "shop",
            "store",
            "forum",
            "support",
            "help",
            "portal",
            "vpn",
            "remote",
            "webmail",
            "cpanel",
        ],
    }

    key = f"{wordlist_type}_{size}"
    return defaults.get(key, defaults.get(f"{wordlist_type}_medium", []))
