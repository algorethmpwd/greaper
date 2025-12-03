"""
Logging System for Greaper Scanner
Structured logging with multiple log levels and file handlers
"""

import logging
import os

from .config import Config


def setup_logging():
    """
    Initialize structured logging system with multiple log files
    """
    log_dir = os.path.join(os.getcwd(), "logs")
    os.makedirs(log_dir, exist_ok=True)

    # Configure log format
    log_format = (
        "%(asctime)s - %(name)s - %(levelname)s - %(module)s:%(lineno)d - %(message)s"
    )
    date_format = "%Y-%m-%d %H:%M:%S"

    # Root logger
    logging.basicConfig(
        level=logging.DEBUG if Config.VERBOSE else logging.INFO,
        format=log_format,
        datefmt=date_format,
    )

    # File handlers for different log levels
    debug_handler = logging.FileHandler(os.path.join(log_dir, "greaper_debug.log"))
    debug_handler.setLevel(logging.DEBUG)
    debug_handler.setFormatter(logging.Formatter(log_format, date_format))

    info_handler = logging.FileHandler(os.path.join(log_dir, "greaper_info.log"))
    info_handler.setLevel(logging.INFO)
    info_handler.setFormatter(logging.Formatter(log_format, date_format))

    error_handler = logging.FileHandler(os.path.join(log_dir, "greaper_errors.log"))
    error_handler.setLevel(logging.ERROR)
    error_handler.setFormatter(logging.Formatter(log_format, date_format))

    findings_handler = logging.FileHandler(
        os.path.join(log_dir, "greaper_findings.log")
    )
    findings_handler.setLevel(logging.WARNING)
    findings_handler.setFormatter(logging.Formatter(log_format, date_format))

    # Add handlers to root logger
    logger = logging.getLogger()
    logger.addHandler(debug_handler)
    logger.addHandler(info_handler)
    logger.addHandler(error_handler)
    logger.addHandler(findings_handler)

    return logger
