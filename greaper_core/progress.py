"""
Progress Tracking and Statistics for Greaper Scanner
"""

import logging
import sys
import time

from tqdm import tqdm

from .config import Config

logger = logging.getLogger(__name__)


def create_progress_bar(iterable, desc="Processing", total=None, disable=False):
    """
    Create progress bar with tqdm
    """
    if disable or not sys.stdout.isatty() or Config.QUIET:
        return iterable

    return tqdm(
        iterable,
        desc=desc,
        total=total,
        unit="item",
        bar_format="{l_bar}{bar}| {n_fmt}/{total_fmt} [{elapsed}<{remaining}, {rate_fmt}]",
        colour="green",
        ncols=100,
    )


class ScanProgress:
    """Track overall scan progress with statistics"""

    def __init__(self, total_targets=1):
        self.total_targets = total_targets
        self.current_target = 0
        self.total_requests = 0
        self.successful_requests = 0
        self.failed_requests = 0
        self.vulnerabilities_found = 0
        self.start_time = time.time()
        self.findings = []

    def update_target(self):
        """Move to next target"""
        self.current_target += 1

    def add_request(self, success=True):
        """Record a request"""
        self.total_requests += 1
        if success:
            self.successful_requests += 1
        else:
            self.failed_requests += 1

    def add_finding(self, finding):
        """Record a vulnerability finding"""
        self.vulnerabilities_found += 1
        self.findings.append(finding)
        logger.warning(f"Vulnerability found: {finding}")

    def get_stats(self):
        """Get current statistics"""
        elapsed = time.time() - self.start_time
        success_rate = (
            (self.successful_requests / self.total_requests * 100)
            if self.total_requests > 0
            else 0
        )

        return {
            "elapsed_time": elapsed,
            "total_requests": self.total_requests,
            "successful_requests": self.successful_requests,
            "failed_requests": self.failed_requests,
            "success_rate": success_rate,
            "vulnerabilities_found": self.vulnerabilities_found,
            "targets_completed": self.current_target,
            "total_targets": self.total_targets,
            "req_per_sec": self.total_requests / elapsed if elapsed > 0 else 0,
        }

    def print_summary(self):
        """Print scan summary statistics"""
        stats = self.get_stats()

        print(
            f"\n{Config.COLOR_BLUE}╔══════════════════════════════════════════════════════════════╗{Config.COLOR_RESET}"
        )
        print(
            f"{Config.COLOR_BLUE}║                  SCAN SUMMARY STATISTICS                     ║{Config.COLOR_RESET}"
        )
        print(
            f"{Config.COLOR_BLUE}╠══════════════════════════════════════════════════════════════╣{Config.COLOR_RESET}"
        )
        print(
            f"{Config.COLOR_GREEN}  Elapsed Time:         {stats['elapsed_time']:.2f}s{Config.COLOR_RESET}"
        )
        print(
            f"{Config.COLOR_GREEN}  Targets Scanned:      {stats['targets_completed']}/{stats['total_targets']}{Config.COLOR_RESET}"
        )
        print(
            f"{Config.COLOR_GREEN}  Total Requests:       {stats['total_requests']}{Config.COLOR_RESET}"
        )
        print(
            f"{Config.COLOR_GREEN}  Success Rate:         {stats['success_rate']:.1f}%{Config.COLOR_RESET}"
        )
        print(
            f"{Config.COLOR_GREEN}  Request Rate:         {stats['req_per_sec']:.2f} req/s{Config.COLOR_RESET}"
        )

        if stats["vulnerabilities_found"] > 0:
            print(
                f"{Config.COLOR_RED}  Vulnerabilities:      {stats['vulnerabilities_found']} found!{Config.COLOR_RESET}"
            )
        else:
            print(
                f"{Config.COLOR_GREEN}  Vulnerabilities:      None found{Config.COLOR_RESET}"
            )

        print(
            f"{Config.COLOR_BLUE}╚══════════════════════════════════════════════════════════════╝{Config.COLOR_RESET}\n"
        )

        logger.info(f"Scan complete: {stats}")
