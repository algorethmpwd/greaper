#!/usr/bin/env python3
"""
Greaper Scanner v2.0 - Complete Modular Architecture
Comprehensive web application security scanner

Author: algorethm
GitHub: https://github.com/algorethmpwd/greaper
"""

import argparse
import asyncio
import concurrent.futures
import os
import random
import sys
import warnings

import pyfiglet
import urllib3

# Suppress SSL warnings
os.environ["PYTHONWARNINGS"] = "ignore:Unverified HTTPS request"
warnings.filterwarnings("ignore")
urllib3.disable_warnings()

# Import modular components
from greaper_core import Config, ScanProgress, setup_logging
from greaper_core.enumerators import JSScanner, SubdomainEnumerator, WebCrawler
from greaper_core.output import OutputFormatter
from greaper_core.scanners import (
    CORSScanner,
    HostHeaderScanner,
    LFIScanner,
    SQLiScanner,
    SSRFScanner,
    XSSScanner,
    XXEScanner,
)
from greaper_core.utils import (
    ContentLengthChecker,
    CVEScanner,
    DirectoryFuzzer,
    IPLookup,
    LiveURLChecker,
    SecurityHeadersChecker,
    StatusChecker,
    WAFDetector,
)

# Initialize logging
logger = setup_logging()

# Display banner
available_fonts = pyfiglet.FigletFont.getFonts()
color_codes = [31, 32, 33, 34, 35, 36, 91, 92, 93, 94, 95, 96]
font = random.choice(available_fonts)
color_code = random.choice(color_codes)
ascii_art = pyfiglet.figlet_format("GREAPER", font=font, width=80)
colored_ascii = f"\033[{color_code}m{ascii_art}\033[0m"
print(colored_ascii)
print(f"\033[{color_code}m{Config.GREAPER_VERSION}\033[0m")
print(" " * 2 + "made by algorethm")


def apply_scan_profile(profile_name, args):
    """Apply predefined scanning profiles"""
    profiles = {
        "recon": {
            "description": "Reconnaissance - subdomain enum, crawling, info gathering",
            "flags": {
                "sub_enum": True,
                "crawl": 2,
                "info": True,
                "sec": True,
                "waf": True,
            },
        },
        "quick": {
            "description": "Quick scan - status, security headers, WAF",
            "flags": {"sc": True, "sec": True, "waf": True, "cors": True},
        },
        "full-scan": {
            "description": "Comprehensive vulnerability assessment",
            "flags": {
                "sub_enum": True,
                "crawl": 3,
                "sqli": True,
                "xss": True,
                "lfi": True,
                "cors": True,
                "hh": True,
                "ssrf": True,
                "xxe": True,
                "sec": True,
                "cve": True,
                "info": True,
            },
        },
        "bugbounty": {
            "description": "Bug bounty hunting mode",
            "flags": {
                "sub_enum": True,
                "crawl": 4,
                "sqli": True,
                "xss": True,
                "lfi": True,
                "cors": True,
                "hh": True,
                "ssrf": True,
                "xxe": True,
                "info": True,
                "rate_limit": 2,
            },
        },
        "stealth": {
            "description": "Stealth mode - slow, careful scanning",
            "flags": {"sc": True, "sec": True, "cors": True, "rate_limit": 1},
        },
    }

    if profile_name in profiles:
        profile = profiles[profile_name]
        print(
            f"{Config.COLOR_BLUE}[*] Applying profile: {profile_name}{Config.COLOR_RESET}"
        )
        print(
            f"{Config.COLOR_BLUE}[*] Description: {profile['description']}{Config.COLOR_RESET}"
        )

        for flag, value in profile["flags"].items():
            setattr(args, flag, value)

    return args


# Scanner runners
def run_sqli_scanner(url, args):
    scanner = SQLiScanner(
        target=url, payload_file=args.payload_file, output_file=args.output
    )
    scanner.scan()


def run_xss_scanner(url, args):
    if not args.payload_file:
        print(
            f"{Config.COLOR_RED}[-] XSS scanner requires payload file (-p){Config.COLOR_RESET}"
        )
        return
    scanner = XSSScanner(
        target=url, payload_file=args.payload_file, output_file=args.output
    )
    scanner.scan()


def run_lfi_scanner(url, args):
    if not args.payload_file:
        print(
            f"{Config.COLOR_RED}[-] LFI scanner requires payload file (-p){Config.COLOR_RESET}"
        )
        return
    scanner = LFIScanner(
        target=url, payload_file=args.payload_file, output_file=args.output
    )
    scanner.scan()


def run_cors_scanner(url, args):
    scanner = CORSScanner(target=url, output_file=args.output)
    scanner.scan()


def run_host_header_scanner(url, args):
    scanner = HostHeaderScanner(target=url, output_file=args.output)
    scanner.scan()


def run_ssrf_scanner(url, args):
    scanner = SSRFScanner(
        target=url, payload_file=args.payload_file, output_file=args.output
    )
    scanner.scan()


def run_xxe_scanner(url, args):
    scanner = XXEScanner(
        target=url, payload_file=args.payload_file, output_file=args.output
    )
    scanner.scan()


def run_subdomain_enum(url, args):
    enumerator = SubdomainEnumerator(
        url=url, output_file=args.output, rate_limit=args.rate_limit
    )
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        loop.run_until_complete(enumerator.enumerate())
    finally:
        loop.close()


def run_crawler(url, args):
    crawler = WebCrawler(url=url, depth=args.crawl, output_file=args.output)
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        loop.run_until_complete(crawler.crawl())
    finally:
        loop.close()


def run_js_scanner(url, args):
    scanner = JSScanner(target=url, output_file=args.output)
    scanner.scan()


def run_cve_scanner(url, args):
    scanner = CVEScanner(url=url, output_file=args.output)
    scanner.scan()


def run_directory_fuzzer(url, args):
    fuzzer = DirectoryFuzzer(
        target=url, payload_file=args.payload_file, output_file=args.output
    )
    fuzzer.fuzz()


def run_content_length(url, args, checker):
    checker.check(url)


def run_live_checker(url, args, checker):
    checker.check(url)


def run_security_headers(url, args):
    checker = SecurityHeadersChecker(url=url, output_file=args.output)
    checker.check()


def run_ip_lookup(url, args):
    lookup = IPLookup(target=url, output_file=args.output)
    lookup.lookup()


def run_status_checker(url, args):
    checker = StatusChecker(output_file=args.output)
    checker.check(url)


def run_waf_detector(url, args):
    detector = WAFDetector()
    detector.detect(url)


def process_urls(urls, scanner_func, args):
    """Process multiple URLs with a scanner function"""
    with concurrent.futures.ThreadPoolExecutor() as executor:
        executor.map(lambda u: scanner_func(u, args), urls)


def main():
    parser = argparse.ArgumentParser(
        description="Greaper Scanner v2.0 - Web Application Security Testing Tool"
    )

    # Core arguments
    parser.add_argument("-u", "--url", help="Single target URL to scan")
    parser.add_argument("-l", "--list", help="File containing multiple URLs")
    parser.add_argument("-o", "--output", help="Output file to save results")
    parser.add_argument(
        "--rate-limit", type=int, default=3, help="Rate limit for requests"
    )

    # Profiles and output formats
    parser.add_argument(
        "--profile",
        choices=["recon", "quick", "full-scan", "bugbounty", "stealth"],
        help="Use predefined scanning profile",
    )
    parser.add_argument(
        "--format",
        choices=["txt", "json", "csv", "html", "markdown"],
        default="txt",
        help="Output format",
    )

    # Vulnerability scanners
    parser.add_argument(
        "-sqli", action="store_true", help="Enable SQL Injection detection"
    )
    parser.add_argument("-xss", action="store_true", help="Enable XSS scanning")
    parser.add_argument("-lfi", action="store_true", help="Enable LFI scanning")
    parser.add_argument(
        "-cors", action="store_true", help="Scan for CORS misconfigurations"
    )
    parser.add_argument(
        "-hh", action="store_true", help="Scan for Host Header Injection"
    )
    parser.add_argument(
        "-ssrf", action="store_true", help="Scan for SSRF vulnerabilities"
    )
    parser.add_argument(
        "-xxe", action="store_true", help="Scan for XXE vulnerabilities"
    )

    # Information gathering
    parser.add_argument(
        "-s", "--sub-enum", action="store_true", help="Enable subdomain enumeration"
    )
    parser.add_argument(
        "-crawl", nargs="?", const=2, type=int, help="Crawl site (specify depth)"
    )
    parser.add_argument(
        "-info", action="store_true", help="Scan JS files for sensitive info"
    )
    parser.add_argument(
        "-ip", action="store_true", help="Perform IP lookup and WAF bypass"
    )

    # Security auditing
    parser.add_argument("-sec", action="store_true", help="Check security headers")
    parser.add_argument("-cve", action="store_true", help="Scan for CVEs")
    parser.add_argument("-waf", action="store_true", help="Detect WAF")

    # Utility functions
    parser.add_argument("-sc", action="store_true", help="Check status codes")
    parser.add_argument("-df", action="store_true", help="Directory fuzzing")
    parser.add_argument("-cl", action="store_true", help="Check content length")
    parser.add_argument("-lv", action="store_true", help="Check if URLs are live")

    # Additional options
    parser.add_argument(
        "-p", "--payload-file", help="Payload file for vulnerability scans"
    )
    parser.add_argument(
        "-dynamic", action="store_true", help="Enable dynamic payload generation"
    )

    args = parser.parse_args()

    # Apply profile if specified
    if args.profile:
        args = apply_scan_profile(args.profile, args)

    # Get URLs
    urls = []
    if args.url:
        urls = [args.url]
    elif args.list:
        with open(args.list, "r") as f:
            urls = [
                line.strip() for line in f if line.strip() and not line.startswith("#")
            ]
    else:
        print(
            f"{Config.COLOR_RED}[-] Please provide a target URL (-u) or URL list (-l){Config.COLOR_RESET}"
        )
        return

    # Execute scans based on flags
    if args.sub_enum:
        for url in urls:
            run_subdomain_enum(url, args)

    elif args.crawl:
        for url in urls:
            run_crawler(url, args)

    elif args.info:
        for url in urls:
            run_js_scanner(url, args)

    elif args.cve:
        for url in urls:
            run_cve_scanner(url, args)

    elif args.df:
        for url in urls:
            run_directory_fuzzer(url, args)

    elif args.sec:
        for url in urls:
            run_security_headers(url, args)

    elif args.ip:
        for url in urls:
            run_ip_lookup(url, args)

    elif args.cl:
        checker = ContentLengthChecker(output_file=args.output)
        for url in urls:
            run_content_length(url, args, checker)
        checker.print_summary()

    elif args.lv:
        checker = LiveURLChecker(output_file=args.output)
        for url in urls:
            run_live_checker(url, args, checker)
        checker.save_results()
        checker.print_summary()

    elif args.sqli:
        if len(urls) == 1:
            run_sqli_scanner(urls[0], args)
        else:
            process_urls(urls, run_sqli_scanner, args)

    elif args.xss:
        if len(urls) == 1:
            run_xss_scanner(urls[0], args)
        else:
            process_urls(urls, run_xss_scanner, args)

    elif args.lfi:
        if len(urls) == 1:
            run_lfi_scanner(urls[0], args)
        else:
            process_urls(urls, run_lfi_scanner, args)

    elif args.cors:
        if len(urls) == 1:
            run_cors_scanner(urls[0], args)
        else:
            process_urls(urls, run_cors_scanner, args)

    elif args.hh:
        if len(urls) == 1:
            run_host_header_scanner(urls[0], args)
        else:
            process_urls(urls, run_host_header_scanner, args)

    elif args.ssrf:
        if len(urls) == 1:
            run_ssrf_scanner(urls[0], args)
        else:
            process_urls(urls, run_ssrf_scanner, args)

    elif args.xxe:
        if len(urls) == 1:
            run_xxe_scanner(urls[0], args)
        else:
            process_urls(urls, run_xxe_scanner, args)

    elif args.sc:
        for url in urls:
            run_status_checker(url, args)

    elif args.waf:
        for url in urls:
            run_waf_detector(url, args)

    else:
        print(
            f"{Config.COLOR_ORANGE}[-] Please specify a scan type{Config.COLOR_RESET}"
        )
        print(
            f"{Config.COLOR_BLUE}[*] Try using --profile for predefined scan combinations{Config.COLOR_RESET}"
        )
        print(
            f"{Config.COLOR_BLUE}[*] Or use --help to see all available options{Config.COLOR_RESET}"
        )


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nKeyboard interrupt received. Exiting...")
    except Exception as e:
        print(
            f"{Config.COLOR_ORANGE}An unexpected error occurred: {e}{Config.COLOR_RESET}"
        )
        logger.exception("Unexpected error in main")
    finally:
        sys.exit(0)
