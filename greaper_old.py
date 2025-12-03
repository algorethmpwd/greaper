#!/usr/bin/env python3
"""
Greaper Scanner v2.0 - Modular Architecture
Comprehensive web application security scanner

Author: algorethm
GitHub: https://github.com/algorethmpwd/greaper
"""

import os
import sys
import argparse
import asyncio
import concurrent.futures
import warnings
import urllib3
import pyfiglet
import random

# Suppress SSL warnings
os.environ['PYTHONWARNINGS'] = 'ignore:Unverified HTTPS request'
warnings.filterwarnings('ignore')
urllib3.disable_warnings()

# Import modular components
from greaper_core import Config, setup_logging, ScanProgress
from greaper_core.scanners import SQLiScanner, XSSScanner, LFIScanner, CORSScanner, HostHeaderScanner
from greaper_core.enumerators import SubdomainEnumerator
from greaper_core.utils import StatusChecker, WAFDetector
from greaper_core.output import OutputFormatter

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
            "flags": {"sub_enum": True, "sec": True, "waf": True}
        },
        "quick": {
            "description": "Quick scan - status, security headers, WAF",
            "flags": {"sc": True, "sec": True, "waf": True, "cors": True}
        },
        "full-scan": {
            "description": "Comprehensive vulnerability assessment",
            "flags": {
                "sub_enum": True, "sqli": True, "xss": True, "lfi": True,
                "cors": True, "hh": True, "sec": True, "waf": True
            }
        },
        "bugbounty": {
            "description": "Bug bounty hunting mode",
            "flags": {
                "sub_enum": True, "sqli": True, "xss": True, "lfi": True,
                "cors": True, "hh": True, "rate_limit": 2
            }
        },
        "stealth": {
            "description": "Stealth mode - slow, careful scanning",
            "flags": {"sc": True, "sec": True, "cors": True, "rate_limit": 1}
        }
    }

    if profile_name in profiles:
        profile = profiles[profile_name]
        print(f"{Config.COLOR_BLUE}[*] Applying profile: {profile_name}{Config.COLOR_RESET}")
        print(f"{Config.COLOR_BLUE}[*] Description: {profile['description']}{Config.COLOR_RESET}")

        for flag, value in profile["flags"].items():
            setattr(args, flag, value)

    return args


def run_sqli_scanner(url, args):
    """Run SQL Injection scanner"""
    scanner = SQLiScanner(
        target=url,
        payload_file=args.payload_file,
        output_file=args.output
    )
    scanner.scan()


def run_xss_scanner(url, args):
    """Run XSS scanner"""
    if not args.payload_file:
        print(f"{Config.COLOR_RED}[-] XSS scanner requires payload file (-p){Config.COLOR_RESET}")
        return
    scanner = XSSScanner(
        target=url,
        payload_file=args.payload_file,
        output_file=args.output
    )
    scanner.scan()


def run_lfi_scanner(url, args):
    """Run LFI scanner"""
    if not args.payload_file:
        print(f"{Config.COLOR_RED}[-] LFI scanner requires payload file (-p){Config.COLOR_RESET}")
        return
    scanner = LFIScanner(
        target=url,
        payload_file=args.payload_file,
        output_file=args.output
    )
    scanner.scan()


def run_cors_scanner(url, args):
    """Run CORS scanner"""
    scanner = CORSScanner(target=url, output_file=args.output)
    scanner.scan()


def run_host_header_scanner(url, args):
    """Run Host Header Injection scanner"""
    scanner = HostHeaderScanner(target=url, output_file=args.output)
    scanner.scan()


def run_subdomain_enum(url, args):
    """Run subdomain enumeration"""
    enumerator = SubdomainEnumerator(
        url=url,
        output_file=args.output,
        rate_limit=args.rate_limit
    )

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        loop.run_until_complete(enumerator.enumerate())
    finally:
        loop.close()


def run_status_checker(url, args):
    """Run status code checker"""
    checker = StatusChecker(output_file=args.output)
    checker.check(url)


def run_waf_detector(url, args):
    """Run WAF detection"""
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
    parser.add_argument("--rate-limit", type=int, default=3, help="Rate limit for requests")

    # Profiles and output formats
    parser.add_argument("--profile", choices=["recon", "quick", "full-scan", "bugbounty", "stealth"],
                       help="Use predefined scanning profile")
    parser.add_argument("--format", choices=["txt", "json", "csv", "html", "markdown"],
                       default="txt", help="Output format")

    # Vulnerability scanners
    parser.add_argument("-sqli", action="store_true", help="Enable SQL Injection detection")
    parser.add_argument("-xss", action="store_true", help="Enable XSS scanning")
    parser.add_argument("-lfi", action="store_true", help="Enable LFI scanning")
    parser.add_argument("-cors", action="store_true", help="Scan for CORS misconfigurations")
    parser.add_argument("-hh", action="store_true", help="Scan for Host Header Injection")

    # Information gathering
    parser.add_argument("-s", "--sub-enum", action="store_true", help="Enable subdomain enumeration")
    parser.add_argument("-sc", action="store_true", help="Check status codes")
    parser.add_argument("-waf", action="store_true", help="Detect WAF")
    parser.add_argument("-sec", action="store_true", help="Check security headers")

    # Additional options
    parser.add_argument("-p", "--payload-file", help="Payload file for vulnerability scans")
    parser.add_argument("-dynamic", action="store_true", help="Enable dynamic payload generation")

    args = parser.parse_args()

    # Apply profile if specified
    if args.profile:
        args = apply_scan_profile(args.profile, args)

    # Get URLs
    urls = []
    if args.url:
        urls = [args.url]
    elif args.list:
        with open(args.list, 'r') as f:
            urls = [line.strip() for line in f if line.strip() and not line.startswith('#')]
    else:
        print(f"{Config.COLOR_RED}[-] Please provide a target URL (-u) or URL list (-l){Config.COLOR_RESET}")
        return

    # Execute scans based on flags
    if args.sub_enum:
        for url in urls:
            run_subdomain_enum(url, args)

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

    elif args.sc:
        for url in urls:
            run_status_checker(url, args)

    elif args.waf:
        for url in urls:
            run_waf_detector(url, args)

    elif args.sec:
        print(f"{Config.COLOR_ORANGE}[*] Security headers checker available in greaper_old.py{Config.COLOR_RESET}")
        print(f"{Config.COLOR_ORANGE}[*] Use: python3 greaper_old.py -u {urls[0]} -sec{Config.COLOR_RESET}")

    else:
        print(f"{Config.COLOR_ORANGE}[-] Please specify a scan type (e.g., -sqli, -xss, -s, -waf){Config.COLOR_RESET}")
        print(f"{Config.COLOR_BLUE}[*] Try using --profile for predefined scan combinations{Config.COLOR_RESET}")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\\nKeyboard interrupt received. Exiting...")
    except Exception as e:
        print(f"{Config.COLOR_ORANGE}An unexpected error occurred: {e}{Config.COLOR_RESET}")
        logger.exception("Unexpected error in main")
    finally:
        sys.exit(0)
