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
def run_sqli_scanner(url, args, progress=None):
    scanner = SQLiScanner(
        target=url, payload_file=args.payload_file, output_file=None, progress=progress
    )
    scanner.scan()
    findings = []
    for result in scanner.results:
        payload = ""
        vuln_url = url
        if " With payload: " in result:
            parts = result.split(" With payload: ")
            payload = parts[1]
            vuln_url = parts[0].replace("[+] Potential SQLi found on ", "").strip()
        finding = {
            "timestamp": datetime.now().isoformat(),
            "target": url,
            "type": "SQL Injection",
            "severity": "high",
            "url": vuln_url,
            "parameter": "FUZZ" if "FUZZ" in url else "",
            "payload": payload
        }
        findings.append(finding)
        if progress:
            progress.add_finding(finding)
    return findings


def run_xss_scanner(url, args, progress=None):
    scanner = XSSScanner(
        target=url, payload_file=args.payload_file, output_file=None, progress=progress
    )
    scanner.scan()
    findings = []
    for result in scanner.results:
        payload = ""
        vuln_url = url
        if " With payload: " in result:
            parts = result.split(" With payload: ")
            payload = parts[1]
            vuln_url = parts[0].replace("[+] Potential XSS found on ", "").strip()
        finding = {
            "timestamp": datetime.now().isoformat(),
            "target": url,
            "type": "Cross-Site Scripting",
            "severity": "high",
            "url": vuln_url,
            "parameter": "FUZZ" if "FUZZ" in url else "",
            "payload": payload
        }
        findings.append(finding)
        if progress:
            progress.add_finding(finding)
    return findings


def run_lfi_scanner(url, args, progress=None):
    scanner = LFIScanner(
        target=url, payload_file=args.payload_file, output_file=None, progress=progress
    )
    scanner.scan()
    findings = []
    for result in scanner.results:
        payload = ""
        vuln_url = url
        if " With file: " in result:
            parts = result.split(" With file: ")
            payload = parts[1]
            vuln_url = parts[0].replace("[+] Potential LFI found on ", "").strip()
        finding = {
            "timestamp": datetime.now().isoformat(),
            "target": url,
            "type": "Local File Inclusion",
            "severity": "high",
            "url": vuln_url,
            "parameter": "FUZZ" if "FUZZ" in url else "",
            "payload": payload
        }
        findings.append(finding)
        if progress:
            progress.add_finding(finding)
    return findings


def run_cors_scanner(url, args, progress=None):
    scanner = CORSScanner(target=url, output_file=None, progress=progress)
    scanner.scan()
    findings = []
    for result in scanner.results:
        origin = ""
        for line in result.splitlines():
            if "Testing Origin:" in line:
                origin = line.split("Testing Origin:")[1].strip()
        finding = {
            "timestamp": datetime.now().isoformat(),
            "target": url,
            "type": "CORS Misconfiguration",
            "severity": "medium",
            "url": url,
            "parameter": "Origin",
            "payload": origin
        }
        findings.append(finding)
        if progress:
            progress.add_finding(finding)
    return findings


def run_host_header_scanner(url, args, progress=None):
    scanner = HostHeaderScanner(target=url, output_file=None, progress=progress)
    scanner.scan()
    findings = []
    for result in scanner.results:
        finding = {
            "timestamp": datetime.now().isoformat(),
            "target": url,
            "type": "Host Header Injection",
            "severity": "medium",
            "url": url,
            "parameter": "Host",
            "payload": "evil.com"
        }
        findings.append(finding)
        if progress:
            progress.add_finding(finding)
    return findings


def run_ssrf_scanner(url, args, progress=None):
    scanner = SSRFScanner(
        target=url, payload_file=args.payload_file, output_file=None, progress=progress
    )
    scanner.scan()
    findings = []
    for finding in scanner.findings:
        f = {
            "timestamp": datetime.now().isoformat(),
            "target": url,
            "type": "SSRF",
            "severity": finding.get("severity", "high"),
            "url": finding.get("url", url),
            "parameter": finding.get("parameter", ""),
            "payload": finding.get("payload", "")
        }
        findings.append(f)
        if progress:
            progress.add_finding(f)
    return findings


def run_xxe_scanner(url, args, progress=None):
    scanner = XXEScanner(
        target=url, payload_file=args.payload_file, output_file=None, progress=progress
    )
    scanner.scan()
    findings = []
    for finding in scanner.findings:
        f = {
            "timestamp": datetime.now().isoformat(),
            "target": url,
            "type": "XXE",
            "severity": finding.get("severity", "critical"),
            "url": finding.get("url", url),
            "parameter": "",
            "payload": finding.get("payload", "")
        }
        findings.append(f)
        if progress:
            progress.add_finding(f)
    return findings


def run_subdomain_enum(url, args):
    enumerator = SubdomainEnumerator(
        url=url, output_file=None, rate_limit=args.rate_limit
    )
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        subdomains = loop.run_until_complete(enumerator.enumerate())
        return subdomains
    finally:
        loop.close()


def run_crawler(url, args):
    crawler = WebCrawler(url=url, depth=args.crawl, output_file=None)
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        urls = loop.run_until_complete(crawler.crawl())
        return list(urls)
    finally:
        loop.close()


def run_js_scanner(url, args, progress=None):
    scanner = JSScanner(target=url, output_file=None)
    scanner.scan()
    return []


def run_cve_scanner(url, args, progress=None):
    scanner = CVEScanner(url=url, output_file=None)
    scanner.scan()
    findings = []
    for result in scanner.results:
        finding = {
            "timestamp": datetime.now().isoformat(),
            "target": url,
            "type": "CVE / Vulnerability Fingerprint",
            "severity": "medium",
            "url": url,
            "parameter": "",
            "payload": result
        }
        findings.append(finding)
        if progress:
            progress.add_finding(finding)
    return findings


def run_directory_fuzzer(url, args, progress=None):
    fuzzer = DirectoryFuzzer(
        target=url, payload_file=args.payload_file, output_file=None
    )
    fuzzer.fuzz()
    findings = []
    for result in fuzzer.results:
        finding = {
            "timestamp": datetime.now().isoformat(),
            "target": url,
            "type": "Directory Discovery",
            "severity": "info",
            "url": result.split(" [Status")[0],
            "parameter": "",
            "payload": result
        }
        findings.append(finding)
        if progress:
            progress.add_finding(finding)
    return findings


def run_content_length(url, args, checker, progress=None):
    checker.check(url)
    return []


def run_live_checker(url, args, checker, progress=None):
    checker.check(url)
    return []


def run_security_headers(url, args, progress=None):
    checker = SecurityHeadersChecker(url=url, output_file=None)
    checker.check()
    return []


def run_ip_lookup(url, args, progress=None):
    lookup = IPLookup(target=url, output_file=None)
    lookup.lookup()
    return []


def run_status_checker(url, args, progress=None):
    checker = StatusChecker(output_file=None)
    checker.check(url)
    return []


def run_waf_detector(url, args, progress=None):
    detector = WAFDetector()
    detector.detect(url)
    return []


def process_urls(urls, scanner_func, args, progress=None):
    """Process multiple URLs with a scanner function concurrently and return findings"""
    findings = []
    from datetime import datetime
    import concurrent.futures
    with concurrent.futures.ThreadPoolExecutor() as executor:
        futures = [executor.submit(scanner_func, u, args, progress) for u in urls]
        for future in concurrent.futures.as_completed(futures):
            try:
                res = future.result()
                if res:
                    findings.extend(res)
            except Exception as e:
                logger.error(f"Error in process_urls scanner execution: {e}")
    return findings


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

    # Initialize ScanProgress and findings list
    progress = ScanProgress(total_targets=len(urls))
    all_findings = []
    scanned_any = False

    # Execute subdomain enumeration first
    if args.sub_enum:
        scanned_any = True
        discovered_subdomains = []
        for url in urls:
            subs = run_subdomain_enum(url, args)
            if subs:
                discovered_subdomains.extend(subs)
            progress.update_target()
        
        # Convert subdomain hosts to full probe URLs (prefer HTTPS, fallback to HTTP)
        subdomain_urls = []
        for sub in set(discovered_subdomains):
            sub = sub.strip()
            if sub:
                subdomain_urls.append(f"https://{sub}")
                subdomain_urls.append(f"http://{sub}")
        
        if subdomain_urls:
            print(f"\n{Config.COLOR_BLUE}[*] Probing discovered subdomains to find live targets...{Config.COLOR_RESET}")
            checker = LiveURLChecker(output_file=None)
            for sub_url in subdomain_urls:
                checker.check(sub_url)
            
            if checker.results:
                print(f"\n{Config.COLOR_GREEN}[+] Added {len(checker.results)} live subdomains as targets for subsequent scans.{Config.COLOR_RESET}")
                for live_sub in checker.results:
                    if live_sub not in urls:
                        urls.append(live_sub)

    # Execute crawler next to discover additional paths
    if args.crawl:
        scanned_any = True
        crawled_paths = []
        for url in urls:
            found_urls = run_crawler(url, args)
            if found_urls:
                crawled_paths.extend(found_urls)
            progress.update_target()
        
        # Add crawled paths to targets so they get scanned
        for crawled_url in set(crawled_paths):
            if crawled_url not in urls:
                urls.append(crawled_url)

    # Update progress target count dynamically
    progress.total_targets = len(urls)

    # Run JS scanner (Information gathering)
    if args.info:
        scanned_any = True
        for url in urls:
            run_js_scanner(url, args, progress)
            progress.update_target()

    # Run CVE scanner
    if args.cve:
        scanned_any = True
        if len(urls) == 1:
            res = run_cve_scanner(urls[0], args, progress)
            all_findings.extend(res)
            progress.update_target()
        else:
            res = process_urls(urls, run_cve_scanner, args, progress)
            all_findings.extend(res)
            for _ in urls:
                progress.update_target()

    # Run Directory Fuzzer
    if args.df:
        scanned_any = True
        if len(urls) == 1:
            res = run_directory_fuzzer(urls[0], args, progress)
            all_findings.extend(res)
            progress.update_target()
        else:
            res = process_urls(urls, run_directory_fuzzer, args, progress)
            all_findings.extend(res)
            for _ in urls:
                progress.update_target()

    # Run Security Headers Checker
    if args.sec:
        scanned_any = True
        for url in urls:
            run_security_headers(url, args, progress)
            progress.update_target()

    # Run IP Lookup
    if args.ip:
        scanned_any = True
        for url in urls:
            run_ip_lookup(url, args, progress)
            progress.update_target()

    # Run Content Length Checker
    if args.cl:
        scanned_any = True
        checker = ContentLengthChecker(output_file=None)
        for url in urls:
            run_content_length(url, args, checker, progress)
            progress.update_target()
        checker.print_summary()

    # Run Live URL Checker
    if args.lv:
        scanned_any = True
        checker = LiveURLChecker(output_file=None)
        for url in urls:
            run_live_checker(url, args, checker, progress)
            progress.update_target()
        checker.print_summary()

    # Run SQLi scanner
    if args.sqli:
        scanned_any = True
        if len(urls) == 1:
            res = run_sqli_scanner(urls[0], args, progress)
            all_findings.extend(res)
            progress.update_target()
        else:
            res = process_urls(urls, run_sqli_scanner, args, progress)
            all_findings.extend(res)
            for _ in urls:
                progress.update_target()

    # Run XSS scanner
    if args.xss:
        scanned_any = True
        if len(urls) == 1:
            res = run_xss_scanner(urls[0], args, progress)
            all_findings.extend(res)
            progress.update_target()
        else:
            res = process_urls(urls, run_xss_scanner, args, progress)
            all_findings.extend(res)
            for _ in urls:
                progress.update_target()

    # Run LFI scanner
    if args.lfi:
        scanned_any = True
        if len(urls) == 1:
            res = run_lfi_scanner(urls[0], args, progress)
            all_findings.extend(res)
            progress.update_target()
        else:
            res = process_urls(urls, run_lfi_scanner, args, progress)
            all_findings.extend(res)
            for _ in urls:
                progress.update_target()

    # Run CORS scanner
    if args.cors:
        scanned_any = True
        if len(urls) == 1:
            res = run_cors_scanner(urls[0], args, progress)
            all_findings.extend(res)
            progress.update_target()
        else:
            res = process_urls(urls, run_cors_scanner, args, progress)
            all_findings.extend(res)
            for _ in urls:
                progress.update_target()

    # Run Host Header scanner
    if args.hh:
        scanned_any = True
        if len(urls) == 1:
            res = run_host_header_scanner(urls[0], args, progress)
            all_findings.extend(res)
            progress.update_target()
        else:
            res = process_urls(urls, run_host_header_scanner, args, progress)
            all_findings.extend(res)
            for _ in urls:
                progress.update_target()

    # Run SSRF scanner
    if args.ssrf:
        scanned_any = True
        if len(urls) == 1:
            res = run_ssrf_scanner(urls[0], args, progress)
            all_findings.extend(res)
            progress.update_target()
        else:
            res = process_urls(urls, run_ssrf_scanner, args, progress)
            all_findings.extend(res)
            for _ in urls:
                progress.update_target()

    # Run XXE scanner
    if args.xxe:
        scanned_any = True
        if len(urls) == 1:
            res = run_xxe_scanner(urls[0], args, progress)
            all_findings.extend(res)
            progress.update_target()
        else:
            res = process_urls(urls, run_xxe_scanner, args, progress)
            all_findings.extend(res)
            for _ in urls:
                progress.update_target()

    # Run HTTP status code checker
    if args.sc:
        scanned_any = True
        for url in urls:
            run_status_checker(url, args, progress)
            progress.update_target()

    # Run WAF Detector
    if args.waf:
        scanned_any = True
        for url in urls:
            run_waf_detector(url, args, progress)
            progress.update_target()

    # Final stats print and report output formatting
    if scanned_any:
        progress.print_summary()

        if args.output:
            report_data = {
                "scan_info": {
                    "target": args.url or args.list,
                    "timestamp": datetime.now().isoformat(),
                    "total_targets_scanned": len(urls),
                    "total_requests": progress.total_requests,
                    "successful_requests": progress.successful_requests,
                    "failed_requests": progress.failed_requests,
                    "vulnerabilities_found": len(all_findings),
                },
                "vulnerabilities": all_findings,
            }
            OutputFormatter.format(report_data, args.format, args.output)
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
