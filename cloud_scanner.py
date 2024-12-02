#!/usr/bin/env python3
import requests
import sys
import argparse
from termcolor import colored
import time
import re
import json
import csv
from datetime import datetime

# Default paths to check for sensitive files
DEFAULT_PATHS = [
    ".env",
    "config.json",
    "backup.sql",
    ".git/config",
    "logs/",
    "admin/",
    "database.sql",
    "settings.yaml"
]

# Patterns for sensitive data
SENSITIVE_PATTERNS = {
    "API Key": r"(?:api[_-]?key|apikey)[\s=:\"']+([a-zA-Z0-9_\-]{10,})",
    "Token": r"(?:token|bearer)[\s=:\"']+([a-zA-Z0-9\.\-_]{10,})",
    "Password": r"(?:password|pwd)[\s=:\"']+([^\s\"']{5,})",
    "JWT": r"eyJ[a-zA-Z0-9\-_]+\.[a-zA-Z0-9\-_]+\.[a-zA-Z0-9\-_]+",
    "Private Key": r"-----BEGIN (?:RSA|EC|DSA|OPENSSH) PRIVATE KEY-----",
    "AWS Access Key": r"AKIA[0-9A-Z]{16}",
    "Google Cloud Key": r"\"type\": \"service_account\"",
    "Azure Key": r"DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[^;]+",
    "Email Address": r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+",
    "IP Address": r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b",
}

# Banner function
def print_banner():
    banner = f"""
    {colored('###################################################', 'blue', attrs=['bold'])}
    {colored('#      Cloud Configuration Scanner               #', 'blue', attrs=['bold'])}
    {colored('#      Developed by: Thomas O\'Neil Álvarez      #', 'blue', attrs=['bold'])}
    {colored('###################################################', 'blue', attrs=['bold'])}

    {colored('DISCLAIMER:', 'red', attrs=['bold'])}
    {colored('Use this tool for ethical purposes only.', 'yellow', attrs=['bold'])}
    {colored('Unauthorized usage is strictly prohibited.', 'yellow')}
    {colored('###################################################', 'blue', attrs=['bold'])}
    """
    print(banner)

# Function to parse command-line arguments
def parse_arguments():
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("-u", "--url", type=str, help="Target URL or domain to scan.")
    parser.add_argument("-m", "--mode", type=str, choices=["basic", "full"], default="basic",
                        help="Scan mode: 'basic' or 'full'.")
    parser.add_argument("--proxy", type=str, help="Optional proxy server for requests.")
    parser.add_argument("-o", "--output", type=str, default="results", help="Base name for output files (without extension).")
    parser.add_argument("--custom-list", type=str, help="Path to a custom list of files/directories to scan.")
    parser.add_argument("-i", "--info", action="store_true", help="Show help information and exit.")
    args = parser.parse_args()

    if args.info:
        show_help()

    if not args.url:
        print(colored("[!] Error: Target URL is required. Use -i for help.", "red"))
        sys.exit(1)

    return args

# Help function
def show_help():
    help_text = f"""
    {colored('Cloud Configuration Scanner - Help Menu', 'blue', attrs=['bold'])}

    Usage: ./cloud_scanner.py [options]

    {colored('Options:', 'yellow')}
    -u, --url         Target URL or domain to scan. (Required)
    -m, --mode        Scan mode: 'basic' (quick scan) or 'full' (deep scan). Default: 'basic'.
    --proxy           Optional proxy server (e.g., http://127.0.0.1:8080).
    -o, --output      Base name for output files (e.g., 'results'). Outputs to 'results.json' and 'results.csv'.
    --custom-list     Path to a custom list of files/directories to scan.
    -i, --info        Show this help message and exit.

    Examples:
    ./cloud_scanner.py -u https://example.com -m basic
    ./cloud_scanner.py -u https://example.com -m full --proxy http://127.0.0.1:8080 -o results

    """
    print(help_text)
    sys.exit(0)

# Function to load custom paths
def load_custom_paths(file_path):
    try:
        with open(file_path, "r") as f:
            return [line.strip() for line in f.readlines()]
    except FileNotFoundError:
        print(colored(f"[!] Custom list file not found: {file_path}", "red"))
        sys.exit(1)

# Function to scan for sensitive files
def scan_common_paths(base_url, paths, proxy=None):
    print(colored("[*] Scanning for sensitive files...", "cyan"))
    found_files = []
    errors = []
    results = []

    # Custom headers to simulate browser traffic
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
        "Connection": "keep-alive"
    }

    for path in paths:
        url = f"{base_url}/{path}"
        try:
            time.sleep(1)  # Delay between requests to avoid rate-limiting
            response = requests.get(
                url,
                headers=headers,
                proxies={"http": proxy, "https": proxy} if proxy else None,
                timeout=5
            )
            if response.status_code == 200:
                print(colored(f"[+] Found: {url} (Status: {response.status_code})", "green"))
                sensitive_data = analyze_content(response.text, url)
                if sensitive_data:
                    results.append({"url": url, "sensitive_data": sensitive_data})
                found_files.append(url)
            elif response.status_code == 404:
                print(colored(f"[*] Not Found: {url}", "red"))
            else:
                print(colored(f"[-] Unexpected status code for {url}: {response.status_code}", "yellow"))
        except requests.exceptions.RequestException as e:
            print(colored(f"[!] Error accessing {url}: {e}", "red"))
            errors.append(url)

    print(colored("\n[*] Scan complete.", "cyan"))
    return found_files, errors, results

# Function to analyze file content
def analyze_content(content, url):
    print(colored(f"[*] Analyzing content of {url}...", "cyan"))
    sensitive_data = {}
    for label, pattern in SENSITIVE_PATTERNS.items():
        matches = re.findall(pattern, content, re.IGNORECASE)
        if matches:
            sensitive_data[label] = matches
            print(colored(f"[!] Found {label} in {url}: {matches}", "red"))
    return sensitive_data

# Function to save results to JSON and CSV
def save_results(output_base, results):
    json_file = f"{output_base}.json"
    csv_file = f"{output_base}.csv"

    # Save as JSON
    with open(json_file, "w") as jf:
        json.dump(results, jf, indent=4)
    print(colored(f"[+] Results saved to {json_file}", "green"))

    # Save as CSV
    with open(csv_file, "w", newline="") as cf:
        writer = csv.writer(cf)
        writer.writerow(["URL", "Sensitive Data"])
        for result in results:
            writer.writerow([result["url"], json.dumps(result["sensitive_data"])])
    print(colored(f"[+] Results saved to {csv_file}", "green"))

# Main function
def main():
    print_banner()
    args = parse_arguments()
    start_time = datetime.now()

    paths = DEFAULT_PATHS
    if args.custom_list:
        paths = load_custom_paths(args.custom_list)

    found_files, errors, results = scan_common_paths(args.url, paths, args.proxy)

    # Save results
    save_results(args.output, results)

    # Summary
    print(colored("\n[Summary]", "cyan"))
    print(f"  Found: {len(found_files)}")
    print(f"  Errors: {len(errors)}")
    print(f"  Time Elapsed: {datetime.now() - start_time}")

if __name__ == "__main__":
    main()
