import requests
import argparse
import sys
from datetime import datetime
from colorama import init, Fore, Style

# Initialize colorama for cross-platform colored output
init(autoreset=True)

# --- Global Constants ---
SECURITY_HEADERS = [
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Content-Type-Options",
    "X-Frame-Options",
    "X-XSS-Protection",
    "Referrer-Policy",
    "Permissions-Policy"
]

INFO_LEAK_HEADERS = [
    "Server",
    "X-Powered-By"  # Added as a bonus common leak
]

REPORT_FILE = "scan_report.txt"

# --- Functions ---

def get_arguments():
    """
    Parses command-line arguments.
    Returns:
        argparse.Namespace: The parsed arguments.
    """
    parser = argparse.ArgumentParser(
        description="LazyHeaderScanner: Analyze HTTP Security Headers for compliance and leaks."
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-u", "--url", dest="url", help="Single Target URL (e.g., https://example.com)")
    group.add_argument("-f", "--file", dest="file", help="File containing a list of Target URLs")
    
    return parser.parse_args()

def analyze_headers(headers):
    """
    Evaluates the headers from the response against the security checklist.
    
    Args:
        headers (dict): The headers dictionary from the requests response.
        
    Returns:
        list: A list of dictionaries containing analysis results.
              Example: [{'header': 'CSP', 'status': 'FOUND', 'value': '...', 'color': Fore.GREEN}]
    """
    results = []

    # Check for Security Headers (Missing vs Found)
    for header in SECURITY_HEADERS:
        if header in headers:
            results.append({
                "header": header,
                "status": "FOUND",
                "value": headers[header],
                "color": Fore.GREEN
            })
        else:
            results.append({
                "header": header,
                "status": "MISSING",
                "value": "Not Configured",
                "color": Fore.RED
            })

    # Check for Information Leaks (Warning if present)
    for header in INFO_LEAK_HEADERS:
        if header in headers:
            results.append({
                "header": header,
                "status": "WARNING",
                "value": headers[header],
                "color": Fore.YELLOW
            })
    
    return results

def save_report(report_data):
    """
    Appends the scan results to a text file.
    
    Args:
        report_data (str): The formatted string to write to the file.
    """
    try:
        with open(REPORT_FILE, "a") as f:
            f.write(report_data + "\n" + "-"*50 + "\n")
    except IOError as e:
        print(f"{Fore.RED}[!] Error writing to report file: {e}")

def scan_target(url):
    """
    The core logic to scan a single target.
    
    Args:
        url (str): The URL to scan.
    """
    # Ensure URL has a schema
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url

    print(f"\n{Style.BRIGHT}Scanning Target: {Fore.CYAN}{url}{Style.RESET_ALL}")
    print("=" * 60)

    report_buffer = f"Scan Target: {url}\nTime: {datetime.now()}\n"

    try:
        # Perform the request
        # timeout=10 prevents hanging indefinitely
        response = requests.get(url, timeout=10, allow_redirects=True)
        
        # Analyze headers
        analysis_results = analyze_headers(response.headers)

        # Output and buffer results
        for item in analysis_results:
            header_name = item['header']
            status = item['status']
            value = item['value']
            color = item['color']

            # Truncate very long header values for display
            display_value = (value[:75] + '..') if len(value) > 75 else value

            # Print to Console
            if status == "MISSING":
                print(f"{color}[-] {header_name}: {status}")
            elif status == "WARNING":
                print(f"{color}[!] {header_name}: {display_value}")
            else:
                print(f"{color}[+] {header_name}: {display_value}")

            # Add to report buffer (without color codes)
            report_buffer += f"[{status}] {header_name}: {value}\n"

    except requests.exceptions.Timeout:
        error_msg = "Connection Timed Out"
        print(f"{Fore.RED}[!] {error_msg}")
        report_buffer += f"[ERROR] {error_msg}\n"
    except requests.exceptions.ConnectionError:
        error_msg = "Connection Error (DNS or Server Down)"
        print(f"{Fore.RED}[!] {error_msg}")
        report_buffer += f"[ERROR] {error_msg}\n"
    except requests.exceptions.RequestException as e:
        error_msg = f"General Request Error: {e}"
        print(f"{Fore.RED}[!] {error_msg}")
        report_buffer += f"[ERROR] {error_msg}\n"
    except Exception as e:
        error_msg = f"Unexpected Error: {e}"
        print(f"{Fore.RED}[!] {error_msg}")
        report_buffer += f"[ERROR] {error_msg}\n"

    # Save the accumulated report for this target
    save_report(report_buffer)

def main():
    # 1. Get Arguments
    args = get_arguments()

    # Clear report file for a fresh run (optional, currently appends)
    # open(REPORT_FILE, 'w').close() 

    targets = []

    # 2. Determine Input Source
    if args.url:
        targets.append(args.url)
    elif args.file:
        try:
            with open(args.file, 'r') as f:
                # Read lines and strip whitespace
                targets = [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
            print(f"{Fore.RED}[!] File not found: {args.file}")
            sys.exit(1)

    # 3. Execution Loop
    if not targets:
        print(f"{Fore.RED}[!] No targets found.")
        sys.exit(1)
        
    print(f"{Fore.BLUE}[*] Starting LazyHeaderScanner on {len(targets)} targets...")
    
    for target in targets:
        scan_target(target)

    print(f"\n{Fore.BLUE}[*] Scan complete. Summary saved to {REPORT_FILE}")

if __name__ == "__main__":
    main()
