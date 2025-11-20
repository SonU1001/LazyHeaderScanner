# LazyHeaderScanner

**LazyHeaderScanner** is a lightweight, Python-based tool designed for **passive reconnaissance** and security auditing. It automates the analysis of HTTP security headers to identify missing defensive configurations and potential information leaks.

Designed for penetration testers and security enthusiasts, this tool provides instant feedback on the security posture of a web server without sending aggressive payloads.

## 🚀 Features

* **Security Header Analysis:** Checks for the presence and valid configuration of critical headers:
    * `Strict-Transport-Security` (HSTS)
    * `Content-Security-Policy` (CSP)
    * `X-Content-Type-Options`
    * `X-Frame-Options`
    * `X-XSS-Protection`
    * `Referrer-Policy`
    * `Permissions-Policy`
* **Info Leak Detection:** Flags headers that reveal server software versions (e.g., `Server`, `X-Powered-By`).
* **Bulk Scanning:** Supports scanning multiple targets from a text file.
* **Visual Output:** Color-coded terminal output for quick assessment (Green=Safe, Red=Missing, Yellow=Warning).
* **Reporting:** Automatically saves results to `scan_report.txt`.

## 📋 Prerequisites

* Python 3.x
* `pip` (Python Package Installer)

## 🛠️ Installation

1.  Clone this repository or download the script:
    ```bash
    git clone [https://github.com/yourusername/LazyHeaderScanner.git](https://github.com/yourusername/LazyHeaderScanner.git)
    cd LazyHeaderScanner
    ```

2.  Install the required dependencies:
    ```bash
    pip install requests colorama
    ```

## 💻 Usage

### Scan a Single Target
Use the `-u` flag to scan a specific URL.
python LazyHeaderScanner.py -u [https://example.com](https://example.com)

Scan Multiple Targets
Use the -f flag to scan a list of URLs from a text file.

Create a file named targets.txt containing one URL per line.
python LazyHeaderScanner.py -f targets.txt
📝 Output Example
Plaintext

Scanning Target: [https://example.com](https://example.com)
============================================================
[+] Strict-Transport-Security: max-age=31536000; includeSubDomains
[-] Content-Security-Policy: MISSING
[+] X-Frame-Options: SAMEORIGIN
[!] Server: Apache/2.4.41 (Ubuntu)
⚠️ Disclaimer
This tool is for educational purposes and authorized security testing only. The developer is not responsible for any misuse of this tool. Always ensure you have permission to scan the target network or website.

📄 License
This project is licensed under the MIT License.
