#!/usr/bin/env python3
import requests
import subprocess
import urllib.parse
import time
import logging
import os
import json
import argparse
import asyncio
import aiohttp
import shutil
import sys
import zipfile

# Function to set up logging
def setup_logging(log_file, log_level):
    logging.basicConfig(filename=log_file, level=log_level, format='%(asctime)s - %(levelname)s - %(message)s')

def check_and_run_figlet():#banner for it
    subprocess.run(["figlet", "WEB-SCANNER"])
    print('>>---S-T-A-R-T-E-D--S-C-A-N-I-N-G---<<\n')

class VulnerabilityScanner:
    CURRENT_VERSION = "v1.5"  # Update this value for each release

    def __init__(self, url, report_file, log_file):
        self.url = url
        self.vulnerabilities = []
        self.report_file = report_file
        self.log_file = log_file

    def log_vulnerability(self, vulnerability):
        logging.info(f"Vulnerability detected: {vulnerability['type']} at {vulnerability['location']}")
        self.vulnerabilities.append(vulnerability)

    async def fetch(self, session, url, params=None):
        try:
            print(f"Fetching URL: {url} with params: {params}")
            async with session.get(url, params=params, timeout=5) as response:
                response.raise_for_status()  # Raise an error for bad responses
                return await response.text(), response  # Return the response object
        except aiohttp.ClientTimeout:
            logging.error(f"Timeout while fetching {url}")
        except aiohttp.ClientError as e:
            logging.error(f"Client error while fetching {url}: {e}")
        except Exception as e:
            logging.error(f"Unexpected error while fetching {url}: {e}")
        return None, None

    async def scan_sql_injection(self):
        payloads = ["' OR 1=1 --", "' UNION SELECT NULL, username, password FROM users --"]
        async with aiohttp.ClientSession() as session:
            for payload in payloads:
                response_text, _ = await self.fetch(session, self.url, params={'query': payload})
                if response_text and ('error' in response_text.lower() or len(response_text) > 1000):
                    vulnerability = {
                        'type': 'SQL Injection',
                        'location': self.url + '?query=' + urllib.parse.quote(payload),
                        'description': 'The application is vulnerable to SQL injection attacks.',
                        'severity': 'High'
                    }
                    self.log_vulnerability(vulnerability)

    async def scan_xss(self):
        payloads = ['<script>alert("XSS")</script>', '<img src=x onerror=alert("XSS")>']
        async with aiohttp.ClientSession() as session:
            for payload in payloads:
                response_text, _ = await self.fetch(session, self.url, params={'query': payload})
                if response_text and payload in response_text:
                    vulnerability = {
                        'type': 'Cross-Site Scripting (XSS)',
                        'location': self.url + '?query=' + urllib.parse.quote(payload),
                        'description': 'The application is vulnerable to XSS attacks.',
                        'severity': 'Medium'
                    }
                    self.log_vulnerability(vulnerability)

    async def scan_csrf(self):
        payload = {'csrf_token': 'invalid_token'}
        async with aiohttp.ClientSession() as session:
            response_text, _ = await self.fetch(session, self.url, params=payload)
            if response_text and 'invalid token' in response_text.lower():
                vulnerability = {
                    'type': 'Cross-Site Request Forgery (CSRF)',
                    'location': self.url,
                    'description': 'The application is vulnerable to CSRF attacks.',
                    'severity': 'Medium'
                }
                self.log_vulnerability(vulnerability)

    async def scan_file_inclusion(self):
        payloads = ['../../../../etc/passwd', 'C:\\Windows\\System32\\drivers\\etc\\hosts']
        async with aiohttp.ClientSession() as session:
            for payload in payloads:
                response_text, _ = await self.fetch(session, self.url, params={'file': payload})
                if response_text and ('root:' in response_text or 'user:' in response_text):
                    vulnerability = {
                        'type': 'File Inclusion',
                        'location': self.url + '?file=' + urllib.parse.quote(payload),
                        'description': 'The application is vulnerable to file inclusion attacks.',
                        'severity': 'High'
                    }
                    self.log_vulnerability(vulnerability)

    async def scan_command_injection(self):
        payloads = ['; ls -l', '| dir']
        async with aiohttp.ClientSession() as session:
            for payload in payloads:
                response_text, _ = await self.fetch(session, self.url, params={'command': payload})
                if response_text and ('total' in response_text or 'drwx' in response_text):
                    vulnerability = {
                        'type': 'Command Injection',
                        'location': self.url + '?command=' + urllib.parse.quote(payload),
                        'description': 'The application is vulnerable to command injection attacks.',
                        'severity': 'High'
                    }
                    self.log_vulnerability(vulnerability)

    async def scan_security_headers(self):
        async with aiohttp.ClientSession() as session:
            response_text, response = await self.fetch(session, self.url)  # Get both text and response
            if response_text and response:  # Ensure response is not None
                missing_headers = []
                security_headers = {
                    'Strict-Transport-Security': 'Missing HSTS header may allow downgrade attacks',
                    'X-Content-Type-Options': 'Missing nosniff header may allow MIME type sniffing',
                    'X-Frame-Options': 'Missing anti-framing header may allow clickjacking attacks',
                    'Content-Security-Policy': 'Missing CSP header may allow various injection attacks',
                    'X-XSS-Protection': 'Missing XSS protection header may allow XSS attacks'
                }

                for header, description in security_headers.items():
                    if header not in response.headers:
                        missing_headers.append((header, description))

                if missing_headers:
                    vulnerability = {
                        'type': 'Missing Security Headers',
                        'location': self.url,
                        'description': f'The application is missing {len(missing_headers)} security headers',
                        'severity': 'Medium',
                        'details': missing_headers
                    }
                    self.log_vulnerability(vulnerability)

    async def scan_open_redirect(self):
        payload = 'http://malicious.com'
        async with aiohttp.ClientSession() as session:
            response_text, _ = await self.fetch(session, self.url, params={'redirect': payload})
            if response_text and payload in response_text:
                vulnerability = {
                    'type': 'Open Redirect',
                    'location': self.url + '?redirect=' + urllib.parse.quote(payload),
                    'description': 'The application is vulnerable to open redirect attacks.',
                    'severity': 'Medium'
                }
                self.log_vulnerability(vulnerability)

    async def scan(self):
        await asyncio.gather(
            self.scan_sql_injection(),
            self.scan_xss(),
            self.scan_csrf(),
            self.scan_file_inclusion(),
            self.scan_command_injection(),
            self.scan_security_headers(),
            self.scan_open_redirect()
        )

    def report(self):
        with open(self.report_file, 'w') as f:
            if not self.vulnerabilities:
                f.write("-> No Vulnerabilities Found.\n")
            else:
                for vulnerability in self.vulnerabilities:
                    f.write(f"{vulnerability['type']} found at {vulnerability['location']}: {vulnerability['description']} (Severity: {vulnerability['severity']})\n")
                    if 'details' in vulnerability:
                        f.write("  Details:\n")
                        for header, desc in vulnerability['details']:
                            f.write(f"  - {header}: {desc}\n")
        logging.info(f"Report generated: {self.report_file}")

    def update_tool(self):
        """Update the tool from the repository."""
        repo_url = "https://api.github.com/repos/CYBEREYE-001/WEB-Scanner/releases/latest"  # Change to your repo
        try:
            response = requests.get(repo_url)
            response.raise_for_status()  # Raise an error for bad responses
            release_info = response.json()

            latest_version = release_info['tag_name']  # Get the latest version from the release
            asset_url = release_info['assets'][0]['browser_download_url']  # Get the download URL for the asset
            asset_name = release_info['assets'][0]['name']  # Get the asset name

            # Check if the current version is the latest
            current_version = self.get_current_version()
            if latest_version == current_version:
                print("You are already using the latest version.")
                return

            # Download the latest release
            print(f"Downloading version {latest_version}...")
            download_response = requests.get(asset_url)
            download_response.raise_for_status()
            # Raise an error for bad responses

            # Save the downloaded file
            with open(asset_name, 'wb') as f:
                f.write(download_response.content)

            print(f"Tool updated successfully to version: {latest_version}!")
            # Optionally, you can update the CURRENT_VERSION variable here if you want to keep it in sync
            self.CURRENT_VERSION = latest_version  # Update the current version to the latest
        except Exception as e:
            print(f"Failed to update the tool: {str(e)}")

    def get_current_version(self):
        return self.CURRENT_VERSION  # Return the hardcoded version

def main():
    output_dir = "output"
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
    
    parser = argparse.ArgumentParser(description='Web Vulnerability Scanner')
    parser.add_argument('-L', '--log', help='Name for the log file')
    parser.add_argument('-R', '--report', help='Name for the report file')
    parser.add_argument('-U', '--url', help='URL to scan')
    parser.add_argument('--log-level', default='INFO', choices=['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'], help='Set the logging level')
    parser.add_argument('--update', action='store_true', help='Check for updates and update the tool if available')
    args = parser.parse_args()

    # If the update flag is set, perform the update and exit
    if args.update:
        scanner = VulnerabilityScanner("", "", "")  # Create a scanner without URL and report
        scanner.update_tool()
        return  # Exit after updating

    # Ensure that the required arguments are provided for scanning
    if not args.report or not args.url:
        parser.error("The following arguments are required when not updating: -R/--report, -U/--url")

    log_file = os.path.join(output_dir, args.log + ".log") if args.log else os.path.join(output_dir, "default.log")
    report_file = os.path.join(output_dir, args.report + ".txt")

    setup_logging(log_file, args.log_level)
    check_and_run_figlet()

    scanner = VulnerabilityScanner(args.url, report_file, log_file)
    asyncio.run(scanner.scan())
    scanner.report()
    print("\n-> Check 'output' Folder For Scan Results")
    print(">>---F-I-N-I-S-H-E-D---<<")

if __name__ == "__main__":
    main()