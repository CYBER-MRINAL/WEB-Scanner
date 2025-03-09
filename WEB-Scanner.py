import requests
import subprocess
import urllib.parse
import time
import logging
import os

# Function to set up logging
def setup_logging(log_file):
    logging.basicConfig(filename=log_file, level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def check_and_run_figlet():
    try:
        # Check if figlet is installed
        subprocess.run(["figlet", "--version"], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    except subprocess.CalledProcessError:
        # If figlet is not installed, install it
        subprocess.run(["sudo", "apt", "install", "figlet", "-y"], check=True)
    
    # Run figlet with the specified options
    subprocess.run(["figlet", "WEB-SCANNER"])
    print('>>---S-T-A-R-T-E-D--S-C-A-N-I-N-G---<<\n')

# Call the function
check_and_run_figlet()

class VulnerabilityScanner:
    def __init__(self, url, report_file, log_file):
        self.url = url
        self.vulnerabilities = []
        self.report_file = report_file
        self.log_file = log_file

    def log_vulnerability(self, vulnerability):
        logging.info(f"Vulnerability detected: {vulnerability['type']} at {vulnerability['location']}")
        self.vulnerabilities.append(vulnerability)

    def scan_sql_injection(self):
        payload = "' OR 1=1 --"
        start_time = time.time()
        try:
            response = requests.get(self.url, params={'query': payload}, timeout=5)
            response_time = time.time() - start_time
            
            # Check for SQL injection vulnerability
            if response_time > 2 or 'error' in response.text.lower():
                vulnerability = {
                    'type': 'SQL Injection',
                    'location': self.url + '?query=' + urllib.parse.quote(payload),
                    'description': 'The application is vulnerable to SQL injection attacks.',
                    'severity': 'High'
                }
                self.log_vulnerability(vulnerability)
        except requests.RequestException as e:
            logging.error(f"Error during SQL injection scan: {e}")

    def scan_xss(self):
        payload = '<script>alert("XSS")</script>'
        try:
            response = requests.get(self.url, params={'query': payload}, timeout=5)
            if payload in response.text:
                vulnerability = {
                    'type': 'Cross-Site Scripting (XSS)',
                    'location': self.url + '?query=' + urllib.parse.quote(payload),
                    'description': 'The application is vulnerable to XSS attacks.',
                    'severity': 'Medium'
                }
                self.log_vulnerability(vulnerability)
        except requests.RequestException as e:
            logging.error(f"Error during XSS scan: {e}")

    def scan_csrf(self):
        payload = {'csrf_token': 'invalid_token'}
        try:
            response = requests.post(self.url, data=payload, timeout=5)
            if 'invalid token' in response.text.lower():
                vulnerability = {
                    'type': 'Cross-Site Request Forgery (CSRF)',
                    'location': self.url,
                    'description': 'The application is vulnerable to CSRF attacks.',
                    'severity': 'Medium'
                }
                self.log_vulnerability(vulnerability)
        except requests.RequestException as e:
            logging.error(f"Error during CSRF scan: {e}")

    def scan_file_inclusion(self):
        payload = '../../../../etc/passwd'
        try:
            response = requests.get(self.url, params={'file': payload}, timeout=5)
            if 'root:' in response.text or 'user:' in response.text:
                vulnerability = {
                    'type': 'File Inclusion',
                    'location': self.url + '?file=' + urllib.parse.quote(payload),
                    'description': 'The application is vulnerable to file inclusion attacks.',
                    'severity': 'High'
                }
                self.log_vulnerability(vulnerability)
        except requests.RequestException as e:
            logging.error(f"Error during File Inclusion scan: {e}")

    def scan_command_injection(self):
        payload = '; ls -l'
        try:
            response = requests.get(self.url, params={'command': payload}, timeout=5)
            if 'total' in response.text or 'drwx' in response.text:
                vulnerability = {
                    'type': 'Command Injection',
                    'location': self.url + '?command=' + urllib.parse.quote(payload),
                    'description': 'The application is vulnerable to command injection attacks.',
                    'severity': 'High'
                }
                self.log_vulnerability(vulnerability)
        except requests.RequestException as e:
            logging.error(f"Error during Command Injection scan: {e}")
    
    def scan(self):
        self.scan_sql_injection()
        self.scan_xss()
        self.scan_csrf()
        self.scan_file_inclusion()
        self.scan_command_injection()

    def report(self):
        # Generate a report of findings
        with open(self.report_file, 'w') as f:
            if not self.vulnerabilities:
                f.write("-> No Vulnerabilities Found.\n")
            else:
                for vulnerability in self.vulnerabilities:
                    f.write(f"{vulnerability['type']} found at {vulnerability['location']}: {vulnerability['description']} (Severity: {vulnerability['severity']})\n")
        logging.info(f"Report generated: {self.report_file}")

# Example usage
if __name__ == "__main__":
    output_dir = "output"
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

    log_name = input("-> Enter Name For Log File: ")
    log_file = os.path.join(output_dir, log_name + ".log")

    report_name = input("-> Enter Name For Report File: ")
    report_file = os.path.join(output_dir, report_name + ".txt")

    setup_logging(log_file)

    target_url = input("-> Enter the URL to scan: ")
    scanner = VulnerabilityScanner(target_url, report_file, log_file)
    scanner.scan()
    scanner.report()
    print("\n-> Check 'output' Folder For Scan Rezults")
    print(">>---F-I-N-I-S-H-E-D---<<")
