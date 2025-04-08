import nmap
import requests
from utils.logger import setup_logger
import logging
from termcolor import colored

setup_logger()

def log_vulnerability(name, severity, details=""):
    """Log vulnerabilities with color coding"""
    color_map = {
        'CRITICAL': 'red',
        'HIGH': 'yellow',
        'MEDIUM': 'blue',
        'LOW': 'green'
    }
    color = color_map.get(severity, 'white')
    message = f"[{severity}] {name}: {details}"
    logging.info(colored(message, color))

def test_sql_injection(target):
    """Test for SQL injection vulnerabilities"""
    test_payloads = ["'", "\"", "1' OR '1'='1"]
    vulnerable = False
    
    for payload in test_payloads:
        try:
            response = requests.get(f"{target}?id={payload}", timeout=5)
            if "error" in response.text.lower() or "sql" in response.text.lower():
                log_vulnerability("SQL Injection", "CRITICAL", f"Vulnerable to payload: {payload}")
                vulnerable = True
        except Exception as e:
            logging.error(f"Error testing SQLi: {str(e)}")
    
    return {'vulnerable': vulnerable}

def test_xss(target):
    """Test for XSS vulnerabilities"""
    test_payload = "<script>alert('XSS')</script>"
    try:
        response = requests.get(f"{target}?search={test_payload}", timeout=5)
        if test_payload in response.text:
            log_vulnerability("XSS", "HIGH", "Reflected XSS detected")
            return {'vulnerable': True}
    except Exception as e:
        logging.error(f"Error testing XSS: {str(e)}")
    return {'vulnerable': False}

def fuzz_owasp(target):
    """Run OWASP Top 10 vulnerability checks"""
    checks = [
        {'name': 'SQL Injection', 'func': test_sql_injection},
        {'name': 'XSS', 'func': test_xss},
        # Additional checks would be added here
    ]
    
    results = []
    for check in checks:
        try:
            result = check['func'](target)
            results.append({
                'vulnerability': check['name'],
                'result': result
            })
        except Exception as e:
            logging.error(f"Error running {check['name']} check: {str(e)}")
    
    return results

class VulnerabilityScanner:
    def __init__(self, target):
        self.target = target
        self.nm = nmap.PortScanner()
        self.vulnerabilities = []

    def port_scan(self):
        try:
            logging.info(f"Starting port scan on {self.target}")
            self.nm.scan(hosts=self.target, arguments='-sV -T4')
            
            for host in self.nm.all_hosts():
                logging.info(f"Scan results for {host}:")
                for proto in self.nm[host].all_protocols():
                    ports = self.nm[host][proto].keys()
                    for port in sorted(ports):
                        service = self.nm[host][proto][port]
                        logging.info(f"Port: {port}\tState: {service['state']}\tService: {service['name']} {service['version']}")
                        self.check_common_vulns(port, service)

        except Exception as e:
            logging.error(f"Port scan failed: {str(e)}")

    def check_common_vulns(self, port, service):
        if port == 80 or port == 443:
            self.check_web_vulns()
        elif 'ftp' in service['name'].lower():
            self.check_ftp_vulns()
        elif 'ssh' in service['name'].lower():
            self.check_ssh_vulns()

    def check_web_vulns(self):
        test_urls = [
            f"http://{self.target}/",
            f"http://{self.target}/admin",
            f"http://{self.target}/phpmyadmin"
        ]
        
        for url in test_urls:
            try:
                response = requests.get(url, timeout=5)
                if response.status_code == 200:
                    logging.warning(f"Potential admin interface found: {url}")
            except requests.RequestException:
                continue

    def check_ftp_vulns(self):
        logging.info("Checking for common FTP vulnerabilities...")

    def check_ssh_vulns(self):
        logging.info("Checking for common SSH vulnerabilities...")

def scan_target(target):
    scanner = VulnerabilityScanner(target)
    scanner.port_scan()
    return scanner.vulnerabilities