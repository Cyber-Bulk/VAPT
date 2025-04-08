import requests
import socket
from bs4 import BeautifulSoup
from urllib.parse import urljoin
from utils.logger import setup_logger
import logging

setup_logger()

def enumerate_subdomains(domain):
    """Enumerate subdomains using common wordlist"""
    common_subdomains = ['www', 'mail', 'ftp', 'admin', 'test', 'dev', 'staging', 
                        'api', 'secure', 'portal', 'blog', 'shop', 'app']
    valid_subdomains = []
    
    for sub in common_subdomains:
        full_domain = f"{sub}.{domain}"
        try:
            socket.gethostbyname(full_domain)
            valid_subdomains.append(full_domain)
            logging.info(f"Discovered subdomain: {full_domain}")
        except socket.gaierror:
            continue
    return valid_subdomains

class WebCrawler:
    def __init__(self, base_url):
        self.base_url = base_url
        self.visited_urls = set()
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; rv:91.0) Gecko/20100101 Firefox/91.0'
        })

    def crawl(self, url=None, depth=0, max_depth=2):
        if url is None:
            url = self.base_url

        if url in self.visited_urls or depth > max_depth:
            return

        try:
            response = self.session.get(url, timeout=10)
            self.visited_urls.add(url)
            logging.info(f"Crawling: {url} (Status: {response.status_code})")

            soup = BeautifulSoup(response.text, 'html.parser')
            self.extract_forms(url, soup)
            
            for link in soup.find_all('a', href=True):
                absolute_url = urljoin(url, link['href'])
                if self.base_url in absolute_url:
                    self.crawl(absolute_url, depth + 1, max_depth)

        except Exception as e:
            logging.error(f"Error crawling {url}: {str(e)}")

    def extract_forms(self, url, soup):
        forms = soup.find_all('form')
        for form in forms:
            form_details = {
                'action': urljoin(url, form.get('action', '')),
                'method': form.get('method', 'get').upper(),
                'inputs': []
            }
            
            for input_tag in form.find_all('input'):
                form_details['inputs'].append({
                    'name': input_tag.get('name'),
                    'type': input_tag.get('type'),
                    'value': input_tag.get('value', '')
                })
            
            logging.info(f"Form found at {url}: {form_details}")

def crawl_website(target_url):
    crawler = WebCrawler(target_url)
    crawler.crawl()
    return crawler.visited_urls