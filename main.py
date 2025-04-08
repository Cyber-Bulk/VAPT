#!/usr/bin/env python3
import argparse
import logging
import os
from utils.logger import setup_logger

def main():
    parser = argparse.ArgumentParser(description='Python Penetration Testing Tool')
    parser.add_argument('--target', help='Target URL or IP address', required=True)
    parser.add_argument('--recon', help='Run reconnaissance modules', action='store_true')
    parser.add_argument('--scan', help='Run vulnerability scanning', action='store_true')
    parser.add_argument('--exploit', help='Run exploitation modules', action='store_true')
    parser.add_argument('--wordlist', help='Path to custom wordlist for brute-force attacks', type=str)
    parser.add_argument('--domains-file', help='File containing list of domains to test', type=str)
    parser.add_argument('--wildcard', help='Enable wildcard subdomain enumeration', action='store_true')
    parser.add_argument('--fuzz-owasp', help='Enable OWASP Top 10 vulnerability fuzzing', action='store_true')
    parser.add_argument('--accept-terms', help='Accept legal terms (automatically enabled)',
                      action='store_true', default=True)
    
    args = parser.parse_args()

    # Validate file inputs
    if args.wordlist and not os.path.exists(args.wordlist):
        logging.error(f"Wordlist file not found: {args.wordlist}")
        return
    if args.domains_file and not os.path.exists(args.domains_file):
        logging.error(f"Domains file not found: {args.domains_file}")
        return

    setup_logger()
    logging.info(f"Starting penetration test against {args.target} (Terms accepted)")

    if args.recon:
        from recon.web_crawler import crawl_website, enumerate_subdomains
        crawl_website(args.target)
        if args.wildcard:
            if args.domains_file:
                with open(args.domains_file) as f:
                    for domain in f:
                        enumerate_subdomains(domain.strip())
            else:
                enumerate_subdomains(args.target)

    if args.scan or args.fuzz_owasp:
        from scan.vuln_scanner import scan_target, fuzz_owasp
        scan_target(args.target)
        if args.fuzz_owasp:
            fuzz_owasp(args.target)

    if args.exploit:
        from exploit.payload_generator import generate_payloads
        generate_payloads(args.target, wordlist=args.wordlist)

if __name__ == "__main__":
    main()