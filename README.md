# Python Penetration Testing Tool

A modular penetration testing framework written in Python.

## Features
- **Reconnaissance**: WHOIS lookup, DNS enumeration, web crawling, wildcard subdomain discovery
- **Vulnerability Scanning**: Port scanning, service detection, OWASP Top 10 checks
- **Exploitation**: Payload generation for XSS, SQLi, and RCE with custom wordlist support
- **Reporting**: Color-coded PDF reports with findings and recommendations

## New Features
- **Wildcard Subdomain Enumeration**: Discover subdomains using `--wildcard`
- **OWASP Top 10 Fuzzing**: Run with `--fuzz-owasp` for automated vulnerability checks
- **Color-Coded Reports**: Terminal logs and PDF reports now show severity levels with colors
- **Custom Wordlists**: Use `--wordlist` for brute-force attacks
- **Multi-Domain Testing**: Test multiple domains with `--domains-file`

## Installation
1. Clone the repository
2. Run setup script:
```bash
chmod +x setup.sh
./setup.sh
```

## Usage
Basic command structure:
```bash
python main.py --target TARGET_URL [OPTIONS]
```

### Options:
- `--recon` : Run reconnaissance modules
- `--scan` : Run vulnerability scanning
- `--exploit` : Run exploitation modules
- `--wordlist PATH` : Custom wordlist for brute-force
- `--domains-file PATH` : File containing domains to test
- `--wildcard` : Enable wildcard subdomain enumeration
- `--fuzz-owasp` : Enable OWASP Top 10 checks

## Example Commands
```bash
# Full scan with OWASP checks and custom wordlist
python main.py --target example.com --wildcard --fuzz-owasp --wordlist /path/to/wordlist.txt

# Multi-domain testing
python main.py --domains-file domains.txt --wildcard --scan
```

## Legal Notice
**WARNING**: Always obtain proper authorization before testing any system. Unauthorized testing is illegal. See [legal.txt](config/legal.txt) for full terms.