# VulnHunter - Advanced Web Application Security Scanner

VulnHunter is a Python CLI tool that automatically detects security vulnerabilities on a given URL. It performs comprehensive reconnaissance and conditionally tests for vulnerabilities based on WAF detection.

## Features

- **Reconnaissance**: Domain info, tech stack, WAF detection, SSL/TLS checks, security headers, CORS analysis.
- **Vulnerability Testing**: SQL injection, brute-force attacks on login forms (only if no WAF or user approves).
- **Modular Design**: Easy to extend with new modules.
- **Reports**: JSON and HTML reports with severity levels.

## Installation

1. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

2. Make executable:
   ```bash
   chmod +x cli.py
   ```

## Usage

```bash
python cli.py <url>
```

Example:
```bash
python cli.py https://example.com
```

The tool will:
1. Run reconnaissance scans.
2. Detect WAF.
3. If WAF detected, prompt user to continue.
4. If approved, crawl and test for vulnerabilities.
5. Generate reports in `reports/` directory.

## Configuration

Edit `config.yaml` to customize timeouts, threads, wordlist paths, etc.

## Disclaimer

For educational and authorized testing only. Use responsibly.