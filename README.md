# AllSafe - Web App Security Scanner

A modular, Python-based Command Line Interface tool for scanning web applications for common security vulnerabilities.

## Features

- **SQL Injection (SQLi) Scanning**: Detects potential SQL injection vulnerabilities by fuzzing parameters.
- **Cross-Site Scripting (XSS) Scanning**: Identifies reflected XSS vulnerabilities.
- **Security Header Analysis**: Checks for missing critical security headers (e.g., X-Frame-Options, CSP).
- **Web Crawler**: Automatically discovers links and forms on the target website.
- **Reporting**: Generates reports in JSON or text format.

## Installation

1.  **Clone the repository:**
    ```bash
    git clone <repository-url>
    cd scanner
    ```

2.  **Set up a virtual environment (recommended):**
    ```bash
    python3 -m venv venv
    source venv/bin/activate  # On Windows: venv\Scripts\activate
    ```

3.  **Install dependencies:**
    ```bash
    pip install -r requirements.txt
    ```

## Usage

You can run the scanner using the `allsafe` script:

```bash
python3 allsafe [OPTIONS] TARGET_URL
```

### Options

- `TARGET_URL`: The URL of the web application to scan (required).
- `--scan-type TEXT`: Type of scan to perform. Options: `all` (default), `sqli`, `xss`, `headers`.
- `--output TEXT`: Path to save the scan report (e.g., `report.json`).
- `-h, --help`: Show the help message.

### Examples

**Run a full scan:**
```bash
python3 allsafe http://example.com
```

**Scan only for SQL Injection:**
```bash
python3 allsafe http://example.com --scan-type sqli
```

**Save report to a file:**
```bash
python3 allsafe http://example.com --output results.json
```

## Disclaimer

**Usage of this tool for attacking targets without prior mutual consent is illegal.** It is the end user's responsibility to obey all applicable local, state, and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program.
