import click
from scanner.core.requester import Requester
from scanner.modules.sqli import SQLInjectionScanner
from scanner.modules.xss import XSSScanner
from scanner.modules.headers import HeaderScanner
from scanner.utils.report import save_report
from scanner.utils.banner import print_banner
from colorama import init, Fore, Style

init(autoreset=True)

@click.command(context_settings=dict(help_option_names=['-h', '--help']))
@click.argument('target_url')
@click.option('--scan-type', default='all', help='Type of scan: all, sqli, xss, headers')
@click.option('--output', help='Output file for the report')
def main(target_url, scan_type, output):
    """
    AllSafe - Web App Security Scanner
    """
    print_banner()
    print(f"{Fore.BLUE}[*] Starting scan on {target_url}{Style.RESET_ALL}")
    
    requester = Requester()
    
    # Verify connectivity
    response = requester.get(target_url)
    if not response:
        print(f"{Fore.RED}[!] Could not access target. Exiting.{Style.RESET_ALL}")
        return

    vulnerabilities = []

    scanners = []
    if scan_type in ['all', 'sqli']:
        scanners.append(SQLInjectionScanner(target_url, requester.session))
    if scan_type in ['all', 'xss']:
        scanners.append(XSSScanner(target_url, requester.session))
    if scan_type in ['all', 'headers']:
        scanners.append(HeaderScanner(target_url, requester.session))

    for scanner in scanners:
        print(f"{Fore.YELLOW}[*] Running {scanner.__class__.__name__}...{Style.RESET_ALL}")
        scanner.scan()
        vulnerabilities.extend(scanner.vulnerabilities)

    print(f"\n{Fore.GREEN}[+] Scan completed!{Style.RESET_ALL}")
    if vulnerabilities:
        print(f"{Fore.RED}[!] Found {len(vulnerabilities)} vulnerabilities:{Style.RESET_ALL}")
        for vuln in vulnerabilities:
            print(f" - [{vuln['severity']}] {vuln['type']}: {vuln['details']}")
    else:
        print(f"{Fore.GREEN}[+] No vulnerabilities found.{Style.RESET_ALL}")
    
    if output:
        save_report(vulnerabilities, output)

if __name__ == '__main__':
    main()
