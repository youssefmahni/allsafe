from colorama import Fore, Style
from modules.base import BaseScanner
from urllib.parse import urlparse, parse_qs, urlunparse, urlencode
import os

class LFIScanner(BaseScanner):
    """
    Scanner to detect Local File Inclusion (LFI) vulnerabilities.
    Performs direct testing using a wordlist against all known OS signatures.
    """
    
    # Static Configuration
    LFI_PAYLOAD_FILE = "wordlists/lfi_payloads.txt"
    COMMON_LFI_PARAMS = ["file", "page", "id", "path"]
    VULN_TYPE = "Local File Inclusion (LFI)"
    VULN_SEVERITY = "High"
    
    # All signatures used for confirmation (OS detection is bypassed)
    ALL_LFI_SIGNATURES = [
        "root:",         # Linux /etc/passwd
        "localhost",     # Linux /etc/hosts
        "[fonts]",       # Windows win.ini
        "[boot loader]", # Windows boot.ini
        "[386Enh]"       # Windows system.ini
    ]

    def _send_and_check(self, url, method, data, location_detail):
        """Helper to send request, check all LFI signatures, and log vulnerability."""
        
        # Send the request (POST uses data, GET uses params)
        try:
            response = self.session.post(url, data=data) if method == 'POST' else self.session.get(url, params=data)
        except Exception:
            return False

        if not response: return False

        # Check for any confirming signature in the response text
        for signature in self.ALL_LFI_SIGNATURES:
            if signature in response.text:
                self.add_vulnerability(
                    self.VULN_TYPE,
                    f"LFI detected! Signature ('{signature}') found in response. Location: {location_detail}",
                    self.VULN_SEVERITY
                )
                print(f"{Fore.RED}[!] LFI VULNERABILITY FOUND: {signature} - {location_detail}{Style.RESET_ALL}")
                return True
        return False

    def scan(self, forms=None, urls=None):
        self.lfi_payloads = self.load_list(self.LFI_PAYLOAD_FILE)
        if not self.lfi_payloads: 
            self.logger.error("No LFI payloads loaded.")
            return

        print(f"{Fore.YELLOW}[*] Starting LFI Scan: Testing {len(self.lfi_payloads)} payloads.{Style.RESET_ALL}")
        
        # 1. Test URLs (GET Parameters)
        if urls:
            for url in urls:
                parsed_url = urlparse(url); query_params = parse_qs(parsed_url.query)
                params_to_test = set(query_params.keys()) | set(self.COMMON_LFI_PARAMS)
                
                for key in params_to_test:
                    for payload in self.lfi_payloads:
                        # Build URL with payload injected (concise version)
                        test_params = query_params.copy(); test_params[key] = [payload]
                        test_url = urlunparse(parsed_url._replace(query=urlencode(test_params, doseq=True)))
                        location = f"GET parameter '{key}' at {test_url}"
                        self._send_and_check(test_url, 'GET', {}, location)
                        
        # 2. Test Forms (POST/GET)
        if forms:
            for form in forms:
                action, method = form.get('action'), form.get('method', 'GET')
                
                for input_field in form.get('inputs', []):
                    input_name = input_field.get('name')
                    if not input_name or input_name not in self.COMMON_LFI_PARAMS: continue

                    for payload in self.lfi_payloads:
                        # Build data dictionary concisely
                        data = {i.get('name'): 'test' for i in form.get('inputs', []) if i.get('name')}
                        data[input_name] = payload
                        location = f"{method} form field '{input_name}' at {action}"
                        self._send_and_check(action, method, data, location)
