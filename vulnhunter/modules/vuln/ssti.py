from colorama import Fore, Style
from urllib.parse import urlparse, parse_qs, urlunparse, urlencode
from modules.base import BaseScanner

class SSTIScanner(BaseScanner):
    """
    Scanner to detect Server-Side Template Injection (SSTI) vulnerabilities.
    
    The expected result if the injection works for the operation 7*7 is '49'.
    """
    
    # SSTI payloads based on simple mathematical operations as requested.
    SSTI_PAYLOADS = {
        "Jinja2/Twig (Python/PHP)": '{{7*7}}',
        "ERB/EJS (Ruby/Node.js)": '<%= 7*7 %>',
        "Freemarker/Smarty-Alt (Java/PHP)": '${7*7}',
        "Smarty (PHP)": '{7*7}',
        "Velocity (Java)": '#set($a=7*7)$a'
        
    }
    
    EXPECTED_RESULT = '49'
    VULN_TYPE = "Server-Side Template Injection (SSTI)"
    VULN_SEVERITY = "High"

    def scan(self, forms=None, urls=None):
        print(f"{Fore.YELLOW}[*] Starting SSTI Scan.{Style.RESET_ALL}")
        
        # 1. Test GET parameters on found URLs
        if urls:
            for url in urls:
                self._test_url_parameters(url)

        # 2. Test input fields on found forms
        if forms:
            for form in forms:
                self._test_form_inputs(form)
        
        # Note: All detected vulnerabilities are stored in self.vulnerabilities 
        # for reporting at the end of the main scanner process.

    def _test_url_parameters(self, url):
        """Tests each GET parameter of the URL for SSTI."""
       
        parsed_url = urlparse(url)
        query_params = parse_qs(parsed_url.query)
        
        if not query_params:
            return

        for key in query_params.keys():
            # Test each parameter with every payload, avoiding duplication of target parameters.
            for engine, payload in self.SSTI_PAYLOADS.items():
                
                # Builds a new query with the payload
                test_params = query_params.copy()
                # The value must be passed as a list of strings (parse_qs does this)
                test_params[key] = [payload]
                
                new_query = urlencode(test_params, doseq=True)
                test_url = urlunparse(parsed_url._replace(query=new_query))
                
                response = self.session.get(test_url)
                self._check_response(response, engine, f"GET parameter '{key}' at {test_url}")
                
    def _test_form_inputs(self, form):
        """Tests each form input field for SSTI."""
        url = form['action']
        method = form['method']
        
        for input_field in form.get('inputs', []):
            input_name = input_field.get('name')
            if not input_name:
                continue

            for engine, payload in self.SSTI_PAYLOADS.items():
                # Get the name of other inputs for payload insertion
                data = {i.get('name'): i.get('name') for i in form.get('inputs', []) if i.get('name')}
                
                # Inject the payload into the current input field
                data[input_name] = payload
                
                response = None
                if method.upper() == 'POST':
                    response = self.session.post(url, data=data)
                elif method.upper() == 'GET':
                    response = self.session.get(url, params=data)
                
                if response:
                    self._check_response(response, engine, f"{method} form field '{input_name}' at {url}")

    def _check_response(self, response, engine, location_detail):

        if response and self.EXPECTED_RESULT in response.text:
            self.add_vulnerability(
                self.VULN_TYPE,
                f"SSTI detected (probable engine: {engine}). The payload was interpreted, returning '{self.EXPECTED_RESULT}'. Location: {location_detail}",
                self.VULN_SEVERITY
            )
            
