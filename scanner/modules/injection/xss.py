from scanner.modules.base import BaseScanner

class XSSScanner(BaseScanner):
    def scan(self, forms=None, urls=None):
        print(f"[*] Starting XSS Scan on {self.target_url}")
        
        from scanner.core.config import ConfigManager
        config = ConfigManager()
        payloads_path = config.get('scanners.xss.payloads')
        
        payloads = ["<script>alert('XSS')</script>"]
        
        if payloads_path:
            try:
                with open(payloads_path, 'r') as f:
                    # Use dict.fromkeys to remove duplicates while preserving order
                    extra_payloads = list(dict.fromkeys(line.strip() for line in f if line.strip()))
                    payloads.extend(extra_payloads)
            except Exception as e:
                print(f"[!] Error loading XSS payloads: {e}")
        
        target_forms = forms or []
        for form in target_forms:
            action = form['action']
            method = form['method']
            inputs = form['inputs']
            
            print(f" - Testing form at {action}")
            
            for payload in payloads:
                data = {}
                for input_tag in inputs:
                    name = input_tag.get('name')
                    if name:
                        data[name] = payload
                
                try:
                    if method == 'post':
                        res = self.session.post(action, data=data)
                    else:
                        res = self.session.get(action, params=data)
                        
                    if payload in res.text:
                        self.add_vulnerability(
                            "Reflected XSS",
                            f"XSS Payload reflected at {action}",
                            "High",
                            url=action
                        )
                        print(f"[!] XSS found at {action}")
                        break # Stop after first successful payload for this form
                except Exception:
                    pass

