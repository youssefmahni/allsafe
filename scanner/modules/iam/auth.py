from scanner.modules.base import BaseScanner
from scanner.core.config import ConfigManager
from colorama import Fore, Style
import os

class AuthScanner(BaseScanner):
    def scan(self, forms=None, urls=None):
        self.log(f"[*] Starting Authentication Testing on {self.target_url}")
        
        config = ConfigManager()
        users_path = config.get('wordlists.users')
        passwords_path = config.get('wordlists.passwords')
        
        # 1. Default Credentials Check (Simplified)
        self.log("[*] Checking for default credentials...")
                
        target_forms = forms or []
        login_form = None
        for form in target_forms:
            # Enhanced heuristic to find login form
            inputs = form.get('inputs', [])
            action = (form.get('action') or '').lower()
            
            # 1. Check for password field (Strong indicator)
            # Check type='password' OR name contains 'pass', 'pwd'
            has_password = any(
                i.get('type') == 'password' or 
                any(kw in (i.get('name') or '').lower() for kw in ['pass', 'pwd'])
                for i in inputs
            )
            
            # 2. Check for user/email field
            has_user = any(
                kw in (i.get('name') or '').lower() 
                for i in inputs 
                for kw in ['user', 'email', 'login', 'username', 'id', 'uname']
            )
            
            # 3. Check for login keywords in action URL
            is_login_url = any(kw in action for kw in ['login', 'signin', 'auth', 'session', 'user'])
            
            # 4. Negative check for registration forms
            is_register = any(kw in action for kw in ['register', 'signup', 'create', 'join'])
            
            if not is_register:
                if has_password and (has_user or is_login_url):
                    login_form = form
                    break
                elif is_login_url and has_user:
                    login_form = form
                    break
        
        if login_form:
            self.log(f"[*] Found potential login form at {login_form['action']}")
            # Here we would attempt to login with defaults
            # For demonstration, we just log that we found the form
            self.add_vulnerability(
                "Login Form Discovered",
                f"Login form found at {login_form['action']}",
                "Info",
                url=login_form['action']
            )
        else:
            self.log("[*] No obvious login form found in crawled data.")

        # 2. Brute Force
        if login_form and users_path and passwords_path and os.path.exists(users_path) and os.path.exists(passwords_path):
            self.log(f"[*] Starting brute-force attack on {login_form['action']}...")
            
            try:
                with open(users_path, 'r', encoding='utf-8', errors='ignore') as f:
                    users = list(dict.fromkeys(line.strip() for line in f if line.strip()))
                with open(passwords_path, 'r', encoding='utf-8', errors='ignore') as f:
                    passwords = list(dict.fromkeys(line.strip() for line in f if line.strip()))
                
                for user in users:
                    for password in passwords:
                        data = {}
                        for input_tag in login_form['inputs']:
                            name = input_tag.get('name')
                            if not name: continue
                            
                            if 'user' in name.lower() or 'email' in name.lower() or 'login' in name.lower():
                                data[name] = user
                            elif 'pass' in name.lower():
                                data[name] = password
                            else:
                                data[name] = 'submit'
                        
                        try:
                            if login_form['method'] == 'post':
                                res = self.session.post(login_form['action'], data=data, allow_redirects=False)
                            else:
                                res = self.session.get(login_form['action'], params=data, allow_redirects=False)
                            
                            # Success detection: Redirect or significant length change
                            # This is heuristic and might need tuning
                            if res.status_code in [301, 302]:
                                location = res.headers.get('Location', '').lower()
                                # False positive check: Redirecting back to login is usually a failure
                                if 'login' in location or 'error' in location or 'fail' in location:
                                    continue
                                    
                                self.log(f"{Fore.GREEN}[+] Potential Success: {user}:{password} (Redirect to {location}){Style.RESET_ALL}")
                                self.add_vulnerability(
                                    "Weak Credentials",
                                    f"Valid credentials found: {user}:{password}",
                                    "Critical",
                                    url=login_form['action']
                                )
                                return # Stop after first success
                        except Exception:
                            pass
            except Exception as e:
                self.log(f"[!] Error during brute-force: {e}")
