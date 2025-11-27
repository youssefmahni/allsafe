import requests
from colorama import Fore, Style

class Requester:
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'SecurityScannerCLI/1.0'
        })

    def get(self, url, **kwargs):
        try:
            return self.session.get(url, **kwargs, timeout=10)
        except requests.RequestException as e:
            print(f"{Fore.RED}[!] Error connecting to {url}: {e}{Style.RESET_ALL}")
            return None

    def post(self, url, data=None, json=None, **kwargs):
        try:
            return self.session.post(url, data=data, json=json, **kwargs, timeout=10)
        except requests.RequestException as e:
            print(f"{Fore.RED}[!] Error connecting to {url}: {e}{Style.RESET_ALL}")
            return None
