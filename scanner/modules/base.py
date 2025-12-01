from abc import ABC, abstractmethod
import requests

class BaseScanner(ABC):
    def __init__(self, target_url, session=None):
        self.target_url = target_url
        self.session = session or requests.Session()
        self.vulnerabilities = []

    @abstractmethod
    def scan(self, forms=None, urls=None):
        """
        Perform the scan and return a list of vulnerabilities.
        """
        pass

    def add_vulnerability(self, vuln_type, details, severity="Medium", url=None):
        self.vulnerabilities.append({
            "type": vuln_type,
            "details": details,
            "severity": severity,
            "url": url or self.target_url
        })

    def log(self, message):
        """Thread-safe logging"""
        import threading
        if not hasattr(BaseScanner, '_print_lock'):
            BaseScanner._print_lock = threading.Lock()
        
        with BaseScanner._print_lock:
            print(message)
