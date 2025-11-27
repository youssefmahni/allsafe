import requests
from abc import ABC, abstractmethod

class BaseScanner(ABC):
    def __init__(self, target_url, session=None):
        self.target_url = target_url
        self.session = session or requests.Session()
        self.vulnerabilities = []

    @abstractmethod
    def scan(self):
        """
        Perform the scan and return a list of vulnerabilities.
        """
        pass

    def add_vulnerability(self, vuln_type, details, severity="Medium"):
        self.vulnerabilities.append({
            "type": vuln_type,
            "details": details,
            "severity": severity,
            "url": self.target_url
        })
