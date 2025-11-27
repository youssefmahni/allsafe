from scanner.modules.base import BaseScanner

class HeaderScanner(BaseScanner):
    def scan(self):
        try:
            response = self.session.get(self.target_url)
            headers = response.headers
            
            security_headers = [
                'X-Frame-Options',
                'Content-Security-Policy',
                'X-Content-Type-Options',
                'Strict-Transport-Security'
            ]
            
            for header in security_headers:
                if header not in headers:
                    self.add_vulnerability(
                        "Missing Security Header",
                        f"Header {header} is missing.",
                        "Low"
                    )
        except Exception as e:
            print(f"Error scanning headers: {e}")
