from scanner.modules.base import BaseScanner
from scanner.core.crawler import Crawler
from urllib.parse import urljoin

class XSSScanner(BaseScanner):
    def scan(self):
        crawler = Crawler(self.target_url, self.session)
        crawler.crawl(depth=1)
        
        payload = "<script>alert('XSS')</script>"
        
        for form in crawler.forms:
            action = form['action']
            method = form['method']
            inputs = form['inputs']
            
            for input_tag in inputs:
                if input_tag['type'] in ['submit', 'button', 'image']:
                    continue
                
                data = {}
                for inp in inputs:
                    if inp['name'] == input_tag['name']:
                        data[inp['name']] = payload
                    else:
                        data[inp['name']] = "test"
                
                try:
                    if method == 'post':
                        res = self.session.post(action, data=data)
                    else:
                        res = self.session.get(action, params=data)
                    
                    if payload in res.text:
                        self.add_vulnerability(
                            "Reflected XSS",
                            f"XSS in {action} parameter {input_tag['name']}",
                            "High"
                        )
                except Exception as e:
                    pass
