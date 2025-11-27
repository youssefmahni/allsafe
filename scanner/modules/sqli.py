from scanner.modules.base import BaseScanner
from scanner.core.crawler import Crawler
from urllib.parse import urljoin

class SQLInjectionScanner(BaseScanner):
    def scan(self):
        crawler = Crawler(self.target_url, self.session)
        crawler.crawl(depth=1) # Shallow crawl for now
        
        payloads = ["'", "\"", "' OR 1=1 --", "\" OR 1=1 --"]
        errors = ["syntax error", "mysql", "sql", "database error"]

        for form in crawler.forms:
            action = form['action']
            method = form['method']
            inputs = form['inputs']
            
            for input_tag in inputs:
                if input_tag['type'] in ['submit', 'button', 'image']:
                    continue
                
                for payload in payloads:
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
                        
                        for error in errors:
                            if error in res.text.lower():
                                self.add_vulnerability(
                                    "SQL Injection",
                                    f"Possible SQLi in {action} parameter {input_tag['name']} with payload {payload}",
                                    "High"
                                )
                                break
                    except Exception as e:
                        pass
