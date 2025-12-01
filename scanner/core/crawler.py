import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
from playwright.sync_api import sync_playwright

class Crawler:
    def __init__(self, target_url):
        self.target_url = target_url
        self.target_domain = urlparse(target_url).netloc
        self.visited_urls = set()
        self.forms = []
        self.form_signatures = set()

    def crawl(self, url=None, depth=2):
        if url is None:
            url = self.target_url
            
        print(f"[*] Starting Headless Crawl on {url} (Depth: {depth})")
        
        try:
            with sync_playwright() as p:
                browser = p.chromium.launch(headless=True)
                context = browser.new_context(ignore_https_errors=True)
                page = context.new_page()
                
                self._crawl_recursive(page, url, depth)
                
                browser.close()
        except Exception as e:
            print(f"[!] Crawler Error: {e}")

    def _crawl_recursive(self, page, url, depth):
        if depth == 0 or url in self.visited_urls:
            return

        self.visited_urls.add(url)
        # print(f" - Visiting: {url}")
        
        try:
            page.goto(url, timeout=15000, wait_until='domcontentloaded')
            # Allow some JS execution
            page.wait_for_timeout(1000)
            
            content = page.content()
            soup = BeautifulSoup(content, 'html.parser')
            
            # Find forms
            for form in soup.find_all('form'):
                action = form.get('action')
                if action:
                    full_action = urljoin(url, action)
                    method = form.get('method', 'get').lower()
                    
                    inputs = []
                    input_names = []
                    for i in form.find_all('input'):
                        name = i.get('name')
                        inputs.append({'name': name, 'type': i.get('type', 'text')})
                        if name:
                            input_names.append(name)
                    
                    # Create a signature for deduplication
                    # Signature: (action, method, sorted_input_names)
                    form_sig = (full_action, method, tuple(sorted(input_names)))
                    
                    if form_sig not in self.form_signatures:
                        self.form_signatures.add(form_sig)
                        self.forms.append({
                            'action': full_action,
                            'method': method,
                            'inputs': inputs
                        })

            # Find links
            for link in soup.find_all('a'):
                href = link.get('href')
                if href:
                    full_url = urljoin(url, href)
                    if self._is_internal(full_url):
                        self._crawl_recursive(page, full_url, depth - 1)
                        
        except Exception as e:
            # print(f" - Error visiting {url}: {e}")
            pass

    def _is_internal(self, url):
        return urlparse(url).netloc == self.target_domain
