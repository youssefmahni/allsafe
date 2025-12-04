from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
import re

class Crawler:
    def __init__(self, base_url, requester, max_depth=2, max_urls=100):
        self.base_url = base_url
        self.requester = requester
        self.max_depth = max_depth
        self.max_urls = max_urls
        self.visited = set()
        self.forms = []
        self.urls = set()
        self.api_endpoints = set()

    def crawl(self, url=None, depth=0):
        if url is None:
            url = self.base_url
        if depth > self.max_depth or url in self.visited or len(self.urls) >= self.max_urls:
            return
        self.visited.add(url)
        response = self.requester.get(url)
        if not response:
            return
        self.urls.add(url)
        soup = BeautifulSoup(response.text, 'html.parser')
        
        # Extract forms
        for form in soup.find_all('form'):
            self.forms.append({
                'action': urljoin(url, form.get('action', '')),
                'method': form.get('method', 'get').upper(),
                'inputs': [{'name': inp.get('name'), 'type': inp.get('type')} for inp in form.find_all('input')]
            })
        
        # Extract links
        for link in soup.find_all('a', href=True):
            next_url = urljoin(url, link['href'])
            if self._is_same_domain(next_url):
                self.crawl(next_url, depth + 1)
        
        # Extract potential API endpoints
        for script in soup.find_all('script', src=True):
            src = urljoin(url, script['src'])
            if 'api' in src.lower():
                self.api_endpoints.add(src)
        
        # Regex for API patterns
        api_patterns = [r'/api/[^\'"]*', r'/v\d+/[^\'"]*']
        for pattern in api_patterns:
            matches = re.findall(pattern, response.text)
            for match in matches:
                self.api_endpoints.add(urljoin(url, match))

    def _is_same_domain(self, url):
        return urlparse(url).netloc == urlparse(self.base_url).netloc