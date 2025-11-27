import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse

class Crawler:
    def __init__(self, target_url, session=None):
        self.target_url = target_url
        self.session = session or requests.Session()
        self.visited_urls = set()
        self.forms = []

    def crawl(self, url=None, depth=2):
        if url is None:
            url = self.target_url
        
        if depth == 0 or url in self.visited_urls:
            return

        self.visited_urls.add(url)
        
        try:
            response = self.session.get(url)
            soup = BeautifulSoup(response.content, 'html.parser')
            
            # Find forms
            for form in soup.find_all('form'):
                self.forms.append({
                    'action': urljoin(url, form.get('action')),
                    'method': form.get('method', 'get').lower(),
                    'inputs': [{'name': input_tag.get('name'), 'type': input_tag.get('type', 'text')} 
                               for input_tag in form.find_all('input')]
                })

            # Find links
            for link in soup.find_all('a'):
                href = link.get('href')
                if href:
                    full_url = urljoin(url, href)
                    if self._is_internal(full_url):
                        self.crawl(full_url, depth - 1)
                        
        except Exception as e:
            pass

    def _is_internal(self, url):
        return urlparse(url).netloc == urlparse(self.target_url).netloc
