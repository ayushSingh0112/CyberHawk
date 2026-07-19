import urllib.parse
import re
import threading
import concurrent.futures
import time
from bs4 import BeautifulSoup
from .requester import Requester

class Crawler:
    """
    Crawls a target website concurrently using BFS, maximizing coverage with 
    Regex extraction (JS variables/redirects) and standard DOM parsing.
    """
    def __init__(self, target_url, max_depth=10, max_pages=300, max_threads=15, requester=None):
        self.target_url = target_url
        self.base_domain = urllib.parse.urlparse(target_url).netloc
        self.max_depth = max_depth
        self.max_pages = max_pages
        self.max_threads = max_threads
        
        self.requester = requester if requester else Requester()
        
        self.visited_urls = set()
        
        # Results
        self.discovered_endpoints = set()
        self.discovered_forms = []
        self.discovered_params = set()
        
        self.lock = threading.Lock()
        
        # General-purpose regex for absolute, relative, template literals, and standard web files. 
        self.js_regex = re.compile(r'''["'`]((?:https?://|/|\.\./|\./)[^"'`\s]+|[a-zA-Z0-9_.-]+\.(?:php|html|js|aspx|jsp|do|action|cfm)(?:\?[^"'`\s]*)?)["'`]''', re.I)

    def is_in_scope(self, url):
        parsed = urllib.parse.urlparse(url)
        target = urllib.parse.urlparse(self.target_url)
        
        base_path = target.path
        if not base_path.endswith('/'):
            base_path = base_path.rsplit('/', 1)[0] + '/'
        if not base_path:
            base_path = '/'
            
        return parsed.netloc == self.base_domain and parsed.scheme in ['http', 'https'] and parsed.path.startswith(base_path)

    def normalize_url(self, url):
        parsed = urllib.parse.urlparse(url)
        return urllib.parse.urlunparse((parsed.scheme, parsed.netloc, parsed.path, '', '', ''))

    def parse_forms(self, html, page_url):
        soup = BeautifulSoup(html, 'html.parser')
        for form in soup.find_all('form'):
            action = form.get('action')
            method = form.get('method', 'get').lower()
            form_url = self.requester.construct_url(page_url, action) if action else page_url
            
            if not self.is_in_scope(form_url):
                continue
                
            inputs = []
            for tag in form.find_all(['input', 'textarea', 'select']):
                name = tag.get('name')
                if name:
                    inputs.append({'name': name, 'type': tag.get('type', 'text')})
            
            if inputs:
                with self.lock:
                    form_entry = {
                        'action': form_url,
                        'method': method,
                        'inputs': inputs,
                        'source_page': page_url
                    }
                    if form_entry not in self.discovered_forms:
                        self.discovered_forms.append(form_entry)

    def normalize_and_filter(self, raw_links, current_url):
        valid_links = set()
        for href in raw_links:
            if href.lower().startswith(('mailto:', 'javascript:', 'tel:', '#')):
                continue
                
            full_url = self.requester.construct_url(current_url, href)
            
            if self.is_in_scope(full_url):
                parsed = urllib.parse.urlparse(full_url)
                if parsed.query:
                    qs = urllib.parse.parse_qs(parsed.query)
                    base = urllib.parse.urlunparse((parsed.scheme, parsed.netloc, parsed.path, '', '', ''))
                    with self.lock:
                        for param in qs.keys():
                            self.discovered_params.add(('get', base, param))
                            
                valid_links.add(full_url)
        return valid_links

    def process_url(self, url, depth):
        # 4. Rate Limiting (Priority 3)
        time.sleep(0.1)
        
        try:
            # 7. Response Filtering
            response = self.requester.session.get(url, timeout=5, stream=True)
            content_type = response.headers.get('Content-Type', '').lower()
            
            if any(t in content_type for t in ['image', 'video', 'audio', 'pdf', 'zip']):
                return set(), depth
                
            content_length = int(response.headers.get('Content-Length', 0))
            if content_length > 5 * 1024 * 1024:  # 5MB Cap
                return set(), depth
                
            html = response.text
        except Exception:
            return set(), depth

        # 2. External JS Fetching + Parsing (Priority 2)
        if 'javascript' in content_type or url.lower().endswith('.js'):
            raw_links = set()
            for match in self.js_regex.finditer(html):
                raw_links.add(match.group(1))
            return self.normalize_and_filter(raw_links, url), depth

        # 1. HTML Parsing (Priority 1)
        self.parse_forms(html, url)
        raw_links = set()
        soup = BeautifulSoup(html, 'html.parser')
        
        # PRIMARY - HTML Tag Extractor
        for tag in soup.find_all(['a', 'frame', 'iframe', 'script', 'link']):
            href = tag.get('href') or tag.get('src')
            if href: raw_links.add(href)
            
        for meta in soup.find_all('meta', attrs={'http-equiv': re.compile('^refresh$', re.I)}):
            content = meta.get('content', '')
            if 'url=' in content.lower():
                raw_links.add(content.lower().split('url=')[-1].strip(' \'";'))

        # SECONDARY - JS Extractor on Inline Scripts
        for script in soup.find_all('script'):
            if script.string:
                for match in self.js_regex.finditer(script.string):
                    raw_links.add(match.group(1))
                    
        # Apply regex over remaining structural elements (DOM Event Handlers)
        for match in self.js_regex.finditer(html):
            raw_links.add(match.group(1))

        return self.normalize_and_filter(raw_links, url), depth

    def run(self):
        print(f"[*] Starting highly concurrent crawl on {self.target_url}")
        
        futures_map = {}
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            with self.lock:
                norm = self.normalize_url(self.target_url)
                self.visited_urls.add(norm)
                self.discovered_endpoints.add(norm)
                f = executor.submit(self.process_url, self.target_url, 0)
                futures_map[f] = self.target_url

            while futures_map:
                done, not_done = concurrent.futures.wait(futures_map.keys(), return_when=concurrent.futures.FIRST_COMPLETED)
                for future in done:
                    url = futures_map.pop(future)
                    try:
                        result = future.result()
                        if result:
                            new_links, depth = result
                            if depth + 1 <= self.max_depth:
                                with self.lock:
                                    for link in new_links:
                                        if len(self.visited_urls) >= self.max_pages:
                                            break
                                            
                                        norm_link = self.normalize_url(link)
                                        if norm_link not in self.visited_urls:
                                            self.visited_urls.add(norm_link)
                                            self.discovered_endpoints.add(norm_link)
                                            
                                            nf = executor.submit(self.process_url, link, depth + 1)
                                            futures_map[nf] = link
                    except Exception as e:
                        print(f"Crawler error on {url}: {e}")

        return {
            'endpoints': list(self.discovered_endpoints),
            'forms': self.discovered_forms,
            'params': list(self.discovered_params)
        }

if __name__ == '__main__':
    pass
