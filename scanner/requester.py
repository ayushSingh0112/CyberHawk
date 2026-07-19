import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
import urllib.parse
import time
import hashlib
import json

class Requester:
    """
    Centralized HTTP Request handler to be used by the Crawler and Scanners.
    Optimized natively to deduplicate brute-force noise, aggressively track Telemetry boundaries, 
    and adaptively throttle thread concurrency based on server-side response latency tolerances.
    """
    def __init__(self, use_auth=False, auth_cookie=None):
        self.session = requests.Session()
        
        # Setup retries - 500 removed as it is often a vulnerability indicator (SQLi)
        retries = Retry(total=3, backoff_factor=0.3, status_forcelist=[502, 503, 504])
        adapter = HTTPAdapter(max_retries=retries)
        self.session.mount('http://', adapter)
        self.session.mount('https://', adapter)
        
        self.session.headers.update({
            'User-Agent': 'Cyberhawk Security Vanguard v1.1',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8'
        })
        
        if use_auth and auth_cookie:
            self.session.cookies.update(auth_cookie)
            
        # Optimization Tracking Cache
        self.start_time = time.time()
        self.requests_sent = 0
        self.bytes_sent = 0
        self.bytes_received = 0
        self.duplicates_skipped = 0
        
        self.seen_requests = set()
        self.param_tests = {}  # {url_path: {param_key: count}}
        self.status_counts = {200: 0, 429: 0, 503: 0, 'other': 0}
        self.response_times = []
        self.throttle_delay = 0.0

    def _generate_signature(self, method, url, params, data):
        """Constructs an MD5 signature reflecting the precise network profile to discard redundant payload firings."""
        sig_data = {
            'm': method,
            'u': url,
            'p': sorted(params.items()) if isinstance(params, dict) else str(params),
            'd': sorted(data.items()) if isinstance(data, dict) else str(data)
        }
        return hashlib.md5(json.dumps(sig_data, sort_keys=True).encode()).hexdigest()

    def _check_payload_efficiency(self, url, params, data):
        """Monitors single-parameter loops to identify and instantly block blind noise fuzzing."""
        path = urllib.parse.urlparse(url).path
        if path not in self.param_tests:
            self.param_tests[path] = {}
        
        keys = []
        if isinstance(params, dict): keys.extend(params.keys())
        if isinstance(data, dict): keys.extend(data.keys())
        
        for k in keys:
            self.param_tests[path][k] = self.param_tests[path].get(k, 0) + 1
            if self.param_tests[path][k] > 100: # Increased threshold for multi-scanner accuracy
                return False
        return True

    def request(self, method, url, params=None, data=None, headers=None, timeout=5):
        # 1. Active Deduplication Sequence
        signature = self._generate_signature(method, url, params, data)
        if signature in self.seen_requests:
            self.requests_sent += 1 # Count it even if skipped for stats? No, keep logic
            self.duplicates_skipped += 1
            return None
        self.seen_requests.add(signature)
        
        # 2. Brute-Force Parameter Prevention
        if not self._check_payload_efficiency(url, params, data):
            self.duplicates_skipped += 1
            return None
            
        # 3. Dynamic Server Tolerance Application
        if self.throttle_delay > 0:
            time.sleep(self.throttle_delay)
            
        try:
            req_start = time.time()
            out_bytes = len(str(params)) + len(str(data))
            self.bytes_sent += out_bytes
            self.requests_sent += 1
            
            # Importing here to isolate warning suppressions per thread natively if needed
            import urllib3
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
            
            response = self.session.request(
                method=method.upper(),
                url=url,
                params=params,
                data=data,
                headers=headers,
                timeout=timeout,
                allow_redirects=True,
                verify=False # CRITICAL: Allows scanning self-signed internal benchmarks
            )
            
            # 4. Telemetry Tracking Core
            req_time = time.time() - req_start
            self.response_times.append(req_time)
            if len(self.response_times) > 100: self.response_times.pop(0)
            
            self.bytes_received += len(response.content)
            
            code = response.status_code
            if code == 200: self.status_counts[200] += 1
            elif code == 429: self.status_counts[429] += 1
            elif code == 503: self.status_counts[503] += 1
            else: self.status_counts['other'] += 1
            
            # 5. Native Adaptive Throttling Heuristics
            if code in [429, 503]:
                # Instant reaction to server panic
                self.throttle_delay = min(self.throttle_delay + 0.5, 5.0) 
            else:
                avg_time = sum(self.response_times) / len(self.response_times) if self.response_times else 0
                if avg_time > 1.5:
                    # Defensive speed brake
                    self.throttle_delay = min(self.throttle_delay + 0.1, 2.0)
                elif self.throttle_delay > 0 and avg_time < 0.4:
                    # Rapid recovery easing
                    self.throttle_delay = max(0, self.throttle_delay - 0.05)

            return response
            
        except requests.exceptions.RequestException as e:
            self.status_counts['other'] += 1
            return None

    def get_stats(self):
        """Returns the real-time operational payload metrics natively mapping server strain."""
        elapsed = time.time() - self.start_time
        rps = self.requests_sent / elapsed if elapsed > 0 else 0
        avg_time = sum(self.response_times) / len(self.response_times) if self.response_times else 0
        return {
            'requests': self.requests_sent,
            'rps': round(rps, 2),
            'avg_time_ms': int(avg_time * 1000),
            'duplicates_skipped': self.duplicates_skipped,
            'throttle': round(self.throttle_delay, 2),
            'mb_sent': round(self.bytes_sent / 1024 / 1024, 2),
            'mb_recv': round(self.bytes_received / 1024 / 1024, 2),
            'status_429': self.status_counts[429],
            'status_503': self.status_counts[503]
        }

    def get(self, url, params=None, **kwargs):
        return self.request('GET', url, params=params, **kwargs)

    def post(self, url, data=None, **kwargs):
        return self.request('POST', url, data=data, **kwargs)

    @staticmethod
    def construct_url(base_url, path):
        """Handles relative URLs and returns an absolute URL"""
        return urllib.parse.urljoin(base_url, path)

    @staticmethod
    def extract_domain(url):
        return urllib.parse.urlparse(url).netloc
