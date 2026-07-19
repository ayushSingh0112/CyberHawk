import re
from bs4 import BeautifulSoup
from .severity import calculate_severity

class XSSScanner:
    def __init__(self, requester):
        self.requester = requester
        self.payloads = [
            {"payload": "<script>alert('CYBERHAWK_XSS')</script>", "verify": "alert('CYBERHAWK_XSS')"},
            {"payload": "\"><script>alert('CYBERHAWK_XSS')</script>", "verify": "alert('CYBERHAWK_XSS')"},
            {"payload": "<img src=x onerror=prompt('CYBERHAWK_XSS')>", "verify": "prompt('CYBERHAWK_XSS')"},
            {"payload": "javascript:prompt('CYBERHAWK_XSS')", "verify": "prompt('CYBERHAWK_XSS')"},
            {"payload": "<scr<script>ipt>alert('CYBERHAWK_XSS')</script>", "verify": "<script>alert('CYBERHAWK_XSS')</script>"} # Fallback for regex strippers
        ]
        self.sinks = [r"innerHTML\s*=", r"document\.write\(", r"eval\("]

    def scan_params(self, params):
        results = []
        for method, url, param_name in params:
            # DOM XSS / JS Sink detection
            base_res = self.requester.get(url)
            if base_res is not None:
                for sink in self.sinks:
                    if re.search(sink, base_res.text):
                        results.append(self.build_finding(url, "N/A", sink, "DOM-Based XSS (JS Sink found)"))
                        # We don't break here since we might find multiple sinks or still want to test reflected

            for entry in self.payloads:
                payload = entry['payload']
                verify = entry['verify']
                res = self.requester.get(url, params={param_name: payload})
                if res is not None and verify in res.text:
                    results.append(self.build_finding(url, param_name, payload, "Reflected XSS"))
                    break
        return results
        
    def scan_forms(self, forms):
        results = []
        for form in forms:
            action = form['action']
            method = form['method']
            inputs = form['inputs']
            
            for entry in self.payloads:
                payload = entry['payload']
                verify = entry['verify']
                
                # Live token extraction: ensure CSRF matches what the server requires NOW
                live_res = self.requester.get(form.get('source_page', action))
                if live_res is not None:
                    soup = BeautifulSoup(live_res.text, 'html.parser')
                    for live_inp in soup.find_all('input', type='hidden'):
                        in_name = live_inp.get('name')
                        if in_name:
                            for cached_inp in inputs:
                                if cached_inp.get('name') == in_name:
                                    cached_inp['value'] = live_inp.get('value', '')
                
                # Intelligent Auth/CSRF token preservation
                data = {}
                for inp in inputs:
                    name = inp.get('name', '')
                    inp_type = inp.get('type', '').lower()
                    
                    if inp_type == 'hidden' or any(t in name.lower() for t in ['csrf', 'token', 'nonce', 'state', 'id']):
                        data[name] = inp.get('value', '1')  # Preserve logic flow
                    else:
                        data[name] = payload
                
                if not data: continue
                
                if method == 'post':
                    res = self.requester.post(action, data=data)
                else:
                    res = self.requester.get(action, params=data)
                    
                if res is not None and verify in res.text:
                    results.append(self.build_finding(action, str(list(data.keys())), payload, "Reflected XSS"))
                    break
                    
                # Stored XSS check
                check_res = self.requester.get(action)
                if check_res is not None and verify in check_res.text:
                    results.append(self.build_finding(action, str(list(data.keys())), payload, "Stored XSS"))
                    break
                    
        return results
    def scan_cookies(self, base_url):
        results = []
        cookies = self.requester.session.cookies.get_dict().copy()
        
        # Fallback dummy cookies if session didn't instantiate any organically
        if not cookies:
            for dummy in ['user', 'name', 'session', 'id', 'uid']:
                cookies[dummy] = '1'
            
        for cookie_name in cookies.keys():
            for entry in self.payloads:
                payload = entry['payload']
                verify = entry['verify']
                
                # Fuzz one cookie at a time strictly through headers to bypass session pollution
                fuzz_header = '; '.join([f"{k}={payload if k == cookie_name else v}" for k, v in cookies.items()])
                
                res = self.requester.get(base_url, headers={'Cookie': fuzz_header})
                if res and verify in res.text:
                    results.append(self.build_finding(base_url, f"Cookie: {cookie_name}", payload, "Reflected XSS (Cookie Parameter)"))
                    break
                    
        return results

    def scan_blind_urls(self, endpoints):
        results = []
        # WIVET commonly uses these parameters behind the scenes without explicitly linking them
        fuzz_params = ['name', 'id', 'user', 'q', 'search', 'username']
        
        for url in endpoints:
            for param_name in fuzz_params:
                for entry in self.payloads:
                    payload = entry['payload']
                    verify = entry['verify']
                    
                    res = self.requester.get(url, params={param_name: payload})
                    if res is not None and verify in res.text:
                        results.append(self.build_finding(url, param_name, payload, "Reflected XSS (Blind URL Fuzzing)"))
                        break
        return results

    def build_finding(self, url, param, payload, type_str="Reflected XSS"):
        if "Stored" in type_str:
            base_imp = 8 # Account takeover / higher persistence impact
            complex_exp = False
        else:
            base_imp = 4 # UI injection limit / requires interaction
            complex_exp = True
            
        sev = calculate_severity(base_impact=base_imp, url=url, param=param, requires_auth=False, complex_exploit=complex_exp)
            
        return {
            'vulnerability': f'Cross-Site Scripting ({type_str})',
            'severity': sev,
            'url': url,
            'parameter': param,
            'payload': payload,
            'description': f"Detected {type_str} on {url} using payload: {payload}",
            'impact': "Attacker can execute arbitrary JavaScript in the victim's browser.",
            'reproduction': f"Submit the payload '{payload}' to {param}.",
            'remediation': "Context-aware HTML encode all user input and use a CSP."
        }
