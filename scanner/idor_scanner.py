import re
from .severity import calculate_severity

class IDORScanner:
    def __init__(self, requester):
        self.requester = requester
        self.uuid_pattern = re.compile(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$', re.I)
        self.hash_pattern = re.compile(r'^[0-9a-f]{32}$', re.I)
        
    def scan_params(self, params, original_cookies=None):
        results = []
        for method, url, param_name in params:
            # Vertical Privilege Escalation
            if 'admin' in url.lower():
                no_auth_res = self.requester.get(url) 
                if original_cookies:
                    auth_res = self.requester.session.get(url, cookies=original_cookies)
                    if no_auth_res is not None and auth_res is not None and len(no_auth_res.text) == len(auth_res.text) and "unauthorized" not in no_auth_res.text.lower():
                         sev = calculate_severity(base_impact=8, url=url, param=param_name, requires_auth=False, complex_exploit=False)
                         finding = self.build_priv_esc(url)
                         finding['severity'] = sev
                         results.append(finding)
                         
            # Multi-step Workflow
            if any(path in url.lower() for path in ['checkout', 'payment', 'reset', 'step']):
                 sev = calculate_severity(base_impact=5, url=url, param=param_name, requires_auth=True, complex_exploit=True)
                 results.append({
                     'vulnerability': 'Potential Multi-Step Workflow IDOR',
                     'severity': sev,
                     'url': url,
                     'parameter': param_name,
                     'payload': 'Manual Check Required',
                     'description': f"Endpoint '{url}' appears to be part of a multi-step workflow. Requires manual state manipulation testing.",
                     'impact': "State-jumping or bypassing payment/verification steps.",
                     'reproduction': "Review the endpoint flow manually.",
                     'remediation': "Enforce strict server-side state machine validation."
                 })

            # Base IDOR Testing
            if any(keyword in param_name.lower() for keyword in ['id', 'user', 'account', 'uuid', 'hash']):
                vuln = self.test_idor(url, param_name)
                if vuln:
                    results.append(vuln)
        return results

    def test_idor(self, url, param_name):
        baseline = self.requester.get(url, params={param_name: '1'})
        if not baseline: return None
        
        is_uuid_hash = False
        if "uuid" in param_name.lower():
             test_val = "00000000-0000-0000-0000-000000000001"
             is_uuid_hash = True
        elif "hash" in param_name.lower():
             test_val = "098f6bcd4621d373cade4e832627b4f6" # MD5 for 'test'
             is_uuid_hash = True
        else:
             test_val = '2'
             
        response = self.requester.get(url, params={param_name: test_val})
        if not response: return None
        
        if response.status_code == 200:
            if "unauthorized" not in response.text.lower() and "forbidden" not in response.text.lower():
                base_len = len(baseline.text)
                resp_len = len(response.text)
                diff_threshold = max(20, int(base_len * 0.05))
                if abs(base_len - resp_len) > diff_threshold:
                    sev = calculate_severity(base_impact=7, url=url, param=param_name, requires_auth=True, complex_exploit=is_uuid_hash)
                    finding = {
                        'vulnerability': 'Insecure Direct Object Reference (IDOR)',
                        'severity': sev,
                        'url': url,
                        'parameter': param_name,
                        'payload': f"{param_name}={test_val}",
                        'description': f"Parameter {param_name} was modified and retrieved a different valid response.",
                        'impact': "An attacker may access data belonging to other users.",
                        'reproduction': f"Change the {param_name} parameter value in the request to {test_val}.",
                        'remediation': "Implement proper authorization checks to ensure the logged-in user has permissions."
                    }
                    if is_uuid_hash:
                         finding['description'] += " (UUID/Hash detected - guessing is harder but still requires auth checks)"
                    return finding
        return None

    def build_priv_esc(self, url):
        return {
            'vulnerability': 'Vertical Privilege Escalation (Broken Access Control)',
            'severity': 'High',
            'url': url,
            'parameter': 'N/A',
            'payload': 'N/A',
            'description': f"Endpoint '{url}' containing 'admin' responds successfully without authentication.",
            'impact': "Attacker could access administrative functionality.",
            'reproduction': "Access the URL without an admin session.",
            'remediation': "Implement role-based access control (RBAC)."
        }
