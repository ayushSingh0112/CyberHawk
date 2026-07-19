import logging
from .crawler import Crawler
from .requester import Requester
from .idor_scanner import IDORScanner
from .sqli_scanner import SQLIScanner
from .xss_scanner import XSSScanner
from .port_scanner import PortScanner
from database import update_scan_status, add_finding, add_log, add_open_port, get_scan
import urllib.parse

def run_scan_pipeline(scan_id, target_url):
    """
    Executes the full scanning pipeline.
    """
    try:
        update_scan_status(scan_id, 'RUNNING', 5)
        add_log(scan_id, 'INFO', f'Started scan pipeline for {target_url}')
        
        parsed_url = urllib.parse.urlparse(target_url)
        target_ip = parsed_url.hostname or target_url

        # 0. Port Scanning Phase
        scan_record = get_scan(scan_id)
        if scan_record.get('target_port') is not None:
            target_port_str = scan_record.get('target_port') if scan_record.get('target_port') else ""
            add_log(scan_id, 'INFO', f'Initializing Port Scanner against {target_ip}')
            port_scanner = PortScanner(target_ip, str(target_port_str))
            open_ports = port_scanner.run()
            add_log(scan_id, 'INFO', f'Port Scan complete. Found {len(open_ports)} open ports.')
            
            for p in open_ports:
                add_open_port(scan_id, p['port'], p['service'], p['version'])
        else:
            add_log(scan_id, 'INFO', 'Port scanning skipped by user.')
        
        update_scan_status(scan_id, 'RUNNING', 15)

        # 1. Setup Session & Authenticated Requester Component
        req = Requester()
        
        def log_telemetry(phase):
            stats = req.get_stats()
            msg = f"[{phase} Network Trace] Active RPS: {stats['rps']} | Requests Sent: {stats['requests']} | Avg Latency: {stats['avg_time_ms']}ms | Noisy Payloads Blocked: {stats['duplicates_skipped']} | Bandwidth D/L: {stats['mb_recv']}MB | Dynamic Throttle: {stats['throttle']}s"
            if stats['status_429'] > 0 or stats['status_503'] > 0:
                msg += f" | 🚨 Rate Limited (429: {stats['status_429']}, 503: {stats['status_503']}). Enforcing aggressive throttling."
            add_log(scan_id, 'INFO', msg)
        
        # 2. Crawl Phase
        add_log(scan_id, 'INFO', 'Booting Layered Crawling Engine. Allocating ThreadPoolExecutor with 15 concurrent asynchronous workers. Maximum boundary scope locked at Depth 10 and 300 total pages. Engaging Primary DOM extraction (BeautifulSoup) alongside Secondary Javascript heuristic parsing (Regex).')
        crawler = Crawler(target_url, max_depth=10, max_pages=300, max_threads=15, requester=req)
        crawl_results = crawler.run()
        
        if get_scan(scan_id)['status'] == 'STOPPED':
            add_log(scan_id, 'WARNING', 'Scan cancelled by user.')
            return
            
        add_log(scan_id, 'INFO', f"Crawler finished: Found {len(crawl_results['endpoints'])} endpoints, {len(crawl_results['forms'])} forms, {len(crawl_results['params'])} params.")
        log_telemetry('Crawl Engine')
        update_scan_status(scan_id, 'RUNNING', 30)
        
        # 3. Setup Scanners with shared Authenticated Session
        idor_scanner = IDORScanner(req)
        sqli_scanner = SQLIScanner(req)
        xss_scanner = XSSScanner(req)
        
        all_findings = []
        
        # 3. IDOR Scan
        add_log(scan_id, 'INFO', 'Initiating Insecure Direct Object Reference (IDOR) heuristics across structural parameters. Executing baseline length deviation algorithms and testing vertical privilege escalation constraints using randomized UUID/Hash injection boundaries.')
        idor_findings = idor_scanner.scan_params(crawl_results['params'])
        for finding in idor_findings:
            if finding:
                all_findings.append(finding)
                add_log(scan_id, 'WARNING', f"Found {finding['vulnerability']} on {finding['url']}")
        log_telemetry('IDOR Heuristics')
        update_scan_status(scan_id, 'RUNNING', 50)
        
        if get_scan(scan_id)['status'] == 'STOPPED': return
        
        # 4. SQLi Scan
        add_log(scan_id, 'INFO', f'Deploying SQL Injection testing suite against {len(crawl_results["forms"])} discovered forms and {len(crawl_results["params"])} parameters. Utilizing Time-Based delays, Out-of-Band (OOB) constraints, Boolean-blind mathematical tolerance thresholds, and Header-based logic (User-Agent/Referer).')
        sqli_findings_forms = sqli_scanner.scan_forms(crawl_results['forms'])
        sqli_findings_params = sqli_scanner.scan_params(crawl_results['params'])
        sqli_findings_blind = sqli_scanner.scan_blind_params(crawl_results['endpoints'])
        for finding in sqli_findings_forms + sqli_findings_params + sqli_findings_blind:
            if finding:
                all_findings.append(finding)
                add_log(scan_id, 'WARNING', f"Found {finding['vulnerability']} on {finding['url']}")
        log_telemetry('SQLi Engine')
        update_scan_status(scan_id, 'RUNNING', 70)
        
        if get_scan(scan_id)['status'] == 'STOPPED': return
        
        # 5. XSS Scan
        add_log(scan_id, 'INFO', 'Firing Cross-Site Scripting (XSS) payload matrices targeting form action sinks, URL parameter reflections, and Active Cookie sessions. Tracking payload reflection states to actively simulate Stored XSS persistence.')
        xss_findings_params = xss_scanner.scan_params(crawl_results['params'])
        xss_findings_forms = xss_scanner.scan_forms(crawl_results['forms'])
        xss_findings_cookies = xss_scanner.scan_cookies(target_url)
        xss_findings_blind = xss_scanner.scan_blind_urls(crawl_results['endpoints'])
        for finding in xss_findings_params + xss_findings_forms + xss_findings_cookies + xss_findings_blind:
            if finding:
                all_findings.append(finding)
                add_log(scan_id, 'WARNING', f"Found {finding['vulnerability']} on {finding['url']}")
        log_telemetry('XSS Engine')
        update_scan_status(scan_id, 'RUNNING', 90)
        
        # 6. Save Findings
        add_log(scan_id, 'INFO', 'Processing and merging findings...')
        grouped_findings = {}
        for f in all_findings:
            key = (f.get('vulnerability'), f.get('url'), f.get('parameter'))
            if key not in grouped_findings:
                grouped_findings[key] = f
                grouped_findings[key]['payloads'] = [f.get('payload')] if f.get('payload') else []
            else:
                if f.get('payload') and f['payload'] not in grouped_findings[key]['payloads']:
                    grouped_findings[key]['payloads'].append(f['payload'])
                    
        for key, f in grouped_findings.items():
            if 'payloads' in f and f['payloads']:
                if len(f['payloads']) > 1:
                    f['payload'] = "\\n".join(f['payloads'][:5])
                    if len(f['payloads']) > 5:
                        f['payload'] += f"\\n...and {len(f['payloads'])-5} more payloads."
                    # Adjust description dynamically to reflect multiple payloads
                    desc_parts = f['description'].split('using payload:')
                    if len(desc_parts) == 2:
                        f['description'] = desc_parts[0] + f"using {len(f['payloads'])} diverse payloads."
                    
                    f['reproduction'] = f"Inject any of the listed payloads into the parameter {f['parameter']}. For example: {f['payloads'][0]}"
                else:
                    f['payload'] = f['payloads'][0]
            add_finding(scan_id, f)
                
        update_scan_status(scan_id, 'COMPLETED', 100)
        add_log(scan_id, 'INFO', 'Scan pipeline completed successfully.')
    except Exception as e:
        print(f"Error during scan {scan_id}: {e}")
        add_log(scan_id, 'ERROR', f'Scan failed: {str(e)}')
        update_scan_status(scan_id, 'FAILED', 0)
