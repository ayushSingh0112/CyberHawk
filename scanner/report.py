import json
from database import get_findings, get_scan

class ReportGenerator:
    """
    Generates structured JSON reports for a given scan ID.
    """
    @staticmethod
    def generate_json_report(scan_id):
        scan_info = get_scan(scan_id)
        findings = get_findings(scan_id)
        
        if not scan_info:
            return None
            
        report = {
            'scan_id': scan_info['id'],
            'target_url': scan_info['target_url'],
            'status': scan_info['status'],
            'start_time': scan_info['start_time'],
            'end_time': scan_info['end_time'],
            'total_vulns': scan_info['total_vulns'],
            'findings': findings
        }
        
        return json.dumps(report, indent=4)
