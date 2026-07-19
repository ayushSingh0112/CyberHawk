import os
import threading
import urllib.parse
import requests
import urllib3
from flask import Flask, render_template, request, jsonify, Response
from database import init_db, create_scan, update_scan_status, get_scan, get_findings, get_all_scans, get_logs, get_open_ports, get_db_connection

# Suppress annoying InsecureRequestWarnings globally in the API
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

app = Flask(__name__)

# Initialize database
init_db()

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/scan/start', methods=['POST'])
def start_scan():
    data = request.json
    scan_name = data.get('scan_name', 'Unnamed Scan')
    target_ip = data.get('target_ip')
    target_port = data.get('target_port', '')
    
    if not target_ip:
        return jsonify({'error': 'target_ip is required'}), 400
    
    # Construct URL for web crawler
    if target_ip.startswith('http://') or target_ip.startswith('https://'):
        target_url = target_ip
    else:
        target_url = f"http://{target_ip}"
        
    parsed = urllib.parse.urlparse(target_url)
    target_ip_clean = parsed.hostname or target_ip
    
    # Reachability check - Augmented with Headers to prevent WAF drops
    try:
        headers = {'User-Agent': 'Cyberhawk Security Vanguard v1.1'}
        response = requests.get(target_url, timeout=10, verify=False, headers=headers)
        # We don't check status_code here, as long as it routes we can scan it (even if it's 403/401)
    except requests.exceptions.RequestException as e:
        return jsonify({'error': f'Target is unreachable or offline. Connection Failed: {str(e)}'}), 400
        
    db_port = target_port if target_port else None
    
    scan_id = create_scan(scan_name, target_ip_clean, db_port, target_url)
    
    from scanner.engine import run_scan_pipeline
    threading.Thread(target=run_scan_pipeline, args=(scan_id, target_url)).start()
    
    return jsonify({'scan_id': scan_id, 'status': 'RUNNING', 'message': 'Scan started successfully'}), 201

@app.route('/api/scan/<int:scan_id>')
def scan_status(scan_id):
    scan = get_scan(scan_id)
    if scan:
        return jsonify(dict(scan))
    return jsonify({'error': 'Scan not found'}), 404

@app.route('/api/scan/<int:scan_id>/findings')
def scan_findings(scan_id):
    findings = get_findings(scan_id)
    return jsonify(findings)

@app.route('/api/scan/<int:scan_id>/ports')
def scan_ports(scan_id):
    ports = get_open_ports(scan_id)
    return jsonify(ports)

@app.route('/api/scan/<int:scan_id>/action', methods=['POST'])
def scan_action(scan_id):
    action = request.json.get('action')
    if action in ['PAUSED', 'STOPPED', 'RUNNING']:
        update_scan_status(scan_id, action, None) # Don't change progress
        return jsonify({'status': 'success', 'action': action})
    return jsonify({'error': 'Invalid action'}), 400

@app.route('/api/scans')
def get_scans_history():
    scans = get_all_scans()
    return jsonify(scans)

@app.route('/api/logs', methods=['GET', 'DELETE'])
def manage_logs():
    if request.method == 'DELETE':
        conn = get_db_connection()
        conn.execute('DELETE FROM logs')
        conn.commit()
        conn.close()
        return jsonify({'status': 'cleared'})
    logs = get_logs()
    return jsonify(logs)

@app.route('/api/logs/export')
def export_logs():
    logs = get_logs()
    log_text = "\n".join([f"[{l['timestamp']}] [{l['level']}] Scan #{l['scan_id']}: {l['message']}" for l in logs])
    export_dir = 'Exports'
    os.makedirs(export_dir, exist_ok=True)
    export_path = os.path.join(export_dir, 'cyberhawk_logs.txt')
    try:
        with open(export_path, 'w', encoding='utf-8') as f:
            f.write(log_text)
        return jsonify({'status': 'success', 'message': f"Logs successfully saved to {export_dir} folder."})
    except Exception as e:
        return jsonify({'status': 'error', 'error': str(e)}), 500

@app.route('/report/<int:scan_id>')
def view_report(scan_id):
    scan = get_scan(scan_id)
    findings = get_findings(scan_id)
    ports = get_open_ports(scan_id)
    if not scan:
        return "Scan not found", 404
    return render_template('report.html', scan=scan, findings=findings, ports=ports)

if __name__ == '__main__':

    # for running in local network
    # app.run(debug=True, port=5000, host='0.0.0.0') 
    
    # for ruuning in localhost
    app.run(debug=True, port=5000)

