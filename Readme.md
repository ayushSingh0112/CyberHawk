# Cyberhawk Web Scanner

Cyberhawk Web Scanner (internally designated *Cyberhawk Security Vanguard*) is a modern, full-stack, local-first web application vulnerability scanner and network infrastructure mapper. Combining concurrent crawling, TCP port analysis, and heuristic vulnerability detection engines, Cyberhawk offers real-time security telemetry and high-fidelity reporting via an interactive web interface.

---

## 🚀 Key Features

*   **Concurrent BFS Crawling:** Crawls target sites concurrently using a Breadth-First Search (BFS) thread pool (up to 15 workers). Extracts endpoints and inputs from both standard HTML elements (BeautifulSoup) and inline/external Javascript source code (regex-based heuristics).
*   **Targeted Port Scanning:** Sweeps TCP ports in parallel using asynchronous socket connections. Automatically attempts banner grabbing (`HEAD / HTTP/1.0`) to resolve server headers and guess running service versions (e.g., SSH, FTP, HTTP, MySQL).
*   **Vulnerability Detection Engines:**
    *   **SQL Injection (SQLi):** Audits parameters, form submissions, JSON requests, and HTTP headers (User-Agent/Referer) using Error-based signature matching, Time-based latency checks, and Boolean-Blind state evaluation.
    *   **Cross-Site Scripting (XSS):** Identifies Reflected XSS in query parameters, Stored XSS in form actions, DOM-based sinks (e.g., `innerHTML =`, `document.write(`, `eval(`), and Cookie parameters.
    *   **Insecure Direct Object Reference (IDOR):** Scans for vertical privilege escalation (Broken Access Control) on admin routes and swaps resource parameters (supporting MD5 hashes, UUID schemas, and standard integer scales).
*   **Intelligent Traffic Telemetry & Throttling:**
    *   **Payload Deduplication:** Generates MD5 signatures of HTTP requests to bypass redundant requests and save network bandwidth.
    *   **Adaptive Server Throttling:** Detects target server strain (`429 Too Many Requests`, `503 Service Unavailable` or high average latency) and throttles scan concurrency dynamically.
*   **Advanced Severity Classification:** Utilizes a rule-based engine scoring severity (Critical, High, Medium, Low) based on vulnerability impact, exploit complexity, authentication limits, and endpoint sensitivity keywords (e.g., `pay`, `checkout`, `admin`, `user`).
*   **Cyberpunk-Themed Web Panel:** Features real-time conic progress tracking, numeric indicators, system log terminal simulation, and multi-parameter filtering.
*   **One-Click Executive Reporting:** Downloads detailed, print-ready PDF reports utilizing off-screen iframe compiling and `html2pdf.js` page breaks.

---

## 📁 Directory Structure

```text
scanner_project/
├── app.py                # Main Flask Backend Orchestrator & API Router
├── database.py           # SQLite Database Init & Data Access Layer (DAL)
├── database.db           # Local SQLite Database File (Created automatically)
├── scanner/
│   ├── __init__.py       # Scanner Module Initialization
│   ├── engine.py         # Threaded Scan Pipeline Orchestrator
│   ├── crawler.py        # Multi-Threaded Concurrent BFS Web Crawler
│   ├── requester.py      # Custom Traffic Telemetry HTTP Client (Deduplication & Auto-Throttle)
│   ├── port_scanner.py   # Multi-Threaded TCP Port Scanner & Banner Grabber
│   ├── sqli_scanner.py   # SQL Injection Vulnerability Auditor
│   ├── xss_scanner.py    # Cross-Site Scripting (XSS) Auditor
│   ├── idor_scanner.py   # Insecure Direct Object Reference (IDOR) Auditor
│   ├── severity.py       # Rule-Based Severity Scoring Engine
│   └── report.py         # Reporting metadata compiler
├── static/
│   ├── style.css         # Dark CSS variables, panel styling, and keyframes
│   ├── script.js         # Frontend controllers, SSE polling, and PDF generator
│   └── new_hawk.png      # Cyberhawk Application Brand Asset
├── templates/
│   ├── index.html        # Main dashboard panel template
│   └── report.html       # Print-ready reporting template (Jinja + Google Charts)
└── Exports/
    └── cyberhawk_logs.txt # Text log export files (Generated automatically)
```

---

## 🛠️ Installation & Setup

### Prerequisites
*   Python 3.8 or higher
*   `pip` package manager

### 1. Clone & Navigate to Project Directory
```bash
git clone <repository-url>
cd scanner_project
```

### 2. Set Up Virtual Environment (Recommended)
```bash
# Create Virtual Environment
python3 -m venv venv

# Activate on Linux/macOS
source venv/bin/activate

# Activate on Windows
venv\Scripts\activate
```

### 3. Install Dependencies
Install the required packages directly using pip:
```bash
pip install Flask requests beautifulsoup4 urllib3
```

### 4. Initialize Database & Start Backend
Run `app.py` to automatically initialize the SQLite tables and boot up the Flask web server:
```bash
python app.py
```
By default, the server runs on localhost:
```text
 * Serving Flask app 'app'
 * Debug mode: on
 * Running on http://127.0.0.1:5000
```

---

## 🖥️ Usage Guide

1.  **Access the Dashboard:** Open your browser and navigate to `http://127.0.0.1:5000`.
2.  **Configure Scan Targets:**
    *   Enter a **Scan Name** (e.g., `Staging Security Audit`).
    *   Enter a **Target IP or Domain** (e.g., `http://testphp.vulnweb.com`).
    *   Toggle **Scan Ports** if you wish to run infrastructure network reconnaissance. Specify port ranges (e.g., `80,443,8080` or `1-1000`).
3.  **Run the Scan:** Click **Start**. The dashboard will transition into a running state, updating progress gauges and streaming logs to the bottom log terminal.
4.  **Analyze Findings:** As vulnerabilities are found, they populate the findings table. Click on any vulnerability row to expand the drawer and inspect descriptions, target parameters, exploitation payloads, impact statements, and remediation code.
5.  **Audit Logs:** Click the **Logs** tab to view raw engine logs, or click **Export Logs (TXT)** to save them to the `Exports/` folder.
6.  **Export PDF Reports:** Go to the **Reports** tab, identify your completed scan, and click the download icon to save a high-resolution PDF report of the findings.

---

## 🛡️ Disclaimer & Safety
> [!WARNING]
> This software is intended for **authorized security testing and educational purposes only**. Scanning targets without explicit, written permission from the owner is illegal and unethical. The authors and developers of this software assume no liability for misuse, system damage, or data loss caused by unauthorized usage. Use responsibly.
