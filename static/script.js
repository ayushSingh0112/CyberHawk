document.addEventListener('DOMContentLoaded', () => {
    const scanBtn = document.getElementById('startScanBtn');
    const urlInput = document.getElementById('targetUrl');
    const progressCircle = document.querySelector('.progress-circle');
    const progressValue = document.querySelector('.progress-value');
    const statusLabel = document.querySelector('.status-label');
    const tbody = document.getElementById('findingsBody');
    
    // Stats elements
    const statCrit = document.getElementById('statCrit');
    const statHigh = document.getElementById('statHigh');
    const statMed = document.getElementById('statMed');
    const statLow = document.getElementById('statLow');

    // Tab elements
    const tabButtons = document.querySelectorAll('nav.tabs button');
    const tabContents = document.querySelectorAll('.tab-content');
    
    // New tab tables
    const scansBody = document.getElementById('scansBody');
    const reportsBody = document.getElementById('reportsBody');
    const logsContainer = document.getElementById('logsContainer');
    const livePortsContainer = document.getElementById('livePortsContainer');

    const pauseScanBtn = document.getElementById('pauseScanBtn');
    const stopScanBtn = document.getElementById('stopScanBtn');

    let currentScanId = null;
    let pollInterval = null;
    let lastFindings = [];
    let lastStatusData = null;
    let currentSortPriority = null;

    // Stat card sort logic
    document.querySelectorAll('.stat-card').forEach(card => {
        card.style.cursor = 'pointer';
        card.addEventListener('click', () => {
            const isCrit = card.classList.contains('critical');
            const isHigh = card.classList.contains('high');
            const isMed = card.classList.contains('medium');
            const isLow = card.classList.contains('low');
            
            const targetSev = isCrit ? 'critical' : isHigh ? 'high' : isMed ? 'medium' : isLow ? 'low' : null;
            
            if (currentSortPriority === targetSev) {
                currentSortPriority = null;
            } else {
                currentSortPriority = targetSev;
            }
            
            document.querySelectorAll('.stat-card').forEach(c => {
                c.style.boxShadow = '';
            });
            if (currentSortPriority) {
                let color = 'white';
                if (isCrit) color = 'var(--sc-critical)';
                if (isHigh) color = 'var(--sc-high)';
                if (isMed) color = 'var(--sc-medium)';
                if (isLow) color = 'var(--sc-low)';
                card.style.boxShadow = `0 0 12px ${color}`;
            }
            
            if (lastFindings.length > 0) {
                updateFindingsUI(lastFindings, lastStatusData);
            }
        });
    });

    // Tab Switching Logic
    tabButtons.forEach(btn => {
        btn.addEventListener('click', () => {
            tabButtons.forEach(b => b.classList.remove('active'));
            tabContents.forEach(c => c.classList.remove('active'));
            
            btn.classList.add('active');
            document.getElementById(btn.getAttribute('data-target')).classList.add('active');
            
            // Auto-refresh data when tabs are clicked
            if (btn.getAttribute('data-target') === 'scans-tab') loadScans();
            if (btn.getAttribute('data-target') === 'reports-tab') loadReports();
            if (btn.getAttribute('data-target') === 'logs-tab') loadLogs();
        });
    });

    document.getElementById('scansSearch').addEventListener('input', loadScans);
    document.getElementById('reportsSearch').addEventListener('input', loadReports);

    document.getElementById('refreshScansBtn').addEventListener('click', loadScans);
    document.getElementById('refreshReportsBtn').addEventListener('click', loadReports);
    document.getElementById('refreshLogsBtn').addEventListener('click', loadLogs);
    
    const clearLogsBtn = document.getElementById('clearLogsBtn');
    if (clearLogsBtn) {
        clearLogsBtn.addEventListener('click', async (e) => {
            e.preventDefault();
            await fetch('/api/logs', { method: 'DELETE' });
            loadLogs();
        });
    }

    const exportLogsBtn = document.getElementById('exportLogsBtn');
    if (exportLogsBtn) {
        exportLogsBtn.addEventListener('click', async (e) => {
            e.preventDefault();
            try {
                const req = await fetch('/api/logs/export');
                const res = await req.json();
                if (res.status === 'success') {
                    alert(res.message);
                } else {
                    alert('Error exporting logs: ' + res.error);
                }
            } catch (err) {
                alert('Failed to export logs to the server.');
            }
        });
    }

    const triggerScan = async () => {
        const scanName = document.getElementById('scanName').value.trim();
        const targetIp = document.getElementById('targetIp').value.trim();
        const enablePortScanDoc = document.getElementById('enablePortScan');
        const targetPortInputDoc = document.getElementById('targetPort');
        const targetPort = enablePortScanDoc && enablePortScanDoc.checked ? targetPortInputDoc.value.trim() : "";
        
        if (!scanName) return alert('Please enter a Scan Name.');
        if (!targetIp) return alert('Please enter a Target IP or Domain.');
        
        const ipDomainRegex = /^(https?:\/\/)?([a-zA-Z0-9.-]+)(:[0-9]+)?(\/.*)?$/;
        if (!ipDomainRegex.test(targetIp)) {
            return alert('Invalid target format. Use an IP (e.g., 192.168.1.1) or URL (e.g., http://example.com/path).');
        }
        
        if (enablePortScanDoc && enablePortScanDoc.checked) {
            if (!targetPort) return alert('Please enter a port or range (e.g., 80,443 or 1-100).');
            if (!/^[\d\-,]+$/.test(targetPort)) return alert('Invalid port format. Only numbers, commas, and hyphens allowed.');
        }

        try {
            scanBtn.style.display = 'none';
            pauseScanBtn.style.display = 'inline-block';
            stopScanBtn.style.display = 'inline-block';
            
            statusLabel.innerHTML = '<span>INITIALIZING</span><span class="blinking-dots">...</span>';
            progressCircle.style.setProperty('--progress', '5%');
            progressValue.textContent = '0%';
            resetUI();
            
            const req = await fetch('/api/scan/start', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ scan_name: scanName, target_ip: targetIp, target_port: targetPort })
            });
            const res = await req.json();
            
            if (res.status === 'RUNNING') {
                currentScanId = res.scan_id;
                
                // Show assigned ID
                const idDisplay = document.getElementById('assignedScanIdDisplay');
                if(idDisplay) {
                    idDisplay.style.display = 'inline-block';
                    idDisplay.textContent = `ID: #${currentScanId}`;
                }
                
                startPolling();
            } else {
                alert('Error starting scan: ' + (res.error || 'Unknown error'));
                scanBtn.style.display = 'inline-block';
                scanBtn.disabled = false;
                pauseScanBtn.style.display = 'none';
                stopScanBtn.style.display = 'none';
            }
        } catch (e) {
            console.error(e);
            alert('Error connecting to backend.');
            scanBtn.style.display = 'inline-block';
            scanBtn.disabled = false;
            pauseScanBtn.style.display = 'none';
            stopScanBtn.style.display = 'none';
        }
    };

    scanBtn.addEventListener('click', triggerScan);

    const enablePortScanDoc = document.getElementById('enablePortScan');
    const targetPortInputDoc = document.getElementById('targetPort');
    if (enablePortScanDoc) {
        enablePortScanDoc.addEventListener('change', () => {
            targetPortInputDoc.style.display = enablePortScanDoc.checked ? 'inline-block' : 'none';
        });
    }

    document.getElementById('scheduleScanBtn').addEventListener('click', () => {
        const timeInput = document.getElementById('scheduleTime').value;
        if (!timeInput) return alert('Please select a time to schedule');
        const targetTime = new Date(timeInput).getTime();
        const delay = targetTime - Date.now();
        if (delay <= 0) return alert('Scheduled time must be in the future');
        alert(`Scan scheduled! It will run automatically in ${Math.round(delay/60000)} minutes.`);
        setTimeout(triggerScan, delay);
    });

    const sendAction = async (action) => {
        if(!currentScanId) return;
        await fetch(`/api/scan/${currentScanId}/action`, {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({action: action})
        });
        if (action === 'STOPPED') {
            scanBtn.style.display = 'inline-block';
            scanBtn.disabled = false;
            pauseScanBtn.style.display = 'none';
            stopScanBtn.style.display = 'none';
            statusLabel.textContent = 'STOPPED';
            clearInterval(pollInterval);
        }
        if (action === 'PAUSED') {
            pauseScanBtn.textContent = 'Resume';
            statusLabel.textContent = 'PAUSED';
        }
        if (action === 'RUNNING') {
            pauseScanBtn.textContent = 'Pause';
        }
    };

    pauseScanBtn.addEventListener('click', () => {
        if(pauseScanBtn.textContent === 'Pause') sendAction('PAUSED');
        else sendAction('RUNNING');
    });

    stopScanBtn.addEventListener('click', () => sendAction('STOPPED'));

    function startPolling() {
        if (pollInterval) clearInterval(pollInterval);
        
        pollInterval = setInterval(async () => {
            if (!currentScanId) return;
            
            try {
                // Fetch status
                const reqStatus = await fetch(`/api/scan/${currentScanId}`);
                const statusData = await reqStatus.json();
                
                // Update Progress
                const p = statusData.progress || 0;
                progressCircle.style.setProperty('--progress', `${p}%`);
                progressValue.textContent = `${p}%`;
                if (!['STOPPED', 'PAUSED'].includes(statusData.status)) {
                    if (statusData.status === 'RUNNING') {
                         statusLabel.innerHTML = `<span>RUNNING</span><span class="blinking-dots">...</span>`;
                    } else {
                         statusLabel.textContent = statusData.status;
                    }
                }
                
                // Fetch Findings
                const reqFindings = await fetch(`/api/scan/${currentScanId}/findings`);
                const findingsData = await reqFindings.json();
                updateFindingsUI(findingsData, statusData);
                
                // Fetch Ports
                try {
                    const reqPorts = await fetch(`/api/scan/${currentScanId}/ports`);
                    const portsData = await reqPorts.json();
                    
                    if (statusData.target_port === null || statusData.target_port === undefined) {
                        livePortsContainer.innerHTML = 'Port scanning skipped';
                    } else if(portsData.length > 0) {
                        livePortsContainer.innerHTML = portsData.map(p => `<div>Port ${p.port} (${p.service})</div>`).join('');
                    } else if (statusData.progress >= 15 || ['COMPLETED', 'FAILED'].includes(statusData.status)) {
                        livePortsContainer.innerHTML = 'No open ports found';
                    } else {
                        livePortsContainer.innerHTML = 'Scanning ports...';
                    }
                } catch(pe) { livePortsContainer.innerHTML = 'Error loading ports'; }
                
                if (statusData.status === 'COMPLETED' || statusData.status === 'FAILED') {
                    clearInterval(pollInterval);
                    scanBtn.style.display = 'inline-block';
                    scanBtn.disabled = false;
                    pauseScanBtn.style.display = 'none';
                    stopScanBtn.style.display = 'none';
                    if (statusLabel.textContent !== 'STOPPED' && statusLabel.textContent !== 'PAUSED') {
                        statusLabel.textContent = statusData.status === 'COMPLETED' ? 'SCAN COMPLETE' : 'SCAN FAILED';
                    }
                }
            } catch (e) {
                console.error("Polling error:", e);
            }
        }, 2000);
    }

    function resetUI() {
        tbody.innerHTML = '';
        statCrit.textContent = '0';
        statHigh.textContent = '0';
        statMed.textContent = '0';
        statLow.textContent = '0';
        const idDisplay = document.getElementById('assignedScanIdDisplay');
        if(idDisplay) { idDisplay.style.display = 'none'; idDisplay.textContent = ''; }
        document.getElementById('livePortsContainer').innerHTML = 'Awaiting scan...';
    }

    function updateFindingsUI(findings, statusData) {
        lastFindings = findings || [];
        lastStatusData = statusData;
        
        tbody.innerHTML = '';
        if (!findings || findings.length === 0) {
            if (statusData && (statusData.status === 'COMPLETED' || statusData.status === 'FAILED')) {
                tbody.innerHTML = '<tr><td colspan="4" style="text-align: center; color: #10b981; font-weight: bold; padding: 2rem;">No vulnerabilities found</td></tr>';
            } else {
                tbody.innerHTML = '<tr><td colspan="4" style="text-align: center; color: var(--text-secondary); padding: 2rem;">No active findings.</td></tr>';
            }
            statCrit.textContent = '0';
            statHigh.textContent = '0';
            statMed.textContent = '0';
            statLow.textContent = '0';
            return;
        }
        
        let counts = { critical: 0, high: 0, medium: 0, low: 0 };
        
        let displayFindings = [...findings];
        if (currentSortPriority) {
            displayFindings.sort((a, b) => {
                const aSev = (a.severity || 'info').toLowerCase();
                const bSev = (b.severity || 'info').toLowerCase();
                
                const aIsTarget = aSev.includes(currentSortPriority);
                const bIsTarget = bSev.includes(currentSortPriority);
                
                if (aIsTarget && !bIsTarget) return -1;
                if (!aIsTarget && bIsTarget) return 1;
                return 0; // maintain original order for rest
            });
        }
        
        displayFindings.forEach(f => {
            const sev = f.severity ? f.severity.toLowerCase() : 'info';
            
            if (counts[sev] !== undefined) counts[sev]++;
            else if (sev.includes('high')) counts['high']++;
            else if (sev.includes('medium')) counts['medium']++;
            
            const displaySev = sev.includes('high') ? 'high' : 
                               sev.includes('medium') ? 'medium' : 
                               sev.includes('critical') ? 'critical' : 'low';
            
            const tr = document.createElement('tr');
            tr.style.cursor = 'pointer';
            tr.innerHTML = `
                <td><span class="badge ${displaySev}">${f.severity}</span></td>
                <td>${f.vulnerability}</td>
                <td style="word-break: break-all;">${f.url}</td>
                <td>${f.parameter || '-'}</td>
            `;
            
            const detailTr = document.createElement('tr');
            detailTr.className = 'detail-row';
            
            const escapeHTML = (str) => {
                if (!str) return '-';
                return str.toString().replace(/[&<>'"]/g, tag => ({
                    '&': '&amp;',
                    '<': '&lt;',
                    '>': '&gt;',
                    "'": '&#39;',
                    '"': '&quot;'
                }[tag] || tag));
            };

            detailTr.innerHTML = `
                <td colspan="4">
                    <div class="detail-content">
                        <h4>Description</h4>
                        <p>${escapeHTML(f.description)}</p>
                        <h4>Payload</h4>
                        <div class="code-block">${escapeHTML(f.payload)}</div>
                        <h4>Impact</h4>
                        <p>${escapeHTML(f.impact)}</p>
                        <h4>Reproduction</h4>
                        <p>${escapeHTML(f.reproduction)}</p>
                        <h4>Remediation</h4>
                        <p>${escapeHTML(f.remediation)}</p>
                    </div>
                </td>
            `;
            
            tr.addEventListener('click', () => {
                detailTr.classList.toggle('open');
            });
            
            tbody.appendChild(tr);
            tbody.appendChild(detailTr);
        });
        
        statCrit.textContent = counts.critical;
        statHigh.textContent = counts.high;
        statMed.textContent = counts.medium;
        statLow.textContent = counts.low;
    }

    async function loadScans() {
        try {
            const req = await fetch('/api/scans');
            let scans = await req.json();
            
            // Search Filtering
            const query = document.getElementById('scansSearch').value.toLowerCase();
            if (query) {
                scans = scans.filter(s => 
                    s.scan_name?.toLowerCase().includes(query) || 
                    s.id.toString().includes(query)
                );
            }
            
            scansBody.innerHTML = '';
            
            if (scans.length === 0) {
                scansBody.innerHTML = '<tr><td colspan="6" style="text-align: center;">No scan history.</td></tr>';
                return;
            }
            
            scans.forEach(s => {
                const tr = document.createElement('tr');
                tr.innerHTML = `
                    <td>#${s.id}</td>
                    <td>${s.scan_name}</td>
                    <td>${s.target_ip}:${s.target_port || 80}</td>
                    <td>${s.status}</td>
                    <td>${s.progress}%</td>
                    <td>${new Date(s.start_time).toLocaleString()}</td>
                `;
                scansBody.appendChild(tr);
            });
        } catch (e) { console.error('Error loading scans', e); }
    }

    async function loadReports() {
        try {
            const req = await fetch('/api/scans');
            let scans = await req.json();
            
            // Search Filtering
            const query = document.getElementById('reportsSearch').value.toLowerCase();
            
            // Only show completed or failed checks for reports
            let reportable = scans.filter(s => s.status === 'COMPLETED' || s.status === 'FAILED');
            
            if (query) {
                reportable = reportable.filter(s => 
                    s.scan_name?.toLowerCase().includes(query) || 
                    s.id.toString().includes(query)
                );
            }

            reportsBody.innerHTML = '';
            
            if (reportable.length === 0) {
                reportsBody.innerHTML = '<tr><td colspan="6" style="text-align: center;">No completed reports available.</td></tr>';
                return;
            }
            
            reportable.forEach(s => {
                const tr = document.createElement('tr');
                tr.innerHTML = `
                    <td>#${s.id}</td>
                    <td>${s.scan_name}</td>
                    <td>${s.target_ip}:${s.target_port || 80}</td>
                    <td>${s.total_vulns}</td>
                    <td>${new Date(s.end_time || s.start_time).toLocaleString()}</td>
                    <td>
                        <div style="display: flex; gap: 0.5rem; align-items: center;">
                            <a href="/report/${s.id}" target="_blank" class="btn-report">View Report</a>
                            <a onclick="triggerDownload(${s.id})" title="Download PDF" style="display: flex; align-items: center; justify-content: center; color: var(--neon-purple); text-decoration: none; cursor: pointer; padding: 0.4rem;">
                                <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                                    <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"></path>
                                    <polyline points="7 10 12 15 17 10"></polyline>
                                    <line x1="12" y1="15" x2="12" y2="3"></line>
                                </svg>
                            </a>
                        </div>
                    </td>
                `;
                reportsBody.appendChild(tr);
            });
        } catch (e) { console.error('Error loading reports', e); }
    }

    async function loadLogs() {
        try {
            const req = await fetch('/api/logs');
            const logs = await req.json();
            if (logs.length === 0) {
                logsContainer.innerHTML = 'No logs available.';
                return;
            }
            
            logsContainer.innerHTML = logs.map(l => {
                const color = l.level === 'ERROR' ? 'var(--sc-critical)' : 
                              l.level === 'WARNING' ? 'var(--sc-medium)' : 'var(--text-secondary)';
                return `<div style="margin-bottom:4px;">
                    <span style="color:#64748b">[${new Date(l.timestamp).toLocaleTimeString()}]</span> 
                    <span style="color:${color}">[${l.level}]</span> 
                    <span style="color:#d1d5db">Scan #${l.scan_id}:</span> 
                    ${l.message}
                </div>`;
            }).join('');
        } catch (e) { console.error('Error loading logs', e); }
    }

    window.triggerDownload = function(id) {
        let iframe = document.getElementById('dl-iframe');
        if (!iframe) {
            iframe = document.createElement('iframe');
            iframe.id = 'dl-iframe';
            iframe.style.position = 'absolute';
            iframe.style.width = '1024px';
            iframe.style.height = '100vh';
            iframe.style.left = '-9999px';
            document.body.appendChild(iframe);
        }
        iframe.src = '/report/' + id + '?download=true';
    };
});
