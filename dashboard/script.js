// Point directly to your Kali Linux IP
const BACKEND_URL = "http://10.206.31.192:5000"; 

let allFetchedAlerts = []; // Global memory store for all fetched SIEM alerts

document.addEventListener('DOMContentLoaded', () => {
    fetchAlerts();
    setInterval(fetchAlerts, 5000); // Poll API every 5 seconds
    initReportTimePickers(); // Initialize date-time pickers default
});

// View Navigation Switcher
function showSection(sectionId) {
    document.querySelectorAll('.content-section').forEach(el => el.classList.add('hidden'));
    
    const target = document.getElementById(`${sectionId}-section`);
    if (target) {
        target.classList.remove('hidden');
    }

    if (sectionId === 'blocked-ips') {
        fetchBlockedIps();
    }
}

// -------------------------------------------------------------
// HELPER: Convert Date Object to Local ISO String (YYYY-MM-THH:mm)
// Prevents UTC shift (e.g. IST +5:30 showing as 5 hours behind)
// -------------------------------------------------------------
function toLocalDatetimeInputValue(date) {
    const tzOffset = date.getTimezoneOffset() * 60000; // Offset in milliseconds
    const localISOTime = (new Date(date.getTime() - tzOffset)).toISOString().slice(0, 16);
    return localISOTime;
}

// -------------------------------------------------------------
// 1. Fetch & Render Live Ingestion Terminal Alerts
// -------------------------------------------------------------
async function fetchAlerts() {
    const tbody = document.getElementById('logs-tbody');
    if (!tbody) return;

    try {
        const response = await fetch(`${BACKEND_URL}/api/wazuh/alerts`);
        if (!response.ok) throw new Error(`HTTP Error: ${response.status}`);

        const data = await response.json();
        const hits = data.hits?.hits || (Array.isArray(data) ? data : []);
        
        allFetchedAlerts = hits; // Store globally for filtering and reports

        let criticalCount = 0;
        let warningCount = 0;
        const filterVal = document.getElementById('severity-filter')?.value || 'all';

        if (hits.length === 0) {
            tbody.innerHTML = `<tr><td colspan="5" class="text-center py-6 text-gray-500 font-mono">🟢 Connected to Kali Node (10.206.31.192), awaiting security events...</td></tr>`;
            return;
        }

        const filteredHits = hits.filter(hit => {
            const level = hit._source?.rule?.level || 0;
            if (filterVal === 'critical') return level >= 8;
            if (filterVal === 'warning') return level >= 5 && level < 8;
            return true;
        });

        tbody.innerHTML = filteredHits.map(hit => {
            const src = hit._source || {};
            const level = src.rule?.level || 0;
            
            // Extract IP safely across system logs, PAM, Rootcheck, and SSH events
            const srcIp = src.data?.srcip || src.data?.src_ip || src.agent?.ip || 'N/A';
            const ruleId = src.rule?.id || '0000';
            const description = src.rule?.description || 'Operational Event';
            const timestamp = src.timestamp || src['@timestamp'] || new Date().toISOString();

            if (level >= 8) criticalCount++;
            else if (level >= 5) warningCount++;

            let badgeStyle = "bg-gray-800 text-gray-300 border border-gray-700";
            if (level >= 8) badgeStyle = "bg-red-900/60 text-red-300 border border-red-700";
            else if (level >= 5) badgeStyle = "bg-yellow-900/60 text-yellow-300 border border-yellow-700";

            return `
                <tr class="hover:bg-gray-800/40 transition-colors border-b border-gray-800">
                    <td class="py-3 px-4 text-gray-400 font-mono text-xs">${new Date(timestamp).toLocaleString()}</td>
                    <td class="py-3 px-4">
                        <span class="px-2 py-0.5 rounded text-xs font-semibold ${badgeStyle}">Level ${level}</span>
                    </td>
                    <td class="py-3 px-4 text-gray-200">
                        <span class="font-mono text-blue-400 mr-2">[${ruleId}]</span>${description}
                    </td>
                    <td class="py-3 px-4 font-mono ${srcIp !== 'N/A' && srcIp !== '000' ? 'text-red-400 font-bold' : 'text-gray-500'}">${srcIp}</td>
                    <td class="py-3 px-4 text-center">
                        ${(srcIp !== 'N/A' && srcIp !== '127.0.0.1' && srcIp !== '000') ? `
                            <button onclick="blockAttackerIp('${srcIp}')" class="bg-red-600/20 hover:bg-red-600 text-red-400 hover:text-white border border-red-500/40 px-3 py-1 rounded text-xs transition-all">
                                🚫 Block IP
                            </button>
                        ` : '<span class="text-gray-600">-</span>'}
                    </td>
                </tr>
            `;
        }).join('');

        document.getElementById('kpi-critical').innerText = criticalCount;
        document.getElementById('kpi-warnings').innerText = warningCount;

    } catch (err) {
        console.error("Alert Sync Error:", err);
        tbody.innerHTML = `
            <tr>
                <td colspan="5" class="text-center py-6 text-red-400 font-mono">
                    ❌ Connection Failed to ${BACKEND_URL}. Enable "Insecure Content" in Chrome Site Settings.
                </td>
            </tr>`;
    }
}

// -------------------------------------------------------------
// 2. Fetch All Currently Blocked IPs
// -------------------------------------------------------------
async function fetchBlockedIps() {
    const tbody = document.getElementById('blocked-ips-tbody');
    if (!tbody) return;

    try {
        const response = await fetch(`${BACKEND_URL}/api/wazuh/blocked-ips`);
        const data = await response.json();

        const blockedList = data.blockedIps || (Array.isArray(data) ? data : []);

        if (blockedList.length === 0) {
            tbody.innerHTML = `
                <tr>
                    <td colspan="5" class="text-center py-8 text-gray-500 font-mono">
                        🟢 No active IP drop rules in host firewall policy.
                    </td>
                </tr>`;
            return;
        }

        tbody.innerHTML = blockedList.map(item => `
            <tr class="hover:bg-gray-800/50 transition-colors border-b border-gray-800">
                <td class="py-3 px-4 font-mono font-bold text-red-400">${item.ip}</td>
                <td class="py-3 px-4 text-gray-400 text-xs">${new Date(item.blockedAt || item.timestamp || Date.now()).toLocaleString()}</td>
                <td class="py-3 px-4">
                    <span class="bg-red-900/40 text-red-400 border border-red-700/50 text-xs font-semibold px-2.5 py-1 rounded-full">
                        ${item.status || 'BLOCKED'}
                    </span>
                </td>
                <td class="py-3 px-4 text-gray-400 text-xs">${item.reason || 'Malicious Threat Vector'}</td>
                <td class="py-3 px-4 text-center">
                    <button onclick="unblockAttackerIp('${item.ip}')" class="bg-emerald-600/20 hover:bg-emerald-600 text-emerald-400 hover:text-white border border-emerald-500/40 px-3 py-1 rounded text-xs font-semibold transition-all">
                        🔓 Unblock IP
                    </button>
                </td>
            </tr>
        `).join('');

    } catch (err) {
        console.error("Error fetching blocked IPs:", err);
    }
}

// -------------------------------------------------------------
// 3. Active Response: Block & Unblock Actions
// -------------------------------------------------------------
async function blockAttackerIp(ipAddress) {
    if (!ipAddress || ipAddress === 'N/A' || ipAddress === '127.0.0.1') {
        alert("Invalid target IP address.");
        return;
    }

    if (!confirm(`Are you sure you want to block IP address ${ipAddress} in real-time?`)) return;

    try {
        const response = await fetch(`${BACKEND_URL}/api/wazuh/block-ip`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ targetIp: ipAddress, ip: ipAddress })
        });

        const result = await response.json();

        if (response.ok) {
            alert(`🚨 ACTIVE RESPONSE TRIGGERED!\n\nTarget IP ${ipAddress} blocked on host firewall.`);
            fetchBlockedIps();
        } else {
            alert(`Failed to block IP: ${result.error || result.message}`);
        }
    } catch (err) {
        alert("Could not reach Express backend server.");
    }
}

async function unblockAttackerIp(ipAddress) {
    if (!confirm(`Are you sure you want to unblock IP address ${ipAddress}?`)) return;

    try {
        const response = await fetch(`${BACKEND_URL}/api/wazuh/unblock-ip`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ targetIp: ipAddress, ip: ipAddress })
        });

        const result = await response.json();

        if (response.ok) {
            alert(`✅ SUCCESS:\n\nIP address ${ipAddress} unblocked from host firewall.`);
            fetchBlockedIps();
        } else {
            alert(`Failed to unblock IP: ${result.error || result.message}`);
        }
    } catch (err) {
        alert("Could not reach Express backend server.");
    }
}

// -------------------------------------------------------------
// 4. Compliance Report Time-Slot Helpers (Fixed Timezone Bug)
// -------------------------------------------------------------
function initReportTimePickers() {
    const fromInput = document.getElementById('report-from-date');
    const toInput = document.getElementById('report-to-date');
    if (!fromInput || !toInput) return;

    const now = new Date();
    const twentyFourHoursAgo = new Date(now.getTime() - (24 * 60 * 60 * 1000));

    fromInput.value = toLocalDatetimeInputValue(twentyFourHoursAgo);
    toInput.value = toLocalDatetimeInputValue(now);
}

function setReportTimePreset(preset) {
    const fromInput = document.getElementById('report-from-date');
    const toInput = document.getElementById('report-to-date');
    if (!fromInput || !toInput) return;

    const now = new Date();
    let fromDate = new Date();

    if (preset === '1h') {
        fromDate = new Date(now.getTime() - (1 * 60 * 60 * 1000));
    } else if (preset === '24h') {
        fromDate = new Date(now.getTime() - (24 * 60 * 60 * 1000));
    } else if (preset === '7d') {
        fromDate = new Date(now.getTime() - (7 * 24 * 60 * 60 * 1000));
    } else if (preset === 'all') {
        fromDate = new Date(0); // Epoch start
    }

    fromInput.value = preset === 'all' ? '1970-01-01T00:00' : toLocalDatetimeInputValue(fromDate);
    toInput.value = toLocalDatetimeInputValue(now);

    const preview = document.getElementById('report-window-preview');
    if (preview) preview.innerText = `Window: ${preset.toUpperCase()} (${fromInput.value.replace('T', ' ')} to ${toInput.value.replace('T', ' ')})`;
}

// -------------------------------------------------------------
// 5. Enterprise Professional PDF Audit Report Generator
// -------------------------------------------------------------
function generatePDFReport() {
    if (!window.jspdf) {
        alert("jsPDF library loading... please try again in a moment.");
        return;
    }

    const { jsPDF } = window.jspdf;
    const doc = new jsPDF();

    const titleInput = document.getElementById('report-title')?.value || 'Security Incident Audit Summary';
    const fromVal = document.getElementById('report-from-date')?.value;
    const toVal = document.getElementById('report-to-date')?.value;

    const fromDate = fromVal ? new Date(fromVal) : new Date(0);
    const toDate = toVal ? new Date(toVal) : new Date();

    // 1. Filter Alerts based on Selected Time Window
    const filteredAlerts = allFetchedAlerts.filter(hit => {
        const src = hit._source || {};
        const rawTime = src.timestamp || src['@timestamp'] || new Date().toISOString();
        const eventTime = new Date(rawTime);
        return eventTime >= fromDate && eventTime <= toDate;
    });

    // 2. Compute Incident Metrics
    let criticalCount = 0;
    let warningCount = 0;
    let lowCount = 0;
    const criticalSourceIpsMap = new Map();

    filteredAlerts.forEach(hit => {
        const src = hit._source || {};
        const level = src.rule?.level || 0;
        const srcIp = src.data?.srcip || src.data?.src_ip || src.agent?.ip || 'N/A';
        const ruleDesc = src.rule?.description || 'Security Anomaly';

        if (level >= 8) {
            criticalCount++;
            if (srcIp !== 'N/A' && srcIp !== '127.0.0.1' && srcIp !== '000') {
                const existing = criticalSourceIpsMap.get(srcIp) || { count: 0, reason: ruleDesc };
                existing.count++;
                criticalSourceIpsMap.set(srcIp, existing);
            }
        } else if (level >= 5) {
            warningCount++;
        } else {
            lowCount++;
        }
    });

    // ---------------------------------------------------------
    // PAGE 1: BRANDED HEADER & EXECUTIVE SUMMARY
    // ---------------------------------------------------------

    // Top Dark Blue Header Banner
    doc.setFillColor(15, 23, 42); // #0f172a
    doc.rect(0, 0, 210, 38, 'F');

    // Title & Subtitle inside Header
    doc.setTextColor(255, 255, 255);
    doc.setFont("helvetica", "bold");
    doc.setFontSize(16);
    doc.text("SEC SAFELY - SOC AUDIT REPORT", 14, 18);

    doc.setFontSize(9);
    doc.setFont("helvetica", "normal");
    doc.setTextColor(180, 200, 230);
    doc.text(titleInput.toUpperCase(), 14, 26);
    doc.text(`SIEM Node IP: 10.206.31.192 | Generated: ${new Date().toLocaleString()}`, 14, 32);

    // Decorative Accent Line
    doc.setFillColor(16, 185, 129); // Emerald Line
    doc.rect(0, 38, 210, 2, 'F');

    let currentY = 50;

    // Report Metadata Box
    doc.setDrawColor(226, 232, 240);
    doc.setFillColor(248, 250, 252);
    doc.roundedRect(14, currentY, 182, 22, 3, 3, 'FD');

    doc.setTextColor(51, 65, 85);
    doc.setFontSize(8.5);
    doc.setFont("helvetica", "bold");
    doc.text("AUDIT TIME WINDOW:", 18, currentY + 8);
    doc.setFont("helvetica", "normal");
    doc.text(`${fromDate.toLocaleString()}  TO  ${toDate.toLocaleString()}`, 60, currentY + 8);

    doc.setFont("helvetica", "bold");
    doc.text("SECURITY CLASSIFICATION:", 18, currentY + 16);
    doc.setFont("helvetica", "normal");
    doc.setTextColor(225, 29, 72); // Red Accent
    doc.text("CONFIDENTIAL - INTERNAL SOC AUDIT ONLY", 70, currentY + 16);

    currentY += 30;

    // Executive Summary Section
    doc.setTextColor(15, 23, 42);
    doc.setFont("helvetica", "bold");
    doc.setFontSize(12);
    doc.text("1. Executive Threat Breakdown", 14, currentY);

    currentY += 8;

    // 4 Metrics Grid Boxes
    const boxWidth = 42;
    const boxHeight = 22;

    // Box 1: Critical
    doc.setFillColor(254, 242, 242);
    doc.setDrawColor(248, 113, 113);
    doc.roundedRect(14, currentY, boxWidth, boxHeight, 2, 2, 'FD');
    doc.setTextColor(153, 27, 27);
    doc.setFontSize(7.5);
    doc.setFont("helvetica", "bold");
    doc.text("CRITICAL (L8+)", 18, currentY + 7);
    doc.setFontSize(14);
    doc.text(String(criticalCount), 18, currentY + 17);

    // Box 2: Medium
    doc.setFillColor(254, 252, 232);
    doc.setDrawColor(250, 204, 21);
    doc.roundedRect(60, currentY, boxWidth, boxHeight, 2, 2, 'FD');
    doc.setTextColor(161, 98, 7);
    doc.setFontSize(7.5);
    doc.setFont("helvetica", "bold");
    doc.text("MEDIUM (L5-7)", 64, currentY + 7);
    doc.setFontSize(14);
    doc.text(String(warningCount), 64, currentY + 17);

    // Box 3: Low
    doc.setFillColor(240, 253, 244);
    doc.setDrawColor(74, 222, 128);
    doc.roundedRect(106, currentY, boxWidth, boxHeight, 2, 2, 'FD');
    doc.setTextColor(21, 128, 61);
    doc.setFontSize(7.5);
    doc.setFont("helvetica", "bold");
    doc.text("LOW / INFO", 110, currentY + 7);
    doc.setFontSize(14);
    doc.text(String(lowCount), 110, currentY + 17);

    // Box 4: Total Events
    doc.setFillColor(241, 245, 249);
    doc.setDrawColor(148, 163, 184);
    doc.roundedRect(152, currentY, boxWidth, boxHeight, 2, 2, 'FD');
    doc.setTextColor(51, 65, 85);
    doc.setFontSize(7.5);
    doc.setFont("helvetica", "bold");
    doc.text("TOTAL EVENTS", 156, currentY + 7);
    doc.setFontSize(14);
    doc.text(String(filteredAlerts.length), 156, currentY + 17);

    currentY += 32;

    // Critical Source IPs Summary Section
    doc.setTextColor(15, 23, 42);
    doc.setFont("helvetica", "bold");
    doc.setFontSize(12);
    doc.text("2. Critical Attacker & Source IP Forensics", 14, currentY);

    currentY += 6;

    // Attacker IP Table Header
    doc.setFillColor(30, 41, 59);
    doc.rect(14, currentY, 182, 7, 'F');
    doc.setTextColor(255, 255, 255);
    doc.setFontSize(8);
    doc.setFont("helvetica", "bold");
    doc.text("ATTACKER IP ADDRESS", 18, currentY + 5);
    doc.text("CRITICAL HITS", 90, currentY + 5);
    doc.text("PRIMARY DETECTED THREAT VECTOR", 125, currentY + 5);

    currentY += 7;

    if (criticalSourceIpsMap.size === 0) {
        doc.setFillColor(255, 255, 255);
        doc.rect(14, currentY, 182, 8, 'F');
        doc.setTextColor(100, 116, 139);
        doc.setFont("helvetica", "italic");
        doc.setFontSize(8);
        doc.text("No high-risk malicious source IPs identified in this audit timeframe.", 18, currentY + 5.5);
        currentY += 12;
    } else {
        criticalSourceIpsMap.forEach((data, ip) => {
            doc.setFillColor(255, 255, 255);
            doc.rect(14, currentY, 182, 8, 'F');
            doc.setDrawColor(226, 232, 240);
            doc.line(14, currentY + 8, 196, currentY + 8);

            doc.setTextColor(225, 29, 72);
            doc.setFont("courier", "bold");
            doc.setFontSize(8.5);
            doc.text(ip, 18, currentY + 5.5);

            doc.setTextColor(15, 23, 42);
            doc.setFont("helvetica", "bold");
            doc.setFontSize(8);
            doc.text(String(data.count), 95, currentY + 5.5);

            doc.setFont("helvetica", "normal");
            doc.text(data.reason.length > 42 ? data.reason.substring(0, 42) + '...' : data.reason, 125, currentY + 5.5);

            currentY += 8;
        });
        currentY += 6;
    }

    currentY += 6;

    // ---------------------------------------------------------
    // PAGE 1 / 2: DETAILED SIEM TELEMETRY LOG BREAKDOWN TABLE
    // ---------------------------------------------------------
    doc.setTextColor(15, 23, 42);
    doc.setFont("helvetica", "bold");
    doc.setFontSize(12);
    doc.text("3. Detailed Telemetry Log Breakdown", 14, currentY);

    currentY += 6;

    // Log Table Header
    doc.setFillColor(30, 41, 59);
    doc.rect(14, currentY, 182, 7, 'F');
    doc.setTextColor(255, 255, 255);
    doc.setFontSize(7.5);
    doc.setFont("helvetica", "bold");
    doc.text("TIMESTAMP", 18, currentY + 5);
    doc.text("LEVEL", 62, currentY + 5);
    doc.text("SOURCE IP", 80, currentY + 5);
    doc.text("RULE DESCRIPTION", 118, currentY + 5);

    currentY += 7;

    if (filteredAlerts.length === 0) {
        doc.setTextColor(100, 116, 139);
        doc.setFont("helvetica", "italic");
        doc.setFontSize(8);
        doc.text("No events recorded within the selected date-time window.", 18, currentY + 6);
    } else {
        filteredAlerts.forEach((hit, idx) => {
            if (currentY > 265) { // Page overflow handler
                doc.addPage();
                currentY = 20;

                // Repeat Table Header on New Page
                doc.setFillColor(30, 41, 59);
                doc.rect(14, currentY, 182, 7, 'F');
                doc.setTextColor(255, 255, 255);
                doc.setFontSize(7.5);
                doc.setFont("helvetica", "bold");
                doc.text("TIMESTAMP", 18, currentY + 5);
                doc.text("LEVEL", 62, currentY + 5);
                doc.text("SOURCE IP", 80, currentY + 5);
                doc.text("RULE DESCRIPTION", 118, currentY + 5);

                currentY += 7;
            }

            const src = hit._source || {};
            const level = src.rule?.level || 0;
            const srcIp = src.data?.srcip || src.data?.src_ip || src.agent?.ip || 'N/A';
            const rawTime = src.timestamp || src['@timestamp'] || new Date().toISOString();
            const timeStr = new Date(rawTime).toLocaleString();
            const desc = src.rule?.description || 'Security Event';

            // Alternating Row Background
            if (idx % 2 === 0) {
                doc.setFillColor(248, 250, 252);
                doc.rect(14, currentY, 182, 7, 'F');
            }

            doc.setTextColor(51, 65, 85);
            doc.setFont("helvetica", "normal");
            doc.setFontSize(7);
            doc.text(timeStr.length > 22 ? timeStr.substring(0, 22) : timeStr, 18, currentY + 5);

            // Level Badge Color
            if (level >= 8) doc.setTextColor(225, 29, 72);
            else if (level >= 5) doc.setTextColor(217, 119, 6);
            else doc.setTextColor(71, 85, 105);

            doc.setFont("helvetica", "bold");
            doc.text(`LVL ${level}`, 62, currentY + 5);

            doc.setFont("courier", "normal");
            doc.setTextColor(15, 23, 42);
            doc.text(srcIp, 80, currentY + 5);

            doc.setFont("helvetica", "normal");
            doc.setTextColor(51, 65, 85);
            doc.text(desc.length > 40 ? desc.substring(0, 40) + '...' : desc, 118, currentY + 5);

            currentY += 7;
        });
    }

    // Footer Page Numbering across all pages
    const pageCount = doc.internal.getNumberOfPages();
    for (let i = 1; i <= pageCount; i++) {
        doc.setPage(i);
        doc.setDrawColor(226, 232, 240);
        doc.line(14, 282, 196, 282);

        doc.setFont("helvetica", "normal");
        doc.setFontSize(7.5);
        doc.setTextColor(148, 163, 184);
        doc.text("SEC SAFELY - Real-Time Enterprise SOC & SIEM Platform | Kali Linux Node (10.206.31.192)", 14, 288);
        doc.text(`Page ${i} of ${pageCount}`, 180, 288);
    }

    // Save Download
    const filename = `SEC-SAFELY-Audit-Report-${Date.now()}.pdf`;
    doc.save(filename);
}