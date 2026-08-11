// Point directly to your Kali Linux IP
const BACKEND_URL = "http://10.45.39.192:5000"; 

document.addEventListener('DOMContentLoaded', () => {
    fetchAlerts();
    setInterval(fetchAlerts, 5000); // Poll API every 5 seconds
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
// 1. Fetch & Render Live Ingestion Terminal Alerts
// -------------------------------------------------------------
async function fetchAlerts() {
    const tbody = document.getElementById('logs-tbody');
    if (!tbody) return;

    try {
        const response = await fetch(`${BACKEND_URL}/api/wazuh/alerts`);
        if (!response.ok) throw new Error(`HTTP Error: ${response.status}`);

        const data = await response.json();
        const hits = data.hits?.hits || [];

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

        if (!data.blockedIps || data.blockedIps.length === 0) {
            tbody.innerHTML = `
                <tr>
                    <td colspan="5" class="text-center py-8 text-gray-500 font-mono">
                        🟢 No active IP drop rules in host firewall policy.
                    </td>
                </tr>`;
            return;
        }

        tbody.innerHTML = data.blockedIps.map(item => `
            <tr class="hover:bg-gray-800/50 transition-colors border-b border-gray-800">
                <td class="py-3 px-4 font-mono font-bold text-red-400">${item.ip}</td>
                <td class="py-3 px-4 text-gray-400 text-xs">${new Date(item.blockedAt).toLocaleString()}</td>
                <td class="py-3 px-4">
                    <span class="bg-red-900/40 text-red-400 border border-red-700/50 text-xs font-semibold px-2.5 py-1 rounded-full">
                        ${item.status}
                    </span>
                </td>
                <td class="py-3 px-4 text-gray-400 text-xs">${item.reason}</td>
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
// 3. Active Response: Block IP Action
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
            body: JSON.stringify({ targetIp: ipAddress })
        });

        const result = await response.json();

        if (response.ok) {
            alert(`🚨 ACTIVE RESPONSE TRIGGERED!\n\nTarget IP ${ipAddress} blocked on host firewall.`);
            fetchBlockedIps();
        } else {
            alert(`Failed to block IP: ${result.error}`);
        }
    } catch (err) {
        alert("Could not reach Express backend server.");
    }
}

// -------------------------------------------------------------
// 4. Active Response: Unblock IP Action
// -------------------------------------------------------------
async function unblockAttackerIp(ipAddress) {
    if (!confirm(`Are you sure you want to unblock IP address ${ipAddress}?`)) return;

    try {
        const response = await fetch(`${BACKEND_URL}/api/wazuh/unblock-ip`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ targetIp: ipAddress })
        });

        const result = await response.json();

        if (response.ok) {
            alert(`✅ SUCCESS:\n\nIP address ${ipAddress} unblocked from host firewall.`);
            fetchBlockedIps();
        } else {
            alert(`Failed to unblock IP: ${result.error}`);
        }
    } catch (err) {
        alert("Could not reach Express backend server.");
    }
}

// -------------------------------------------------------------
// 5. PDF Incident Audit Summary Generator
// -------------------------------------------------------------
function generatePDFReport() {
    const { jsPDF } = window.jspdf;
    const doc = new jsPDF();
    const title = document.getElementById('report-title')?.value || 'SOC Incident Audit Summary';

    doc.setFont("helvetica", "bold");
    doc.setFontSize(16);
    doc.text("SEC SAFELY - " + title, 14, 20);

    doc.setFontSize(10);
    doc.setFont("helvetica", "normal");
    doc.text(`Generated On: ${new Date().toLocaleString()}`, 14, 28);
    doc.text(`SIEM Manager IP: 10.206.31.192`, 14, 34);

    doc.line(14, 38, 196, 38);

    doc.text("Executive Summary:", 14, 46);
    doc.text("- Live threats processed asynchronously from Kali SIEM Node.", 14, 54);
    doc.text("- Active Response firewall policies enforced in real-time.", 14, 60);

    doc.save(`SEC-SAFELY-Report-${Date.now()}.pdf`);
}