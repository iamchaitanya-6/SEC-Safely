💾 Persistence] Loaded 4 sent alert ID(s) from sent_alerts.json
=======================================================
🛡️  SEC SAFELY API Bridge Operational
📡 Local Binding:    http://127.0.0.1:5000
🌐 Network Endpoint: http://10.206.31.192:5000
=======================================================
(node:4187) Warning: Setting the NODE_TLS_REJECT_UNAUTHORIZED environment variable to '0' makes TLS connections and HTTPS requests insecure by disabling certificate verification.
(Use `node --trace-warnings ...` to show where the warning was created)
[Wazuh Indexer Bridge Error]: connect ECONNREFUSED 127.0.0.1:9200
[Wazuh Indexer Bridge Error]: connect ECONNREFUSED 127.0.0.1:9200
[Wazuh Indexer Bridge Error]: connect ECONNREFUSED 127.0.0.1:9200
[Wazuh Indexer Bridge Error]: connect ECONNREFUSED 127.0.0.1:9200
[Wazuh Indexer Bridge Error]: connect ECONNREFUSED 127.0.0.1:9200
[JSON Parse Error]: Raw response: OpenSearch Security not initialized.
[JSON Parse Error]: Raw response: OpenSearch Security not initialized.
[JSON Parse Error]: Raw response: OpenSearch Security not initialized.
[JSON Parse Error]: Raw response: OpenSearch Security not initialized.
^C
                                                                                                                                     
┌──(kali㉿kali)-[~]
└─$ node server.js
[💾 Persistence] Loaded 4 sent alert ID(s) from sent_alerts.json
=======================================================
🛡️  SEC SAFELY API Bridge Operational
📡 Local Binding:    http://127.0.0.1:5000
🌐 Network Endpoint: http://10.206.31.192:5000
=======================================================
(node:8686) Warning: Setting the NODE_TLS_REJECT_UNAUTHORIZED environment variable to '0' makes TLS connections and HTTPS requests insecure by disabling certificate verification.
(Use `node --trace-warnings ...` to show where the warning was created)
[📱 Telegram Success] Sent notification for Rule [2502] - syslog: User missed the password more than one time
[📱 Telegram Success] Sent notification for Rule [2502] - syslog: User missed the password more than one time
[📱 Telegram Success] Sent notification for Rule [5712] - sshd: brute force trying to get access to the system. Non existent user.
^C
                                                                                                                                     
┌──(kali㉿kali)-[~]
└─$ cat server.js           
/**
 * SEC SAFELY - Real-Time SOC Middleware API Server
 * Target Host IP: 10.206.31.192
 * Port: 5000
 */

const express = require('express');
const cors = require('cors');
const { exec } = require('child_process');
const https = require('https');
const fs = require('fs');
const path = require('path');

const app = express();

// Prevent silent process crashes
process.on('uncaughtException', (err) => {
    console.error('[⚠️ Uncaught Exception]:', err.message);
});

// Enable CORS for Netlify Frontend
app.use(cors({ origin: '*' }));
app.use(express.json());

// Bypass TLS/SSL verification for local OpenSearch / Wazuh Indexer
process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';

const HOST_IP = '10.206.31.192';
const PORT = 5000;

const WAZUH_INDEXER_HOST = '127.0.0.1';
const WAZUH_INDEXER_PORT = 9200;
const WAZUH_INDEX_PATH = '/*wazuh-alerts*/_search'; 

// Auto-generated Wazuh credentials
const WAZUH_CREDENTIALS = 'admin:E3SA+3jBqpVK?BigCMGp6eB2B716yuRo';
const WAZUH_AUTH = Buffer.from(WAZUH_CREDENTIALS).toString('base64');

const TELEGRAM_BOT_TOKEN = '8845400985:AAFjLHj8iMPkWK8q4sXlYsTiHwNYSgkDsS0';
const TELEGRAM_CHAT_ID = '1490320757';

// -------------------------------------------------------------
// 🛡️ PERSISTENT DEDUPLICATION ENGINE
// -------------------------------------------------------------
const SENT_ALERTS_FILE = path.join(__dirname, 'sent_alerts.json');
let sentAlertsLog = new Set();

// Record server startup timestamp (allows a 5-minute grace window for recent live events)
const SERVER_START_TIME = new Date(Date.now() - 5 * 60 * 1000);

// Load previously sent alert IDs from disk on startup
if (fs.existsSync(SENT_ALERTS_FILE)) {
    try {
        const fileData = fs.readFileSync(SENT_ALERTS_FILE, 'utf8');
        const parsed = JSON.parse(fileData);
        sentAlertsLog = new Set(parsed);
        console.log(`[💾 Persistence] Loaded ${sentAlertsLog.size} sent alert ID(s) from sent_alerts.json`);
    } catch (e) {
        console.error('[⚠️ Persistence Error] Failed to read sent_alerts.json:', e.message);
    }
}

// Function to write sent alert IDs to disk
function saveSentAlerts() {
    try {
        const arr = Array.from(sentAlertsLog);
        // Keep file size managed (store last 500 alert IDs)
        const trimmedArr = arr.slice(-500);
        fs.writeFileSync(SENT_ALERTS_FILE, JSON.stringify(trimmedArr, null, 2));
    } catch (e) {
        console.error('[⚠️ Persistence Error] Failed to save sent_alerts.json:', e.message);
    }
}

let blockedIpsList = [];

// -------------------------------------------------------------
// Helper function: Dispatch alerts to Telegram (HTML mode)
// -------------------------------------------------------------
function sendTelegramNotification(alertData) {
    const ruleId = alertData.rule?.id || 'N/A';
    const description = alertData.rule?.description || 'Threat Detected';
    const level = alertData.rule?.level || 'High';
    const srcIp = alertData.data?.srcip || alertData.agent?.ip || 'N/A';
    const timestamp = alertData.timestamp || alertData['@timestamp'] || new Date().toISOString();

    const message = 
        `<b>🚨 CRITICAL SECURITY ALERT 🚨</b>\n\n` +
        `<b>Rule ID:</b> ${ruleId}\n` +
        `<b>Description:</b> ${description}\n` +
        `<b>Level:</b> Level ${level}\n` +
        `<b>Source IP:</b> <code>${srcIp}</code>\n` +
        `<b>Timestamp:</b> ${timestamp}`;

    const payload = JSON.stringify({
        chat_id: TELEGRAM_CHAT_ID,
        text: message,
        parse_mode: 'HTML'
    });

    const req = https.request({
        hostname: 'api.telegram.org',
        path: `/bot${TELEGRAM_BOT_TOKEN}/sendMessage`,
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'Content-Length': Buffer.byteLength(payload)
        }
    }, (res) => {
        let resBody = '';
        res.on('data', chunk => resBody += chunk);
        res.on('end', () => {
            if (res.statusCode === 200) {
                console.log(`[📱 Telegram Success] Sent notification for Rule [${ruleId}] - ${description}`);
            } else {
                console.error(`[❌ Telegram API Rejected Request]: Status ${res.statusCode} - ${resBody}`);
            }
        });
    });

    req.on('error', (err) => console.error('[❌ Telegram Network Error]:', err.message));
    req.write(payload);
    req.end();
}

// -------------------------------------------------------------
// 1. Fetch Live Wazuh Alerts Endpoint
// -------------------------------------------------------------
app.get('/api/wazuh/alerts', (req, res) => {
    const queryPayload = JSON.stringify({
        size: 100,
        sort: [{ "@timestamp": { order: "desc" } }]
    });

    const options = {
        hostname: WAZUH_INDEXER_HOST,
        port: WAZUH_INDEXER_PORT,
        path: WAZUH_INDEX_PATH,
        method: 'POST',
        headers: {
            'Authorization': `Basic ${WAZUH_AUTH}`,
            'Content-Type': 'application/json',
            'Content-Length': Buffer.byteLength(queryPayload)
        }
    };

    const wazuhReq = https.request(options, (wazuhRes) => {
        let body = '';
        wazuhRes.on('data', chunk => body += chunk);
        wazuhRes.on('end', () => {
            if (wazuhRes.statusCode === 401 || body.trim() === "Unauthorized") {
                console.error(`[❌ AUTH ERROR] Wazuh Indexer rejected credentials.`);
                return res.status(401).json({ error: "Unauthorized access to Wazuh Indexer on port 9200" });
            }

            try {
                const parsedData = JSON.parse(body);
                const hits = parsedData.hits?.hits || [];

                hits.forEach(hit => {
                    const alertData = hit._source;
                    const level = alertData?.rule?.level || 0;
                    const alertId = hit._id;
                    const eventTime = new Date(alertData?.timestamp || alertData?.['@timestamp'] || Date.now());

                    // Safeguards:
                    // 1. Severity Level >= 8
                    // 2. Alert ID has NOT been processed previously
                    // 3. Alert timestamp occurred AFTER server startup time
                    if (level >= 8 && !sentAlertsLog.has(alertId) && eventTime >= SERVER_START_TIME) {
                        sentAlertsLog.add(alertId);
                        saveSentAlerts(); // Save ID to disk file sent_alerts.json
                        sendTelegramNotification(alertData);
                    }
                });

                return res.status(200).json(parsedData);
            } catch (err) {
                console.error("[JSON Parse Error]: Raw response:", body);
                return res.status(500).json({ error: "Failed to parse Wazuh Indexer response", raw: body });
            }
        });
    });

    wazuhReq.on('error', (err) => {
        console.error('[Wazuh Indexer Bridge Error]:', err.message);
        return res.status(502).json({ error: "Could not connect to Wazuh Indexer on port 9200" });
    });

    wazuhReq.write(queryPayload);
    wazuhReq.end();
});

// -------------------------------------------------------------
// 2. Fetch All Currently Blocked IPs
// -------------------------------------------------------------
app.get('/api/wazuh/blocked-ips', (req, res) => {
    return res.status(200).json({
        status: "success",
        total: blockedIpsList.length,
        blockedIps: blockedIpsList
    });
});

// -------------------------------------------------------------
// 3. Real-Time Active Response: Block IP
// -------------------------------------------------------------
app.post('/api/wazuh/block-ip', (req, res) => {
    const { targetIp } = req.body;
    const requesterIp = req.headers['x-forwarded-for'] || req.socket.remoteAddress || '';

    if (!targetIp || targetIp === '127.0.0.1' || targetIp === HOST_IP) {
        return res.status(400).json({ error: "Cannot block loopback or server host IP address." });
    }

    if (requesterIp.includes(targetIp)) {
        console.warn(`[⚠️ SAFEGUARD] Prevented user from blocking their own IP: ${targetIp}`);
        return res.status(403).json({ 
            error: "Safety Safeguard: You cannot block your own workstation IP address! Doing so breaks your network connection to the dashboard." 
        });
    }

    console.log(`[⚡ Active Response] Executing iptables DROP for: ${targetIp}`);

    const blockCmd = `sudo iptables -A INPUT -s ${targetIp} -j DROP`;

    exec(blockCmd, (error, stdout, stderr) => {
        if (error) {
            console.error(`[❌ Block Failed]: ${error.message}`);
            return res.status(500).json({ error: "Failed to apply iptables block rule", details: error.message });
        }

        if (!blockedIpsList.some(item => item.ip === targetIp)) {
            blockedIpsList.push({
                ip: targetIp,
                blockedAt: new Date().toISOString(),
                status: "Active (Blocked)",
                reason: "SOC Incident Mitigation"
            });
        }

        exec(`echo "$(date) firewall-drop add - ${targetIp}" | sudo tee -a /var/ossec/logs/active-responses.log`);

        console.log(`[🛡️ Block Success] IP ${targetIp} blocked.`);
        return res.status(200).json({
            status: "success",
            message: `Attacker IP address ${targetIp} blocked in real-time.`,
            ip: targetIp,
            timestamp: new Date().toISOString()
        });
    });
});

// -------------------------------------------------------------
// 4. Real-Time Active Response: Unblock IP
// -------------------------------------------------------------
app.post('/api/wazuh/unblock-ip', (req, res) => {
    const { targetIp } = req.body;

    if (!targetIp) {
        return res.status(400).json({ error: "Missing target IP address" });
    }

    console.log(`[🔓 Active Response] Removing iptables DROP for: ${targetIp}`);

    const unblockCmd = `sudo iptables -D INPUT -s ${targetIp} -j DROP`;

    exec(unblockCmd, (error, stdout, stderr) => {
        if (error) {
            console.error(`[❌ Unblock Failed]: ${error.message}`);
            return res.status(500).json({ error: "Failed to remove iptables drop rule", details: error.message });
        }

        blockedIpsList = blockedIpsList.filter(item => item.ip !== targetIp);

        exec(`echo "$(date) firewall-drop delete - ${targetIp}" | sudo tee -a /var/ossec/logs/active-responses.log`);

        console.log(`[✅ Unblock Success] IP ${targetIp} unblocked.`);
        return res.status(200).json({
            status: "success",
            message: `IP address ${targetIp} unblocked from host firewall.`,
            ip: targetIp,
            timestamp: new Date().toISOString()
        });
    });
});

const server = app.listen(PORT, '0.0.0.0', () => {
    console.log(`=======================================================`);
    console.log(`🛡️  SEC SAFELY API Bridge Operational`);
    console.log(`📡 Local Binding:    http://127.0.0.1:${PORT}`);
    console.log(`🌐 Network Endpoint: http://${HOST_IP}:${PORT}`);
    console.log(`=======================================================`);
});

server.on('error', (e) => {
    if (e.code === 'EADDRINUSE') {
        console.error(`[❌ ERROR] Port ${PORT} is in use. Run 'sudo fuser -k ${PORT}/tcp' to release.`);
    }
});
