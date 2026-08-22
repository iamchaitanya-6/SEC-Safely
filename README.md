# 🛡️ SEC SAFELY - Enterprise SIEM & SOC Platform

![Status](https://img.shields.io/badge/Status-Active_Development-brightgreen)
![Version](https://img.shields.io/badge/Version-1.0.0-blue)
![Architecture](https://img.shields.io/badge/Architecture-Cloud_%7C_On--Premise-orange)

**SEC SAFELY** is an advanced, hybrid Security Information and Event Management (SIEM) and Security Operations Center (SOC) platform. It provides centralized, real-time threat detection, multi-asset log ingestion, and automated active defense mechanisms (IPS/IDS) bridging local Linux endpoints and remote cloud-hosted web applications.

---

## 📖 Table of Contents
- [Project Overview](#-project-overview)
- [System Architecture](#-system-architecture)
- [Key Features Implemented](#-key-features-implemented)
- [Technology Stack](#-technology-stack)
- [How It Works (Threat Pipeline)](#-how-it-works-threat-pipeline)
- [Installation & Setup](#-installation--setup)
- [Future Roadmap](#-future-roadmap)

---

## 🔍 Project Overview
Modern infrastructure requires monitoring both local server endpoints and remote cloud assets simultaneously. SEC SAFELY addresses this by creating a "single-pane-of-glass" SOC pipeline. It not only passively monitors telemetry but actively mitigates high-speed automated attacks (e.g., brute-force, credential stuffing) through automated firewall drops and instant mobile alerting.

---

## 🏗️ System Architecture
The architecture seamlessly integrates a Node.js API middleware bridge, a Wazuh SIEM engine, an OpenSearch indexer, and a cloud frontend (Netlify) with mobile integrations (Telegram).

1. **Telemetry Layer:** Captures SSH auth logs (`auth.log`) from Kali Linux and web auth failures from the Netlify portal.
2. **Middleware API:** A Node.js/Express bridge (`server.js`) that handles cross-origin log ingestion and active firewall controls.
3. **SIEM Core (Wazuh):** Parses raw logs using custom XML decoders (`sec_safely_webapp`) and evaluates them against MITRE ATT&CK mapped rules.
4. **Data Indexing (OpenSearch):** Indexes triggered alerts on Port 9200 for rapid REST DSL querying.
5. **Response Layer:** Executes kernel-level packet drops (`iptables`) and routes deduplicated alerts to Telegram.

---

## ✨ Key Features Implemented (Up to Phase 3)

### 1. Multi-Asset Telemetry Ingestion
- Ingests standard local endpoint logs alongside asynchronous web application telemetry via custom `/api/wazuh/web-event` REST routes.
- Resolves client attacker IPs dynamically using fallback APIs (`api.ipify.org`) during web gateway credential stuffing attacks.

### 2. Custom Threat Correlation Engine
- Custom Wazuh XML decoders (`local_decoder.xml`) extract dynamic fields (`action`, `dstuser`, `srcip`).
- Custom Level 10 correlation rules (`100020`, `100021`, `100002`) trigger specifically when $\ge 3$ failed logins occur within a 60-second sliding window to eliminate false positives.

### 3. Automated Active Defense (IPS)
- Real-time Node.js Child Process integration executes zero-latency kernel drops: `sudo iptables -A INPUT -s <IP> -j DROP`.
- **Workstation Safeguard Engine:** Request IP header inspection prevents SOC analysts from accidentally locking out their own management IP or the loopback interface (`127.0.0.1`).

### 4. Smart Mobile Incident Routing
- Critical incidents (Severity $\ge 8$) are pushed instantly to security teams via the Telegram Bot API (`@SEC_safely_bot`).
- **Disk-Backed Deduplication:** A persistent cache engine (`sent_alerts.json`) prevents alert flooding and duplicate notifications during high-frequency dashboard polling.

### 5. Real-Time SOC Dashboard & Forensics
- Cloud-hosted Netlify React/Vanilla JS dashboard continuously polls OpenSearch data at 5-second intervals.
- Generates dynamic, downloadable PDF compliance and forensic audit reports mapping events to GDPR/PCI DSS standards.

---

## 💻 Technology Stack
* **SIEM Engine:** Wazuh (v4.x)
* **Data Indexer:** OpenSearch (Port 9200)
* **Backend Middleware:** Node.js, Express.js
* **Frontend:** HTML/CSS (Tailwind), JavaScript (Fetch API), Netlify
* **OS / Networking:** Kali Linux, `iptables`, Netfilter, Bash Scripting
* **Log Forwarding:** Filebeat, `rsyslog`
* **Third-Party Integrations:** Telegram Bot Webhook API

---

## ⚙️ How It Works (Threat Pipeline)

**Scenario: A threat actor initiates an automated brute-force attack against the web portal.**

1. **Recon & Attack:** The attacker inputs 3 incorrect credentials within 60 seconds on the Netlify login page.
2. **Ingestion:** The frontend `auth.js` triggers a Fetch API call, sending the telemetry to the backend Node.js server. The server writes this to `/var/log/sec_safely_web.log`.
3. **Parsing & Detection:** Wazuh reads the log file instantly. The `sec_safely_webapp` decoder parses the data, and Rule `100021` fires a Level 10 Critical Alert.
4. **Indexing:** The alert is indexed into OpenSearch ($\le 0.6$ seconds latency).
5. **Mitigation:** The active response script fires, appending the attacker's IP to the Linux `iptables` DROP list, isolating them instantly.
6. **Notification:** The Node middleware checks `sent_alerts.json`. Since this is a new event, it pushes a formatted alert to the Telegram Bot.

---

## 🚀 Installation & Setup

*(Note: Ensure you are running on a Linux-based OS like Kali/Ubuntu for iptables integration).*

### 1. Clone the Repository
```bash
git clone [https://github.com/yourusername/sec-safely.git](https://github.com/yourusername/sec-safely.git)
cd sec-safely
2. Backend Middleware Setup (Node.js)Bashcd backend
npm install
# Create a .env file and add your Telegram Bot Token and Chat ID
echo "TELEGRAM_BOT_TOKEN=your_token_here" >> .env
echo "TELEGRAM_CHAT_ID=your_chat_id" >> .env
# Start the API server
node server.js
3. Wazuh ConfigurationCopy the custom decoders to /var/ossec/etc/decoders/local_decoder.xml.Copy the custom rules to /var/ossec/etc/rules/local_rules.xml.Restart the Wazuh Manager:Bashsudo systemctl restart wazuh-manager
4. Frontend SetupDeploy the /frontend directory to Netlify or run it locally using a Live Server.Ensure the API endpoint in auth.js points to your backend IP (e.g., http://<your-kali-ip>:5000).🚧 Future Roadmap (Planned Work)[ ] Implement automated background timer routines (node-cron) for temporary 5-minute IP unblocking (iptables -D).[ ] Conduct full-scale stress testing ($> 1,000$ EPS) to benchmark OpenSearch ingestion latency.[ ] Implement multi-factor authentication (MFA) for the SOC administrative panel.Developed by Chejarla Chaitanya | Capstone Project - Cybersecurity / SIEM Architecture
