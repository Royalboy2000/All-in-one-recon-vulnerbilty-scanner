# RedSentry: The Ultimate Red Teaming Framework

RedSentry is a massive, modular Red Teaming framework written in Python. It is designed to be a comprehensive tool for offensive security operations, featuring native Python algorithms for OSINT, Android application analysis, network traffic inspection (SIGINT), web vulnerability scanning, and HUMINT/data correlation.

> **Disclaimer:** This tool is for educational and authorized testing purposes only. The author is not responsible for any misuse or damage caused by this program.

## Features

### Core Framework
- **Dynamic Module Loading:** Modules are loaded automatically from the `modules/` directory.
- **Centralized Database:** All findings are stored in a SQLite database (`redsentry.db`) for persistence and correlation.
- **Robust Logging:** Detailed logging to both console (color-coded) and file (`redsentry.log`).

### Modules

#### 1. OSINT (Open Source Intelligence)
Gather intel using free, permanent sources without paid APIs.
- **Certificate Search:** enumerates subdomains using `crt.sh`.
- **Tech Stack Detector:** Analyzes HTTP headers and HTML source to identify technologies (WordPress, React, etc.).
- **Wayback Machine Scraper:** Finds archived URLs and interesting parameters (e.g., `id=`, `admin=`).
- **Google Dork Generator:** Generates search links to find config files, logs, and login pages.

#### 2. Android Pentesting
Static analysis of APK files using `androguard`.
- **Manifest Analysis:** Extracts permissions and flags dangerous ones (e.g., `READ_SMS`, `ACCESS_FINE_LOCATION`).
- **Secret Hunter:** Scans files for hardcoded secrets (API keys, Bearer tokens, Firebase URLs) using Regex.
- **Activity Exporter:** Lists exported activities that can be launched by other apps.

#### 3. SIGINT (Network Intelligence)
Local network analysis and packet inspection using `scapy`. **Requires Root/Sudo.**
- **Wi-Fi Scanner:** Detects available SSIDs and their encryption types (WEP/WPA2).
- **ARP Monitor:** Passively listens for ARP requests to identify devices on the network.
- **Packet Sniffer:** Analyzes packets for clear-text HTTP traffic and DNS queries.

#### 4. Web Pentesting
Native algorithms for detecting web vulnerabilities.
- **JWT Analysis:** Tests for `None` algorithm, weak secrets (brute-force), and KID injection.
- **SQL Injection:** Checks for Boolean Inference, Time-Based Blind SQLi, and Error-Based SQLi.
- **XSS Engine:** Detects Reflected XSS, Polyglot payloads, and DOM-based sinks.
- **SSRF:** Checks for Loopback and Cloud Metadata service interactions.
- **Logic Flaws:** Tests for IDOR (Insecure Direct Object Reference) and Race Conditions.

#### 5. Analysis & HUMINT
Connects the dots between gathered data points.
- **Username Correlation:** Checks for username existence across major social platforms (GitHub, Twitter, etc.).
- **Data Miner:** Correlates entities (e.g., emails found in OSINT vs Android) to build profiles.
- **Reporting:** Generates a comprehensive HTML report of all findings.

#### 6. M365 Device Code Phishing
- Automates the Microsoft 365 Device Code flow phishing attack.
- Requests device code, displays user code, and polls for access tokens.
- Saves full token data (Access, Refresh, Scope) to database.

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/redsentry.git
   cd redsentry
   ```

2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
   *Note: `scapy` and `androguard` may have system-level dependencies depending on your OS.*

## Usage

Run the main framework script:

```bash
python3 main.py
```

**For SIGINT features (Network Scanning), run with sudo:**

```bash
sudo python3 main.py
```

### Main Menu
Select a module by entering its number:
```
1. ANALYSIS
2. ANDROID
3. M365_PHISH
4. N8N
5. OSINT
6. SCIM
7. SECRETS
8. SIGINT
9. SSH
10. WEB
11. WORDPRESS
0. Exit
```

Follow the prompts to enter targets (Domain, URL, APK Path, or Network Interface).

## Project Structure

- `main.py`: Entry point and main menu loop.
- `database.py`: Handles SQLite database operations.
- `utils.py`: Logging and helper functions.
- `modules/`: Contains all functional modules.
  - `osint.py`
  - `android.py`
  - `sigint.py`
  - `web.py`
  - `analysis.py`
  - `reporting.py`
  - `n8n.py`
  - `ssh.py`
  - `wordpress.py`
  - `secrets.py`
  - `scim.py`
  - `m365_phish.py`
- `requirements.txt`: Python dependencies.

## TODO / Roadmap

Based on recent operation analysis (2026-op), the following capabilities are prioritized:

- [ ] **Okta Reconnaissance:** Check for `pssoEnabled`, `desktopMFAEnabled`, and weak pipeline configurations.
- [ ] **Subdomain Takeover Scanner:** Identify dangling CNAME records pointing to AWS/Azure/GCP.
- [ ] **MySQL Enumeration:** Banner grabbing, version detection, and weak authentication checks (Port 3306).
- [ ] **cPanel/WHM Recon:** Identify exposed admin panels (2082, 2083, 2087) and brute-force common credentials.
- [ ] **Advanced Cloud Enum:** AWS S3 bucket enumeration and permissions checking.
- [ ] **Report Generation:** Export findings to Markdown/HTML formats similar to operation summaries.

## License

This project is open-source and available under the MIT License.
