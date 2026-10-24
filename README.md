# ThreatLens — Cybersecurity Vulnerability Assessment & Risk Management System

> **Final-Year / Internship Capstone Cybersecurity Project**  
> An explainable, evidence-based, web-based vulnerability assessment and risk management platform demonstrating the complete defensive security lifecycle in an authorized environment.

---

## 📌 Project Overview

**ThreatLens** is a defensive cybersecurity assessment system that performs controlled service discovery, parses scanner output into structured records, evaluates services using evidence-based rules, correlates verified CVE threat intelligence, calculates quantitative risk scores, enables analyst-in-the-loop validation, and generates publication-grade PDF assessment reports.

### Purpose
A web-based system that performs controlled Nmap service discovery, analyzes discovered services using evidence-based rules, calculates risk, supports analyst validation, and generates security assessment reports.

### ⚠️ Important Clarification: Service Discovery vs. Vulnerabilities
**Nmap discovers open ports and running services; it does not automatically prove that every open port is a vulnerability.**  
ThreatLens analyzes the discovered services and creates findings **only when its rules have verifiable evidence** (e.g., cleartext protocol, exposed administrative interface, known vulnerable version). Discovered services without identifiable flaws remain safe open services rather than being falsely flagged. ThreatLens strictly does **not** fabricate findings or assign arbitrary CVE identifiers.

---

## 🔄 End-to-End Workflow

```
Target Specification (e.g., 127.0.0.1 / localhost)
       │
       ▼
Target Validation & Command-Injection Guard
       │
       ▼
Controlled Nmap Scan (nmap -sV -T3 <target>)
       │
       ▼
Structured Output Parsing (XML & Text Parser)
       │
       ▼
Rule-Based Vulnerability Engine (Evidence Evaluation)
       │
       ▼
CVE Intelligence Correlation (NVD API v2 with Caching)
       │
       ▼
Quantitative Risk Scoring (Likelihood × Impact / 10.0)
       │
       ▼
Manual Analyst Validation (Confirmed / False Positive)
       │
       ▼
Risk Prioritization Matrix (P1 Critical → P5 Info)
       │
       ▼
Professional Executive & Technical PDF Report
```

---

## 🎯 Demo Target: `127.0.0.1` / `localhost`

The primary demonstration target is `127.0.0.1` (`localhost`), representing the local host computer.

When scanned at runtime using `nmap -sV -T3 127.0.0.1`, Nmap discovers the actual listening services on the host machine. On standard Windows systems with ThreatLens running:
- **Port 135/tcp** → `msrpc` (Microsoft Windows RPC)
- **Port 445/tcp** → `microsoft-ds` (Microsoft SMB File Sharing)
- **Port 5000/tcp** → `http` (Werkzeug / ThreatLens Web Server)

ThreatLens evaluates these exact services:
1. **Port 135:** Identifies *Exposed Microsoft RPC Endpoint Mapper (Port 135)* [Severity: Low, CVE: None]
2. **Port 445:** Identifies *Exposed Microsoft SMB Service (Port 445)* [Severity: Medium, CVE: None]
3. **Port 5000:** Identifies *Unencrypted HTTP Web Service Exposed (Missing TLS/HTTPS)* [Severity: Low/Medium, CVE: None]

**Result Integrity:** The system displays **only** findings supported by discovered ports. Unrelated services (such as FTP, Telnet, vsftpd) are **never** displayed unless that specific service was actually discovered in the scan.

---

## 🏛️ Project Architecture

```
cybersecurity-vulnerability-assessment/
│
├── app.py                      # Application factory & route registration
├── requirements.txt            # Python dependencies
├── README.md                   # System documentation
├── PROJECT_DOCUMENTATION.md    # Comprehensive technical viva/defense guide
├── .gitignore                  # Git tracking rules
│
├── database/
│   ├── __init__.py
│   └── db.py                   # SQLAlchemy ORM models & table migrations
│
├── scanner/
│   ├── __init__.py
│   ├── nmap_scanner.py         # Subprocess execution, Nmap path resolution & target validation
│   ├── parser.py               # Nmap XML and plain-text output parser
│   └── vuln_engine.py          # Evidence-based rule engine & scan-specific deduplication
│
├── risk/
│   ├── __init__.py
│   └── risk_engine.py          # Mathematical risk formulation, P1-P5 priorities & SLAs
│
├── cve/
│   ├── __init__.py
│   └── cve_service.py          # NIST NVD API client, caching & offline dictionary
│
├── reports/
│   ├── __init__.py
│   ├── report_generator.py     # ReportLab PDF security assessment report builder
│   └── generated/              # Output directory for compiled PDF reports
│
├── routes/
│   ├── __init__.py
│   ├── dashboard.py            # Real-time metrics & Chart.js data endpoints
│   ├── assessments.py          # Assessment CRUD & scan execution
│   ├── scans.py                # Scan results & discovered ports view
│   ├── vulnerabilities.py      # Finding listing, multi-filter & analyst triage validation
│   ├── risk.py                 # Risk prioritization matrix (P1–P5)
│   └── reports.py              # PDF report generation & file download
│
├── templates/
│   ├── base.html               # Master layout with sidebar navigation
│   ├── dashboard.html          # Operational dashboard with live metrics
│   ├── new_assessment.html     # Target scope configuration & validation
│   ├── assessments.html        # Assessment history
│   ├── assessment_detail.html  # Assessment hub, scan launcher & finding overview
│   ├── scans.html              # Comprehensive scans register
│   ├── scan_results.html       # Discovered ports, services & raw execution log
│   ├── results.html            # Vulnerability register with multi-factor filtering
│   ├── vulnerability_details.html # Finding inspection, evidence, CVE & triage form
│   ├── risk_assessment.html    # Prioritized risk action matrix
│   ├── reports.html            # PDF report generator & archive
│   └── errors/                 # 404 & 500 error handlers
│
├── static/
│   ├── css/style.css           # Modern cyber-themed dark UI design system
│   └── js/main.js              # Chart initializers & dynamic metric animations
│
└── tests/
    └── test_threatlens.py      # Automated unit and integration test suite
```

---

## 🗄️ Database Schema & Entities

The SQLite database (`database/database.db`) manages 7 core relational tables:

| Table | Description |
|---|---|
| `assessments` | Target assessment sessions (target, scope name, lifecycle status) |
| `scans` | Nmap scan execution records (command, status, timing, raw output) |
| `scan_results` | Individual discovered ports and services (port, protocol, service, product, version) |
| `vulnerabilities` | Factual findings linked directly to `assessment_id` and `scan_id` |
| `validation_records` | Audit log of security analyst triage decisions |
| `cve_records` | Local SQLite cache of NIST NVD vulnerability records |
| `reports` | Generated PDF security assessment metadata and file paths |

---

## 🛡️ Safety & Ethical Scanning Model

- **Authorized Targets Only:** Validates all targets before execution. Supports `localhost`, `127.0.0.1`, private IP addresses, or authorized hostnames.
- **Strict Injection Protection:** Reject flags starting with `-` and command separators (`;`, `&`, `|`, `` ` ``, `$()`).
- **Safe Scanning:** Uses strictly `nmap -sV -T3 <target>` with arguments passed as a safe list (`subprocess.run(shell=False)`).
- **Non-Destructive:** No exploit payloads, no brute force, no denial-of-service, no intrusive NSE scripts.

---

## ⚙️ Installation & Running

### 1. Prerequisites
- Python 3.10 or higher
- Nmap installed and available in system `PATH` (Verify: `nmap --version`)

### 2. Activate Virtual Environment
```powershell
# Windows PowerShell
.\venv\Scripts\activate
```

### 3. Install Dependencies
```bash
pip install -r requirements.txt
```

### 4. Run the Application
```bash
python app.py
```
Open your browser and navigate to:  
**http://127.0.0.1:5000**

---

## 🧪 Running Automated Tests

Run the full automated test suite (target validation, parser, rule engine, deduplication, risk scoring, routes, and PDF generation):
```powershell
.\venv\Scripts\python.exe -m unittest tests/test_threatlens.py
```

---

## 📋 Key Capabilities Demonstrated

1. **Scan-Specific Findings:** Every finding is linked to `scan_id` and `affected_host`. Historical vulnerabilities from previous scans never contaminate new assessments.
2. **True Deduplication:** Clicking "Re-analyze Scan" updates existing findings safely without producing duplicate rows.
3. **Analyst Triage & False-Positive Handling:** Security analysts can mark findings as *Confirmed* or *False Positive*. False positives are mathematically excluded from active risk counts, the risk prioritization matrix, and executive reports.
4. **Dynamic Dashboard Metrics:** All dashboard cards (Total Assessments, Total Scans, Total Findings, Active Findings, Severity Counts, False Positives) calculate live values directly from the database.
5. **PDF Report Compilation:** Downloads executive and technical reports generated on demand with ReportLab, containing only the discovered services and validated findings of the selected assessment.
