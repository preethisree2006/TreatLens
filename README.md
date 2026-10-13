# 🛡️ ThreatLens — Cybersecurity Vulnerability Assessment & Risk Management System

> **Academic Final-Year B.E. CSE Project**
>
> A realistic, working web-based Vulnerability Assessment and Risk Management System that demonstrates the complete security lifecycle: authorized network scanning, structured service parsing, rule-based vulnerability analysis, severity classification, quantitative risk scoring, CVE threat mapping, manual analyst validation, false-positive handling, actionable remediation recommendations, and automated PDF security report generation.

---

## ⚠️ Ethical & Legal Notice

> **IMPORTANT:** ThreatLens is designed exclusively for authorized cybersecurity testing, educational research, and evaluation of systems you own or have explicit, documented permission to assess.
>
> **Strict Operational Safeguards:**
> - Offensive exploitation, brute forcing, password cracking, denial-of-service, or destructive actions are **NEVER** implemented.
> - Network scanning is strictly limited to non-intrusive service discovery (`nmap -sV -T3`).
> - Arbitrary Nmap argument injection is strictly blocked via rigorous input validation.
> - Unauthorized port scanning or penetration testing without written authorization is illegal.

---

## 📌 Project Overview

Traditional cybersecurity scanners often overwhelm security teams with thousands of raw logs or superficial alert lists without context. **ThreatLens** bridges the gap between raw network discovery and operational risk remediation by implementing a disciplined, multi-stage assessment pipeline:

```
Dashboard
   ↓
Create Assessment (Target Scope & Validation)
   ↓
Controlled Security Scan (Nmap -sV -T3)
   ↓
Scan Results (Structured Host & Service Parsing)
   ↓
Vulnerability Analysis Engine (Rule-based Evidence Detection)
   ↓
Severity Classification & Risk Scoring (Likelihood × Impact)
   ↓
CVE Intelligence Mapping (NVD API v2 with Caching & Fallback)
   ↓
Manual Validation & False-Positive Management
   ↓
Remediation Engine (Actionable Guidance & SLA Timelines)
   ↓
Risk Prioritization Matrix (P1 to P5)
   ↓
Executive & Technical PDF Security Report Export
```

---

## 🎯 Problem Statement & Objectives

### Problem Statement
Organizations struggle with vulnerability overload, high false-positive rates, and delayed remediation cycles. Educational prototypes often either simulate entire scan results with fabricated data or act merely as thin shells running a command without data persistence, scoring models, analyst validation, or risk prioritization.

### Objectives
1. **Authorized Scanning:** Execute controlled, non-destructive Nmap service detection scans safely against authorized targets.
2. **Factual Parsing:** Parse real scanner XML output into structured database records (port, protocol, service, product, version).
3. **Evidence-Based Analysis:** Evaluate discovered services against deterministic security rules without fabricating nonexistent vulnerabilities.
4. **Transparent Risk Scoring:** Calculate explainable risk scores using `(Likelihood × Impact) / 10.0` combined with CVSS benchmarks.
5. **Analyst Validation & False-Positive Handling:** Provide an interactive triage workflow allowing analysts to confirm findings, mark false positives (excluding them from active risk calculations), and maintain an audit log.
6. **Actionable Remediation:** Provide prioritized fixes and SLA timelines for every confirmed weakness.
7. **Publication-Grade Reporting:** Generate downloadable PDF security assessment reports using ReportLab.

---

## ✨ Features

- **Centralized Security Operations Dashboard:**
  - Real database metrics: Total Assessments, Total Scans, Total Findings, Active Findings, Critical/High/Medium/Low counts, Confirmed findings, and False-Positive metrics.
  - Interactive Chart.js charts: Severity Donut distribution and Assessment Status breakdown.
  - Quick-triage tables for recent scans and top priority risks.
- **Assessment Scope Management:**
  - Standardized ID format: `ASM-YYYYMMDD-XXX`.
  - Target input validation blocking command separators and flag injections.
- **Controlled Security Scanning Engine:**
  - Safe subprocess execution running `nmap -sV -T3 <target>`.
  - Missing Nmap detection with friendly troubleshooting guidance.
  - Structured storage of hosts, ports, states, services, software products, and version strings.
- **Rule-Based Vulnerability Analysis:**
  - Flags dangerous exposed services (e.g. Telnet cleartext, unencrypted FTP, exposed databases, cleartext HTTP).
  - Matches specific vulnerable software signatures (e.g. vsftpd 2.3.4 backdoor).
  - Discovered services without identifiable flaws remain safe open ports (not falsely flagged).
- **Quantitative Risk Engine:**
  - Likelihood (1–10) × Impact (1–10) normalized to a 10.0 scale.
  - Priority classes: P1 (Critical), P2 (High), P3 (Medium), P4 (Low), P5 (Informational).
  - Defined SLA remediation deadlines: Immediate, 24 Hours, 7 Days, 30 Days.
- **CVE Intelligence Integration:**
  - Integrates with the NIST NVD API v2 with SQLite caching to reduce external network calls.
  - Offline fallback dictionary for resilient air-gapped or lab operation.
  - Direct links to official NIST vulnerability entries.
- **Interactive Analyst Validation & False-Positive Management:**
  - Status options: `Needs Review` (default), `Confirmed`, `False Positive`, `Resolved`.
  - False positives are dynamically excluded from active risk metrics and prioritization matrices.
  - Complete validation history audit trail with analyst timestamps and justification notes.
- **Risk Prioritization Matrix (`/risk`):**
  - Ordered by priority urgency (P1 → P5) and descending risk score.
  - False positives strictly filtered out.
- **Professional PDF Report Export (`/reports`):**
  - Cover page, Executive summary, Assessment scope, Discovered services table, Risk summary, Detailed findings with scan evidence, Separated false-positive register, and Remediation roadmap.

---

## 🛠️ Technology Stack

| Layer | Technologies |
|---|---|
| **Backend Framework** | Python 3.10+, Flask 3.0+ |
| **Database & ORM** | SQLite 3, Flask-SQLAlchemy 3.1+ |
| **Security Scanner** | Nmap 7.90+ (Service Detection `-sV -T3`) |
| **PDF Generation** | ReportLab 4.2+ |
| **Frontend UI** | Semantic HTML5, Vanilla Modern CSS (Dark Cybersecurity Theme), JavaScript |
| **Visualization** | Chart.js 4.4+ |
| **External Threat Intelligence** | NIST National Vulnerability Database (NVD API v2) |

---

## 🏛️ System Architecture

```
cybersecurity-vulnerability-assessment/
│
├── app.py                      # Application factory & route registration
├── requirements.txt            # Project dependencies
├── README.md                   # Complete system documentation
│
├── database/
│   ├── __init__.py
│   ├── db.py                   # SQLAlchemy models (Assessment, Scan, ScanResult, Vulnerability, etc.)
│   └── database.db             # Persistent SQLite database
│
├── scanner/
│   ├── __init__.py
│   ├── nmap_scanner.py         # Subprocess execution, target validation & Nmap path resolution
│   ├── parser.py               # Nmap XML & text parsing into structured service dictionaries
│   ├── scanner.py              # OOP Scanner wrapper interface
│   └── vuln_engine.py          # Rule-based vulnerability analysis & evidence evaluator
│
├── risk/
│   ├── __init__.py
│   └── risk_engine.py          # Numerical risk scoring, priority mapping & SLA timelines
│
├── cve/
│   ├── __init__.py
│   └── cve_service.py          # NIST NVD API client, caching & offline dictionary
│
├── reports/
│   ├── __init__.py
│   ├── report_generator.py     # ReportLab PDF report builder
│   └── generated/              # Output directory for compiled PDF reports
│
├── routes/
│   ├── __init__.py
│   ├── dashboard.py            # Real-time metrics & Chart.js data endpoints
│   ├── assessments.py          # Assessment CRUD & scan triggering
│   ├── scans.py                # Scan history & discovered services views
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
└── static/
    ├── css/style.css           # Premium cyber-themed dark UI design system
    └── js/main.js              # Chart initializers & dynamic metric animations
```

---

## 🗄️ Database Entity-Relationship Model

```
┌──────────────────┐       1:N       ┌──────────────────┐       1:N       ┌──────────────────┐
│   assessments    │────────────────>│      scans       │────────────────>│   scan_results   │
├──────────────────┤                 ├──────────────────┤                 ├──────────────────┤
│ id (PK)          │                 │ id (PK)          │                 │ id (PK)          │
│ assessment_id    │                 │ scan_id          │                 │ scan_id (FK)     │
│ name             │                 │ assessment_id(FK)│                 │ port, protocol   │
│ target           │                 │ status           │                 │ state, service   │
│ description      │                 │ started_at       │                 │ product, version │
│ status           │                 │ raw_output       │                 │ extra_info       │
└──────────────────┘                 └──────────────────┘                 └──────────────────┘
         │
         │ 1:N
         ▼
┌──────────────────┐       1:N       ┌─────────────────────┐
│ vulnerabilities  │────────────────>│ validation_records  │
├──────────────────┤                 ├─────────────────────┤
│ id (PK)          │                 │ id (PK)             │
│ assessment_id(FK)│                 │ vulnerability_id(FK)│
│ name, description│                 │ analyst             │
│ severity         │                 │ previous_status     │
│ risk_score, cvss │                 │ new_status          │
│ cve_id           │                 │ notes               │
│ affected_port    │                 │ created_at          │
│ validation_status│                 └─────────────────────┘
│ is_false_positive│
└──────────────────┘
```

---

## ⚙️ Installation & Setup

### 1. Prerequisites
- Python 3.10 or higher
- Git
- Windows, Linux, or macOS

### 2. Clone Repository & Setup Virtual Environment
```bash
# Clone repository
git clone https://github.com/your-username/cybersecurity-vulnerability-assessment.git
cd cybersecurity-vulnerability-assessment

# Create virtual environment
python -m venv venv

# Activate virtual environment
# Windows:
.\venv\Scripts\activate
# Linux/macOS:
source venv/bin/activate

# Install required dependencies
pip install -r requirements.txt
```

### 3. Nmap Setup (Windows & Linux)

ThreatLens utilizes the system Nmap binary for service discovery.

#### On Windows:
1. Download the official installer from [https://nmap.org/download.html](https://nmap.org/download.html) (e.g. `nmap-7.95-setup.exe`).
2. Run the installer and check the box to install Npcap and command-line tools.
3. Ensure Nmap is included in your system `PATH` (typically `C:\Program Files (x86)\Nmap`).
4. Verify by opening PowerShell and executing:
   ```powershell
   nmap --version
   ```

> **Note on Nmap Availability:**
> If Nmap is not installed or not in PATH, ThreatLens will **NOT crash**. It gracefully displays:
> *"Nmap is not installed or could not be found. Please install Nmap and ensure it is available in the system PATH."*
> You can still inspect assessments, manage findings, and export reports.

#### On Linux (Debian/Ubuntu):
```bash
sudo apt update && sudo apt install nmap -y
nmap --version
```

---

## 🚀 Running the Application

Ensure your virtual environment is active:

```bash
python app.py
```

The application will start on:
```
http://127.0.0.1:5000
```

Open your browser and navigate to `http://127.0.0.1:5000` to access the ThreatLens Dashboard.

---

## 📖 End-to-End User Workflow

1. **Dashboard:** Review system status, tracked targets, and high-level risk statistics.
2. **New Assessment:** Click **"New Assessment"**, input an authorized target (e.g. `127.0.0.1`), descriptive name, and scope notes.
3. **Trigger Security Scan:** On the Assessment Details page, click **"Run Security Scan"**. Read and accept the authorization modal.
4. **Scan Execution:** ThreatLens executes `nmap -sV -T3 <target>` safely via subprocess and saves discovered services.
5. **Vulnerability Analysis:** Discovered open ports are processed by the vulnerability engine. Findings are cataloged with status `Needs Review`.
6. **Analyst Triage & Manual Validation:** Open a finding to view scan evidence and CVE details:
   - Mark as `Confirmed` if verified as an active threat.
   - Mark as `False Positive` with justification notes if benign; it is immediately removed from the active risk score.
7. **Risk Prioritization:** Visit `/risk` to review active vulnerabilities ordered by priority (P1 to P5) and SLA deadlines.
8. **PDF Report Export:** Go to `/reports`, select your assessment, and click **"Generate PDF Report"** to compile and download an executive security report.

---

## 📐 Risk Scoring Methodology

ThreatLens computes risk scores transparently using a deterministic formula grounded in security risk principles:

$$\text{Base Risk Score} = \frac{\text{Likelihood} \times \text{Impact}}{10.0}$$

Where:
- **Likelihood (1–10):** Evaluates ease of exploitation, protocol exposure, and network reachability.
- **Impact (1–10):** Evaluates confidentiality, integrity, and availability impact if exploited.

When official CVSS v3.x intelligence is available, the score is mathematically blended:

$$\text{Final Risk Score} = 0.6 \times \text{Base Risk} + 0.4 \times \text{CVSS}$$

### Severity & Priority Classification Matrix

| Final Risk Score | Severity Level | Priority | SLA Remediation Timeline |
|---|---|---|---|
| **9.0 – 10.0** | Critical | **P1** | Immediate Response |
| **7.0 – 8.9** | High | **P2** | &le; 24 Hours |
| **4.0 – 6.9** | Medium | **P3** | &le; 7 Days |
| **1.0 – 3.9** | Low | **P4** | &le; 30 Days |
| **0.0 – 0.9** | Informational | **P5** | Review when possible |

---

## 🧪 Testing & Validation

### Automated Verification Test Suite
Run the test suite using your virtual environment:

```powershell
.\venv\Scripts\python -c "
from app import create_app
from database.db import Assessment, Scan, Vulnerability
from scanner.nmap_scanner import validate_target
from reports.report_generator import generate_pdf_report
import os

app = create_app('testing')
client = app.test_client()

with app.app_context():
    print('Checking all routes...')
    for r in ['/', '/dashboard', '/assessments/', '/scans/', '/vulnerabilities/', '/risk/', '/reports/']:
        res = client.get(r)
        assert res.status_code == 200, f'Failed {r}'
        print(f' - {r}: OK')
    print('Testing target validation...')
    assert validate_target('127.0.0.1')[0] is True
    assert validate_target('; bad command')[0] is False
    print('Verification tests complete.')
"
```

---

## ⚠️ Known Limitations

1. **Service Discovery Scope:** Scanning uses standard TCP port discovery (`nmap -sV -T3`). It does not run invasive vulnerability scripts (`--script vuln`) by default to protect target stability.
2. **NVD API Rate Limits:** Public queries to the NIST NVD API may be throttled without an API key. ThreatLens mitigates this with an SQLite caching table and an internal fallback dictionary.
3. **No Active Exploitation:** The system intentionally does not exploit services or confirm compromise through invasive payloads.

---

## 🔮 Future Enhancements

- Multi-user role-based access control (Admin, Lead Analyst, Auditor).
- Automated scheduled re-scanning and remediation tracking.
- Webhook notifications for Slack and Microsoft Teams on Critical findings.
- NIST SP 800-53 and ISO 27001 compliance control mapping.

---

## 📄 License & Academic Attribution

This project was developed as a final-year academic capstone in Computer Science and Engineering. It is distributed for educational and research use under the MIT License.
