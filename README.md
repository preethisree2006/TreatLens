# 🛡️ ThreatLens — Cybersecurity Vulnerability Assessment & Risk Management System

> **Academic Project** | Final-Year B.E. Computer Science Engineering
>
> A professional web-based Vulnerability Assessment and Risk Management System demonstrating the complete security assessment workflow.

---

## ⚠️ IMPORTANT ETHICAL & LEGAL NOTICE

> **This tool is designed strictly for:**
> - Your own systems
> - Intentionally vulnerable lab machines (Metasploitable, DVWA, VulnHub VMs)
> - Systems for which you have **explicit written authorization**
>
> **Unauthorized scanning of systems you do not own is ILLEGAL.**
> This project is for educational purposes in controlled, authorized environments only.

---

## 📌 Project Overview

**ThreatLens** is a Flask-based web application that demonstrates the complete vulnerability assessment lifecycle:

```
Assessment → Scan → Findings → Risk Analysis → CVE Mapping → Validation → Remediation → Report
```

### Key Features (across all phases)

| Feature | Phase | Status |
|---|---|---|
| Professional Dashboard | 1 | ✅ Done |
| Assessment Management | 2 | ⏳ Pending |
| Nmap Scanner Integration | 3 | ⏳ Pending |
| Vulnerability Analysis | 4 | ⏳ Pending |
| CVE Mapping (NVD API) | 5 | ⏳ Pending |
| Manual Validation | 6 | ⏳ Pending |
| Remediation Guidance | 7 | ⏳ Pending |
| PDF Report Generation | 8 | ⏳ Pending |
| Testing & Polish | 9–10 | ⏳ Pending |

---

## 🏗️ Project Architecture

```
cybersecurity-vulnerability-assessment/
│
├── app.py                    # Flask application factory + entry point
├── requirements.txt          # Python dependencies
├── .gitignore
├── README.md
│
├── database/
│   ├── __init__.py
│   └── db.py                 # SQLAlchemy models + DB init + demo data seed
│
├── routes/
│   ├── __init__.py
│   ├── dashboard.py          # Dashboard statistics & overview
│   ├── assessments.py        # Assessment CRUD routes
│   ├── vulnerabilities.py    # Vulnerability list + detail routes
│   └── reports.py            # Report generation routes
│
├── scanner/                  # Phase 3 — Nmap integration
│   ├── scanner.py            # NmapScanner class (placeholder)
│   └── parser.py             # Scan output parser (placeholder)
│
├── risk/                     # Phase 4 — Risk scoring
│   └── risk_engine.py        # Risk calculation logic (placeholder)
│
├── cve/                      # Phase 5 — CVE lookup
│   └── cve_service.py        # NVD API integration (placeholder)
│
├── reports/                  # Phase 8 — PDF generation
│   └── report_generator.py   # ReportLab PDF generator (placeholder)
│
├── templates/
│   ├── base.html             # Base layout with sidebar + topnav
│   ├── dashboard.html        # Main dashboard
│   ├── new_assessment.html   # New assessment form
│   ├── assessments.html      # Assessment list
│   ├── scan_progress.html    # Assessment detail / scan progress
│   ├── results.html          # Vulnerability results table
│   ├── vulnerability_details.html  # Single vulnerability detail
│   ├── reports.html          # Reports management
│   └── errors/
│       ├── 404.html
│       └── 500.html
│
├── static/
│   ├── css/style.css         # Full dark cybersecurity theme
│   ├── js/main.js            # Animations, chart integration
│   └── images/
│
└── screenshots/              # UI screenshots for README
```

---

## 🗄️ Database Schema

```
┌─────────────┐     ┌──────────────┐     ┌──────────────────┐
│   targets   │◄────│ assessments  │◄────│ vulnerabilities   │
├─────────────┤     ├──────────────┤     ├──────────────────┤
│ id          │     │ id           │     │ id               │
│ name        │     │ name         │     │ assessment_id    │
│ ip_address  │     │ target_id    │     │ name             │
│ description │     │ scan_type    │     │ severity         │
│ os_info     │     │ status       │     │ risk_score       │
│ created_at  │     │ progress     │     │ cvss_score       │
└─────────────┘     │ notes        │     │ cve_id           │
                    │ started_at   │     │ affected_port    │
                    │ completed_at │     │ affected_service │
                    └──────────────┘     │ evidence         │
                                         │ impact           │
                                         │ remediation      │
                         ┌───────────────│ validation_status│
                         │               │ is_false_positive│
                         ▼               └──────────────────┘
              ┌────────────────────┐
              │  validation_records │
              ├────────────────────┤
              │ id                 │
              │ vulnerability_id   │
              │ analyst            │
              │ previous_status    │
              │ new_status         │
              │ notes              │
              │ created_at         │
              └────────────────────┘
                    ┌─────────┐
                    │ reports  │
                    ├─────────┤
                    │ id       │
                    │ assess.. │
                    │ filename │
                    │ file_path│
                    └─────────┘
```

---

## ⚙️ Risk Scoring Logic

The risk scoring system (implemented in `risk/risk_engine.py` in Phase 4) uses the following approach:

### Score Thresholds

| Severity | Risk Score | Priority | SLA |
|---|---|---|---|
| 🔴 Critical | 9.0 – 10.0 | 1 — Immediate | Immediate |
| 🟠 High | 7.0 – 8.9 | 2 — Urgent | 24 hours |
| 🟡 Medium | 4.0 – 6.9 | 3 — Moderate | 7 days |
| 🟢 Low | 0.1 – 3.9 | 4 — Low | 30 days |

### Score Factors (Phase 4)

```
Base Score = CVSS score (if CVE exists) OR heuristic score

Heuristic factors:
+ Port exposure        : External access adds +1.0
+ Plaintext protocol   : FTP, Telnet, HTTP → +1.5
+ No authentication    : Anonymous access → +2.0
+ Known CVE            : +1.5
+ Outdated version     : +1.0
```

---

## 🚀 Getting Started

### Prerequisites

- Python 3.10 or later
- pip
- (Optional) Nmap installed for Phase 3 scanning: https://nmap.org/download

### Installation

**Step 1: Clone the repository**
```bash
git clone <your-repo-url>
cd cybersecurity-vulnerability-assessment
```

**Step 2: Create a virtual environment**
```bash
python -m venv venv
```

**Step 3: Activate virtual environment**

On Windows:
```bash
.\venv\Scripts\activate
```

On Linux/macOS:
```bash
source venv/bin/activate
```

**Step 4: Install dependencies**
```bash
pip install -r requirements.txt
```

**Step 5: Run the application**
```bash
python app.py
```

**Step 6: Open in browser**
```
http://127.0.0.1:5000
```

> The database is created automatically on first launch.
> Demo data is seeded so the dashboard is not empty.

---

## 📦 Dependencies

| Package | Version | Purpose |
|---|---|---|
| Flask | 3.0.3 | Web framework |
| Flask-SQLAlchemy | 3.1.1 | ORM for SQLite |
| SQLAlchemy | 2.0.36 | Database ORM |
| python-dotenv | 1.0.1 | Environment variables |
| reportlab | 4.2.5 | PDF generation (Phase 8) |
| requests | 2.32.3 | HTTP client for CVE API (Phase 5) |
| Werkzeug | 3.0.6 | WSGI utilities |
| python-nmap | 0.7.1 | Nmap integration (Phase 3) |

---

## 🌐 Application Pages

| Page | URL | Description |
|---|---|---|
| Dashboard | `/` | Overview stats, charts, recent activity |
| New Assessment | `/assessments/new` | Configure and start a scan |
| Assessments | `/assessments/` | List all assessment sessions |
| Assessment Detail | `/assessments/<id>` | Scan progress and findings |
| Vulnerabilities | `/vulnerabilities/` | All findings with filters |
| Vulnerability Detail | `/vulnerabilities/<id>` | Full finding details |
| Reports | `/reports/` | PDF report management |

---

## 🔄 Development Phases

### ✅ Phase 1 — Project Setup (CURRENT)
- Flask app with blueprint architecture
- SQLite database with full ORM models
- Professional dark cybersecurity dashboard UI
- Demo data seed for visual testing
- Placeholder routes for all sections
- Requirements and README

### ⏳ Phase 2 — Assessment Module
- Working new assessment form (POST handler)
- Target creation/selection
- Assessment history with edit/delete
- Assessment state machine (pending → running → complete)

### ⏳ Phase 3 — Scanning Engine
- Real Nmap integration via `python-nmap`
- Scan type implementations (basic, full, stealth)
- Scan output XML parsing
- Background scan execution (threading)
- Live progress updates (polling)

### ⏳ Phase 4 — Vulnerability Analysis
- Automatic vulnerability classification from scan results
- Risk score calculation (heuristic + CVSS)
- Severity classification (Critical/High/Medium/Low)
- Priority assignment

### ⏳ Phase 5 — CVE Mapping
- NVD API v2 integration
- CVE lookup per detected service/vulnerability
- CVSS score enrichment
- Local CVE cache (database)

### ⏳ Phase 6 — Manual Validation
- Analyst validation workflow
- Mark: Confirmed / False Positive / Needs Review
- Validation notes and audit trail
- `validation_records` table integration

### ⏳ Phase 7 — Remediation
- Service-specific remediation recommendations
- Linked to vulnerability type and affected service
- Priority-ordered action items

### ⏳ Phase 8 — PDF Reports
- Professional PDF via ReportLab
- Executive summary + technical findings
- Embedded charts and statistics
- Downloadable from the web interface

### ⏳ Phases 9–10 — Testing & Polish
- Controlled lab testing (Metasploitable, DVWA)
- UI improvements and error handling
- GitHub README with screenshots
- Project demonstration documentation

---

## 🖥️ UI Design

- **Theme:** Dark cybersecurity professional
- **Colors:** Navy/slate background, blue accents, severity-coded badges
- **Typography:** Inter (UI) + JetBrains Mono (code/IDs)
- **Charts:** Chart.js (doughnut + bar)
- **Animations:** Count-up stats, animated accent border, hover effects

---

## 📁 Technology Stack

| Layer | Technology |
|---|---|
| Frontend | HTML5, CSS3 (Vanilla), JavaScript |
| Backend | Python 3, Flask |
| Database | SQLite via Flask-SQLAlchemy |
| Scanning | Nmap + python-nmap (Phase 3) |
| CVE Data | NIST NVD API v2 (Phase 5) |
| Reports | ReportLab (Phase 8) |
| Charts | Chart.js (CDN) |
| Fonts | Google Fonts (Inter, JetBrains Mono) |

---

## 🔒 Security Notes

- Intended for localhost use only
- No authentication implemented (academic scope)
- All scan targets must be authorized
- SQLite is used for simplicity; upgrade to PostgreSQL for production
- Demo data uses fictional lab IP addresses only

---

## 👨‍💻 Author

Final-Year B.E. Computer Science Engineering Student
Academic Project — Cybersecurity Module

---

## 📄 License

This project is for educational purposes only.
Not licensed for commercial or production use.
