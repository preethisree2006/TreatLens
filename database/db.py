"""
Database Models & Initialization
=================================
Defines all SQLAlchemy ORM models for the Cybersecurity
Vulnerability Assessment & Risk Management System.

Tables:
    - Target          : Systems being assessed
    - Assessment      : Individual scan sessions
    - Vulnerability   : Detected security findings
    - ValidationRecord: Analyst validation notes
    - Report          : Generated assessment reports
"""

from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
import json

db = SQLAlchemy()


# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------

class Target(db.Model):
    """Represents a system/host being assessed."""
    __tablename__ = 'targets'

    id          = db.Column(db.Integer, primary_key=True)
    name        = db.Column(db.String(128), nullable=False)
    ip_address  = db.Column(db.String(64), nullable=False)
    description = db.Column(db.Text, default='')
    os_info     = db.Column(db.String(128), default='Unknown')
    created_at  = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at  = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships
    assessments = db.relationship('Assessment', back_populates='target', lazy='dynamic')

    def __repr__(self):
        return f'<Target {self.name} ({self.ip_address})>'

    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'ip_address': self.ip_address,
            'description': self.description,
            'os_info': self.os_info,
            'created_at': self.created_at.isoformat(),
        }


class Assessment(db.Model):
    """Represents a single vulnerability assessment session."""
    __tablename__ = 'assessments'

    # Status constants
    STATUS_PENDING    = 'pending'
    STATUS_RUNNING    = 'running'
    STATUS_COMPLETED  = 'completed'
    STATUS_FAILED     = 'failed'
    STATUS_CANCELLED  = 'cancelled'

    id              = db.Column(db.Integer, primary_key=True)
    name            = db.Column(db.String(128), nullable=False)
    target_id       = db.Column(db.Integer, db.ForeignKey('targets.id'), nullable=False)
    scan_type       = db.Column(db.String(64), default='basic')   # basic | full | stealth | custom
    status          = db.Column(db.String(32), default=STATUS_PENDING)
    progress        = db.Column(db.Integer, default=0)            # 0–100 %
    notes           = db.Column(db.Text, default='')
    started_at      = db.Column(db.DateTime, nullable=True)
    completed_at    = db.Column(db.DateTime, nullable=True)
    created_at      = db.Column(db.DateTime, default=datetime.utcnow)

    # Relationships
    target          = db.relationship('Target', back_populates='assessments')
    vulnerabilities = db.relationship('Vulnerability', back_populates='assessment', lazy='dynamic')
    reports         = db.relationship('Report', back_populates='assessment', lazy='dynamic')

    def __repr__(self):
        return f'<Assessment {self.name} [{self.status}]>'

    @property
    def vulnerability_count(self):
        return self.vulnerabilities.count()

    @property
    def critical_count(self):
        return self.vulnerabilities.filter_by(severity='Critical').count()

    @property
    def high_count(self):
        return self.vulnerabilities.filter_by(severity='High').count()

    @property
    def medium_count(self):
        return self.vulnerabilities.filter_by(severity='Medium').count()

    @property
    def low_count(self):
        return self.vulnerabilities.filter_by(severity='Low').count()

    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'target': self.target.to_dict() if self.target else None,
            'scan_type': self.scan_type,
            'status': self.status,
            'progress': self.progress,
            'vulnerability_count': self.vulnerability_count,
            'critical_count': self.critical_count,
            'high_count': self.high_count,
            'medium_count': self.medium_count,
            'low_count': self.low_count,
            'started_at': self.started_at.isoformat() if self.started_at else None,
            'completed_at': self.completed_at.isoformat() if self.completed_at else None,
            'created_at': self.created_at.isoformat(),
        }


class Vulnerability(db.Model):
    """Represents a single security finding detected during an assessment."""
    __tablename__ = 'vulnerabilities'

    # Severity constants
    SEV_CRITICAL = 'Critical'
    SEV_HIGH     = 'High'
    SEV_MEDIUM   = 'Medium'
    SEV_LOW      = 'Low'
    SEV_INFO     = 'Informational'

    # Validation status constants
    VAL_UNVERIFIED    = 'Unverified'
    VAL_CONFIRMED     = 'Confirmed'
    VAL_FALSE_POSITIVE = 'False Positive'
    VAL_NEEDS_REVIEW  = 'Needs Review'

    id                 = db.Column(db.Integer, primary_key=True)
    assessment_id      = db.Column(db.Integer, db.ForeignKey('assessments.id'), nullable=False)
    name               = db.Column(db.String(256), nullable=False)
    description        = db.Column(db.Text, default='')
    severity           = db.Column(db.String(32), default=SEV_MEDIUM)
    risk_score         = db.Column(db.Float, default=0.0)   # 0.0–10.0
    cvss_score         = db.Column(db.Float, nullable=True)
    cve_id             = db.Column(db.String(32), nullable=True)
    cve_description    = db.Column(db.Text, nullable=True)
    affected_port      = db.Column(db.Integer, nullable=True)
    affected_service   = db.Column(db.String(64), nullable=True)
    affected_protocol  = db.Column(db.String(16), nullable=True)
    evidence           = db.Column(db.Text, default='')
    impact             = db.Column(db.Text, default='')
    remediation        = db.Column(db.Text, default='')
    validation_status  = db.Column(db.String(32), default=VAL_UNVERIFIED)
    validation_notes   = db.Column(db.Text, default='')
    is_false_positive  = db.Column(db.Boolean, default=False)
    source             = db.Column(db.String(64), default='nmap')  # nmap | manual | openvas
    raw_data           = db.Column(db.Text, default='{}')          # JSON blob
    discovered_at      = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at         = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships
    assessment         = db.relationship('Assessment', back_populates='vulnerabilities')
    validation_records = db.relationship('ValidationRecord', back_populates='vulnerability', lazy='dynamic')

    def __repr__(self):
        return f'<Vulnerability {self.name} [{self.severity}]>'

    @property
    def severity_badge_class(self):
        mapping = {
            'Critical': 'badge-critical',
            'High':     'badge-high',
            'Medium':   'badge-medium',
            'Low':      'badge-low',
            'Informational': 'badge-info',
        }
        return mapping.get(self.severity, 'badge-info')

    @property
    def priority(self):
        """Returns numeric priority (lower = more urgent)."""
        mapping = {
            'Critical': 1,
            'High':     2,
            'Medium':   3,
            'Low':      4,
            'Informational': 5,
        }
        return mapping.get(self.severity, 5)

    def get_raw_data(self):
        try:
            return json.loads(self.raw_data)
        except Exception:
            return {}

    def to_dict(self):
        return {
            'id': self.id,
            'assessment_id': self.assessment_id,
            'name': self.name,
            'description': self.description,
            'severity': self.severity,
            'risk_score': self.risk_score,
            'cvss_score': self.cvss_score,
            'cve_id': self.cve_id,
            'affected_port': self.affected_port,
            'affected_service': self.affected_service,
            'evidence': self.evidence,
            'impact': self.impact,
            'remediation': self.remediation,
            'validation_status': self.validation_status,
            'is_false_positive': self.is_false_positive,
            'source': self.source,
            'discovered_at': self.discovered_at.isoformat(),
        }


class ValidationRecord(db.Model):
    """Audit log of every validation action taken on a vulnerability."""
    __tablename__ = 'validation_records'

    id               = db.Column(db.Integer, primary_key=True)
    vulnerability_id = db.Column(db.Integer, db.ForeignKey('vulnerabilities.id'), nullable=False)
    analyst          = db.Column(db.String(64), default='Analyst')
    previous_status  = db.Column(db.String(32))
    new_status       = db.Column(db.String(32))
    notes            = db.Column(db.Text, default='')
    created_at       = db.Column(db.DateTime, default=datetime.utcnow)

    # Relationship
    vulnerability    = db.relationship('Vulnerability', back_populates='validation_records')

    def __repr__(self):
        return f'<ValidationRecord vuln={self.vulnerability_id} {self.new_status}>'


class Report(db.Model):
    """Tracks generated PDF assessment reports."""
    __tablename__ = 'reports'

    id            = db.Column(db.Integer, primary_key=True)
    assessment_id = db.Column(db.Integer, db.ForeignKey('assessments.id'), nullable=False)
    filename      = db.Column(db.String(256), nullable=False)
    file_path     = db.Column(db.String(512), nullable=False)
    generated_at  = db.Column(db.DateTime, default=datetime.utcnow)
    generated_by  = db.Column(db.String(64), default='System')

    # Relationship
    assessment    = db.relationship('Assessment', back_populates='reports')

    def __repr__(self):
        return f'<Report {self.filename}>'


# ---------------------------------------------------------------------------
# Database Initialisation Helper
# ---------------------------------------------------------------------------

def init_db(app):
    """Create all tables and optionally seed demo data."""
    with app.app_context():
        db.create_all()
        _seed_demo_data()


def _seed_demo_data():
    """
    Seeds a small set of demo records so the dashboard is not empty
    on first launch. Safe demo data only — no real scan results.
    """
    if Target.query.count() > 0:
        return   # Already seeded

    # --- Demo Targets ---
    t1 = Target(
        name='Local Lab VM — Metasploitable',
        ip_address='192.168.1.100',
        description='Intentionally vulnerable VM used for security testing.',
        os_info='Linux (Ubuntu 8.04)',
    )
    t2 = Target(
        name='DVWA Server',
        ip_address='192.168.1.101',
        description='Damn Vulnerable Web Application for testing.',
        os_info='Linux (Debian)',
    )
    t3 = Target(
        name='Windows Lab Machine',
        ip_address='192.168.1.102',
        description='Windows Server 2012 R2 lab machine.',
        os_info='Windows Server 2012 R2',
    )
    db.session.add_all([t1, t2, t3])
    db.session.flush()

    # --- Demo Assessments ---
    a1 = Assessment(
        name='Initial Lab Scan — Metasploitable',
        target_id=t1.id,
        scan_type='full',
        status=Assessment.STATUS_COMPLETED,
        progress=100,
        started_at=datetime(2026, 10, 10, 9, 0, 0),
        completed_at=datetime(2026, 10, 10, 9, 45, 0),
    )
    a2 = Assessment(
        name='DVWA Web Assessment',
        target_id=t2.id,
        scan_type='basic',
        status=Assessment.STATUS_COMPLETED,
        progress=100,
        started_at=datetime(2026, 10, 11, 10, 0, 0),
        completed_at=datetime(2026, 10, 11, 10, 30, 0),
    )
    a3 = Assessment(
        name='Windows Server Baseline',
        target_id=t3.id,
        scan_type='basic',
        status=Assessment.STATUS_PENDING,
        progress=0,
    )
    db.session.add_all([a1, a2, a3])
    db.session.flush()

    # --- Demo Vulnerabilities ---
    vulns = [
        Vulnerability(
            assessment_id=a1.id,
            name='Unencrypted FTP Service Running',
            description='The target exposes an FTP service on port 21 that does not enforce encryption. Credentials are transmitted in plaintext.',
            severity='High',
            risk_score=7.5,
            cvss_score=7.5,
            cve_id='CVE-1999-0497',
            cve_description='Anonymous FTP login allowed.',
            affected_port=21,
            affected_service='ftp',
            affected_protocol='tcp',
            evidence='PORT 21/tcp open ftp vsftpd 2.3.4',
            impact='Attackers can intercept credentials and gain unauthorized file access.',
            remediation='Disable FTP. Use SFTP or FTPS instead. If FTP is required, enforce encryption.',
            validation_status='Confirmed',
            source='nmap',
        ),
        Vulnerability(
            assessment_id=a1.id,
            name='Outdated SSH Version with Known Vulnerabilities',
            description='SSH service is running an outdated OpenSSH version with multiple known vulnerabilities.',
            severity='Critical',
            risk_score=9.1,
            cvss_score=9.1,
            cve_id='CVE-2023-38408',
            cve_description='Remote code execution in ssh-agent.',
            affected_port=22,
            affected_service='ssh',
            affected_protocol='tcp',
            evidence='PORT 22/tcp open ssh OpenSSH 4.7p1 Debian 8ubuntu1',
            impact='Remote code execution is possible, leading to full system compromise.',
            remediation='Upgrade OpenSSH to the latest stable version. Apply OS security patches.',
            validation_status='Confirmed',
            source='nmap',
        ),
        Vulnerability(
            assessment_id=a1.id,
            name='Telnet Service Exposed',
            description='Telnet transmits all data, including passwords, in plaintext over the network.',
            severity='Critical',
            risk_score=9.8,
            cvss_score=9.8,
            cve_id=None,
            affected_port=23,
            affected_service='telnet',
            affected_protocol='tcp',
            evidence='PORT 23/tcp open telnet Linux telnetd',
            impact='Network eavesdropping allows credential theft and session hijacking.',
            remediation='Disable Telnet service immediately. Replace with SSH for all remote access.',
            validation_status='Confirmed',
            source='nmap',
        ),
        Vulnerability(
            assessment_id=a1.id,
            name='SMB Service Open — EternalBlue Risk',
            description='Windows SMBv1 service is enabled. SMBv1 is vulnerable to EternalBlue and related exploits.',
            severity='Critical',
            risk_score=9.8,
            cvss_score=9.8,
            cve_id='CVE-2017-0144',
            cve_description='EternalBlue — Remote code execution via SMBv1.',
            affected_port=445,
            affected_service='microsoft-ds',
            affected_protocol='tcp',
            evidence='PORT 445/tcp open microsoft-ds Samba smbd 3.0.20',
            impact='Wormable remote code execution without authentication (e.g., WannaCry, NotPetya).',
            remediation='Disable SMBv1. Apply MS17-010 patch. Block port 445 at the network boundary.',
            validation_status='Needs Review',
            source='nmap',
        ),
        Vulnerability(
            assessment_id=a1.id,
            name='HTTP Server Without HTTPS',
            description='Web server running on port 80 without TLS encryption.',
            severity='Medium',
            risk_score=5.3,
            cvss_score=5.3,
            cve_id=None,
            affected_port=80,
            affected_service='http',
            affected_protocol='tcp',
            evidence='PORT 80/tcp open http Apache httpd 2.2.8',
            impact='Sensitive data, session cookies, and credentials may be intercepted in transit.',
            remediation='Configure TLS/SSL. Redirect all HTTP to HTTPS. Use HSTS headers.',
            validation_status='Unverified',
            source='nmap',
        ),
        Vulnerability(
            assessment_id=a1.id,
            name='MySQL Listening on External Interface',
            description='MySQL database is accessible on a non-loopback interface.',
            severity='High',
            risk_score=7.8,
            cvss_score=7.8,
            cve_id=None,
            affected_port=3306,
            affected_service='mysql',
            affected_protocol='tcp',
            evidence='PORT 3306/tcp open mysql MySQL 5.0.51a-3ubuntu5',
            impact='Remote attackers can attempt to connect to the database service directly.',
            remediation='Bind MySQL to 127.0.0.1. Use a firewall to block external access on port 3306.',
            validation_status='Unverified',
            source='nmap',
        ),
        Vulnerability(
            assessment_id=a2.id,
            name='SQL Injection in Login Form',
            description='The login page is vulnerable to SQL injection. Authentication can be bypassed.',
            severity='Critical',
            risk_score=10.0,
            cvss_score=10.0,
            cve_id=None,
            affected_port=80,
            affected_service='http',
            affected_protocol='tcp',
            evidence="Payload: ' OR '1'='1 bypasses authentication.",
            impact='Full database compromise. Authentication bypass. Data exfiltration.',
            remediation='Use parameterized queries (prepared statements). Validate and sanitize all inputs.',
            validation_status='Confirmed',
            source='manual',
        ),
        Vulnerability(
            assessment_id=a2.id,
            name='Reflected Cross-Site Scripting (XSS)',
            description='User input is reflected in the page without sanitization, enabling script injection.',
            severity='High',
            risk_score=6.1,
            cvss_score=6.1,
            cve_id=None,
            affected_port=80,
            affected_service='http',
            affected_protocol='tcp',
            evidence='<script>alert(1)</script> executed in vulnerable parameter.',
            impact='Session hijacking, phishing, credential theft via malicious script execution.',
            remediation='Encode all user-supplied output. Implement Content-Security-Policy headers.',
            validation_status='Confirmed',
            source='manual',
        ),
        Vulnerability(
            assessment_id=a2.id,
            name='Directory Listing Enabled',
            description='Web server exposes directory contents, revealing file structure.',
            severity='Low',
            risk_score=3.5,
            cvss_score=3.5,
            cve_id=None,
            affected_port=80,
            affected_service='http',
            affected_protocol='tcp',
            evidence='GET /uploads/ returns directory listing.',
            impact='Information disclosure: attackers can enumerate files and directories.',
            remediation='Disable directory listing in the web server configuration (Options -Indexes).',
            validation_status='Unverified',
            source='manual',
        ),
    ]
    db.session.add_all(vulns)
    db.session.commit()
    print("[DB] Demo data seeded successfully.")
