"""
ThreatLens — Database Models & Schema Management
=================================================
Defines SQLAlchemy ORM models for the complete vulnerability assessment,
scanning, risk scoring, validation, and reporting lifecycle.

Models:
    - Assessment      : Target assessment session
    - Scan            : Nmap execution record
    - ScanResult      : Discovered ports and services
    - Vulnerability   : Rule-based security findings from scan evidence
    - ValidationRecord: Audit trail of analyst review actions
    - CVERecord       : Locally cached CVE intelligence
    - Report          : Generated PDF security assessment reports
"""

import json
from datetime import datetime
from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()


# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------

class Assessment(db.Model):
    """Represents a vulnerability assessment session for an authorized target."""
    __tablename__ = 'assessments'

    STATUS_CREATED    = 'Created'
    STATUS_RUNNING    = 'Running'
    STATUS_COMPLETED  = 'Completed'
    STATUS_FAILED     = 'Failed'
    STATUS_CANCELLED  = 'Cancelled'

    id              = db.Column(db.Integer, primary_key=True, autoincrement=True)
    assessment_id   = db.Column(db.String(32), unique=True, nullable=False, index=True)
    name            = db.Column(db.String(128), nullable=False)
    target          = db.Column(db.String(128), nullable=False)
    description     = db.Column(db.Text, nullable=False, default='')
    status          = db.Column(db.String(32), nullable=False, default=STATUS_CREATED)
    created_at      = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at      = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Scopes and operational metadata
    scan_type       = db.Column(db.String(64), default='basic')
    progress        = db.Column(db.Integer, default=0)
    notes           = db.Column(db.Text, default='')
    started_at      = db.Column(db.DateTime, nullable=True)
    completed_at    = db.Column(db.DateTime, nullable=True)

    # Relationships
    scans           = db.relationship('Scan', back_populates='assessment', cascade='all, delete-orphan', lazy='dynamic')
    vulnerabilities = db.relationship('Vulnerability', back_populates='assessment', cascade='all, delete-orphan', lazy='dynamic')
    reports         = db.relationship('Report', back_populates='assessment', cascade='all, delete-orphan', lazy='dynamic')

    def __repr__(self):
        return f'<Assessment {self.assessment_id} - {self.name} [{self.status}]>'

    @property
    def latest_scan(self):
        return self.scans.order_by(Scan.started_at.desc()).first()

    @property
    def scan_status(self):
        latest = self.latest_scan
        return latest.status if latest else 'Not Started'

    @property
    def last_scanned_at(self):
        latest = self.latest_scan
        return latest.completed_at or latest.started_at if latest else None

    # Vulnerability counts (excluding false positives from active risk)
    @property
    def active_vulns(self):
        return self.vulnerabilities.filter_by(is_false_positive=False)

    @property
    def vulnerability_count(self):
        return self.active_vulns.count()

    @property
    def critical_count(self):
        return self.active_vulns.filter_by(severity='Critical').count()

    @property
    def high_count(self):
        return self.active_vulns.filter_by(severity='High').count()

    @property
    def medium_count(self):
        return self.active_vulns.filter_by(severity='Medium').count()

    @property
    def low_count(self):
        return self.active_vulns.filter_by(severity='Low').count()

    @property
    def info_count(self):
        return self.active_vulns.filter_by(severity='Informational').count()

    @property
    def false_positive_count(self):
        return self.vulnerabilities.filter_by(is_false_positive=True).count()

    @property
    def confirmed_count(self):
        return self.vulnerabilities.filter_by(validation_status='Confirmed', is_false_positive=False).count()

    @property
    def needs_review_count(self):
        return self.vulnerabilities.filter_by(validation_status='Needs Review', is_false_positive=False).count()

    def to_dict(self):
        return {
            'id': self.id,
            'assessment_id': self.assessment_id,
            'name': self.name,
            'target': self.target,
            'description': self.description,
            'status': self.status,
            'scan_status': self.scan_status,
            'vulnerability_count': self.vulnerability_count,
            'critical_count': self.critical_count,
            'high_count': self.high_count,
            'medium_count': self.medium_count,
            'low_count': self.low_count,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None,
        }


class Scan(db.Model):
    """Represents an execution of an Nmap network/service discovery scan."""
    __tablename__ = 'scans'

    STATUS_NOT_STARTED = 'Not Started'
    STATUS_RUNNING     = 'Running'
    STATUS_COMPLETED   = 'Completed'
    STATUS_FAILED      = 'Failed'

    id             = db.Column(db.Integer, primary_key=True, autoincrement=True)
    scan_id        = db.Column(db.String(32), unique=True, nullable=False, index=True)
    assessment_id  = db.Column(db.Integer, db.ForeignKey('assessments.id'), nullable=False)
    target         = db.Column(db.String(128), nullable=False)
    status         = db.Column(db.String(32), nullable=False, default=STATUS_NOT_STARTED)
    started_at     = db.Column(db.DateTime, default=datetime.utcnow)
    completed_at   = db.Column(db.DateTime, nullable=True)
    command_used   = db.Column(db.String(256), default='')
    raw_output     = db.Column(db.Text, default='')
    error_message  = db.Column(db.Text, default='')

    # Relationships
    assessment     = db.relationship('Assessment', back_populates='scans')
    results        = db.relationship('ScanResult', back_populates='scan', cascade='all, delete-orphan', lazy='dynamic')
    vulnerabilities = db.relationship('Vulnerability', back_populates='scan', cascade='all, delete-orphan', lazy='dynamic')

    def __repr__(self):
        return f'<Scan {self.scan_id} on {self.target} [{self.status}]>'

    @property
    def result_count(self):
        return self.results.count()

    @property
    def duration_seconds(self):
        if self.started_at and self.completed_at:
            return round((self.completed_at - self.started_at).total_seconds(), 1)
        return None

    def to_dict(self):
        return {
            'id': self.id,
            'scan_id': self.scan_id,
            'assessment_id': self.assessment_id,
            'target': self.target,
            'status': self.status,
            'started_at': self.started_at.isoformat() if self.started_at else None,
            'completed_at': self.completed_at.isoformat() if self.completed_at else None,
            'duration_seconds': self.duration_seconds,
            'command_used': self.command_used,
            'result_count': self.result_count,
            'error_message': self.error_message,
        }


class ScanResult(db.Model):
    """Represents an individual port and service discovered by Nmap."""
    __tablename__ = 'scan_results'

    id          = db.Column(db.Integer, primary_key=True, autoincrement=True)
    scan_id     = db.Column(db.Integer, db.ForeignKey('scans.id'), nullable=False)
    host        = db.Column(db.String(128), nullable=False)
    port        = db.Column(db.Integer, nullable=False)
    protocol    = db.Column(db.String(16), nullable=False, default='tcp')
    state       = db.Column(db.String(32), nullable=False, default='open')
    service     = db.Column(db.String(64), nullable=False, default='unknown')
    product     = db.Column(db.String(128), default='')
    version     = db.Column(db.String(64), default='')
    extra_info  = db.Column(db.String(128), default='')
    created_at  = db.Column(db.DateTime, default=datetime.utcnow)

    # Relationships
    scan        = db.relationship('Scan', back_populates='results')

    def __repr__(self):
        return f'<ScanResult {self.port}/{self.protocol} {self.service} [{self.state}]>'

    def to_dict(self):
        return {
            'id': self.id,
            'scan_id': self.scan_id,
            'host': self.host,
            'port': self.port,
            'protocol': self.protocol,
            'state': self.state,
            'service': self.service,
            'product': self.product,
            'version': self.version,
            'extra_info': self.extra_info,
        }


class Vulnerability(db.Model):
    """
    Represents a rule-based security finding identified from scan evidence.
    Includes risk scoring, CVE correlation, validation audit, and remediation.
    """
    __tablename__ = 'vulnerabilities'

    # Severity constants
    SEV_CRITICAL      = 'Critical'
    SEV_HIGH          = 'High'
    SEV_MEDIUM        = 'Medium'
    SEV_LOW           = 'Low'
    SEV_INFO          = 'Informational'

    # Validation status constants
    VAL_NEEDS_REVIEW   = 'Needs Review'
    VAL_CONFIRMED      = 'Confirmed'
    VAL_FALSE_POSITIVE = 'False Positive'
    VAL_RESOLVED       = 'Resolved'

    id                 = db.Column(db.Integer, primary_key=True, autoincrement=True)
    finding_id         = db.Column(db.String(32), unique=True, nullable=True, index=True)
    assessment_id      = db.Column(db.Integer, db.ForeignKey('assessments.id'), nullable=False)
    scan_id            = db.Column(db.Integer, db.ForeignKey('scans.id'), nullable=True, index=True)
    affected_host      = db.Column(db.String(128), default='')
    name               = db.Column(db.String(256), nullable=False)
    description        = db.Column(db.Text, default='')
    severity           = db.Column(db.String(32), default=SEV_MEDIUM)
    confidence         = db.Column(db.String(32), default='Medium') # High | Medium | Low
    risk_score         = db.Column(db.Float, default=5.0)           # 0.0 – 10.0
    impact             = db.Column(db.Float, default=5.0)           # 1.0 – 10.0
    likelihood         = db.Column(db.Float, default=5.0)           # 1.0 – 10.0
    cvss_score         = db.Column(db.Float, nullable=True)
    cve_id             = db.Column(db.String(32), nullable=True)
    cve_description    = db.Column(db.Text, nullable=True)
    cve_url            = db.Column(db.String(256), nullable=True)
    affected_port      = db.Column(db.Integer, nullable=True)
    affected_service   = db.Column(db.String(64), nullable=True)
    affected_protocol  = db.Column(db.String(16), default='tcp')
    product            = db.Column(db.String(128), default='')
    version            = db.Column(db.String(64), default='')
    evidence           = db.Column(db.Text, default='')
    remediation        = db.Column(db.Text, default='')
    recommended_action = db.Column(db.Text, default='')
    priority           = db.Column(db.Integer, default=3)           # 1 (Critical) to 5 (Info)

    # Validation
    validation_status  = db.Column(db.String(32), default=VAL_NEEDS_REVIEW)
    validation_notes   = db.Column(db.Text, default='')
    validator_name     = db.Column(db.String(64), default='Security Analyst')
    validated_at       = db.Column(db.DateTime, nullable=True)
    is_false_positive  = db.Column(db.Boolean, default=False)
    source             = db.Column(db.String(64), default='nmap_rule_engine')
    raw_data           = db.Column(db.Text, default='{}')

    discovered_at      = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at         = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships
    assessment         = db.relationship('Assessment', back_populates='vulnerabilities')
    scan               = db.relationship('Scan', back_populates='vulnerabilities')
    validation_records = db.relationship('ValidationRecord', back_populates='vulnerability', cascade='all, delete-orphan', lazy='dynamic')

    def __repr__(self):
        return f'<Vulnerability {self.finding_id or self.id} - {self.name} [{self.severity}]>'

    @property
    def severity_badge_class(self):
        mapping = {
            'Critical':      'badge-critical',
            'High':          'badge-high',
            'Medium':        'badge-medium',
            'Low':           'badge-low',
            'Informational': 'badge-info',
        }
        return mapping.get(self.severity, 'badge-info')

    @property
    def priority_label(self):
        labels = {
            1: 'P1 — Critical (Immediate)',
            2: 'P2 — High (24h)',
            3: 'P3 — Medium (7d)',
            4: 'P4 — Low (30d)',
            5: 'P5 — Informational',
        }
        return labels.get(self.priority, f'P{self.priority}')

    def to_dict(self):
        return {
            'id': self.id,
            'finding_id': self.finding_id or f'VULN-{self.id}',
            'assessment_id': self.assessment_id,
            'scan_id': self.scan_id,
            'affected_host': self.affected_host,
            'name': self.name,
            'description': self.description,
            'severity': self.severity,
            'risk_score': self.risk_score,
            'cvss_score': self.cvss_score,
            'cve_id': self.cve_id,
            'affected_port': self.affected_port,
            'affected_service': self.affected_service,
            'affected_protocol': self.affected_protocol,
            'product': self.product,
            'version': self.version,
            'evidence': self.evidence,
            'remediation': self.remediation,
            'validation_status': self.validation_status,
            'is_false_positive': self.is_false_positive,
            'priority': self.priority,
            'discovered_at': self.discovered_at.isoformat() if self.discovered_at else None,
        }


class ValidationRecord(db.Model):
    """Audit log of analyst review decisions on findings."""
    __tablename__ = 'validation_records'

    id               = db.Column(db.Integer, primary_key=True, autoincrement=True)
    vulnerability_id = db.Column(db.Integer, db.ForeignKey('vulnerabilities.id'), nullable=False)
    analyst          = db.Column(db.String(64), default='Security Analyst')
    previous_status  = db.Column(db.String(32))
    new_status       = db.Column(db.String(32))
    notes            = db.Column(db.Text, default='')
    created_at       = db.Column(db.DateTime, default=datetime.utcnow)

    # Relationship
    vulnerability    = db.relationship('Vulnerability', back_populates='validation_records')

    def __repr__(self):
        return f'<ValidationRecord vuln={self.vulnerability_id} {self.new_status}>'


class CVERecord(db.Model):
    """Local cache of CVE vulnerability information to avoid redundant external API calls."""
    __tablename__ = 'cve_records'

    id            = db.Column(db.Integer, primary_key=True, autoincrement=True)
    cve_id        = db.Column(db.String(32), unique=True, nullable=False, index=True)
    description   = db.Column(db.Text, default='')
    cvss_score    = db.Column(db.Float, nullable=True)
    severity      = db.Column(db.String(32), default='Medium')
    reference_url = db.Column(db.String(256), default='')
    cached_at     = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f'<CVERecord {self.cve_id}>'


class Report(db.Model):
    """Tracks generated PDF security assessment reports."""
    __tablename__ = 'reports'

    id            = db.Column(db.Integer, primary_key=True, autoincrement=True)
    report_id     = db.Column(db.String(32), unique=True, nullable=True, index=True)
    assessment_id = db.Column(db.Integer, db.ForeignKey('assessments.id'), nullable=False)
    filename      = db.Column(db.String(256), nullable=False)
    file_path     = db.Column(db.String(512), nullable=False)
    report_type   = db.Column(db.String(32), default='full') # full | executive
    summary       = db.Column(db.Text, default='')
    generated_at  = db.Column(db.DateTime, default=datetime.utcnow)
    generated_by  = db.Column(db.String(64), default='ThreatLens Engine')

    # Relationship
    assessment    = db.relationship('Assessment', back_populates='reports')

    def __repr__(self):
        return f'<Report {self.report_id or self.id} - {self.filename}>'


# ---------------------------------------------------------------------------
# Database Initialisation & Safe Migration Helper
# ---------------------------------------------------------------------------

def init_db(app):
    """
    Ensure all tables exist and add any missing columns safely
    without deleting existing user assessments or data.
    """
    with app.app_context():
        # 1. Create all missing tables
        db.create_all()

        # 2. Check and migrate table columns if older schema exists
        inspector = db.inspect(db.engine)
        existing_tables = inspector.get_table_names()

        # Migrate vulnerabilities table columns
        if 'vulnerabilities' in existing_tables:
            vuln_cols = [c['name'] for c in inspector.get_columns('vulnerabilities')]
            needed_vuln_cols = [
                ('finding_id', 'VARCHAR(32)'),
                ('scan_id', 'INTEGER'),
                ('affected_host', 'VARCHAR(128) DEFAULT ""'),
                ('confidence', 'VARCHAR(32) DEFAULT "Medium"'),
                ('impact', 'FLOAT DEFAULT 5.0'),
                ('likelihood', 'FLOAT DEFAULT 5.0'),
                ('cve_url', 'VARCHAR(256)'),
                ('product', 'VARCHAR(128) DEFAULT ""'),
                ('version', 'VARCHAR(64) DEFAULT ""'),
                ('recommended_action', 'TEXT DEFAULT ""'),
                ('priority', 'INTEGER DEFAULT 3'),
                ('validator_name', 'VARCHAR(64) DEFAULT "Security Analyst"'),
                ('validated_at', 'DATETIME'),
            ]
            for col_name, col_type in needed_vuln_cols:
                if col_name not in vuln_cols:
                    try:
                        db.session.execute(db.text(f"ALTER TABLE vulnerabilities ADD COLUMN {col_name} {col_type}"))
                        db.session.commit()
                    except Exception:
                        db.session.rollback()

        # Migrate reports table columns
        if 'reports' in existing_tables:
            report_cols = [c['name'] for c in inspector.get_columns('reports')]
            needed_rep_cols = [
                ('report_id', 'VARCHAR(32)'),
                ('report_type', 'VARCHAR(32) DEFAULT "full"'),
                ('summary', 'TEXT DEFAULT ""'),
            ]
            for col_name, col_type in needed_rep_cols:
                if col_name not in report_cols:
                    try:
                        db.session.execute(db.text(f"ALTER TABLE reports ADD COLUMN {col_name} {col_type}"))
                        db.session.commit()
                    except Exception:
                        db.session.rollback()
