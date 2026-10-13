"""
Dashboard Route Blueprint — ThreatLens
======================================
Serves the central security operations center dashboard driven entirely
by live SQLite database records across assessments, scans, and findings.
"""

from flask import Blueprint, render_template
from database.db import db, Assessment, Scan, Vulnerability

dashboard_bp = Blueprint('dashboard', __name__)


@dashboard_bp.route('/')
@dashboard_bp.route('/dashboard')
def index():
    """Main operations dashboard with real-time cybersecurity metrics."""

    # --- Assessment Metrics ---
    total_assessments = Assessment.query.count()
    if total_assessments > 0:
        total_targets = db.session.query(Assessment.target).distinct().count()
    else:
        total_targets = 0

    # --- Scan Metrics ---
    total_scans = Scan.query.count()
    completed_scans = Scan.query.filter_by(status='Completed').count()
    failed_scans = Scan.query.filter_by(status='Failed').count()
    running_scans = Scan.query.filter_by(status='Running').count()

    # --- Vulnerability Finding Metrics (Real Evidence-based) ---
    all_vulns_query = Vulnerability.query
    total_vulns = all_vulns_query.count()

    # Active findings exclude false positives
    active_vulns_query = all_vulns_query.filter_by(is_false_positive=False)
    active_vulns = active_vulns_query.count()

    critical_count = active_vulns_query.filter_by(severity='Critical').count()
    high_count = active_vulns_query.filter_by(severity='High').count()
    medium_count = active_vulns_query.filter_by(severity='Medium').count()
    low_count = active_vulns_query.filter_by(severity='Low').count()
    info_count = active_vulns_query.filter_by(severity='Informational').count()

    confirmed_count = active_vulns_query.filter_by(validation_status='Confirmed').count()
    needs_review_count = active_vulns_query.filter_by(validation_status='Needs Review').count()
    false_positive_count = all_vulns_query.filter_by(is_false_positive=True).count()

    # --- Recent Activity (Last 5 records) ---
    recent_assessments = (
        Assessment.query
        .order_by(Assessment.created_at.desc())
        .limit(5)
        .all()
    )

    recent_scans = (
        Scan.query
        .order_by(Scan.started_at.desc())
        .limit(5)
        .all()
    )

    recent_vulns = (
        active_vulns_query
        .order_by(Vulnerability.priority.asc(), Vulnerability.risk_score.desc())
        .limit(5)
        .all()
    )

    # --- Charts Data ---
    severity_chart = {
        'labels': ['Critical', 'High', 'Medium', 'Low', 'Informational'],
        'values': [critical_count, high_count, medium_count, low_count, info_count],
        'colors': ['#ef4444', '#f97316', '#eab308', '#22c55e', '#64748b'],
    }

    scan_status_chart = {
        'labels': ['Completed', 'Running', 'Failed'],
        'values': [completed_scans, running_scans, failed_scans],
        'colors': ['#22c55e', '#3b82f6', '#ef4444'],
    }

    # Assessment Status counts for charts
    created_assessments = Assessment.query.filter(Assessment.status.in_(['Created', 'created'])).count()
    running_assessments = Assessment.query.filter(Assessment.status.in_(['Running', 'running'])).count()
    completed_assessments = Assessment.query.filter(Assessment.status.in_(['Completed', 'completed'])).count()
    failed_assessments = Assessment.query.filter(Assessment.status.in_(['Failed', 'failed'])).count()
    pending_assessments = Assessment.query.filter(Assessment.status.in_(['Pending', 'pending'])).count()

    return render_template(
        'dashboard.html',
        active_page='dashboard',
        total_assessments=total_assessments,
        total_targets=total_targets,
        total_scans=total_scans,
        completed_scans=completed_scans,
        failed_scans=failed_scans,
        running_scans=running_scans,
        total_vulns=total_vulns,
        active_vulns=active_vulns,
        critical_count=critical_count,
        high_count=high_count,
        medium_count=medium_count,
        low_count=low_count,
        info_count=info_count,
        confirmed_count=confirmed_count,
        needs_review_count=needs_review_count,
        false_positive_count=false_positive_count,
        recent_assessments=recent_assessments,
        recent_scans=recent_scans,
        recent_vulns=recent_vulns,
        severity_chart=severity_chart,
        scan_status_chart=scan_status_chart,
        created_assessments=created_assessments,
        running_assessments=running_assessments,
        completed_assessments=completed_assessments,
        failed_assessments=failed_assessments,
        pending_assessments=pending_assessments,
    )
