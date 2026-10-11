"""Dashboard Route Blueprint"""
from flask import Blueprint, render_template
from database.db import db, Assessment, Vulnerability, Target

dashboard_bp = Blueprint('dashboard', __name__)


@dashboard_bp.route('/')
@dashboard_bp.route('/dashboard')
def index():
    """Main dashboard with statistics and recent activity."""

    # --- Summary Statistics ---
    total_assessments   = Assessment.query.count()
    total_targets       = Target.query.count()
    total_vulns         = Vulnerability.query.count()
    critical_count      = Vulnerability.query.filter_by(severity='Critical').count()
    high_count          = Vulnerability.query.filter_by(severity='High').count()
    medium_count        = Vulnerability.query.filter_by(severity='Medium').count()
    low_count           = Vulnerability.query.filter_by(severity='Low').count()
    confirmed_count     = Vulnerability.query.filter_by(validation_status='Confirmed').count()
    false_positive_count = Vulnerability.query.filter_by(is_false_positive=True).count()

    # --- Recent Assessments (last 5) ---
    recent_assessments = (
        Assessment.query
        .order_by(Assessment.created_at.desc())
        .limit(5)
        .all()
    )

    # --- Recent Vulnerabilities (last 5, highest risk first) ---
    recent_vulns = (
        Vulnerability.query
        .filter(Vulnerability.is_false_positive == False)
        .order_by(Vulnerability.risk_score.desc())
        .limit(5)
        .all()
    )

    # --- Chart data: severity distribution ---
    severity_chart = {
        'labels':  ['Critical', 'High', 'Medium', 'Low'],
        'values':  [critical_count, high_count, medium_count, low_count],
        'colors':  ['#ef4444', '#f97316', '#eab308', '#22c55e'],
    }

    # --- Assessment status breakdown ---
    completed_assessments = Assessment.query.filter_by(status='completed').count()
    pending_assessments   = Assessment.query.filter_by(status='pending').count()
    running_assessments   = Assessment.query.filter_by(status='running').count()
    failed_assessments    = Assessment.query.filter_by(status='failed').count()

    return render_template(
        'dashboard.html',
        active_page='dashboard',
        total_assessments=total_assessments,
        total_targets=total_targets,
        total_vulns=total_vulns,
        critical_count=critical_count,
        high_count=high_count,
        medium_count=medium_count,
        low_count=low_count,
        confirmed_count=confirmed_count,
        false_positive_count=false_positive_count,
        recent_assessments=recent_assessments,
        recent_vulns=recent_vulns,
        severity_chart=severity_chart,
        completed_assessments=completed_assessments,
        pending_assessments=pending_assessments,
        running_assessments=running_assessments,
        failed_assessments=failed_assessments,
    )
