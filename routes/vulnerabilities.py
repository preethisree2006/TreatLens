"""
Vulnerabilities Route Blueprint — ThreatLens
============================================
Handles finding listing, multi-factor filtering, detail views,
and interactive analyst validation / false positive management.
"""

from datetime import datetime
from flask import Blueprint, render_template, request, redirect, url_for, flash
from database.db import db, Vulnerability, ValidationRecord, Assessment
from cve.cve_service import get_cve_info

vulnerabilities_bp = Blueprint('vulnerabilities', __name__, url_prefix='/vulnerabilities')


@vulnerabilities_bp.route('/')
def list_vulnerabilities():
    """
    List all detected vulnerabilities with filters:
    - severity: all | critical | high | medium | low | informational
    - status: all | needs_review | confirmed | false_positive | resolved
    - target: optional host filter
    - q: optional search keyword
    """
    severity_filter = request.args.get('severity', 'all').lower()
    status_filter = request.args.get('status', 'all').lower()
    target_filter = request.args.get('target', '').strip()
    search_query = request.args.get('q', '').strip()

    query = Vulnerability.query

    # Severity filter
    if severity_filter != 'all':
        query = query.filter(Vulnerability.severity == severity_filter.capitalize())

    # Status filter
    if status_filter == 'confirmed':
        query = query.filter(Vulnerability.validation_status == 'Confirmed', Vulnerability.is_false_positive == False)
    elif status_filter == 'false_positive':
        query = query.filter(Vulnerability.is_false_positive == True)
    elif status_filter == 'needs_review':
        query = query.filter(Vulnerability.validation_status == 'Needs Review', Vulnerability.is_false_positive == False)
    elif status_filter == 'resolved':
        query = query.filter(Vulnerability.validation_status == 'Resolved')

    # Target filter
    if target_filter:
        query = query.join(Assessment).filter(Assessment.target == target_filter)

    # Search keyword
    if search_query:
        query = query.filter(
            (Vulnerability.name.ilike(f"%{search_query}%")) |
            (Vulnerability.description.ilike(f"%{search_query}%")) |
            (Vulnerability.cve_id.ilike(f"%{search_query}%")) |
            (Vulnerability.affected_service.ilike(f"%{search_query}%"))
        )

    # Sort: False positives at bottom, then by priority (1 to 5) and highest risk score
    vulnerabilities = (
        query
        .order_by(
            Vulnerability.is_false_positive.asc(),
            Vulnerability.priority.asc(),
            Vulnerability.risk_score.desc()
        )
        .all()
    )

    # Global counts for badge indicators
    all_vulns = Vulnerability.query
    counts = {
        'total':          all_vulns.count(),
        'active':         all_vulns.filter_by(is_false_positive=False).count(),
        'critical':       all_vulns.filter_by(severity='Critical', is_false_positive=False).count(),
        'high':           all_vulns.filter_by(severity='High', is_false_positive=False).count(),
        'medium':         all_vulns.filter_by(severity='Medium', is_false_positive=False).count(),
        'low':            all_vulns.filter_by(severity='Low', is_false_positive=False).count(),
        'informational':  all_vulns.filter_by(severity='Informational', is_false_positive=False).count(),
        'confirmed':      all_vulns.filter_by(validation_status='Confirmed', is_false_positive=False).count(),
        'false_positive': all_vulns.filter_by(is_false_positive=True).count(),
        'needs_review':   all_vulns.filter_by(validation_status='Needs Review', is_false_positive=False).count(),
    }

    # Unique targets for filtering dropdown
    all_targets = [a.target for a in Assessment.query.all()]

    return render_template(
        'results.html',
        active_page='vulnerabilities',
        vulnerabilities=vulnerabilities,
        severity_filter=severity_filter,
        status_filter=status_filter,
        target_filter=target_filter,
        search_query=search_query,
        counts=counts,
        all_targets=all_targets,
    )


@vulnerabilities_bp.route('/<int:vuln_id>')
def vulnerability_detail(vuln_id):
    """View full details, risk analysis, CVE mapping, and audit trail of a single finding."""
    vuln = Vulnerability.query.get_or_404(vuln_id)
    history = vuln.validation_records.order_by(ValidationRecord.created_at.desc()).all()

    # If CVE exists, fetch or refresh cached intelligence
    cve_details = None
    if vuln.cve_id:
        cve_details = get_cve_info(vuln.cve_id)

    return render_template(
        'vulnerability_details.html',
        active_page='vulnerabilities',
        vuln=vuln,
        history=history,
        cve_details=cve_details,
    )


@vulnerabilities_bp.route('/<int:vuln_id>/validate', methods=['POST'])
def validate_vulnerability(vuln_id):
    """
    Analyst review action:
    Updates status to 'Confirmed', 'False Positive', 'Needs Review', or 'Resolved'.
    Records audit entry in validation_records.
    """
    vuln = Vulnerability.query.get_or_404(vuln_id)
    new_status = request.form.get('validation_status', Vulnerability.VAL_NEEDS_REVIEW)
    analyst_name = request.form.get('analyst_name', '').strip() or 'Security Analyst'
    notes = request.form.get('validation_notes', '').strip()

    valid_statuses = [
        Vulnerability.VAL_CONFIRMED,
        Vulnerability.VAL_FALSE_POSITIVE,
        Vulnerability.VAL_NEEDS_REVIEW,
        Vulnerability.VAL_RESOLVED,
    ]

    if new_status not in valid_statuses:
        flash("Invalid validation status specified.", "error")
        return redirect(url_for('vulnerabilities.vulnerability_detail', vuln_id=vuln.id))

    previous_status = vuln.validation_status

    # Update vulnerability
    vuln.validation_status = new_status
    vuln.validator_name = analyst_name
    vuln.validation_notes = notes
    vuln.validated_at = datetime.utcnow()
    vuln.is_false_positive = (new_status == Vulnerability.VAL_FALSE_POSITIVE)

    # Create audit record
    audit = ValidationRecord(
        vulnerability_id=vuln.id,
        analyst=analyst_name,
        previous_status=previous_status,
        new_status=new_status,
        notes=notes,
        created_at=datetime.utcnow(),
    )
    db.session.add(audit)
    db.session.commit()

    if new_status == Vulnerability.VAL_FALSE_POSITIVE:
        flash(f"Finding {vuln.finding_id or vuln.id} marked as False Positive (excluded from active risk).", "info")
    else:
        flash(f"Finding {vuln.finding_id or vuln.id} status updated to '{new_status}'.", "success")

    return redirect(url_for('vulnerabilities.vulnerability_detail', vuln_id=vuln.id))
