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
    scan_id_filter = request.args.get('scan_id', type=int)
    assessment_id_filter = request.args.get('assessment_id', type=int)

    query = Vulnerability.query

    # Scan ID filter
    if scan_id_filter:
        query = query.filter(Vulnerability.scan_id == scan_id_filter)

    # Assessment ID filter
    if assessment_id_filter:
        query = query.filter(Vulnerability.assessment_id == assessment_id_filter)

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
        query = query.filter(
            (Vulnerability.affected_host == target_filter) |
            (Vulnerability.assessment.has(Assessment.target == target_filter))
        )

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

    # Scoped counts based on scan/assessment if filtered, else global counts
    count_base = Vulnerability.query
    if scan_id_filter:
        count_base = count_base.filter(Vulnerability.scan_id == scan_id_filter)
    elif assessment_id_filter:
        count_base = count_base.filter(Vulnerability.assessment_id == assessment_id_filter)

    counts = {
        'total':          count_base.count(),
        'active':         count_base.filter_by(is_false_positive=False).count(),
        'critical':       count_base.filter_by(severity='Critical', is_false_positive=False).count(),
        'high':           count_base.filter_by(severity='High', is_false_positive=False).count(),
        'medium':         count_base.filter_by(severity='Medium', is_false_positive=False).count(),
        'low':            count_base.filter_by(severity='Low', is_false_positive=False).count(),
        'informational':  count_base.filter_by(severity='Informational', is_false_positive=False).count(),
        'confirmed':      count_base.filter_by(validation_status='Confirmed', is_false_positive=False).count(),
        'false_positive': count_base.filter_by(is_false_positive=True).count(),
        'needs_review':   count_base.filter_by(validation_status='Needs Review', is_false_positive=False).count(),
    }

    # Unique targets for filtering dropdown
    targets_from_assessments = [a.target for a in Assessment.query.all() if a.target]
    targets_from_vulns = [v[0] for v in db.session.query(Vulnerability.affected_host).distinct().all() if v[0]]
    all_targets = sorted(list(set(targets_from_assessments + targets_from_vulns)))

    return render_template(
        'results.html',
        active_page='vulnerabilities',
        vulnerabilities=vulnerabilities,
        severity_filter=severity_filter,
        status_filter=status_filter,
        target_filter=target_filter,
        search_query=search_query,
        scan_id_filter=scan_id_filter,
        assessment_id_filter=assessment_id_filter,
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
