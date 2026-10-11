"""Vulnerabilities Route Blueprint — Phase 1 (listing + detail view)"""
from flask import Blueprint, render_template, request
from database.db import db, Vulnerability, Assessment

vulnerabilities_bp = Blueprint('vulnerabilities', __name__, url_prefix='/vulnerabilities')


@vulnerabilities_bp.route('/')
def list_vulnerabilities():
    """List all vulnerabilities with optional severity filter."""
    severity_filter = request.args.get('severity', 'all')
    query = Vulnerability.query.filter(Vulnerability.is_false_positive == False)

    if severity_filter and severity_filter != 'all':
        query = query.filter_by(severity=severity_filter.capitalize())

    vulnerabilities = query.order_by(Vulnerability.risk_score.desc()).all()

    # Counts for filter badges
    counts = {
        'all':      Vulnerability.query.count(),
        'critical': Vulnerability.query.filter_by(severity='Critical').count(),
        'high':     Vulnerability.query.filter_by(severity='High').count(),
        'medium':   Vulnerability.query.filter_by(severity='Medium').count(),
        'low':      Vulnerability.query.filter_by(severity='Low').count(),
    }

    return render_template(
        'results.html',
        active_page='vulnerabilities',
        vulnerabilities=vulnerabilities,
        severity_filter=severity_filter,
        counts=counts,
    )


@vulnerabilities_bp.route('/<int:vuln_id>')
def vulnerability_detail(vuln_id):
    """View full details of a single vulnerability."""
    vuln = Vulnerability.query.get_or_404(vuln_id)
    return render_template(
        'vulnerability_details.html',
        active_page='vulnerabilities',
        vuln=vuln,
    )
