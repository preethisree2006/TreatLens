"""
Risk Assessment Route Blueprint — ThreatLens
============================================
Presents prioritized active risks ordered by severity and SLA urgency.
Strictly excludes false positives from the risk matrix.
"""

from flask import Blueprint, render_template
from database.db import Vulnerability

risk_bp = Blueprint('risk', __name__, url_prefix='/risk')


@risk_bp.route('/')
@risk_bp.route('/assessment')
def index():
    """Display active vulnerabilities ordered by priority (P1 Critical -> P5 Informational)."""
    # Active risks only: False positives are excluded
    active_findings = (
        Vulnerability.query
        .filter_by(is_false_positive=False)
        .order_by(Vulnerability.priority.asc(), Vulnerability.risk_score.desc())
        .all()
    )

    # Priority counts
    counts = {
        'p1': sum(1 for v in active_findings if v.priority == 1),
        'p2': sum(1 for v in active_findings if v.priority == 2),
        'p3': sum(1 for v in active_findings if v.priority == 3),
        'p4': sum(1 for v in active_findings if v.priority == 4),
        'p5': sum(1 for v in active_findings if v.priority == 5),
        'total': len(active_findings),
    }

    return render_template(
        'risk_assessment.html',
        active_page='risk',
        findings=active_findings,
        counts=counts,
    )
