"""Reports Route Blueprint — Phase 1 (placeholder)"""
from flask import Blueprint, render_template
from database.db import db, Report, Assessment

reports_bp = Blueprint('reports', __name__, url_prefix='/reports')


@reports_bp.route('/')
def list_reports():
    """List all generated reports (Phase 8 will add PDF generation)."""
    reports = Report.query.order_by(Report.generated_at.desc()).all()
    assessments = Assessment.query.filter_by(status='completed').all()
    return render_template(
        'reports.html',
        active_page='reports',
        reports=reports,
        assessments=assessments,
    )
