"""
Reports Route Blueprint — ThreatLens
====================================
Handles security assessment report management, PDF generation via ReportLab,
and report file downloads.
"""

import os
from flask import Blueprint, render_template, request, redirect, url_for, flash, send_file, abort
from database.db import db, Report, Assessment
from reports.report_generator import generate_pdf_report

reports_bp = Blueprint('reports', __name__, url_prefix='/reports')


@reports_bp.route('/')
def list_reports():
    """List all generated security assessment reports."""
    reports = Report.query.order_by(Report.generated_at.desc()).all()
    # Assessments available for reporting
    assessments = Assessment.query.order_by(Assessment.created_at.desc()).all()

    return render_template(
        'reports.html',
        active_page='reports',
        reports=reports,
        assessments=assessments,
    )


@reports_bp.route('/generate', methods=['POST'])
@reports_bp.route('/generate/<int:assessment_id>', methods=['POST'])
def generate_report_for_assessment(assessment_id=None):
    """Generate a PDF report for the selected assessment."""
    if assessment_id is None:
        raw_id = request.form.get('assessment_id')
        if not raw_id:
            flash("Please select an assessment to generate a report.", "error")
            return redirect(url_for('reports.list_reports'))
        try:
            assessment_id = int(raw_id)
        except ValueError:
            flash("Invalid assessment ID provided.", "error")
            return redirect(url_for('reports.list_reports'))

    assessment = Assessment.query.get_or_404(assessment_id)
    report_type = request.form.get('report_type', 'full')

    try:
        pdf_path, filename = generate_pdf_report(assessment.id, report_type=report_type)
        flash(f"PDF Security Report '{filename}' generated successfully.", "success")
    except Exception as e:
        flash(f"Failed to generate report: {str(e)}", "error")

    return redirect(url_for('reports.list_reports'))


@reports_bp.route('/download/<int:report_id>')
def download_report(report_id):
    """Download a generated PDF report."""
    report = Report.query.get_or_404(report_id)

    if not os.path.exists(report.file_path):
        flash("Report file not found on disk.", "error")
        return redirect(url_for('reports.list_reports'))

    return send_file(
        report.file_path,
        as_attachment=True,
        download_name=report.filename,
        mimetype='application/pdf',
    )
