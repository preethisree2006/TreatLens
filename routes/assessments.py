"""Assessments Route Blueprint — Phase 1 (listing only)"""
from flask import Blueprint, render_template
from database.db import db, Assessment, Target

assessments_bp = Blueprint('assessments', __name__, url_prefix='/assessments')


@assessments_bp.route('/')
def list_assessments():
    """List all assessments."""
    assessments = Assessment.query.order_by(Assessment.created_at.desc()).all()
    return render_template(
        'assessments.html',
        active_page='assessments',
        assessments=assessments,
    )


@assessments_bp.route('/new')
def new_assessment():
    """New assessment form (Phase 2 will make this functional)."""
    targets = Target.query.all()
    return render_template(
        'new_assessment.html',
        active_page='new_assessment',
        targets=targets,
    )


@assessments_bp.route('/<int:assessment_id>')
def assessment_detail(assessment_id):
    """View a single assessment's details and progress."""
    assessment = Assessment.query.get_or_404(assessment_id)
    return render_template(
        'scan_progress.html',
        active_page='assessments',
        assessment=assessment,
    )
