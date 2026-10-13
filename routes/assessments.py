"""
Assessments Route Blueprint — ThreatLens
========================================
Handles assessment creation, input validation, unique ID generation,
assessment listing, individual details, scan triggering, and analysis.
"""
from datetime import datetime
from flask import Blueprint, render_template, request, redirect, url_for, flash
from database.db import db, Assessment, Scan, ScanResult, Vulnerability
from scanner.nmap_scanner import (
    run_nmap_scan,
    validate_target,
    generate_scan_id,
    is_nmap_installed,
    NMAP_NOT_FOUND_MSG,
)
from scanner.vuln_engine import analyze_scan

assessments_bp = Blueprint('assessments', __name__, url_prefix='/assessments')


def generate_assessment_id():
    """
    Generate a unique Assessment ID formatted as: ASM-YYYYMMDD-XXX
    Example: ASM-20261013-001
    """
    today_str = datetime.now().strftime('%Y%m%d')
    prefix = f"ASM-{today_str}-"

    latest = (
        Assessment.query
        .filter(Assessment.assessment_id.like(f"{prefix}%"))
        .order_by(Assessment.id.desc())
        .first()
    )

    if latest and latest.assessment_id:
        try:
            seq_part = latest.assessment_id.split('-')[-1]
            next_seq = int(seq_part) + 1
        except (ValueError, IndexError):
            next_seq = 1
    else:
        next_seq = 1

    return f"{prefix}{next_seq:03d}"


@assessments_bp.route('/')
def list_assessments():
    """Assessment History: Display all existing assessments."""
    assessments = Assessment.query.order_by(Assessment.created_at.desc()).all()
    return render_template(
        'assessments.html',
        active_page='assessments',
        assessments=assessments,
    )


@assessments_bp.route('/new', methods=['GET', 'POST'])
def new_assessment():
    """Create a new Assessment record."""
    if request.method == 'POST':
        name = request.form.get('name', '').strip()
        target = request.form.get('target', '').strip()
        description = request.form.get('description', '').strip()

        if not name:
            flash('Assessment Name is required.', 'error')
            return render_template('new_assessment.html', active_page='new_assessment', form_data=request.form)

        if not target:
            flash('Target is required. Please provide a local/controlled target (e.g. 127.0.0.1 or localhost).', 'error')
            return render_template('new_assessment.html', active_page='new_assessment', form_data=request.form)

        if not description:
            flash('Description is required.', 'error')
            return render_template('new_assessment.html', active_page='new_assessment', form_data=request.form)

        # Validate target
        is_valid_target, target_err = validate_target(target)
        if not is_valid_target:
            flash(target_err, 'error')
            return render_template('new_assessment.html', active_page='new_assessment', form_data=request.form)

        assessment_id = generate_assessment_id()

        new_record = Assessment(
            assessment_id=assessment_id,
            name=name,
            target=target,
            description=description,
            status='Created',
            created_at=datetime.utcnow(),
            updated_at=datetime.utcnow(),
        )

        try:
            db.session.add(new_record)
            db.session.commit()
            flash(f"Assessment {assessment_id} created successfully.", "success")
            return redirect(url_for('assessments.assessment_detail', assessment_id=new_record.id))
        except Exception:
            db.session.rollback()
            flash('Database error: Unable to save assessment. Please try again.', 'error')
            return render_template('new_assessment.html', active_page='new_assessment', form_data=request.form)

    return render_template(
        'new_assessment.html',
        active_page='new_assessment',
        form_data={},
    )


@assessments_bp.route('/<int:assessment_id>')
def assessment_detail(assessment_id):
    """View details of an individual assessment, scan history, and findings."""
    assessment = Assessment.query.get_or_404(assessment_id)
    scans = assessment.scans.order_by(Scan.started_at.desc()).all()
    latest_scan = assessment.latest_scan
    active_findings = assessment.vulnerabilities.filter_by(is_false_positive=False).order_by(Vulnerability.priority.asc(), Vulnerability.risk_score.desc()).all()
    fp_findings = assessment.vulnerabilities.filter_by(is_false_positive=True).all()

    return render_template(
        'assessment_detail.html',
        active_page='assessments',
        assessment=assessment,
        scans=scans,
        latest_scan=latest_scan,
        findings=active_findings,
        fp_findings=fp_findings,
        nmap_available=is_nmap_installed(),
        nmap_error_msg=NMAP_NOT_FOUND_MSG,
    )


@assessments_bp.route('/<int:assessment_id>/scan', methods=['POST'])
def trigger_scan(assessment_id):
    """
    Start Scan endpoint:
    1. Confirm assessment exists.
    2. Validate target.
    3. Generate Scan ID and create 'Running' record.
    4. Execute safe Nmap service discovery scan (-sV -T3).
    5. Save results to database.
    6. Automatically run rule-based vulnerability analysis on discovered services.
    7. Redirect user to Scan Results page.
    """
    assessment = Assessment.query.get_or_404(assessment_id)

    # Validate target format
    is_valid, target_or_err = validate_target(assessment.target)
    if not is_valid:
        flash(f"Target validation failed: {target_or_err}", "error")
        return redirect(url_for('assessments.assessment_detail', assessment_id=assessment.id))

    # Generate unique Scan ID
    scan_id = generate_scan_id()

    # Create initial Scan record in database
    scan = Scan(
        scan_id=scan_id,
        assessment_id=assessment.id,
        target=assessment.target,
        status='Running',
        started_at=datetime.utcnow(),
        command_used=f"nmap -sV -T3 {assessment.target}",
    )
    assessment.status = 'Running'
    db.session.add(scan)
    db.session.commit()

    # Execute Nmap scan safely via subprocess
    scan_res = run_nmap_scan(assessment.target)

    # Update scan record
    scan.completed_at = datetime.utcnow()
    scan.command_used = scan_res.get('command', scan.command_used)
    scan.raw_output = scan_res.get('raw_output', '')

    if scan_res['success']:
        scan.status = 'Completed'
        assessment.status = 'Completed'

        # Store discovered services
        for s in scan_res.get('services', []):
            sr = ScanResult(
                scan_id=scan.id,
                host=s.get('host', assessment.target),
                port=s.get('port', 0),
                protocol=s.get('protocol', 'tcp'),
                state=s.get('state', 'open'),
                service=s.get('service', 'unknown'),
                product=s.get('product', ''),
                version=s.get('version', ''),
                extra_info=s.get('extra_info', ''),
            )
            db.session.add(sr)

        db.session.commit()

        # Run Vulnerability Analysis Engine on discovered services
        new_vulns = analyze_scan(assessment.id, scan.id)
        svc_count = len(scan_res.get('services', []))

        if new_vulns:
            flash(
                f"Scan {scan.scan_id} completed. Discovered {svc_count} service(s) and identified {len(new_vulns)} finding(s) for analyst review.",
                "success"
            )
        else:
            flash(
                f"Scan {scan.scan_id} completed. Discovered {svc_count} service(s). No vulnerabilities detected.",
                "success"
            )

    else:
        scan.status = 'Failed'
        scan.error_message = scan_res.get('error', 'Scan execution failed.')
        assessment.status = 'Failed'
        db.session.commit()

        if scan_res.get('error') == NMAP_NOT_FOUND_MSG:
            flash(NMAP_NOT_FOUND_MSG, "error")
        else:
            flash(f"Scan failed: {scan.error_message}", "error")

    return redirect(url_for('scans.scan_detail', scan_id=scan.id))


@assessments_bp.route('/<int:assessment_id>/analyze', methods=['POST'])
def run_analysis(assessment_id):
    """Manually trigger vulnerability analysis on the assessment's latest scan."""
    assessment = Assessment.query.get_or_404(assessment_id)
    latest_scan = assessment.latest_scan

    if not latest_scan or latest_scan.status != 'Completed':
        flash("No completed scan available to analyze.", "error")
        return redirect(url_for('assessments.assessment_detail', assessment_id=assessment.id))

    new_vulns = analyze_scan(assessment.id, latest_scan.id)
    if new_vulns:
        flash(f"Analysis complete. Identified {len(new_vulns)} security finding(s).", "success")
    else:
        flash("Analysis complete. No new vulnerabilities detected on discovered services.", "info")

    return redirect(url_for('assessments.assessment_detail', assessment_id=assessment.id))
