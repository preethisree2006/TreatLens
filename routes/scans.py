"""
Scans Route Blueprint — Phase 3: Controlled Vulnerability Scanning Foundation
=============================================================================
Handles scan initiation, status tracking, and structured scan results presentation.
"""
from datetime import datetime
from flask import Blueprint, render_template, request, redirect, url_for, flash
from database.db import db, Assessment, Scan, ScanResult
from scanner.nmap_scanner import (
    run_nmap_scan,
    validate_target,
    generate_scan_id,
    is_nmap_installed,
    NMAP_NOT_FOUND_MSG,
)

scans_bp = Blueprint('scans', __name__, url_prefix='/scans')


@scans_bp.route('/')
def list_scans():
    """List all scans executed across all assessments."""
    scans = Scan.query.order_by(Scan.started_at.desc()).all()
    return render_template(
        'scans.html',
        active_page='assessments',
        scans=scans,
    )


@scans_bp.route('/<int:scan_id>')
def scan_detail(scan_id):
    """
    Scan Results View:
    Displays scan information, discovered ports/services table, and raw output.
    """
    scan = Scan.query.get_or_404(scan_id)
    assessment = Assessment.query.get(scan.assessment_id)
    services = scan.results.order_by(ScanResult.port.asc()).all()

    return render_template(
        'scan_results.html',
        active_page='assessments',
        scan=scan,
        assessment=assessment,
        services=services,
        nmap_available=is_nmap_installed(),
        nmap_error_msg=NMAP_NOT_FOUND_MSG,
    )
