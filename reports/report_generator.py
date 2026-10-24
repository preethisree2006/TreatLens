"""
ThreatLens — PDF Security Assessment Report Generator
=====================================================
Generates comprehensive, professional cybersecurity assessment reports
in PDF format using ReportLab.

Sections:
    1. Title & Executive Summary
    2. Target Scope & Assessment Metadata
    3. Scan Summary & Discovered Services
    4. Risk Summary & Severity Breakdown
    5. Detailed Vulnerability Findings
    6. False Positives (separated from active risk)
    7. Prioritized Remediation Recommendations
    8. Posture Assessment & Security Conclusion
"""

import os
from pathlib import Path
from datetime import datetime
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
    KeepTogether,
    HRFlowable,
)
from database.db import db, Assessment, Scan, ScanResult, Vulnerability, Report

REPORTS_DIR = Path(__file__).resolve().parent / 'generated'


def generate_pdf_report(assessment_id: int, report_type: str = 'full') -> tuple[str, str]:
    """
    Generate a professional PDF assessment report for a given assessment.

    Args:
        assessment_id: Assessment primary key
        report_type: 'full' | 'executive'

    Returns:
        tuple[str, str]: (relative_or_absolute_file_path, filename)
    """
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)

    assessment = Assessment.query.get(assessment_id)
    if not assessment:
        raise ValueError(f"Assessment with id {assessment_id} not found.")

    timestamp_str = datetime.now().strftime('%Y%m%d_%H%M%S')
    filename = f"ThreatLens_Report_{assessment.assessment_id}_{timestamp_str}.pdf"
    pdf_path = REPORTS_DIR / filename

    doc = SimpleDocTemplate(
        str(pdf_path),
        pagesize=letter,
        leftMargin=40,
        rightMargin=40,
        topMargin=40,
        bottomMargin=40,
    )

    styles = getSampleStyleSheet()

    # Custom styles
    title_style = ParagraphStyle(
        'DocTitle',
        parent=styles['Heading1'],
        fontName='Helvetica-Bold',
        fontSize=22,
        leading=26,
        textColor=colors.HexColor('#0f172a'),
    )

    subtitle_style = ParagraphStyle(
        'DocSub',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=12,
        leading=16,
        textColor=colors.HexColor('#2563eb'),
    )

    h1_style = ParagraphStyle(
        'H1',
        parent=styles['Heading2'],
        fontName='Helvetica-Bold',
        fontSize=14,
        leading=18,
        textColor=colors.HexColor('#1e293b'),
        spaceBefore=14,
        spaceAfter=6,
    )

    h2_style = ParagraphStyle(
        'H2',
        parent=styles['Heading3'],
        fontName='Helvetica-Bold',
        fontSize=11,
        leading=15,
        textColor=colors.HexColor('#334155'),
        spaceBefore=8,
        spaceAfter=4,
    )

    body_style = ParagraphStyle(
        'Body',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=9.5,
        leading=14,
        textColor=colors.HexColor('#334155'),
    )

    code_style = ParagraphStyle(
        'Code',
        parent=styles['Normal'],
        fontName='Courier',
        fontSize=8.5,
        leading=11,
        textColor=colors.HexColor('#1e293b'),
    )

    story = []

    # -------------------------------------------------------------
    # 1. Cover & Header Banner
    # -------------------------------------------------------------
    story.append(Paragraph("🛡️ ThreatLens", title_style))
    story.append(Paragraph("Cybersecurity Vulnerability Assessment & Risk Management System", subtitle_style))
    story.append(Spacer(1, 4))
    story.append(HRFlowable(width="100%", thickness=2, color=colors.HexColor('#2563eb'), spaceBefore=4, spaceAfter=14))

    # -------------------------------------------------------------
    # 2. Executive Summary
    # -------------------------------------------------------------
    story.append(Paragraph("1. Executive Summary", h1_style))
    latest_scan = assessment.latest_scan
    service_count = latest_scan.results.count() if latest_scan else 0

    if latest_scan:
        active_vulns = assessment.vulnerabilities.filter_by(is_false_positive=False).filter(
            (Vulnerability.scan_id == latest_scan.id) | (Vulnerability.scan_id.is_(None))
        ).all()
        fp_vulns = assessment.vulnerabilities.filter_by(is_false_positive=True).filter(
            (Vulnerability.scan_id == latest_scan.id) | (Vulnerability.scan_id.is_(None))
        ).all()
    else:
        active_vulns = assessment.vulnerabilities.filter_by(is_false_positive=False).all()
        fp_vulns = assessment.vulnerabilities.filter_by(is_false_positive=True).all()

    exec_summary_text = (
        f"This document provides the official technical security assessment report for target "
        f"<b>{assessment.target}</b> (Assessment ID: <b>{assessment.assessment_id}</b>). "
        f"Security scanning was conducted in an authorized environment using safe network service discovery. "
        f"A total of <b>{service_count}</b> open service(s) were identified. "
        f"Following rule-based vulnerability analysis, <b>{len(active_vulns)}</b> active security finding(s) "
        f"were detected and categorized by risk severity. "
        f"Additionally, <b>{len(fp_vulns)}</b> item(s) were identified as False Positives and excluded from active risk."
    )
    story.append(Paragraph(exec_summary_text, body_style))
    story.append(Spacer(1, 10))

    # -------------------------------------------------------------
    # 3. Assessment Metadata & Scope Table
    # -------------------------------------------------------------
    story.append(Paragraph("2. Scope & Target Information", h1_style))
    meta_data = [
        [Paragraph("<b>Assessment Name</b>", body_style), Paragraph(assessment.name, body_style)],
        [Paragraph("<b>Assessment ID</b>", body_style), Paragraph(assessment.assessment_id, body_style)],
        [Paragraph("<b>Target Host / IP</b>", body_style), Paragraph(assessment.target, body_style)],
        [Paragraph("<b>Lifecycle Status</b>", body_style), Paragraph(assessment.status, body_style)],
        [Paragraph("<b>Date Generated</b>", body_style), Paragraph(datetime.now().strftime('%d %B %Y, %H:%M UTC'), body_style)],
        [Paragraph("<b>Scope Description</b>", body_style), Paragraph(assessment.description or 'Authorized security baseline', body_style)],
    ]
    t_meta = Table(meta_data, colWidths=[150, 380])
    t_meta.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (0, -1), colors.HexColor('#f8fafc')),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#cbd5e1')),
        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 5),
        ('TOPPADDING', (0, 0), (-1, -1), 5),
    ]))
    story.append(t_meta)
    story.append(Spacer(1, 12))

    # -------------------------------------------------------------
    # 4. Scan Summary & Discovered Services
    # -------------------------------------------------------------
    story.append(Paragraph("3. Scan Summary & Discovered Services", h1_style))
    if latest_scan:
        scan_meta = [
            [Paragraph("<b>Scan ID</b>", body_style), Paragraph(latest_scan.scan_id, body_style)],
            [Paragraph("<b>Scan Status</b>", body_style), Paragraph(latest_scan.status, body_style)],
            [Paragraph("<b>Command Used</b>", body_style), Paragraph(latest_scan.command_used or 'nmap -sV -T3', code_style)],
            [Paragraph("<b>Duration</b>", body_style), Paragraph(f"{latest_scan.duration_seconds or 0} seconds", body_style)],
        ]
        t_scan = Table(scan_meta, colWidths=[150, 380])
        t_scan.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (0, -1), colors.HexColor('#f8fafc')),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#cbd5e1')),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
            ('TOPPADDING', (0, 0), (-1, -1), 4),
        ]))
        story.append(t_scan)
        story.append(Spacer(1, 8))

        # Services Table
        services = latest_scan.results.order_by(ScanResult.port.asc()).all()
        if services:
            svc_rows = [[
                Paragraph("<b>Port</b>", body_style),
                Paragraph("<b>Protocol</b>", body_style),
                Paragraph("<b>State</b>", body_style),
                Paragraph("<b>Service</b>", body_style),
                Paragraph("<b>Product / Version</b>", body_style),
            ]]
            for s in services:
                pv = f"{s.product} {s.version}".strip() or "—"
                svc_rows.append([
                    Paragraph(str(s.port), body_style),
                    Paragraph(s.protocol.upper(), body_style),
                    Paragraph(s.state, body_style),
                    Paragraph(s.service, body_style),
                    Paragraph(pv, body_style),
                ])
            t_services = Table(svc_rows, colWidths=[55, 65, 65, 110, 235])
            t_services.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#f1f5f9')),
                ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#cbd5e1')),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
                ('TOPPADDING', (0, 0), (-1, -1), 4),
            ]))
            story.append(t_services)
        else:
            story.append(Paragraph("<i>No open ports or services were discovered on the target.</i>", body_style))
    else:
        story.append(Paragraph("<i>No security scan has been executed for this assessment yet.</i>", body_style))

    story.append(Spacer(1, 12))

    # -------------------------------------------------------------
    # 5. Risk Summary & Severity Breakdown
    # -------------------------------------------------------------
    story.append(Paragraph("4. Risk Severity Summary", h1_style))
    crit_c = sum(1 for v in active_vulns if v.severity == 'Critical')
    high_c = sum(1 for v in active_vulns if v.severity == 'High')
    med_c = sum(1 for v in active_vulns if v.severity == 'Medium')
    low_c = sum(1 for v in active_vulns if v.severity == 'Low')
    info_c = sum(1 for v in active_vulns if v.severity == 'Informational')

    sev_counts = [
        [Paragraph("<b>Severity Level</b>", body_style), Paragraph("<b>Active Count</b>", body_style), Paragraph("<b>Priority & SLA</b>", body_style)],
        [Paragraph("<font color='#ef4444'><b>Critical</b></font>", body_style), str(crit_c), "Priority 1 — Immediate (4h)"],
        [Paragraph("<font color='#f97316'><b>High</b></font>", body_style), str(high_c), "Priority 2 — Urgent (24h)"],
        [Paragraph("<font color='#eab308'><b>Medium</b></font>", body_style), str(med_c), "Priority 3 — Scheduled (7d)"],
        [Paragraph("<font color='#22c55e'><b>Low</b></font>", body_style), str(low_c), "Priority 4 — Routine (30d)"],
        [Paragraph("<font color='#64748b'><b>Informational</b></font>", body_style), str(info_c), "Priority 5 — Monitoring"],
        [Paragraph("<b>Total Active Findings</b>", body_style), str(len(active_vulns)), "Excludes False Positives"],
    ]
    t_sev = Table(sev_counts, colWidths=[140, 100, 290])
    t_sev.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#f1f5f9')),
        ('BACKGROUND', (0, -1), (-1, -1), colors.HexColor('#e2e8f0')),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#cbd5e1')),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
        ('TOPPADDING', (0, 0), (-1, -1), 4),
    ]))
    story.append(t_sev)
    story.append(Spacer(1, 14))

    # -------------------------------------------------------------
    # 6. Detailed Active Vulnerability Findings
    # -------------------------------------------------------------
    story.append(Paragraph("5. Detailed Vulnerability Findings", h1_style))
    if active_vulns:
        # Sort by priority/risk score descending
        sorted_vulns = sorted(active_vulns, key=lambda v: (v.priority or 5, -(v.risk_score or 0)))

        for idx, v in enumerate(sorted_vulns, 1):
            sev_color = {
                'Critical': '#ef4444',
                'High':     '#f97316',
                'Medium':   '#eab308',
                'Low':      '#22c55e',
            }.get(v.severity, '#64748b')

            f_table_data = [
                [
                    Paragraph(f"<b>Finding #{idx}: {v.name}</b>", h2_style),
                    Paragraph(f"<font color='{sev_color}'><b>{v.severity.upper()}</b></font> (Score: {v.risk_score:.1f}/10)", body_style),
                ],
                [
                    Paragraph("<b>Finding ID / CVE</b>", body_style),
                    Paragraph(f"{v.finding_id or '—'} | {v.cve_id or 'None'}", body_style),
                ],
                [
                    Paragraph("<b>Affected Service</b>", body_style),
                    Paragraph(f"Port {v.affected_port}/{v.affected_protocol} ({v.affected_service})", body_style),
                ],
                [
                    Paragraph("<b>Description</b>", body_style),
                    Paragraph(v.description or 'No description provided.', body_style),
                ],
                [
                    Paragraph("<b>Scan Evidence</b>", body_style),
                    Paragraph(f"<font face='Courier' size='8'>{v.evidence or 'Nmap scan match'}</font>", code_style),
                ],
                [
                    Paragraph("<b>Validation Status</b>", body_style),
                    Paragraph(f"{v.validation_status} (Reviewed by: {v.validator_name or 'Analyst'})", body_style),
                ],
                [
                    Paragraph("<b>Remediation</b>", body_style),
                    Paragraph(f"<b>{v.remediation}</b><br/>{v.recommended_action or ''}", body_style),
                ],
            ]

            t_finding = Table(f_table_data, colWidths=[130, 400])
            t_finding.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#f8fafc')),
                ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#cbd5e1')),
                ('VALIGN', (0, 0), (-1, -1), 'TOP'),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
                ('TOPPADDING', (0, 0), (-1, -1), 4),
            ]))

            story.append(KeepTogether([t_finding, Spacer(1, 10)]))
    else:
        story.append(Paragraph("<i>No active vulnerabilities were identified during this assessment.</i>", body_style))
        story.append(Spacer(1, 10))

    # -------------------------------------------------------------
    # 7. False Positives (Separated)
    # -------------------------------------------------------------
    story.append(Paragraph("6. False Positive Determinations", h1_style))
    if fp_vulns:
        fp_rows = [[
            Paragraph("<b>Finding Name</b>", body_style),
            Paragraph("<b>Port</b>", body_style),
            Paragraph("<b>Analyst Notes / Rationale</b>", body_style),
        ]]
        for fp in fp_vulns:
            fp_rows.append([
                Paragraph(fp.name, body_style),
                Paragraph(f"{fp.affected_port}/{fp.affected_protocol}", body_style),
                Paragraph(fp.validation_notes or 'Marked as false positive by analyst review.', body_style),
            ])
        t_fp = Table(fp_rows, colWidths=[180, 70, 280])
        t_fp.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#f1f5f9')),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#cbd5e1')),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
            ('TOPPADDING', (0, 0), (-1, -1), 4),
        ]))
        story.append(t_fp)
    else:
        story.append(Paragraph("<i>No findings were marked as False Positives.</i>", body_style))

    story.append(Spacer(1, 14))

    # -------------------------------------------------------------
    # 8. Prioritized Recommendations & Posture
    # -------------------------------------------------------------
    story.append(Paragraph("7. Remediation Strategy & Overall Posture", h1_style))
    posture_text = (
        "<b>Strategic Guidance:</b> Remediation efforts must strictly prioritize Critical (P1) and High (P2) "
        "findings before addressing medium and low-risk items. Ensure that legacy plaintext protocols (Telnet, unencrypted FTP) "
        "are terminated or tunnelled through SSH/TLS, exposed administrative or database ports are constrained to loopback "
        "or secure management VPNs, and vendor security patches are applied across all running software stacks."
    )
    story.append(Paragraph(posture_text, body_style))
    story.append(Spacer(1, 14))
    story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor('#94a3b8'), spaceBefore=8, spaceAfter=8))
    story.append(Paragraph("ThreatLens Security Assessment System • Academic Security Evaluation Prototype", ParagraphStyle('Foot', parent=body_style, fontSize=8, textColor=colors.HexColor('#94a3b8'), alignment=1)))

    # Build Document
    doc.build(story)

    # Record generated report in database
    rep_record = Report(
        report_id=f"REP-{timestamp_str[:8]}-{assessment.id:03d}",
        assessment_id=assessment.id,
        filename=filename,
        file_path=str(pdf_path),
        report_type=report_type,
        summary=f"Automated assessment report for {assessment.target}. Discovered {service_count} services, {len(active_vulns)} active findings.",
        generated_at=datetime.utcnow(),
        generated_by="ThreatLens Report Generator",
    )
    db.session.add(rep_record)
    db.session.commit()

    return str(pdf_path), filename
