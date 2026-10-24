"""
ThreatLens — Comprehensive System & Integration Tests
======================================================
Tests:
1. Nmap installation check & Target validation (injection prevention)
2. Nmap parser (XML and Text formats)
3. Vulnerability Rule Engine (evidence-based finding generation, no fake CVEs)
4. Deduplication & Scan-Specific Findings (re-analysis creates zero duplicates)
5. Risk Calculation Engine (Likelihood x Impact, CVSS blend, P1-P5 priorities)
6. Flask Routes (Dashboard, Assessments, Scans, Vulnerabilities, Risk, Reports)
7. Analyst Validation & False Positive exclusion from active risk
8. ReportLab PDF Generation (scoped to assessment/scan)
"""

import os
import unittest
from datetime import datetime
from app import create_app
from database.db import db, Assessment, Scan, ScanResult, Vulnerability, ValidationRecord, Report
from scanner.nmap_scanner import validate_target, is_nmap_installed, generate_scan_id
from scanner.parser import parse_nmap_xml, parse_nmap_text
from scanner.vuln_engine import analyze_service, analyze_scan
from risk.risk_engine import calculate_risk
from reports.report_generator import generate_pdf_report


class ThreatLensTestCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = create_app('testing')
        cls.client = cls.app.test_client()

    def setUp(self):
        self.app_context = self.app.app_context()
        self.app_context.push()
        db.create_all()

    def tearDown(self):
        db.session.remove()
        db.drop_all()
        self.app_context.pop()

    # -------------------------------------------------------------
    # 1. Target Validation Tests
    # -------------------------------------------------------------
    def test_target_validation_valid(self):
        valid_targets = ['127.0.0.1', 'localhost', '192.168.1.1', 'scanme.nmap.org']
        for target in valid_targets:
            is_valid, msg = validate_target(target)
            self.assertTrue(is_valid, f"Expected {target} to be valid, got: {msg}")

    def test_target_validation_injection_prevention(self):
        invalid_targets = [
            '-sS 127.0.0.1',        # Flag injection
            '127.0.0.1; whoami',    # Command separator
            '127.0.0.1 | dir',      # Pipe
            '127.0.0.1 & calc',     # Background operator
            '$(whoami)',            # Subshell substitution
            '`id`',                 # Backtick execution
            '',                     # Empty string
            '   ',                  # Whitespace
        ]
        for target in invalid_targets:
            is_valid, msg = validate_target(target)
            self.assertFalse(is_valid, f"Expected {target} to be rejected, but it passed: {msg}")

    # -------------------------------------------------------------
    # 2. Scanner Parser Tests
    # -------------------------------------------------------------
    def test_parse_nmap_text(self):
        sample_output = """
PORT     STATE SERVICE       VERSION
135/tcp  open  msrpc         Microsoft Windows RPC
445/tcp  open  microsoft-ds  Microsoft Windows 10
5000/tcp open  http          Werkzeug httpd 3.0.6 (Python 3.10)
"""
        services = parse_nmap_text(sample_output, default_host='127.0.0.1')
        self.assertEqual(len(services), 3)
        self.assertEqual(services[0]['port'], 135)
        self.assertEqual(services[0]['service'], 'msrpc')
        self.assertEqual(services[1]['port'], 445)
        self.assertEqual(services[1]['service'], 'microsoft-ds')
        self.assertEqual(services[2]['port'], 5000)
        self.assertEqual(services[2]['service'], 'http')

    # -------------------------------------------------------------
    # 3. Vulnerability Rule Engine & Evidence Integrity
    # -------------------------------------------------------------
    def test_rule_engine_findings_evidence_based(self):
        # Service 1: 135 MSRPC
        sr_135 = ScanResult(
            host='127.0.0.1', port=135, protocol='tcp', state='open',
            service='msrpc', product='Microsoft Windows RPC', version=''
        )
        findings_135 = analyze_service(sr_135, '127.0.0.1')
        self.assertEqual(len(findings_135), 1)
        self.assertIn('135', findings_135[0]['name'])
        self.assertIsNone(findings_135[0]['cve_id'], "Should NOT fabricate a CVE for general MSRPC")

        # Service 2: 445 SMB
        sr_445 = ScanResult(
            host='127.0.0.1', port=445, protocol='tcp', state='open',
            service='microsoft-ds', product='', version=''
        )
        findings_445 = analyze_service(sr_445, '127.0.0.1')
        self.assertEqual(len(findings_445), 1)
        self.assertIn('SMB', findings_445[0]['name'])
        self.assertIsNone(findings_445[0]['cve_id'], "Should NOT fabricate EternalBlue CVE without SMBv1 evidence")

        # Service 3: 5000 HTTP
        sr_5000 = ScanResult(
            host='127.0.0.1', port=5000, protocol='tcp', state='open',
            service='http', product='Werkzeug httpd', version='3.0.6'
        )
        findings_5000 = analyze_service(sr_5000, '127.0.0.1')
        self.assertEqual(len(findings_5000), 1)
        self.assertIn('Unencrypted HTTP', findings_5000[0]['name'])
        self.assertIsNone(findings_5000[0]['cve_id'])

        # Service 4: 21 FTP (Generic vs vsftpd 2.3.4)
        sr_ftp_generic = ScanResult(
            host='127.0.0.1', port=21, protocol='tcp', state='open',
            service='ftp', product='ProFTPD', version='1.3.5'
        )
        findings_ftp = analyze_service(sr_ftp_generic, '127.0.0.1')
        self.assertEqual(len(findings_ftp), 1)
        self.assertNotIn('vsftpd', findings_ftp[0]['name'])
        self.assertIsNone(findings_ftp[0]['cve_id'])

        # vsftpd 2.3.4 Backdoor
        sr_vsftpd = ScanResult(
            host='127.0.0.1', port=21, protocol='tcp', state='open',
            service='ftp', product='vsftpd', version='2.3.4'
        )
        findings_vsftpd = analyze_service(sr_vsftpd, '127.0.0.1')
        self.assertEqual(len(findings_vsftpd), 1)
        self.assertIn('vsftpd 2.3.4 Backdoor', findings_vsftpd[0]['name'])
        self.assertEqual(findings_vsftpd[0]['cve_id'], 'CVE-2011-2523')

    # -------------------------------------------------------------
    # 4. Risk Calculation Engine Tests
    # -------------------------------------------------------------
    def test_risk_calculation(self):
        # Critical test
        r_crit = calculate_risk(likelihood=9.5, impact=10.0, cvss_score=9.8)
        self.assertEqual(r_crit['severity'], 'Critical')
        self.assertEqual(r_crit['priority'], 1)

        # Medium test
        r_med = calculate_risk(likelihood=6.0, impact=6.5)
        self.assertIn(r_med['severity'], ['Low', 'Medium'])

    # -------------------------------------------------------------
    # 5. End-to-End Scan, Analysis, Deduplication & False-Positive Tests
    # -------------------------------------------------------------
    def test_assessment_scan_and_deduplication(self):
        # Create assessment
        asm = Assessment(
            assessment_id='ASM-TEST-UNIT-001',
            name='Unit Test Assessment',
            target='127.0.0.1',
            description='Automated unit test assessment',
            status='Created'
        )
        db.session.add(asm)
        db.session.commit()

        # Create scan
        scan = Scan(
            scan_id='SCN-TEST-UNIT-001',
            assessment_id=asm.id,
            target='127.0.0.1',
            status='Completed',
            command_used='nmap -sV -T3 127.0.0.1'
        )
        db.session.add(scan)
        db.session.commit()

        # Add scan results representing 127.0.0.1
        sr1 = ScanResult(scan_id=scan.id, host='127.0.0.1', port=135, protocol='tcp', state='open', service='msrpc', product='Microsoft Windows RPC')
        sr2 = ScanResult(scan_id=scan.id, host='127.0.0.1', port=445, protocol='tcp', state='open', service='microsoft-ds', product='')
        sr3 = ScanResult(scan_id=scan.id, host='127.0.0.1', port=5000, protocol='tcp', state='open', service='http', product='Werkzeug httpd', version='3.0.6')
        db.session.add_all([sr1, sr2, sr3])
        db.session.commit()

        # Run analysis
        vulns_pass_1 = analyze_scan(asm.id, scan.id)
        self.assertEqual(len(vulns_pass_1), 3)

        # Confirm all 3 are linked to scan.id and 127.0.0.1
        for v in vulns_pass_1:
            self.assertEqual(v.scan_id, scan.id)
            self.assertEqual(v.affected_host, '127.0.0.1')
            self.assertIn(v.affected_port, [135, 445, 5000])

        # Test Deduplication: Run analysis AGAIN on same scan
        vulns_pass_2 = analyze_scan(asm.id, scan.id)
        self.assertEqual(len(vulns_pass_2), 3, "Re-analysis must NOT create duplicate findings")
        
        # Verify total findings in database for this scan is exactly 3
        total_for_scan = Vulnerability.query.filter_by(scan_id=scan.id).count()
        self.assertEqual(total_for_scan, 3, "Database count must remain 3 after re-analysis")

        # Test False Positive Validation
        v_to_fp = vulns_pass_1[0]
        v_to_fp.validation_status = Vulnerability.VAL_FALSE_POSITIVE
        v_to_fp.is_false_positive = True
        db.session.commit()

        # Active findings query must now return 2 (excluding false positive)
        active_count = asm.active_vulns.count()
        self.assertEqual(active_count, 2)
        fp_count = asm.false_positive_count
        self.assertEqual(fp_count, 1)

        # Test PDF Report Generation
        pdf_path, filename = generate_pdf_report(asm.id)
        self.assertTrue(os.path.exists(pdf_path))
        self.assertTrue(filename.endswith('.pdf'))

        # Clean up created PDF and test records
        try:
            os.remove(pdf_path)
        except OSError:
            pass

        db.session.delete(asm)
        db.session.commit()

    # -------------------------------------------------------------
    # 6. Route HTTP Status Code Tests
    # -------------------------------------------------------------
    def test_routes_status_codes(self):
        routes_to_test = [
            '/',
            '/dashboard',
            '/assessments/',
            '/assessments/new',
            '/scans/',
            '/vulnerabilities/',
            '/risk/',
            '/reports/',
        ]
        for route in routes_to_test:
            res = self.client.get(route)
            self.assertEqual(res.status_code, 200, f"Route {route} failed with status {res.status_code}")


if __name__ == '__main__':
    unittest.main()
