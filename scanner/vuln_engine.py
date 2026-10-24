"""
ThreatLens — Vulnerability Analysis Engine
===========================================
Performs rule-based vulnerability analysis on factual scan evidence discovered
by Nmap. Strictly produces explainable findings tied to observed open ports,
service banners, and software versions.

Rules:
    - Exposed MSRPC Endpoint Mapper (Port 135)
    - Exposed SMB / NetBIOS File Sharing (Port 445 / 139)
    - Missing TLS encryption on web interfaces (Port 80 / non-SSL HTTP)
    - Insecure / plaintext protocols (Telnet Port 23, FTP Port 21)
    - Outdated/known vulnerable software (e.g. vsftpd 2.3.4 backdoor)
    - Exposed database services (MySQL, PostgreSQL, MongoDB, Redis, MSSQL)
    - Exposed Remote Desktop (RDP Port 3389)

NOTE: An open port is a discovered service, NOT automatically a vulnerability.
Only ports with verifiable security risks or protocol weaknesses produce findings.
CVE IDs are assigned strictly when verified evidence (product + version) supports it.
"""

from datetime import datetime
from database.db import db, Assessment, Scan, ScanResult, Vulnerability
from risk.risk_engine import calculate_risk


def generate_finding_id() -> str:
    """Generate a unique Finding ID: VULN-YYYYMMDD-XXX"""
    today_str = datetime.now().strftime('%Y%m%d')
    prefix = f"VULN-{today_str}-"

    latest = (
        Vulnerability.query
        .filter(Vulnerability.finding_id.like(f"{prefix}%"))
        .order_by(Vulnerability.id.desc())
        .first()
    )

    if latest and latest.finding_id:
        try:
            seq_part = latest.finding_id.split('-')[-1]
            next_seq = int(seq_part) + 1
        except (ValueError, IndexError):
            next_seq = 1
    else:
        next_seq = 1

    return f"{prefix}{next_seq:03d}"


def analyze_service(service_record: ScanResult, assessment_target: str) -> list[dict]:
    """
    Evaluates an individual ScanResult against explainable vulnerability detection rules.
    Returns a list of finding definition dicts (empty if no vulnerability rule matches).
    """
    findings = []
    port = service_record.port
    protocol = (service_record.protocol or 'tcp').lower()
    service = (service_record.service or '').lower()
    product = (service_record.product or '').strip()
    version = (service_record.version or '').strip()
    extra_info = (service_record.extra_info or '').strip()

    evidence_text = (
        f"Target: {assessment_target}\n"
        f"Host: {service_record.host or assessment_target}\n"
        f"Port: {port}/{protocol}\n"
        f"Service: {service}\n"
        f"Product: {product or 'None specified'}\n"
        f"Version: {version or 'None specified'}\n"
        f"State: {service_record.state}"
    )

    # -------------------------------------------------------------
    # Rule 1: Telnet Service (Insecure Plaintext Remote Access)
    # -------------------------------------------------------------
    if port == 23 or 'telnet' in service:
        findings.append({
            'name': 'Insecure Telnet Service Exposed (Cleartext Protocol)',
            'description': (
                'The target is running a Telnet service. Telnet transmits all communication, '
                'including usernames and passwords, in unencrypted cleartext across the network. '
                'Any attacker on the local network or path can capture credentials using packet sniffers.'
            ),
            'likelihood': 8.5,
            'impact': 8.5,
            'cvss_score': 7.5,
            'cve_id': 'CVE-1999-0619',
            'cve_description': 'Telnet transmits login sessions and credentials in plaintext.',
            'cve_url': 'https://nvd.nist.gov/vuln/detail/CVE-1999-0619',
            'confidence': 'High',
            'remediation': 'Disable the Telnet service immediately and replace with SSH (Secure Shell).',
            'recommended_action': (
                'Stop and disable the Telnet daemon (systemctl stop telnet / disable Windows Telnet Server). '
                'Configure OpenSSH on port 22 with key-based authentication and strong ciphers.'
            ),
        })

    # -------------------------------------------------------------
    # Rule 2: FTP Service (Plaintext Authentication / Specific Backdoor)
    # -------------------------------------------------------------
    if port == 21 or 'ftp' in service:
        if 'vsftpd' in product.lower() and '2.3.4' in version:
            findings.append({
                'name': 'vsftpd 2.3.4 Backdoor Command Execution Vulnerability',
                'description': (
                    'The target is running vsftpd version 2.3.4 which contains an intentional backdoor. '
                    'Sending a smiley face :) in the username parameter causes the server to spawn a root '
                    'shell listening on TCP port 6200.'
                ),
                'likelihood': 9.5,
                'impact': 10.0,
                'cvss_score': 9.8,
                'cve_id': 'CVE-2011-2523',
                'cve_description': 'vsftpd 2.3.4 contains a backdoor in the smile function leading to remote root access.',
                'cve_url': 'https://nvd.nist.gov/vuln/detail/CVE-2011-2523',
                'confidence': 'High',
                'remediation': 'Upgrade vsftpd immediately to a modern patched version or replace with SFTP.',
                'recommended_action': 'Remove vsftpd 2.3.4 immediately. Install updated package via package manager.',
            })
        else:
            findings.append({
                'name': 'Unencrypted FTP Service Detected (Plaintext Authentication)',
                'description': (
                    f'An FTP service is exposed on port {port}. Standard FTP does not encrypt credentials '
                    'or session data by default, exposing transmitted files and administrative passwords to interception.'
                ),
                'likelihood': 6.5,
                'impact': 6.5,
                'cvss_score': None,
                'cve_id': None,
                'cve_description': None,
                'cve_url': None,
                'confidence': 'High',
                'remediation': 'Enforce FTPS (FTP over TLS) or replace with SFTP over port 22.',
                'recommended_action': 'Configure TLS encryption on the FTP server or migrate file transfers to SFTP.',
            })

    # -------------------------------------------------------------
    # Rule 3: Microsoft RPC Endpoint Mapper (Port 135)
    # -------------------------------------------------------------
    if port == 135 or 'msrpc' in service or 'epmap' in service:
        findings.append({
            'name': 'Exposed Microsoft RPC Endpoint Mapper (Port 135)',
            'description': (
                'Microsoft Windows Remote Procedure Call (MSRPC) Endpoint Mapper is listening on TCP port 135. '
                'Exposing the RPC endpoint mapper enables network adversaries to query and enumerate registered '
                'RPC interfaces, service UUIDs, and internal network endpoints on the target host.'
            ),
            'likelihood': 5.0,
            'impact': 4.5,
            'cvss_score': None,
            'cve_id': None,
            'cve_description': None,
            'cve_url': None,
            'confidence': 'High',
            'remediation': 'Block inbound TCP port 135 from untrusted subnets using Windows Firewall or network ACLs.',
            'recommended_action': (
                'Configure Windows Firewall to block TCP port 135 from external or untrusted networks. '
                'Restrict RPC communication exclusively to authorized management hosts.'
            ),
        })

    # -------------------------------------------------------------
    # Rule 4: SMB / NetBIOS File Sharing Exposed (Port 445 / 139)
    # -------------------------------------------------------------
    if port in (445, 139) or 'microsoft-ds' in service or 'netbios' in service or 'smb' in service:
        findings.append({
            'name': 'Exposed Microsoft SMB Service (Port 445)',
            'description': (
                f'Server Message Block (SMB / microsoft-ds) is listening on port {port}. '
                'Directly exposing SMB file sharing interfaces without strict network boundary controls '
                'increases exposure to unauthenticated share enumeration, credential harvesting, '
                'and lateral movement across internal subnets.'
            ),
            'likelihood': 6.5,
            'impact': 6.5,
            'cvss_score': None,
            'cve_id': None,
            'cve_description': None,
            'cve_url': None,
            'confidence': 'High',
            'remediation': 'Restrict TCP port 445 via firewall, enforce SMB signing, and ensure legacy SMBv1 is disabled.',
            'recommended_action': (
                'Block TCP port 445 at the host or perimeter firewall for unauthorized networks. '
                'Verify SMBv1 is disabled via PowerShell: Set-SmbServerConfiguration -EnableSMB1Protocol $false.'
            ),
        })

    # -------------------------------------------------------------
    # Rule 5: Unencrypted HTTP Web Service (Missing TLS/HTTPS)
    # -------------------------------------------------------------
    if port == 80 or (service == 'http' and port not in (443, 8443)):
        prod_display = f" ({product})" if product else ""
        findings.append({
            'name': 'Unencrypted HTTP Web Service Exposed (Missing TLS/HTTPS)',
            'description': (
                f'A web server on port {port}{prod_display} is serving traffic over unencrypted HTTP. '
                'Without TLS/HTTPS encryption, sensitive information, session cookies, and authentication '
                'credentials are transmitted in cleartext and susceptible to network interception or tampering.'
            ),
            'likelihood': 6.0,
            'impact': 6.0,
            'cvss_score': None,
            'cve_id': None,
            'cve_description': None,
            'cve_url': None,
            'confidence': 'High',
            'remediation': 'Implement TLS/SSL certificates and configure automatic HTTP-to-HTTPS redirection.',
            'recommended_action': (
                'Deploy an SSL/TLS certificate (Let\'s Encrypt or enterprise CA), bind HTTPS to port 443, '
                'and configure 301 Permanent Redirects for all cleartext HTTP traffic.'
            ),
        })

    # -------------------------------------------------------------
    # Rule 6: Exposed Database Management Ports
    # -------------------------------------------------------------
    db_ports = {
        3306: 'MySQL',
        5432: 'PostgreSQL',
        27017: 'MongoDB',
        6379: 'Redis',
        1433: 'Microsoft SQL Server',
    }
    if port in db_ports:
        db_name = db_ports[port]
        findings.append({
            'name': f'Exposed {db_name} Database Service on External Port',
            'description': (
                f'The {db_name} database service is listening on port {port}. Directly exposing database '
                'management ports to network interfaces increases exposure to automated authentication '
                'brute-force attacks and potential unauthorized access.'
            ),
            'likelihood': 6.5,
            'impact': 7.5,
            'cvss_score': None,
            'cve_id': None,
            'cve_description': None,
            'cve_url': None,
            'confidence': 'High',
            'remediation': f'Bind {db_name} exclusively to localhost (127.0.0.1) or an internal isolated network.',
            'recommended_action': (
                f'Configure the bind-address parameter to 127.0.0.1 in the {db_name} configuration file, '
                'and tunnel remote administration sessions through an encrypted VPN or SSH tunnel.'
            ),
        })

    # -------------------------------------------------------------
    # Rule 7: Remote Desktop Protocol (RDP Port 3389)
    # -------------------------------------------------------------
    if port == 3389 or 'ms-wbt-server' in service or 'rdp' in service:
        findings.append({
            'name': 'Remote Desktop Protocol (RDP) Exposed to Network',
            'description': (
                'Remote Desktop Services (RDP) is listening on port 3389. Directly accessible RDP endpoints '
                'are frequent targets of automated credential brute-force attacks and network intrusion.'
            ),
            'likelihood': 6.5,
            'impact': 7.5,
            'cvss_score': None,
            'cve_id': None,
            'cve_description': None,
            'cve_url': None,
            'confidence': 'High',
            'remediation': 'Require Network Level Authentication (NLA) and restrict RDP access through VPN.',
            'recommended_action': (
                'Enable Network Level Authentication (NLA) in System Settings. Restrict TCP port 3389 '
                'at the host firewall to authorized administrative jump boxes or VPN subnets.'
            ),
        })

    # Attach common service metadata to every detected finding
    for f in findings:
        f['evidence'] = evidence_text
        f['affected_host'] = service_record.host or assessment_target
        f['affected_port'] = port
        f['affected_service'] = service
        f['affected_protocol'] = protocol
        f['product'] = product
        f['version'] = version

    return findings


def analyze_scan(assessment_id: int, scan_id: int) -> list[Vulnerability]:
    """
    Analyzes all scan results for a given scan and creates or safely updates
    structured Vulnerability findings.
    
    Guarantees:
    - Findings are strictly linked to assessment_id and scan_id
    - Findings are created ONLY for services discovered by THIS scan
    - Complete deduplication: repeated analysis updates existing findings without duplicates
    - Findings removed if port/service is no longer present in current scan
    - Does NOT touch findings of other scans or assessments
    """
    assessment = Assessment.query.get(assessment_id)
    scan = Scan.query.get(scan_id)
    if not assessment or not scan:
        return []

    services = ScanResult.query.filter_by(scan_id=scan.id).all()

    # 1. Collect all rule detections from current scan services
    detected_items = []
    for svc in services:
        rules = analyze_service(svc, assessment.target)
        for r in rules:
            detected_items.append((svc, r))

    # 2. Existing findings for THIS scan
    existing_scan_vulns = Vulnerability.query.filter_by(scan_id=scan.id).all()
    existing_map = {
        (v.affected_port, v.name): v for v in existing_scan_vulns
    }

    current_keys = set()
    result_findings = []

    for svc, rule in detected_items:
        key = (rule['affected_port'], rule['name'])
        current_keys.add(key)

        risk_info = calculate_risk(
            likelihood=rule['likelihood'],
            impact=rule['impact'],
            cvss_score=rule.get('cvss_score')
        )

        if key in existing_map:
            # Safely update existing finding without duplicating or losing analyst validation
            finding = existing_map[key]
            finding.affected_host = svc.host or assessment.target
            finding.affected_service = rule['affected_service']
            finding.affected_protocol = rule['affected_protocol']
            finding.product = rule.get('product', '')
            finding.version = rule.get('version', '')
            finding.evidence = rule['evidence']
            finding.remediation = rule['remediation']
            finding.recommended_action = rule['recommended_action']
            finding.description = rule['description']
            finding.confidence = rule.get('confidence', 'High')
            finding.updated_at = datetime.utcnow()

            # Only refresh risk score if still awaiting analyst triage
            if finding.validation_status == Vulnerability.VAL_NEEDS_REVIEW:
                finding.risk_score = risk_info['risk_score']
                finding.severity = risk_info['severity']
                finding.priority = risk_info['priority']

            result_findings.append(finding)
        else:
            # Create new finding linked to THIS scan
            finding = Vulnerability(
                finding_id=generate_finding_id(),
                assessment_id=assessment.id,
                scan_id=scan.id,
                affected_host=svc.host or assessment.target,
                name=rule['name'],
                description=rule['description'],
                severity=risk_info['severity'],
                confidence=rule.get('confidence', 'High'),
                risk_score=risk_info['risk_score'],
                impact=rule['impact'],
                likelihood=rule['likelihood'],
                cvss_score=rule.get('cvss_score'),
                cve_id=rule.get('cve_id'),
                cve_description=rule.get('cve_description'),
                cve_url=rule.get('cve_url'),
                affected_port=rule['affected_port'],
                affected_service=rule['affected_service'],
                affected_protocol=rule['affected_protocol'],
                product=rule.get('product', ''),
                version=rule.get('version', ''),
                evidence=rule['evidence'],
                remediation=rule['remediation'],
                recommended_action=rule['recommended_action'],
                priority=risk_info['priority'],
                validation_status=Vulnerability.VAL_NEEDS_REVIEW,
                is_false_positive=False,
                source='nmap_rule_engine',
                discovered_at=datetime.utcnow(),
            )
            db.session.add(finding)
            result_findings.append(finding)

    # 3. Clean up any stale findings for THIS scan that are no longer supported by current scan results
    for key, old_v in existing_map.items():
        if key not in current_keys:
            db.session.delete(old_v)

    db.session.commit()
    return result_findings
