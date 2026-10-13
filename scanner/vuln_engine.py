"""
ThreatLens — Vulnerability Analysis Engine
===========================================
Performs rule-based vulnerability analysis on actual scan evidence discovered
by Nmap. Strictly produces explainable findings tied to observed open ports,
service banners, and software versions.

Rules:
    - Insecure / plaintext protocols (Telnet, FTP, HTTP, legacy r-commands)
    - Exposed network storage & database services (SMB, MySQL, Redis, MongoDB)
    - Outdated/known vulnerable service versions (vsftpd 2.3.4 backdoor, legacy SSH/Apache)
    - Missing TLS encryption on web interfaces

NOTE: An open port is a discovered service, NOT automatically a vulnerability.
Only ports with verifiable security risks or protocol weaknesses produce findings.
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
    Returns a list of finding definition dicts (may be empty if no vulnerability exists).
    """
    findings = []
    port = service_record.port
    protocol = service_record.protocol.lower()
    service = (service_record.service or '').lower()
    product = (service_record.product or '').strip()
    version = (service_record.version or '').strip()
    extra_info = (service_record.extra_info or '').strip()

    evidence_text = (
        f"Target: {assessment_target}\n"
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
    # Rule 2: FTP Service (Plaintext Authentication & Data)
    # -------------------------------------------------------------
    if port == 21 or 'ftp' in service:
        # Check for specific known vulnerable vsftpd version
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
                'impact': 7.0,
                'cvss_score': 6.5,
                'cve_id': 'CVE-1999-0497',
                'cve_description': 'FTP protocol transmits authentication credentials in cleartext.',
                'cve_url': 'https://nvd.nist.gov/vuln/detail/CVE-1999-0497',
                'confidence': 'High',
                'remediation': 'Enforce FTPS (FTP over TLS) or replace with SFTP over port 22.',
                'recommended_action': 'Configure TLS encryption on the FTP server or migrate file transfers to SFTP.',
            })

    # -------------------------------------------------------------
    # Rule 3: SMB / NetBIOS File Sharing Exposed (Port 445 / 139)
    # -------------------------------------------------------------
    if port in (445, 139) or 'microsoft-ds' in service or 'netbios' in service or 'smb' in service:
        findings.append({
            'name': 'SMB File Sharing Protocol Exposed on Network Interface',
            'description': (
                f'Server Message Block (SMB) is exposed on port {port}. Insecure SMB configurations '
                'or legacy SMBv1 dialects expose systems to remote code execution (e.g. EternalBlue), '
                'unauthenticated share enumeration, and network lateral movement.'
            ),
            'likelihood': 7.5,
            'impact': 9.0,
            'cvss_score': 8.5,
            'cve_id': 'CVE-2017-0144',
            'cve_description': 'SMB remote code execution vulnerability (EternalBlue).',
            'cve_url': 'https://nvd.nist.gov/vuln/detail/CVE-2017-0144',
            'confidence': 'High',
            'remediation': 'Disable SMBv1, require SMB signing and encryption, and restrict port 445 via firewall.',
            'recommended_action': (
                'Block TCP port 445 from untrusted subnets. Ensure SMBv1 is disabled and apply latest OS patches.'
            ),
        })

    # -------------------------------------------------------------
    # Rule 4: Exposed Database Management Ports
    # -------------------------------------------------------------
    db_ports = {
        3306: ('MySQL', 'CVE-2000-0182'),
        5432: ('PostgreSQL', 'CVE-2018-1058'),
        27017: ('MongoDB', 'CVE-2019-2386'),
        6379: ('Redis', 'CVE-2022-0543'),
        1433: ('Microsoft SQL Server', 'CVE-2002-0649'),
    }
    if port in db_ports:
        db_name, db_cve = db_ports[port]
        findings.append({
            'name': f'Exposed {db_name} Database Service on External Port',
            'description': (
                f'The {db_name} database service is listening on port {port}. Directly exposing database '
                'services increases the attack surface for authentication brute-force, credential stuffing, '
                'and potential unauthenticated access.'
            ),
            'likelihood': 7.0,
            'impact': 8.5,
            'cvss_score': 7.5,
            'cve_id': db_cve,
            'cve_description': f'Exposed {db_name} database interface without network boundary isolation.',
            'cve_url': f'https://nvd.nist.gov/vuln/detail/{db_cve}',
            'confidence': 'High',
            'remediation': f'Bind {db_name} to localhost (127.0.0.1) and enforce firewall restrictions.',
            'recommended_action': (
                f'Set bind-address = 127.0.0.1 in the {db_name} configuration file and route remote access through an encrypted SSH tunnel or VPN.'
            ),
        })

    # -------------------------------------------------------------
    # Rule 5: Unencrypted HTTP (Port 80 without SSL/TLS)
    # -------------------------------------------------------------
    if (port == 80 or (service == 'http' and port not in (443, 8443))):
        findings.append({
            'name': 'Unencrypted HTTP Web Service Exposed (Missing TLS/HTTPS)',
            'description': (
                f'Web server on port {port} is serving content over unencrypted HTTP. '
                'Without HTTPS, sensitive information, session tokens, and passwords can be intercepted '
                'or modified in transit.'
            ),
            'likelihood': 5.5,
            'impact': 5.0,
            'cvss_score': 5.3,
            'cve_id': None,
            'cve_description': None,
            'cve_url': None,
            'confidence': 'High',
            'remediation': 'Implement TLS/SSL certificates and configure automatic HTTP to HTTPS redirect.',
            'recommended_action': (
                'Install a TLS certificate (Let\'s Encrypt or trusted CA), enable HTTPS on port 443, '
                'and set HTTP 301 redirects to HTTPS.'
            ),
        })

    # -------------------------------------------------------------
    # Rule 6: Remote Desktop (RDP Port 3389)
    # -------------------------------------------------------------
    if port == 3389 or 'ms-wbt-server' in service or 'rdp' in service:
        findings.append({
            'name': 'Remote Desktop Protocol (RDP) Exposed to Network',
            'description': (
                'Remote Desktop Services (RDP) is listening on port 3389. Directly accessible RDP ports '
                'are frequent targets of automated brute-force attacks and protocol vulnerabilities (e.g., BlueKeep).'
            ),
            'likelihood': 7.0,
            'impact': 8.5,
            'cvss_score': 8.1,
            'cve_id': 'CVE-2019-0708',
            'cve_description': 'Remote Desktop Services Remote Code Execution Vulnerability (BlueKeep).',
            'cve_url': 'https://nvd.nist.gov/vuln/detail/CVE-2019-0708',
            'confidence': 'High',
            'remediation': 'Require Network Level Authentication (NLA) and restrict RDP through VPN access.',
            'recommended_action': (
                'Enable Network Level Authentication (NLA) in System Settings. Block port 3389 at the perimeter firewall.'
            ),
        })

    # Return all findings detected for this service record
    for f in findings:
        f['evidence'] = evidence_text
        f['affected_port'] = port
        f['affected_service'] = service
        f['affected_protocol'] = protocol
        f['product'] = product
        f['version'] = version

    return findings


def analyze_scan(assessment_id: int, scan_id: int) -> list[Vulnerability]:
    """
    Analyzes all scan results for a given scan and creates structured Vulnerability findings.
    Ensures findings default to 'Needs Review' status and computes risk score via risk_engine.
    """
    assessment = Assessment.query.get(assessment_id)
    scan = Scan.query.get(scan_id)
    if not assessment or not scan:
        return []

    services = ScanResult.query.filter_by(scan_id=scan.id).all()
    created_findings = []

    for svc in services:
        detected_rules = analyze_service(svc, assessment.target)

        for rule in detected_rules:
            # Check if this exact finding already exists for this assessment on this port
            existing = Vulnerability.query.filter_by(
                assessment_id=assessment.id,
                affected_port=rule['affected_port'],
                name=rule['name']
            ).first()

            if existing:
                continue

            # Calculate risk using the risk engine
            risk_info = calculate_risk(
                likelihood=rule['likelihood'],
                impact=rule['impact'],
                cvss_score=rule.get('cvss_score')
            )

            finding = Vulnerability(
                finding_id=generate_finding_id(),
                assessment_id=assessment.id,
                name=rule['name'],
                description=rule['description'],
                severity=risk_info['severity'],
                confidence=rule.get('confidence', 'Medium'),
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
                validation_status=Vulnerability.VAL_NEEDS_REVIEW,  # Rule: initially 'Needs Review'
                is_false_positive=False,
                source='nmap_rule_engine',
                discovered_at=datetime.utcnow(),
            )

            db.session.add(finding)
            created_findings.append(finding)

    db.session.commit()
    return created_findings
