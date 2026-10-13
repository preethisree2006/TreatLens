"""
ThreatLens — CVE Intelligence & Mapping Service
================================================
Queries authoritative CVE data from the NIST National Vulnerability Database
(NVD) API v2 and caches results locally in SQLite to prevent redundant API calls.

Gracefully handles offline environments, API rate limits, and network errors.
Strictly does NOT fabricate CVE IDs.
"""

import requests
from datetime import datetime
from database.db import db, CVERecord

NVD_API_BASE = 'https://services.nvd.nist.gov/rest/json/cves/2.0'
REQUEST_TIMEOUT = 5  # seconds

# Curated offline reference intelligence for common CVEs identified by the scanner
OFFLINE_CVE_INTEL = {
    'CVE-2011-2523': {
        'cve_id': 'CVE-2011-2523',
        'description': 'vsftpd 2.3.4 contains a backdoor in the smile function that triggers a root shell on port 6200.',
        'cvss_score': 9.8,
        'severity': 'Critical',
        'reference_url': 'https://nvd.nist.gov/vuln/detail/CVE-2011-2523',
    },
    'CVE-2017-0144': {
        'cve_id': 'CVE-2017-0144',
        'description': 'Microsoft Windows SMBv1 server remote code execution vulnerability (EternalBlue).',
        'cvss_score': 8.5,
        'severity': 'High',
        'reference_url': 'https://nvd.nist.gov/vuln/detail/CVE-2017-0144',
    },
    'CVE-1999-0619': {
        'cve_id': 'CVE-1999-0619',
        'description': 'Telnet transmits authentication and session communications in unencrypted cleartext.',
        'cvss_score': 7.5,
        'severity': 'High',
        'reference_url': 'https://nvd.nist.gov/vuln/detail/CVE-1999-0619',
    },
    'CVE-1999-0497': {
        'cve_id': 'CVE-1999-0497',
        'description': 'File Transfer Protocol (FTP) server authentication allows cleartext credential transmission.',
        'cvss_score': 6.5,
        'severity': 'Medium',
        'reference_url': 'https://nvd.nist.gov/vuln/detail/CVE-1999-0497',
    },
    'CVE-2019-0708': {
        'cve_id': 'CVE-2019-0708',
        'description': 'Remote Desktop Services remote code execution vulnerability (BlueKeep).',
        'cvss_score': 9.8,
        'severity': 'Critical',
        'reference_url': 'https://nvd.nist.gov/vuln/detail/CVE-2019-0708',
    },
    'CVE-2021-41773': {
        'cve_id': 'CVE-2021-41773',
        'description': 'Apache HTTP Server 2.4.49 path traversal and file disclosure vulnerability.',
        'cvss_score': 7.5,
        'severity': 'High',
        'reference_url': 'https://nvd.nist.gov/vuln/detail/CVE-2021-41773',
    },
}


def get_cve_info(cve_id: str) -> dict | None:
    """
    Retrieve CVE information with local SQLite caching.
    1. Check local CVERecord table.
    2. If missing, attempt query to NVD API.
    3. If external network unavailable, fallback to offline curated intel.
    """
    if not cve_id or not isinstance(cve_id, str):
        return None

    cve_id = cve_id.strip().upper()
    if not cve_id.startswith('CVE-'):
        return None

    # Step 1: Check SQLite database cache
    cached = CVERecord.query.filter_by(cve_id=cve_id).first()
    if cached:
        return {
            'cve_id': cached.cve_id,
            'description': cached.description,
            'cvss_score': cached.cvss_score,
            'severity': cached.severity,
            'reference_url': cached.reference_url,
            'source': 'Local Cache',
        }

    # Step 2: Try online NVD API v2
    try:
        url = f"{NVD_API_BASE}?cveId={cve_id}"
        headers = {'User-Agent': 'ThreatLens-Security-Assessment/1.0'}
        resp = requests.get(url, headers=headers, timeout=REQUEST_TIMEOUT)

        if resp.status_code == 200:
            data = resp.json()
            vulnerabilities = data.get('vulnerabilities', [])
            if vulnerabilities:
                cve_data = vulnerabilities[0].get('cve', {})
                desc_list = cve_data.get('descriptions', [])
                description = desc_list[0].get('value', '') if desc_list else ''

                # Extract CVSS
                cvss_score = None
                severity = 'Medium'
                metrics = cve_data.get('metrics', {})
                if 'cvssMetricV31' in metrics and metrics['cvssMetricV31']:
                    cvss_data = metrics['cvssMetricV31'][0].get('cvssData', {})
                    cvss_score = cvss_data.get('baseScore')
                    severity = cvss_data.get('baseSeverity', 'Medium').capitalize()
                elif 'cvssMetricV30' in metrics and metrics['cvssMetricV30']:
                    cvss_data = metrics['cvssMetricV30'][0].get('cvssData', {})
                    cvss_score = cvss_data.get('baseScore')
                    severity = cvss_data.get('baseSeverity', 'Medium').capitalize()

                ref_url = f"https://nvd.nist.gov/vuln/detail/{cve_id}"

                # Save to cache
                new_cache = CVERecord(
                    cve_id=cve_id,
                    description=description,
                    cvss_score=cvss_score,
                    severity=severity,
                    reference_url=ref_url,
                    cached_at=datetime.utcnow(),
                )
                db.session.add(new_cache)
                db.session.commit()

                return {
                    'cve_id': cve_id,
                    'description': description,
                    'cvss_score': cvss_score,
                    'severity': severity,
                    'reference_url': ref_url,
                    'source': 'NVD API',
                }
    except Exception:
        # Network timeout or API failure — fall back gracefully
        pass

    # Step 3: Offline curated fallback if network is unreachable
    if cve_id in OFFLINE_CVE_INTEL:
        info = OFFLINE_CVE_INTEL[cve_id]
        new_cache = CVERecord(
            cve_id=info['cve_id'],
            description=info['description'],
            cvss_score=info['cvss_score'],
            severity=info['severity'],
            reference_url=info['reference_url'],
            cached_at=datetime.utcnow(),
        )
        try:
            db.session.add(new_cache)
            db.session.commit()
        except Exception:
            db.session.rollback()

        return {**info, 'source': 'Curated Offline Intel'}

    return None
