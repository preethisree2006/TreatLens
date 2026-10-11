"""
CVE Service — Phase 5 (Placeholder)
=====================================
Fetches CVE information from the NIST National Vulnerability Database (NVD) API.

Phase 5 implementation plan:
    - Query NVD API v2: https://services.nvd.nist.gov/rest/json/cves/2.0
    - Cache results in the database to avoid repeated API calls
    - Graceful fallback if API is unavailable
    - Extract: CVE ID, description, CVSS score, CWE, references

API Endpoint:
    GET https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-XXXX-XXXX

NOTE: Phase 5 will implement this fully.
"""

import requests
from typing import Optional

NVD_API_BASE = 'https://services.nvd.nist.gov/rest/json/cves/2.0'
REQUEST_TIMEOUT = 10  # seconds


def get_cve_info(cve_id: str) -> Optional[dict]:
    """
    Fetch CVE details from NVD API.

    Phase 5 will implement full error handling, caching, and retries.

    Args:
        cve_id: e.g. 'CVE-2017-0144'

    Returns:
        dict with keys: cve_id, description, cvss_score, severity, references
        or None if not found / API unavailable.
    """
    raise NotImplementedError("CVE service not yet implemented. Coming in Phase 5.")


def search_cves_by_keyword(keyword: str, limit: int = 10) -> list:
    """
    Search NVD for CVEs matching a keyword (e.g., service name).

    Phase 5 will implement this.
    """
    raise NotImplementedError("CVE search not yet implemented. Coming in Phase 5.")
