"""
Risk Engine — Phase 4 (Placeholder)
=====================================
Calculates risk scores and prioritizes vulnerabilities.

Scoring Logic (to be implemented in Phase 4):
---------------------------------------------
Base Score = CVSS score if available, else heuristic score.

Heuristic scoring factors:
    1. Port exposure          : External ports score higher
    2. Service criticality    : SSH, Telnet, RDP, SMB score higher
    3. Authentication bypass  : No-auth services score higher
    4. Known CVE              : +1.5 if a CVE exists
    5. Encryption absent      : +1.0 for plaintext protocols

Priority Matrix:
    Critical (9.0–10.0) → Priority 1 → Immediate action
    High     (7.0–8.9)  → Priority 2 → Address within 24 hours
    Medium   (4.0–6.9)  → Priority 3 → Address within 7 days
    Low      (0.1–3.9)  → Priority 4 → Address within 30 days
    Info     (0.0)      → Priority 5 → Informational only

NOTE: Phase 4 will implement this fully.
"""

SEVERITY_THRESHOLDS = {
    'Critical': (9.0, 10.0),
    'High':     (7.0, 8.9),
    'Medium':   (4.0, 6.9),
    'Low':      (0.1, 3.9),
    'Informational': (0.0, 0.0),
}


def calculate_risk_score(service: str, port: int, has_cve: bool = False,
                          is_authenticated: bool = True, cvss: float = None) -> float:
    """
    Calculate a risk score (0.0–10.0) for a detected service/vulnerability.

    Phase 4 will implement full logic. Returns placeholder value.
    """
    if cvss is not None:
        return min(cvss, 10.0)
    return 5.0  # Default placeholder


def classify_severity(risk_score: float) -> str:
    """Map a numeric risk score to a severity label."""
    if risk_score >= 9.0:
        return 'Critical'
    elif risk_score >= 7.0:
        return 'High'
    elif risk_score >= 4.0:
        return 'Medium'
    elif risk_score > 0.0:
        return 'Low'
    return 'Informational'


def get_priority(severity: str) -> int:
    """Return numeric priority (lower = more urgent)."""
    return {'Critical': 1, 'High': 2, 'Medium': 3, 'Low': 4, 'Informational': 5}.get(severity, 5)
