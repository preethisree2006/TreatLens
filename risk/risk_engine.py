"""
ThreatLens — Risk Scoring Engine
=================================
Calculates explainable numerical risk scores and prioritizes vulnerabilities
based on Likelihood, Impact, and optional CVSS reference metrics.

Risk Formulation:
    Risk Score (0.0 – 10.0) = (Likelihood × Impact) / 10.0
    If CVSS v3 score is available:
        Combined Score = round(0.6 * CVSS + 0.4 * (Likelihood × Impact / 10.0), 1)

Severity Classification:
    Critical      : 9.0 – 10.0   (Priority 1: Immediate action)
    High          : 7.0 – 8.9    (Priority 2: Address within 24 hours)
    Medium        : 4.0 – 6.9    (Priority 3: Address within 7 days)
    Low           : 1.0 – 3.9    (Priority 4: Address within 30 days)
    Informational : 0.0 – 0.9    (Priority 5: Informational guidance)
"""

SEVERITY_THRESHOLDS = {
    'Critical':      (9.0, 10.0),
    'High':          (7.0, 8.9),
    'Medium':        (4.0, 6.9),
    'Low':           (1.0, 3.9),
    'Informational': (0.0, 0.9),
}

PRIORITY_MAP = {
    'Critical':      1,
    'High':          2,
    'Medium':        3,
    'Low':           4,
    'Informational': 5,
}

SLA_MAP = {
    1: 'Immediate Remediation (Within 4 hours)',
    2: 'Urgent (Within 24 hours)',
    3: 'Scheduled (Within 7 days)',
    4: 'Low Priority (Within 30 days)',
    5: 'Informational (As scheduled)',
}


def calculate_risk(likelihood: float, impact: float, cvss_score: float = None) -> dict:
    """
    Compute structured risk score, severity, and remediation priority.

    Args:
        likelihood: Value between 1.0 and 10.0
        impact: Value between 1.0 and 10.0
        cvss_score: Optional CVSS base score (0.0 – 10.0)

    Returns:
        dict: {
            'risk_score': float,
            'severity': str,
            'priority': int,
            'sla': str,
            'likelihood': float,
            'impact': float
        }
    """
    # Clamp inputs
    lh = max(1.0, min(10.0, float(likelihood)))
    imp = max(1.0, min(10.0, float(impact)))

    # Base calculated score
    raw_score = (lh * imp) / 10.0

    if cvss_score is not None and 0.0 <= cvss_score <= 10.0:
        # Weighted blend: 60% CVSS authoritative score, 40% contextual likelihood/impact
        final_score = round(0.6 * cvss_score + 0.4 * raw_score, 1)
    else:
        final_score = round(raw_score, 1)

    final_score = max(0.0, min(10.0, final_score))
    severity = classify_severity(final_score)
    priority = PRIORITY_MAP.get(severity, 5)
    sla = SLA_MAP.get(priority, 'When possible')

    return {
        'risk_score': final_score,
        'severity': severity,
        'priority': priority,
        'sla': sla,
        'likelihood': lh,
        'impact': imp,
    }


def classify_severity(risk_score: float) -> str:
    """Classify numeric risk score into standard severity categories."""
    if risk_score >= 9.0:
        return 'Critical'
    elif risk_score >= 7.0:
        return 'High'
    elif risk_score >= 4.0:
        return 'Medium'
    elif risk_score >= 1.0:
        return 'Low'
    return 'Informational'


def get_priority(severity: str) -> int:
    """Return numeric priority (1=Critical, 5=Informational)."""
    return PRIORITY_MAP.get(severity, 5)


def get_sla(priority: int) -> str:
    """Return SLA timeline based on numeric priority."""
    return SLA_MAP.get(priority, 'When possible')
