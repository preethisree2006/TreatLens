"""
Nmap Output Parser — Phase 3 (Placeholder)
==========================================
Will parse raw Nmap scan output (XML/dict) into structured
Vulnerability objects ready for database insertion.

Phase 3 implementation plan:
    - parse_nmap_result(nm_result) → list[dict]
    - classify_port_vulnerability(port, service, version) → dict
    - extract_cve_hints(script_output) → list[str]
"""


def parse_nmap_result(nm_result: dict) -> list:
    """
    Parse python-nmap result dict into a list of vulnerability dicts.

    Phase 3 will implement this fully. Currently a placeholder.

    Args:
        nm_result: dict from nmap.PortScanner().scan()

    Returns:
        list of dicts, each representing a potential vulnerability finding.
    """
    raise NotImplementedError("Parser not yet implemented. Coming in Phase 3.")
