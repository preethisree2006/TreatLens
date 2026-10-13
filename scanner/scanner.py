"""
Scanner Module — ThreatLens
===========================
Provides an object-oriented wrapper around the core Nmap scanner engine.
"""
from scanner.nmap_scanner import (
    run_nmap_scan,
    is_nmap_installed,
    validate_target,
    generate_scan_id,
    get_nmap_path,
)


class NmapScanner:
    """
    Nmap service discovery scanner interface.
    """

    def __init__(self, target: str, scan_type: str = 'basic'):
        self.target = target
        self.scan_type = scan_type

    def run(self) -> dict:
        """Execute the safe service discovery scan."""
        return run_nmap_scan(self.target)

    @staticmethod
    def is_available() -> bool:
        """Check if Nmap binary is found."""
        return is_nmap_installed()
