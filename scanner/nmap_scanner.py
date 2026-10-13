"""
Nmap Scanner Module — Phase 3: Controlled Vulnerability Scanning Foundation
==========================================================================
Executes authorized, safe Nmap service detection scans (-sV -T3) using Python's
subprocess module. Strictly avoids aggressive options, exploitation, and shell injection.
"""
import os
import shutil
import re
import ipaddress
import tempfile
import subprocess
from datetime import datetime
from scanner.parser import parse_nmap_xml, parse_nmap_text


# Exact error message required when Nmap cannot be located
NMAP_NOT_FOUND_MSG = (
    "Nmap is not installed or could not be found. "
    "Please install Nmap and ensure it is available in the system PATH."
)


def get_nmap_path() -> str | None:
    """
    Locate the Nmap executable in PATH or standard Windows installation locations.
    Returns the path string if found, otherwise None.
    """
    # 1. Check system PATH
    found = shutil.which('nmap') or shutil.which('nmap.exe')
    if found:
        return found

    # 2. Check standard Windows default directories
    common_win_paths = [
        os.path.expandvars(r'%ProgramFiles%\Nmap\nmap.exe'),
        os.path.expandvars(r'%ProgramFiles(x86)%\Nmap\nmap.exe'),
        r'C:\Program Files\Nmap\nmap.exe',
        r'C:\Program Files (x86)\Nmap\nmap.exe',
    ]

    for p in common_win_paths:
        if os.path.isfile(p):
            return p

    return None


def is_nmap_installed() -> bool:
    """Check if Nmap is installed and accessible."""
    return get_nmap_path() is not None


def validate_target(target: str) -> tuple[bool, str]:
    """
    Validate target input before running Nmap.
    Accepts:
        - 'localhost'
        - Valid IPv4 address (e.g. '127.0.0.1', '192.168.1.100')
        - Valid hostname/domain (e.g. 'lab.local')
    Rejects:
        - Any flag/option injection (e.g. starting with '-')
        - Whitespace or command separator characters
    """
    if not target or not isinstance(target, str):
        return False, "Target cannot be empty."

    target_clean = target.strip()

    if not target_clean:
        return False, "Target cannot be empty."

    # Prevent command-line flag injection
    if target_clean.startswith('-'):
        return False, "Invalid target: target cannot start with a hyphen (-)."

    # Reject dangerous characters
    disallowed_chars = set(" ;&|`$<>(){}[]*?'\"\\\n\r\t")
    if any(ch in disallowed_chars for ch in target_clean):
        return False, "Invalid target: target contains invalid characters or command separators."

    # 1. Allow 'localhost'
    if target_clean.lower() == 'localhost':
        return True, target_clean

    # 2. Allow valid IPv4 address
    try:
        ip = ipaddress.ip_address(target_clean)
        if isinstance(ip, ipaddress.IPv4Address):
            return True, str(ip)
    except ValueError:
        pass

    # 3. Allow valid hostname (RFC 1123 format)
    hostname_regex = re.compile(
        r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?$'
    )
    if hostname_regex.match(target_clean) and len(target_clean) <= 253:
        return True, target_clean

    return False, "Invalid target: please enter 'localhost', a valid IPv4 address (e.g., 127.0.0.1), or an authorized hostname."


def generate_scan_id() -> str:
    """
    Generate a unique Scan ID formatted as: SCN-YYYYMMDD-XXX
    Example: SCN-20261013-001
    """
    from database.db import Scan
    today_str = datetime.now().strftime('%Y%m%d')
    prefix = f"SCN-{today_str}-"

    latest = (
        Scan.query
        .filter(Scan.scan_id.like(f"{prefix}%"))
        .order_by(Scan.id.desc())
        .first()
    )

    if latest and latest.scan_id:
        try:
            seq_part = latest.scan_id.split('-')[-1]
            next_seq = int(seq_part) + 1
        except (ValueError, IndexError):
            next_seq = 1
    else:
        next_seq = 1

    return f"{prefix}{next_seq:03d}"


def run_nmap_scan(target: str, timeout: int = 180) -> dict:
    """
    Executes an authorized Nmap service discovery scan (-sV -T3) safely.

    Returns dict:
        {
            'success': bool,
            'status': 'Completed' | 'Failed',
            'target': str,
            'command': str,
            'raw_output': str,
            'error': str,
            'services': list[dict]
        }
    """
    # 1. Validate target
    is_valid, target_or_err = validate_target(target)
    if not is_valid:
        return {
            'success': False,
            'status': 'Failed',
            'target': target,
            'command': f'nmap -sV -T3 {target}',
            'raw_output': '',
            'error': target_or_err,
            'services': [],
        }

    target = target_or_err

    # 2. Check Nmap availability
    nmap_path = get_nmap_path()
    if not nmap_path:
        return {
            'success': False,
            'status': 'Failed',
            'target': target,
            'command': f'nmap -sV -T3 {target}',
            'raw_output': '',
            'error': NMAP_NOT_FOUND_MSG,
            'services': [],
        }

    # 3. Create a temporary XML file for structured parsing
    tmp_fd, xml_path = tempfile.mkstemp(suffix='.xml', prefix='threatlens_scan_')
    os.close(tmp_fd)

    # Subprocess arguments list (never use shell=True or string concatenation)
    cmd = [nmap_path, '-sV', '-T3', '-oX', xml_path, target]
    command_str = f"nmap -sV -T3 {target}"

    try:
        proc = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=timeout,
        )

        raw_output = proc.stdout or ''
        if proc.stderr:
            raw_output += f"\n[Nmap Stderr]\n{proc.stderr}"

        # Parse XML file
        services = []
        if os.path.exists(xml_path) and os.path.getsize(xml_path) > 0:
            services = parse_nmap_xml(xml_path, default_host=target)

        # Fallback to text parsing if XML produced 0 services but stdout exists
        if not services and raw_output:
            services = parse_nmap_text(raw_output, default_host=target)

        is_success = (proc.returncode == 0) or len(services) > 0
        error_msg = '' if is_success else (proc.stderr.strip() or f'Nmap process exited with code {proc.returncode}')

        return {
            'success': is_success,
            'status': 'Completed' if is_success else 'Failed',
            'target': target,
            'command': command_str,
            'raw_output': raw_output,
            'error': error_msg,
            'services': services,
        }

    except subprocess.TimeoutExpired:
        return {
            'success': False,
            'status': 'Failed',
            'target': target,
            'command': command_str,
            'raw_output': f'Scan execution timed out after {timeout} seconds.',
            'error': f'Scan timed out after {timeout} seconds.',
            'services': [],
        }
    except Exception as e:
        return {
            'success': False,
            'status': 'Failed',
            'target': target,
            'command': command_str,
            'raw_output': '',
            'error': f'Scan execution failure: {str(e)}',
            'services': [],
        }
    finally:
        # Clean up temporary XML file
        if os.path.exists(xml_path):
            try:
                os.remove(xml_path)
            except OSError:
                pass
