"""
Nmap Output Parser — Phase 3: Service Discovery
===============================================
Parses Nmap output (XML and plain text) into structured service discovery
records (port, protocol, state, service, product, version).

NOTE: Phase 3 performs service discovery only. No vulnerability classification
or CVE correlation is performed in this module.
"""
import os
import re
import xml.etree.ElementTree as ET


def parse_nmap_xml(xml_source: str, default_host: str = 'localhost') -> list[dict]:
    """
    Parse Nmap XML output into a structured list of discovered services.
    
    Args:
        xml_source: Path to an XML file, or raw XML string.
        default_host: Fallback host identifier if address is missing.

    Returns:
        list of dicts: [
            {
                'host': '127.0.0.1',
                'port': 80,
                'protocol': 'tcp',
                'state': 'open',
                'service': 'http',
                'product': 'Apache httpd',
                'version': '2.4.41',
                'extra_info': '(Ubuntu)',
            }, ...
        ]
    """
    services = []

    try:
        if os.path.exists(xml_source):
            tree = ET.parse(xml_source)
            root = tree.getroot()
        else:
            root = ET.fromstring(xml_source)
    except Exception:
        # If XML parse fails (e.g. corrupt or empty), return empty list
        return []

    for host_el in root.findall('host'):
        # Check host status
        status_el = host_el.find('status')
        # Extract host address
        addr = default_host
        addr_el = host_el.find('address')
        if addr_el is not None and 'addr' in addr_el.attrib:
            addr = addr_el.attrib['addr']

        # Extract ports
        ports_el = host_el.find('ports')
        if ports_el is None:
            continue

        for port_el in ports_el.findall('port'):
            protocol = port_el.attrib.get('protocol', 'tcp')
            try:
                port_id = int(port_el.attrib.get('portid', 0))
            except (ValueError, TypeError):
                continue

            state_el = port_el.find('state')
            state = state_el.attrib.get('state', 'unknown') if state_el is not None else 'unknown'

            # Service details
            service_name = 'unknown'
            product = ''
            version = ''
            extra_info = ''

            service_el = port_el.find('service')
            if service_el is not None:
                service_name = service_el.attrib.get('name', 'unknown')
                product = service_el.attrib.get('product', '')
                version = service_el.attrib.get('version', '')
                extra_info = service_el.attrib.get('extrainfo', '')

            services.append({
                'host': addr,
                'port': port_id,
                'protocol': protocol,
                'state': state,
                'service': service_name,
                'product': product,
                'version': version,
                'extra_info': extra_info,
            })

    return services


def parse_nmap_text(text: str, default_host: str = 'localhost') -> list[dict]:
    """
    Fallback regex parser for standard Nmap terminal text output.
    Matches lines like:
    80/tcp   open  http    Apache httpd 2.4.41 ((Ubuntu))
    """
    services = []
    if not text:
        return services

    # Regex matching port lines: <port>/<protocol>  <state>  <service>  [version info]
    port_pattern = re.compile(
        r'^\s*(\d+)/(tcp|udp)\s+(\w+)\s+(\S+)(?:\s+(.*))?$',
        re.MULTILINE
    )

    for match in port_pattern.finditer(text):
        port_num = int(match.group(1))
        protocol = match.group(2)
        state = match.group(3)
        service = match.group(4)
        rest = (match.group(5) or '').strip()

        product = rest
        version = ''
        extra_info = ''

        # Simple split of product and version if version digits exist
        ver_match = re.search(r'(\d+[\.\d\w\-_]+)', rest)
        if ver_match:
            v_start = ver_match.start()
            product = rest[:v_start].strip()
            version = rest[v_start:].strip()

        services.append({
            'host': default_host,
            'port': port_num,
            'protocol': protocol,
            'state': state,
            'service': service,
            'product': product,
            'version': version,
            'extra_info': extra_info,
        })

    return services
