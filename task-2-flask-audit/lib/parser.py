import re
import ipaddress
from models import get_db_connection

def parse_config_file(filepath, db_path="network_audit.db"):
    with open(filepath, 'r') as f:
        content = f.read()

    hostname = "UNKNOWN_DEVICE"
    host_match = re.search(r'(?:hostname|sysname|host-name)\s+["\']?([a-zA-Z0-9_-]+)["\']?;?', content, re.IGNORECASE)
    if host_match:
        hostname = host_match.group(1)

    has_loopback0 = 1 if re.search(r'interface\s+LoopBack0|interface\s+lo0|lo0\s*\{', content, re.IGNORECASE) else 0

    bgp_as = None
    bgp_match = re.search(r'(?:router\s+bgp|bgp)\s+(\d+)', content, re.IGNORECASE)
    if bgp_match:
        bgp_as = bgp_match.group(1)

    ospf_area = None
    ospf_match = re.search(r'area\s+([0-9\.]+)', content, re.IGNORECASE)
    if ospf_match:
        ospf_area = ospf_match.group(1)

    conn = get_db_connection(db_path)
    cursor = conn.cursor()

    cursor.execute('''
        INSERT INTO devices (hostname, has_loopback0, bgp_as, ospf_area)
        VALUES (?, ?, ?, ?)
        ON CONFLICT(hostname) DO UPDATE SET
            has_loopback0=excluded.has_loopback0,
            bgp_as=excluded.bgp_as,
            ospf_area=excluded.ospf_area
    ''', (hostname, has_loopback0, bgp_as, ospf_area))

    cursor.execute("SELECT id FROM devices WHERE hostname = ?", (hostname,))
    device_id = cursor.fetchone()['id']

    cursor.execute("DELETE FROM interfaces WHERE device_id = ?", (device_id,))
    cursor.execute("DELETE FROM acl_rules WHERE device_id = ?", (device_id,))

    # Cisco / Huawei style
    standard_ifaces = re.findall(r'interface\s+(\S+)\n([\s\S]*?)(?=!|interface|sysname|hostname|return|$)', content, re.IGNORECASE)
    for iface_name, iface_body in standard_ifaces:
        ip_match = re.search(r'ip\s+address\s+(\d+\.\d+\.\d+\.\d+)\s+(\d+\.\d+\.\d+\.\d+)', iface_body, re.IGNORECASE)
        if ip_match:
            ip_addr, mask = ip_match.groups()
            cursor.execute('''
                INSERT INTO interfaces (device_id, interface_name, ip_address, subnet_mask)
                VALUES (?, ?, ?, ?)
            ''', (device_id, iface_name, ip_addr, mask))

    # Juniper style
    juniper_ifaces = re.findall(r'(\S+)\s*\{\s*description[\s\S]*?address\s+(\d+\.\d+\.\d+\.\d+)\/(\d+)', content, re.IGNORECASE)
    for iface_name, ip_addr, cidr in juniper_ifaces:
        net = ipaddress.IPv4Network(f"0.0.0.0/{cidr}")
        mask = str(net.netmask)
        cursor.execute('''
            INSERT INTO interfaces (device_id, interface_name, ip_address, subnet_mask)
            VALUES (?, ?, ?, ?)
        ''', (device_id, iface_name, ip_addr, mask))

    acls = re.findall(r'(?:access-list|ip\s+access-list\s+extended|acl\s+number)\s+(\S+)', content, re.IGNORECASE)
    for acl in acls:
        cursor.execute('''
            INSERT INTO acl_rules (device_id, rule_name)
            VALUES (?, ?)
        ''', (device_id, str(acl)))

    conn.commit()
    conn.close()
    return hostname

def parse_log_file(filepath, db_path="network_audit.db"):
    conn = get_db_connection(db_path)
    cursor = conn.cursor()

    with open(filepath, 'r') as f:
        for line in f:
            match = re.search(r'(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})?\s*([a-zA-Z0-9_-]+)?\s*(%?\w+[-:]\d?[-:]?\w+)?:?\s*(.*)', line)
            if match:
                ts, device, category, desc = match.groups()
                ts = ts or "2026-08-09 12:00:00"
                device = device or "UNKNOWN"
                category = category or "SYSTEM"
                desc = desc or line.strip()

                risk_level = "Info"
                if any(k in desc.upper() for k in ["DOWN", "FAIL", "FLAP", "OVERLAP", "ERROR", "CRITICAL"]):
                    risk_level = "Critical"
                elif any(k in desc.upper() for k in ["WARN", "MISMATCH", "EXCEEDED"]):
                    risk_level = "High"

                cursor.execute('''
                    INSERT INTO log_events (timestamp, device_name, category, severity, description, risk_level)
                    VALUES (?, ?, ?, ?, ?, ?)
                ''', (ts, device, category, "3", desc, risk_level))

    conn.commit()
    conn.close()

def run_network_validations(db_path="network_audit.db"):
    conn = get_db_connection(db_path)
    cursor = conn.cursor()

    cursor.execute("DELETE FROM audit_validations")
    cursor.execute("SELECT id, hostname, has_loopback0, bgp_as, ospf_area FROM devices")
    devices = cursor.fetchall()

    for dev in devices:
        if dev['has_loopback0'] == 1:
            cursor.execute("INSERT INTO audit_validations VALUES (NULL, ?, 'Loopback0 Status', 'PASS', 'Loopback0 interface is properly configured.')", (dev['hostname'],))
        else:
            cursor.execute("INSERT INTO audit_validations VALUES (NULL, ?, 'Loopback0 Status', 'FAIL', 'CRITICAL: Missing Loopback0 interface!')", (dev['hostname'],))

    cursor.execute("SELECT d.hostname, i.interface_name, i.ip_address, i.subnet_mask FROM interfaces i JOIN devices d ON i.device_id = d.id")
    interfaces = cursor.fetchall()
    
    subnets = []
    ip_map = {}
    for iface in interfaces:
        try:
            net = ipaddress.IPv4Network(f"{iface['ip_address']}/{iface['subnet_mask']}", strict=False)
            subnets.append((iface['hostname'], iface['interface_name'], iface['ip_address'], net))
            
            if iface['ip_address'] in ip_map and ('loop' in iface['interface_name'].lower() or 'lo' in iface['interface_name'].lower()):
                other_dev = ip_map[iface['ip_address']]
                cursor.execute("INSERT INTO audit_validations VALUES (NULL, ?, 'Duplicate Loopback IP', 'FAIL', ?)",
                               (iface['hostname'], f"Duplicate Loopback IP {iface['ip_address']} conflicts with {other_dev}"))
            ip_map[iface['ip_address']] = iface['hostname']
        except Exception:
            continue

    for i in range(len(subnets)):
        for j in range(i + 1, len(subnets)):
            dev1, if1, ip1, net1 = subnets[i]
            dev2, if2, ip2, net2 = subnets[j]
            if dev1 != dev2 and net1.overlaps(net2):
                cursor.execute("INSERT INTO audit_validations VALUES (NULL, ?, 'Subnet Overlap', 'FAIL', ?)",
                               (dev1, f"Subnet overlap detected with {dev2} ({if2}: {ip2})"))

    bgp_units = [d for d in devices if d['bgp_as']]
    if bgp_units:
        base_as = bgp_units[0]['bgp_as']
        for dev in bgp_units:
            if dev['bgp_as'] != base_as:
                cursor.execute("INSERT INTO audit_validations VALUES (NULL, ?, 'BGP AS Consistency', 'FAIL', ?)",
                               (dev['hostname'], f"BGP AS Mismatch: Uses AS {dev['bgp_as']} instead of main AS {base_as}"))

    conn.commit()
    conn.close()
