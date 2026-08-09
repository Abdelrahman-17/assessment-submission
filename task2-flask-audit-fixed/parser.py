import ipaddress
import re
from collections import Counter
from datetime import datetime
from models import get_db_connection


def _read(path):
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        return f.read()


def _vendor(content):
    # Prefer explicit vendor syntax. Do not use interface description text for detection.
    if re.search(r"\bsysname\s+|^\s*peer\s+\d+\.\d+\.\d+\.\d+\s+as-number", content, re.I | re.M):
        return "Huawei"
    if re.search(r"\bhost-name\s+|^\s*system\s*\{|^\s*protocols\s*\{", content, re.I | re.M):
        return "Juniper"
    return "Cisco"


def _hostname(content):
    patterns = [
        r"\bhostname\s+([\w.-]+)",
        r"\bsysname\s+([\w.-]+)",
        r"\bhost-name\s+([\w.-]+)\s*;",
    ]
    for p in patterns:
        m = re.search(p, content, re.I)
        if m:
            return m.group(1)
    return "UNKNOWN_DEVICE"


def _mask_from_cidr(cidr):
    return str(ipaddress.IPv4Network(f"0.0.0.0/{cidr}").netmask)


def _extract_interfaces(content, vendor):
    results = []
    if vendor in ("Cisco", "Huawei"):
        blocks = re.finditer(r"^interface\s+(\S+)\s*$([\s\S]*?)(?=^!\s*$|^interface\s+\S+\s*$|\Z)", content, re.I | re.M)
        for m in blocks:
            name, body = m.group(1), m.group(2)
            ip_m = re.search(r"\bip\s+address\s+(\d+\.\d+\.\d+\.\d+)\s+(\d+\.\d+\.\d+\.\d+)", body, re.I)
            if ip_m:
                results.append((name, ip_m.group(1), ip_m.group(2)))
    else:
        for m in re.finditer(r"(?m)^\s*([a-z]+-?\d+/\d+/\d+|lo0)\s*\{([\s\S]*?)^\s*\}", content, re.I):
            name, body = m.group(1), m.group(2)
            ip_m = re.search(r"address\s+(\d+\.\d+\.\d+\.\d+)/(\d+)", body, re.I)
            if ip_m:
                results.append((name, ip_m.group(1), _mask_from_cidr(ip_m.group(2))))
    return results


def _extract_routing(content, vendor):
    protocols = []
    bgp_as = None
    ospf_areas = set()
    neighbors = []

    if vendor == "Juniper":
        if re.search(r"\bbgp\s*\{", content, re.I):
            protocols.append(("BGP", None))
            for m in re.finditer(r"\bneighbor\s+(\d+\.\d+\.\d+\.\d+)", content, re.I):
                neighbors.append((m.group(1), None))
        if re.search(r"\bospf\s*\{", content, re.I):
            protocols.append(("OSPF", None))
            ospf_areas.update(re.findall(r"\barea\s+([0-9.]+)\s*\{", content, re.I))
    else:
        bgp_m = re.search(r"(?:router\s+bgp|^bgp)\s+(\d+)", content, re.I | re.M)
        if bgp_m:
            bgp_as = bgp_m.group(1)
            protocols.append(("BGP", bgp_as))
            if vendor == "Cisco":
                for m in re.finditer(r"^\s*neighbor\s+(\d+\.\d+\.\d+\.\d+)\s+remote-as\s+(\d+)", content, re.I | re.M):
                    neighbors.append((m.group(1), m.group(2)))
            else:
                for m in re.finditer(r"^\s*peer\s+(\d+\.\d+\.\d+\.\d+)\s+as-number\s+(\d+)", content, re.I | re.M):
                    neighbors.append((m.group(1), m.group(2)))

        ospf_m = re.search(r"(?:^router\s+ospf|^ospf)\s+\d+", content, re.I | re.M)
        if ospf_m:
            protocols.append(("OSPF", ospf_m.group(0).split()[-1]))
            # Cisco/Huawei samples use area N in network/area lines or standalone area N.
            ospf_areas.update(re.findall(r"\barea\s+([0-9.]+)", content[ospf_m.start():], re.I))

    return protocols, bgp_as, sorted(ospf_areas), neighbors


def _extract_acls(content, vendor):
    names = []
    if vendor == "Cisco":
        names += re.findall(r"^\s*ip\s+access-list\s+(?:standard|extended)\s+(\S+)", content, re.I | re.M)
        names += re.findall(r"^\s*access-list\s+(\S+)", content, re.I | re.M)
    elif vendor == "Huawei":
        names += re.findall(r"^\s*acl\s+number\s+(\S+)", content, re.I | re.M)
    else:
        names += re.findall(r"\bfilter\s+(\S+)\s*\{", content, re.I)
        names += re.findall(r"\bpolicy-statement\s+(\S+)\s*\{", content, re.I)
    return sorted(set(names))


def parse_config_file(filepath, db_path="network_audit.db"):
    content = _read(filepath)
    vendor = _vendor(content)
    hostname = _hostname(content)
    interfaces = _extract_interfaces(content, vendor)
    protocols, bgp_as, ospf_areas, neighbors = _extract_routing(content, vendor)
    acls = _extract_acls(content, vendor)
    has_loopback0 = int(any(name.lower() in {"loopback0", "lo0", "lo0.0"} for name, _, _ in interfaces) or bool(re.search(r"interface\s+LoopBack0|\blo0\s*\{", content, re.I)))
    ospf_area = ospf_areas[0].replace("0.0.0.0", "0") if ospf_areas else None
    ospf_areas = [a.replace("0.0.0.0", "0") for a in ospf_areas]

    conn = get_db_connection(db_path)
    cur = conn.cursor()
    cur.execute("""
        INSERT INTO devices(hostname, vendor, has_loopback0, bgp_as, ospf_area)
        VALUES (?, ?, ?, ?, ?)
        ON CONFLICT(hostname) DO UPDATE SET
            vendor=excluded.vendor,
            has_loopback0=excluded.has_loopback0,
            bgp_as=excluded.bgp_as,
            ospf_area=excluded.ospf_area
    """, (hostname, vendor, has_loopback0, bgp_as, ospf_area))
    device_id = cur.execute("SELECT id FROM devices WHERE hostname=?", (hostname,)).fetchone()["id"]

    for table in ("interfaces", "routing_protocols", "bgp_neighbors", "ospf_areas", "acl_rules"):
        cur.execute(f"DELETE FROM {table} WHERE device_id=?", (device_id,))

    for name, ip_addr, mask in interfaces:
        cur.execute("INSERT INTO interfaces(device_id, interface_name, ip_address, subnet_mask) VALUES(?,?,?,?)", (device_id, name, ip_addr, mask))
    for protocol, process in protocols:
        cur.execute("INSERT INTO routing_protocols(device_id, protocol, process_or_as) VALUES(?,?,?)", (device_id, protocol, process))
    for neighbor_ip, remote_as in neighbors:
        cur.execute("INSERT INTO bgp_neighbors(device_id, neighbor_ip, remote_as) VALUES(?,?,?)", (device_id, neighbor_ip, remote_as))
    for area in ospf_areas:
        cur.execute("INSERT INTO ospf_areas(device_id, area) VALUES(?,?)", (device_id, area))
    for acl in acls:
        cur.execute("INSERT INTO acl_rules(device_id, rule_name) VALUES(?,?)", (device_id, acl))

    conn.commit()
    conn.close()
    return hostname


def classify_log(description):
    text = description.upper()
    if any(x in text for x in ("INTERFACE", "LINK PROTOCOL")):
        return "Interface"
    if "BGP" in text:
        return "BGP"
    if "CPU" in text:
        return "CPU"
    if any(x in text for x in ("TEMPERATURE", "THERMAL")):
        return "Thermal"
    if "SNMP" in text or "AUTHENTICATION FAILURE" in text:
        return "SNMP/Security"
    return "Other"


def risk_for_log(severity, description):
    text = description.upper()
    if "95%" in text or "CRITICAL" in text:
        return "Critical"
    if severity.upper() in {"ERROR", "CRITICAL"}:
        return "High"
    if any(x in text for x in ("FAIL", "EXCEEDED", "DOWN", "FLAP", "OVERLAP", "MISMATCH")):
        return "High"
    if severity.upper() in {"WARNING", "WARN"}:
        return "Medium"
    return "Info"


def parse_log_file(filepath, db_path="network_audit.db"):
    conn = get_db_connection(db_path)
    cur = conn.cursor()
    pattern = re.compile(r"^(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+(\S+)\s+(.+)$")
    with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            m = pattern.match(line)
            if not m:
                continue
            ts, device, severity, description = m.groups()
            cur.execute("INSERT INTO log_events(timestamp,device_name,category,severity,description,risk_level) VALUES(?,?,?,?,?,?)",
                        (ts, device, classify_log(description), severity, description, risk_for_log(severity, description)))
    conn.commit()
    conn.close()


def run_network_validations(db_path="network_audit.db"):
    conn = get_db_connection(db_path)
    cur = conn.cursor()
    cur.execute("DELETE FROM audit_validations")

    devices = cur.execute("SELECT * FROM devices ORDER BY hostname").fetchall()
    for dev in devices:
        status = "PASS" if dev["has_loopback0"] else "FAIL"
        detail = "Loopback0 interface is configured." if dev["has_loopback0"] else "Missing Loopback0 interface."
        cur.execute("INSERT INTO audit_validations(device_name,rule_checked,status,details) VALUES(?,?,?,?)", (dev["hostname"], "Loopback0 Status", status, detail))

    interfaces = cur.execute("""
        SELECT d.hostname, i.interface_name, i.ip_address, i.subnet_mask
        FROM interfaces i JOIN devices d ON d.id=i.device_id
        WHERE i.ip_address IS NOT NULL AND i.subnet_mask IS NOT NULL
    """).fetchall()
    networks = []
    for row in interfaces:
        try:
            net = ipaddress.ip_network(f"{row['ip_address']}/{row['subnet_mask']}", strict=False)
            networks.append((row["hostname"], row["interface_name"], row["ip_address"], net))
        except ValueError:
            cur.execute("INSERT INTO audit_validations(device_name,rule_checked,status,details) VALUES(?,?,?,?)",
                        (row["hostname"], "IP Address Format", "FAIL", f"Invalid IP/subnet on {row['interface_name']}: {row['ip_address']}/{row['subnet_mask']}"))

    overlap_devices = set()
    for i, a in enumerate(networks):
        for b in networks[i + 1:]:
            if a[0] != b[0] and a[3].overlaps(b[3]):
                overlap_devices.update((a[0], b[0]))
                cur.execute("INSERT INTO audit_validations(device_name,rule_checked,status,details) VALUES(?,?,?,?)",
                            (a[0], "Subnet Overlap", "FAIL", f"{a[1]} {a[3]} overlaps {b[0]} {b[1]} {b[3]}"))
    for dev in devices:
        if dev["hostname"] not in overlap_devices:
            cur.execute("INSERT INTO audit_validations(device_name,rule_checked,status,details) VALUES(?,?,?,?)",
                        (dev["hostname"], "Subnet Overlap", "PASS", "No overlapping subnets detected with other devices."))

    bgp = [d for d in devices if d["bgp_as"]]
    if bgp:
        base_as = Counter(d["bgp_as"] for d in bgp).most_common(1)[0][0]
        for dev in bgp:
            status = "PASS" if dev["bgp_as"] == base_as else "FAIL"
            detail = f"BGP AS {dev['bgp_as']} matches the dominant configured AS {base_as}." if status == "PASS" else f"BGP AS {dev['bgp_as']} differs from dominant AS {base_as}."
            cur.execute("INSERT INTO audit_validations(device_name,rule_checked,status,details) VALUES(?,?,?,?)", (dev["hostname"], "BGP AS Consistency", status, detail))

    ospf = [d for d in devices if d["ospf_area"]]
    if ospf:
        base_area = Counter(d["ospf_area"] for d in ospf).most_common(1)[0][0]
        for dev in ospf:
            status = "PASS" if dev["ospf_area"] == base_area else "FAIL"
            detail = f"OSPF area {dev['ospf_area']} matches dominant area {base_area}." if status == "PASS" else f"OSPF area {dev['ospf_area']} differs from dominant area {base_area}."
            cur.execute("INSERT INTO audit_validations(device_name,rule_checked,status,details) VALUES(?,?,?,?)", (dev["hostname"], "OSPF Area Consistency", status, detail))

    for dev in devices:
        risk_count = cur.execute("SELECT COUNT(*) FROM log_events WHERE device_name=? AND risk_level IN ('High','Critical')", (dev["hostname"],)).fetchone()[0]
        status = "FAIL" if risk_count else "PASS"
        detail = f"{risk_count} high-risk log event(s) linked to this device." if risk_count else "No High/Critical log events linked to this device."
        cur.execute("INSERT INTO audit_validations(device_name,rule_checked,status,details) VALUES(?,?,?,?)", (dev["hostname"], "High-Risk Log Findings", status, detail))

    conn.commit()
    conn.close()
