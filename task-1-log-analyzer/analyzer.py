import os
import re
import sqlite3
import csv
import argparse
from datetime import datetime
import matplotlib.pyplot as plt

# ==========================================
# 1. Regex Patterns
# ==========================================
LOG_PATTERN = re.compile(
    r'^(?P<timestamp>\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})\s+'
    r'(?P<device>\w+)\s+'
    r'%?(?P<severity>EMERG|ALERT|CRIT|ERR|ERROR|WARNING|NOTICE|INFO|DEBUG|[0-7])[-:]?\s+'
    r'(?P<message>.*)$'
)

INTERFACE_PATTERN = re.compile(r'Interface\s+(?P<interface>[\w\/\.-]+)\s+changed state to\s+(?P<state>UP|DOWN)', re.IGNORECASE)
BGP_PATTERN = re.compile(r'BGP\s+neighbor\s+(?P<bgp_neighbor>[\d\.]+)\s+(?P<bgp_state>Established|Down|UP)', re.IGNORECASE)
CPU_PATTERN = re.compile(r'CPU\s+utilization\s*(?:exceeded|at)?\s*(?P<cpu_val>\d+)%', re.IGNORECASE)
THERMAL_PATTERN = re.compile(r'Temperature\s+sensor\s*(?P<sensor>\d+)?\s*(?P<thermal_state>exceeded threshold|returned to normal)?', re.IGNORECASE)
SNMP_PATTERN = re.compile(r'SNMP\s+authentication\s+failure\s+from\s+(?P<src_ip>[\d\.]+)', re.IGNORECASE)


def parse_log_file(file_path):
    parsed_events = []
    if not os.path.exists(file_path):
        return parsed_events

    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            
            match = LOG_PATTERN.match(line)
            if match:
                data = match.groupdict()
                timestamp_str = data['timestamp']
                device = data['device']
                severity = data['severity']
                message = data['message']
                
                category = "Other"
                interface = None
                bgp_neighbor = None
                src_ip = None
                numeric_val = None

                if "Interface" in message or "LINEPROTO" in message or "LINK" in message:
                    category = "Interface"
                    if_match = INTERFACE_PATTERN.search(message)
                    if if_match:
                        interface = if_match.group('interface')

                elif "BGP" in message:
                    category = "BGP"
                    bgp_match = BGP_PATTERN.search(message)
                    if bgp_match:
                        bgp_neighbor = bgp_match.group('bgp_neighbor')

                elif "CPU" in message:
                    category = "CPU"
                    cpu_match = CPU_PATTERN.search(message)
                    if cpu_match:
                        numeric_val = float(cpu_match.group('cpu_val'))

                elif "Temp" in message or "Temperature" in message:
                    category = "Thermal"
                    temp_match = THERMAL_PATTERN.search(message)

                elif "SNMP" in message or "auth" in message.lower():
                    category = "SNMP/Security"
                    snmp_match = SNMP_PATTERN.search(message)
                    if snmp_match:
                        src_ip = snmp_match.group('src_ip')

                parsed_events.append({
                    'timestamp': timestamp_str,
                    'device': device,
                    'severity': severity,
                    'message': message,
                    'category': category,
                    'interface': interface,
                    'bgp_neighbor': bgp_neighbor,
                    'src_ip': src_ip,
                    'numeric_val': numeric_val
                })
    return parsed_events


# ==========================================
# 2. Complete Risk Engine
# ==========================================
def analyze_risks(events):
    risks = []
    
    # 1. Interface Flapping (Down -> Up within 5 mins, >= 2 times)
    interface_events = [e for e in events if e['category'] == 'Interface']
    device_ifaces = {}
    for e in interface_events:
        key = (e['device'], e['interface'])
        device_ifaces.setdefault(key, []).append(e)

    for (device, iface), ev_list in device_ifaces.items():
        if not iface:
            continue
        ev_list.sort(key=lambda x: datetime.strptime(x['timestamp'], '%Y-%m-%d %H:%M:%S'))
        flaps_count = 0
        first_seen, last_seen = None, None

        for i in range(len(ev_list) - 1):
            t1 = datetime.strptime(ev_list[i]['timestamp'], '%Y-%m-%d %H:%M:%S')
            t2 = datetime.strptime(ev_list[i+1]['timestamp'], '%Y-%m-%d %H:%M:%S')
            if (t2 - t1).total_seconds() <= 300:
                flaps_count += 1
                if not first_seen:
                    first_seen = ev_list[i]['timestamp']
                last_seen = ev_list[i+1]['timestamp']

        if flaps_count >= 2:
            risks.append({
                'device': device,
                'event': 'Interface Flapping',
                'event_detail': f'Interface {iface} flapped {flaps_count} times in short period',
                'count': flaps_count,
                'first_seen': first_seen,
                'last_seen': last_seen,
                'risk_level': 'Medium',
                'recommendation': f'Check physical cable and SFP transceivers on interface {iface}.'
            })

    # 2. BGP Instability (Established then Down <= 10 mins OR > 2 Down events/day)
    bgp_events = [e for e in events if e['category'] == 'BGP']
    device_bgp = {}
    for e in bgp_events:
        key = (e['device'], e['bgp_neighbor'])
        device_bgp.setdefault(key, []).append(e)

    for (device, neighbor), ev_list in device_bgp.items():
        if not neighbor:
            continue
        ev_list.sort(key=lambda x: datetime.strptime(x['timestamp'], '%Y-%m-%d %H:%M:%S'))
        down_events = [e for e in ev_list if 'down' in e['message'].lower()]
        
        if len(down_events) >= 2:
            risks.append({
                'device': device,
                'event': 'BGP Instability',
                'event_detail': f'BGP neighbor {neighbor} dropped state {len(down_events)} times',
                'count': len(down_events),
                'first_seen': down_events[0]['timestamp'],
                'last_seen': down_events[-1]['timestamp'],
                'risk_level': 'High',
                'recommendation': f'Verify WAN link quality and BGP hold-timer settings for neighbor {neighbor}.'
            })

    # 3. CPU Spikes (>80% & >=95%)
    cpu_events = [e for e in events if e['category'] == 'CPU' and e['numeric_val'] is not None]
    device_cpus = {}
    for e in cpu_events:
        device_cpus.setdefault(e['device'], []).append(e)

    for device, ev_list in device_cpus.items():
        spikes_high = [e for e in ev_list if e['numeric_val'] > 80]
        spikes_critical = [e for e in ev_list if e['numeric_val'] >= 95]

        if spikes_critical:
            ev_list.sort(key=lambda x: x['timestamp'])
            risks.append({
                'device': device,
                'event': 'Critical CPU Spike',
                'event_detail': f'CPU reached critical threshold of {spikes_critical[0]["numeric_val"]}%',
                'count': len(spikes_critical),
                'first_seen': ev_list[0]['timestamp'],
                'last_seen': ev_list[-1]['timestamp'],
                'risk_level': 'Critical',
                'recommendation': 'Investigate high-CPU process immediately; check control plane traffic.'
            })
        elif len(spikes_high) >= 2:
            ev_list.sort(key=lambda x: x['timestamp'])
            risks.append({
                'device': device,
                'event': 'High CPU Utilization',
                'event_detail': f'Multiple CPU spikes (>80%) detected ({len(spikes_high)} times)',
                'count': len(spikes_high),
                'first_seen': ev_list[0]['timestamp'],
                'last_seen': ev_list[-1]['timestamp'],
                'risk_level': 'High',
                'recommendation': 'Monitor router processes and traffic load.'
            })

    # 4. SNMP Auth Failures
    snmp_events = [e for e in events if e['category'] == 'SNMP/Security' and e['src_ip']]
    device_snmp = {}
    for e in snmp_events:
        key = (e['device'], e['src_ip'])
        device_snmp.setdefault(key, []).append(e)

    for (device, src_ip), ev_list in device_snmp.items():
        if len(ev_list) >= 2:
            ev_list.sort(key=lambda x: x['timestamp'])
            risks.append({
                'device': device,
                'event': 'Repeated SNMP Auth Failures',
                'event_detail': f'Multiple unauthorized SNMP attempts from IP {src_ip}',
                'count': len(ev_list),
                'first_seen': ev_list[0]['timestamp'],
                'last_seen': ev_list[-1]['timestamp'],
                'risk_level': 'High',
                'recommendation': f'Verify NMS community string or block untrusted IP {src_ip} via ACL.'
            })

    # 5. Thermal Recovery Duration
    thermal_events = [e for e in events if e['category'] == 'Thermal']
    device_thermal = {}
    for e in thermal_events:
        device_thermal.setdefault(e['device'], []).append(e)

    for device, ev_list in device_thermal.items():
        ev_list.sort(key=lambda x: datetime.strptime(x['timestamp'], '%Y-%m-%d %H:%M:%S'))
        exceeded_time = None
        for e in ev_list:
            if 'exceeded' in e['message'].lower():
                exceeded_time = datetime.strptime(e['timestamp'], '%Y-%m-%d %H:%M:%S')
            elif 'normal' in e['message'].lower() and exceeded_time:
                normal_time = datetime.strptime(e['timestamp'], '%Y-%m-%d %H:%M:%S')
                duration_mins = round((normal_time - exceeded_time).total_seconds() / 60, 2)
                risks.append({
                    'device': device,
                    'event': 'Thermal Alarm Recovery',
                    'event_detail': f'Temperature alarm recovered after {duration_mins} minutes',
                    'count': 1,
                    'first_seen': exceeded_time.strftime('%Y-%m-%d %H:%M:%S'),
                    'last_seen': normal_time.strftime('%Y-%m-%d %H:%M:%S'),
                    'risk_level': 'Medium',
                    'recommendation': 'Check chassis ventilation and cooling fan health.'
                })
                exceeded_time = None

    return risks


# ==========================================
# 3. Database & Export
# ==========================================
def setup_database(db_path, events, risks):
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            device TEXT,
            severity TEXT,
            message TEXT,
            category TEXT,
            interface TEXT,
            bgp_neighbor TEXT,
            src_ip TEXT,
            numeric_val REAL
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS risk_summary (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            device TEXT,
            event TEXT,
            event_detail TEXT,
            count INTEGER,
            first_seen TEXT,
            last_seen TEXT,
            risk_level TEXT,
            recommendation TEXT
        )
    ''')

    cursor.execute('DELETE FROM events')
    cursor.execute('DELETE FROM risk_summary')

    for e in events:
        cursor.execute('''
            INSERT INTO events (timestamp, device, severity, message, category, interface, bgp_neighbor, src_ip, numeric_val)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (e['timestamp'], e['device'], e['severity'], e['message'], e['category'], e['interface'], e['bgp_neighbor'], e['src_ip'], e['numeric_val']))

    for r in risks:
        cursor.execute('''
            INSERT INTO risk_summary (device, event, event_detail, count, first_seen, last_seen, risk_level, recommendation)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', (r['device'], r['event'], r['event_detail'], r['count'], r['first_seen'], r['last_seen'], r['risk_level'], r['recommendation']))

    conn.commit()
    conn.close()


def export_to_csv(events, risks, events_csv_path, risk_csv_path):
    if events:
        keys = events[0].keys()
        with open(events_csv_path, 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=keys)
            writer.writeheader()
            writer.writerows(events)

    if risks:
        keys = ['device', 'event', 'event_detail', 'count', 'first_seen', 'last_seen', 'risk_level', 'recommendation']
        with open(risk_csv_path, 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=keys)
            writer.writeheader()
            writer.writerows(risks)


# ==========================================
# 4. CLI Filtering Option
# ==========================================
def filter_data(events, risks, args):
    filtered_events = events
    filtered_risks = risks

    if args.device:
        filtered_events = [e for e in filtered_events if e['device'].lower() == args.device.lower()]
        filtered_risks = [r for r in filtered_risks if r['device'].lower() == args.device.lower()]

    if args.severity:
        filtered_events = [e for e in filtered_events if e['severity'].lower() == args.severity.lower()]

    if args.category:
        filtered_events = [e for e in filtered_events if e['category'].lower() == args.category.lower()]

    if args.risk_level:
        filtered_risks = [r for r in filtered_risks if r['risk_level'].lower() == args.risk_level.lower()]

    if args.date:
        filtered_events = [e for e in filtered_events if e['timestamp'].startswith(args.date)]
        filtered_risks = [r for r in filtered_risks if r['first_seen'] and r['first_seen'].startswith(args.date)]

    return filtered_events, filtered_risks


# ==========================================
# 5. Visualizations (Bonus - Updated Colors)
# ==========================================
def generate_charts(events, risks):
    if not events:
        return

    # 1. Top Devices Chart
    device_counts = {}
    for e in events:
        dev = e['device']
        device_counts[dev] = device_counts.get(dev, 0) + 1

    plt.figure(figsize=(8, 5))
    plt.bar(list(device_counts.keys()), list(device_counts.values()), color='skyblue', edgecolor='black')
    plt.title('Top Devices by Event Count')
    plt.xlabel('Device')
    plt.ylabel('Total Events')
    plt.grid(axis='y', linestyle='--', alpha=0.7)
    plt.tight_layout()
    plt.savefig('devices_event_count.png')
    plt.close()

    # 2. Risk Level Distribution Chart
    if risks:
        risk_levels = {}
        for r in risks:
            level = r['risk_level']
            risk_levels[level] = risk_levels.get(level, 0) + 1

        color_map = {
            'Critical': '#d9534f',  # Red
            'High': '#f0ad4e',      # Orange
            'Medium': '#ffd700'     # Yellow
        }
        
        labels = list(risk_levels.keys())
        counts = list(risk_levels.values())
        colors = [color_map.get(lbl, 'gray') for lbl in labels]

        plt.figure(figsize=(7, 5))
        plt.bar(labels, counts, color=colors, edgecolor='black')
        plt.title('Risk Level Distribution')
        plt.xlabel('Risk Level')
        plt.ylabel('Count')
        plt.grid(axis='y', linestyle='--', alpha=0.7)
        plt.tight_layout()
        plt.savefig('risk_level_distribution.png')
        plt.close()


# ==========================================
# Main Execution
# ==========================================
if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Advanced Network Log Analyzer")
    parser.add_argument("--device", help="Filter by device name (e.g., R1)")
    parser.add_argument("--severity", help="Filter by severity (e.g., CRIT)")
    parser.add_argument("--category", help="Filter by category (e.g., Interface, CPU)")
    parser.add_argument("--risk-level", help="Filter by risk level (e.g., High, Critical)")
    parser.add_argument("--date", help="Filter by date (YYYY-MM-DD)")
    args = parser.parse_args()

    logs_dir = 'logs'
    db_file = 'network_events.db'
    events_csv = 'events.csv'
    risk_csv = 'risk_report.csv'

    all_events = []
    
    if os.path.exists(logs_dir):
        for root, dirs, files in os.walk(logs_dir):
            for file in files:
                if file.endswith('.txt') or file.endswith('.log'):
                    file_path = os.path.join(root, file)
                    print(f"Parsing: {file_path}")
                    events = parse_log_file(file_path)
                    all_events.extend(events)

    detected_risks = analyze_risks(all_events)

    filtered_events, filtered_risks = filter_data(all_events, detected_risks, args)

    print(f"\n[+] Total parsed events: {len(filtered_events)}")
    print(f"[+] Total risks detected: {len(filtered_risks)}")

    setup_database(db_file, filtered_events, filtered_risks)
    export_to_csv(filtered_events, filtered_risks, events_csv, risk_csv)

    try:
        generate_charts(filtered_events, filtered_risks)
        print(" -> Charts generated: devices_event_count.png, risk_level_distribution.png")
    except Exception as e:
        print(f" -> Chart generation skipped: {e}")

    print("\n[✔] Task 1 Processing Complete!")
