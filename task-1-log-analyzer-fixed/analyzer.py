import argparse
import csv
import re
import sqlite3
from collections import defaultdict
from datetime import datetime, timedelta
from pathlib import Path

import matplotlib.pyplot as plt


TIMESTAMP_FORMAT = "%Y-%m-%d %H:%M:%S"

LOG_PATTERN = re.compile(
    r"^(?P<timestamp>\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})\s+"
    r"(?P<device>\S+)\s+"
    r"%?(?P<severity>EMERG|ALERT|CRIT|ERR|ERROR|WARN|WARNING|NOTICE|INFO|DEBUG|[0-7])"
    r"(?:[-:])?\s+(?P<message>.*)$",
    re.IGNORECASE,
)

INTERFACE_PATTERN = re.compile(
    r"Interface\s+(?P<interface>[\w/.-]+)\s+changed\s+state\s+to\s+"
    r"(?P<state>up|down)",
    re.IGNORECASE,
)

BGP_PATTERN = re.compile(
    r"BGP\s+neighbor\s+(?P<bgp_neighbor>\d{1,3}(?:\.\d{1,3}){3})\s+"
    r"(?P<bgp_state>established|went\s+down|down|up)",
    re.IGNORECASE,
)

CPU_PATTERN = re.compile(
    r"CPU\s+utilization\s+(?:exceeded|at)\s+(?P<cpu_val>\d+(?:\.\d+)?)%",
    re.IGNORECASE,
)

SNMP_PATTERN = re.compile(
    r"SNMP\s+authentication\s+failure\s+from\s+"
    r"(?P<src_ip>\d{1,3}(?:\.\d{1,3}){3})",
    re.IGNORECASE,
)

THERMAL_PATTERN = re.compile(
    r"Temperature\s+sensor\s+(?P<sensor>\d+)\s+"
    r"(?P<thermal_state>exceeded\s+threshold|returned\s+to\s+normal)",
    re.IGNORECASE,
)


def parse_timestamp(value):
    return datetime.strptime(value, TIMESTAMP_FORMAT)


def parse_log_file(file_path):
    """Parse one syslog file into normalized event dictionaries."""
    events = []

    with open(file_path, "r", encoding="utf-8", errors="ignore") as handle:
        for line_number, raw_line in enumerate(handle, start=1):
            line = raw_line.strip()
            if not line:
                continue

            match = LOG_PATTERN.match(line)
            if not match:
                continue

            data = match.groupdict()
            message = data["message"]

            category = "Other"
            interface = None
            interface_state = None
            bgp_neighbor = None
            bgp_state = None
            src_ip = None
            numeric_val = None
            thermal_state = None
            thermal_sensor = None

            interface_match = INTERFACE_PATTERN.search(message)
            bgp_match = BGP_PATTERN.search(message)
            cpu_match = CPU_PATTERN.search(message)
            snmp_match = SNMP_PATTERN.search(message)
            thermal_match = THERMAL_PATTERN.search(message)

            if interface_match:
                category = "Interface"
                interface = interface_match.group("interface")
                interface_state = interface_match.group("state").upper()

            elif bgp_match:
                category = "BGP"
                bgp_neighbor = bgp_match.group("bgp_neighbor")
                bgp_state = bgp_match.group("bgp_state").lower().replace(" ", "_")

            elif cpu_match or "cpu" in message.lower():
                category = "CPU"
                if cpu_match:
                    numeric_val = float(cpu_match.group("cpu_val"))

            elif thermal_match or "temperature" in message.lower():
                category = "Thermal"
                if thermal_match:
                    thermal_state = thermal_match.group("thermal_state").lower()
                    thermal_sensor = thermal_match.group("sensor")

            elif snmp_match or "authentication failure" in message.lower():
                category = "SNMP/Security"
                if snmp_match:
                    src_ip = snmp_match.group("src_ip")

            events.append(
                {
                    "timestamp": data["timestamp"],
                    "device": data["device"],
                    "severity": data["severity"].upper(),
                    "message": message,
                    "category": category,
                    "interface": interface,
                    "interface_state": interface_state,
                    "bgp_neighbor": bgp_neighbor,
                    "bgp_state": bgp_state,
                    "src_ip": src_ip,
                    "numeric_val": numeric_val,
                    "thermal_sensor": thermal_sensor,
                    "thermal_state": thermal_state,
                    "source_file": Path(file_path).name,
                    "line_number": line_number,
                }
            )

    return events


def _rolling_window(events, window_minutes):
    """Yield lists representing each event's preceding rolling time window."""
    window = timedelta(minutes=window_minutes)
    for index, current in enumerate(events):
        current_time = parse_timestamp(current["timestamp"])
        start = index
        while start < index and current_time - parse_timestamp(events[start]["timestamp"]) > window:
            start += 1
        yield events[start : index + 1]


def detect_interface_flaps(events):
    """Detect DOWN -> UP transitions within 5 minutes and repeated >=2/hour."""
    grouped = defaultdict(list)

    for event in events:
        if event["category"] == "Interface" and event["interface"] and event["interface_state"]:
            grouped[(event["device"], event["interface"])].append(event)

    risks = []

    for (device, interface), items in grouped.items():
        items.sort(key=lambda event: parse_timestamp(event["timestamp"]))

        flap_events = []
        index = 0

        while index < len(items) - 1:
            current = items[index]
            next_event = items[index + 1]

            if current["interface_state"] == "DOWN" and next_event["interface_state"] == "UP":
                duration = (
                    parse_timestamp(next_event["timestamp"])
                    - parse_timestamp(current["timestamp"])
                ).total_seconds()

                if 0 <= duration <= 300:
                    flap_events.append(
                        {
                            "down": current["timestamp"],
                            "up": next_event["timestamp"],
                        }
                    )
                    index += 2
                    continue

            index += 1

        if len(flap_events) < 2:
            continue

        flap_events.sort(key=lambda item: parse_timestamp(item["down"]))

        best_window = []
        for i, start_event in enumerate(flap_events):
            start_time = parse_timestamp(start_event["down"])
            current_window = []

            for candidate in flap_events[i:]:
                if parse_timestamp(candidate["down"]) - start_time <= timedelta(hours=1):
                    current_window.append(candidate)
                else:
                    break

            if len(current_window) > len(best_window):
                best_window = current_window

        if len(best_window) >= 2:
            risks.append(
                {
                    "device": device,
                    "event": "Interface Flapping",
                    "event_detail": (
                        f"{interface} had {len(best_window)} DOWN->UP flaps "
                        "within one hour"
                    ),
                    "count": len(best_window),
                    "first_seen": best_window[0]["down"],
                    "last_seen": best_window[-1]["up"],
                    "risk_level": "Medium",
                    "recommendation": (
                        f"Check physical connectivity, optics/SFPs, errors, "
                        f"and interface stability on {interface}."
                    ),
                }
            )

    return risks


def detect_bgp_instability(events):
    """Detect session resets and >2 BGP down events per device/day."""
    grouped = defaultdict(list)

    for event in events:
        if event["category"] == "BGP" and event["bgp_neighbor"]:
            grouped[(event["device"], event["bgp_neighbor"])].append(event)

    risks = []

    # Established -> Down within 10 minutes for each neighbor.
    for (device, neighbor), items in grouped.items():
        items.sort(key=lambda event: parse_timestamp(event["timestamp"]))

        resets = []
        for index, event in enumerate(items):
            if event["bgp_state"] != "established":
                continue

            for next_event in items[index + 1 :]:
                next_time = parse_timestamp(next_event["timestamp"])
                event_time = parse_timestamp(event["timestamp"])

                if next_time - event_time > timedelta(minutes=10):
                    break

                if next_event["bgp_state"] in {"went_down", "down"}:
                    resets.append((event["timestamp"], next_event["timestamp"]))
                    break

        if resets:
            risks.append(
                {
                    "device": device,
                    "event": "BGP Instability",
                    "event_detail": (
                        f"Neighbor {neighbor} transitioned Established -> Down "
                        f"{len(resets)} time(s) within 10 minutes"
                    ),
                    "count": len(resets),
                    "first_seen": resets[0][0],
                    "last_seen": resets[-1][1],
                    "risk_level": "High",
                    "recommendation": (
                        f"Check WAN/link stability, BGP timers, packet loss, "
                        f"and peer health for neighbor {neighbor}."
                    ),
                }
            )

    # More than two BGP DOWN events for the same device on the same day.
    daily_downs = defaultdict(list)

    for event in events:
        if (
            event["category"] == "BGP"
            and event["bgp_state"] in {"went_down", "down"}
        ):
            date_key = parse_timestamp(event["timestamp"]).date()
            daily_downs[(event["device"], date_key)].append(event)

    for (device, date_key), downs in daily_downs.items():
        if len(downs) > 2:
            downs.sort(key=lambda event: parse_timestamp(event["timestamp"]))
            neighbors = sorted(
                {
                    event["bgp_neighbor"]
                    for event in downs
                    if event["bgp_neighbor"]
                }
            )

            risks.append(
                {
                    "device": device,
                    "event": "Frequent BGP Down Events",
                    "event_detail": (
                        f"{len(downs)} BGP down events on {date_key} "
                        f"across neighbor(s): {', '.join(neighbors)}"
                    ),
                    "count": len(downs),
                    "first_seen": downs[0]["timestamp"],
                    "last_seen": downs[-1]["timestamp"],
                    "risk_level": "High",
                    "recommendation": (
                        "Review BGP peer stability, routing path quality, "
                        "interface errors, and underlying transport."
                    ),
                }
            )

    return risks


def detect_cpu_risks(events):
    """Detect >80% spikes and >=95% critical spikes."""
    grouped = defaultdict(list)

    for event in events:
        if event["category"] == "CPU" and event["numeric_val"] is not None:
            grouped[event["device"]].append(event)

    risks = []

    for device, items in grouped.items():
        items.sort(key=lambda event: parse_timestamp(event["timestamp"]))

        critical = [event for event in items if event["numeric_val"] >= 95]

        if critical:
            risks.append(
                {
                    "device": device,
                    "event": "Critical CPU Spike",
                    "event_detail": (
                        f"CPU reached {max(e['numeric_val'] for e in critical):g}% "
                        "or higher"
                    ),
                    "count": len(critical),
                    "first_seen": critical[0]["timestamp"],
                    "last_seen": critical[-1]["timestamp"],
                    "risk_level": "Critical",
                    "recommendation": (
                        "Investigate high-CPU processes immediately and check "
                        "control-plane traffic and resource utilization."
                    ),
                }
            )

        # More than two (>80%) spikes in any one-hour window.
        high_spikes = [event for event in items if event["numeric_val"] > 80]

        if len(high_spikes) >= 3:
            best_window = []

            for i, start_event in enumerate(high_spikes):
                start_time = parse_timestamp(start_event["timestamp"])
                window = []

                for candidate in high_spikes[i:]:
                    if (
                        parse_timestamp(candidate["timestamp"]) - start_time
                        <= timedelta(hours=1)
                    ):
                        window.append(candidate)
                    else:
                        break

                if len(window) > len(best_window):
                    best_window = window

            if len(best_window) >= 3:
                risks.append(
                    {
                        "device": device,
                        "event": "High CPU Utilization",
                        "event_detail": (
                            f"{len(best_window)} CPU spikes above 80% "
                            "within one hour"
                        ),
                        "count": len(best_window),
                        "first_seen": best_window[0]["timestamp"],
                        "last_seen": best_window[-1]["timestamp"],
                        "risk_level": "High",
                        "recommendation": (
                            "Review CPU-consuming processes, traffic load, "
                            "control-plane activity, and capacity."
                        ),
                    }
                )

    return risks


def detect_snmp_risks(events):
    """Detect repeated SNMP authentication failures from a source IP."""
    grouped = defaultdict(list)

    for event in events:
        if event["category"] == "SNMP/Security" and event["src_ip"]:
            grouped[(event["device"], event["src_ip"])].append(event)

    risks = []

    for (device, src_ip), items in grouped.items():
        if len(items) >= 2:
            items.sort(key=lambda event: parse_timestamp(event["timestamp"]))
            risks.append(
                {
                    "device": device,
                    "event": "Repeated SNMP Auth Failures",
                    "event_detail": (
                        f"{len(items)} authentication failures from {src_ip}"
                    ),
                    "count": len(items),
                    "first_seen": items[0]["timestamp"],
                    "last_seen": items[-1]["timestamp"],
                    "risk_level": "High",
                    "recommendation": (
                        f"Verify NMS credentials/community configuration and "
                        f"restrict untrusted source {src_ip} with ACL/security controls."
                    ),
                }
            )

    return risks


def detect_thermal_recovery(events):
    """Calculate recovery duration from threshold exceeded to normal."""
    grouped = defaultdict(list)

    for event in events:
        if event["category"] == "Thermal":
            grouped[(event["device"], event["thermal_sensor"])].append(event)

    risks = []

    for (device, sensor), items in grouped.items():
        items.sort(key=lambda event: parse_timestamp(event["timestamp"]))
        exceeded_time = None

        for event in items:
            state = event["thermal_state"] or ""

            if "exceeded" in state:
                exceeded_time = parse_timestamp(event["timestamp"])

            elif "returned_to_normal" in state and exceeded_time:
                normal_time = parse_timestamp(event["timestamp"])
                duration = round(
                    (normal_time - exceeded_time).total_seconds() / 60, 2
                )

                if duration >= 0:
                    risks.append(
                        {
                            "device": device,
                            "event": "Thermal Alarm Recovery",
                            "event_detail": (
                                f"Temperature sensor {sensor} recovered "
                                f"after {duration:g} minutes"
                            ),
                            "count": 1,
                            "first_seen": exceeded_time.strftime(TIMESTAMP_FORMAT),
                            "last_seen": normal_time.strftime(TIMESTAMP_FORMAT),
                            "risk_level": "Medium",
                            "recommendation": (
                                "Check chassis ventilation, temperature sensors, "
                                "and cooling fan health."
                            ),
                        }
                    )

                exceeded_time = None

    return risks


def analyze_risks(events):
    """Run all risk detectors."""
    risks = []
    risks.extend(detect_interface_flaps(events))
    risks.extend(detect_bgp_instability(events))
    risks.extend(detect_cpu_risks(events))
    risks.extend(detect_snmp_risks(events))
    risks.extend(detect_thermal_recovery(events))

    risks.sort(key=lambda item: (item["risk_level"], item["device"], item["first_seen"]))
    return risks


def setup_database(db_path, events, risks):
    db_path = Path(db_path)
    db_path.parent.mkdir(parents=True, exist_ok=True)

    with sqlite3.connect(db_path) as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                device TEXT NOT NULL,
                severity TEXT,
                message TEXT NOT NULL,
                category TEXT NOT NULL,
                interface TEXT,
                interface_state TEXT,
                bgp_neighbor TEXT,
                bgp_state TEXT,
                src_ip TEXT,
                numeric_val REAL,
                thermal_sensor TEXT,
                thermal_state TEXT,
                source_file TEXT,
                line_number INTEGER
            )
            """
        )

        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS risk_summary (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                device TEXT NOT NULL,
                event TEXT NOT NULL,
                event_detail TEXT,
                count INTEGER,
                first_seen TEXT,
                last_seen TEXT,
                risk_level TEXT,
                recommendation TEXT
            )
            """
        )

        conn.execute("DELETE FROM events")
        conn.execute("DELETE FROM risk_summary")

        conn.executemany(
            """
            INSERT INTO events (
                timestamp, device, severity, message, category,
                interface, interface_state, bgp_neighbor, bgp_state,
                src_ip, numeric_val, thermal_sensor, thermal_state,
                source_file, line_number
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            [
                (
                    e["timestamp"],
                    e["device"],
                    e["severity"],
                    e["message"],
                    e["category"],
                    e["interface"],
                    e["interface_state"],
                    e["bgp_neighbor"],
                    e["bgp_state"],
                    e["src_ip"],
                    e["numeric_val"],
                    e["thermal_sensor"],
                    e["thermal_state"],
                    e["source_file"],
                    e["line_number"],
                )
                for e in events
            ],
        )

        conn.executemany(
            """
            INSERT INTO risk_summary (
                device, event, event_detail, count,
                first_seen, last_seen, risk_level, recommendation
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            [
                (
                    r["device"],
                    r["event"],
                    r["event_detail"],
                    r["count"],
                    r["first_seen"],
                    r["last_seen"],
                    r["risk_level"],
                    r["recommendation"],
                )
                for r in risks
            ],
        )


def export_to_csv(events, risks, output_dir):
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    events_path = output_dir / "events.csv"
    risks_path = output_dir / "risk_report.csv"

    event_fields = [
        "timestamp",
        "device",
        "severity",
        "message",
        "category",
        "interface",
        "interface_state",
        "bgp_neighbor",
        "bgp_state",
        "src_ip",
        "numeric_val",
        "thermal_sensor",
        "thermal_state",
        "source_file",
        "line_number",
    ]

    with events_path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=event_fields)
        writer.writeheader()
        writer.writerows(events)

    risk_fields = [
        "device",
        "event",
        "event_detail",
        "count",
        "first_seen",
        "last_seen",
        "risk_level",
        "recommendation",
    ]

    with risks_path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=risk_fields)
        writer.writeheader()
        writer.writerows(risks)

    return events_path, risks_path


def filter_data(events, risks, args):
    filtered_events = list(events)
    filtered_risks = list(risks)

    if args.device:
        filtered_events = [
            e for e in filtered_events
            if e["device"].lower() == args.device.lower()
        ]
        filtered_risks = [
            r for r in filtered_risks
            if r["device"].lower() == args.device.lower()
        ]

    if args.severity:
        filtered_events = [
            e for e in filtered_events
            if e["severity"].lower() == args.severity.lower()
        ]

    if args.category:
        filtered_events = [
            e for e in filtered_events
            if e["category"].lower() == args.category.lower()
        ]

    if args.risk_level:
        filtered_risks = [
            r for r in filtered_risks
            if r["risk_level"].lower() == args.risk_level.lower()
        ]

    if args.date:
        filtered_events = [
            e for e in filtered_events
            if e["timestamp"].startswith(args.date)
        ]
        filtered_risks = [
            r for r in filtered_risks
            if r["first_seen"] and r["first_seen"].startswith(args.date)
        ]

    return filtered_events, filtered_risks


def generate_charts(events, risks, output_dir):
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    if not events:
        return

    device_counts = defaultdict(int)
    for event in events:
        device_counts[event["device"]] += 1

    plt.figure(figsize=(8, 5))
    plt.bar(device_counts.keys(), device_counts.values())
    plt.title("Top Devices by Event Count")
    plt.xlabel("Device")
    plt.ylabel("Total Events")
    plt.grid(axis="y", alpha=0.3)
    plt.tight_layout()
    plt.savefig(output_dir / "devices_event_count.png", dpi=150)
    plt.close()

    if risks:
        risk_levels = defaultdict(int)
        for risk in risks:
            risk_levels[risk["risk_level"]] += 1

        plt.figure(figsize=(7, 5))
        plt.bar(risk_levels.keys(), risk_levels.values())
        plt.title("Risk Level Distribution")
        plt.xlabel("Risk Level")
        plt.ylabel("Count")
        plt.grid(axis="y", alpha=0.3)
        plt.tight_layout()
        plt.savefig(output_dir / "risk_level_distribution.png", dpi=150)
        plt.close()


def main():
    parser = argparse.ArgumentParser(
        description="Advanced Network Log Analyzer"
    )
    parser.add_argument(
        "--device",
        help="Filter results by device name, e.g. R1",
    )
    parser.add_argument(
        "--severity",
        help="Filter normalized events by syslog severity, e.g. CRIT",
    )
    parser.add_argument(
        "--category",
        help="Filter normalized events by category, e.g. Interface or CPU",
    )
    parser.add_argument(
        "--risk-level",
        choices=["Medium", "High", "Critical"],
        help="Filter risks by risk level",
    )
    parser.add_argument(
        "--date",
        help="Filter results by date, format YYYY-MM-DD",
    )

    args = parser.parse_args()

    base_dir = Path(__file__).resolve().parent
    logs_dir = base_dir / "logs"
    output_dir = base_dir / "output"
    db_file = base_dir / "network_events.db"

    if not logs_dir.exists():
        raise SystemExit(f"Logs directory not found: {logs_dir}")

    all_events = []

    log_files = sorted(logs_dir.glob("*.log"))
    if not log_files:
        # Keep compatibility with the supplied sample files during transition.
        log_files = sorted(logs_dir.glob("*.txt"))

    if not log_files:
        raise SystemExit(f"No .log files found in {logs_dir}")

    for log_file in log_files:
        print(f"Parsing: {log_file.name}")
        all_events.extend(parse_log_file(log_file))

    all_events.sort(key=lambda event: parse_timestamp(event["timestamp"]))
    all_risks = analyze_risks(all_events)

    # Persist the complete normalized dataset.
    setup_database(db_file, all_events, all_risks)

    # CLI filters affect the generated report view, while SQLite keeps all data.
    filtered_events, filtered_risks = filter_data(
        all_events,
        all_risks,
        args,
    )

    events_csv, risk_csv = export_to_csv(
        filtered_events,
        filtered_risks,
        output_dir,
    )

    generate_charts(filtered_events, filtered_risks, output_dir)

    print(f"\n[+] Total parsed events: {len(all_events)}")
    print(f"[+] Total risks detected: {len(all_risks)}")
    print(f"[+] Filtered events exported: {len(filtered_events)}")
    print(f"[+] Filtered risks exported: {len(filtered_risks)}")
    print(f"[+] Database: {db_file}")
    print(f"[+] Events report: {events_csv}")
    print(f"[+] Risk report: {risk_csv}")
    print("[+] Charts generated in output/")

    print("\n[OK] Task 1 processing complete.")


if __name__ == "__main__":
    main()
