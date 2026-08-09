# Task 2 — Flask Network Audit Platform

A lightweight Flask application for ingesting multi-vendor network configuration files and syslog files, storing normalized data in SQLite, validating network design rules, and presenting the results in a searchable dashboard.

## Features

- Multiple Cisco, Huawei, and Juniper configuration uploads
- Multiple `.log` / `.txt` log uploads
- Extraction of hostnames, interfaces, IP addresses, routing protocols, BGP AS/neighbors, OSPF areas, ACL/security rule names, and Loopback0 status
- Log categorization using the same operational categories as Task 1: Interface, BGP, CPU, Thermal, SNMP/Security, Other
- Device/log correlation by hostname
- SQLite persistence with automatic schema creation
- Validation of Loopback0, subnet overlap, BGP AS consistency, OSPF area consistency, and high-risk log findings
- Dashboard charts for BGP vs OSPF router count and interfaces per device
- Search/filter by hostname/rule, validation status, and routing protocol
- Device drill-down page
- CSV compliance export
- Optional local admin login controlled entirely through environment variables

## Project Structure

```text
task-2-flask-audit/
├── app.py
├── models.py
├── parser.py
├── requirements.txt
├── .env.example
├── templates/
│   ├── base.html
│   ├── dashboard.html
│   ├── device_detail.html
│   ├── login.html
│   └── upload.html
├── static/
│   └── style.css
└── internal_data/
    ├── uploads/
    └── exports/
```

## Setup

Python 3.10+ is recommended.

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
```

Edit `.env` and set a local admin username/password. The application automatically creates `network_audit.db` on first run.

## Run

```bash
python3 app.py
```

Open `http://127.0.0.1:5000`.

## Workflow

1. Open **Admin Login** and sign in using the credentials from `.env`.
2. Open **Upload**.
3. Upload one or more configuration files and one or more log files.
4. The parser stores normalized records in SQLite and runs the validation engine.
5. Review the dashboard and open a device for detailed interfaces, routing protocols, BGP neighbors, ACL/security rules, logs, and validations.
6. Use **Export CSV** to download the audit validation report.

## Parsing Assumptions

- Cisco/Huawei interface blocks are identified using `interface ...` sections.
- Juniper interface blocks are identified from `interfaces { ... }` syntax and IPv4 addresses in `family inet` sections.
- Cisco BGP neighbors use `neighbor <ip> remote-as <asn>`.
- Huawei BGP peers use `peer <ip> as-number <asn>`.
- Juniper BGP neighbors use `neighbor <ip>`.
- OSPF areas are extracted from Cisco/Huawei `area` declarations and Juniper `area <id> {` blocks.
- Logs are expected in the simple assessment format: `timestamp device severity message`.
- High/Critical log findings are linked to a device when the hostname in the log matches a parsed device hostname.

## Validation Rules

- Every device should have Loopback0/lo0.
- IPv4 subnets must not overlap across different devices.
- BGP AS values are compared with the dominant configured AS among BGP devices.
- OSPF areas are compared with the dominant configured area among OSPF devices for this assessment dataset.
- Devices with High/Critical linked log events are surfaced as validation failures.

## Security Notes

- Secrets are loaded from `.env`; `.env` is ignored by Git.
- Uploaded filenames are sanitized with `secure_filename`.
- Uploads are restricted to expected configuration/log extensions.
- Maximum request size is 10 MB.
- Debug mode is disabled by default.

## Known Limitations

This is an assessment-scale parser rather than a full vendor configuration parser. Production deployment would benefit from vendor-specific grammars, stronger authentication/session controls, CSRF protection, background processing for large uploads, and more granular validation policies.
