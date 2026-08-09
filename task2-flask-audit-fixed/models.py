import sqlite3


def get_db_connection(db_path="network_audit.db"):
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_db(db_path="network_audit.db"):
    conn = get_db_connection(db_path)
    cur = conn.cursor()
    cur.executescript("""
    CREATE TABLE IF NOT EXISTS devices (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        hostname TEXT UNIQUE NOT NULL,
        vendor TEXT,
        has_loopback0 INTEGER NOT NULL DEFAULT 0,
        bgp_as TEXT,
        ospf_area TEXT
    );
    CREATE TABLE IF NOT EXISTS interfaces (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        device_id INTEGER NOT NULL,
        interface_name TEXT NOT NULL,
        ip_address TEXT,
        subnet_mask TEXT,
        FOREIGN KEY(device_id) REFERENCES devices(id) ON DELETE CASCADE
    );
    CREATE TABLE IF NOT EXISTS routing_protocols (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        device_id INTEGER NOT NULL,
        protocol TEXT NOT NULL,
        process_or_as TEXT,
        FOREIGN KEY(device_id) REFERENCES devices(id) ON DELETE CASCADE
    );
    CREATE TABLE IF NOT EXISTS bgp_neighbors (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        device_id INTEGER NOT NULL,
        neighbor_ip TEXT NOT NULL,
        remote_as TEXT,
        FOREIGN KEY(device_id) REFERENCES devices(id) ON DELETE CASCADE
    );
    CREATE TABLE IF NOT EXISTS ospf_areas (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        device_id INTEGER NOT NULL,
        area TEXT NOT NULL,
        FOREIGN KEY(device_id) REFERENCES devices(id) ON DELETE CASCADE
    );
    CREATE TABLE IF NOT EXISTS acl_rules (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        device_id INTEGER NOT NULL,
        rule_name TEXT NOT NULL,
        FOREIGN KEY(device_id) REFERENCES devices(id) ON DELETE CASCADE
    );
    CREATE TABLE IF NOT EXISTS log_events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT,
        device_name TEXT,
        category TEXT,
        severity TEXT,
        description TEXT,
        risk_level TEXT
    );
    CREATE TABLE IF NOT EXISTS audit_validations (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        device_name TEXT,
        rule_checked TEXT,
        status TEXT,
        details TEXT
    );
    """)
    conn.commit()
    conn.close()
