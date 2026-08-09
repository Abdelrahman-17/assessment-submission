import sqlite3

def get_db_connection(db_path="network_audit.db"):
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    return conn

def init_db(db_path="network_audit.db"):
    conn = get_db_connection(db_path)
    cursor = conn.cursor()
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS devices (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            hostname TEXT UNIQUE NOT NULL,
            has_loopback0 INTEGER DEFAULT 0,
            bgp_as TEXT,
            ospf_area TEXT
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS interfaces (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            device_id INTEGER,
            interface_name TEXT,
            ip_address TEXT,
            subnet_mask TEXT,
            FOREIGN KEY (device_id) REFERENCES devices (id)
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS acl_rules (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            device_id INTEGER,
            rule_name TEXT,
            FOREIGN KEY (device_id) REFERENCES devices (id)
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS audit_validations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            device_name TEXT,
            rule_checked TEXT,
            status TEXT,
            details TEXT
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS log_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            device_name TEXT,
            category TEXT,
            severity TEXT,
            description TEXT,
            risk_level TEXT
        )
    ''')

    conn.commit()
    conn.close()

if __name__ == "__main__":
    init_db()
    print("[+] Database schema initialized!")
