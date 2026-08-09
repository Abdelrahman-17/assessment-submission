import os
import csv
from flask import Flask, render_template, request, redirect, url_for, session, flash, send_file
from dotenv import load_dotenv
from models import init_db, get_db_connection
from parser import parse_config_file, parse_log_file, run_network_validations

load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", "fallback_secret_key")
DB_PATH = os.getenv("DATABASE_PATH", "network_audit.db")

init_db(DB_PATH)

@app.route('/')
def index():
    return redirect(url_for('dashboard'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        if username == os.getenv('ADMIN_USERNAME') and password == os.getenv('ADMIN_PASSWORD'):
            session['user'] = username
            flash('Logged in successfully!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid credentials!', 'danger')
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('user', None)
    flash('Logged out.', 'info')
    return redirect(url_for('login'))

@app.route('/upload', methods=['GET', 'POST'])
def upload():
    if request.method == 'POST':
        config_files = request.files.getlist('configs')
        log_files = request.files.getlist('logs')

        os.makedirs('uploads', exist_ok=True)

        for file in config_files:
            if file and file.filename != '':
                path = os.path.join('uploads', file.filename)
                file.save(path)
                parse_config_file(path, DB_PATH)

        for file in log_files:
            if file and file.filename != '':
                path = os.path.join('uploads', file.filename)
                file.save(path)
                parse_log_file(path, DB_PATH)

        run_network_validations(DB_PATH)
        flash('Files uploaded and network audit completed successfully!', 'success')
        return redirect(url_for('dashboard'))

    return render_template('upload.html')

@app.route('/dashboard')
def dashboard():
    search_q = request.args.get('q', '')
    status_filter = request.args.get('status', '')

    conn = get_db_connection(DB_PATH)
    cursor = conn.cursor()

    val_query = "SELECT * FROM audit_validations WHERE 1=1"
    params = []
    if search_q:
        val_query += " AND (device_name LIKE ? OR rule_checked LIKE ?)"
        params.extend([f"%{search_q}%", f"%{search_q}%"])
    if status_filter:
        val_query += " AND status = ?"
        params.append(status_filter)

    cursor.execute(val_query, params)
    validations = cursor.fetchall()

    cursor.execute("SELECT * FROM log_events WHERE risk_level IN ('Critical', 'High') ORDER BY id DESC LIMIT 10")
    recent_risks = cursor.fetchall()

    cursor.execute("SELECT COUNT(*) FROM devices WHERE bgp_as IS NOT NULL")
    bgp_count = cursor.fetchone()[0]
    cursor.execute("SELECT COUNT(*) FROM devices WHERE ospf_area IS NOT NULL")
    ospf_count = cursor.fetchone()[0]

    cursor.execute('''
        SELECT d.hostname, COUNT(i.id) as iface_count 
        FROM devices d LEFT JOIN interfaces i ON d.id = i.device_id 
        GROUP BY d.id
    ''')
    iface_stats = cursor.fetchall()

    conn.close()

    return render_template('dashboard.html', 
                           validations=validations, 
                           recent_risks=recent_risks,
                           bgp_count=bgp_count,
                           ospf_count=ospf_count,
                           iface_stats=iface_stats,
                           search_q=search_q,
                           status_filter=status_filter)

@app.route('/device/<hostname>')
def device_detail(hostname):
    conn = get_db_connection(DB_PATH)
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM devices WHERE hostname = ?", (hostname,))
    device = cursor.fetchone()

    if not device:
        conn.close()
        return "Device not found", 404

    cursor.execute("SELECT * FROM interfaces WHERE device_id = ?", (device['id'],))
    interfaces = cursor.fetchall()

    cursor.execute("SELECT * FROM acl_rules WHERE device_id = ?", (device['id'],))
    acls = cursor.fetchall()

    cursor.execute("SELECT * FROM log_events WHERE device_name = ?", (hostname,))
    logs = cursor.fetchall()

    cursor.execute("SELECT * FROM audit_validations WHERE device_name = ?", (hostname,))
    validations = cursor.fetchall()

    conn.close()

    return render_template('device_detail.html', device=device, interfaces=interfaces, acls=acls, logs=logs, validations=validations)

@app.route('/export')
def export_csv():
    os.makedirs('exports', exist_ok=True)
    export_path = os.path.join('exports', 'audit_report.csv')

    conn = get_db_connection(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM audit_validations")
    rows = cursor.fetchall()

    with open(export_path, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(['ID', 'Device Name', 'Rule Checked', 'Status', 'Details'])
        for r in rows:
            writer.writerow([r['id'], r['device_name'], r['rule_checked'], r['status'], r['details']])

    conn.close()
    return send_file(export_path, as_attachment=True)

if __name__ == '__main__':
    port = int(os.getenv("PORT", 5000))
    app.run(host='0.0.0.0', port=port, debug=True)
