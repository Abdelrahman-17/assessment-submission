import csv
import os
from functools import wraps
from pathlib import Path
from flask import Flask, flash, redirect, render_template, request, send_file, session, url_for
from werkzeug.utils import secure_filename
from dotenv import load_dotenv
from models import get_db_connection, init_db
from parser import parse_config_file, parse_log_file, run_network_validations

load_dotenv()

BASE_DIR = Path(__file__).resolve().parent
UPLOAD_DIR = BASE_DIR / os.getenv("UPLOAD_DIR", "internal_data/uploads")
EXPORT_DIR = BASE_DIR / os.getenv("EXPORT_DIR", "internal_data/exports")
DB_PATH = BASE_DIR / os.getenv("DATABASE_PATH", "network_audit.db")
ALLOWED_CONFIG = {"txt", "cfg", "conf"}
ALLOWED_LOG = {"txt", "log"}

app = Flask(__name__)
app.config["SECRET_KEY"] = os.getenv("SECRET_KEY", "change-me-in-env")
app.config["MAX_CONTENT_LENGTH"] = 10 * 1024 * 1024
init_db(str(DB_PATH))


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not session.get("user"):
            flash("Please log in to access this page.", "warning")
            return redirect(url_for("login", next=request.path))
        return view(*args, **kwargs)
    return wrapped


def extension_allowed(filename, allowed):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in allowed


@app.route("/")
def index():
    return redirect(url_for("dashboard"))


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        if username == os.getenv("ADMIN_USERNAME") and password == os.getenv("ADMIN_PASSWORD"):
            session["user"] = username
            flash("Logged in successfully.", "success")
            return redirect(request.args.get("next") or url_for("dashboard"))
        flash("Invalid credentials.", "danger")
    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    flash("Logged out.", "info")
    return redirect(url_for("login"))


@app.route("/upload", methods=["GET", "POST"])
@login_required
def upload():
    if request.method == "POST":
        configs = request.files.getlist("configs")
        logs = request.files.getlist("logs")
        UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
        config_count = log_count = 0

        for file in configs:
            if not file or not file.filename:
                continue
            name = secure_filename(file.filename)
            if not extension_allowed(name, ALLOWED_CONFIG):
                flash(f"Skipped unsupported config file: {name}", "warning")
                continue
            path = UPLOAD_DIR / name
            file.save(path)
            parse_config_file(str(path), str(DB_PATH))
            config_count += 1

        for file in logs:
            if not file or not file.filename:
                continue
            name = secure_filename(file.filename)
            if not extension_allowed(name, ALLOWED_LOG):
                flash(f"Skipped unsupported log file: {name}", "warning")
                continue
            path = UPLOAD_DIR / name
            file.save(path)
            parse_log_file(str(path), str(DB_PATH))
            log_count += 1

        run_network_validations(str(DB_PATH))
        flash(f"Audit complete: {config_count} config file(s), {log_count} log file(s).", "success")
        return redirect(url_for("dashboard"))
    return render_template("upload.html")


@app.route("/dashboard")
def dashboard():
    q = request.args.get("q", "").strip()
    status = request.args.get("status", "").strip()
    protocol = request.args.get("protocol", "").strip().upper()
    risk = request.args.get("risk", "").strip()

    conn = get_db_connection(str(DB_PATH))
    cur = conn.cursor()
    sql = "SELECT * FROM audit_validations WHERE 1=1"
    params = []
    if q:
        sql += " AND (device_name LIKE ? OR rule_checked LIKE ? OR details LIKE ?)"
        params += [f"%{q}%"] * 3
    if status:
        sql += " AND status=?"
        params.append(status)
    if protocol:
        sql += " AND device_name IN (SELECT d.hostname FROM devices d JOIN routing_protocols rp ON rp.device_id=d.id WHERE rp.protocol=?)"
        params.append(protocol)
    sql += " ORDER BY id DESC"
    validations = cur.execute(sql, params).fetchall()

    risk_sql = "SELECT * FROM log_events WHERE risk_level IN ('Critical','High')"
    risk_params = []
    if risk:
        risk_sql = "SELECT * FROM log_events WHERE risk_level=?"
        risk_params.append(risk)
    recent_risks = cur.execute(risk_sql + " ORDER BY id DESC LIMIT 15", risk_params).fetchall()

    bgp_count = cur.execute("SELECT COUNT(DISTINCT device_id) FROM routing_protocols WHERE protocol='BGP'").fetchone()[0]
    ospf_count = cur.execute("SELECT COUNT(DISTINCT device_id) FROM routing_protocols WHERE protocol='OSPF'").fetchone()[0]
    iface_stats = cur.execute("""
        SELECT d.hostname, COUNT(i.id) AS iface_count
        FROM devices d LEFT JOIN interfaces i ON i.device_id=d.id
        GROUP BY d.id ORDER BY d.hostname
    """).fetchall()
    devices = cur.execute("SELECT hostname, vendor FROM devices ORDER BY hostname").fetchall()
    conn.close()
    return render_template("dashboard.html", validations=validations, recent_risks=recent_risks,
                           bgp_count=bgp_count, ospf_count=ospf_count, iface_stats=iface_stats,
                           search_q=q, status_filter=status, protocol_filter=protocol, risk_filter=risk,
                           devices=devices)


@app.route("/device/<hostname>")
def device_detail(hostname):
    conn = get_db_connection(str(DB_PATH))
    cur = conn.cursor()
    device = cur.execute("SELECT * FROM devices WHERE hostname=?", (hostname,)).fetchone()
    if not device:
        conn.close()
        return "Device not found", 404
    interfaces = cur.execute("SELECT * FROM interfaces WHERE device_id=?", (device["id"],)).fetchall()
    protocols = cur.execute("SELECT * FROM routing_protocols WHERE device_id=?", (device["id"],)).fetchall()
    neighbors = cur.execute("SELECT * FROM bgp_neighbors WHERE device_id=?", (device["id"],)).fetchall()
    ospf_areas = cur.execute("SELECT * FROM ospf_areas WHERE device_id=?", (device["id"],)).fetchall()
    acls = cur.execute("SELECT * FROM acl_rules WHERE device_id=?", (device["id"],)).fetchall()
    logs = cur.execute("SELECT * FROM log_events WHERE device_name=? ORDER BY id DESC", (hostname,)).fetchall()
    validations = cur.execute("SELECT * FROM audit_validations WHERE device_name=? ORDER BY id DESC", (hostname,)).fetchall()
    conn.close()
    return render_template("device_detail.html", device=device, interfaces=interfaces, protocols=protocols,
                           neighbors=neighbors, ospf_areas=ospf_areas, acls=acls, logs=logs, validations=validations)


@app.route("/export")
@login_required
def export_csv():
    EXPORT_DIR.mkdir(parents=True, exist_ok=True)
    path = EXPORT_DIR / "audit_report.csv"
    conn = get_db_connection(str(DB_PATH))
    rows = conn.execute("SELECT device_name, rule_checked, status, details FROM audit_validations ORDER BY device_name, id").fetchall()
    with path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["Device Name", "Rule Checked", "Status", "Details"])
        writer.writerows([[r["device_name"], r["rule_checked"], r["status"], r["details"]] for r in rows])
    conn.close()
    return send_file(path, as_attachment=True, download_name="audit_report.csv", mimetype="text/csv")


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", "5000")), debug=False)
