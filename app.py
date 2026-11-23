"""NetWatch web app.

Home screen (/) is the simple view for everyone: a status light and five buttons.
/advanced is the detailed dashboard for technicians.

Accounts: the first admin is created on first run (/setup). Admins can do
everything; viewers can only look.

Run with root for packet capture and OS detection:  sudo .venv/bin/python app.py
The dashboard binds to 127.0.0.1 by default. For use across a network, put it
behind HTTPS (see README) and change bind_host.
"""
import ipaddress
import json
import logging
import os
import secrets
import threading
import time

from flask import (Flask, jsonify, redirect, render_template, request, session,
                   url_for)
from werkzeug.security import check_password_hash, generate_password_hash

import db
import health
import notify
import scanner
from monitor import Monitor

BASE = os.path.dirname(os.path.abspath(__file__))
with open(os.path.join(BASE, "config.json")) as fh:
    CFG = json.load(fh)
with open(os.path.join(BASE, "fixes.json")) as fh:
    FIXES = json.load(fh)

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")


def _load_secret_key():
    """Session signing key, created once and kept next to the app."""
    path = os.path.join(os.environ.get("NETWATCH_DATA", BASE), "netwatch_secret.key")
    if os.path.exists(path):
        with open(path) as fh:
            return fh.read().strip()
    key = secrets.token_hex(32)
    with open(path, "w") as fh:
        fh.write(key)
    os.chmod(path, 0o600)
    return key


app = Flask(__name__)
app.secret_key = _load_secret_key()
app.config.update(SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Lax")
db.init_db()
monitor = Monitor(CFG)

PUBLIC_API = {"/api/login", "/api/setup", "/api/me"}
LOGIN_LIMIT = 5             # failed attempts allowed
LOGIN_LOCK_SECONDS = 300    # lock period after too many failures
_failed_logins = {}         # username -> [count, first_failure_time]


# ---------------------------------------------------------------- accounts

def users_exist():
    return db.one("SELECT COUNT(*) AS n FROM users")["n"] > 0


def current_user():
    if "user" in session:
        return {"username": session["user"], "role": session.get("role", "viewer")}
    return None


@app.before_request
def require_login():
    path = request.path
    if path.startswith("/static"):
        return None
    if not users_exist():
        if path.startswith("/api/"):
            if path == "/api/setup":
                return None
            return jsonify({"error": "Set up an admin account first", "setup": True}), 403
        return None if path == "/setup" else redirect(url_for("setup_page"))
    if path in PUBLIC_API or path in ("/login", "/setup"):
        return None
    user = current_user()
    if user is None:
        if path.startswith("/api/"):
            return jsonify({"error": "Please log in"}), 401
        return redirect(url_for("login_page"))
    if request.method not in ("GET", "HEAD", "OPTIONS") and user["role"] != "admin":
        return jsonify({"error": "Only an admin can do this"}), 403
    return None


def _check_lockout(username):
    entry = _failed_logins.get(username)
    if entry and entry[0] >= LOGIN_LIMIT and time.time() - entry[1] < LOGIN_LOCK_SECONDS:
        return False
    if entry and time.time() - entry[1] >= LOGIN_LOCK_SECONDS:
        _failed_logins.pop(username, None)
    return True


@app.get("/login")
def login_page():
    if not users_exist():
        return redirect(url_for("setup_page"))
    return render_template("login.html", setup=False)


@app.get("/setup")
def setup_page():
    if users_exist():
        return redirect(url_for("login_page"))
    return render_template("login.html", setup=True)


@app.post("/api/setup")
def api_setup():
    if users_exist():
        return jsonify({"error": "Setup is already done"}), 409
    body = request.get_json(silent=True) or {}
    username = str(body.get("username", "")).strip()
    password = str(body.get("password", ""))
    if not username or len(password) < 8:
        return jsonify({"error": "Choose a username and a password of at least 8 characters"}), 400
    db.write("INSERT INTO users (username, password_hash, role, created) VALUES (?,?,?,?)",
             (username, generate_password_hash(password), "admin", time.time()))
    db.add_audit(username, "setup", "first admin created")
    session.clear()
    session.update(user=username, role="admin")
    return jsonify({"ok": True, "username": username, "role": "admin"})


@app.post("/api/login")
def api_login():
    body = request.get_json(silent=True) or {}
    username = str(body.get("username", "")).strip()
    password = str(body.get("password", ""))
    if not _check_lockout(username):
        return jsonify({"error": "Too many failed attempts. Wait 5 minutes and try again."}), 429
    user = db.one("SELECT * FROM users WHERE username=?", (username,))
    if user is None or not check_password_hash(user["password_hash"], password):
        entry = _failed_logins.setdefault(username, [0, time.time()])
        entry[0] += 1
        db.add_audit(username, "login_failed", "")
        return jsonify({"error": "Wrong username or password"}), 401
    _failed_logins.pop(username, None)
    session.clear()
    session.update(user=username, role=user["role"])
    session.permanent = False
    db.add_audit(username, "login", "")
    return jsonify({"ok": True, "username": username, "role": user["role"]})


@app.post("/api/logout")
def api_logout():
    user = current_user()
    if user:
        db.add_audit(user["username"], "logout", "")
    session.clear()
    return jsonify({"ok": True})


@app.get("/api/me")
def api_me():
    user = current_user()
    if user is None:
        return jsonify({"logged_in": False, "setup_needed": not users_exist()})
    return jsonify({"logged_in": True, **user})


@app.get("/api/users")
def list_users():
    return jsonify(db.query("SELECT id, username, role, created FROM users ORDER BY id"))


@app.post("/api/users")
def add_user():
    body = request.get_json(silent=True) or {}
    username = str(body.get("username", "")).strip()
    password = str(body.get("password", ""))
    role = body.get("role", "viewer")
    if role not in ("admin", "viewer"):
        return jsonify({"error": "Role must be admin or viewer"}), 400
    if not username or len(password) < 8:
        return jsonify({"error": "Username and a password of at least 8 characters are needed"}), 400
    if db.one("SELECT id FROM users WHERE username=?", (username,)):
        return jsonify({"error": "That username already exists"}), 409
    db.write("INSERT INTO users (username, password_hash, role, created) VALUES (?,?,?,?)",
             (username, generate_password_hash(password), role, time.time()))
    db.add_audit(current_user()["username"], "user_added", f"{username} ({role})")
    return jsonify({"ok": True}), 201


# ---------------------------------------------------------------- pages

@app.route("/")
def home():
    return render_template("home.html")


@app.route("/advanced")
def index():
    return render_template("index.html")


# ---------------------------------------------------------------- home screen

@app.get("/api/home")
def api_home():
    status = health.compute_status(CFG)
    cutoff = time.time() - 2 * CFG.get("discovery_interval_seconds", 120)
    total = db.one("SELECT COUNT(*) AS n FROM devices")["n"]
    online = db.one("SELECT COUNT(*) AS n FROM devices WHERE last_seen>=?", (cutoff,))["n"]
    problems = 0
    for d in db.query("SELECT vuln_summary FROM devices WHERE vuln_summary IS NOT NULL"):
        counts = json.loads(d["vuln_summary"])
        if counts.get("critical") or counts.get("high"):
            problems += 1
    return jsonify({
        "status": status,
        "devices_total": total,
        "devices_online": online,
        "devices_with_problems": problems,
        "network": monitor.subnet,
        "help_contact": CFG.get("help_contact", "your IT support"),
        "scanning_now": scanner.state["current_ip"],
        "email_on": notify.email_settings().get("enabled", False),
    })


@app.post("/api/devices/<mac>/approve")
def approve_device(mac):
    user = current_user()["username"]
    row = db.one("SELECT ip, hostname FROM devices WHERE mac=?", (mac.upper(),))
    if row is None:
        return jsonify({"error": "Device not found"}), 404
    db.write("UPDATE devices SET trusted=1, blocked=0 WHERE mac=?", (mac.upper(),))
    db.add_audit(user, "device_approved", f"{row['ip']} {mac.upper()}")
    return jsonify({"ok": True})


@app.post("/api/devices/<mac>/block")
def block_device(mac):
    user = current_user()["username"]
    row = db.one("SELECT ip, hostname FROM devices WHERE mac=?", (mac.upper(),))
    if row is None:
        return jsonify({"error": "Device not found"}), 404
    db.write("UPDATE devices SET trusted=0, blocked=1 WHERE mac=?", (mac.upper(),))
    db.add_audit(user, "device_blocked", f"{row['ip']} {mac.upper()}")
    return jsonify({
        "ok": True,
        "router_steps": [
            f"Open your router's settings page: {CFG.get('router_admin_url', 'http://192.168.0.1')}",
            "Log in with the router's admin account.",
            "Find the connected devices or access control list and find this device by its MAC address: " + mac.upper(),
            "Choose Block (or turn off its internet access) and save.",
            "Come back here and press Check again on the home screen.",
        ],
    })


@app.post("/api/send-report")
def send_report_now():
    user = current_user()["username"]
    ok, message = notify.send_weekly_report(user)
    if not ok:
        return jsonify({"error": f"Could not send the report: {message}"}), 400
    return jsonify({"ok": True, "message": "Report sent"})


# ---------------------------------------------------------------- existing API

@app.get("/api/status")
def status():
    unacked = db.one("SELECT COUNT(*) AS n FROM alerts WHERE acknowledged=0")["n"]
    devices = db.one("SELECT COUNT(*) AS n FROM devices")["n"]
    untrusted = db.one("SELECT COUNT(*) AS n FROM devices WHERE trusted=0")["n"]
    cutoff = time.time() - 2 * CFG.get("discovery_interval_seconds", 120)
    online = db.one("SELECT COUNT(*) AS n FROM devices WHERE last_seen>=?", (cutoff,))["n"]
    return jsonify({**monitor.status(), "unacked_alerts": unacked,
                    "devices": devices, "devices_online": online,
                    "untrusted_devices": untrusted})


@app.get("/api/devices")
def devices():
    # A device is "online" if discovery saw it within the last two discovery intervals.
    cutoff = time.time() - 2 * CFG.get("discovery_interval_seconds", 120)
    rows = db.query("SELECT * FROM devices ORDER BY last_seen DESC")
    for r in rows:
        r["online"] = r["last_seen"] >= cutoff
    return jsonify(rows)


@app.post("/api/devices/<mac>/trust")
def trust(mac):
    db.write("UPDATE devices SET trusted=1, blocked=0 WHERE mac=?", (mac.upper(),))
    db.add_audit(current_user()["username"], "device_approved", mac.upper())
    return jsonify({"ok": True})


@app.post("/api/discover")
def discover_now():
    found = monitor.discover()
    db.add_audit(current_user()["username"], "scan_network", f"{found} devices")
    return jsonify({"hosts_found": found})


@app.post("/api/network")
def set_network():
    """Monitor the whole network that contains the given local IP.

    Example: {"ip": "192.168.0.1", "prefix": 24} watches 192.168.0.0/24.
    Only private networks are accepted, and the choice is saved to config.json.
    """
    body = request.get_json(silent=True) or {}
    raw_ip = str(body.get("ip", "")).strip()
    try:
        prefix = int(body.get("prefix", 24))
        addr = ipaddress.ip_address(raw_ip)
    except (ValueError, TypeError):
        return jsonify({"error": "Enter a valid IP address, e.g. 192.168.0.1"}), 400
    if addr.version != 4 or not (16 <= prefix <= 30):
        return jsonify({"error": "Use an IPv4 address and a prefix between /16 and /30"}), 400
    if not addr.is_private:
        return jsonify({"error": "Only private (home or office) networks can be monitored"}), 400

    subnet = str(ipaddress.ip_network(f"{addr}/{prefix}", strict=False))
    CFG["discovery_subnet"] = subnet
    with open(os.path.join(BASE, "config.json"), "w") as fh:
        json.dump(CFG, fh, indent=2)
        fh.write("\n")
    monitor.subnet = subnet
    monitor.last_discovery = None
    threading.Thread(target=monitor.discover, daemon=True).start()
    db.add_audit(current_user()["username"], "network_changed", subnet)
    return jsonify({"subnet": subnet, "message": "Scanning the network now"}), 202


@app.get("/api/alerts")
def alerts():
    since = int(request.args.get("since", 0))
    rows = db.query(
        "SELECT * FROM alerts WHERE id>? ORDER BY id DESC LIMIT 200", (since,))
    return jsonify(rows)


@app.post("/api/alerts/<int:alert_id>/ack")
def ack(alert_id):
    db.write("UPDATE alerts SET acknowledged=1 WHERE id=?", (alert_id,))
    return jsonify({"ok": True})


@app.post("/api/alerts/ack-all")
def ack_all():
    db.write("UPDATE alerts SET acknowledged=1 WHERE acknowledged=0")
    db.add_audit(current_user()["username"], "alerts_read", "")
    return jsonify({"ok": True})


@app.get("/api/audit")
def audit_log():
    return jsonify(db.query("SELECT * FROM audit ORDER BY id DESC LIMIT 200"))


@app.get("/api/traffic")
def traffic():
    return jsonify(monitor.traffic_summary())


@app.get("/api/ip/<ip>")
def ip_detail(ip):
    detail = monitor.ip_detail(ip)
    device = db.one("SELECT * FROM devices WHERE ip=? ORDER BY last_seen DESC", (ip,))
    detail["device"] = device
    detail["scans"] = db.query(
        "SELECT id, started, status, summary FROM scans WHERE ip=? ORDER BY id DESC LIMIT 5",
        (ip,))
    return jsonify(detail)


@app.post("/api/scan")
def start_scan():
    ip = (request.get_json(silent=True) or {}).get("ip", "").strip()
    try:
        scan_id = scanner.start_scan(ip, CFG)
    except scanner.ScopeError as exc:
        return jsonify({"error": str(exc)}), 400
    db.add_audit(current_user()["username"], "scan_device", ip)
    return jsonify({"scan_id": scan_id}), 202


@app.get("/api/scans")
def scans():
    return jsonify(db.query("SELECT * FROM scans ORDER BY id DESC LIMIT 50"))


@app.get("/api/scans/<int:scan_id>")
def scan_detail(scan_id):
    scan = db.one("SELECT * FROM scans WHERE id=?", (scan_id,))
    if scan is None:
        return jsonify({"error": "not found"}), 404
    scan["findings"] = _with_steps(db.query(
        "SELECT * FROM findings WHERE scan_id=? ORDER BY "
        "CASE severity WHEN 'critical' THEN 4 WHEN 'high' THEN 3 "
        "WHEN 'medium' THEN 2 WHEN 'low' THEN 1 ELSE 0 END DESC, port",
        (scan_id,)))
    return jsonify(scan)


_location = {"at": 0.0, "data": None}


def _with_steps(findings):
    """Attach the plain-language fix checklist to each finding."""
    for f in findings:
        f["steps"] = FIXES.get(f["title"], [f["fix"]])
    return findings


def public_location():
    """Geolocate this network's public IP (the router's address on the internet).

    Devices on your LAN have private addresses and cannot be geolocated, so
    this is the only location the app can report. It is cached for an hour.
    """
    import urllib.request
    if _location["data"] and time.time() - _location["at"] < 3600:
        return _location["data"]
    try:
        req = urllib.request.Request("https://ipwho.is/",
                                     headers={"User-Agent": "netwatch/1.0"})
        with urllib.request.urlopen(req, timeout=8) as resp:
            d = json.load(resp)
        if not d.get("success", False):
            raise ValueError(d.get("message", "lookup failed"))
        conn = d.get("connection") or {}
        data = {
            "public_ip": d.get("ip"),
            "city": d.get("city"),
            "region": d.get("region"),
            "country": d.get("country"),
            "isp": conn.get("isp"),
            "timezone": (d.get("timezone") or {}).get("id"),
        }
    except Exception as exc:  # offline, rate limited, etc.
        data = {"error": f"Location unavailable: {exc}"}
    _location.update(at=time.time(), data=data)
    return data


@app.get("/api/summary")
def summary():
    cutoff = time.time() - 2 * CFG.get("discovery_interval_seconds", 120)
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for row in db.query("SELECT vuln_summary FROM devices WHERE vuln_summary IS NOT NULL"):
        for sev, n in json.loads(row["vuln_summary"]).items():
            if sev in counts:
                counts[sev] += n
    total = db.one("SELECT COUNT(*) AS n FROM devices")["n"]
    online = db.one("SELECT COUNT(*) AS n FROM devices WHERE last_seen>=?", (cutoff,))["n"]
    scanned = db.one("SELECT COUNT(*) AS n FROM devices WHERE last_scanned IS NOT NULL")["n"]
    return jsonify({
        "subnet": monitor.subnet,
        "devices_total": total,
        "devices_online": online,
        "devices_scanned": scanned,
        "scanning_now": scanner.state["current_ip"],
        "auto_scan": scanner.state["auto_enabled"],
        "vulnerabilities": counts,
        "network_location": public_location(),
        "running_as_root": monitor.status()["running_as_root"],
    })


@app.get("/api/vuln-overview")
def vuln_overview():
    cutoff = time.time() - 2 * CFG.get("discovery_interval_seconds", 120)
    rows = db.query("SELECT * FROM devices ORDER BY last_seen DESC")
    for r in rows:
        r["online"] = r["last_seen"] >= cutoff
        r["vulns"] = json.loads(r["vuln_summary"]) if r["vuln_summary"] else None
        r.pop("vuln_summary", None)
    return jsonify(rows)


@app.get("/api/device-findings/<ip>")
def device_findings(ip):
    scan = db.one("SELECT * FROM scans WHERE ip=? AND status='done' ORDER BY id DESC LIMIT 1",
                  (ip,))
    if scan is None:
        return jsonify({"ip": ip, "scan": None, "findings": []})
    findings = _with_steps(db.query(
        "SELECT * FROM findings WHERE scan_id=? ORDER BY "
        "CASE severity WHEN 'critical' THEN 4 WHEN 'high' THEN 3 "
        "WHEN 'medium' THEN 2 WHEN 'low' THEN 1 ELSE 0 END DESC, port",
        (scan["id"],)))
    return jsonify({"ip": ip, "scan": scan, "findings": findings})


@app.get("/api/traffic-history")
def traffic_history():
    """Download and upload per minute, for the whole network or one device (?ip=)."""
    minutes = request.args.get("minutes", 60, type=int)
    ip = request.args.get("ip") or None
    if ip:
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            return jsonify({"error": "Not a valid IP address"}), 400
    return jsonify(monitor.history_series(minutes, ip))


@app.get("/api/problems")
def problems():
    """Every device that has findings, with its steps, for the Fix problems screen."""
    out = []
    for d in db.query("SELECT * FROM devices WHERE vuln_summary IS NOT NULL ORDER BY last_seen DESC"):
        counts = json.loads(d["vuln_summary"])
        if not any(counts.get(s, 0) for s in ("critical", "high", "medium", "low")):
            continue
        scan = db.one("SELECT * FROM scans WHERE ip=? AND status='done' ORDER BY id DESC LIMIT 1",
                      (d["ip"],))
        findings = _with_steps(db.query(
            "SELECT * FROM findings WHERE scan_id=? ORDER BY "
            "CASE severity WHEN 'critical' THEN 4 WHEN 'high' THEN 3 "
            "WHEN 'medium' THEN 2 WHEN 'low' THEN 1 ELSE 0 END DESC, port",
            (scan["id"],))) if scan else []
        out.append({"ip": d["ip"], "mac": d["mac"], "hostname": d["hostname"],
                    "os": d["os_guess"], "counts": counts, "findings": findings})
    return jsonify(out)


if __name__ == "__main__":
    if CFG.get("auto_scan", True):
        threading.Thread(target=scanner.auto_scan_loop, args=(CFG,), daemon=True).start()
    threading.Thread(target=notify.weekly_loop, daemon=True).start()
    monitor.start()
    app.run(host=CFG.get("bind_host", "127.0.0.1"), port=CFG.get("port", 5000),
            debug=False, threaded=True)
