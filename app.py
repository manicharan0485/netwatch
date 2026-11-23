"""NetWatch web app: device monitoring, traffic view, alerts and vulnerability scans.

Run with root for packet capture:  sudo .venv/bin/python app.py
The dashboard binds to 127.0.0.1 by default. Do not expose it to other networks
without adding authentication first.
"""
import ipaddress
import json
import logging
import os
import threading
import time

from flask import Flask, jsonify, render_template, request

import db
import scanner
from monitor import Monitor

BASE = os.path.dirname(os.path.abspath(__file__))
with open(os.path.join(BASE, "config.json")) as fh:
    CFG = json.load(fh)

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

app = Flask(__name__)
db.init_db()
monitor = Monitor(CFG)


@app.route("/")
def index():
    return render_template("index.html")


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
    db.write("UPDATE devices SET trusted=1 WHERE mac=?", (mac.upper(),))
    return jsonify({"ok": True})


@app.post("/api/discover")
def discover_now():
    found = monitor.discover()
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
    return jsonify({"scan_id": scan_id}), 202


@app.get("/api/scans")
def scans():
    return jsonify(db.query("SELECT * FROM scans ORDER BY id DESC LIMIT 50"))


@app.get("/api/scans/<int:scan_id>")
def scan_detail(scan_id):
    scan = db.one("SELECT * FROM scans WHERE id=?", (scan_id,))
    if scan is None:
        return jsonify({"error": "not found"}), 404
    scan["findings"] = db.query(
        "SELECT * FROM findings WHERE scan_id=? ORDER BY "
        "CASE severity WHEN 'critical' THEN 4 WHEN 'high' THEN 3 "
        "WHEN 'medium' THEN 2 WHEN 'low' THEN 1 ELSE 0 END DESC, port",
        (scan_id,))
    return jsonify(scan)


_location = {"at": 0.0, "data": None}


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
    findings = db.query(
        "SELECT * FROM findings WHERE scan_id=? ORDER BY "
        "CASE severity WHEN 'critical' THEN 4 WHEN 'high' THEN 3 "
        "WHEN 'medium' THEN 2 WHEN 'low' THEN 1 ELSE 0 END DESC, port",
        (scan["id"],))
    return jsonify({"ip": ip, "scan": scan, "findings": findings})


if __name__ == "__main__":
    if CFG.get("auto_scan", True):
        threading.Thread(target=scanner.auto_scan_loop, args=(CFG,), daemon=True).start()
    monitor.start()
    app.run(host=CFG.get("bind_host", "127.0.0.1"), port=CFG.get("port", 5000),
            debug=False, threaded=True)
