"""NetWatch web app: device monitoring, traffic view, alerts and vulnerability scans.

Run with root for packet capture:  sudo .venv/bin/python app.py
The dashboard binds to 127.0.0.1 by default. Do not expose it to other networks
without adding authentication first.
"""
import json
import logging
import os

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
    return jsonify({**monitor.status(), "unacked_alerts": unacked,
                    "devices": devices, "untrusted_devices": untrusted})


@app.get("/api/devices")
def devices():
    return jsonify(db.query("SELECT * FROM devices ORDER BY last_seen DESC"))


@app.post("/api/devices/<mac>/trust")
def trust(mac):
    db.write("UPDATE devices SET trusted=1 WHERE mac=?", (mac.upper(),))
    return jsonify({"ok": True})


@app.post("/api/discover")
def discover_now():
    found = monitor.discover()
    return jsonify({"hosts_found": found})


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


if __name__ == "__main__":
    monitor.start()
    app.run(host=CFG.get("bind_host", "127.0.0.1"), port=CFG.get("port", 5000),
            debug=False, threaded=True)
