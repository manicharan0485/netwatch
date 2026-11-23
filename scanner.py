"""Exposure and vulnerability scanner.

What it does:
  1. Checks the target is inside the networks listed in config.json (private
     ranges by default) so the tool cannot be pointed at arbitrary internet hosts.
  2. Runs nmap service/version detection (-sV), plus OS detection (-O) when
     running as root. This only connects to ports and reads banners; it does
     not send exploit payloads or try passwords.
  3. Matches open ports and detected software versions against vulns.json and
     stores each match with a description and a fix.
  4. Automatically scans every device found on the monitored network, and
     rescans each one on a schedule (auto_scan_hours in config.json).
"""
import ipaddress
import json
import logging
import os
import re
import subprocess
import threading
import time
import xml.etree.ElementTree as ET

import db

log = logging.getLogger("netwatch.scanner")

BASE = os.path.dirname(os.path.abspath(__file__))
with open(os.path.join(BASE, "vulns.json")) as fh:
    RULES = json.load(fh)

SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

# Shared state for the dashboard: which device is being scanned right now.
state = {"current_ip": None, "auto_enabled": False, "last_full_pass": None}


class ScopeError(ValueError):
    pass


def check_target(ip, allowed_networks):
    """Raise ScopeError unless ip is a valid address inside an allowed network."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        raise ScopeError(f"'{ip}' is not a valid IP address")
    for net in allowed_networks:
        if addr in ipaddress.ip_network(net, strict=False):
            return str(addr)
    raise ScopeError(
        f"{ip} is outside the allowed networks in config.json. "
        "Only scan devices you own or are authorized to test.")


def _version_tuple(text):
    parts = re.findall(r"\d+", text or "")
    return tuple(int(p) for p in parts[:3]) if parts else None


def _match(rule, port, service, product, version):
    m = rule["match"]
    if "port" in m and port != m["port"]:
        return False
    if "ports" in m and port not in m["ports"]:
        return False
    if "service" in m and service != m["service"]:
        return False
    if "product" in m and m["product"].lower() not in (product or "").lower():
        return False
    if "version_lt" in m:
        have = _version_tuple(version)
        want = _version_tuple(m["version_lt"])
        if have is None or want is None or have >= want:
            return False
    return True


def match_findings(open_ports):
    """open_ports: list of dicts with port, service, product, version."""
    findings = []
    for p in open_ports:
        for rule in RULES:
            if _match(rule, p["port"], p["service"], p["product"], p["version"]):
                findings.append({
                    "port": p["port"],
                    "service": (p["service"] or "") +
                               (f" {p['product']} {p['version']}".rstrip() if p["product"] else ""),
                    "severity": rule["severity"],
                    "title": rule["title"],
                    "description": rule["description"],
                    "fix": rule["fix"],
                })
    findings.sort(key=lambda f: SEVERITY_ORDER.get(f["severity"], 0), reverse=True)
    return findings


def parse_nmap_xml(root):
    ports = []
    for port in root.iter("port"):
        if port.get("protocol") != "tcp":
            continue
        state_el = port.find("state")
        if state_el is None or state_el.get("state") != "open":
            continue
        svc = port.find("service")
        ports.append({
            "port": int(port.get("portid")),
            "service": svc.get("name", "") if svc is not None else "",
            "product": svc.get("product", "") if svc is not None else "",
            "version": svc.get("version", "") if svc is not None else "",
        })
    return ports


def parse_os(root):
    """Best OS guess from nmap -O output: name (with version), accuracy and family."""
    best = None
    for m in root.findall("host/os/osmatch"):
        accuracy = int(m.get("accuracy", "0"))
        if best is None or accuracy > best["os_accuracy"]:
            cls = m.find("osclass")
            best = {
                "os_guess": m.get("name"),
                "os_accuracy": accuracy,
                "os_family": cls.get("osfamily", "") if cls is not None else "",
            }
    return best or {}


def _record_port_changes(ip, open_ports):
    """Compare with the previous scan: new ports raise an alert, closed ports are logged."""
    prev = db.one("SELECT mac, open_ports FROM devices WHERE ip=? AND last_scanned IS NOT NULL"
                  " ORDER BY last_seen DESC LIMIT 1", (ip,))
    if prev is None or prev["open_ports"] is None:
        return
    before = {int(x) for x in prev["open_ports"].split(",") if x.strip().isdigit()}
    now_ports = {p["port"] for p in open_ports}
    now = time.time()
    for port in sorted(now_ports - before):
        db.write("INSERT INTO device_events (ts, mac, kind, detail) VALUES (?,?,?,?)",
                 (now, prev["mac"], "port_opened", f"port {port}"))
        db.add_alert("medium", "port_change", f"New open port {port} on {ip}",
                     "A service started listening on this device since the last check. "
                     "If you did not set it up, investigate before trusting the device.",
                     ip=ip, dedupe_key=f"port_change:{ip}:{port}", window_seconds=86400)
    for port in sorted(before - now_ports):
        db.write("INSERT INTO device_events (ts, mac, kind, detail) VALUES (?,?,?,?)",
                 (now, prev["mac"], "port_closed", f"port {port}"))


def start_scan(ip, cfg):
    """Create a scan record and run it in a background thread. Returns scan id."""
    target = check_target(ip, cfg["allowed_networks"])
    scan_id = db.write(
        "INSERT INTO scans (ip, started, status) VALUES (?,?,?)",
        (target, time.time(), "running"),
    )
    threading.Thread(target=_run, args=(scan_id, target, cfg), daemon=True).start()
    return scan_id


def _run(scan_id, ip, cfg):
    try:
        is_root = hasattr(os, "geteuid") and os.geteuid() == 0
        cmd = ["nmap", "-Pn", "-sV", "-T4"]
        if is_root:
            cmd.append("-O")   # OS detection needs root
        cmd += ["--top-ports", str(cfg.get("scan_top_ports", 200)), "-oX", "-", ip]
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=1800)
        if proc.returncode != 0 and not proc.stdout:
            raise RuntimeError(proc.stderr.strip() or "nmap failed")

        root = ET.fromstring(proc.stdout)
        open_ports = parse_nmap_xml(root)
        findings = match_findings(open_ports)
        counts = {s: 0 for s in SEVERITY_ORDER}
        for f in findings:
            counts[f["severity"]] += 1
            db.write(
                "INSERT INTO findings (scan_id, ip, port, service, severity, title,"
                " description, fix) VALUES (?,?,?,?,?,?,?,?)",
                (scan_id, ip, f["port"], f["service"], f["severity"], f["title"],
                 f["description"], f["fix"]),
            )
            if SEVERITY_ORDER[f["severity"]] >= SEVERITY_ORDER["high"]:
                db.add_alert(
                    f["severity"], "vulnerability", f"{f['title']} on {ip}",
                    f"Port {f['port']}: {f['description']} Fix: {f['fix']}",
                    ip=ip, dedupe_key=f"vuln:{ip}:{f['port']}:{f['title']}",
                    window_seconds=86400,
                )

        info = parse_os(root) if is_root else {}
        _record_port_changes(ip, open_ports)
        db.write(
            "UPDATE devices SET os_guess=?, os_accuracy=?, os_family=?, open_ports=?,"
            " last_scanned=?, vuln_summary=? WHERE ip=?",
            (info.get("os_guess"), info.get("os_accuracy"), info.get("os_family"),
             ",".join(str(p["port"]) for p in open_ports), time.time(),
             json.dumps(counts), ip),
        )
        summary = f"{len(open_ports)} open TCP ports, {len(findings)} findings"
        db.write("UPDATE scans SET status=?, finished=?, summary=? WHERE id=?",
                 ("done", time.time(), summary, scan_id))
    except Exception as exc:
        db.write("UPDATE scans SET status=?, finished=?, summary=? WHERE id=?",
                 ("failed", time.time(), str(exc), scan_id))
        # Record the attempt so a broken host is not retried every minute.
        db.write("UPDATE devices SET last_scanned=? WHERE ip=?", (time.time(), ip))


def scan_device(ip, cfg):
    """Scan one device in the current thread and return its scan id."""
    scan_id = db.write(
        "INSERT INTO scans (ip, started, status) VALUES (?,?,?)",
        (ip, time.time(), "running"),
    )
    state["current_ip"] = ip
    try:
        _run(scan_id, ip, cfg)
    finally:
        state["current_ip"] = None
    return scan_id


def auto_scan_loop(cfg):
    """Scan every online device that has never been scanned, or is due a rescan.

    Devices are scanned one at a time so the network is not flooded.
    """
    state["auto_enabled"] = True
    interval = cfg.get("auto_scan_hours", 24) * 3600
    online_window = 2 * cfg.get("discovery_interval_seconds", 120)
    while True:
        try:
            now = time.time()
            due = db.query(
                "SELECT ip FROM devices WHERE last_seen>=?"
                " AND (last_scanned IS NULL OR last_scanned<?)"
                " ORDER BY last_seen DESC",
                (now - online_window, now - interval),
            )
            for row in due:
                try:
                    check_target(row["ip"], cfg["allowed_networks"])
                except ScopeError:
                    continue
                scan_device(row["ip"], cfg)
            if due:
                state["last_full_pass"] = time.time()
        except Exception:
            log.exception("auto scan pass failed")
        time.sleep(60)
