"""Exposure and vulnerability scanner.

What it does:
  1. Checks the target is inside the networks listed in config.json (private
     ranges by default) so the tool cannot be pointed at arbitrary internet hosts.
  2. Runs nmap service/version detection (-sV). This only connects to ports and
     reads banners; it does not send exploit payloads or try passwords.
  3. Matches open ports and detected software versions against vulns.json and
     stores each match with a description and a fix.
"""
import ipaddress
import json
import os
import re
import subprocess
import threading
import time
import xml.etree.ElementTree as ET

import db

BASE = os.path.dirname(os.path.abspath(__file__))
with open(os.path.join(BASE, "vulns.json")) as fh:
    RULES = json.load(fh)

SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


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


def parse_nmap_xml(xml_text):
    root = ET.fromstring(xml_text)
    ports = []
    for port in root.iter("port"):
        if port.get("protocol") != "tcp":
            continue
        state = port.find("state")
        if state is None or state.get("state") != "open":
            continue
        svc = port.find("service")
        ports.append({
            "port": int(port.get("portid")),
            "service": svc.get("name", "") if svc is not None else "",
            "product": svc.get("product", "") if svc is not None else "",
            "version": svc.get("version", "") if svc is not None else "",
        })
    return ports


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
        cmd = ["nmap", "-Pn", "-sV", "-T4", "--top-ports",
               str(cfg.get("scan_top_ports", 200)), "-oX", "-", ip]
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=1800)
        if proc.returncode != 0 and not proc.stdout:
            raise RuntimeError(proc.stderr.strip() or "nmap failed")
        open_ports = parse_nmap_xml(proc.stdout)
        findings = match_findings(open_ports)
        for f in findings:
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
        summary = f"{len(open_ports)} open TCP ports, {len(findings)} findings"
        db.write("UPDATE scans SET status=?, finished=?, summary=? WHERE id=?",
                 ("done", time.time(), summary, scan_id))
    except Exception as exc:
        db.write("UPDATE scans SET status=?, finished=?, summary=? WHERE id=?",
                 ("failed", time.time(), str(exc), scan_id))
