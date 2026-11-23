"""Uptime and certificate checks.

Each check watches one thing on a schedule:
  tcp   - can we open a connection to host:port (a service is listening)
  http  - does a web address answer with a status below 400
  ping  - does the host answer a ping
  cert  - does the HTTPS certificate on host:port stay valid, and how many days are left

Checks are only useful for things you run or depend on. They make ordinary
connections; they do not send attacks or login attempts.
"""
import logging
import re
import socket
import ssl
import subprocess
import threading
import time
import urllib.error
import urllib.request
from urllib.parse import urlparse

import db

log = logging.getLogger("netwatch.checks")

KINDS = ("tcp", "http", "ping", "cert")
DEFAULT_PORT = {"tcp": None, "http": 80, "ping": None, "cert": 443}
RESULT_KEEP_SECONDS = 7 * 86400
INTERVAL = {"tcp": 60, "http": 60, "ping": 60, "cert": 6 * 3600}


def _clean_target(kind, target, port):
    target = (target or "").strip()
    if not target:
        raise ValueError("Enter a host name, IP address or web address")
    if kind == "http":
        if not target.startswith(("http://", "https://")):
            target = "https://" + target
        if not urlparse(target).hostname:
            raise ValueError("That web address does not look right")
        return target, None
    if re.search(r"\s", target) or "/" in target:
        raise ValueError("Enter just the host name or IP address, without a path")
    if kind == "tcp" and not port:
        raise ValueError("Enter the port number to check (for example 22 or 443)")
    if port is not None and not (1 <= int(port) <= 65535):
        raise ValueError("The port must be between 1 and 65535")
    return target, (int(port) if port else DEFAULT_PORT.get(kind))


def create(name, kind, target, port, username):
    if kind not in KINDS:
        raise ValueError("Choose a check type: tcp, http, ping or cert")
    target, port = _clean_target(kind, target, port)
    name = (name or target).strip()[:80]
    check_id = db.write(
        "INSERT INTO checks (name, kind, target, port, enabled, created) VALUES (?,?,?,?,1,?)",
        (name, kind, target, port, time.time()))
    db.add_audit(username, "check_created", f"#{check_id} {kind} {target}")
    return check_id


def delete(check_id, username):
    db.write("DELETE FROM check_results WHERE check_id=?", (check_id,))
    db.write("DELETE FROM checks WHERE id=?", (check_id,))
    db.add_audit(username, "check_deleted", f"#{check_id}")


def list_checks():
    rows = db.query("SELECT * FROM checks ORDER BY id")
    for r in rows:
        r["history"] = [x["ok"] for x in db.query(
            "SELECT ok FROM check_results WHERE check_id=? ORDER BY ts DESC LIMIT 30",
            (r["id"],))][::-1]
    return rows


# ------------------------------------------------------------------ probes

def _probe_tcp(host, port):
    start = time.time()
    with socket.create_connection((host, port), timeout=5):
        pass
    return True, (time.time() - start) * 1000, f"port {port} is open"


def _probe_http(url):
    start = time.time()
    req = urllib.request.Request(url, headers={"User-Agent": "netwatch-check/1.0"})
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            code = resp.status
    except urllib.error.HTTPError as exc:
        code = exc.code
    ms = (time.time() - start) * 1000
    return code < 400, ms, f"HTTP {code}"


def _probe_ping(host):
    proc = subprocess.run(["ping", "-c", "1", "-W", "3", host],
                          capture_output=True, text=True, timeout=10)
    m = re.search(r"time[=<]([\d.]+) ms", proc.stdout)
    if proc.returncode == 0 and m:
        return True, float(m.group(1)), "replied to ping"
    return False, None, "no reply to ping"


def _probe_cert(host, port):
    ctx = ssl.create_default_context()
    start = time.time()
    with socket.create_connection((host, port), timeout=8) as sock:
        with ctx.wrap_socket(sock, server_hostname=host) as tls:
            cert = tls.getpeercert()
    expires = ssl.cert_time_to_seconds(cert["notAfter"])
    days = int((expires - time.time()) // 86400)
    ok = days > 7
    return ok, (time.time() - start) * 1000, f"certificate expires in {days} days"


def run_probe(check):
    kind, target, port = check["kind"], check["target"], check["port"]
    try:
        if kind == "tcp":
            return _probe_tcp(target, port)
        if kind == "http":
            return _probe_http(target)
        if kind == "ping":
            return _probe_ping(target)
        if kind == "cert":
            return _probe_cert(target, port or 443)
    except ssl.SSLCertVerificationError as exc:
        return False, None, f"certificate not trusted: {exc.verify_message}"
    except (OSError, ssl.SSLError, subprocess.SubprocessError) as exc:
        return False, None, str(exc) or exc.__class__.__name__
    return False, None, "unknown check type"


# ------------------------------------------------------------------ running

def _record(check, ok, latency, detail):
    now = time.time()
    db.write("INSERT INTO check_results (check_id, ts, ok, latency_ms, detail) VALUES (?,?,?,?,?)",
             (check["id"], now, 1 if ok else 0, latency, detail))
    previous_ok = check["last_ok"]
    fails = 0 if ok else (check["fails"] or 0) + 1
    db.write("UPDATE checks SET last_ok=?, last_latency_ms=?, last_checked=?, last_detail=?,"
             " fails=? WHERE id=?",
             (1 if ok else 0, latency, now, detail, fails, check["id"]))
    label = check["name"]
    if not ok and fails == 2:
        db.add_alert("high", "uptime", f"{label} is not responding",
                     f"{check['kind'].upper()} check of {check['target']} failed twice in a row: {detail}.",
                     ip=check["target"], dedupe_key=f"check:{check['id']}:down",
                     window_seconds=1800)
    if ok and previous_ok == 0:
        db.add_alert("low", "uptime", f"{label} is back up",
                     f"{check['target']} is responding again.",
                     ip=check["target"], dedupe_key=f"check:{check['id']}:up",
                     window_seconds=60)
    if check["kind"] == "cert":
        m = re.search(r"expires in (-?\d+) days", detail or "")
        days = int(m.group(1)) if m else None
        if days is not None and days <= 14:
            db.add_alert("high", "certificate", f"Certificate for {check['target']} expires soon",
                         f"It expires in {days} days. Renew it before it runs out.",
                         ip=check["target"], dedupe_key=f"cert:{check['id']}:14",
                         window_seconds=86400)
        elif days is not None and days <= 30:
            db.add_alert("medium", "certificate", f"Certificate for {check['target']} expires in {days} days",
                         "Plan the renewal.", ip=check["target"],
                         dedupe_key=f"cert:{check['id']}:30", window_seconds=86400)


def run_check_now(check_id):
    rows = db.query("SELECT * FROM checks WHERE id=?", (check_id,))
    if not rows:
        return None
    check = rows[0]
    ok, latency, detail = run_probe(check)
    _record(check, ok, latency, detail)
    return {"ok": ok, "latency_ms": latency, "detail": detail}


def _due():
    now = time.time()
    out = []
    for c in db.query("SELECT * FROM checks WHERE enabled=1"):
        last = c["last_checked"] or 0
        if now - last >= INTERVAL.get(c["kind"], 60):
            out.append(c)
    return out


def loop():
    last_prune = 0
    while True:
        try:
            for check in _due():
                ok, latency, detail = run_probe(check)
                _record(check, ok, latency, detail)
            if time.time() - last_prune > 3600:
                db.write("DELETE FROM check_results WHERE ts < ?",
                         (time.time() - RESULT_KEEP_SECONDS,))
                db.write("DELETE FROM dns_queries WHERE ts < ?",
                         (time.time() - RESULT_KEEP_SECONDS,))
                last_prune = time.time()
        except Exception:
            log.exception("check loop error")
        time.sleep(15)


def start():
    threading.Thread(target=loop, daemon=True).start()
