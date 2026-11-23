"""Email for serious alerts and the weekly summary.

Settings live in the "email" section of config.json. The SMTP password is never
stored in the file: set it in the environment as NETWATCH_SMTP_PASSWORD.
"""
import json
import logging
import os
import smtplib
import threading
import time
from email.message import EmailMessage

import db
import health

log = logging.getLogger("netwatch.notify")
BASE = os.path.dirname(os.path.abspath(__file__))


def load_config():
    with open(os.path.join(BASE, "config.json")) as fh:
        return json.load(fh)


def email_settings():
    return load_config().get("email", {})


def send_email(subject, body):
    """Send one plain-text email. Returns (ok, message). Never raises."""
    cfg = email_settings()
    if not cfg.get("enabled"):
        return False, "email is turned off in config.json"
    recipients = cfg.get("to") or []
    if not recipients:
        return False, "no recipients set in config.json"
    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = cfg.get("from", "netwatch@localhost")
    msg["To"] = ", ".join(recipients)
    msg.set_content(body)
    try:
        with smtplib.SMTP(cfg["smtp_host"], cfg.get("smtp_port", 587), timeout=20) as s:
            s.starttls()
            if cfg.get("smtp_user"):
                s.login(cfg["smtp_user"], os.environ.get("NETWATCH_SMTP_PASSWORD", ""))
            s.send_message(msg)
        return True, "sent"
    except Exception as exc:
        log.warning("email failed: %s", exc)
        return False, str(exc)


def alert_email(severity, title, detail, ip):
    """Email serious alerts. Called from db.add_alert; runs in the background."""
    if severity not in ("critical", "high") or not email_settings().get("enabled"):
        return
    body = (f"{detail}\n\n"
            f"Device: {ip or 'whole network'}\n"
            f"Time: {time.strftime('%Y-%m-%d %H:%M')}\n\n"
            "Open NetWatch and choose Fix problems to see the steps.")
    threading.Thread(target=send_email,
                     args=(f"[NetWatch] {severity.upper()}: {title}", body),
                     daemon=True).start()


def weekly_summary_text():
    cfg = load_config()
    status = health.compute_status(cfg)
    week_ago = time.time() - 7 * 86400
    total = db.one("SELECT COUNT(*) AS n FROM devices")["n"]
    new = db.one("SELECT COUNT(*) AS n FROM devices WHERE first_seen>?", (week_ago,))["n"]
    alerts = db.one("SELECT COUNT(*) AS n FROM alerts WHERE ts>?", (week_ago,))["n"]
    lines = [
        "NetWatch weekly summary",
        "=" * 30,
        f"Status: {status['headline']}",
    ]
    lines += [f"  - {r}" for r in status["reasons"]] or ["  - Nothing needs your attention."]
    lines += [
        "",
        f"Devices on the network: {total}",
        f"New devices this week: {new}",
        f"Alerts this week: {alerts}",
        "",
        "Open NetWatch for details and step-by-step fixes.",
    ]
    return "\n".join(lines)


def send_weekly_report(username="system"):
    ok, message = send_email("[NetWatch] Weekly network summary", weekly_summary_text())
    if ok:
        db.add_audit(username, "weekly_report", "sent")
    return ok, message


def weekly_loop():
    """Send the summary once a week, on the configured weekday and hour."""
    while True:
        try:
            cfg = email_settings()
            now = time.localtime()
            if cfg.get("enabled") and cfg.get("send_weekly_report", True) \
                    and now.tm_wday == cfg.get("weekly_day", 0) \
                    and now.tm_hour >= cfg.get("weekly_hour", 8):
                last = db.one("SELECT ts FROM audit WHERE action='weekly_report'"
                               " ORDER BY id DESC LIMIT 1")
                if not last or time.time() - last["ts"] > 6 * 86400:
                    send_weekly_report()
        except Exception:
            log.exception("weekly report check failed")
        time.sleep(3600)
