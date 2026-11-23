"""Turns the raw numbers into one plain-language status for the home screen.

red    = something serious needs attention now
yellow = something to check soon
green  = all good
"""
import json
import time

import db

WEEK = 7 * 86400


def compute_status(cfg):
    online_cutoff = time.time() - 2 * cfg.get("discovery_interval_seconds", 120)
    reds, yellows = [], []

    serious = db.one(
        "SELECT COUNT(*) AS n FROM alerts WHERE acknowledged=0"
        " AND severity IN ('critical','high') AND ts>?", (time.time() - WEEK,))["n"]
    if serious:
        reds.append(f"{serious} serious alert{'s' if serious != 1 else ''} not yet read")

    crit_devices = high_devices = 0
    untrusted_online = blocked_online = 0
    devices = db.query("SELECT * FROM devices")
    for d in devices:
        vulns = json.loads(d["vuln_summary"]) if d.get("vuln_summary") else {}
        if vulns.get("critical"):
            crit_devices += 1
        elif vulns.get("high"):
            high_devices += 1
        if d["last_seen"] >= online_cutoff:
            if not d["trusted"] and not d.get("blocked"):
                untrusted_online += 1
            if d.get("blocked"):
                blocked_online += 1
    if crit_devices:
        reds.append(f"{crit_devices} device{'s have' if crit_devices != 1 else ' has'} critical problems")

    medium = db.one(
        "SELECT COUNT(*) AS n FROM alerts WHERE acknowledged=0"
        " AND severity='medium' AND ts>?", (time.time() - WEEK,))["n"]
    if medium:
        yellows.append(f"{medium} alert{'s' if medium != 1 else ''} to check")
    if high_devices:
        yellows.append(f"{high_devices} device{'s have' if high_devices != 1 else ' has'} serious problems to fix")
    if untrusted_online:
        yellows.append(f"{untrusted_online} unknown device{'s are' if untrusted_online != 1 else ' is'} on the network")
    if blocked_online:
        yellows.append(f"{blocked_online} blocked device{'s are' if blocked_online != 1 else ' is'} still connected")

    if reds:
        level, headline = "red", "Serious problem: action needed"
    elif yellows:
        level, headline = "yellow", "Please check a few things"
    else:
        level, headline = "green", "Your network looks good"
    return {"level": level, "headline": headline, "reasons": reds + yellows}
