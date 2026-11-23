"""SQLite storage for devices, alerts, scans and findings."""
import os
import sqlite3
import threading
import time

BASE = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE, "netwatch.db")
_write_lock = threading.Lock()

SCHEMA = """
CREATE TABLE IF NOT EXISTS devices (
    mac TEXT PRIMARY KEY,
    ip TEXT,
    hostname TEXT,
    first_seen REAL,
    last_seen REAL,
    trusted INTEGER DEFAULT 0
);
CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts REAL,
    severity TEXT,
    category TEXT,
    title TEXT,
    detail TEXT,
    ip TEXT,
    dedupe_key TEXT,
    acknowledged INTEGER DEFAULT 0
);
CREATE TABLE IF NOT EXISTS scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip TEXT,
    started REAL,
    finished REAL,
    status TEXT,
    summary TEXT
);
CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER,
    ip TEXT,
    port INTEGER,
    service TEXT,
    severity TEXT,
    title TEXT,
    description TEXT,
    fix TEXT
);
"""


def connect():
    c = sqlite3.connect(DB_PATH, timeout=10, check_same_thread=False)
    c.row_factory = sqlite3.Row
    return c


def init_db():
    with connect() as c:
        c.executescript(SCHEMA)


def write(sql, params=()):
    """Run a write statement under a lock and return the cursor's lastrowid."""
    with _write_lock, connect() as c:
        cur = c.execute(sql, params)
        return cur.lastrowid


def query(sql, params=()):
    with connect() as c:
        return [dict(r) for r in c.execute(sql, params).fetchall()]


def one(sql, params=()):
    rows = query(sql, params)
    return rows[0] if rows else None


def add_alert(severity, category, title, detail, ip=None, dedupe_key=None,
              window_seconds=300):
    """Insert an alert unless an identical one was raised within the window."""
    key = dedupe_key or f"{category}:{ip}:{title}"
    recent = one(
        "SELECT id FROM alerts WHERE dedupe_key=? AND ts>?",
        (key, time.time() - window_seconds),
    )
    if recent:
        return None
    return write(
        "INSERT INTO alerts (ts, severity, category, title, detail, ip, dedupe_key)"
        " VALUES (?,?,?,?,?,?,?)",
        (time.time(), severity, category, title, detail, ip, key),
    )
