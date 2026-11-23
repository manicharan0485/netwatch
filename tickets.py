"""Simple support tickets for NetWatch.

A ticket tracks one problem from start to finish: who reported it, which device
it is about, who is working on it, the notes, and how it was resolved.
Serious alerts (critical or high) open a ticket automatically, once per problem.
"""
import os
import re
import secrets
import time

import db

STATUSES = ("open", "in_progress", "resolved")
SEVERITIES = ("critical", "high", "medium", "low")
DEFAULT_SEVERITY = "medium"

TICKET_SCHEMA = """
CREATE TABLE IF NOT EXISTS tickets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT,
    description TEXT,
    severity TEXT,
    status TEXT,
    ip TEXT,
    assignee TEXT,
    reported_by TEXT,
    source_key TEXT,        -- alert key, so one open ticket per problem
    created REAL,
    updated REAL,
    resolved_note TEXT
);
CREATE TABLE IF NOT EXISTS ticket_comments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ticket_id INTEGER,
    username TEXT,
    text TEXT,
    ts REAL
);
"""


ATTACH_SCHEMA = """
CREATE TABLE IF NOT EXISTS ticket_attachments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ticket_id INTEGER,
    filename TEXT,          -- name as uploaded, shown to people
    stored_name TEXT,       -- random name on disk, never shown
    mime TEXT,
    size INTEGER,
    uploaded_by TEXT,
    ts REAL
);
"""

MAX_FILE_BYTES = 10 * 1024 * 1024
MAX_FILES_PER_UPLOAD = 5

# extension -> (required first bytes or None, mime type)
ALLOWED_TYPES = {
    ".png": (b"\x89PNG\r\n\x1a\n", "image/png"),
    ".jpg": (b"\xff\xd8\xff", "image/jpeg"),
    ".jpeg": (b"\xff\xd8\xff", "image/jpeg"),
    ".gif": (b"GIF8", "image/gif"),
    ".webp": (b"RIFF", "image/webp"),
    ".pdf": (b"%PDF", "application/pdf"),
    ".txt": (None, "text/plain; charset=utf-8"),
    ".docx": (b"PK\x03\x04", "application/vnd.openxmlformats-officedocument.wordprocessingml.document"),
    ".xlsx": (b"PK\x03\x04", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"),
}
IMAGE_EXTS = {".png", ".jpg", ".jpeg", ".gif", ".webp"}


def attachments_dir():
    path = os.path.join(db.DATA_DIR, "attachments")
    os.makedirs(path, exist_ok=True)
    return path


def _safe_name(name):
    base = os.path.basename(name or "file").strip().replace("\x00", "")
    base = re.sub(r"[^A-Za-z0-9._ -]", "_", base)[:120]
    return base or "file"


def read_upload(upload):
    """Check one uploaded file without saving it. Raises ValueError with a plain message."""
    filename = _safe_name(upload.filename)
    ext = os.path.splitext(filename)[1].lower()
    if ext not in ALLOWED_TYPES:
        allowed = ", ".join(sorted(e[1:] for e in ALLOWED_TYPES))
        raise ValueError(f"'{filename}' is not a supported file. Use one of: {allowed}")
    data = upload.read(MAX_FILE_BYTES + 1)
    if len(data) > MAX_FILE_BYTES:
        raise ValueError(f"'{filename}' is larger than 10 MB")
    if not data:
        raise ValueError(f"'{filename}' is empty")
    magic, mime = ALLOWED_TYPES[ext]
    if magic and not data.startswith(magic):
        raise ValueError(f"'{filename}' does not look like a {ext[1:].upper()} file")
    if ext == ".txt":
        if b"\x00" in data[:4096]:
            raise ValueError(f"'{filename}' is not a plain text file")
        data.decode("utf-8", errors="replace")

    return {"filename": filename, "ext": ext, "mime": mime, "data": data}


def store_attachment(ticket_id, uploaded_by, info):
    """Save a file that read_upload() has already checked."""
    filename, ext, mime, data = info["filename"], info["ext"], info["mime"], info["data"]
    stored = secrets.token_hex(16) + ext
    with open(os.path.join(attachments_dir(), stored), "wb") as fh:
        fh.write(data)
    attachment_id = db.write(
        "INSERT INTO ticket_attachments (ticket_id, filename, stored_name, mime, size,"
        " uploaded_by, ts) VALUES (?,?,?,?,?,?,?)",
        (ticket_id, filename, stored, mime, len(data), uploaded_by, time.time()))
    _touch(ticket_id)
    db.add_audit(uploaded_by, "ticket_attachment", f"#{ticket_id} {filename}")
    return attachment_id


def add_attachment(ticket_id, uploaded_by, upload):
    return store_attachment(ticket_id, uploaded_by, read_upload(upload))


def get_attachment(ticket_id, attachment_id):
    row = db.one("SELECT * FROM ticket_attachments WHERE id=? AND ticket_id=?",
                 (attachment_id, ticket_id))
    if row is None:
        return None, None
    return row, os.path.join(attachments_dir(), row["stored_name"])


def _touch(ticket_id):
    db.write("UPDATE tickets SET updated=? WHERE id=?", (time.time(), ticket_id))


def create(title, description="", severity=DEFAULT_SEVERITY, ip=None,
           reported_by="system", source_key=None):
    now = time.time()
    if severity not in SEVERITIES:
        severity = DEFAULT_SEVERITY
    ticket_id = db.write(
        "INSERT INTO tickets (title, description, severity, status, ip, assignee,"
        " reported_by, source_key, created, updated) VALUES (?,?,?,?,?,?,?,?,?,?)",
        (title.strip()[:200], description.strip()[:4000], severity, "open", ip, None,
         reported_by, source_key, now, now))
    db.add_audit(reported_by, "ticket_created", f"#{ticket_id} {title[:80]}")
    return ticket_id


def auto_from_alert(severity, title, detail, ip, dedupe_key):
    """Open a ticket for a serious alert, unless one is already open for it."""
    if severity not in ("critical", "high"):
        return None
    existing = db.one(
        "SELECT id FROM tickets WHERE source_key=? AND status!='resolved'",
        (dedupe_key,))
    if existing:
        return None
    return create(title=title + (f" on {ip}" if ip and ip not in title else ""),
                  description=detail, severity=severity, ip=ip,
                  reported_by="NetWatch (automatic)", source_key=dedupe_key)


def list_tickets(status="open"):
    if status == "all":
        rows = db.query("SELECT * FROM tickets ORDER BY"
                        " CASE status WHEN 'resolved' THEN 1 ELSE 0 END, updated DESC")
    elif status == "resolved":
        rows = db.query("SELECT * FROM tickets WHERE status='resolved' ORDER BY updated DESC")
    else:  # open and in-progress
        rows = db.query("SELECT * FROM tickets WHERE status!='resolved'"
                        " ORDER BY CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1"
                        " WHEN 'medium' THEN 2 ELSE 3 END, created DESC")
    return rows


def get(ticket_id):
    ticket = db.one("SELECT * FROM tickets WHERE id=?", (ticket_id,))
    if ticket is None:
        return None
    ticket["comments"] = db.query(
        "SELECT * FROM ticket_comments WHERE ticket_id=? ORDER BY id", (ticket_id,))
    ticket["attachments"] = db.query(
        "SELECT id, filename, mime, size, uploaded_by, ts FROM ticket_attachments"
        " WHERE ticket_id=? ORDER BY id", (ticket_id,))
    return ticket


def add_comment(ticket_id, username, text):
    if not text.strip():
        raise ValueError("Write a note first")
    db.write("INSERT INTO ticket_comments (ticket_id, username, text, ts) VALUES (?,?,?,?)",
             (ticket_id, username, text.strip()[:2000], time.time()))
    _touch(ticket_id)
    db.add_audit(username, "ticket_comment", f"#{ticket_id}")


def set_status(ticket_id, status, username, note=""):
    if status not in STATUSES:
        raise ValueError("Unknown status")
    if status == "resolved":
        db.write("UPDATE tickets SET status=?, resolved_note=?, updated=? WHERE id=?",
                 (status, note.strip()[:2000], time.time(), ticket_id))
    else:
        db.write("UPDATE tickets SET status=?, updated=? WHERE id=?",
                 (status, time.time(), ticket_id))
    if note.strip() and status != "resolved":
        add_comment(ticket_id, username, note)
    db.add_audit(username, "ticket_" + status, f"#{ticket_id}")


def assign(ticket_id, assignee, username):
    db.write("UPDATE tickets SET assignee=?, status=CASE WHEN status='open' THEN 'in_progress'"
             " ELSE status END, updated=? WHERE id=?",
             (assignee or None, time.time(), ticket_id))
    db.add_audit(username, "ticket_assigned", f"#{ticket_id} to {assignee or 'nobody'}")


def counts():
    rows = db.query("SELECT status, COUNT(*) AS n FROM tickets GROUP BY status")
    out = {s: 0 for s in STATUSES}
    for r in rows:
        out[r["status"]] = r["n"]
    out["unresolved"] = out["open"] + out["in_progress"]
    return out
