import os
import sqlite3
from datetime import datetime, timezone

DB_PATH = os.getenv("DB_PATH", "prompt_history.db")


def get_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_connection()
    conn.execute(
        """CREATE TABLE IF NOT EXISTS history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            prompt TEXT NOT NULL,
            template TEXT NOT NULL,
            mode TEXT NOT NULL,
            response TEXT NOT NULL,
            status TEXT NOT NULL
        )"""
    )
    conn.execute(
        """CREATE TABLE IF NOT EXISTS counters (
            template TEXT PRIMARY KEY,
            count INTEGER NOT NULL DEFAULT 0
        )"""
    )
    conn.commit()
    conn.close()


def log_prompt(prompt, template, mode, response, status):
    conn = get_connection()
    timestamp = datetime.now(timezone.utc).isoformat(timespec="seconds")
    conn.execute(
        "INSERT INTO history (timestamp, prompt, template, mode, response, status) VALUES (?, ?, ?, ?, ?, ?)",
        (timestamp, prompt, template, mode, response, status),
    )
    if status == "Success":
        conn.execute("INSERT OR IGNORE INTO counters (template, count) VALUES (?, 0)", (template,))
        conn.execute("UPDATE counters SET count = count + 1 WHERE template = ?", (template,))
    conn.commit()
    conn.close()


def fetch_history(search=""):
    conn = get_connection()
    if search:
        pattern = f"%{search}%"
        rows = conn.execute(
            """SELECT id, timestamp, prompt, template, mode, response, status
               FROM history
               WHERE prompt LIKE ? OR response LIKE ? OR template LIKE ?
               ORDER BY id DESC""",
            (pattern, pattern, pattern),
        ).fetchall()
    else:
        rows = conn.execute(
            """SELECT id, timestamp, prompt, template, mode, response, status
               FROM history ORDER BY id DESC"""
        ).fetchall()
    conn.close()
    return [tuple(row) for row in rows]


def fetch_counters():
    conn = get_connection()
    rows = conn.execute("SELECT template, count FROM counters ORDER BY count DESC, template").fetchall()
    conn.close()
    return [tuple(row) for row in rows]
