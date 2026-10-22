"""SQLite storage for analysis results."""
import json
import os
import sqlite3
from datetime import datetime, timezone
from typing import Any, Optional
 
DB_PATH = os.environ.get("APKSCOPE_DB", "apkscope.db")
 
 
def _conn():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute(
        """CREATE TABLE IF NOT EXISTS analyses (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            filename TEXT NOT NULL,
            sha256 TEXT NOT NULL UNIQUE,
            package TEXT,
            score INTEGER,
            level TEXT,
            created_at TEXT,
            result_json TEXT NOT NULL
        )"""
    )
    return conn
 
 
def save_result(filename, sha256, result):
    """Store a result. Re-analysing the same file (same hash) replaces the old one."""
    with _conn() as conn:
        conn.execute("DELETE FROM analyses WHERE sha256 = ?", (sha256,))
        cur = conn.execute(
            "INSERT INTO analyses (filename, sha256, package, score, level, created_at, result_json)"
            " VALUES (?, ?, ?, ?, ?, ?, ?)",
            (
                filename, sha256, result["info"].get("package"),
                result["risk"]["score"], result["risk"]["level"],
                datetime.now(timezone.utc).isoformat(timespec="seconds"),
                json.dumps(result),
            ),
        )
        return cur.lastrowid
 
 
def list_results() -> list[dict[str, Any]]:
    with _conn() as conn:
        rows = conn.execute(
            "SELECT id, filename, sha256, package, score, level, created_at "
            "FROM analyses ORDER BY id DESC"
        ).fetchall()
    return [dict(r) for r in rows]
 
 
def get_result(analysis_id: int) -> Optional[dict[str, Any]]:
    with _conn() as conn:
        row = conn.execute("SELECT * FROM analyses WHERE id = ?", (analysis_id,)).fetchone()
    if row is None:
        return None
    data = dict(row)
    data["result"] = json.loads(data.pop("result_json"))
    return data