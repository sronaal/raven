import sqlite3
import json
import logging
from pathlib import Path
from config.settings import BASE_DIR

logger = logging.getLogger(__name__)

DB_PATH = BASE_DIR / "data" / "scans.db"


def get_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    return conn


def init_db():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = get_connection()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            url TEXT NOT NULL,
            timestamp TEXT NOT NULL,
            level TEXT NOT NULL,
            total_score INTEGER,
            level1_score INTEGER,
            level2_score INTEGER,
            level3_score INTEGER,
            result_json TEXT NOT NULL,
            client_ip TEXT,
            created_at TEXT DEFAULT (datetime('now'))
        )
    """)
    conn.execute("CREATE INDEX IF NOT EXISTS idx_scans_url ON scans(url)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_scans_timestamp ON scans(timestamp)")
    conn.commit()
    conn.close()
    logger.info("Database initialized at %s", DB_PATH)


def save_scan(url: str, timestamp: str, level: str, result: dict, client_ip: str = "") -> int:
    conn = get_connection()
    resumen = result.get("resumen_general", {})
    nivel1 = result.get("nivel1", {})
    nivel2 = result.get("nivel2", {})
    nivel3 = result.get("nivel3", {})

    cursor = conn.execute(
        """INSERT INTO scans (url, timestamp, level, total_score, level1_score, level2_score, level3_score, result_json, client_ip)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (
            url,
            timestamp,
            level,
            resumen.get("total_score"),
            nivel1.get("security_score"),
            nivel2.get("vulnerability_score"),
            nivel3.get("parameter_score"),
            json.dumps(result),
            client_ip,
        ),
    )
    conn.commit()
    scan_id = cursor.lastrowid
    conn.close()
    return scan_id


def get_scans(limit: int = 50, offset: int = 0) -> list:
    conn = get_connection()
    rows = conn.execute(
        "SELECT id, url, timestamp, level, total_score, level1_score, level2_score, level3_score, client_ip, created_at FROM scans ORDER BY timestamp DESC LIMIT ? OFFSET ?",
        (limit, offset),
    ).fetchall()
    scans = [dict(r) for r in rows]
    conn.close()
    return scans


def get_scan_by_id(scan_id: int) -> dict | None:
    conn = get_connection()
    row = conn.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()
    result = dict(row) if row else None
    if result:
        result["result_json"] = json.loads(result["result_json"])
    conn.close()
    return result


def delete_scan(scan_id: int) -> bool:
    conn = get_connection()
    cursor = conn.execute("DELETE FROM scans WHERE id = ?", (scan_id,))
    conn.commit()
    deleted = cursor.rowcount > 0
    conn.close()
    return deleted


def get_scan_stats() -> dict:
    conn = get_connection()
    total = conn.execute("SELECT COUNT(*) as count FROM scans").fetchone()["count"]
    avg_score = conn.execute("SELECT AVG(total_score) as avg FROM scans WHERE total_score IS NOT NULL").fetchone()["avg"]
    top_urls = [dict(r) for r in conn.execute(
        "SELECT url, COUNT(*) as count, AVG(total_score) as avg_score FROM scans GROUP BY url ORDER BY count DESC LIMIT 10"
    ).fetchall()]
    severity_counts = {}
    for row in conn.execute("""
        SELECT json_extract(result_json, '$.nivel2.vulnerabilities') as vulns
        FROM scans WHERE json_extract(result_json, '$.nivel2.vulnerabilities') IS NOT NULL
    """).fetchall():
        vulns = json.loads(row["vulns"]) if isinstance(row["vulns"], str) else row["vulns"]
        if isinstance(vulns, list):
            for v in vulns:
                sev = v.get("severity", "UNKNOWN")
                severity_counts[sev] = severity_counts.get(sev, 0) + 1
    conn.close()
    return {
        "total_scans": total,
        "average_score": round(avg_score or 0, 1),
        "top_scanned_urls": top_urls,
        "vulnerability_severity_counts": severity_counts,
    }
