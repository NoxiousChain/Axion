
import json
import os
from typing import Any, Dict, List, Optional

# SQLCipher: encrypt the agent's local alert store at rest.
# Requires system package (apk add sqlcipher / apt install sqlcipher libsqlcipher-dev)
# and Python binding (pip install sqlcipher3).
# If unavailable, falls back to plain sqlite3 transparently.
try:
    from sqlcipher3 import dbapi2 as _db_module
    _SQLCIPHER = True
except ImportError:
    import sqlite3 as _db_module  # type: ignore[no-redef]
    _SQLCIPHER = False

# Passphrase for the agent DB, derived from env var.
# Set AXION_AGENT_DB_KEY in the agent's environment file.
# Empty string disables encryption even when sqlcipher3 is installed.
_AGENT_DB_KEY: str = os.environ.get("AXION_AGENT_DB_KEY", "")

if _SQLCIPHER and not _AGENT_DB_KEY:
    import logging as _log
    _log.getLogger(__name__).warning(
        "sqlcipher3 installed but AXION_AGENT_DB_KEY not set — agent DB is unencrypted."
    )


def _apply_key(conn) -> None:
    """Set SQLCipher encryption key immediately after opening the connection."""
    if _SQLCIPHER and _AGENT_DB_KEY:
        key_hex = _AGENT_DB_KEY.encode().hex()
        conn.execute(f"PRAGMA key=\"x'{key_hex}'\"")
        conn.execute("PRAGMA cipher_page_size = 4096")
        conn.execute("PRAGMA kdf_iter = 64000")
        conn.execute("PRAGMA cipher_hmac_algorithm = HMAC_SHA512")


class AlertStore:
    def __init__(self, path: str):
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        self.conn = _db_module.connect(path)
        _apply_key(self.conn)
        self._init()

    def _init(self):
        cur = self.conn.cursor()
        cur.execute('''
            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts REAL,
                detector TEXT,
                severity TEXT,
                title TEXT,
                details TEXT,
                node_id TEXT,
                location TEXT
            )
        ''')
        existing = {row[1] for row in cur.execute("PRAGMA table_info(alerts)")}
        for col, typedef in [("node_id", "TEXT"), ("location", "TEXT")]:
            if col not in existing:
                cur.execute(f"ALTER TABLE alerts ADD COLUMN {col} {typedef}")
        self.conn.commit()

    def write(self, ts: float, detector: str, severity: str, title: str, details: dict,
              node_id: Optional[str] = None, location: Optional[str] = None):
        cur = self.conn.cursor()
        cur.execute(
            "INSERT INTO alerts (ts, detector, severity, title, details, node_id, location) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (ts, detector, severity, title, json.dumps(details), node_id, location),
        )
        self.conn.commit()

    def recent(self, limit: int = 200) -> List[Dict[str, Any]]:
        cur = self.conn.cursor()
        cur.execute(
            "SELECT ts, detector, severity, title, details, node_id, location "
            "FROM alerts ORDER BY ts DESC LIMIT ?",
            (limit,),
        )
        rows = []
        for row in cur.fetchall():
            rows.append({
                "ts": row[0],
                "detector": row[1],
                "severity": row[2],
                "title": row[3],
                "details": json.loads(row[4]) if row[4] else {},
                "node_id": row[5],
                "location": row[6],
            })
        return rows

    def close(self):
        self.conn.close()
