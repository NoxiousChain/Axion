"""
Rules-based incident correlator.

Groups incoming alerts into incidents when they share at least one entity
(src_ip, dst_ip, user, device_id, host, or top_dst) AND arrive within
`window_seconds` of the incident's last update (default 5 minutes).

Called synchronously inside POST /api/alerts so every stored alert is
tagged with an incident_id before the response returns.  All functions
accept an open sqlite3.Connection so the caller controls transaction scope.
"""

from __future__ import annotations

import sqlite3
from typing import Optional

_SEVERITY_RANK = {"low": 0, "medium": 1, "high": 2, "critical": 3}
_RANK_SEVERITY = {v: k for k, v in _SEVERITY_RANK.items()}

# Details fields considered correlation keys, in preference order for labels.
_ENTITY_FIELDS = ("dst_ip", "src_ip", "user", "device_id", "host", "top_dst")
_SKIP_VALUES = frozenset({"", "unknown", "-", "none"})


def _rank(sev: str) -> int:
    return _SEVERITY_RANK.get((sev or "").lower(), 0)


def extract_entities(details: dict) -> list:
    """Return normalised 'field:value' strings that serve as correlation keys."""
    out = []
    for field in _ENTITY_FIELDS:
        val = str(details.get(field) or "").strip()
        if val and val.lower() not in _SKIP_VALUES:
            out.append(f"{field}:{val}")
    return out


def ensure_schema(conn: sqlite3.Connection) -> None:
    """Create incidents/incident_entities tables and add incident_id to alerts."""
    conn.execute("""
        CREATE TABLE IF NOT EXISTS incidents (
            id                INTEGER PRIMARY KEY AUTOINCREMENT,
            created_at        REAL,
            updated_at        REAL,
            severity          TEXT,
            title             TEXT,
            alert_count       INTEGER DEFAULT 1,
            detectors         TEXT,
            acknowledged      INTEGER DEFAULT 0,
            acknowledged_by   TEXT,
            acknowledged_at   REAL,
            acknowledged_note TEXT
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS incident_entities (
            incident_id INTEGER REFERENCES incidents(id),
            entity      TEXT,
            PRIMARY KEY (incident_id, entity)
        )
    """)
    conn.execute("CREATE INDEX IF NOT EXISTS idx_inc_updated ON incidents(updated_at)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_inc_ent    ON incident_entities(entity)")
    existing = {r[1] for r in conn.execute("PRAGMA table_info(alerts)")}
    if "incident_id" not in existing:
        conn.execute("ALTER TABLE alerts ADD COLUMN incident_id INTEGER")
    conn.commit()


def correlate(
    conn: sqlite3.Connection,
    alert_id: int,
    ts: float,
    detector: str,
    severity: str,
    details: dict,
    window_seconds: float = 300.0,
) -> int:
    """Find or create an incident for this alert.  Returns the incident_id."""
    entities = extract_entities(details)
    incident_id = _find_open(conn, ts, entities, window_seconds)

    if incident_id is None:
        incident_id = _create(conn, ts, detector, severity, entities)
    else:
        _update(conn, incident_id, ts, detector, severity, entities)

    conn.execute(
        "UPDATE alerts SET incident_id = ? WHERE id = ?",
        (incident_id, alert_id),
    )
    conn.commit()
    return incident_id


# ---------- internal helpers ----------

def _find_open(
    conn: sqlite3.Connection,
    ts: float,
    entities: list,
    window_seconds: float,
) -> Optional[int]:
    if not entities:
        return None
    cutoff = ts - window_seconds
    placeholders = ",".join("?" * len(entities))
    row = conn.execute(
        f"""
        SELECT ie.incident_id
        FROM   incident_entities ie
        JOIN   incidents i ON i.id = ie.incident_id
        WHERE  ie.entity IN ({placeholders})
          AND  i.updated_at >= ?
          AND  i.acknowledged = 0
        ORDER BY i.updated_at DESC
        LIMIT  1
        """,
        entities + [cutoff],
    ).fetchone()
    return row[0] if row else None


def _create(
    conn: sqlite3.Connection,
    ts: float,
    detector: str,
    severity: str,
    entities: list,
) -> int:
    label = _entity_label(entities) if entities else detector
    cur = conn.execute(
        """INSERT INTO incidents
           (created_at, updated_at, severity, title, alert_count, detectors)
           VALUES (?, ?, ?, ?, 1, ?)""",
        (ts, ts, severity.lower(), f"Incident: {label}", detector),
    )
    inc_id = cur.lastrowid
    for e in entities:
        conn.execute(
            "INSERT OR IGNORE INTO incident_entities (incident_id, entity) VALUES (?, ?)",
            (inc_id, e),
        )
    return inc_id


def _update(
    conn: sqlite3.Connection,
    incident_id: int,
    ts: float,
    detector: str,
    severity: str,
    entities: list,
) -> None:
    row = conn.execute(
        "SELECT severity, alert_count, detectors FROM incidents WHERE id = ?",
        (incident_id,),
    ).fetchone()
    if not row:
        return
    old_sev, count, det_str = row
    new_sev = _RANK_SEVERITY[max(_rank(old_sev), _rank(severity))]
    dets = set(det_str.split(",")) if det_str else set()
    dets.add(detector)
    new_count = count + 1

    for e in entities:
        conn.execute(
            "INSERT OR IGNORE INTO incident_entities (incident_id, entity) VALUES (?, ?)",
            (incident_id, e),
        )
    all_entities = [
        r[0] for r in conn.execute(
            "SELECT entity FROM incident_entities WHERE incident_id = ?",
            (incident_id,),
        ).fetchall()
    ]
    label = _entity_label(all_entities)
    det_list = ", ".join(sorted(dets))
    conn.execute(
        """UPDATE incidents
           SET updated_at=?, severity=?, title=?, alert_count=?, detectors=?
           WHERE id=?""",
        (ts, new_sev, f"{new_count}-alert incident on {label} [{det_list}]",
         new_count, ",".join(sorted(dets)), incident_id),
    )


def _entity_label(entities: list) -> str:
    """Pick the most human-readable value from the entity list."""
    by_type: dict = {}
    for e in entities:
        if ":" in e:
            field, val = e.split(":", 1)
            by_type.setdefault(field, val)
    for field in _ENTITY_FIELDS:
        if field in by_type:
            return by_type[field]
    return entities[0].split(":", 1)[-1] if entities else "unknown"
