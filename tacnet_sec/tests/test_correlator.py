"""
Tests for the incident correlator (tacnet_sec/server/correlator.py)
and the new /api/incidents endpoints in tacnet_sec/server/api.py.

Run from the project root:

    python -m pytest tacnet_sec/tests -v
"""

from __future__ import annotations

import json
import sqlite3
import time

import pytest

from tacnet_sec.server import correlator as cor


# ---------- fixtures ----------

@pytest.fixture
def db(tmp_path):
    """In-memory-ish SQLite with the full server schema applied."""
    path = str(tmp_path / "test.sqlite")
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    # Minimal alerts table matching the server schema.
    conn.execute("""
        CREATE TABLE alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts REAL, detector TEXT, severity TEXT,
            title TEXT, details TEXT, node_id TEXT, location TEXT,
            acknowledged INTEGER DEFAULT 0
        )
    """)
    conn.commit()
    cor.ensure_schema(conn)
    yield conn
    conn.close()


def _insert_alert(conn, *, ts=None, detector="TestDet", severity="high",
                  title="Test", details=None):
    """Helper: insert a raw alert row and return its id."""
    if ts is None:
        ts = time.time()
    cur = conn.execute(
        "INSERT INTO alerts (ts, detector, severity, title, details) VALUES (?,?,?,?,?)",
        (ts, detector, severity, title, json.dumps(details or {})),
    )
    conn.commit()
    return cur.lastrowid


# ---------- extract_entities ----------

def test_extract_entities_standard_fields():
    e = cor.extract_entities({"src_ip": "1.2.3.4", "dst_ip": "5.6.7.8", "user": "alice"})
    assert "dst_ip:5.6.7.8" in e
    assert "src_ip:1.2.3.4" in e
    assert "user:alice" in e


def test_extract_entities_skips_blanks_and_sentinels():
    e = cor.extract_entities({"src_ip": "", "dst_ip": "unknown", "user": "-", "host": None})
    assert e == []


def test_extract_entities_top_dst():
    e = cor.extract_entities({"top_dst": "10.0.0.1"})
    assert "top_dst:10.0.0.1" in e


# ---------- ensure_schema ----------

def test_ensure_schema_creates_tables(db):
    tables = {r[0] for r in db.execute(
        "SELECT name FROM sqlite_master WHERE type='table'"
    ).fetchall()}
    assert "incidents" in tables
    assert "incident_entities" in tables


def test_ensure_schema_adds_incident_id_to_alerts(db):
    cols = {r[1] for r in db.execute("PRAGMA table_info(alerts)").fetchall()}
    assert "incident_id" in cols


def test_ensure_schema_idempotent(db):
    """Calling ensure_schema twice must not raise."""
    cor.ensure_schema(db)   # second call
    tables = {r[0] for r in db.execute(
        "SELECT name FROM sqlite_master WHERE type='table'"
    ).fetchall()}
    assert "incidents" in tables


# ---------- correlate: new incident ----------

def test_correlate_creates_incident_for_first_alert(db):
    aid = _insert_alert(db, details={"dst_ip": "10.0.0.1"})
    inc_id = cor.correlate(db, aid, ts=1000.0, detector="Det", severity="high",
                           details={"dst_ip": "10.0.0.1"})
    assert isinstance(inc_id, int) and inc_id > 0

    row = db.execute("SELECT * FROM incidents WHERE id=?", (inc_id,)).fetchone()
    assert row["severity"] == "high"
    assert row["alert_count"] == 1
    assert row["detectors"] == "Det"


def test_correlate_tags_alert_with_incident_id(db):
    aid = _insert_alert(db, details={"dst_ip": "10.0.0.1"})
    inc_id = cor.correlate(db, aid, ts=1000.0, detector="Det", severity="high",
                           details={"dst_ip": "10.0.0.1"})
    row = db.execute("SELECT incident_id FROM alerts WHERE id=?", (aid,)).fetchone()
    assert row["incident_id"] == inc_id


def test_correlate_stores_entities(db):
    aid = _insert_alert(db, details={"dst_ip": "10.0.0.5", "user": "alice"})
    inc_id = cor.correlate(db, aid, ts=1000.0, detector="D", severity="low",
                           details={"dst_ip": "10.0.0.5", "user": "alice"})
    entities = {r[0] for r in db.execute(
        "SELECT entity FROM incident_entities WHERE incident_id=?", (inc_id,)
    ).fetchall()}
    assert "dst_ip:10.0.0.5" in entities
    assert "user:alice" in entities


# ---------- correlate: grouping ----------

def test_correlate_groups_alerts_sharing_dst_ip(db):
    ts = 1_000_000.0
    a1 = _insert_alert(db, details={"dst_ip": "192.168.1.10"})
    inc1 = cor.correlate(db, a1, ts=ts, detector="DDoS", severity="high",
                         details={"dst_ip": "192.168.1.10"})
    a2 = _insert_alert(db, details={"dst_ip": "192.168.1.10", "user": "bob"})
    inc2 = cor.correlate(db, a2, ts=ts + 60, detector="Insider", severity="medium",
                         details={"dst_ip": "192.168.1.10", "user": "bob"})
    assert inc1 == inc2, "both alerts share dst_ip and are within window - should be same incident"


def test_correlate_groups_alerts_sharing_user(db):
    ts = 2_000_000.0
    a1 = _insert_alert(db, details={"user": "eve"})
    inc1 = cor.correlate(db, a1, ts=ts, detector="Insider", severity="medium",
                         details={"user": "eve"})
    a2 = _insert_alert(db, details={"user": "eve", "dst_ip": "1.2.3.4"})
    inc2 = cor.correlate(db, a2, ts=ts + 120, detector="Malware", severity="high",
                         details={"user": "eve", "dst_ip": "1.2.3.4"})
    assert inc1 == inc2


def test_correlate_does_not_group_unrelated_entities(db):
    ts = 3_000_000.0
    a1 = _insert_alert(db, details={"dst_ip": "10.0.0.1"})
    inc1 = cor.correlate(db, a1, ts=ts, detector="D", severity="high",
                         details={"dst_ip": "10.0.0.1"})
    a2 = _insert_alert(db, details={"dst_ip": "10.0.0.2"})
    inc2 = cor.correlate(db, a2, ts=ts + 30, detector="D", severity="high",
                         details={"dst_ip": "10.0.0.2"})
    assert inc1 != inc2, "different IPs should produce separate incidents"


def test_correlate_does_not_group_outside_time_window(db):
    ts = 4_000_000.0
    a1 = _insert_alert(db, details={"dst_ip": "172.16.0.1"})
    inc1 = cor.correlate(db, a1, ts=ts, detector="D", severity="high",
                         details={"dst_ip": "172.16.0.1"}, window_seconds=300.0)
    # 10 minutes later — outside the 5-minute window.
    a2 = _insert_alert(db, details={"dst_ip": "172.16.0.1"})
    inc2 = cor.correlate(db, a2, ts=ts + 601, detector="D", severity="high",
                         details={"dst_ip": "172.16.0.1"}, window_seconds=300.0)
    assert inc1 != inc2, "stale incident should not absorb a new alert"


def test_correlate_does_not_reopen_acknowledged_incident(db):
    ts = 5_000_000.0
    a1 = _insert_alert(db, details={"dst_ip": "10.10.10.10"})
    inc1 = cor.correlate(db, a1, ts=ts, detector="D", severity="high",
                         details={"dst_ip": "10.10.10.10"})
    # Acknowledge the incident.
    db.execute("UPDATE incidents SET acknowledged=1 WHERE id=?", (inc1,))
    db.commit()
    # New alert with same entity should open a fresh incident.
    a2 = _insert_alert(db, details={"dst_ip": "10.10.10.10"})
    inc2 = cor.correlate(db, a2, ts=ts + 60, detector="D", severity="high",
                         details={"dst_ip": "10.10.10.10"})
    assert inc1 != inc2, "acknowledged incident should never be reopened"


# ---------- correlate: severity escalation ----------

def test_correlate_escalates_severity_to_max(db):
    ts = 6_000_000.0
    a1 = _insert_alert(db, details={"user": "charlie"})
    inc_id = cor.correlate(db, a1, ts=ts, detector="D", severity="low",
                           details={"user": "charlie"})
    # Second alert: medium → incident upgrades to medium.
    a2 = _insert_alert(db, details={"user": "charlie"})
    cor.correlate(db, a2, ts=ts + 10, detector="D2", severity="medium",
                  details={"user": "charlie"})
    row = db.execute("SELECT severity FROM incidents WHERE id=?", (inc_id,)).fetchone()
    assert row["severity"] == "medium"

    # Third alert: high → incident escalates to high.
    a3 = _insert_alert(db, details={"user": "charlie"})
    cor.correlate(db, a3, ts=ts + 20, detector="D3", severity="high",
                  details={"user": "charlie"})
    row = db.execute("SELECT severity FROM incidents WHERE id=?", (inc_id,)).fetchone()
    assert row["severity"] == "high"

    # Fourth alert: low → severity must NOT drop back down.
    a4 = _insert_alert(db, details={"user": "charlie"})
    cor.correlate(db, a4, ts=ts + 30, detector="D4", severity="low",
                  details={"user": "charlie"})
    row = db.execute("SELECT severity FROM incidents WHERE id=?", (inc_id,)).fetchone()
    assert row["severity"] == "high"


# ---------- correlate: alert count & title ----------

def test_correlate_increments_alert_count_and_updates_title(db):
    ts = 7_000_000.0
    details = {"dst_ip": "8.8.8.8"}
    a1 = _insert_alert(db, details=details)
    inc_id = cor.correlate(db, a1, ts=ts, detector="DDoS", severity="high", details=details)

    for i in range(1, 4):
        a = _insert_alert(db, details=details)
        cor.correlate(db, a, ts=ts + i * 5, detector="Malware", severity="medium", details=details)

    row = db.execute("SELECT alert_count, title FROM incidents WHERE id=?", (inc_id,)).fetchone()
    assert row["alert_count"] == 4
    assert "4-alert" in row["title"]
    assert "8.8.8.8" in row["title"]


def test_correlate_tracks_multiple_detectors(db):
    ts = 8_000_000.0
    details = {"device_id": "camera-01"}
    aids = []
    for det in ("IoTDetector", "DDoSDetector", "MalwareDetector"):
        aid = _insert_alert(db, details=details)
        cor.correlate(db, aid, ts=ts, detector=det, severity="medium", details=details)
        ts += 10
        aids.append(aid)

    # All three should belong to the same incident.
    rows = db.execute("SELECT DISTINCT incident_id FROM alerts WHERE id IN (?,?,?)",
                      tuple(aids)).fetchall()
    assert len(rows) == 1

    inc_id = rows[0][0]
    row = db.execute("SELECT detectors FROM incidents WHERE id=?", (inc_id,)).fetchone()
    dets = set(row["detectors"].split(","))
    assert "IoTDetector" in dets
    assert "DDoSDetector" in dets
    assert "MalwareDetector" in dets


# ---------- entity_label helper ----------

def test_entity_label_prefers_dst_ip():
    label = cor._entity_label(["src_ip:1.2.3.4", "dst_ip:5.6.7.8", "user:alice"])
    assert label == "5.6.7.8"


def test_entity_label_falls_back_to_user():
    label = cor._entity_label(["user:bob"])
    assert label == "bob"


def test_entity_label_unknown_for_empty():
    assert cor._entity_label([]) == "unknown"


# ---------- API endpoint tests ----------

_TEST_API_KEY = "test-key-fixture"


@pytest.fixture
def api_mod_db(tmp_path):
    """Set up an isolated DB and API key; yield the api module. Teardown resets state."""
    import tacnet_sec.server.api as api_mod
    db_path = str(tmp_path / "srv.sqlite")
    api_mod.DB_PATH = db_path
    api_mod._API_KEY = _TEST_API_KEY
    api_mod.init_db()
    yield api_mod
    api_mod._API_KEY = None


@pytest.fixture
def api_client(api_mod_db):
    """TestClient authenticated as the seeded 'admin' user (JWT)."""
    from fastapi.testclient import TestClient
    from tacnet_sec.server.auth import create_token
    # 'admin' is seeded by init_db() with role='admin', satisfies _require_operator + _require_admin.
    token = create_token("admin", _TEST_API_KEY)
    with TestClient(api_mod_db.app, headers={"Authorization": f"Bearer {token}"}) as client:
        yield client


@pytest.fixture
def analyst_client(api_mod_db):
    """TestClient authenticated as an analyst user (read-only role)."""
    from fastapi.testclient import TestClient
    from tacnet_sec.server.auth import create_token, hash_password
    import sqlite3, time
    conn = sqlite3.connect(api_mod_db.DB_PATH)
    conn.execute(
        "INSERT INTO users (username, password_hash, role, created_at) VALUES (?,?,?,?)",
        ("analyst-tester", hash_password("testpass1"), "analyst", time.time()),
    )
    conn.commit()
    conn.close()
    token = create_token("analyst-tester", _TEST_API_KEY)
    with TestClient(api_mod_db.app, headers={"Authorization": f"Bearer {token}"}) as client:
        yield client


def test_api_ingest_returns_incident_id(api_client):
    resp = api_client.post("/api/alerts", json={
        "ts": 1_000_000.0, "detector": "DDoSDetector", "severity": "high",
        "title": "Flood", "details": {"dst_ip": "10.0.0.1"},
    })
    assert resp.status_code == 200
    body = resp.json()
    assert "incident_id" in body
    assert isinstance(body["incident_id"], int)


def test_api_ingest_groups_related_alerts(api_client):
    ts = 2_000_000.0
    r1 = api_client.post("/api/alerts", json={
        "ts": ts, "detector": "DDoSDetector", "severity": "high",
        "title": "Flood", "details": {"dst_ip": "10.1.1.1"},
    }).json()
    r2 = api_client.post("/api/alerts", json={
        "ts": ts + 30, "detector": "MalwareDetector", "severity": "high",
        "title": "Process", "details": {"dst_ip": "10.1.1.1"},
    }).json()
    assert r1["incident_id"] == r2["incident_id"]


def test_api_ingest_separates_unrelated_alerts(api_client):
    ts = 3_000_000.0
    r1 = api_client.post("/api/alerts", json={
        "ts": ts, "detector": "D", "severity": "low",
        "title": "A", "details": {"dst_ip": "1.1.1.1"},
    }).json()
    r2 = api_client.post("/api/alerts", json={
        "ts": ts + 10, "detector": "D", "severity": "low",
        "title": "B", "details": {"dst_ip": "2.2.2.2"},
    }).json()
    assert r1["incident_id"] != r2["incident_id"]


def test_api_list_incidents(api_client):
    ts = 4_000_000.0
    api_client.post("/api/alerts", json={
        "ts": ts, "detector": "D", "severity": "medium",
        "title": "X", "details": {"dst_ip": "9.9.9.9"},
    })
    resp = api_client.get("/api/incidents")
    assert resp.status_code == 200
    incs = resp.json()
    assert len(incs) >= 1
    inc = incs[0]
    assert "id" in inc
    assert "severity" in inc
    assert "alert_count" in inc
    assert "detectors" in inc
    assert isinstance(inc["entities"], list)


def test_api_get_incident_includes_alerts(api_client):
    ts = 5_000_000.0
    r = api_client.post("/api/alerts", json={
        "ts": ts, "detector": "IoTDetector", "severity": "low",
        "title": "Policy", "details": {"device_id": "camera-99"},
    }).json()
    inc_id = r["incident_id"]
    resp = api_client.get(f"/api/incidents/{inc_id}")
    assert resp.status_code == 200
    inc = resp.json()
    assert inc["id"] == inc_id
    assert "alerts" in inc
    assert len(inc["alerts"]) == 1
    assert inc["alerts"][0]["detector"] == "IoTDetector"


def test_api_ack_incident_cascades_to_alerts(api_client):
    ts = 6_000_000.0
    for i in range(3):
        api_client.post("/api/alerts", json={
            "ts": ts + i * 5, "detector": "D", "severity": "high",
            "title": f"Alert {i}", "details": {"dst_ip": "50.50.50.50"},
        })
    incs = api_client.get("/api/incidents").json()
    inc_id = incs[0]["id"]

    ack_resp = api_client.post(f"/api/incidents/{inc_id}/ack",
                               json={"by": "analyst", "note": "handled"})
    assert ack_resp.status_code == 200

    # Incident itself should be acked.
    inc = api_client.get(f"/api/incidents/{inc_id}").json()
    assert inc["acknowledged"] is True

    # All constituent alerts should be acked.
    for a in inc["alerts"]:
        assert a["acknowledged"] is True, f"alert {a['id']} not acked after incident ack"


def test_api_ack_incident_hides_from_default_list(api_client):
    ts = 7_000_000.0
    r = api_client.post("/api/alerts", json={
        "ts": ts, "detector": "D", "severity": "low",
        "title": "Z", "details": {"user": "zara"},
    }).json()
    inc_id = r["incident_id"]
    api_client.post(f"/api/incidents/{inc_id}/ack", json={})

    # Default list hides acked.
    incs = api_client.get("/api/incidents").json()
    assert all(i["id"] != inc_id for i in incs)

    # Explicit show_acked=false → same as default.
    incs2 = api_client.get("/api/incidents?hide_acked=false").json()
    assert any(i["id"] == inc_id for i in incs2)


def test_api_stats_includes_open_incidents(api_client):
    api_client.post("/api/alerts", json={
        "ts": time.time(), "detector": "D", "severity": "high",
        "title": "T", "details": {"dst_ip": "11.11.11.11"},
    })
    stats = api_client.get("/api/stats").json()
    assert "open_incidents" in stats
    assert stats["open_incidents"] >= 1


def test_api_alerts_include_incident_id(api_client):
    ts = 8_000_000.0
    api_client.post("/api/alerts", json={
        "ts": ts, "detector": "D", "severity": "medium",
        "title": "T", "details": {"dst_ip": "99.99.99.99"},
    })
    alerts = api_client.get("/api/alerts").json()
    assert len(alerts) >= 1
    assert "incident_id" in alerts[0]
    assert isinstance(alerts[0]["incident_id"], int)


def test_api_alerts_filter_by_incident_id(api_client):
    ts = 9_000_000.0
    r1 = api_client.post("/api/alerts", json={
        "ts": ts, "detector": "D", "severity": "high",
        "title": "A1", "details": {"dst_ip": "20.20.20.20"},
    }).json()
    api_client.post("/api/alerts", json={
        "ts": ts + 30, "detector": "D2", "severity": "low",
        "title": "A2", "details": {"dst_ip": "20.20.20.20"},
    })
    # Third alert on different IP — different incident.
    api_client.post("/api/alerts", json={
        "ts": ts + 5, "detector": "D", "severity": "low",
        "title": "A3", "details": {"dst_ip": "30.30.30.30"},
    })

    inc_id = r1["incident_id"]
    alerts = api_client.get(f"/api/alerts?incident_id={inc_id}").json()
    assert all(a["incident_id"] == inc_id for a in alerts)
    assert len(alerts) >= 1


# ---------- RBAC tests ----------

def test_analyst_can_read_alerts(analyst_client, api_client):
    """Analysts must be able to list alerts."""
    api_client.post("/api/alerts", json={
        "ts": 10_000_000.0, "detector": "D", "severity": "low",
        "title": "Probe", "details": {"dst_ip": "1.2.3.4"},
    })
    resp = analyst_client.get("/api/alerts")
    assert resp.status_code == 200
    assert len(resp.json()) >= 1


def test_analyst_cannot_ingest_alert(analyst_client):
    """Analysts must not be allowed to POST /api/alerts."""
    resp = analyst_client.post("/api/alerts", json={
        "ts": 10_100_000.0, "detector": "D", "severity": "low",
        "title": "Smuggled", "details": {},
    })
    assert resp.status_code == 403


def test_analyst_cannot_ack_alert(analyst_client, api_client):
    """Analysts must not be allowed to acknowledge an alert."""
    r = api_client.post("/api/alerts", json={
        "ts": 10_200_000.0, "detector": "D", "severity": "high",
        "title": "Flood", "details": {"dst_ip": "5.5.5.5"},
    }).json()
    alert_id = r["alert_id"]
    resp = analyst_client.post(f"/api/alerts/{alert_id}/ack", json={})
    assert resp.status_code == 403


def test_analyst_cannot_ack_incident(analyst_client, api_client):
    """Analysts must not be allowed to acknowledge an incident."""
    r = api_client.post("/api/alerts", json={
        "ts": 10_300_000.0, "detector": "D", "severity": "high",
        "title": "Scan", "details": {"dst_ip": "6.6.6.6"},
    }).json()
    inc_id = r["incident_id"]
    resp = analyst_client.post(f"/api/incidents/{inc_id}/ack", json={})
    assert resp.status_code == 403


def test_machine_token_can_ingest_alert(api_mod_db):
    """X-Axion-Key machine token must bypass user-role check and ingest alerts."""
    from fastapi.testclient import TestClient
    with TestClient(api_mod_db.app, headers={"X-Axion-Key": _TEST_API_KEY}) as client:
        resp = client.post("/api/alerts", json={
            "ts": 10_400_000.0, "detector": "Agent", "severity": "medium",
            "title": "From agent", "details": {"src_ip": "10.0.0.1"},
        })
    assert resp.status_code == 200


# ---------- Audit log tests ----------

def test_audit_log_records_login_success(api_mod_db):
    """A successful login must appear in the audit_log table."""
    from fastapi.testclient import TestClient
    import sqlite3
    # Give admin a known password.
    from tacnet_sec.server.auth import hash_password
    conn = sqlite3.connect(api_mod_db.DB_PATH)
    conn.execute("UPDATE users SET password_hash=? WHERE username='admin'",
                 (hash_password("adminpass"),))
    conn.commit()
    conn.close()

    with TestClient(api_mod_db.app) as client:
        client.post("/api/login", json={
            "username": "admin", "password": "adminpass", "api_key": _TEST_API_KEY,
        })

    conn = sqlite3.connect(api_mod_db.DB_PATH)
    row = conn.execute(
        "SELECT action FROM audit_log WHERE actor='admin' AND action='login_success'"
    ).fetchone()
    conn.close()
    assert row is not None


def test_audit_log_records_login_failure(api_mod_db):
    """A failed login must appear in the audit_log table."""
    from fastapi.testclient import TestClient
    import sqlite3
    with TestClient(api_mod_db.app) as client:
        client.post("/api/login", json={
            "username": "admin", "password": "wrongpass", "api_key": _TEST_API_KEY,
        })

    conn = sqlite3.connect(api_mod_db.DB_PATH)
    row = conn.execute(
        "SELECT action FROM audit_log WHERE actor='admin' AND action='login_failed'"
    ).fetchone()
    conn.close()
    assert row is not None


def test_audit_log_records_ack(api_client):
    """Acknowledging an incident must produce an audit_log entry."""
    import sqlite3
    import tacnet_sec.server.api as api_mod
    r = api_client.post("/api/alerts", json={
        "ts": 11_000_000.0, "detector": "D", "severity": "high",
        "title": "Ack me", "details": {"dst_ip": "7.7.7.7"},
    }).json()
    inc_id = r["incident_id"]
    api_client.post(f"/api/incidents/{inc_id}/ack", json={"note": "resolved"})

    conn = sqlite3.connect(api_mod.DB_PATH)
    row = conn.execute(
        "SELECT * FROM audit_log WHERE action='ack_incident' AND target=?",
        (str(inc_id),),
    ).fetchone()
    conn.close()
    assert row is not None


def test_audit_endpoint_requires_admin(analyst_client):
    """Non-admin must not access the audit log endpoint."""
    resp = analyst_client.get("/api/audit")
    assert resp.status_code == 403


def test_audit_endpoint_returns_entries(api_client):
    """Admin must be able to query audit entries."""
    resp = api_client.get("/api/audit")
    assert resp.status_code == 200
    assert isinstance(resp.json(), list)


# ---------- Body size limit ----------

def test_body_size_limit_rejects_oversized_request(api_mod_db):
    """Requests with Content-Length > MAX_BODY_BYTES must get 413."""
    from fastapi.testclient import TestClient
    from tacnet_sec.server.auth import create_token
    token = create_token("admin", _TEST_API_KEY)
    # Temporarily lower the limit so we don't allocate a huge buffer in the test.
    original = api_mod_db.MAX_BODY_BYTES
    api_mod_db.MAX_BODY_BYTES = 100
    try:
        with TestClient(api_mod_db.app, headers={"Authorization": f"Bearer {token}"}) as client:
            big_payload = "x" * 200
            resp = client.post(
                "/api/alerts",
                content=big_payload,
                headers={"Content-Type": "application/json", "Content-Length": str(len(big_payload))},
            )
        assert resp.status_code == 413
    finally:
        api_mod_db.MAX_BODY_BYTES = original
