"""
Unit tests covering the regression that motivated this sprint (detectors not
firing because of async/await on the bus) plus each detector and the
dedupe / node-identity plumbing.

Run from the project root:

    python -m pytest tacnet_sec/tests -v
"""

from __future__ import annotations

import calendar
import os
import tempfile
import time

import pytest

from tacnet_sec.core.anomaly import EWMATracker
from tacnet_sec.core.bus import EventBus
from tacnet_sec.core.store import AlertStore
from tacnet_sec.core.throttle import AlertThrottler
from tacnet_sec.detectors.ddos import DDoSDetector
from tacnet_sec.detectors.insider import InsiderDetector
from tacnet_sec.detectors.iot import IoTDetector
from tacnet_sec.detectors.malware import MalwareDetector
from tacnet_sec.responders.actions import Alert


BASE_CFG = {
    "agent": {"node_id": "test-node", "location": "lab", "forward_alerts": False},
    "ddos": {"window_seconds": 2, "pkt_rate_threshold": 50, "unique_src_entropy_min": 0.5, "enable": True},
    "malware": {"suspicious_proc_names": ["mimikatz.exe", "nc.exe"], "dns_tunnel_minlen": 40, "enable": True},
    "insider": {"baseline_hours": [6, 20], "max_data_mb_per_hour": 1, "new_host_contact_threshold": 5, "enable": True},
    "iot": {
        "allowed_services": {"camera-*": ["tcp/443"]},
        "weak_creds_usernames": ["admin", "root"],
        "enable": True,
    },
    # Disable anomaly by default so existing tests continue to reason only
    # about the static rules. Tests that need anomaly enable it explicitly.
    "anomaly": {"enable": False},
}


@pytest.fixture
def store(tmp_path):
    s = AlertStore(str(tmp_path / "alerts.sqlite"))
    yield s
    s.close()


@pytest.fixture(autouse=True)
def _reset_throttler():
    # Fresh cooldown slots per test so one test doesn't suppress the next.
    Alert._default_throttler = AlertThrottler(cooldown_seconds=30.0)
    yield


def _event(**overrides):
    ev = {
        "ts": time.time(),
        "src_ip": "10.0.0.1", "dst_ip": "10.0.0.2",
        "dst_port": 443, "proto": "tcp", "bytes": 500,
        "user": "alice", "device_id": "laptop-22", "proc": "chrome.exe",
        "dns_qname_len": 0,
    }
    ev.update(overrides)
    return ev


# --- the regression test ----------------------------------------------

def test_sync_publish_invokes_handlers(store):
    """Regression: bus.publish used to be async so fire-and-forget calls
    never actually ran handlers. It's sync now."""
    bus = EventBus()
    seen = []
    bus.subscribe("net_event", lambda e: seen.append(e))
    bus.publish("net_event", {"ts": 1.0})
    assert seen == [{"ts": 1.0}]


# --- detectors -------------------------------------------------------

def test_ddos_fires_on_flood(store):
    bus = EventBus()
    DDoSDetector(bus, BASE_CFG, store)
    now = time.time()
    for _ in range(300):
        bus.publish("net_event", _event(ts=now, src_ip="203.0.113.9", dst_ip="10.1.0.5"))
    rows = store.recent()
    assert any(r["detector"] == "DDoSDetector" for r in rows)
    # Exactly one emission despite 300 matching events (dedupe).
    ddos = [r for r in rows if r["detector"] == "DDoSDetector"]
    assert len(ddos) == 1
    assert ddos[0]["node_id"] == "test-node"


def test_malware_process_and_dns(store):
    bus = EventBus()
    MalwareDetector(bus, BASE_CFG, store)
    bus.publish("net_event", _event(proc="mimikatz.exe", device_id="host-A"))
    bus.publish("net_event", _event(dns_qname_len=80, src_ip="10.0.0.99"))
    titles = {r["title"] for r in store.recent()}
    assert "Suspicious tool/process observed" in titles
    assert "Possible DNS tunneling" in titles


def test_insider_volume_and_hosts(store):
    bus = EventBus()
    InsiderDetector(bus, BASE_CFG, store)
    # Pick a UTC timestamp inside baseline hours so off-hours rule doesn't fire.
    ts = calendar.timegm((2026, 1, 1, 12, 0, 0, 0, 1, 0))
    # push >1MB for user bob
    for _ in range(5):
        bus.publish("net_event", _event(ts=ts, user="bob", bytes=400_000))
    # Broad scan
    for i in range(10):
        bus.publish("net_event", _event(ts=ts, user="bob", dst_ip=f"198.51.100.{i}"))
    titles = {r["title"] for r in store.recent()}
    assert "Excessive data volume" in titles
    assert "High number of new hosts contacted" in titles


def test_insider_off_hours_is_throttled(store):
    bus = EventBus()
    InsiderDetector(bus, BASE_CFG, store)
    ts_night = calendar.timegm((2026, 1, 1, 2, 0, 0, 0, 1, 0))  # 02:00 UTC
    for _ in range(50):
        bus.publish("net_event", _event(ts=ts_night, user="carol", bytes=100))
    off_hours = [r for r in store.recent() if r["title"] == "Off-hours activity"]
    assert len(off_hours) == 1  # one per (user, hour), not 50


def test_iot_policy_violation(store):
    bus = EventBus()
    IoTDetector(bus, BASE_CFG, store)
    bus.publish("net_event", _event(device_id="camera-99", proto="tcp", dst_port=23))
    bus.publish("net_event", _event(device_id="camera-99", proto="tcp", dst_port=443))  # allowed
    rows = store.recent()
    assert len(rows) == 1
    assert rows[0]["details"]["service"] == "tcp/23"


def test_iot_weak_credential_alert(store):
    bus = EventBus()
    IoTDetector(bus, BASE_CFG, store)
    bus.publish("net_event", _event(device_id="sensor-1", username="admin"))
    bus.publish("net_event", _event(device_id="sensor-1", username="admin"))  # deduped
    bus.publish("net_event", _event(device_id="sensor-1", username="alice"))  # not weak
    rows = [r for r in store.recent() if r["title"] == "Weak credential detected on IoT device"]
    assert len(rows) == 1
    assert rows[0]["details"]["username"] == "admin"
    assert rows[0]["severity"] == "high"


def test_iot_weak_credential_user_field(store):
    """Falls back to 'user' field when 'username' is absent."""
    bus = EventBus()
    IoTDetector(bus, BASE_CFG, store)
    bus.publish("net_event", _event(device_id="cam-42", user="root"))
    rows = [r for r in store.recent() if r["title"] == "Weak credential detected on IoT device"]
    assert rows and rows[0]["details"]["username"] == "root"


def test_dedupe_key_separation(store):
    """Different (host, proc) pairs should get their own alerts even within
    the cooldown window."""
    bus = EventBus()
    MalwareDetector(bus, BASE_CFG, store)
    bus.publish("net_event", _event(proc="nc.exe", device_id="host-A"))
    bus.publish("net_event", _event(proc="nc.exe", device_id="host-A"))  # deduped
    bus.publish("net_event", _event(proc="nc.exe", device_id="host-B"))  # new slot
    rows = [r for r in store.recent() if r["title"] == "Suspicious tool/process observed"]
    assert len(rows) == 2
    hosts = {r["details"]["host"] for r in rows}
    assert hosts == {"host-A", "host-B"}


def test_store_migration_adds_node_id_column(tmp_path):
    """Old databases without node_id should be upgraded transparently."""
    from tacnet_sec.core import store as store_mod
    path = tmp_path / "legacy.sqlite"
    # Use the same db module and key as AlertStore so the file format matches.
    conn = store_mod._db_module.connect(str(path))
    store_mod._apply_key(conn)
    conn.execute(
        "CREATE TABLE alerts (id INTEGER PRIMARY KEY AUTOINCREMENT, "
        "ts REAL, detector TEXT, severity TEXT, title TEXT, details TEXT)"
    )
    conn.execute(
        "INSERT INTO alerts (ts, detector, severity, title, details) "
        "VALUES (1.0, 'x', 'low', 'legacy', '{}')"
    )
    conn.commit(); conn.close()

    s = AlertStore(str(path))  # should migrate
    s.write(2.0, "new", "high", "fresh", {"k": 1}, node_id="node-Z", location="lab")
    rows = s.recent()
    s.close()
    assert rows[0]["node_id"] == "node-Z"
    assert any(r["title"] == "legacy" for r in rows)


def test_throttler_suppress_count():
    t = AlertThrottler(cooldown_seconds=10.0)
    emit, sup = t.should_emit("a")
    assert emit and sup == 0
    for _ in range(4):
        e2, _ = t.should_emit("a")
        assert not e2
    # Advance clock by forcing a new slot; 4 hits were suppressed.
    t._slots[("a",)].first_seen -= 11.0  # simulate cooldown passing
    emit, sup = t.should_emit("a")
    assert emit and sup == 4


# --- anomaly tracker --------------------------------------------------

def test_ewma_cold_start_returns_none():
    t = EWMATracker(alpha=0.3, cold_start_samples=5, min_std=0.01)
    for v in [10, 11, 10, 9, 10]:
        z = t.update(("k",), v)
        # Tracker needs at least cold_start_samples observations before scoring.
        assert z is None


def test_ewma_flat_baseline_does_not_fire_on_steady_traffic():
    t = EWMATracker(alpha=0.2, cold_start_samples=5, min_std=1.0)
    zs = []
    for _ in range(40):
        z = t.update(("k",), 100.0)
        if z is not None:
            zs.append(z)
    # After warmup, every sample is exactly the mean -> z=0.
    assert zs, "tracker never produced a z-score"
    assert all(abs(z) < 0.5 for z in zs)


def test_ewma_spike_produces_high_z_score():
    t = EWMATracker(alpha=0.1, cold_start_samples=10, min_std=1.0)
    for _ in range(30):
        t.update(("k",), 100.0)  # train on ~100
    z = t.update(("k",), 1000.0)  # huge spike
    assert z is not None and z > 5.0


def test_ewma_per_entity_isolation():
    t = EWMATracker(alpha=0.2, cold_start_samples=5, min_std=1.0)
    for _ in range(20):
        t.update(("dst-A",), 10.0)
        t.update(("dst-B",), 1000.0)
    # A has a low baseline; a value of 1000 should be extremely anomalous for A
    z_a = t.update(("dst-A",), 1000.0)
    # B has a high baseline; the same 1000 should look normal to B
    z_b = t.update(("dst-B",), 1000.0)
    assert z_a is not None and z_b is not None
    assert z_a > z_b
    assert z_a > 3.0
    assert abs(z_b) < 2.0


# --- anomaly integrated into detectors --------------------------------

def _anomaly_cfg(**overrides):
    cfg = {k: v for k, v in BASE_CFG.items()}
    cfg["anomaly"] = {
        "enable": True,
        "alpha": 0.2,
        "z_threshold": 3.0,
        "cold_start_samples": 5,
        "min_std_ddos": 1.0,
        "min_std_insider": 1024.0,
    }
    cfg.update(overrides)
    return cfg


def test_ddos_anomaly_catches_subtle_spike_under_static_threshold(store):
    """A rate that stays under pkt_rate_threshold but is 10x the learned
    baseline for a destination should fire the anomaly alert even though
    the static threshold does not."""
    bus = EventBus()
    # Static threshold set very high so only the anomaly path can fire.
    cfg = _anomaly_cfg(ddos={"window_seconds": 2, "pkt_rate_threshold": 100000,
                                "unique_src_entropy_min": 0.0, "enable": True})
    DDoSDetector(bus, cfg, store)

    now = 1_000_000.0
    # Train: 30 buckets of ~2 pkts each to dst-A (baseline ~2 pkts/bucket)
    for bucket_i in range(30):
        ts = now + bucket_i * 3  # > ANOMALY_BUCKET_SECONDS so each flush distinct
        for _ in range(2):
            bus.publish("net_event", _event(ts=ts, dst_ip="10.0.0.5"))

    # Attack: one bucket with 50 packets to the same dst (25x baseline).
    attack_ts = now + 30 * 3
    for _ in range(50):
        bus.publish("net_event", _event(ts=attack_ts, dst_ip="10.0.0.5"))
    # A follow-up event forces the bucket to flush.
    bus.publish("net_event", _event(ts=attack_ts + 5, dst_ip="10.0.0.99"))

    alerts = [r for r in store.recent()
                if r["detector"] == "DDoSDetector"
                and r["title"] == "Anomalous traffic spike to destination"]
    assert alerts, "anomaly detector did not fire on 25x baseline spike"
    assert alerts[0]["details"]["dst_ip"] == "10.0.0.5"
    assert alerts[0]["details"]["z_score"] >= 3.0


def test_insider_anomaly_catches_atypical_user(store):
    """A user who usually transfers ~5 KB/hour suddenly moves 50 MB in an
    hour - the hard ceiling is 1 MB here so the static rule fires too, but
    we also confirm the anomaly rule fires with a z-score."""
    bus = EventBus()
    cfg = _anomaly_cfg(insider={"baseline_hours": [0, 24],  # disable off-hours noise
                                "max_data_mb_per_hour": 9999,  # keep static quiet
                                "new_host_contact_threshold": 99999,
                                "enable": True})
    InsiderDetector(bus, cfg, store)

    # Train: 10 quiet hours for alice (~5 KB each).
    base_ts = calendar.timegm((2026, 1, 1, 0, 0, 0, 0, 1, 0))
    for hour_i in range(10):
        ts = base_ts + hour_i * 3600
        for _ in range(5):
            bus.publish("net_event", _event(ts=ts, user="alice", bytes=1024))

    # Current hour: alice moves 50 MB - way above her learned ~5 KB mean.
    attack_hour_ts = base_ts + 11 * 3600
    for _ in range(50):
        bus.publish("net_event", _event(ts=attack_hour_ts, user="alice", bytes=1024 * 1024))

    alerts = [r for r in store.recent()
                if r["title"] == "Anomalous data volume vs. user baseline"]
    assert alerts, "insider anomaly did not fire on a 10,000x deviation"
    d = alerts[0]["details"]
    assert d["user"] == "alice"
    assert d["z_score"] >= 3.0


def test_insider_anomaly_quiet_on_consistent_user(store):
    """A user with a stable bytes/hour profile should never trigger the
    anomaly alert, even across many hours."""
    bus = EventBus()
    cfg = _anomaly_cfg(insider={"baseline_hours": [0, 24],
                                "max_data_mb_per_hour": 9999,
                                "new_host_contact_threshold": 99999,
                                "enable": True})
    InsiderDetector(bus, cfg, store)

    base_ts = calendar.timegm((2026, 1, 1, 0, 0, 0, 0, 1, 0))
    for hour_i in range(24):
        ts = base_ts + hour_i * 3600
        # Small, slightly varying volume that's still well inside noise.
        for _ in range(10):
            bus.publish("net_event", _event(ts=ts, user="bob", bytes=1024 + hour_i))

    anomaly_alerts = [r for r in store.recent()
                        if r["title"] == "Anomalous data volume vs. user baseline"]
    assert anomaly_alerts == []


# --- EWMATracker.score() ------------------------------------------------------

def test_score_returns_none_during_cold_start():
    """score() must respect the cold_start gate even though it never updates state."""
    t = EWMATracker(alpha=0.2, cold_start_samples=10, min_std=0.01)
    for i in range(9):
        t.update(("k",), float(i))
    # Only 9 observations - still in cold start.
    assert t.score(("k",), 999.0) is None


def test_score_returns_none_for_unknown_key():
    t = EWMATracker(alpha=0.2, cold_start_samples=5, min_std=0.01)
    assert t.score(("never_seen",), 1.0) is None


def test_score_does_not_mutate_state():
    """Calling score() repeatedly must not change observations() or baseline()."""
    t = EWMATracker(alpha=0.2, cold_start_samples=5, min_std=0.01)
    for v in range(20):
        t.update(("k",), float(v))

    obs_before = t.observations(("k",))
    baseline_before = t.baseline(("k",))

    for _ in range(10):
        t.score(("k",), 999.0)

    assert t.observations(("k",)) == obs_before
    assert t.baseline(("k",)) == baseline_before


def test_score_agrees_with_update_zscore():
    """score(value) should return the same z as update(value) would have
    returned - i.e. scored against the pre-update baseline."""
    t_score = EWMATracker(alpha=0.2, cold_start_samples=5, min_std=0.01)
    t_update = EWMATracker(alpha=0.2, cold_start_samples=5, min_std=0.01)

    for v in [10.0, 10.5, 9.8, 10.2, 10.1, 9.9, 10.3]:
        t_score.update(("k",), v)
        t_update.update(("k",), v)

    probe = 50.0
    z_via_score = t_score.score(("k",), probe)
    z_via_update = t_update.update(("k",), probe)

    assert z_via_score is not None and z_via_update is not None
    assert abs(z_via_score - z_via_update) < 1e-9


def test_score_uses_min_std_floor():
    """On a perfectly flat baseline (var=0), score() should still produce a
    finite z-score using min_std rather than dividing by zero."""
    min_std = 5.0
    t = EWMATracker(alpha=0.1, cold_start_samples=5, min_std=min_std)
    for _ in range(20):
        t.update(("k",), 100.0)  # identical values -> var converges to ~0

    z = t.score(("k",), 100.0 + min_std)
    assert z is not None
    assert abs(z - 1.0) < 0.1  # deviation of exactly one min_std -> z ≈ 1


# --- EWMA variance formula correctness ----------------------------------------

def test_ewma_variance_converges_to_true_variance():
    """After many samples the EWMA variance estimate should converge close to
    the true variance, not be systematically biased.

    The old formula `(1-a)*(var + a*delta^2)` converged to (1-alpha)*sigma^2
    instead of sigma^2.  The fixed formula `(1-a)*var + a*delta^2` converges
    to sigma^2.
    """
    import random
    random.seed(42)
    alpha = 0.05
    true_mean = 100.0
    true_std = 10.0
    t = EWMATracker(alpha=alpha, cold_start_samples=1, min_std=0.001)

    # Feed 2000 samples from N(true_mean, true_std).
    for _ in range(2000):
        v = true_mean + random.gauss(0, true_std)
        t.update(("k",), v)

    _, est_std = t.baseline(("k",))
    # With the correct formula the steady-state variance tracks true variance.
    # Accept ±20% error as EWMA is an approximation.
    assert 0.80 * true_std <= est_std <= 1.20 * true_std, (
        f"std estimate {est_std:.2f} too far from true std {true_std}"
    )


def test_ewma_variance_old_formula_would_have_failed():
    """Demonstrate that the old formula produced a systematically lower
    variance.  We simulate the old formula and show its std estimate
    undershoots the true value by ~(1-alpha) factor."""
    import math, random
    random.seed(42)
    alpha = 0.1
    true_mean = 100.0
    true_std = 20.0

    # Simulate old formula manually.
    mean = true_mean
    var = 0.0
    for _ in range(2000):
        v = true_mean + random.gauss(0, true_std)
        delta = v - mean
        mean += alpha * delta
        var = (1 - alpha) * (var + alpha * delta * delta)   # old (buggy) formula
    old_std = math.sqrt(var)

    # Simulate new (correct) formula via the actual tracker.
    random.seed(42)
    t = EWMATracker(alpha=alpha, cold_start_samples=1, min_std=0.001)
    for _ in range(2000):
        v = true_mean + random.gauss(0, true_std)
        t.update(("k",), v)
    _, new_std = t.baseline(("k",))

    # Old formula undershoots; new formula should be closer to true_std.
    assert old_std < new_std, "old formula should produce lower std than corrected formula"
    assert abs(new_std - true_std) < abs(old_std - true_std), (
        "corrected formula should be closer to the true std than the old formula"
    )


# --- detector init smoke tests (covers forwarder= crash) ----------------------

def test_ddos_detector_init_does_not_require_forwarder(store):
    """DDoSDetector must initialize without a forwarder argument - regression
    for the TypeError that crashed on Alert(store, cfg, forwarder=...)."""
    bus = EventBus()
    det = DDoSDetector(bus, BASE_CFG, store)
    # A single publish proves the handler is wired and doesn't immediately crash.
    bus.publish("net_event", _event())


def test_insider_detector_init_does_not_require_forwarder(store):
    """InsiderDetector must initialize without a forwarder argument."""
    bus = EventBus()
    det = InsiderDetector(bus, BASE_CFG, store)
    bus.publish("net_event", _event())


def test_ddos_detector_accepts_forwarder_kwarg(store):
    """Passing forwarder= is still allowed (it's in the __init__ signature);
    it just shouldn't be forwarded to Alert() any more."""
    bus = EventBus()
    # forwarder kwarg should be silently accepted without TypeError.
    det = DDoSDetector(bus, BASE_CFG, store, forwarder=None)
    bus.publish("net_event", _event())


# --- emit() key= parameter fix ------------------------------------------------

def test_alert_emit_uses_key_parameter(store):
    """Regression: emit() calls formerly used dedupe_key= (wrong) instead of
    key= (correct).  Verify emit() works and deduplication still applies."""
    a = Alert(store, BASE_CFG)
    a.emit("Det", "high", "title", {"x": 1}, key=("host-A", "anomaly"))
    a.emit("Det", "high", "title", {"x": 2}, key=("host-A", "anomaly"))  # deduped
    a.emit("Det", "high", "title", {"x": 3}, key=("host-B", "anomaly"))  # new slot
    rows = [r for r in store.recent() if r["detector"] == "Det"]
    assert len(rows) == 2
    hosts = {r["details"]["x"] for r in rows}
    assert hosts == {1, 3}


def test_ddos_anomaly_emit_does_not_crash(store):
    """End-to-end check that the anomaly path in DDoSDetector runs without
    a TypeError on emit() (regression for dedupe_key= → key= fix)."""
    bus = EventBus()
    cfg = _anomaly_cfg(ddos={"window_seconds": 2, "pkt_rate_threshold": 100000,
                              "unique_src_entropy_min": 0.0, "enable": True})
    DDoSDetector(bus, cfg, store)

    now = 2_000_000.0
    for i in range(40):
        ts = now + i * 3
        for _ in range(2):
            bus.publish("net_event", _event(ts=ts, dst_ip="10.5.5.5"))

    attack_ts = now + 40 * 3
    for _ in range(80):
        bus.publish("net_event", _event(ts=attack_ts, dst_ip="10.5.5.5"))
    bus.publish("net_event", _event(ts=attack_ts + 5, dst_ip="10.5.5.6"))

    alerts = [r for r in store.recent()
              if r["title"] == "Anomalous traffic spike to destination"]
    assert alerts, "anomaly emit path did not fire"


def test_insider_anomaly_emit_does_not_crash(store):
    """End-to-end check that the anomaly path in InsiderDetector runs without
    a TypeError on emit() (regression for dedupe_key= → key= fix)."""
    bus = EventBus()
    cfg = _anomaly_cfg(insider={"baseline_hours": [0, 24],
                                "max_data_mb_per_hour": 9999,
                                "new_host_contact_threshold": 99999,
                                "enable": True})
    InsiderDetector(bus, cfg, store)

    base_ts = calendar.timegm((2026, 6, 1, 0, 0, 0, 0, 1, 0))
    for hour_i in range(8):
        ts = base_ts + hour_i * 3600
        for _ in range(5):
            bus.publish("net_event", _event(ts=ts, user="eve", bytes=512))

    attack_ts = base_ts + 9 * 3600
    for _ in range(100):
        bus.publish("net_event", _event(ts=attack_ts, user="eve", bytes=1024 * 1024))

    alerts = [r for r in store.recent()
              if r["title"] == "Anomalous data volume vs. user baseline"]
    assert alerts, "insider anomaly emit path did not fire"