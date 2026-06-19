"""
Tests for the four new detectors added in H5 (MITRE ATT&CK TTP coverage):
  - PortScanDetector   (H5-a)
  - BeaconingDetector  (H5-b)
  - LateralMovementDetector (H5-c)
  - ARPSpoofDetector   (H5-d)

Run from the project root:

    python -m pytest tacnet_sec/tests/test_h5_detectors.py -v
"""

from __future__ import annotations

import time

import pytest

from tacnet_sec.core.bus import EventBus
from tacnet_sec.core.store import AlertStore
from tacnet_sec.core.throttle import AlertThrottler
from tacnet_sec.detectors.portscan import PortScanDetector
from tacnet_sec.detectors.beaconing import BeaconingDetector
from tacnet_sec.detectors.lateral import LateralMovementDetector
from tacnet_sec.detectors.arp import ARPSpoofDetector
from tacnet_sec.responders.actions import Alert


BASE_CFG = {
    "agent": {"node_id": "test-node", "location": "lab", "forward_alerts": False},
    "portscan": {
        "window_seconds": 10.0,
        "port_threshold": 5,   # low threshold for fast tests
    },
    "beaconing": {
        "min_observations": 5,
        "cv_threshold": 0.20,
        "max_beacon_interval_seconds": 300,
        "window_seconds": 600,
    },
    "lateral_movement": {
        "window_seconds": 300,
        "node_threshold": 2,
    },
    "arp": {
        "enable": True,
    },
}


@pytest.fixture
def store(tmp_path):
    s = AlertStore(str(tmp_path / "alerts.sqlite"))
    yield s
    s.close()


@pytest.fixture(autouse=True)
def _reset_throttler():
    Alert._default_throttler = AlertThrottler(cooldown_seconds=30.0)
    yield


def _net_event(**overrides):
    ev = {
        "ts": time.time(),
        "src_ip": "10.0.0.1",
        "dst_ip": "10.0.0.2",
        "dst_port": 80,
        "node_id": "test-node",
    }
    ev.update(overrides)
    return ev


# ─── PortScanDetector ────────────────────────────────────────────────────────

def test_portscan_fires_on_threshold(store):
    """Source touching >= port_threshold distinct ports within window → alert."""
    bus = EventBus()
    PortScanDetector(bus, BASE_CFG, store)
    now = time.time()
    for port in range(1, 6):   # 5 distinct ports == threshold
        bus.publish("net_event", _net_event(ts=now, src_ip="192.0.2.10", dst_port=port))

    rows = [r for r in store.recent() if r["detector"] == "PortScanDetector"]
    assert rows, "PortScanDetector did not fire at threshold"
    assert rows[0]["severity"] == "high"
    assert rows[0]["details"]["src_ip"] == "192.0.2.10"
    assert rows[0]["details"]["port_count"] >= 5


def test_portscan_no_fire_below_threshold(store):
    """Fewer than port_threshold distinct ports → no alert."""
    bus = EventBus()
    PortScanDetector(bus, BASE_CFG, store)
    now = time.time()
    for port in range(1, 5):   # only 4 distinct ports < threshold of 5
        bus.publish("net_event", _net_event(ts=now, src_ip="192.0.2.20", dst_port=port))

    rows = [r for r in store.recent() if r["detector"] == "PortScanDetector"]
    assert not rows, "PortScanDetector should not fire below threshold"


def test_portscan_deduplicates_same_source(store):
    """Crossing threshold multiple times for the same source → one alert (throttle)."""
    bus = EventBus()
    PortScanDetector(bus, BASE_CFG, store)
    now = time.time()
    for port in range(1, 20):   # 19 distinct ports
        bus.publish("net_event", _net_event(ts=now, src_ip="192.0.2.30", dst_port=port))

    rows = [r for r in store.recent() if r["detector"] == "PortScanDetector"]
    assert len(rows) == 1, "Expected exactly one alert per source/cooldown"


def test_portscan_repeated_port_not_double_counted(store):
    """Same port sent many times should not inflate distinct-port count."""
    bus = EventBus()
    PortScanDetector(bus, BASE_CFG, store)
    now = time.time()
    for _ in range(20):
        bus.publish("net_event", _net_event(ts=now, src_ip="192.0.2.40", dst_port=443))

    rows = [r for r in store.recent() if r["detector"] == "PortScanDetector"]
    assert not rows, "Repeated hits on a single port must not trigger portscan alert"


def test_portscan_separate_sources_independent(store):
    """Two source IPs each below threshold independently should not fire."""
    bus = EventBus()
    PortScanDetector(bus, BASE_CFG, store)
    now = time.time()
    # Each source touches only 3 ports (< 5 threshold)
    for port in range(1, 4):
        bus.publish("net_event", _net_event(ts=now, src_ip="192.0.2.50", dst_port=port))
        bus.publish("net_event", _net_event(ts=now, src_ip="192.0.2.51", dst_port=port))

    rows = [r for r in store.recent() if r["detector"] == "PortScanDetector"]
    assert not rows


def test_portscan_window_eviction(store):
    """Ports outside the rolling window are evicted; count should drop below threshold."""
    bus = EventBus()
    PortScanDetector(bus, BASE_CFG, store)
    now = 1_000_000.0
    window = BASE_CFG["portscan"]["window_seconds"]

    # 4 ports far in the past (outside window)
    for port in range(1, 5):
        bus.publish("net_event", _net_event(
            ts=now - window - 1, src_ip="192.0.2.60", dst_port=port))

    # 1 new port inside the window → total in-window = 1 < threshold
    bus.publish("net_event", _net_event(ts=now, src_ip="192.0.2.60", dst_port=999))

    rows = [r for r in store.recent() if r["detector"] == "PortScanDetector"]
    assert not rows, "Evicted (old) ports should not count toward threshold"


def test_portscan_missing_fields_ignored(store):
    """Events without src_ip or dst_port must not crash the detector."""
    bus = EventBus()
    PortScanDetector(bus, BASE_CFG, store)
    bus.publish("net_event", {"ts": time.time()})              # no src_ip, no dst_port
    bus.publish("net_event", {"ts": time.time(), "src_ip": "1.2.3.4"})  # no dst_port
    # No exception → pass; no alert either
    rows = [r for r in store.recent() if r["detector"] == "PortScanDetector"]
    assert not rows


# ─── BeaconingDetector ───────────────────────────────────────────────────────

def test_beaconing_fires_on_regular_intervals(store):
    """Very regular (clock-like) inter-connection intervals → CV near 0 → alert."""
    bus = EventBus()
    BeaconingDetector(bus, BASE_CFG, store)
    base = 1_000_000.0
    # 7 timestamps at exactly 10 s apart → 6 intervals, all equal → CV = 0
    for i in range(7):
        bus.publish("net_event", _net_event(
            ts=base + i * 10, src_ip="10.1.0.5", dst_ip="198.51.100.1"))

    rows = [r for r in store.recent() if r["detector"] == "BeaconingDetector"]
    assert rows, "BeaconingDetector did not fire on perfectly regular beaconing"
    assert rows[0]["severity"] == "high"
    d = rows[0]["details"]
    assert d["src_ip"] == "10.1.0.5"
    assert d["dst_ip"] == "198.51.100.1"
    assert d["interval_cv"] < 0.20


def test_beaconing_no_fire_on_irregular_traffic(store):
    """Irregular intervals produce a high CV → no alert."""
    bus = EventBus()
    BeaconingDetector(bus, BASE_CFG, store)
    base = 1_000_000.0
    # Highly irregular gaps: 1, 50, 3, 80, 2, 70 seconds
    gaps = [0, 1, 51, 54, 134, 136, 206]
    for offset in gaps:
        bus.publish("net_event", _net_event(
            ts=base + offset, src_ip="10.1.0.6", dst_ip="198.51.100.2"))

    rows = [r for r in store.recent() if r["detector"] == "BeaconingDetector"]
    assert not rows, "Irregular traffic should not trigger beaconing alert"


def test_beaconing_needs_min_observations(store):
    """Fewer than min_observations connections → no scoring, no alert."""
    bus = EventBus()
    BeaconingDetector(bus, BASE_CFG, store)
    base = 1_000_000.0
    # min_observations=5, send only 4 timestamps → 3 intervals, not enough
    for i in range(4):
        bus.publish("net_event", _net_event(
            ts=base + i * 10, src_ip="10.1.0.7", dst_ip="198.51.100.3"))

    rows = [r for r in store.recent() if r["detector"] == "BeaconingDetector"]
    assert not rows


def test_beaconing_ignores_slow_beacons(store):
    """Mean interval > max_beacon_interval_seconds → not a beacon pattern."""
    bus = EventBus()
    BeaconingDetector(bus, BASE_CFG, store)
    base = 1_000_000.0
    max_iv = BASE_CFG["beaconing"]["max_beacon_interval_seconds"]
    # Very slow regular intervals (> max threshold)
    for i in range(7):
        bus.publish("net_event", _net_event(
            ts=base + i * (max_iv + 50),
            src_ip="10.1.0.8", dst_ip="198.51.100.4"))

    rows = [r for r in store.recent() if r["detector"] == "BeaconingDetector"]
    assert not rows


def test_beaconing_ignores_loopback(store):
    """src_ip == dst_ip events should be silently skipped."""
    bus = EventBus()
    BeaconingDetector(bus, BASE_CFG, store)
    base = 1_000_000.0
    for i in range(10):
        bus.publish("net_event", _net_event(
            ts=base + i * 10, src_ip="10.0.0.1", dst_ip="10.0.0.1"))

    rows = [r for r in store.recent() if r["detector"] == "BeaconingDetector"]
    assert not rows


def test_beaconing_separate_pairs_independent(store):
    """Each (src, dst) pair has its own state; a second pair crossing the
    threshold independently should also fire."""
    bus = EventBus()
    BeaconingDetector(bus, BASE_CFG, store)
    base = 1_000_000.0

    for i in range(7):
        bus.publish("net_event", _net_event(
            ts=base + i * 10, src_ip="10.2.0.1", dst_ip="203.0.113.10"))
        bus.publish("net_event", _net_event(
            ts=base + i * 10, src_ip="10.2.0.2", dst_ip="203.0.113.11"))

    rows = [r for r in store.recent() if r["detector"] == "BeaconingDetector"]
    pairs = {(r["details"]["src_ip"], r["details"]["dst_ip"]) for r in rows}
    assert ("10.2.0.1", "203.0.113.10") in pairs
    assert ("10.2.0.2", "203.0.113.11") in pairs


# ─── LateralMovementDetector ─────────────────────────────────────────────────

def test_lateral_movement_fires_on_two_nodes(store):
    """Same source IP seen on two distinct nodes → alert."""
    bus = EventBus()
    LateralMovementDetector(bus, BASE_CFG, store)
    now = time.time()
    bus.publish("net_event", _net_event(ts=now, src_ip="10.5.0.1", node_id="sensor-A"))
    bus.publish("net_event", _net_event(ts=now, src_ip="10.5.0.1", node_id="sensor-B"))

    rows = [r for r in store.recent() if r["detector"] == "LateralMovementDetector"]
    assert rows, "LateralMovementDetector did not fire"
    assert rows[0]["severity"] == "critical"
    d = rows[0]["details"]
    assert d["src_ip"] == "10.5.0.1"
    assert d["node_count"] >= 2
    assert "sensor-A" in d["nodes"]
    assert "sensor-B" in d["nodes"]


def test_lateral_movement_no_fire_single_node(store):
    """Same source IP appearing many times on one node → no alert."""
    bus = EventBus()
    LateralMovementDetector(bus, BASE_CFG, store)
    now = time.time()
    for _ in range(10):
        bus.publish("net_event", _net_event(ts=now, src_ip="10.5.0.2", node_id="sensor-A"))

    rows = [r for r in store.recent() if r["detector"] == "LateralMovementDetector"]
    assert not rows


def test_lateral_movement_deduplicates(store):
    """Multiple crossings of threshold for same source → one alert (throttle)."""
    bus = EventBus()
    LateralMovementDetector(bus, BASE_CFG, store)
    now = time.time()
    for _ in range(5):
        bus.publish("net_event", _net_event(ts=now, src_ip="10.5.0.3", node_id="node-X"))
        bus.publish("net_event", _net_event(ts=now, src_ip="10.5.0.3", node_id="node-Y"))

    rows = [r for r in store.recent() if r["detector"] == "LateralMovementDetector"]
    assert len(rows) == 1, "Expected single deduplicated alert"


def test_lateral_movement_window_eviction(store):
    """A node observation that falls outside the window should be evicted."""
    bus = EventBus()
    LateralMovementDetector(bus, BASE_CFG, store)
    window = BASE_CFG["lateral_movement"]["window_seconds"]
    now = 1_000_000.0

    # Old observation on sensor-A (outside window)
    bus.publish("net_event", _net_event(
        ts=now - window - 1, src_ip="10.5.0.4", node_id="sensor-A"))
    # Recent observation on sensor-A only (inside window)
    bus.publish("net_event", _net_event(
        ts=now, src_ip="10.5.0.4", node_id="sensor-A"))

    rows = [r for r in store.recent() if r["detector"] == "LateralMovementDetector"]
    assert not rows, "Evicted node should not count toward threshold"


def test_lateral_movement_missing_fields_ignored(store):
    """Events without src_ip or node_id must be silently skipped."""
    bus = EventBus()
    LateralMovementDetector(bus, BASE_CFG, store)
    bus.publish("net_event", {"ts": time.time()})
    bus.publish("net_event", {"ts": time.time(), "src_ip": "1.2.3.4"})
    rows = [r for r in store.recent() if r["detector"] == "LateralMovementDetector"]
    assert not rows


def test_lateral_movement_fallback_to_cfg_node_id(store):
    """When the event has no node_id, the detector falls back to cfg node_id."""
    bus = EventBus()
    LateralMovementDetector(bus, BASE_CFG, store)
    now = time.time()
    # First event has explicit node_id; second falls back to cfg node_id ("test-node")
    bus.publish("net_event", _net_event(ts=now, src_ip="10.5.0.5", node_id="sensor-Z"))
    # Publish without node_id — fallback to BASE_CFG["agent"]["node_id"] = "test-node"
    ev = {"ts": now, "src_ip": "10.5.0.5", "dst_ip": "10.0.0.2", "dst_port": 80}
    bus.publish("net_event", ev)

    rows = [r for r in store.recent() if r["detector"] == "LateralMovementDetector"]
    assert rows, "Fallback node_id should allow lateral movement detection"


# ─── ARPSpoofDetector ────────────────────────────────────────────────────────

def _arp_event(ip, mac, ts=None):
    return {"ip": ip, "mac": mac, "ts": ts or time.time()}


def test_arp_spoof_detected(store):
    """IP seen with one MAC, then a different MAC → alert fires."""
    bus = EventBus()
    ARPSpoofDetector(bus, BASE_CFG, store)

    bus.publish("arp_event", _arp_event("192.168.1.1", "aa:bb:cc:dd:ee:01"))
    bus.publish("arp_event", _arp_event("192.168.1.1", "ff:ff:ff:ff:ff:01"))

    rows = [r for r in store.recent() if r["detector"] == "ARPSpoofDetector"]
    assert rows, "ARPSpoofDetector did not fire on MAC change"
    assert rows[0]["severity"] == "critical"
    d = rows[0]["details"]
    assert d["ip"] == "192.168.1.1"
    assert d["legitimate_mac"] == "aa:bb:cc:dd:ee:01"
    assert d["spoofed_mac"] == "ff:ff:ff:ff:ff:01"


def test_arp_no_alert_for_new_ip(store):
    """First observation of an IP/MAC pair → just record, no alert."""
    bus = EventBus()
    ARPSpoofDetector(bus, BASE_CFG, store)
    bus.publish("arp_event", _arp_event("10.0.0.1", "de:ad:be:ef:00:01"))

    rows = [r for r in store.recent() if r["detector"] == "ARPSpoofDetector"]
    assert not rows


def test_arp_consistent_mac_no_alert(store):
    """Same IP/MAC seen repeatedly → no alert."""
    bus = EventBus()
    ARPSpoofDetector(bus, BASE_CFG, store)
    for _ in range(10):
        bus.publish("arp_event", _arp_event("10.0.0.2", "11:22:33:44:55:66"))

    rows = [r for r in store.recent() if r["detector"] == "ARPSpoofDetector"]
    assert not rows


def test_arp_fires_once_per_change(store):
    """Each distinct MAC change fires its own alert (no cooldown between changes)."""
    bus = EventBus()
    ARPSpoofDetector(bus, BASE_CFG, store)

    # Fresh throttler with 0-second cooldown so every change gets through
    Alert._default_throttler = AlertThrottler(cooldown_seconds=0.0)

    bus.publish("arp_event", _arp_event("10.0.0.3", "aa:00:00:00:00:01"))
    bus.publish("arp_event", _arp_event("10.0.0.3", "bb:00:00:00:00:02"))  # change 1
    bus.publish("arp_event", _arp_event("10.0.0.3", "cc:00:00:00:00:03"))  # change 2

    rows = [r for r in store.recent() if r["detector"] == "ARPSpoofDetector"]
    assert len(rows) == 2, f"Expected 2 alerts for 2 MAC changes, got {len(rows)}"


def test_arp_accepts_src_ip_src_mac_fields(store):
    """Detector supports src_ip/src_mac field names for capture-layer compatibility."""
    bus = EventBus()
    ARPSpoofDetector(bus, BASE_CFG, store)

    bus.publish("arp_event", {"src_ip": "172.16.0.1", "src_mac": "01:02:03:04:05:06", "ts": time.time()})
    bus.publish("arp_event", {"src_ip": "172.16.0.1", "src_mac": "99:88:77:66:55:44", "ts": time.time()})

    rows = [r for r in store.recent() if r["detector"] == "ARPSpoofDetector"]
    assert rows, "ARPSpoofDetector should accept src_ip/src_mac field names"


def test_arp_missing_fields_ignored(store):
    """Events without ip/mac fields must not crash the detector."""
    bus = EventBus()
    ARPSpoofDetector(bus, BASE_CFG, store)
    bus.publish("arp_event", {"ts": time.time()})
    bus.publish("arp_event", {"ip": "1.2.3.4", "ts": time.time()})  # no mac
    rows = [r for r in store.recent() if r["detector"] == "ARPSpoofDetector"]
    assert not rows


def test_arp_multiple_ips_independent(store):
    """Each IP has its own MAC state; a spoof on one IP must not affect another."""
    bus = EventBus()
    ARPSpoofDetector(bus, BASE_CFG, store)

    # Two IPs, each with stable MACs
    bus.publish("arp_event", _arp_event("10.10.0.1", "a1:a1:a1:a1:a1:a1"))
    bus.publish("arp_event", _arp_event("10.10.0.2", "b2:b2:b2:b2:b2:b2"))

    # Only the first IP gets spoofed
    bus.publish("arp_event", _arp_event("10.10.0.1", "de:ad:00:00:00:01"))

    rows = [r for r in store.recent() if r["detector"] == "ARPSpoofDetector"]
    assert len(rows) == 1
    assert rows[0]["details"]["ip"] == "10.10.0.1"
