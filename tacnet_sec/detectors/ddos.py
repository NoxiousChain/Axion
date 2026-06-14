"""
DDoS / flood detector.

Two independent triggers, both honored:

  * Static threshold (existing behavior): packet rate over the configured
    window exceeds `ddos.pkt_rate_threshold`, OR source-IP entropy is low
    while the rate is elevated.
  * Learned anomaly: per-destination packet rate deviates from that dst's
    EWMA baseline by more than `anomaly.z_threshold` sigmas. Catches slow-
    burn floods that never trip the absolute threshold but are wildly
    abnormal for the target.

Dedupe key is the top destination so one attack = one alert per cooldown.
"""

from __future__ import annotations

import os
from collections import Counter, defaultdict, deque
from time import time
from typing import Dict

from ..core.anomaly import EWMATracker
from ..core.utils import shannon_entropy
from ..responders.actions import Alert

# How long each anomaly bucket is. Shorter = more reactive, noisier.
ANOMALY_BUCKET_SECONDS = 2


class DDoSDetector:
    def __init__(self, bus, cfg, store, forwarder=None, siem=None):
        self.bus = bus
        self.cfg = cfg
        self.store = store
        self.alerter = Alert(store, cfg, forwarder=forwarder, siem=siem)
        self.window = deque(maxlen=20000)

        ano = cfg.get("anomaly", {}) or {}
        self.anomaly_enabled = bool(ano.get("enable", True))
        self.z_threshold = float(ano.get("z_threshold", 3.0))

        baseline_dir = ano.get("baseline_dir")
        baseline_path = os.path.join(baseline_dir, "ddos.json") if baseline_dir else None

        self.tracker = EWMATracker(
            alpha=float(ano.get("alpha", 0.1)),
            cold_start_samples=int(ano.get("cold_start_samples", 20)),
            min_std=float(ano.get("min_std_ddos", 2.0)),
            baseline_path=baseline_path,
        )
        # per-dst counts in the current bucket
        self._bucket_counts: Dict[str, int] = defaultdict(int)
        self._bucket_start: float = 0.0

        bus.subscribe("net_event", self.on_event)

    # ------------------------------------------------------------------

    def on_event(self, e):
        ts = float(e.get("ts") or time())
        self._update_anomaly_buckets(ts, e)
        self._check_static_threshold(ts, e)

    # --- anomaly path -------------------------------------------------

    def _update_anomaly_buckets(self, ts: float, e: dict) -> None:
        if not self.anomaly_enabled:
            return
        if self._bucket_start == 0.0:
            self._bucket_start = ts

        # If we've rolled into a new bucket, flush the old one through EWMA.
        if ts - self._bucket_start >= ANOMALY_BUCKET_SECONDS:
            self._flush_bucket()
            self._bucket_start = ts

        dst = e.get("dst_ip") or ""
        if dst:
            self._bucket_counts[dst] += 1

    def _flush_bucket(self) -> None:
        for dst, count in self._bucket_counts.items():
            z = self.tracker.update(("ddos", dst), float(count))
            if z is not None and z >= self.z_threshold:
                baseline = self.tracker.baseline(("ddos", dst))
                mean, std = baseline if baseline else (0.0, 0.0)
                self.alerter.emit(
                    "DDoSDetector",
                    "high",
                    "Anomalous traffic spike to destination",
                    {
                        "dst_ip": dst,
                        "pkts_in_window": count,
                        "window_seconds": ANOMALY_BUCKET_SECONDS,
                        "baseline_mean": round(mean, 2),
                        "baseline_std": round(std, 2),
                        "z_score": round(z, 2),
                    },
                    key=(dst, "anomaly"),
                )
        self._bucket_counts.clear()

    # --- static threshold path (unchanged behavior) -------------------

    def _check_static_threshold(self, ts: float, e: dict) -> None:
        ddos_cfg = self.cfg.get("ddos", {}) or {}
        window_s = float(ddos_cfg.get("window_seconds", 8))
        rate_thresh = float(ddos_cfg.get("pkt_rate_threshold", 120))
        src_ent_min = float(ddos_cfg.get("unique_src_entropy_min", 2.3))

        self.window.append(e)
        recent = [x for x in self.window if ts - x["ts"] <= window_s]
        if len(recent) < 20:
            return

        pkt_rate = len(recent) / max(1.0, window_s)
        src_ips = [x["src_ip"] for x in recent]
        dst_ports = [str(x["dst_port"]) for x in recent]
        ent_src = shannon_entropy(src_ips)
        ent_dstp = shannon_entropy(dst_ports)

        rate_breach = pkt_rate > rate_thresh
        entropy_breach = ent_src < src_ent_min and pkt_rate > (rate_thresh * 0.3)

        if rate_breach or entropy_breach:
            top_dst = Counter(x["dst_ip"] for x in recent).most_common(1)[0][0]
            details = {
                "pkt_rate": round(pkt_rate, 1),
                "entropy_src": round(ent_src, 3),
                "entropy_dst_port": round(ent_dstp, 3),
                "samples": len(recent),
                "top_dst": top_dst,
            }
            self.alerter.emit(
                "DDoSDetector",
                "high",
                "Potential DDoS/flood detected",
                details,
                key=(top_dst,),
            )