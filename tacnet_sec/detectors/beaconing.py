"""
C2 beaconing detector (H5-b).

Tracks outbound connection timestamps per (src_ip, dst_ip) pair within a
rolling window. When a pair accumulates enough observations, the detector
computes the coefficient of variation (std / mean) of inter-connection
intervals. A very low CV — regular, clock-like spacing — is a strong indicator
of automated C2 beaconing regardless of payload size or protocol.

Config:
  beaconing.min_observations        (int, default 5)   — samples before scoring
  beaconing.cv_threshold            (float, default 0.20) — flag when CV < this
  beaconing.max_beacon_interval_seconds (int, default 300) — ignore slow beacons
  beaconing.window_seconds          (int, default 600)  — rolling observation window
"""

from __future__ import annotations

import math
import threading
import time
from collections import defaultdict
from typing import Dict, List

from ..responders.actions import Alert


class BeaconingDetector:
    def __init__(self, bus, cfg, store, forwarder=None, siem=None):
        self.bus = bus
        self.cfg = cfg
        self.store = store
        self.alerter = Alert(store, cfg, forwarder=forwarder, siem=siem)

        bc_cfg = cfg.get("beaconing", {}) or {}
        self.min_observations = int(bc_cfg.get("min_observations", 5))
        self.cv_threshold = float(bc_cfg.get("cv_threshold", 0.20))
        self.max_interval = float(bc_cfg.get("max_beacon_interval_seconds", 300))
        self.window_seconds = float(bc_cfg.get("window_seconds", 600))

        # {(src_ip, dst_ip): [ts, ...]}
        self._times: Dict[tuple, List[float]] = defaultdict(list)
        self._lock = threading.Lock()

        bus.subscribe("net_event", self.on_event)

    def on_event(self, e):
        src = e.get("src_ip") or ""
        dst = e.get("dst_ip") or ""
        ts = float(e.get("ts") or time.time())

        if not src or not dst or src == dst:
            return

        pair = (src, dst)
        cutoff = ts - self.window_seconds

        with self._lock:
            times = self._times[pair]
            times = [t for t in times if t > cutoff]
            times.append(ts)
            self._times[pair] = times

            if len(times) < self.min_observations + 1:
                return

            intervals = [times[i + 1] - times[i] for i in range(len(times) - 1)]
            mean = sum(intervals) / len(intervals)

            if mean <= 0 or mean > self.max_interval:
                return

            variance = sum((iv - mean) ** 2 for iv in intervals) / len(intervals)
            cv = math.sqrt(variance) / mean

            if cv < self.cv_threshold:
                self.alerter.emit(
                    "BeaconingDetector",
                    "high",
                    "Possible C2 beaconing",
                    {
                        "src_ip": src,
                        "dst_ip": dst,
                        "interval_mean_s": round(mean, 1),
                        "interval_cv": round(cv, 3),
                        "observations": len(times),
                    },
                    key=(src, dst, "beacon"),
                )
