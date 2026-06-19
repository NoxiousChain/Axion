"""
Lateral movement detector (H5-c).

Tracks which node IDs have recently reported network activity from each source
IP. When the same source IP appears on two or more distinct nodes within
`window_seconds`, it is flagged as possible lateral movement.

In simulation mode the agent uses its own node_id for every event. In a
real multi-sensor deployment, events carry the originating sensor's node_id,
so the detector correlates across sensor fields of view.

Config:
  lateral_movement.window_seconds  (int, default 300)
  lateral_movement.node_threshold  (int, default 2)
"""

from __future__ import annotations

import threading
import time
from collections import defaultdict
from typing import Dict

from ..responders.actions import Alert


class LateralMovementDetector:
    def __init__(self, bus, cfg, store, forwarder=None, siem=None):
        self.bus = bus
        self.cfg = cfg
        self.store = store
        self.alerter = Alert(store, cfg, forwarder=forwarder, siem=siem)

        lm_cfg = cfg.get("lateral_movement", {}) or {}
        self.window_seconds = float(lm_cfg.get("window_seconds", 300))
        self.node_threshold = int(lm_cfg.get("node_threshold", 2))

        # {src_ip: {node_id: last_seen_ts}}
        self._src_nodes: Dict[str, Dict[str, float]] = defaultdict(dict)
        self._lock = threading.Lock()

        bus.subscribe("net_event", self.on_event)

    def on_event(self, e):
        src = e.get("src_ip") or ""
        # Prefer the event's node_id; fall back to the agent's own node_id.
        node_id = (
            e.get("node_id")
            or self.cfg.get("agent", {}).get("node_id")
            or ""
        )
        ts = float(e.get("ts") or time.time())

        if not src or not node_id:
            return

        cutoff = ts - self.window_seconds

        with self._lock:
            nodes = self._src_nodes[src]
            nodes[node_id] = ts
            # Prune stale entries
            self._src_nodes[src] = {n: t for n, t in nodes.items() if t > cutoff}
            active_nodes = self._src_nodes[src]

            if len(active_nodes) >= self.node_threshold:
                self.alerter.emit(
                    "LateralMovementDetector",
                    "critical",
                    "Possible lateral movement",
                    {
                        "src_ip": src,
                        "nodes": sorted(active_nodes.keys()),
                        "node_count": len(active_nodes),
                        "window_seconds": self.window_seconds,
                    },
                    key=(src, "lateral"),
                )
