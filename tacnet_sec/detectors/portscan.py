"""
Port scan detector (H5-a).

Tracks distinct destination ports contacted by each source IP within a rolling
time window. A single source that touches more than `port_threshold` distinct
ports inside `window_seconds` is flagged regardless of packet volume — this
catches low-and-slow Nmap scans that stay well under the DDoS thresholds.

Deduplicate key is (src_ip, "portscan") so one alert fires per cooldown window
per source, rather than per port.
"""

from __future__ import annotations

import threading
import time
from collections import defaultdict
from typing import Dict, List, Tuple

from ..responders.actions import Alert


class PortScanDetector:
    def __init__(self, bus, cfg, store, forwarder=None, siem=None):
        self.bus = bus
        self.cfg = cfg
        self.store = store
        self.alerter = Alert(store, cfg, forwarder=forwarder, siem=siem)

        ps_cfg = cfg.get("portscan", {}) or {}
        self.window_seconds = float(ps_cfg.get("window_seconds", 10.0))
        self.port_threshold = int(ps_cfg.get("port_threshold", 15))

        # {src_ip: [(ts, dst_port), ...]}
        self._contacts: Dict[str, List[Tuple[float, int]]] = defaultdict(list)
        self._lock = threading.Lock()

        bus.subscribe("net_event", self.on_event)

    def on_event(self, e):
        src = e.get("src_ip") or ""
        dst_port = e.get("dst_port") or 0
        ts = float(e.get("ts") or time.time())

        if not src or not dst_port:
            return

        cutoff = ts - self.window_seconds
        with self._lock:
            contacts = self._contacts[src]
            # Slide the window
            contacts = [(t, p) for t, p in contacts if t > cutoff]
            contacts.append((ts, int(dst_port)))
            self._contacts[src] = contacts

            distinct_ports = {p for _, p in contacts}
            if len(distinct_ports) >= self.port_threshold:
                self.alerter.emit(
                    "PortScanDetector",
                    "high",
                    "Port scan detected",
                    {
                        "src_ip": src,
                        "port_count": len(distinct_ports),
                        "window_seconds": self.window_seconds,
                    },
                    key=(src, "portscan"),
                )
