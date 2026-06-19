"""
ARP spoofing detector (H5-d).

Listens for "arp_event" bus events (published by the capture layer when it
observes ARP traffic). Maintains a table of known (IP → MAC) mappings. When
an IP begins advertising from a different MAC address, a critical alert is
raised — this is the canonical indicator of on-segment ARP poisoning.

Expected event fields:
  ip  (str)  — the IP address being announced
  mac (str)  — the MAC address claiming that IP
  ts  (float)

The detector also accepts src_ip / src_mac field names for compatibility with
capture layers that use those names for ARP events.

Config:
  arp.enable  (bool, default true)
"""

from __future__ import annotations

import threading
import time
from typing import Dict

from ..responders.actions import Alert


class ARPSpoofDetector:
    def __init__(self, bus, cfg, store, forwarder=None, siem=None):
        self.bus = bus
        self.cfg = cfg
        self.store = store
        self.alerter = Alert(store, cfg, forwarder=forwarder, siem=siem)

        # {ip: mac}
        self._ip_mac: Dict[str, str] = {}
        self._lock = threading.Lock()

        bus.subscribe("arp_event", self.on_event)

    def on_event(self, e):
        ip = e.get("ip") or e.get("src_ip") or ""
        mac = e.get("mac") or e.get("src_mac") or ""
        ts = float(e.get("ts") or time.time())  # noqa: F841 — reserved for future TTL

        if not ip or not mac:
            return

        with self._lock:
            known = self._ip_mac.get(ip)
            if known is None:
                self._ip_mac[ip] = mac
                return

            if known != mac:
                self.alerter.emit(
                    "ARPSpoofDetector",
                    "critical",
                    "ARP spoofing detected",
                    {
                        "ip": ip,
                        "legitimate_mac": known,
                        "spoofed_mac": mac,
                    },
                    key=(ip, "arp_spoof"),
                )
                # Update to new MAC so subsequent changes are also caught.
                self._ip_mac[ip] = mac
