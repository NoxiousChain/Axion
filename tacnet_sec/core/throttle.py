"""
Alert dedupe / rate-limiter.

A packet flood or a user who stays over quota for an hour should not produce
thousands of duplicate alerts. AlertThrottler collapses identical findings
into a single alert per cooldown window and returns an aggregate count when
the window closes so the dashboard can show "87 hits, suppressed".
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass
from typing import Dict, Optional, Tuple

Key = Tuple[str, ...]


@dataclass
class _Slot:
    first_seen: float
    count: int


class AlertThrottler:
    def __init__(self, cooldown_seconds: float = 30.0):
        self.cooldown = float(cooldown_seconds)
        self._slots: Dict[Key, _Slot] = {}
        self._lock = threading.Lock()

    def should_emit(self, *key_parts: str) -> Tuple[bool, int]:
        """Decide whether to emit an alert for this key.

        Returns (emit, suppressed_count). When `emit` is True the caller should
        fire the alert; `suppressed_count` is the number of repeats collapsed
        into this emission since the last one (0 the first time).
        """
        key = tuple(str(p) for p in key_parts)
        now = time.time()
        with self._lock:
            slot = self._slots.get(key)
            if slot is None or (now - slot.first_seen) >= self.cooldown:
                suppressed = slot.count - 1 if slot and slot.count > 1 else 0
                self._slots[key] = _Slot(first_seen=now, count=1)
                return True, suppressed
            slot.count += 1
            return False, 0

    def snapshot(self) -> Dict[Key, int]:
        with self._lock:
            return {k: v.count for k, v in self._slots.items()}