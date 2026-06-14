"""
Per-entity EWMA anomaly tracker.

Maintains an exponentially-weighted mean and variance for each key (dst_ip,
user, device, whatever the caller chooses) in O(1) memory per key. Update()
returns a z-score the caller can compare to a config threshold.

Why EWMA and not a sliding window?
  * Constant memory per entity - important when there are thousands of dsts.
  * Recency weighting falls out naturally: older samples fade without manual
    bookkeeping.
  * Closed-form update; trivially unit-testable.

Cold start: we refuse to emit a z-score until we've seen `cold_start_samples`
observations for that key, because a baseline of one sample will flag every
subsequent sample as a wild anomaly.

Baseline persistence: pass `baseline_path` to automatically save/load state
from a JSON file so baselines survive agent restarts. State is saved every
`save_interval` updates (default 100) and on explicit calls to save().

References: Welford-style running moments adapted for EWMA.
"""

from __future__ import annotations

import json
import math
import pathlib
import threading
from dataclasses import dataclass
from typing import Dict, Optional, Tuple


@dataclass
class _Stats:
    count: int = 0
    mean: float = 0.0
    var: float = 0.0  # EWMA of squared deviation

    def std(self) -> float:
        return math.sqrt(max(self.var, 0.0))


class EWMATracker:
    """Keyed EWMA tracker returning z-scores after a warm-up period.

    Args:
        alpha: smoothing factor in (0, 1]. Higher = more reactive, less stable.
               0.1 means ~10 samples of effective history.
        cold_start_samples: minimum observations before update() returns a
               z-score. Before that, update() returns None and just trains.
        min_std: floor on the std used in z-score to avoid divide-by-near-zero
               when a baseline is perfectly flat (e.g. a dst that always sees
               exactly 1 pkt/sec - one extra packet shouldn't read as 9 sigma).
        baseline_path: optional path to a JSON file for persisting baselines
               across restarts. Auto-loaded on init, auto-saved every
               `save_interval` updates. Pass None to disable persistence.
        save_interval: number of update() calls between auto-saves.
    """

    def __init__(
        self,
        alpha: float = 0.1,
        cold_start_samples: int = 20,
        min_std: float = 1.0,
        baseline_path: Optional[str] = None,
        save_interval: int = 100,
    ):
        if not 0 < alpha <= 1:
            raise ValueError("alpha must be in (0, 1]")
        self.alpha = float(alpha)
        self.cold_start = int(cold_start_samples)
        self.min_std = float(min_std)
        self._baseline_path = baseline_path
        self._save_interval = max(1, int(save_interval))
        self._updates_since_save: int = 0
        self._stats: Dict[Tuple[str, ...], _Stats] = {}
        self._lock = threading.Lock()

        if baseline_path:
            self._load_locked_unsafe()

    def update(self, key: Tuple[str, ...], value: float) -> Optional[float]:
        """Record a new observation and return its z-score vs. the baseline.

        Returns None while the key is still warming up.
        """
        with self._lock:
            st = self._stats.get(key)
            if st is None:
                st = _Stats()
                self._stats[key] = st

            if st.count == 0:
                # seed: mean = value, var = 0
                st.mean = float(value)
                st.var = 0.0
                st.count = 1
                return None

            # Score BEFORE updating, so the current obs isn't in its own baseline.
            std = max(st.std(), self.min_std)
            z: Optional[float] = (float(value) - st.mean) / std if st.count >= self.cold_start else None

            # EWMA update of mean and variance.
            delta = float(value) - st.mean          # deviation from old mean
            st.mean += self.alpha * delta
            st.var = (1 - self.alpha) * st.var + self.alpha * delta * delta
            st.count += 1

            # Periodic auto-save.
            if self._baseline_path:
                self._updates_since_save += 1
                if self._updates_since_save >= self._save_interval:
                    self._save_locked()
                    self._updates_since_save = 0

            return z

    def score(self, key: Tuple[str, ...], value: float) -> Optional[float]:
        """Z-score of value against the current baseline without updating state.

        Returns None during cold start or if the key is unknown.
        """
        with self._lock:
            st = self._stats.get(key)
            if st is None or st.count < self.cold_start:
                return None
            std = max(st.std(), self.min_std)
            return (float(value) - st.mean) / std

    def observations(self, key: Tuple[str, ...]) -> int:
        with self._lock:
            st = self._stats.get(key)
            return st.count if st else 0

    def baseline(self, key: Tuple[str, ...]) -> Optional[Tuple[float, float]]:
        """Return (mean, std) for a key, or None if unknown."""
        with self._lock:
            st = self._stats.get(key)
            return (st.mean, st.std()) if st and st.count > 0 else None

    def reset(self) -> None:
        with self._lock:
            self._stats.clear()

    # ------------------------------------------------------------------
    # Persistence

    def save(self) -> None:
        """Explicitly persist baselines to disk (if baseline_path was given)."""
        if not self._baseline_path:
            return
        with self._lock:
            self._save_locked()

    def _save_locked(self) -> None:
        """Serialize state to JSON — caller must hold self._lock."""
        data: Dict[str, dict] = {}
        for k, v in self._stats.items():
            # Tuple key → JSON array string to survive round-trip without
            # worrying about separator characters in key components.
            key_str = json.dumps(list(k))
            data[key_str] = {"count": v.count, "mean": v.mean, "var": v.var}
        try:
            p = pathlib.Path(self._baseline_path)
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(json.dumps(data))
        except OSError:
            pass  # non-fatal: baselines will be rebuilt from scratch on restart

    def _load_locked_unsafe(self) -> None:
        """Deserialize state from JSON — called from __init__ before lock needed."""
        p = pathlib.Path(self._baseline_path)
        if not p.exists():
            return
        try:
            raw = json.loads(p.read_text())
        except Exception:
            return
        loaded = 0
        for key_str, vals in raw.items():
            try:
                key = tuple(json.loads(key_str))
                self._stats[key] = _Stats(
                    count=int(vals["count"]),
                    mean=float(vals["mean"]),
                    var=float(vals["var"]),
                )
                loaded += 1
            except Exception:
                continue
        if loaded:
            import logging
            logging.getLogger(__name__).info(
                "Loaded %d anomaly baselines from %s", loaded, self._baseline_path
            )
