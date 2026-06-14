"""
Insider threat / UEBA-lite detector.

Tracks per-user behavior in 1-hour buckets, and alerts on either a static
threshold or a learned baseline:

Static triggers (existing):
  * Activity outside configured working hours (low severity, once per hour)
  * Bytes/hour above `insider.max_data_mb_per_hour`
  * Contact with more than `insider.new_host_contact_threshold` distinct dsts

Learned trigger (new):
  * Bytes/hour for this user deviates by more than `anomaly.z_threshold`
    sigmas from that user's EWMA baseline. Catches exfiltration that's
    unusual-for-alice even if it stays under the absolute MB ceiling.

We only train the baseline at hour rollover (completed hours only). During
the current hour we score the in-progress bucket against the existing
baseline but don't feed it back in - otherwise an attack during the
training window would be learned as "normal."

Dedupe key is (user, hour) so each alert fires once per user-hour.
"""

from __future__ import annotations

import os
from collections import defaultdict
from datetime import datetime
from typing import Dict, Tuple

from ..core.anomaly import EWMATracker
from ..responders.actions import Alert


class InsiderDetector:
    def __init__(self, bus, cfg, store, forwarder=None, siem=None):
        self.bus = bus
        self.cfg = cfg
        self.store = store
        self.alerter = Alert(store, cfg, forwarder=forwarder, siem=siem)

        self.bytes_by_user_hour: Dict[Tuple[str, int], int] = defaultdict(int)
        self.contacts_by_user: Dict[Tuple[str, int], set] = defaultdict(set)
        self.last_seen_hour: Dict[str, int] = {}

        ano = cfg.get("anomaly", {}) or {}
        self.anomaly_enabled = bool(ano.get("enable", True))
        self.z_threshold = float(ano.get("z_threshold", 3.0))

        baseline_dir = ano.get("baseline_dir")
        baseline_path = os.path.join(baseline_dir, "insider.json") if baseline_dir else None

        self.tracker = EWMATracker(
            alpha=float(ano.get("alpha", 0.1)),
            cold_start_samples=int(ano.get("cold_start_samples", 5)),
            min_std=float(ano.get("min_std_insider", 1024.0 * 1024.0)),
            baseline_path=baseline_path,
        )

        bus.subscribe("net_event", self.on_event)

    def on_event(self, e):
        ins_cfg = self.cfg.get("insider", {}) or {}
        user = e.get("user") or "unknown"
        ts = float(e.get("ts") or 0)
        hour = datetime.utcfromtimestamp(ts).hour
        bucket = (user, hour)

        # Detect hour rollover for this user and retire the completed hour's
        # bucket to the baseline so the tracker learns normal behavior.
        prev_hour = self.last_seen_hour.get(user)
        if prev_hour is not None and prev_hour != hour:
            prev_bucket = (user, prev_hour)
            prev_bytes = self.bytes_by_user_hour.get(prev_bucket, 0)
            if self.anomaly_enabled and prev_bytes > 0:
                self.tracker.update(("insider_bytes", user), float(prev_bytes))
            # Free memory for the closed hour.
            self.bytes_by_user_hour.pop(prev_bucket, None)
            self.contacts_by_user.pop(prev_bucket, None)
        self.last_seen_hour[user] = hour

        # Accumulate current-hour stats.
        self.bytes_by_user_hour[bucket] += int(e.get("bytes") or 0)
        dst = e.get("dst_ip")
        if dst:
            self.contacts_by_user[bucket].add(dst)

        # --- static checks (unchanged) ---
        start, end = ins_cfg.get("baseline_hours", [6, 20])
        if hour < start or hour >= end:
            self.alerter.emit(
                "InsiderDetector",
                "low",
                "Off-hours activity",
                {"user": user, "hour": hour},
                key=bucket,
            )

        mb = self.bytes_by_user_hour[bucket] / (1024 * 1024)
        if mb > float(ins_cfg.get("max_data_mb_per_hour", 120)):
            self.alerter.emit(
                "InsiderDetector",
                "high",
                "Excessive data volume",
                {"user": user, "hour": hour, "mb": round(mb, 2)},
                key=bucket,
            )

        contact_count = len(self.contacts_by_user[bucket])
        if contact_count > int(ins_cfg.get("new_host_contact_threshold", 35)):
            self.alerter.emit(
                "InsiderDetector",
                "medium",
                "High number of new hosts contacted",
                {"user": user, "count": contact_count, "hour": hour},
                key=bucket,
            )

        # --- anomaly check (new) ---
        # Score the in-progress hour against the baseline WITHOUT training on it.
        if self.anomaly_enabled:
            current = float(self.bytes_by_user_hour[bucket])
            z = self.tracker.score(("insider_bytes", user), current)
            if z is not None and z >= self.z_threshold:
                baseline = self.tracker.baseline(("insider_bytes", user))
                mean, std = baseline if baseline else (0.0, 0.0)
                self.alerter.emit(
                    "InsiderDetector",
                    "medium",
                    "Anomalous data volume vs. user baseline",
                    {
                        "user": user,
                        "hour": hour,
                        "bytes": int(current),
                        "baseline_mean_bytes": int(mean),
                        "baseline_std_bytes": int(std),
                        "z_score": round(z, 2),
                    },
                    key=(user, hour, "anomaly"),
                )