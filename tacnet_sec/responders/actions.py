
from time import time
from typing import Any, Dict, Optional, Tuple

from ..core.throttle import AlertThrottler


class Alert:
    _default_throttler = AlertThrottler(cooldown_seconds=30.0)

    def __init__(self, store, cfg: Optional[dict] = None, forwarder=None, siem=None):
        self.store = store
        self.cfg = cfg or {}
        self.forwarder = forwarder
        self.siem = siem  # SIEMForwarder or None

    def emit(self, detector: str, severity: str, title: str, details: Dict[str, Any],
             key: Tuple[str, ...] = ()):
        should_emit, _ = self._default_throttler.should_emit(detector, title, *key)
        if not should_emit:
            return

        ts = time()
        agent_cfg = self.cfg.get("agent", {})
        node_id = agent_cfg.get("node_id")
        location = agent_cfg.get("location")

        print(f"[ALERT] {severity.upper()} | {detector} | {title} | {details}")
        self.store.write(ts, detector, severity, title, details, node_id=node_id, location=location)

        payload = {
            "ts": ts,
            "detector": detector,
            "severity": severity,
            "title": title,
            "details": details,
            "node_id": node_id,
            "location": location,
        }

        # Forward to central server (async queue).
        srv_cfg = self.cfg.get("server", {})
        if agent_cfg.get("forward_alerts") and srv_cfg.get("ingest_url"):
            if self.forwarder is not None:
                self.forwarder.submit(payload)
            else:
                import requests
                headers = {"Content-Type": "application/json"}
                if srv_cfg.get("api_key"):
                    headers["X-Axion-Key"] = srv_cfg["api_key"]
                ca_cert = srv_cfg.get("ca_cert", True)
                try:
                    requests.post(srv_cfg["ingest_url"], json=payload, headers=headers,
                                  timeout=srv_cfg.get("timeout_seconds", 2), verify=ca_cert)
                except Exception:
                    pass

        # Forward to SIEM (fire-and-forget, non-blocking).
        if self.siem is not None:
            self.siem.send_alert({
                **payload,
                "event_provider": "axion-agent",
                "event_code": "ALERT_EMITTED",
            })


def block_ip(ip: str, dry_run: bool = True):
    cmd = f"iptables -A INPUT -s {ip} -j DROP"
    if dry_run:
        print(f"[DRY-RUN] Would execute: {cmd}")
    else:
        import subprocess
        subprocess.run(cmd.split(), check=False)
