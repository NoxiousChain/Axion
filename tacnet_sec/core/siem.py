"""
SIEM output — syslog (RFC 5424) and HTTP webhook.

Sends alerts and audit events to an external SIEM collector:
  - syslog: RFC 5424 UDP to any syslog daemon, Splunk syslog input, or Logstash
  - webhook: HTTP POST JSON to Splunk HEC, Elastic, or any webhook endpoint

Non-blocking: all sends happen on a background worker thread so detection
hot paths are never stalled by network I/O.

Server config (env vars):
    AXION_SIEM_TYPE   = syslog | webhook | none  (default: none)
    AXION_SIEM_HOST   = syslog UDP host          (default: localhost)
    AXION_SIEM_PORT   = syslog UDP port          (default: 514)
    AXION_SIEM_URL    = webhook / Splunk HEC URL
    AXION_SIEM_TOKEN  = Authorization token for webhook (Bearer)
    AXION_SIEM_TIMEOUT= HTTP timeout in seconds  (default: 5)

Agent config (configs/config.yaml siem section):
    siem:
      type: syslog           # syslog | webhook | none
      host: localhost
      port: 514
      url: ""
      token: ""
      timeout_seconds: 5
"""

from __future__ import annotations

import json
import logging
import os
import queue
import socket
import threading
import time
import urllib.request
import urllib.error
from typing import Any, Dict, Optional

log = logging.getLogger(__name__)

# RFC 5424 severity mapping from Axion severity strings.
_SYSLOG_SEV = {
    "critical": 2,  # CRIT
    "high":     3,  # ERR
    "medium":   4,  # WARNING
    "low":      6,  # INFO
}

# Syslog facility 16 = local0 (general alerts), 10 = authpriv (audit events)
_FAC_ALERT = 16
_FAC_AUDIT = 10


class SIEMForwarder:
    """Thread-safe, non-blocking SIEM forwarder.

    Instantiate once at startup.  Call send_alert() and send_audit() from any
    thread; events are queued and delivered by an internal worker thread.
    Call stop() on shutdown to flush the queue.
    """

    def __init__(self, cfg: Dict[str, Any]):
        self._type = str(cfg.get("type", "none")).lower().strip()
        self._host = str(cfg.get("host", "localhost"))
        self._port = int(cfg.get("port", 514))
        self._url = str(cfg.get("url", ""))
        self._token = str(cfg.get("token", ""))
        self._timeout = int(cfg.get("timeout_seconds", 5))
        self._enabled = self._type not in ("none", "disabled", "")

        self._q: "queue.Queue[Optional[tuple]]" = queue.Queue(maxsize=2000)
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None

        if self._enabled:
            self._thread = threading.Thread(
                target=self._worker, name="AxionSIEM", daemon=True
            )
            self._thread.start()
            log.info("SIEM forwarder started (type=%s)", self._type)

    # ------------------------------------------------------------------
    # Public API

    def send_alert(self, event: Dict[str, Any]) -> None:
        """Queue an alert event for SIEM delivery."""
        self._enqueue(event, facility=_FAC_ALERT)

    def send_audit(self, event: Dict[str, Any]) -> None:
        """Queue an audit event for SIEM delivery (authpriv facility)."""
        self._enqueue(event, facility=_FAC_AUDIT)

    def stop(self, timeout: float = 5.0) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=timeout)

    # ------------------------------------------------------------------

    def _enqueue(self, event: Dict[str, Any], facility: int) -> None:
        if not self._enabled:
            return
        try:
            self._q.put_nowait((event, facility))
        except queue.Full:
            log.debug("SIEM queue full, dropping event")

    def _worker(self) -> None:
        while not self._stop.is_set():
            try:
                item = self._q.get(timeout=0.5)
            except queue.Empty:
                continue
            event, facility = item
            try:
                if self._type == "syslog":
                    self._send_syslog(event, facility)
                elif self._type in ("webhook", "splunk", "elk"):
                    self._send_webhook(event)
            except Exception as exc:
                log.debug("SIEM send failed: %s", exc)
            finally:
                self._q.task_done()
        # Drain remaining on stop.
        while True:
            try:
                item = self._q.get_nowait()
            except queue.Empty:
                break
            event, facility = item
            try:
                if self._type == "syslog":
                    self._send_syslog(event, facility)
                elif self._type in ("webhook", "splunk", "elk"):
                    self._send_webhook(event)
            except Exception:
                pass

    def _send_syslog(self, event: Dict[str, Any], facility: int) -> None:
        """RFC 5424 syslog over UDP."""
        severity = _SYSLOG_SEV.get(str(event.get("severity", "")).lower(), 6)
        pri = facility * 8 + severity
        hostname = socket.gethostname()[:255]
        ts = time.strftime("%Y-%m-%dT%H:%M:%S.000Z", time.gmtime())
        # MSG-ID: use action (audit) or detector (alert), max 32 chars
        msg_id = str(event.get("action", event.get("detector", "AXION")))[:32]
        # STRUCTURED-DATA: Axion-specific SD element
        sd_id = "axion@32473"
        severity_str = str(event.get("severity", "-"))
        node_id = str(event.get("node_id", "-"))
        structured = f'[{sd_id} severity="{severity_str}" node="{node_id}"]'
        msg = json.dumps(event, separators=(",", ":"))
        packet = f"<{pri}>1 {ts} {hostname} axion - {msg_id} {structured} {msg}"
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(2)
            s.sendto(packet.encode("utf-8", errors="replace")[:8192], (self._host, self._port))

    def _send_webhook(self, event: Dict[str, Any]) -> None:
        """HTTP POST to webhook / Splunk HEC / Elastic endpoint."""
        if not self._url:
            return
        headers = {
            "Content-Type": "application/json",
            "User-Agent": "Axion-SIEM/1.0",
        }
        if self._token:
            headers["Authorization"] = f"Bearer {self._token}"
        body = json.dumps(event, separators=(",", ":")).encode()
        req = urllib.request.Request(self._url, data=body, headers=headers, method="POST")
        with urllib.request.urlopen(req, timeout=self._timeout) as resp:
            if resp.status >= 400:
                log.debug("SIEM webhook HTTP %d", resp.status)


def from_env() -> "SIEMForwarder":
    """Build a SIEMForwarder from AXION_SIEM_* environment variables."""
    return SIEMForwarder({
        "type":            os.environ.get("AXION_SIEM_TYPE", "none"),
        "host":            os.environ.get("AXION_SIEM_HOST", "localhost"),
        "port":            int(os.environ.get("AXION_SIEM_PORT", "514")),
        "url":             os.environ.get("AXION_SIEM_URL", ""),
        "token":           os.environ.get("AXION_SIEM_TOKEN", ""),
        "timeout_seconds": int(os.environ.get("AXION_SIEM_TIMEOUT", "5")),
    })


def from_cfg(cfg: dict) -> "SIEMForwarder":
    """Build a SIEMForwarder from an agent config dict (siem: section)."""
    return SIEMForwarder(cfg.get("siem") or {})


_NOOP: Optional[SIEMForwarder] = None


def noop() -> "SIEMForwarder":
    """Singleton no-op forwarder for when SIEM is disabled."""
    global _NOOP
    if _NOOP is None:
        _NOOP = SIEMForwarder({"type": "none"})
    return _NOOP
