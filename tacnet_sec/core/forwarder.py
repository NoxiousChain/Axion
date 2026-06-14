"""
Background alert forwarder.

Keeps requests.post out of the detection hot path. Alerts are handed off to a
queue and shipped on a worker thread. If the central server is down or flaky,
retries happen out-of-band; detection keeps running.

Two queue backends are available:

  In-memory queue (default):
      Fast, no dependencies. Alerts are lost if the agent process crashes
      while the server is unreachable. Use for dev/test.

  Persistent SQLite queue (set queue_db to a file path):
      Survives process crashes. Undelivered alerts are re-attempted on next
      startup. Use for production edge deployments where offline resilience
      matters. Each alert row is marked delivered (not deleted) so there's
      an audit trail of forwarding attempts.
"""

from __future__ import annotations

import json
import logging
import queue
import sqlite3
import threading
import time
from typing import Any, Dict, List, Optional, Tuple

try:
    import requests
except Exception:  # noqa: BLE001
    requests = None  # type: ignore

log = logging.getLogger(__name__)

_QUEUE_TTL_HOURS = 72        # drop undelivered alerts older than this
_MAX_ATTEMPTS    = 10        # give up forwarding after this many failures


# ---------- persistent queue backend ----------

class _PersistentQueue:
    """SQLite-backed alert queue for offline resilience.

    Thread-safe.  One connection shared across threads, protected by a lock.
    Items survive process restarts; they are marked `delivered=1` on success
    rather than deleted so forwarding history is preserved.
    """

    def __init__(self, db_path: str):
        self._db_path = db_path
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(db_path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._init()

    def _init(self) -> None:
        with self._lock:
            self._conn.execute("""
                CREATE TABLE IF NOT EXISTS pending_alerts (
                    id         INTEGER PRIMARY KEY AUTOINCREMENT,
                    created_at REAL    NOT NULL,
                    payload    TEXT    NOT NULL,
                    attempts   INTEGER DEFAULT 0,
                    delivered  INTEGER DEFAULT 0,
                    delivered_at REAL
                )
            """)
            self._conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_pq_pending "
                "ON pending_alerts(delivered, attempts)"
            )
            self._conn.commit()

    def put(self, payload: Dict[str, Any]) -> None:
        with self._lock:
            self._conn.execute(
                "INSERT INTO pending_alerts (created_at, payload) VALUES (?, ?)",
                (time.time(), json.dumps(payload)),
            )
            self._conn.commit()

    def get_batch(self, limit: int = 20) -> List[Tuple[int, Dict[str, Any]]]:
        """Return up to `limit` undelivered, non-exhausted rows."""
        with self._lock:
            rows = self._conn.execute(
                "SELECT id, payload FROM pending_alerts "
                "WHERE delivered = 0 AND attempts < ? "
                "ORDER BY created_at LIMIT ?",
                (_MAX_ATTEMPTS, limit),
            ).fetchall()
        return [(r["id"], json.loads(r["payload"])) for r in rows]

    def mark_delivered(self, row_id: int) -> None:
        with self._lock:
            self._conn.execute(
                "UPDATE pending_alerts SET delivered=1, delivered_at=? WHERE id=?",
                (time.time(), row_id),
            )
            self._conn.commit()

    def increment_attempts(self, row_id: int) -> None:
        with self._lock:
            self._conn.execute(
                "UPDATE pending_alerts SET attempts=attempts+1 WHERE id=?",
                (row_id,),
            )
            self._conn.commit()

    def cleanup(self) -> int:
        """Remove rows that are delivered or permanently failed and old enough."""
        cutoff = time.time() - _QUEUE_TTL_HOURS * 3600
        with self._lock:
            cur = self._conn.execute(
                "DELETE FROM pending_alerts "
                "WHERE (delivered=1 AND created_at < ?) OR (attempts >= ? AND created_at < ?)",
                (cutoff, _MAX_ATTEMPTS, cutoff),
            )
            self._conn.commit()
        return cur.rowcount

    def pending_count(self) -> int:
        with self._lock:
            return self._conn.execute(
                "SELECT COUNT(*) FROM pending_alerts WHERE delivered=0 AND attempts < ?",
                (_MAX_ATTEMPTS,),
            ).fetchone()[0]

    def close(self) -> None:
        with self._lock:
            self._conn.close()


# ---------- forwarder ----------

class AlertForwarder:
    """Submits alerts to the central server on a background worker thread.

    Args:
        ingest_url:  Full URL of the server's POST /api/alerts endpoint.
        timeout:     Per-request HTTP timeout in seconds.
        api_key:     Value for the X-Axion-Key header.
        queue_size:  In-memory queue cap (ignored when queue_db is set).
        ca_cert:     CA cert path for TLS verification, False to skip, or None.
        client_cert: (certfile, keyfile) tuple for mTLS, or None.
        queue_db:    Path to a SQLite file for the persistent queue.
                     When set, the in-memory queue is not used.
    """

    def __init__(
        self,
        ingest_url: Optional[str],
        timeout: float = 2.0,
        api_key: Optional[str] = None,
        queue_size: int = 1000,
        ca_cert: Optional[str] = None,
        client_cert: Optional[tuple] = None,
        queue_db: Optional[str] = None,
    ):
        self.ingest_url = ingest_url
        self.timeout = float(timeout)
        self.api_key = api_key
        self.ca_cert = ca_cert
        self.client_cert = client_cert

        self._pq: Optional[_PersistentQueue] = None
        self._q: Optional["queue.Queue[Dict[str, Any]]"] = None

        if queue_db:
            self._pq = _PersistentQueue(queue_db)
            log.info("Using persistent alert queue at %s (%d pending)",
                     queue_db, self._pq.pending_count())
        else:
            self._q = queue.Queue(maxsize=queue_size)

        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None

        if ingest_url and requests is not None:
            target = self._run_persistent if self._pq else self._run_memory
            self._thread = threading.Thread(
                target=target, name="AxionForwarder", daemon=False
            )
            self._thread.start()

    def submit(self, payload: Dict[str, Any]) -> bool:
        if not self.ingest_url or requests is None:
            return False
        if self._pq is not None:
            self._pq.put(payload)
            return True
        try:
            self._q.put_nowait(payload)  # type: ignore[union-attr]
            return True
        except queue.Full:
            log.warning("forwarder queue full; dropping alert %s", payload.get("title"))
            return False

    def stop(self, flush_timeout: float = 5.0) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=flush_timeout)
        if self._pq is not None:
            self._pq.cleanup()
            self._pq.close()

    # ------------------------------------------------------------------
    # Worker: in-memory path (dev / backward-compat)

    def _run_memory(self) -> None:
        assert self._q is not None
        headers = self._make_headers()
        while not self._stop.is_set():
            try:
                payload = self._q.get(timeout=0.5)
            except queue.Empty:
                continue
            self._post_with_retry(payload, headers)
            self._q.task_done()
        # Drain on shutdown.
        while True:
            try:
                payload = self._q.get_nowait()
            except queue.Empty:
                return
            self._post_with_retry(payload, headers)
            self._q.task_done()

    # ------------------------------------------------------------------
    # Worker: persistent queue path (production)

    def _run_persistent(self) -> None:
        assert self._pq is not None
        headers = self._make_headers()
        cleanup_counter = 0
        while not self._stop.is_set():
            batch = self._pq.get_batch(limit=20)
            if not batch:
                time.sleep(0.5)
                continue
            for row_id, payload in batch:
                success = self._post_once(payload, headers)
                if success:
                    self._pq.mark_delivered(row_id)
                else:
                    self._pq.increment_attempts(row_id)
            # Periodic maintenance cleanup.
            cleanup_counter += 1
            if cleanup_counter >= 200:
                self._pq.cleanup()
                cleanup_counter = 0
        # On stop, persistent items survive — nothing to drain explicitly.

    # ------------------------------------------------------------------

    def _make_headers(self) -> Dict[str, str]:
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["X-Axion-Key"] = self.api_key
        return headers

    def _post_with_retry(self, payload: Dict[str, Any], headers: Dict[str, str]) -> None:
        delay = 0.5
        for attempt in range(3):
            if self._post_once(payload, headers):
                return
            log.debug("forward attempt %d failed for %s", attempt + 1, payload.get("title"))
            time.sleep(delay)
            delay *= 2
        log.warning("giving up on alert %s after 3 attempts", payload.get("title"))

    def _post_once(self, payload: Dict[str, Any], headers: Dict[str, str]) -> bool:
        try:
            verify = self.ca_cert if self.ca_cert is not None else True
            resp = requests.post(
                self.ingest_url,
                data=json.dumps(payload),
                headers=headers,
                timeout=self.timeout,
                verify=verify,
                cert=self.client_cert,  # mTLS: (certfile, keyfile) or None
            )
            if not resp.ok:
                log.debug("forward rejected HTTP %s for %s", resp.status_code, payload.get("title"))
                return False
            return True
        except Exception as exc:  # noqa: BLE001
            log.debug("forward failed: %s", exc)
            return False
