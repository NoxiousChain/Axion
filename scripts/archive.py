#!/usr/bin/env python3
"""
Archive old alerts and incidents to JSON before deletion.

Run this BEFORE retention.py so data is preserved in cold storage prior to
being pruned from the live database. Archives are newline-delimited JSON
(one object per line) for easy ingestion by Splunk, ELK, or other SIEM.

Usage:
    python scripts/archive.py [--db PATH] [--out-dir DIR] [--days N] [--dry-run]

Example (cron — archive then prune, weekly):
    0 3 * * 0 axion python /opt/axion/scripts/archive.py \
        --db /var/lib/axion/server_alerts.sqlite \
        --out-dir /var/backups/axion/archive && \
      python /opt/axion/scripts/retention.py \
        --db /var/lib/axion/server_alerts.sqlite --days 90
"""
import argparse
import json
import pathlib
import sqlite3
import sys
import time


def _table_exists(conn: sqlite3.Connection, name: str) -> bool:
    return conn.execute(
        "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=?", (name,)
    ).fetchone()[0] > 0


def archive(db_path: str, out_dir: str, retain_days: int, dry_run: bool) -> None:
    cutoff = time.time() - retain_days * 86400
    cutoff_str = time.strftime("%Y-%m-%d %H:%M UTC", time.gmtime(cutoff))
    stamp = time.strftime("%Y%m%d_%H%M%S")
    out = pathlib.Path(out_dir)

    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row

    alerts = conn.execute(
        "SELECT * FROM alerts WHERE ts < ?", (cutoff,)
    ).fetchall()

    incidents = conn.execute(
        "SELECT * FROM incidents WHERE created_at < ? AND acknowledged = 1", (cutoff,)
    ).fetchall() if _table_exists(conn, "incidents") else []

    audit_rows = conn.execute(
        "SELECT * FROM audit_log WHERE ts < ?", (cutoff,)
    ).fetchall() if _table_exists(conn, "audit_log") else []

    conn.close()

    print(f"DB       : {db_path}")
    print(f"Retain   : {retain_days} days  (cutoff: {cutoff_str})")
    print(f"Dry-run  : {dry_run}")
    print(f"\nAlerts to archive   : {len(alerts)}")
    print(f"Incidents to archive: {len(incidents)}  (acknowledged only)")
    print(f"Audit rows to archive: {len(audit_rows)}")

    if dry_run:
        print("\nDry-run — no files written.")
        return

    out.mkdir(parents=True, exist_ok=True)

    def _write_ndjson(rows, filename: str) -> pathlib.Path:
        path = out / filename
        with path.open("w", encoding="utf-8") as f:
            for r in rows:
                f.write(json.dumps(dict(r)) + "\n")
        return path

    if alerts:
        p = _write_ndjson(alerts, f"alerts_{stamp}.ndjson")
        print(f"\nArchived {len(alerts):>6} alerts    -> {p}")
    if incidents:
        p = _write_ndjson(incidents, f"incidents_{stamp}.ndjson")
        print(f"Archived {len(incidents):>6} incidents -> {p}")
    if audit_rows:
        p = _write_ndjson(audit_rows, f"audit_{stamp}.ndjson")
        print(f"Archived {len(audit_rows):>6} audit rows -> {p}")

    print("\nDone. Run retention.py to delete the archived rows from the live DB.")


def main() -> None:
    ap = argparse.ArgumentParser(description="Axion cold-storage archive")
    ap.add_argument("--db", default="server_alerts.sqlite", help="Path to SQLite DB")
    ap.add_argument("--out-dir", default="archive", help="Output directory for NDJSON files")
    ap.add_argument("--days", type=int, default=90, help="Archive rows older than N days")
    ap.add_argument("--dry-run", action="store_true", help="Report counts without writing files")
    args = ap.parse_args()

    db = pathlib.Path(args.db)
    if not db.exists():
        print(f"ERROR: DB not found: {db}", file=sys.stderr)
        sys.exit(1)

    archive(str(db), args.out_dir, args.days, args.dry_run)


if __name__ == "__main__":
    main()
