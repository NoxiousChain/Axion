#!/usr/bin/env python3
"""
Data retention script — prune old alerts and incidents from SQLite.

Usage:
    python scripts/retention.py [--db PATH] [--days N] [--dry-run]

Default TTL is 90 days. Pass --days 0 to disable deletion (dry-run only).
"""
import argparse
import sqlite3
import time


def run(db_path: str, retain_days: int, dry_run: bool) -> None:
    cutoff = time.time() - retain_days * 86400
    cutoff_str = time.strftime("%Y-%m-%d %H:%M UTC", time.gmtime(cutoff))
    print(f"DB       : {db_path}")
    print(f"Retain   : {retain_days} days  (cutoff: {cutoff_str})")
    print(f"Dry-run  : {dry_run}")

    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row

    alert_count = conn.execute(
        "SELECT COUNT(*) FROM alerts WHERE ts < ?", (cutoff,)
    ).fetchone()[0]
    incident_count = conn.execute(
        "SELECT COUNT(*) FROM incidents WHERE created_at < ? AND acknowledged = 1",
        (cutoff,),
    ).fetchone()[0]
    audit_count = conn.execute(
        "SELECT COUNT(*) FROM audit_log WHERE ts < ?", (cutoff,)
    ).fetchone()[0] if _table_exists(conn, "audit_log") else 0

    print(f"\nAlerts to delete   : {alert_count}")
    print(f"Incidents to delete: {incident_count}  (acknowledged only)")
    print(f"Audit rows to prune: {audit_count}")

    if dry_run:
        print("\nDry-run — no changes made.")
        conn.close()
        return

    conn.execute("DELETE FROM alerts WHERE ts < ?", (cutoff,))
    conn.execute(
        "DELETE FROM incidents WHERE created_at < ? AND acknowledged = 1", (cutoff,)
    )
    if _table_exists(conn, "audit_log"):
        conn.execute("DELETE FROM audit_log WHERE ts < ?", (cutoff,))
    conn.execute("VACUUM")
    conn.commit()
    conn.close()
    print("\nDone.")


def _table_exists(conn: sqlite3.Connection, name: str) -> bool:
    return conn.execute(
        "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=?", (name,)
    ).fetchone()[0] > 0


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="Axion data retention cleanup")
    ap.add_argument("--db", default="server_alerts.sqlite", help="Path to SQLite DB")
    ap.add_argument("--days", type=int, default=90, help="Retain rows newer than N days")
    ap.add_argument("--dry-run", action="store_true", help="Report counts without deleting")
    args = ap.parse_args()
    run(args.db, args.days, args.dry_run)
