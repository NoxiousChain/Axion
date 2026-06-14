#!/usr/bin/env python3
"""
Hot SQLite backup using the built-in online backup API.

The backup is safe to run while the server is live — SQLite's backup API
takes a consistent snapshot without locking out writers for more than a
page at a time.

Usage:
    python scripts/backup.py [--db PATH] [--out PATH]

Example (cron — daily backup to /var/backups/axion/):
    0 2 * * * axion python /opt/axion/scripts/backup.py \
        --db /var/lib/axion/server_alerts.sqlite \
        --out /var/backups/axion/
"""
import argparse
import pathlib
import sqlite3
import sys
import time


def backup(src: str, dst: str) -> None:
    src_conn = sqlite3.connect(src)
    dst_conn = sqlite3.connect(dst)
    try:
        src_conn.backup(dst_conn)
    finally:
        dst_conn.close()
        src_conn.close()


def main() -> None:
    ap = argparse.ArgumentParser(description="Axion SQLite hot backup")
    ap.add_argument("--db", default="server_alerts.sqlite", help="Source DB path")
    ap.add_argument("--out", default=None,
                    help="Destination file or directory. If a directory, a timestamped "
                         "filename is created automatically.")
    args = ap.parse_args()

    src = pathlib.Path(args.db)
    if not src.exists():
        print(f"ERROR: source DB not found: {src}", file=sys.stderr)
        sys.exit(1)

    if args.out:
        out = pathlib.Path(args.out)
        if out.is_dir():
            stamp = time.strftime("%Y%m%d_%H%M%S")
            out = out / f"{src.stem}_{stamp}.sqlite"
    else:
        stamp = time.strftime("%Y%m%d_%H%M%S")
        out = src.parent / f"{src.stem}_{stamp}.sqlite"

    out.parent.mkdir(parents=True, exist_ok=True)
    backup(str(src), str(out))
    size_mb = out.stat().st_size / (1024 * 1024)
    print(f"Backup complete: {src} -> {out}  ({size_mb:.2f} MB)")


if __name__ == "__main__":
    main()
