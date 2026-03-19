#!/usr/bin/env python3
"""
CBS AppsIndex.db forensic parser.

Parses the Windows Start Menu application index database (AppsIndex.db)
found within the MicrosoftWindows.Client.CBS package. This database tracks
installed applications and their launch counts from any execution source
(Start Menu, Taskbar, direct execution, etc.).

Usage:
    python cbs_appsindex_parser.py -i <path> -o <output_dir> [--json] [-v]

The input path can be:
  - Direct path to AppsIndex.db
  - The CBS package directory
  - A broader directory (e.g. a drive image mount) - the script will search
    for LocalState/Search/AppsIndex.db within it.
"""

import argparse
import csv
import json
import logging
import os
import shutil
import sqlite3
import sys
import tempfile
from dataclasses import dataclass, asdict
from pathlib import Path

from cbs_known_folders import GUID_RE as _GUID_RE, resolve_guid_path as _resolve_guid_path

logger = logging.getLogger("cbs_parser")

# Dataclasses

@dataclass
class AppRecord:
    display_name: str
    resolved_path: str
    launch_count: int
    app_type: str        # Win32 / UWP
    app_id: str


# Path classification

def _classify(serialized_id: str, app_id: str):
    """Return (app_type, resolved_path)."""
    if serialized_id.startswith("P~"):
        return "UWP", app_id

    # Win32 - resolve Known Folder GUIDs in the path if present
    if _GUID_RE.match(app_id):
        return "Win32", _resolve_guid_path(app_id)

    return "Win32", app_id


# Database discovery

_RELATIVE_DB_PATH = os.path.join(
    "LocalState", "Search", "AppsIndex.db"
)

def find_appsindex_db(path: str | Path) -> Path | None:
    """Locate AppsIndex.db from a direct path, CBS package dir, or broader tree."""
    p = Path(path)

    # Direct path to file
    if p.is_file() and p.name == "AppsIndex.db":
        return p

    # Check known relative location under CBS package
    candidate = p / _RELATIVE_DB_PATH
    if candidate.is_file():
        return candidate

    # Walk looking for the pattern
    logger.debug("Searching for AppsIndex.db under %s …", p)
    for root, _dirs, files in os.walk(p):
        if "AppsIndex.db" in files:
            full = Path(root) / "AppsIndex.db"
            if full.match("**/LocalState/Search/AppsIndex.db"):
                logger.debug("Found: %s", full)
                return full

    return None


# Schema validation

_EXPECTED_TABLES = {"tiles_content", "metadata"}

def _validate_schema(con: sqlite3.Connection) -> None:
    tables = {
        row[0]
        for row in con.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        )
    }
    missing = _EXPECTED_TABLES - tables
    if missing:
        raise ValueError(
            f"AppsIndex.db is missing expected tables: {', '.join(sorted(missing))}"
        )


# Database open helper

def _open_db(db_path: Path) -> tuple[sqlite3.Connection, str | None, str | None]:
    """
    Open AppsIndex.db read-only.

    If a non-empty WAL file exists alongside the database, copies the database
    and its journal files to a temporary directory and opens the copy normally
    so that SQLite replays the WAL.  The original evidence is never modified.

    Returns (connection, temp_dir_or_None, wal_note_or_None).
    The caller must close the connection and, if temp_dir is not None, clean it
    up with shutil.rmtree.
    """
    wal = db_path.with_suffix(".db-wal")
    shm = db_path.with_suffix(".db-shm")
    wal_has_data = wal.is_file() and wal.stat().st_size > 0

    if wal_has_data:
        wal_size = wal.stat().st_size
        tmp_dir = tempfile.mkdtemp(prefix="appsindex_")
        tmp_db = Path(tmp_dir) / db_path.name
        shutil.copy2(db_path, tmp_db)
        shutil.copy2(wal, tmp_db.with_suffix(".db-wal"))
        if shm.is_file():
            shutil.copy2(shm, tmp_db.with_suffix(".db-shm"))

        note = (
            f"WAL file present ({wal_size:,} bytes). "
            "Replayed on a temporary copy - original evidence unchanged."
        )
        logger.debug("%s", note)

        # Open normally (not immutable) so SQLite replays the WAL on the copy
        con = sqlite3.connect(str(tmp_db))
        return con, tmp_dir, note

    # No WAL - open original immutably
    uri = f"file:{db_path}?immutable=1"
    con = sqlite3.connect(uri, uri=True)
    return con, None, None


# Core parser

def parse_appsindex(db_path: str | Path) -> dict:
    """
    Parse AppsIndex.db and return a dict with keys:
      - apps: list[AppRecord]
      - metadata: dict[str, str]
      - db_path: str
      - wal_replayed: bool
      - wal_note: str | None
    """
    db_path = Path(db_path)
    result: dict = {"db_path": str(db_path)}

    con, tmp_dir, wal_note = _open_db(db_path)
    result["wal_replayed"] = tmp_dir is not None
    result["wal_note"] = wal_note

    try:
        _validate_schema(con)

        # Metadata
        meta = {}
        for name, value in con.execute("SELECT name, value FROM metadata"):
            meta[name] = value
        result["metadata"] = meta
        logger.debug("Metadata: %s", meta)

        # Apps from tiles_content
        apps: list[AppRecord] = []
        for row in con.execute(
            "SELECT c0, c1, c3, c4 FROM tiles_content"
        ):
            serialized_id, app_id, display_name, launch_count = row
            app_type, resolved_path = _classify(
                str(serialized_id), str(app_id)
            )
            try:
                lc = int(launch_count)
            except (TypeError, ValueError):
                lc = 0

            apps.append(AppRecord(
                display_name=str(display_name) if display_name else "",
                resolved_path=resolved_path,
                launch_count=lc,
                app_type=app_type,
                app_id=str(app_id),
            ))

        # Sort: launch_count DESC, display_name ASC
        apps.sort(key=lambda a: (-a.launch_count, a.display_name))
        result["apps"] = apps

    finally:
        con.close()
        if tmp_dir is not None:
            shutil.rmtree(tmp_dir, ignore_errors=True)

    return result


# Output helpers

_APP_FIELDS = [
    "display_name", "resolved_path", "launch_count",
    "app_type", "app_id",
]


def write_csv(rows: list[dict], fieldnames: list[str], output) -> int:
    writer = csv.DictWriter(output, fieldnames=fieldnames, extrasaction="ignore")
    writer.writeheader()
    for row in rows:
        writer.writerow(row)
    return len(rows)


def write_jsonl(records: list[dict], output) -> int:
    for rec in records:
        json.dump(rec, output, ensure_ascii=False)
        output.write("\n")
    return len(records)


# CLI

def main():
    parser = argparse.ArgumentParser(
        description="Parse Windows AppsIndex.db (Start Menu application index).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""\
examples:
  %(prog)s -i C:\\Users\\user\\...\\AppsIndex.db -o ./output/
  %(prog)s -i /mnt/image/C/ -o ./output/ -v
  %(prog)s -i ./evidence/ --json > apps.jsonl
""",
    )
    parser.add_argument(
        "-i", "--input", required=True,
        help="Path to AppsIndex.db, its parent CBS package dir, or a broader directory to search.",
    )
    parser.add_argument(
        "-o", "--output", default=None,
        help="Output directory for CSV files. If omitted, CSV is written to stdout.",
    )
    parser.add_argument(
        "--json", action="store_true",
        help="Output JSON Lines to stdout instead of CSV.",
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true",
        help="Enable debug logging to stderr.",
    )
    args = parser.parse_args()

    logging.basicConfig(
        format="%(levelname)s: %(message)s",
        level=logging.DEBUG if args.verbose else logging.WARNING,
        stream=sys.stderr,
    )

    # Locate database
    db_path = find_appsindex_db(args.input)
    if db_path is None:
        print("ERROR: Could not find AppsIndex.db at or under the given path.", file=sys.stderr)
        sys.exit(1)

    logger.debug("Using database: %s", db_path)

    # Parse
    data = parse_appsindex(db_path)

    if data["wal_note"]:
        print(f"INFO: {data['wal_note']}", file=sys.stderr)

    apps_dicts = [asdict(a) for a in data["apps"]]
    app_count = len(apps_dicts)

    # Metadata summary
    meta = data["metadata"]
    logger.debug(
        "Database version=%s, language=%s, contentHash=%s",
        meta.get("version", "?"),
        meta.get("language", "?"),
        meta.get("appsContentHash", "?"),
    )

    # JSON output
    if args.json:
        write_jsonl(apps_dicts, sys.stdout)
        print(f"Wrote {app_count} app records as JSON Lines.", file=sys.stderr)
        return

    # CSV output
    if args.output:
        out_dir = Path(args.output)
        out_dir.mkdir(parents=True, exist_ok=True)

        apps_path = out_dir / "appsindex_apps.csv"
        with open(apps_path, "w", newline="", encoding="utf-8") as f:
            write_csv(apps_dicts, _APP_FIELDS, f)
        print(f"Wrote {app_count} app records to {apps_path}", file=sys.stderr)
    else:
        write_csv(apps_dicts, _APP_FIELDS, sys.stdout)
        print(f"Wrote {app_count} app records.", file=sys.stderr)


if __name__ == "__main__":
    main()
