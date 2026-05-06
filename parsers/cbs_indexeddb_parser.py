#!/usr/bin/env python3
"""
CBS IndexedDB forensic parser.

Parses the Bing IndexedDB (LevelDB) from the Windows Start Menu's embedded
Edge WebView (EBWebView).  This database records every Start Menu search
interaction: what the user typed, what they launched, and when.

Produces two CSV outputs:
  indexeddb_summary.csv  - Latest state per search prefix + target
  indexeddb_timeline.csv - Individual launch events reconstructed from
                           LevelDB version diffs

Requires: ccl_chromium_reader (pip install ccl_chromium_reader)

Usage:
    python cbs_indexeddb_parser.py -i <path> -o <output_dir> [--json] [-v]

The input path can be:
  - Direct path to the LevelDB directory
  - The CBS package directory or EBWebView/Default directory
  - A broader directory (e.g. a drive image mount) - the script will
    search for the known path pattern.
"""

import argparse
import csv
import json
import logging
import os
import sys
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

from ccl_chromium_reader import ccl_chromium_indexeddb
from cbs_known_folders import GUID_RE, resolve_guid_path

logger = logging.getLogger(__name__)

_UNIX_TS_MIN = 1_500_000_000
_UNIX_TS_MAX = 2_000_000_000

# groupType to category mapping. Validated by controlled Start Menu testing
# (see whitepaper Section 2.3). Each row of this map corresponds to a
# Start Menu category tab whose semantics were exercised at least once.
# groupType=10 is deliberately unmapped. No record carrying that value was
# observed in the data examined for this paper, so any classification would
# be speculation. Unknown group types fall through to "Unknown(<n>)" rather
# than being silently dropped.
_GROUP_TYPES = {
    0: "App",
    1: "Settings",
    4: "Image",
    5: "Video",
    7: "Document",
    8: "Folder",
    11: "Web",
}


def _classify_group_type(group_type: int) -> str:
    """Return the category label for a groupType, or 'Unknown(<n>)' if unmapped."""
    label = _GROUP_TYPES.get(group_type)
    if label is not None:
        return label
    return f"Unknown({group_type})"

_SUMMARY_FIELDS = [
    "target", "resolved_target", "type",
    "launch_count", "last_launched",
    "preview_count", "last_previewed",
]

_TIMELINE_FIELDS = [
    "timestamp", "search_prefix", "target", "resolved_target",
    "type",
]

_RELATIVE_IDB_PATH = os.path.join(
    "LocalState", "EBWebView", "Default", "IndexedDB",
    "https_www.bing.com_0.indexeddb.leveldb",
)


def find_indexeddb(path: str | Path) -> Path | None:
    """Locate the Bing IndexedDB LevelDB directory."""
    p = Path(path)

    # Direct path to LevelDB dir
    if p.is_dir() and (p / "MANIFEST-000001").is_file():
        return p

    # Known relative location under CBS package
    candidate = p / _RELATIVE_IDB_PATH
    if candidate.is_dir():
        return candidate

    # Walk
    logger.debug("Searching for Bing IndexedDB under %s …", p)
    for root, _dirs, files in os.walk(p):
        if "MANIFEST-000001" in files and Path(root).name == "https_www.bing.com_0.indexeddb.leveldb":
            full = Path(root)
            logger.debug("Found: %s", full)
            return full

    return None


def _ts_to_utc(value) -> str:
    """Convert a Unix epoch (seconds or ms) to UTC datetime string."""
    try:
        v = float(value)
    except (TypeError, ValueError):
        return ""
    if _UNIX_TS_MIN <= v <= _UNIX_TS_MAX:
        return datetime.fromtimestamp(v, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    if _UNIX_TS_MIN * 1000 <= v <= _UNIX_TS_MAX * 1000:
        return datetime.fromtimestamp(v / 1000, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    return ""


def _resolve_target(identifier: str, group_type: int) -> str:
    """Resolve raw target identifier to a human-readable path.

    Resolution behaviour depends on the groupType, per the identifier formats
    validated in the whitepaper Section 2.3:
      - gT=0 (App): may be a Known Folder GUID + relative path. Resolve the
        GUID. AUMIDs, raw absolute paths, and URI handlers fall through
        unchanged.
      - gT=4/5/7/8 (Image, Video, Document, Folder): file:-prefixed
        forward-slash path. Strip the prefix and normalize slashes.
      - gT=1 (Settings) and gT=11 (Web): identifier is an internal page ID
        or a literal query string. Return as-is.
      - Unknown groupTypes: return as-is to avoid speculative resolution.
    """
    if group_type in (4, 5, 7, 8):
        if identifier.startswith("file:"):
            return identifier[5:].replace("/", "\\")
        return identifier
    if group_type == 0 and GUID_RE.match(identifier):
        return resolve_guid_path(identifier)
    return identifier


def _parse_sed_key(sed_key: str) -> tuple[int, str]:
    """Parse 'groupType\\tidentifier' into (group_type, identifier)."""
    if "\t" in sed_key:
        gt_str, ident = sed_key.split("\t", 1)
        try:
            return int(gt_str), ident
        except ValueError:
            return -1, sed_key
    return -1, sed_key


def _load_records(idb_path: Path) -> dict[str, list]:
    """Load all mruWithIndex records, grouped by key, sorted by seq_no."""
    by_key: dict[str, list] = defaultdict(list)

    with ccl_chromium_indexeddb.WrappedIndexDB(idb_path, None) as idb:
        for dbid in idb.database_ids:
            if dbid.name != "mruWithIndex":
                continue
            wrapped_db = idb[dbid]
            for obj_store in wrapped_db:
                for rec in obj_store.iterate_records(
                    bad_deserializer_data_handler=lambda k, v: logger.warning(
                        "Bad deserializer data for key %s", k
                    )
                ):
                    if not isinstance(rec.value, dict):
                        continue
                    key = str(rec.key.value)
                    by_key[key].append(rec)

    # Sort each key's versions by sequence number
    for key in by_key:
        by_key[key].sort(key=lambda r: r.ldb_seq_no)

    return by_key


def _extract_summary(by_key: dict[str, list]) -> list[dict]:
    """One row per target, aggregated across all search prefixes."""
    # Accumulate totals per identifier. groupType is treated as stable for a
    # given identifier (validated in whitepaper Section 2.3: App / Settings /
    # File / Folder / Web identifier shapes do not overlap), so we don't key
    # the dict by (group_type, identifier).
    agg: dict[str, dict] = {}

    for versions in by_key.values():
        rec = versions[-1]  # latest version

        for sed_key, eng in rec.value.get("SuggestionEngagementData", {}).items():
            if not isinstance(eng, dict):
                continue

            group_type = eng.get("groupType", -1)
            type_label = _classify_group_type(group_type)

            _, identifier = _parse_sed_key(sed_key)

            launch_count = eng.get("prefixLaunchCount", 0)
            last_launched = eng.get("lastLaunchTime", 0)
            preview_count = eng.get("previewPaneLaunchCount", 0)
            last_previewed = eng.get("lastPreviewPaneLaunchTime", 0)

            if identifier in agg:
                entry = agg[identifier]
                entry["launch_count"] += launch_count
                entry["preview_count"] += preview_count
                if last_launched > entry["_last_launched_raw"]:
                    entry["_last_launched_raw"] = last_launched
                if last_previewed > entry["_last_previewed_raw"]:
                    entry["_last_previewed_raw"] = last_previewed
            else:
                agg[identifier] = {
                    "target": identifier,
                    "resolved_target": _resolve_target(identifier, group_type),
                    "type": type_label,
                    "launch_count": launch_count,
                    "_last_launched_raw": last_launched,
                    "preview_count": preview_count,
                    "_last_previewed_raw": last_previewed,
                }

    # Convert to output rows
    rows = []
    for entry in agg.values():
        rows.append({
            "target": entry["target"],
            "resolved_target": entry["resolved_target"],
            "type": entry["type"],
            "launch_count": entry["launch_count"],
            "last_launched": _ts_to_utc(entry["_last_launched_raw"]),
            "preview_count": entry["preview_count"] if entry["preview_count"] else "",
            "last_previewed": _ts_to_utc(entry["_last_previewed_raw"]),
        })

    # Sort by last_launched descending
    rows.sort(key=lambda r: r["last_launched"], reverse=True)
    return rows


def _extract_timeline(by_key: dict[str, list]) -> list[dict]:
    """Reconstruct individual events from LevelDB version diffs."""
    rows = []

    for search_prefix, versions in by_key.items():
        # Track previous counts per sed_key to detect increments
        prev_counts: dict[str, int] = {}

        for rec in versions:
            for sed_key, eng in rec.value.get("SuggestionEngagementData", {}).items():
                if not isinstance(eng, dict):
                    continue

                group_type = eng.get("groupType", -1)
                type_label = _classify_group_type(group_type)

                current_count = eng.get("prefixLaunchCount", 0)
                last_time = eng.get("lastLaunchTime", 0)
                _, identifier = _parse_sed_key(sed_key)

                timestamp = _ts_to_utc(last_time)
                if not timestamp:
                    prev_counts[sed_key] = current_count
                    continue

                if sed_key not in prev_counts:
                    # First time seeing this target - output one event
                    rows.append({
                        "timestamp": timestamp,
                        "search_prefix": search_prefix,
                        "target": identifier,
                        "resolved_target": _resolve_target(identifier, group_type),
                        "type": type_label,
                    })
                elif current_count > prev_counts[sed_key]:
                    # Count incremented - output event(s) for each increment
                    # We only have one timestamp for possibly multiple increments,
                    # so output one row (the timestamp is for the most recent)
                    rows.append({
                        "timestamp": timestamp,
                        "search_prefix": search_prefix,
                        "target": identifier,
                        "resolved_target": _resolve_target(identifier, group_type),
                        "type": type_label,
                    })

                prev_counts[sed_key] = current_count

    # Sort by timestamp descending
    rows.sort(key=lambda r: r["timestamp"], reverse=True)
    return rows


def parse_indexeddb(idb_path: str | Path) -> dict:
    """
    Parse the Bing IndexedDB and return a dict with:
      - summary: list[dict]
      - timeline: list[dict]
      - idb_path: str
    """
    idb_path = Path(idb_path)
    by_key = _load_records(idb_path)

    if not by_key:
        logger.warning(
            "No mruWithIndex records found in %s. The store may be empty, "
            "or the LevelDB may belong to a different origin.",
            idb_path,
        )

    summary = _extract_summary(by_key)
    timeline = _extract_timeline(by_key)

    logger.debug(
        "Extracted %d summary rows, %d timeline events",
        len(summary), len(timeline),
    )

    return {
        "summary": summary,
        "timeline": timeline,
        "idb_path": str(idb_path),
    }


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


def main():
    parser = argparse.ArgumentParser(
        description="Parse Windows CBS EBWebView IndexedDB (Start Menu search history).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""\
examples:
  %(prog)s -i /mnt/image/C/ -o ./output/ -v
  %(prog)s -i ./https_www.bing.com_0.indexeddb.leveldb/ --json
""",
    )
    parser.add_argument(
        "-i", "--input", required=True,
        help="Path to LevelDB dir, CBS package dir, or broader directory.",
    )
    parser.add_argument(
        "-o", "--output", default=None,
        help="Output directory for CSV files. If omitted, summary CSV to stdout.",
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

    idb_path = find_indexeddb(args.input)
    if idb_path is None:
        print(
            "ERROR: Could not find Bing IndexedDB LevelDB at or under the given path.",
            file=sys.stderr,
        )
        sys.exit(1)

    logger.debug("Using IndexedDB: %s", idb_path)

    try:
        data = parse_indexeddb(idb_path)
    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        sys.exit(2)

    summary = data["summary"]
    timeline = data["timeline"]

    if args.json:
        all_records = [{"_csv": "summary", **r} for r in summary]
        all_records += [{"_csv": "timeline", **r} for r in timeline]
        write_jsonl(all_records, sys.stdout)
        print(
            f"Wrote {len(summary)} summary + {len(timeline)} timeline records as JSON Lines.",
            file=sys.stderr,
        )
        return

    if args.output:
        out_dir = Path(args.output)
        out_dir.mkdir(parents=True, exist_ok=True)

        summary_path = out_dir / "indexeddb_summary.csv"
        with open(summary_path, "w", newline="", encoding="utf-8") as f:
            write_csv(summary, _SUMMARY_FIELDS, f)
        print(f"Wrote {len(summary)} summary rows to {summary_path}", file=sys.stderr)

        timeline_path = out_dir / "indexeddb_timeline.csv"
        with open(timeline_path, "w", newline="", encoding="utf-8") as f:
            write_csv(timeline, _TIMELINE_FIELDS, f)
        print(f"Wrote {len(timeline)} timeline events to {timeline_path}", file=sys.stderr)
    else:
        write_csv(summary, _SUMMARY_FIELDS, sys.stdout)
        print(f"Wrote {len(summary)} summary rows.", file=sys.stderr)


if __name__ == "__main__":
    main()
