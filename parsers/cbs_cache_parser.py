#!/usr/bin/env python3
"""
CBS EBWebView cache parser.

Parses the Chromium blockfile disk cache used by the Windows Start Menu's
embedded Edge WebView (EBWebView).  Extracts cached URLs with timestamps
and, for Bing search URLs, unfurls the query parameters into dedicated
columns so investigators can see exactly what the user searched for from
the Start Menu, even if they never clicked through to a browser.

Usage:
    python cbs_cache_parser.py -i <path> -o <output_dir> [--json] [-v]

The input path can be:
  - Direct path to the Cache_Data directory
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
from dataclasses import dataclass, asdict, fields
from pathlib import Path
from urllib.parse import urlparse, parse_qs, unquote_plus

from ccl_chromium_reader import ccl_chromium_cache

logger = logging.getLogger(__name__)


@dataclass
class SearchEntry:
    user_typed: str
    bing_searched: str
    qs: str
    form: str
    session_id: str
    last_accessed: str
    record_created_time: str
    server_time: str
    language: str
    country: str
    content_type: str
    content_length: int
    url: str
    cache_name: str


def _addr_to_cache_name(addr) -> str:
    """Map a ccl Addr to the on-disk filename (data_N or f_XXXXXX)."""
    if addr is None or not addr.is_initialized:
        return ""
    if addr.file_type == ccl_chromium_cache.FileType.EXTERNAL:
        return f"f_{addr.external_file_number:06x}"
    if addr.file_selector is not None:
        return f"data_{addr.file_selector}"
    return ""


def _format_time(dt) -> str:
    if dt is None:
        return ""
    return dt.strftime("%Y-%m-%d %H:%M:%S")


def _extract_url(key: str) -> str:
    """Strip Chromium's partition prefix (e.g., '1/0/_dk_<origin> <origin> <url>')."""
    if " " in key:
        return key.rsplit(" ", 1)[-1]
    return key


def _parse_search_entry(url: str, *, last_accessed: str,
                        record_created_time: str, server_time: str,
                        content_type: str, content_length: int,
                        cache_name: str) -> SearchEntry | None:
    """If the URL is a Bing search, extract query parameters into a SearchEntry."""
    try:
        parsed = urlparse(url)
    except Exception:
        return None

    if "bing.com" not in parsed.netloc:
        return None
    if parsed.path != "/search":
        return None

    params = parse_qs(parsed.query)
    q = params.get("q", [None])[0]
    if q is None:
        return None

    return SearchEntry(
        user_typed=unquote_plus(params.get("pq", [""])[0]),
        bing_searched=unquote_plus(q),
        qs=params.get("qs", [""])[0],
        form=params.get("form", [""])[0],
        session_id=params.get("cvid", [""])[0],
        last_accessed=last_accessed,
        record_created_time=record_created_time,
        server_time=server_time,
        language=params.get("setlang", [""])[0],
        country=params.get("cc", [""])[0],
        content_type=content_type,
        content_length=content_length,
        url=url,
        cache_name=cache_name,
    )


_RELATIVE_CACHE_PATH = os.path.join(
    "LocalState", "EBWebView", "Default", "Cache", "Cache_Data"
)


def find_cache_data(path: str | Path) -> Path | None:
    """Locate the Cache_Data directory from a direct path or broader tree."""
    p = Path(path)

    if p.is_dir() and p.name == "Cache_Data" and (p / "data_1").is_file():
        return p

    candidate = p / _RELATIVE_CACHE_PATH
    if candidate.is_dir() and (candidate / "data_1").is_file():
        return candidate

    logger.debug("Searching for Cache_Data under %s …", p)
    for root, _dirs, files in os.walk(p):
        if "data_1" in files and Path(root).name == "Cache_Data":
            full = Path(root)
            if full.match("**/EBWebView/Default/Cache/Cache_Data"):
                logger.debug("Found: %s", full)
                return full

    return None


def parse_cache(cache_dir: str | Path) -> dict:
    """
    Parse the EBWebView blockfile cache and return a dict with:
      - search_entries: list[SearchEntry]
      - cache_dir: str
    """
    cache_dir = Path(cache_dir)
    search_entries: list[SearchEntry] = []

    cache = ccl_chromium_cache.ChromiumBlockFileCache(cache_dir)
    try:
        for raw_key, entry in cache.items():
            url = _extract_url(raw_key)
            if "bing.com" not in url:
                continue

            content_type = ""
            server_time = ""
            request_time = None
            try:
                meta_list = cache.get_metadata(raw_key)
            except Exception:
                meta_list = []
            if meta_list:
                meta = meta_list[0]
                request_time = meta.request_time
                for name, value in meta.http_header_attributes:
                    if name == "content-type" and not content_type:
                        content_type = value.strip()
                    elif name == "date" and not server_time:
                        server_time = value.strip()

            data_addrs = entry.data_addrs
            response_body_addr = data_addrs[1] if len(data_addrs) > 1 else None
            data_sizes = entry.data_sizes
            content_length = data_sizes[1] if len(data_sizes) > 1 else 0

            se = _parse_search_entry(
                url,
                last_accessed=_format_time(request_time),
                record_created_time=_format_time(entry.creation_time),
                server_time=server_time,
                content_type=content_type,
                content_length=content_length,
                cache_name=_addr_to_cache_name(response_body_addr),
            )
            if se:
                search_entries.append(se)
    finally:
        cache.close()

    search_entries.sort(key=lambda e: e.last_accessed, reverse=True)
    logger.debug("Found %d Bing search entries", len(search_entries))

    return {
        "search_entries": search_entries,
        "cache_dir": str(cache_dir),
    }


_SEARCH_FIELDS = [f.name for f in fields(SearchEntry)]


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
        description="Parse Windows CBS EBWebView cache (Start Menu search cache).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""\
examples:
  %(prog)s -i /mnt/image/C/ -o ./output/ -v
  %(prog)s -i ./Cache_Data/ --json > cache.jsonl
""",
    )
    parser.add_argument(
        "-i", "--input", required=True,
        help="Path to Cache_Data dir, CBS package dir, or broader directory.",
    )
    parser.add_argument(
        "-o", "--output", default=None,
        help="Output directory for CSV files. If omitted, searches CSV to stdout.",
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

    cache_dir = find_cache_data(args.input)
    if cache_dir is None:
        print(
            "ERROR: Could not find EBWebView Cache_Data at or under the given path.",
            file=sys.stderr,
        )
        sys.exit(1)

    logger.debug("Using cache dir: %s", cache_dir)

    try:
        data = parse_cache(cache_dir)
    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        sys.exit(2)

    search_dicts = [asdict(s) for s in data["search_entries"]]
    search_count = len(search_dicts)

    if args.json:
        write_jsonl(search_dicts, sys.stdout)
        print(f"Wrote {search_count} search entries as JSON Lines.", file=sys.stderr)
        return

    if args.output:
        out_dir = Path(args.output)
        out_dir.mkdir(parents=True, exist_ok=True)

        search_path = out_dir / "cache_searches.csv"
        with open(search_path, "w", newline="", encoding="utf-8") as f:
            write_csv(search_dicts, _SEARCH_FIELDS, f)
        print(f"Wrote {search_count} search entries to {search_path}", file=sys.stderr)
    else:
        write_csv(search_dicts, _SEARCH_FIELDS, sys.stdout)
        print(f"Wrote {search_count} search entries.", file=sys.stderr)


if __name__ == "__main__":
    main()
