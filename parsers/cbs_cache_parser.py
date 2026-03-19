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
import datetime
import json
import logging
import os
import struct
import sys
from dataclasses import dataclass, asdict, fields
from pathlib import Path
from urllib.parse import urlparse, parse_qs, unquote_plus

logger = logging.getLogger("cbs_parser")

# Constants

_BLOCKFILE_MAGIC = 0xC104CAC3
_BLOCK_HEADER_SIZE = 8192
_ENTRY_BASE_SIZE = 256
_KEY_INLINE_MAX = 160  # bytes available for key in first block (256 - 96)
_ENTRY_HEADER_SIZE = 96
_CHROMIUM_EPOCH = datetime.datetime(1601, 1, 1, tzinfo=datetime.timezone.utc)

# Bing "qs=" parameter: how the query was formed from user input
_QS_LABELS = {
    "SW": "typed",              # Search Word - user typed it verbatim
    "UT": "typed",              # User Typed - full query typed out
    "EP": "suggestion",         # Expanded/Popular - suggestion from partial input
    "LS": "suggestion",         # List Suggestion - picked from dropdown
    "AS": "suggestion",         # Auto Suggest
    "MB": "entity_match",       # Match Box - entity card clicked (has filters=)
    "SC": "spell_corrected",    # Spell Corrected by Bing
    "LT": "suggestion",         # Long Tail suggestion
    "OS": "suggestion",         # Original Suggestion
}

# Bing "form=" parameter: where the search was initiated
_FORM_LABELS = {
    "WMSAUT": "start_menu_autosuggest",
    "WMSMAN": "start_menu_manual",
    "QBRE":   "bing_search_box",
}


# Dataclasses

@dataclass
class SearchEntry:
    user_typed: str          # pq= (what the user actually typed)
    bing_searched: str       # q= (what Bing searched for after suggestion/correction)
    query_method: str        # qs= decoded (typed/suggestion/spell_corrected/entity_match)
    search_source: str       # form= decoded (start_menu_autosuggest, etc.)
    session_id: str          # cvid (links searches within one Start Menu open)
    last_accessed: str       # last HTTP request time
    record_created_time: str # when the cache record was first created
    server_time: str         # Date header from the server
    language: str            # setlang=
    country: str             # cc=
    content_type: str
    content_length: int
    url: str                 # full URL
    cache_name: str          # data_N or f_XXXXXX file holding the response body


# Chromium time helper

def _chromium_time(us: int) -> str:
    """Convert Chromium microseconds-since-1601 to ISO 8601 UTC string."""
    if us <= 0:
        return ""
    try:
        dt = _CHROMIUM_EPOCH + datetime.timedelta(microseconds=us)
        return dt.strftime("%Y-%m-%d %H:%M:%S")
    except (OverflowError, OSError):
        return ""


def _is_valid_chromium_time(us: int) -> bool:
    """Check if a uint64 looks like a plausible Chromium timestamp (2000–2100)."""
    return 12_600_000_000_000_000 < us < 15_700_000_000_000_000


def _addr_to_filename(addr: int) -> str:
    """Convert a CacheAddr to the filename that holds the data (data_N or f_XXXXXX)."""
    if addr == 0:
        return ""
    file_type = (addr >> 28) & 0x7
    if file_type == 0:
        file_num = addr & 0x0FFFFFFF
        return f"f_{file_num:06x}"
    file_num = (addr >> 16) & 0xFF
    return f"data_{file_num}"


# HTTP info parsing

def _parse_http_info(data: bytes, size: int) -> dict:
    """Extract timestamps, HTTP status, and headers from Chromium cache stream 0.

    Stream 0 layout (after 4-byte pickle length):
      - variable flags (skipped by scanning for timestamps)
      - request_time:  int64 Chromium µs  (first valid timestamp)
      - response_time: int64 Chromium µs  (second valid timestamp)
      - HTTP status line + headers (null-separated, starting with "HTTP/")
    """
    if not data or size <= 0:
        return {}
    raw = data[:size]

    result: dict = {}

    # Scan for the first two Chromium timestamps in the first 48 bytes
    timestamps = []
    for offset in range(4, min(48, len(raw) - 8), 4):
        val = struct.unpack_from("<Q", raw, offset)[0]
        if _is_valid_chromium_time(val):
            timestamps.append(val)
            if len(timestamps) == 2:
                break

    if len(timestamps) >= 1:
        result["request_time"] = timestamps[0]
    if len(timestamps) >= 2:
        result["response_time"] = timestamps[1]

    # Find HTTP status line and headers
    http_pos = raw.find(b"HTTP/")
    if http_pos < 0:
        return result

    header_bytes = raw[http_pos:]
    parts = header_bytes.split(b"\x00")

    try:
        status_line = parts[0].decode("utf-8", errors="replace")
        tokens = status_line.split()
        if len(tokens) >= 2:
            result["status"] = int(tokens[1])
    except (ValueError, IndexError):
        pass

    for part in parts[1:]:
        try:
            line = part.decode("utf-8", errors="replace").strip()
            if ":" in line:
                k, v = line.split(":", 1)
                k_lower = k.strip().lower()
                # Only store headers we care about (avoid cert noise)
                if k_lower in ("content-type", "date", "content-length"):
                    result[k_lower] = v.strip()
        except Exception:
            pass

    return result


# Blockfile cache parser

def _read_block_data(cache_dir: Path, fname: str, offset: int, size: int,
                     block_cache: dict) -> bytes | None:
    """Read data from a block file at the given offset."""
    if fname not in block_cache:
        fpath = cache_dir / fname
        if not fpath.is_file():
            return None
        block_cache[fname] = fpath.read_bytes()
    data = block_cache[fname]
    if offset + size > len(data):
        return None
    return data[offset:offset + size]


def _read_at_addr(addr: int, cache_dir: Path, block_cache: dict) -> bytes | None:
    """Read data at a CacheAddr."""
    if addr == 0:
        return None
    file_type = (addr >> 28) & 0x7
    if file_type == 0:
        # External file
        file_num = addr & 0x0FFFFFFF
        fpath = cache_dir / f"f_{file_num:06x}"
        if not fpath.is_file():
            return None
        return fpath.read_bytes()
    block_sizes = {1: 36, 2: 256, 3: 1024, 4: 4096}
    bs = block_sizes.get(file_type)
    if bs is None:
        return None
    file_num = (addr >> 16) & 0xFF
    num_blocks = ((addr >> 24) & 0x3) + 1
    block_num = addr & 0xFFFF
    fname = f"data_{file_num}"
    offset = _BLOCK_HEADER_SIZE + block_num * bs
    return _read_block_data(cache_dir, fname, offset, bs * num_blocks, block_cache)


def _parse_entries(cache_dir: Path) -> list[dict]:
    """Parse all cache entries from the blockfile data_1."""
    data_1_path = cache_dir / "data_1"
    if not data_1_path.is_file():
        raise FileNotFoundError(f"Block file not found: {data_1_path}")

    raw = data_1_path.read_bytes()
    block_cache = {"data_1": raw}

    # Validate magic
    if len(raw) < _BLOCK_HEADER_SIZE:
        raise ValueError("data_1 too small to contain block header")
    magic = struct.unpack_from("<I", raw, 0)[0]
    if magic != _BLOCKFILE_MAGIC:
        raise ValueError(f"Bad block file magic: 0x{magic:08X}")

    entry_size = struct.unpack_from("<I", raw, 12)[0]
    if entry_size != _ENTRY_BASE_SIZE:
        raise ValueError(f"Unexpected entry size: {entry_size}")

    entries_data = raw[_BLOCK_HEADER_SIZE:]
    max_blocks = len(entries_data) // _ENTRY_BASE_SIZE

    entries = []
    idx = 0
    while idx < max_blocks:
        offset = idx * _ENTRY_BASE_SIZE
        if offset + _ENTRY_BASE_SIZE > len(entries_data):
            break

        entry = entries_data[offset:offset + _ENTRY_BASE_SIZE]
        hash_val = struct.unpack_from("<I", entry, 0)[0]
        if hash_val == 0:
            idx += 1
            continue

        key_len = struct.unpack_from("<i", entry, 32)[0]
        long_key_addr = struct.unpack_from("<I", entry, 36)[0]
        creation_time = struct.unpack_from("<Q", entry, 24)[0]
        data_sizes = struct.unpack_from("<4i", entry, 40)
        data_addrs = struct.unpack_from("<4I", entry, 56)

        if key_len <= 0 or key_len > 50000:
            idx += 1
            continue

        # Determine key location
        key = None
        num_blocks = 1

        if long_key_addr != 0:
            # Key stored in separate block/file
            key_data = _read_at_addr(long_key_addr, cache_dir, block_cache)
            if key_data and len(key_data) >= key_len:
                key = key_data[:key_len].decode("utf-8", errors="replace")
        elif key_len <= _KEY_INLINE_MAX:
            # Key fits in single block
            key = entry[_ENTRY_HEADER_SIZE:_ENTRY_HEADER_SIZE + key_len] \
                .decode("utf-8", errors="replace")
        else:
            # Key spans multiple consecutive blocks
            num_blocks = 1 + ((key_len - _KEY_INLINE_MAX + _ENTRY_BASE_SIZE - 1)
                              // _ENTRY_BASE_SIZE)
            end = offset + num_blocks * _ENTRY_BASE_SIZE
            if end <= len(entries_data):
                multi = entries_data[offset:end]
                key = multi[_ENTRY_HEADER_SIZE:_ENTRY_HEADER_SIZE + key_len] \
                    .decode("utf-8", errors="replace")

        if key is None:
            idx += num_blocks
            continue

        # Validate: real cache keys are printable and look like URLs or
        # Chromium cache key prefixes (e.g. "1/0/_dk_...").  Skip ranking
        # nodes and other internal structures that decode as garbage.
        if not key.isprintable() or not (
            "://" in key or key[:4].isdigit()
        ):
            idx += num_blocks
            continue

        entries.append({
            "key": key,
            "creation_time_us": creation_time,
            "data_sizes": data_sizes,
            "data_addrs": data_addrs,
            "cache_name": _addr_to_filename(data_addrs[1]),
        })
        idx += num_blocks

    logger.debug("Parsed %d cache entries from data_1", len(entries))
    return entries


# URL extraction from cache keys

def _extract_url(key: str) -> str:
    """Extract the actual URL from a Chromium cache key.

    Keys may have a partition prefix like "1/0/_dk_<origin> <origin> <url>".
    """
    if " " in key:
        return key.rsplit(" ", 1)[-1]
    return key


# Search query extraction

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

    qs_raw = params.get("qs", [""])[0]
    form_raw = params.get("form", [""])[0]

    return SearchEntry(
        user_typed=unquote_plus(params.get("pq", [""])[0]),
        bing_searched=unquote_plus(q),
        query_method=_QS_LABELS.get(qs_raw, qs_raw),
        search_source=_FORM_LABELS.get(form_raw, form_raw),
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


# Path discovery

_RELATIVE_CACHE_PATH = os.path.join(
    "LocalState", "EBWebView", "Default", "Cache", "Cache_Data"
)

def find_cache_data(path: str | Path) -> Path | None:
    """Locate the Cache_Data directory from a direct path or broader tree."""
    p = Path(path)

    # Direct path to Cache_Data
    if p.is_dir() and p.name == "Cache_Data" and (p / "data_1").is_file():
        return p

    # Known relative location under CBS package
    candidate = p / _RELATIVE_CACHE_PATH
    if candidate.is_dir() and (candidate / "data_1").is_file():
        return candidate

    # Walk
    logger.debug("Searching for Cache_Data under %s …", p)
    for root, dirs, files in os.walk(p):
        if "data_1" in files and Path(root).name == "Cache_Data":
            full = Path(root)
            if full.match("**/EBWebView/Default/Cache/Cache_Data"):
                logger.debug("Found: %s", full)
                return full

    return None


# Core parser

def parse_cache(cache_dir: str | Path) -> dict:
    """
    Parse the EBWebView blockfile cache and return a dict with:
      - search_entries: list[SearchEntry]
      - cache_dir: str
    """
    cache_dir = Path(cache_dir)
    block_cache: dict[str, bytes] = {}

    raw_entries = _parse_entries(cache_dir)

    search_entries: list[SearchEntry] = []

    for entry in raw_entries:
        url = _extract_url(entry["key"])

        # Only process Bing search URLs
        if "bing.com" not in url:
            continue

        # Parse HTTP info from stream 0 (timestamps + headers)
        headers_data = _read_at_addr(
            entry["data_addrs"][0], cache_dir, block_cache
        )
        http_info = _parse_http_info(headers_data, entry["data_sizes"][0])

        se = _parse_search_entry(
            url,
            last_accessed=_chromium_time(http_info.get("request_time", 0)),
            record_created_time=_chromium_time(entry["creation_time_us"]),
            server_time=http_info.get("date", ""),
            content_type=http_info.get("content-type", ""),
            content_length=entry["data_sizes"][1],
            cache_name=entry["cache_name"],
        )
        if se:
            search_entries.append(se)

    # Sort by last accessed time descending
    search_entries.sort(key=lambda e: e.last_accessed, reverse=True)

    logger.debug("Found %d Bing search entries", len(search_entries))

    return {
        "search_entries": search_entries,
        "cache_dir": str(cache_dir),
    }


# Output helpers

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


# CLI

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

    data = parse_cache(cache_dir)

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
