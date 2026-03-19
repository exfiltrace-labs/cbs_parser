#!/usr/bin/env python3
"""
CBS Parser - main entry point for all CBS forensic parsers.

Runs all three Start Menu artifact parsers by default, or a subset
selected with --parser.

Usage:
    python cbs_parser.py -i <path> -o <output_dir> [--parser ...] [--json] [-v]
    python cbs_parser.py -i <path> -o <output_dir> --xlsx
"""

import argparse
import csv
import subprocess
import sys
from pathlib import Path

PARSERS = {
    "indexeddb": {
        "script": "parsers/cbs_indexeddb_parser.py",
        "label": "IndexedDB (LevelDB)",
    },
    "cache": {
        "script": "parsers/cbs_cache_parser.py",
        "label": "EBWebView Cache",
    },
    "appsindex": {
        "script": "parsers/cbs_appsindex_parser.py",
        "label": "AppsIndex.db",
    },
}

PARSER_ORDER = ["indexeddb", "cache", "appsindex"]


def csvs_to_xlsx(out_dir, xlsx_path):
    """Combine all CSVs in out_dir into a single .xlsx with one sheet per CSV."""
    from openpyxl import Workbook

    csv_files = sorted(out_dir.glob("*.csv"))
    if not csv_files:
        print("  No CSV files found to combine into XLSX.")
        return

    wb = Workbook()
    wb.remove(wb.active)

    for csv_file in csv_files:
        sheet_name = csv_file.stem[:31]
        ws = wb.create_sheet(title=sheet_name)
        with open(csv_file, newline="", encoding="utf-8") as f:
            for row in csv.reader(f):
                ws.append(row)

    wb.save(xlsx_path)
    print(f"  XLSX written: {xlsx_path} ({len(csv_files)} sheets)")


def build_command(script_path, args):
    """Build the subprocess command list for a parser."""
    cmd = [sys.executable, str(script_path), "-i", str(args.input)]
    if args.output:
        cmd += ["-o", str(args.output)]
    if args.json:
        cmd.append("--json")
    if args.verbose:
        cmd.append("-v")
    return cmd


def main():
    parser = argparse.ArgumentParser(
        description="CBS forensic toolkit - run one or more Start Menu artifact parsers.",
    )
    parser.add_argument(
        "-i", "--input", required=True, type=Path,
        help="Path to evidence directory (drive image mount, CBS package dir, etc.)",
    )
    parser.add_argument(
        "-o", "--output", type=Path,
        help="Output directory (recommended when running multiple parsers)",
    )
    parser.add_argument(
        "--parser", nargs="+", choices=PARSER_ORDER, default=PARSER_ORDER,
        help="Parser(s) to run (default: all three)",
    )
    parser.add_argument(
        "--json", action="store_true",
        help="Emit JSON Lines output instead of CSV",
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true",
        help="Enable debug logging",
    )
    parser.add_argument(
        "--xlsx", action="store_true",
        help="After parsing, combine all CSVs into a single .xlsx workbook",
    )
    args = parser.parse_args()

    if args.xlsx and not args.output:
        parser.error("--xlsx requires --output / -o")
    if args.xlsx and args.json:
        parser.error("--xlsx and --json are mutually exclusive (XLSX is built from CSVs)")

    script_dir = Path(__file__).resolve().parent
    selected = args.parser
    results = {}

    for name in selected:
        info = PARSERS[name]
        script_path = script_dir / info["script"]
        label = info["label"]

        print(f"\n=== Running: {label} ===")

        if not script_path.exists():
            print(f"  ERROR: {script_path.name} not found")
            results[name] = (1, "script not found")
            continue

        cmd = build_command(script_path, args)
        result = subprocess.run(cmd)
        if result.returncode == 0:
            results[name] = (0, "success")
        else:
            results[name] = (result.returncode, "failed")
            print(f"  WARNING: {label} exited with code {result.returncode}")

    # Summary
    succeeded = sum(1 for rc, _ in results.values() if rc == 0)
    total = len(results)

    print(f"\n{'='*50}")
    print(f"Summary: {succeeded}/{total} parsers completed successfully.")
    for name in selected:
        rc, status = results[name]
        label = PARSERS[name]["label"]
        marker = "OK" if rc == 0 else "FAILED"
        print(f"  {label}: {marker}")
    if args.output:
        print(f"Output directory: {args.output}")

    if args.xlsx and succeeded > 0:
        xlsx_path = args.output / "cbs_results.xlsx"
        print()
        csvs_to_xlsx(args.output, xlsx_path)

    print()

    sys.exit(0 if succeeded > 0 else 1)


if __name__ == "__main__":
    main()
