# CBS Forensic Toolkit

The **CBS Forensic Toolkit** parses forensic artifacts from the Windows Start Menu search subsystem (`MicrosoftWindows.Client.CBS_cw5n1h2txyewy`). It is able to extract search history, cached Bing queries, and application launch records (including timestamps and counts) into CSVs or a single Excel workbook.

No mainstream forensic tool currently parses all of these artifacts.

## Artifacts

The CBS package lives at:

```
C:\Users\<user>\AppData\Local\Packages\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\
```

This toolkit currently parses three main artifacts of value:

| Parser | Artifact | Forensic Value |
|--------|----------|-----------------|
| **IndexedDB** | `LocalState/EBWebView/Default/IndexedDB/` (LevelDB) | **Start Menu search interactions**: what the user typed, what they launched, and when |
| **Cache** | `LocalState/EBWebView/Default/Cache/Cache_Data/` (Chromium blockfile cache) | Cached **Bing search URLs** with unfurled query parameters: internet searches performed from the Start Menu even without opening a browser |
| **AppsIndex** | `LocalState/Search/AppsIndex.db` (SQLite) | Installed **Start Menu applications** and their **launch counts** from any execution source (Start Menu, Taskbar, direct execution, etc.) |

## Installation

```bash
git clone https://github.com/exfiltrace-labs/cbs_parser
cd cbs_parser
pip install -r requirements.txt
```

Requires Python 3.10+.

## Usage

```bash
# Run all three parsers, output CSVs
python cbs_parser.py -i C/Users/bob/AppData/Local/Packages/MicrosoftWindows.Client.CBS_cw5n1h2txyewy/ -o ./results/

# Run all three parsers, produce a single Excel workbook
python cbs_parser.py -i C/Users/bob/AppData/Local/Packages/MicrosoftWindows.Client.CBS_cw5n1h2txyewy/ -o ./results/ --xlsx

# Run a specific parser
python cbs_parser.py -i C/Users/bob/AppData/Local/Packages/MicrosoftWindows.Client.CBS_cw5n1h2txyewy/ -o ./results/ --parser indexeddb

# Run two parsers
python cbs_parser.py -i C/Users/bob/AppData/Local/Packages/MicrosoftWindows.Client.CBS_cw5n1h2txyewy/ -o ./results/ --parser cache appsindex

# JSON Lines output to stdout
python cbs_parser.py -i ./C/ --json

# Verbose (debug) logging
python cbs_parser.py -i ./C/ -o ./results/ -v
```

The input path (`-i`) can be a drive image mount, the CBS package directory, or a path directly to the artifact. Each parser will search for the expected path pattern within whatever you provide.

### Options

| Flag | Required | Description |
|------|----------|-------------|
| `-i, --input` | Yes | Path to evidence directory |
| `-o, --output` | No | Output directory for CSVs and optional XLSX (default: stdout) |
| `--parser` | No | One or more of: `indexeddb`, `cache`, `appsindex` (default: all) |
| `--json` | No | JSON output instead of CSV |
| `--xlsx` | No | Combine all CSVs into a single `cbs_results.xlsx` workbook (requires `-o`) |
| `-v, --verbose` | No | Debug logging to stderr |

### Standalone parsers

Each parser also works independently and can be run from the `/parsers` directory with similar usage flags:

```bash
python parsers/cbs_indexeddb_parser.py -i ./C/ -o ./results/
python parsers/cbs_cache_parser.py -i ./C/ -o ./results/
python parsers/cbs_appsindex_parser.py -i ./C/ -o ./results/
```

## Output Files

### `indexeddb_summary.csv`

Latest state for each search prefix and target combination.

| Column | Description |
|--------|-------------|
| `target` | Application, file, or setting identifier |
| `resolved_target` | Human-readable path (Known Folder GUIDs resolved) |
| `type` | App, Settings, File, etc. |
| `launch_count` | Total launches from this search prefix |
| `last_launched` | UTC timestamp of most recent launch |
| `preview_count` | Times hovered/previewed without launching |
| `last_previewed` | UTC timestamp of most recent preview |

### `indexeddb_timeline.csv`

Individual launch events reconstructed from LevelDB version diffs, presented in a timeline format.

| Column | Description |
|--------|-------------|
| `timestamp` | UTC timestamp of the event |
| `search_prefix` | What the user typed (includes typos) |
| `target` | Application, file, or setting identifier |
| `resolved_target` | Human-readable path |
| `type` | App, Settings, File, etc. |

### `cache_searches.csv`

Bing search URLs extracted from the EBWebView disk cache with query parameters unfurled.

| Column | Description |
|--------|-------------|
| `user_typed` | What the user typed into the Start Menu |
| `bing_searched` | The full query sent to Bing |
| `query_method` | How the query was formed (typed, suggestion, etc.) |
| `search_source` | Where the search originated |
| `session_id` | Bing session identifier |
| `last_accessed` | When the cache entry was last accessed |
| `record_created_time` | When the cache entry was created |
| `server_time` | Timestamp from the HTTP response |
| `language` | Language code from the request |
| `country` | Country code from the request |
| `content_type` | HTTP content type |
| `content_length` | Response size in bytes |
| `url` | Full cached URL |
| `cache_name` | Cache block file containing this entry |

### `appsindex_apps.csv`

Applications registered in the Start Menu index with launch counts.

| Column | Description |
|--------|-------------|
| `display_name` | Application display name |
| `resolved_path` | Resolved file path or UWP package ID |
| `launch_count` | Total launches (from any source, not just Start Menu) |
| `app_type` | Win32 or UWP |
| `app_id` | Internal application identifier |

## Analysis Tips

1. **Build a timeline** - `indexeddb_timeline.csv` sorted by `timestamp` can show the user's recent Start Menu activity in sequence.

2. **Evidence of user intent** - `cache_searches.csv` can reveal what the user searched for from the Start Menu, even if they never opened a browser. Searches like "sdelete" or "how to delete history" could be indicative of anti-forensics. The cache parser is particularly valuable as it captures searches the user may not have realized were recorded.

3. **User profiling through typos** - The `search_prefix` column captures exactly what was typed, including misspellings (e.g., "poewrs" for PowerShell). Multiple prefixes pointing to the same target file or executable can help establish typing behavior.

4. **Cross-reference launch counts** - `appsindex_apps.csv` tracks launches from *all* sources (Taskbar, Run dialog, etc.), while `indexeddb_summary.csv` tracks only Start Menu launches. Comparing the two shows whether an application was typically launched from Start Menu or elsewhere. Discrepancies in run counts between AppsIndex.db, UserAssist, and Prefetch are expected, given that each artifact records activity using different methods and scopes.

## Acknowledgements

The IndexedDB parser leverages [ccl_chromium_reader](https://github.com/cclgroupltd/ccl_chromium_reader) by [CCL Forensics](https://www.cclsolutionsgroup.com/).

Additionally, recognition is given to the work published by *thedigitaldetective* in [Introducing AppsIndex.db: New Windows 11 Artifact for Tracking Start Menu Application Execution](https://detect.fyi/introducing-appsindex-db-new-windows-11-artifact-for-tracking-start-menu-application-execution-b294c8e764fa). During research and development of this tool, it was observed that this may have been among the first public documentations of the `AppsIndex.db` artifact.

## License

MIT - see [LICENSE](LICENSE).
