# CBS Forensic Toolkit

The **CBS Forensic Toolkit** parses forensic artifacts from the Windows Start Menu search subsystem (`MicrosoftWindows.Client.CBS_cw5n1h2txyewy`). It is able to extract search history, cached Bing queries, and application launch records (including timestamps and counts) into CSVs or a single Excel workbook.

## Artifacts

The CBS package lives at:

```
%LOCALAPPDATA%\Packages\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\
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
python cbs_parser.py -i <path_to_evidence> -o ./results/

# Run all three parsers, produce a single Excel workbook
python cbs_parser.py -i <path_to_evidence> -o ./results/ --xlsx

# Run a specific parser
python cbs_parser.py -i <path_to_evidence> -o ./results/ --parser indexeddb

# Run two parsers
python cbs_parser.py -i <path_to_evidence> -o ./results/ --parser cache appsindex

# JSON Lines output
python cbs_parser.py -i <path_to_evidence> -o ./results/ --json

# Verbose (debug) logging
python cbs_parser.py -i <path_to_evidence> -o ./results/ -v
```

The input path (`-i`) can be a drive image mount, the CBS package directory, or a path directly to the artifact. Each parser will search for the expected path pattern within whatever you provide.

### Options

| Flag | Required | Description |
|------|----------|-------------|
| `-i, --input` | Yes | Path to evidence directory |
| `-o, --output` | Yes | Output directory for parsed results |
| `--parser` | No | One or more of: `indexeddb`, `cache`, `appsindex` (default: all) |
| `--timeout` | No | Per-parser timeout in seconds (default: no limit) |
| `--json` | No | JSON output instead of CSV |
| `--xlsx` | No | Combine all CSVs into a single `cbs_results.xlsx` workbook |
| `-v, --verbose` | No | Debug logging to stderr |

### Standalone parsers

Each parser also works independently and can be run from the `/parsers` directory with similar usage flags:

```bash
python parsers/cbs_indexeddb_parser.py -i <path_to_evidence> -o ./results/
python parsers/cbs_cache_parser.py -i <path_to_evidence> -o ./results/
python parsers/cbs_appsindex_parser.py -i <path_to_evidence> -o ./results/
```

## Output Files

### `indexeddb_summary.csv`

Latest state for each search prefix and target combination.

| Column | Description |
|--------|-------------|
| `target` | Application, file, folder, settings page, or web-query identifier |
| `resolved_target` | Human-readable path. For applications stored under a Known Folder GUID, the GUID is expanded (e.g., `{1AC14E77-...}\cmd.exe` → `%SystemRoot%\System32\cmd.exe`). For files and folders, the `file:` prefix is stripped and forward slashes are converted to backslashes. AUMIDs, raw paths, URI handlers, settings page IDs, and web-search query strings are passed through unchanged. |
| `type` | Category derived from the underlying `groupType`: `App` (0), `Settings` (1), `Image` (4), `Video` (5), `Document` (7), `Folder` (8), `Web` (11). Unrecognised group types appear as `Unknown(<n>)`. |
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
| `target` | Application, file, folder, settings page, or web-query identifier |
| `resolved_target` | Human-readable path (same resolution rules as in `indexeddb_summary.csv`) |
| `type` | Category derived from the underlying `groupType`: `App`, `Settings`, `Image`, `Video`, `Document`, `Folder`, `Web`, or `Unknown(<n>)` for any value not validated in this paper |

### `cache_searches.csv`

Bing search URLs extracted from the EBWebView disk cache with query parameters unfurled.

| Column | Description |
|--------|-------------|
| `user_typed` | What the user typed into the Start Menu |
| `bing_searched` | The full query sent to Bing |
| `qs` | Raw `qs=` parameter from the cached URL. Bing's "SuggestionType" code indicating how the query was formed (e.g., `SW`, `UT`, `MB`, `EP`, `LS`, `AS`, `LT`, `OS`, `SC`). The semantics of each code are not officially documented; do not infer them without validation. |
| `form` | Raw `form=` parameter from the cached URL. Bing's source-of-search code (e.g., `WMSAUT` for Start Menu auto-suggest, `WMSMAN` for manually-typed Start Menu queries). Also undocumented. |
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
| `resolved_path` | Resolved filesystem path when the underlying `serializedId` is a Known Folder GUID + relative path (e.g., `%ProgramFiles%\VideoLAN\VLC\vlc.exe`). For UWP entries and for Win32 apps registered under an AUMID rather than a fixed install path (e.g., `Brave`, `com.squirrel.Discord.Discord`, `Microsoft.Windows.Explorer`), there is no path to resolve and this column falls back to the AUMID itself. |
| `launch_count` | Total launches (from any source, not just Start Menu) |
| `app_type` | Win32 or UWP |
| `app_id` | Internal application identifier |
| `c_rank` | Numeric rank value from the `tiles.cRank` column. Presumed to feed Start Menu ordering. Apps without a learned rank typically carry the value stored in `metadata.defaultRank`. The exact semantics are not officially documented. |

## Acknowledgements

The IndexedDB and cache parsers leverage [ccl_chromium_reader](https://github.com/cclgroupltd/ccl_chromium_reader) by [CCL Forensics](https://www.cclsolutionsgroup.com/). The IndexedDB parser uses it for LevelDB parsing and V8 value deserialization, and the cache parser uses it for Chromium blockfile decoding.

Additionally, recognition is given to the work published by *thedigitaldetective* in [Introducing AppsIndex.db: New Windows 11 Artifact for Tracking Start Menu Application Execution](https://detect.fyi/introducing-appsindex-db-new-windows-11-artifact-for-tracking-start-menu-application-execution-b294c8e764fa). During research and development of this tool, it was observed that this may have been among the first public documentations of the `AppsIndex.db` artifact.

## License

MIT - see [LICENSE](LICENSE).
