#!/usr/bin/env python3
"""
Windows Known Folder GUID mappings.

Shared reference for resolving Known Folder GUIDs (e.g. {1AC14E77-...})
to their environment-variable paths (e.g. %SystemRoot%\\System32).
Used by multiple CBS forensic parsers.
"""

import re

# Regex for GUID paths

GUID_RE = re.compile(r"^\{[0-9A-Fa-f-]{36}\}")

# Known Folder GUIDs

KNOWN_FOLDER_GUIDS = {
    "{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}": r"%SystemRoot%\System32",
    "{7C5A40EF-A0FB-4BFC-874A-C0F2E0B9FA8E}": r"%ProgramFiles%",
    "{6D809377-6AF0-444B-8957-A3773F02200E}": r"%ProgramFiles(x86)%",
    "{D65231B0-B2F1-4857-A4CE-A8E7C6EA7D27}": r"%SystemRoot%\SysWOW64",
    "{F38BF404-1D43-42F2-9305-67DE0B28FC23}": r"%SystemRoot%",
    "{905E63B6-C1BF-494E-B29C-65B732D3D21A}": r"%ProgramFiles%\Common Files",
    "{F7F1ED05-9F6D-47A2-AAAE-29D317C6F066}": r"%ProgramFiles(x86)%\Common Files",
    "{62AB5D82-FDC1-4DC3-A9DD-070D1D495D97}": r"%ProgramData%",
    "{FDD39AD0-238F-46AF-ADB4-6C85480369C7}": r"%UserProfile%\Documents",
    "{374DE290-123F-4565-9164-39C4925E467B}": r"%UserProfile%\Downloads",
    "{1777F761-68AD-4D8A-87BD-30B759FA33DD}": r"%UserProfile%\Favorites",
    "{BFB9D5E0-C6A9-404C-B2B2-AE6DB6AF4968}": r"%UserProfile%\Links",
    "{4BD8D571-6D19-48D3-BE97-422220080E43}": r"%UserProfile%\Music",
    "{33E28130-4E1E-4676-835A-98395C3BC3BB}": r"%UserProfile%\Pictures",
    "{18989B1D-99B5-455B-841C-AB7C74E4DDFC}": r"%UserProfile%\Videos",
    "{5E6C858F-0E22-4760-9AFE-EA3317B67173}": r"%UserProfile%",
    "{A77F5D77-2E2B-44C3-A6A2-ABA601054A51}": r"%AppData%",
    "{3EB685DB-65F9-4CF6-A03A-E3EF65729F3D}": r"%LocalAppData%",
    "{B97D20BB-F46A-4C97-BA10-5E3608430854}": r"%AppData%\Microsoft\Windows\Start Menu",
    "{A4115719-D62E-491D-AA7C-E74B8BE3B067}": r"%AppData%\Microsoft\Windows\Start Menu\Programs",
    "{625B53C3-AB48-4EC1-BA1F-A1EF4146FC19}": r"%AppData%\Microsoft\Windows\Start Menu\Programs\Startup",
    "{0139D44E-6AFE-49F2-8690-3DAFCAE6FFB8}": r"%ProgramData%\Microsoft\Windows\Start Menu\Programs",
    "{B4BFCC3A-DB2C-424C-B029-7FE99A87C641}": r"%UserProfile%\Desktop",
    "{C4AA340D-F20F-4863-AFEF-F87EF2E6BA25}": r"%Public%\Desktop",
    "{DFDF76A2-C82A-4D63-906A-5644AC457385}": r"%Public%",
}


def resolve_guid_path(path: str) -> str:
    """Replace a leading Known Folder GUID with its environment-variable path."""
    m = GUID_RE.match(path)
    if not m:
        return path
    guid = m.group(0)
    folder = KNOWN_FOLDER_GUIDS.get(guid.upper()) or KNOWN_FOLDER_GUIDS.get(guid)
    if folder:
        return folder + path[len(guid):]
    return path
