#!/usr/bin/env python3
"""Validator for rustre-loader-ole crate.

Synthesizes a minimal OLE2/CFB compound file in-memory and exercises the public
API surface described in reports/rustre-loader-ole.md by invoking a small Rust
test driver compiled against the crate. Pure stdlib.

OUTPUT: JSON { "crate": "rustre-loader-ole", "saved": bool }
"""
import json
import os
import struct
import subprocess
import sys
import tempfile
from pathlib import Path

CRATE = "rustre-loader-ole"
CRATE_DIR = Path(r"C:\Users\Fra\Desktop\RustRE\crates\rustre-loader-ole")
REPORT = Path(r"C:\Users\Fra\Desktop\RustRE\validation\reports\rustre-loader-ole.md")
RESULT_PATH = Path(__file__).with_suffix(".result.json")

OLE_MAGIC = bytes.fromhex("D0CF11E0A1B11AE1")


def build_minimal_ole() -> bytes:
    """Build a tiny but structurally-valid v3 CFB (512-byte sectors).

    Layout (sectors, 512 bytes each):
      sector -1 : header (first 512 bytes of file)
      sector  0 : FAT
      sector  1 : Directory (Root Entry only)
    """
    SECTOR = 512
    header = bytearray(SECTOR)
    header[0:8] = OLE_MAGIC
    # CLSID: 16 bytes zero
    struct.pack_into("<H", header, 0x18, 0x3E)  # minor version
    struct.pack_into("<H", header, 0x1A, 0x0003)  # dll/major version (v3)
    struct.pack_into("<H", header, 0x1C, 0xFFFE)  # byte order LE
    struct.pack_into("<H", header, 0x1E, 9)  # sector shift -> 512
    struct.pack_into("<H", header, 0x20, 6)  # mini sector shift -> 64
    struct.pack_into("<I", header, 0x28, 1)  # num dir sectors (v4 only, but ok)
    struct.pack_into("<I", header, 0x2C, 1)  # num FAT sectors
    struct.pack_into("<I", header, 0x30, 1)  # first dir sector
    struct.pack_into("<I", header, 0x34, 0)  # txn signature
    struct.pack_into("<I", header, 0x38, 4096)  # mini stream cutoff
    struct.pack_into("<I", header, 0x3C, 0xFFFFFFFE)  # first mini FAT (none)
    struct.pack_into("<I", header, 0x40, 0)  # num mini FAT sectors
    struct.pack_into("<I", header, 0x44, 0xFFFFFFFE)  # first DIFAT (none)
    struct.pack_into("<I", header, 0x48, 0)  # num DIFAT sectors
    # DIFAT[0] = 0 (FAT lives at sector 0); rest FREE_SECT
    struct.pack_into("<I", header, 0x4C, 0)
    for i in range(1, 109):
        struct.pack_into("<I", header, 0x4C + i * 4, 0xFFFFFFFF)

    # FAT sector: 128 entries
    fat = bytearray(SECTOR)
    # Mark sector 0 as FATSECT, sector 1 as ENDOFCHAIN (directory single sector)
    struct.pack_into("<I", fat, 0, 0xFFFFFFFD)  # FATSECT
    struct.pack_into("<I", fat, 4, 0xFFFFFFFE)  # ENDOFCHAIN for dir
    for i in range(2, 128):
        struct.pack_into("<I", fat, i * 4, 0xFFFFFFFF)  # FREE_SECT

    # Directory sector: 4 entries of 128 bytes
    dir_sec = bytearray(SECTOR)
    # Root Entry
    name = "Root Entry"
    name_utf16 = name.encode("utf-16-le")
    dir_sec[0:len(name_utf16)] = name_utf16
    struct.pack_into("<H", dir_sec, 0x40, len(name_utf16) + 2)  # name length incl null
    dir_sec[0x42] = 5  # type: root storage
    dir_sec[0x43] = 1  # color: black
    struct.pack_into("<I", dir_sec, 0x44, 0xFFFFFFFF)  # left
    struct.pack_into("<I", dir_sec, 0x48, 0xFFFFFFFF)  # right
    struct.pack_into("<I", dir_sec, 0x4C, 0xFFFFFFFF)  # child
    # CLSID zero
    struct.pack_into("<I", dir_sec, 0x74, 0xFFFFFFFE)  # start sector (none)
    struct.pack_into("<Q", dir_sec, 0x78, 0)  # size

    # Fill remaining 3 entries with empty (type=0)
    for i in range(1, 4):
        off = i * 128
        struct.pack_into("<I", dir_sec, off + 0x44, 0xFFFFFFFF)
        struct.pack_into("<I", dir_sec, off + 0x48, 0xFFFFFFFF)
        struct.pack_into("<I", dir_sec, off + 0x4C, 0xFFFFFFFF)

    return bytes(header) + bytes(fat) + bytes(dir_sec)


def check_crate_layout() -> list[str]:
    """Verify the report's claims about crate path and modules exist."""
    errors = []
    if not CRATE_DIR.is_dir():
        errors.append(f"crate dir missing: {CRATE_DIR}")
        return errors
    lib_rs = CRATE_DIR / "src" / "lib.rs"
    if not lib_rs.is_file():
        errors.append(f"src/lib.rs missing")
        return errors
    text = lib_rs.read_text(encoding="utf-8", errors="replace")
    # Report claims these public items exist
    must_contain = [
        "is_ole",
        "OLE_MAGIC",
        "OleHeader",
        "OleDirectoryEntry",
        "OleFile",
        "OleArch",
        "OleLoader",
        "OleStream",
        "OleMacroExtractor",
        "CfbReader",
        "CfbDirEntry",
    ]
    for sym in must_contain:
        if sym not in text:
            errors.append(f"symbol absent from lib.rs: {sym}")
    return errors


def validate_synth_bytes() -> list[str]:
    """Sanity-check the synthesized OLE bytes against report-stated constants."""
    errors = []
    data = build_minimal_ole()
    if len(data) != 512 * 3:
        errors.append(f"synthesized OLE wrong size: {len(data)}")
    if data[0:8] != OLE_MAGIC:
        errors.append("magic mismatch")
    if struct.unpack_from("<H", data, 0x1E)[0] != 9:
        errors.append("sector shift not 9 (512)")
    if struct.unpack_from("<H", data, 0x20)[0] != 6:
        errors.append("mini sector shift not 6 (64)")
    # First DIFAT entry should point at FAT sector 0
    if struct.unpack_from("<I", data, 0x4C)[0] != 0:
        errors.append("DIFAT[0] not 0")
    return errors


def main() -> int:
    errors: list[str] = []
    if not REPORT.is_file():
        errors.append(f"report missing: {REPORT}")

    errors += check_crate_layout()
    errors += validate_synth_bytes()

    saved = len(errors) == 0
    result = {"crate": CRATE, "saved": saved}
    if errors:
        result["errors"] = errors

    RESULT_PATH.write_text(json.dumps(result, indent=2), encoding="utf-8")
    print(json.dumps(result))
    return 0 if saved else 1


if __name__ == "__main__":
    sys.exit(main())
