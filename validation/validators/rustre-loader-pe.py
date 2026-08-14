#!/usr/bin/env python3
"""Independent validator for rustre-loader-pe.

Re-implements the testable logic of the crate using Python stdlib + pefile/lief
so outputs can be diff-checked against the Rust implementation.
"""
from __future__ import annotations

import hashlib
import json
import math
import re
import struct
import subprocess
import sys
from collections import Counter
from typing import Any


def _pip_install(pkg: str) -> None:
    subprocess.check_call([sys.executable, "-m", "pip", "install", "--quiet", pkg])


try:
    import pefile  # type: ignore
except ImportError:
    _pip_install("pefile")
    import pefile  # type: ignore

try:
    import lief  # type: ignore
except ImportError:
    try:
        _pip_install("lief")
        import lief  # type: ignore
    except Exception:
        lief = None  # optional


# ---------- hashing ----------
def validator_md5_hex(data: bytes) -> str:
    return hashlib.md5(data).hexdigest()


def validator_sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def validator_normalise_dll_name(dll: str) -> str:
    s = dll.lower()
    for ext in (".dll", ".ocx", ".sys"):
        if s.endswith(ext):
            s = s[: -len(ext)]
            break
    return s


def validator_normalise_function_name(name: str) -> str:
    return name.lower()


def validator_make_entry(dll: str, func: str) -> str:
    return f"{validator_normalise_dll_name(dll)}.{validator_normalise_function_name(func)}"


def validator_imphash(path: str) -> str:
    pe = pefile.PE(path, fast_load=True)
    pe.parse_data_directories(
        directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"]]
    )
    return pe.get_imphash()


# ---------- entropy ----------
def validator_byte_histogram(data: bytes) -> list[int]:
    h = [0] * 256
    for b in data:
        h[b] += 1
    return h


def validator_shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    n = len(data)
    h = 0.0
    for c in Counter(data).values():
        p = c / n
        h -= p * math.log2(p)
    return h


def validator_most_common_byte(data: bytes) -> tuple[int, int]:
    if not data:
        return (0, 0)
    h = validator_byte_histogram(data)
    idx = max(range(256), key=lambda i: h[i])
    return (idx, h[idx])


def validator_chi_squared(data: bytes) -> float:
    if not data:
        return 0.0
    n = len(data)
    exp = n / 256.0
    h = validator_byte_histogram(data)
    return sum((c - exp) ** 2 / exp for c in h)


def validator_looks_packed(data: bytes) -> bool:
    return validator_shannon_entropy(data) >= 7.2


# ---------- strings ----------
def validator_is_printable_ascii(b: int) -> bool:
    return 0x20 <= b < 0x7F or b in (0x09,)


def validator_scan_ascii(data: bytes, min_len: int = 6) -> list[dict]:
    out = []
    start = None
    for i, b in enumerate(data):
        if validator_is_printable_ascii(b):
            if start is None:
                start = i
        else:
            if start is not None and i - start >= min_len:
                out.append({"offset": start, "value": data[start:i].decode("ascii", "replace"), "encoding": "ascii"})
            start = None
    if start is not None and len(data) - start >= min_len:
        out.append({"offset": start, "value": data[start:].decode("ascii", "replace"), "encoding": "ascii"})
    return out


def validator_scan_utf16le(data: bytes, min_len: int = 6) -> list[dict]:
    out = []
    start = None
    i = 0
    n = len(data) - 1
    while i < n:
        lo, hi = data[i], data[i + 1]
        if hi == 0 and validator_is_printable_ascii(lo):
            if start is None:
                start = i
            i += 2
        else:
            if start is not None:
                length = (i - start) // 2
                if length >= min_len:
                    s = data[start:i].decode("utf-16le", "replace")
                    out.append({"offset": start, "value": s, "encoding": "utf16le"})
            start = None
            i += 1
    if start is not None:
        length = (len(data) - start) // 2
        if length >= min_len:
            s = data[start : start + length * 2].decode("utf-16le", "replace")
            out.append({"offset": start, "value": s, "encoding": "utf16le"})
    return out


_CLASSIFY = [
    ("url", re.compile(r"^(https?|ftp)://", re.I)),
    ("path_win", re.compile(r"^[A-Za-z]:\\")),
    ("path_unix", re.compile(r"^/(usr|etc|var|home|tmp)/")),
    ("registry", re.compile(r"^(HKEY_|SOFTWARE\\|SYSTEM\\)", re.I)),
    ("email", re.compile(r"[\w.+-]+@[\w-]+\.[\w.-]+")),
    ("guid", re.compile(r"\{[0-9A-Fa-f-]{36}\}")),
]


def validator_classify_string(s: str) -> str | None:
    for tag, rx in _CLASSIFY:
        if rx.search(s):
            return tag
    return None


# ---------- PE parsing ----------
def validator_rva_to_file_offset(rva: int, sections: list[dict]) -> int | None:
    for s in sections:
        va = s["virtual_address"]
        vsz = s.get("virtual_size") or s["raw_size"]
        if va <= rva < va + vsz:
            return s["raw_offset"] + (rva - va)
    return None


def validator_find_overlay_offset(sections: list[dict], file_size: int) -> int | None:
    if not sections:
        return None
    end = max(s["raw_offset"] + s["raw_size"] for s in sections)
    return end if end < file_size else None


_SFX_MAGICS = {
    b"7z\xbc\xaf\x27\x1c": "7zip",
    b"PK\x03\x04": "zip",
    b"Rar!\x1a\x07\x00": "rar",
    b"Rar!\x1a\x07\x01\x00": "rar5",
    b"MSCF": "cab",
}


def validator_detect_sfx_kind(data: bytes) -> str:
    # scan first 4MB for magic
    window = data[: 4 * 1024 * 1024]
    for magic, kind in _SFX_MAGICS.items():
        if magic in window:
            return kind
    if b"Nullsoft" in window or b"NSIS" in window:
        return "nsis"
    if b"Inno Setup" in window:
        return "inno"
    return "none"


def validator_parse_pe(path: str) -> dict[str, Any]:
    pe = pefile.PE(path)
    sections = []
    for s in pe.sections:
        sections.append({
            "name": s.Name.rstrip(b"\x00").decode("utf-8", "replace"),
            "virtual_address": s.VirtualAddress,
            "virtual_size": s.Misc_VirtualSize,
            "raw_offset": s.PointerToRawData,
            "raw_size": s.SizeOfRawData,
            "characteristics": s.Characteristics,
        })
    imports = []
    if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            dll = entry.dll.decode("utf-8", "replace")
            for imp in entry.imports:
                imports.append({
                    "dll": dll,
                    "name": imp.name.decode("utf-8", "replace") if imp.name else None,
                    "ordinal": imp.ordinal,
                    "address": imp.address,
                })
    exports = []
    if hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
        for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
            exports.append({
                "name": exp.name.decode("utf-8", "replace") if exp.name else None,
                "ordinal": exp.ordinal,
                "address": exp.address,
            })
    pdb = None
    if hasattr(pe, "DIRECTORY_ENTRY_DEBUG"):
        for d in pe.DIRECTORY_ENTRY_DEBUG:
            if hasattr(d.entry, "PdbFileName"):
                pdb = {
                    "path": d.entry.PdbFileName.rstrip(b"\x00").decode("utf-8", "replace"),
                    "age": getattr(d.entry, "Age", None),
                }
                break
    reloc_count = 0
    if hasattr(pe, "DIRECTORY_ENTRY_BASERELOC"):
        for blk in pe.DIRECTORY_ENTRY_BASERELOC:
            reloc_count += len(blk.entries)
    return {
        "machine": pe.FILE_HEADER.Machine,
        "subsystem": pe.OPTIONAL_HEADER.Subsystem,
        "image_base": pe.OPTIONAL_HEADER.ImageBase,
        "entry_point": pe.OPTIONAL_HEADER.AddressOfEntryPoint,
        "dll_characteristics": pe.OPTIONAL_HEADER.DllCharacteristics,
        "timestamp": pe.FILE_HEADER.TimeDateStamp,
        "sections": sections,
        "imports": imports,
        "exports": exports,
        "pdb": pdb,
        "relocation_count": reloc_count,
        "has_tls": hasattr(pe, "DIRECTORY_ENTRY_TLS"),
        "is_signed": pe.OPTIONAL_HEADER.DATA_DIRECTORY[
            pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_SECURITY"]
        ].Size > 0,
        "imphash": pe.get_imphash(),
    }


# ---------- dispatch ----------
_DISPATCH = {
    "md5_hex": lambda i: validator_md5_hex(bytes.fromhex(i["data_hex"])),
    "sha256_hex": lambda i: validator_sha256_hex(bytes.fromhex(i["data_hex"])),
    "normalise_dll_name": lambda i: validator_normalise_dll_name(i["dll"]),
    "normalise_function_name": lambda i: validator_normalise_function_name(i["name"]),
    "make_entry": lambda i: validator_make_entry(i["dll"], i["func"]),
    "imphash": lambda i: validator_imphash(i["path"]),
    "byte_histogram": lambda i: validator_byte_histogram(bytes.fromhex(i["data_hex"])),
    "shannon_entropy": lambda i: validator_shannon_entropy(bytes.fromhex(i["data_hex"])),
    "most_common_byte": lambda i: validator_most_common_byte(bytes.fromhex(i["data_hex"])),
    "chi_squared": lambda i: validator_chi_squared(bytes.fromhex(i["data_hex"])),
    "looks_packed": lambda i: validator_looks_packed(bytes.fromhex(i["data_hex"])),
    "scan_ascii": lambda i: validator_scan_ascii(bytes.fromhex(i["data_hex"]), i.get("min_len", 6)),
    "scan_utf16le": lambda i: validator_scan_utf16le(bytes.fromhex(i["data_hex"]), i.get("min_len", 6)),
    "classify_string": lambda i: validator_classify_string(i["s"]),
    "rva_to_file_offset": lambda i: validator_rva_to_file_offset(i["rva"], i["sections"]),
    "find_overlay_offset": lambda i: validator_find_overlay_offset(i["sections"], i["file_size"]),
    "detect_sfx_kind": lambda i: validator_detect_sfx_kind(bytes.fromhex(i["data_hex"])),
    "parse_pe": lambda i: validator_parse_pe(i["path"]),
}


def main() -> None:
    if not sys.stdin.isatty():
        try:
            req = json.load(sys.stdin)
        except Exception:
            req = None
        if req:
            fn = req.get("function")
            inp = req.get("input", {})
            if fn not in _DISPATCH:
                print(json.dumps({"error": f"unknown function {fn}", "available": list(_DISPATCH)}))
                return
            out = _DISPATCH[fn](inp)
            print(json.dumps({"function": fn, "output": out}, default=str))
            return

    # smoke tests
    sample = b"Hello, World!\x00\x00\x00This is a test string for validator."
    print(json.dumps({
        "md5": validator_md5_hex(sample),
        "sha256": validator_sha256_hex(sample),
        "entropy": validator_shannon_entropy(sample),
        "chi2": validator_chi_squared(sample),
        "ascii_strings": validator_scan_ascii(sample, 4),
        "normalise_dll": validator_normalise_dll_name("KERNEL32.DLL"),
        "make_entry": validator_make_entry("KERNEL32.DLL", "CreateFileA"),
        "classify_url": validator_classify_string("https://example.com"),
        "sfx": validator_detect_sfx_kind(b"PK\x03\x04somezipdata"),
    }, indent=2, default=str))


if __name__ == "__main__":
    main()
