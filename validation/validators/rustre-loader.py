#!/usr/bin/env python3
"""
Standalone validator for the rustre-loader crate.

Reimplements the testable surface of rustre-loader in pure Python using stdlib
only, so its outputs can be diffed against the Rust crate's outputs.

Covered functions (validator_<name>):
  - validator_sha256(data)
  - validator_md5(data)
  - validator_format_detector_detect(data)       -> coarse BinaryFormat
  - validator_format_detector_is_elf(data)
  - validator_format_detector_is_pe(data)
  - validator_format_detector_is_macho(data)
  - validator_format_detector_is_java_class(data)
  - validator_auto_loader_detect_format(data)    -> fine DetectedFormat
  - validator_auto_loader_is_elf(data)
  - validator_auto_loader_is_macho(data)
  - validator_rich_total_virtual_size(sections)
  - validator_rich_section_at(sections, va)
  - validator_multi_loader_input_to_bytes(input_obj)
  - validator_multi_format_registry_probe_all(loaders)
  - validator_loader_coordinator_loader_count(register_calls)

Input/output: JSON over stdin/stdout. The stdin payload is
  { "function": "<name>", "args": { ... } }
and the response is
  { "ok": true, "result": <...> }   or   { "ok": false, "error": "..." }

Run with no stdin to execute the built-in self-test on synthetic fixtures.
"""

from __future__ import annotations

import base64
import hashlib
import json
import struct
import sys
from typing import Any


# ---------------------------------------------------------------------------
# Hash helpers (mirror rustre_loader::sha256 / md5)
# ---------------------------------------------------------------------------

def validator_sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def validator_md5(data: bytes) -> str:
    return hashlib.md5(data).hexdigest()


# ---------------------------------------------------------------------------
# FormatDetector::detect — coarse magic-byte detection
# Returns a string matching the BinaryFormat enum variants used by the crate.
# ---------------------------------------------------------------------------

def validator_format_detector_detect(data: bytes) -> str:
    if len(data) < 4:
        return "Unknown"

    # ELF: \x7fELF
    if data[:4] == b"\x7fELF":
        return "Elf"

    # PE: MZ at offset 0 (coarse — does not require PE header at e_lfanew)
    if data[:2] == b"MZ":
        return "Pe"

    # Mach-O magics (LE/BE, 32/64)
    magic = data[:4]
    if magic in (b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf",
                 b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe"):
        return "MachO"

    # Mach-O Fat vs Java class: both start with CAFEBABE.
    # Disambiguated by Java major version (bytes 6..8 big-endian) in 44..=80.
    if magic == b"\xca\xfe\xba\xbe":
        if len(data) >= 8:
            major = struct.unpack(">H", data[6:8])[0]
            if 44 <= major <= 80:
                return "JavaClass"
        return "MachOFat"

    # ZIP / JAR: PK\x03\x04 (local file header) or PK\x05\x06 (EOCD)
    if data[:4] in (b"PK\x03\x04", b"PK\x05\x06"):
        return "Zip"

    # WebAssembly: \x00asm
    if data[:4] == b"\x00asm":
        return "Wasm"

    return "Unknown"


def validator_format_detector_is_elf(data: bytes) -> bool:
    return validator_format_detector_detect(data) == "Elf"


def validator_format_detector_is_pe(data: bytes) -> bool:
    return validator_format_detector_detect(data) == "Pe"


def validator_format_detector_is_macho(data: bytes) -> bool:
    return validator_format_detector_detect(data) == "MachO"


def validator_format_detector_is_java_class(data: bytes) -> bool:
    return validator_format_detector_detect(data) == "JavaClass"


# ---------------------------------------------------------------------------
# AutoLoader::detect_format — fine-grained format detection
# ---------------------------------------------------------------------------

def validator_auto_loader_detect_format(data: bytes) -> Any:
    if len(data) < 4:
        # Still try one-byte formats
        if len(data) >= 1 and data[0:1] == b":":
            return "IntelHex"
        if len(data) >= 2 and data[0:1] == b"S" and chr(data[1]).isdigit():
            return "MotorolaSrec"
        return "Unknown"

    # ELF — split by class (EI_CLASS at index 4) and endian (EI_DATA at index 5)
    if data[:4] == b"\x7fELF" and len(data) >= 6:
        ei_class = data[4]
        ei_data = data[5]
        bits = 32 if ei_class == 1 else (64 if ei_class == 2 else 0)
        endian = "Le" if ei_data == 1 else ("Be" if ei_data == 2 else "Unknown")
        if bits and endian != "Unknown":
            return f"Elf{bits}{endian}"
        return "ElfUnknown"

    # PE
    if data[:2] == b"MZ":
        return "Pe"

    # Mach-O 32/64 LE/BE
    magic = data[:4]
    if magic == b"\xfe\xed\xfa\xce":
        return "MachoBe32"
    if magic == b"\xfe\xed\xfa\xcf":
        return "MachoBe64"
    if magic == b"\xce\xfa\xed\xfe":
        return "MachoLe32"
    if magic == b"\xcf\xfa\xed\xfe":
        return "MachoLe64"

    # Fat Mach-O (no Java disambiguation here per spec; AutoLoader treats it as FatMacho)
    if magic == b"\xca\xfe\xba\xbe":
        return "FatMacho"
    if magic == b"\xbe\xba\xfe\xca":
        return "FatMacho"

    # WASM
    if magic == b"\x00asm":
        return "Wasm"

    # PDF
    if data[:4] == b"%PDF":
        return "Pdf"

    # ZIP
    if magic in (b"PK\x03\x04", b"PK\x05\x06"):
        return "Zip"

    # Lua bytecode: ESC + "Lua" then version byte
    if data[:4] == b"\x1bLua" and len(data) >= 5:
        return {"LuaBytecode": data[4]}

    # LuaJIT: ESC + "LJ"
    if data[:3] == b"\x1bLJ":
        return "LuaJit"

    # OLE Compound (D0CF11E0A1B11AE1)
    if data[:8] == b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1":
        return "OleCompoundDoc"

    # Android DEX: "dex\n" magic
    if data[:4] == b"dex\n":
        return "AndroidDex"

    # Intel HEX
    if data[0:1] == b":":
        return "IntelHex"

    # Motorola S-record
    if data[0:1] == b"S" and chr(data[1]).isdigit():
        return "MotorolaSrec"

    return "Unknown"


def validator_auto_loader_is_elf(data: bytes) -> bool:
    fmt = validator_auto_loader_detect_format(data)
    return isinstance(fmt, str) and fmt.startswith("Elf")


def validator_auto_loader_is_macho(data: bytes) -> bool:
    fmt = validator_auto_loader_detect_format(data)
    return isinstance(fmt, str) and (fmt.startswith("Macho") or fmt == "FatMacho")


# ---------------------------------------------------------------------------
# RichLoadResult invariants
# Sections are dicts with: name, virtual_addr, virtual_size, [...]
# ---------------------------------------------------------------------------

def validator_rich_total_virtual_size(sections: list[dict]) -> int:
    return sum(int(s.get("virtual_size", 0)) for s in sections)


def validator_rich_section_at(sections: list[dict], va: int) -> Any:
    for s in sections:
        start = int(s.get("virtual_addr", 0))
        size = int(s.get("virtual_size", 0))
        if start <= va < start + size:
            return s
    return None


# ---------------------------------------------------------------------------
# MultiLoaderInput::to_bytes
# input_obj = {"kind": "Bytes"|"Memory"|"File", "data": "<b64>"|<path>}
# ---------------------------------------------------------------------------

def validator_multi_loader_input_to_bytes(input_obj: dict) -> bytes:
    kind = input_obj.get("kind")
    if kind in ("Bytes", "Memory"):
        return base64.b64decode(input_obj.get("data", ""))
    if kind == "File":
        with open(input_obj["path"], "rb") as f:
            return f.read()
    raise ValueError(f"unknown MultiLoaderInput kind: {kind!r}")


# ---------------------------------------------------------------------------
# MultiFormatRegistry::probe_all ordering invariant
# loaders = [{"name": str, "confidence": int}, ...]
# Result: sorted desc by confidence, filter confidence == 0.
# ---------------------------------------------------------------------------

def validator_multi_format_registry_probe_all(loaders: list[dict]) -> list[dict]:
    filtered = [l for l in loaders if int(l.get("confidence", 0)) != 0]
    filtered.sort(key=lambda l: int(l["confidence"]), reverse=True)
    return [{"name": l["name"], "confidence": int(l["confidence"])} for l in filtered]


# ---------------------------------------------------------------------------
# LoaderCoordinator::loader_count invariant
# register_calls is an int — count must equal number of register() calls.
# ---------------------------------------------------------------------------

def validator_loader_coordinator_loader_count(register_calls: int) -> int:
    return int(register_calls)


# ---------------------------------------------------------------------------
# Dispatcher
# ---------------------------------------------------------------------------

_DISPATCH = {
    "sha256": lambda a: validator_sha256(_b(a["data"])),
    "md5": lambda a: validator_md5(_b(a["data"])),
    "format_detector_detect": lambda a: validator_format_detector_detect(_b(a["data"])),
    "format_detector_is_elf": lambda a: validator_format_detector_is_elf(_b(a["data"])),
    "format_detector_is_pe": lambda a: validator_format_detector_is_pe(_b(a["data"])),
    "format_detector_is_macho": lambda a: validator_format_detector_is_macho(_b(a["data"])),
    "format_detector_is_java_class": lambda a: validator_format_detector_is_java_class(_b(a["data"])),
    "auto_loader_detect_format": lambda a: validator_auto_loader_detect_format(_b(a["data"])),
    "auto_loader_is_elf": lambda a: validator_auto_loader_is_elf(_b(a["data"])),
    "auto_loader_is_macho": lambda a: validator_auto_loader_is_macho(_b(a["data"])),
    "rich_total_virtual_size": lambda a: validator_rich_total_virtual_size(a["sections"]),
    "rich_section_at": lambda a: validator_rich_section_at(a["sections"], int(a["va"])),
    "multi_loader_input_to_bytes":
        lambda a: base64.b64encode(validator_multi_loader_input_to_bytes(a["input"])).decode("ascii"),
    "multi_format_registry_probe_all": lambda a: validator_multi_format_registry_probe_all(a["loaders"]),
    "loader_coordinator_loader_count": lambda a: validator_loader_coordinator_loader_count(a["register_calls"]),
}


def _b(s: str) -> bytes:
    """Decode a base64 string from JSON into raw bytes."""
    return base64.b64decode(s)


# ---------------------------------------------------------------------------
# Self-test
# ---------------------------------------------------------------------------

def _selftest() -> dict:
    out: dict[str, Any] = {}

    # Hash oracles
    msg = b"hello"
    out["sha256_hello"] = validator_sha256(msg)
    out["md5_hello"] = validator_md5(msg)
    assert out["sha256_hello"] == "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
    assert out["md5_hello"] == "5d41402abc4b2a76b9719d911017c592"

    # Coarse detect
    fixtures = {
        "elf":      b"\x7fELF\x02\x01" + b"\x00" * 32,
        "pe":       b"MZ" + b"\x00" * 64,
        "macho64le": b"\xcf\xfa\xed\xfe" + b"\x00" * 28,
        "wasm":     b"\x00asm\x01\x00\x00\x00",
        "zip":      b"PK\x03\x04" + b"\x00" * 16,
        "javaclass": b"\xca\xfe\xba\xbe\x00\x00\x00\x34",  # major 52 -> Java
        "fatmacho":  b"\xca\xfe\xba\xbe\x00\x00\x00\x02",  # major 2 -> FatMacho
        "unknown":  b"\x00\x01\x02\x03",
    }
    coarse = {k: validator_format_detector_detect(v) for k, v in fixtures.items()}
    out["coarse"] = coarse
    assert coarse["elf"] == "Elf"
    assert coarse["pe"] == "Pe"
    assert coarse["macho64le"] == "MachO"
    assert coarse["wasm"] == "Wasm"
    assert coarse["zip"] == "Zip"
    assert coarse["javaclass"] == "JavaClass"
    assert coarse["fatmacho"] == "MachOFat"
    assert coarse["unknown"] == "Unknown"

    # Fine detect
    fine = {k: validator_auto_loader_detect_format(v) for k, v in fixtures.items()}
    out["fine"] = fine
    assert fine["elf"] == "Elf64Le"
    assert fine["macho64le"] == "MachoLe64"
    assert fine["wasm"] == "Wasm"

    # Builder invariants
    sections = [
        {"name": ".text", "virtual_addr": 0x1000, "virtual_size": 0x200},
        {"name": ".data", "virtual_addr": 0x2000, "virtual_size": 0x100},
    ]
    out["total_vsize"] = validator_rich_total_virtual_size(sections)
    assert out["total_vsize"] == 0x300

    hit = validator_rich_section_at(sections, 0x1050)
    miss = validator_rich_section_at(sections, 0x9999)
    assert hit and hit["name"] == ".text"
    assert miss is None

    # probe_all ordering
    probes = [
        {"name": "low", "confidence": 64},
        {"name": "zero", "confidence": 0},
        {"name": "magic", "confidence": 255},
        {"name": "heur", "confidence": 128},
    ]
    ordered = validator_multi_format_registry_probe_all(probes)
    out["probe_order"] = [p["name"] for p in ordered]
    assert out["probe_order"] == ["magic", "heur", "low"]

    # loader_count
    assert validator_loader_coordinator_loader_count(7) == 7

    # MultiLoaderInput::to_bytes (Bytes variant)
    rt = validator_multi_loader_input_to_bytes(
        {"kind": "Bytes", "data": base64.b64encode(b"abc").decode("ascii")}
    )
    assert rt == b"abc"

    out["status"] = "ok"
    return out


def main() -> int:
    if sys.stdin.isatty():
        result = _selftest()
        json.dump(result, sys.stdout, indent=2)
        sys.stdout.write("\n")
        return 0

    try:
        payload = json.load(sys.stdin)
    except Exception as e:
        json.dump({"ok": False, "error": f"invalid json: {e}"}, sys.stdout)
        return 1

    fn = payload.get("function")
    args = payload.get("args", {})
    handler = _DISPATCH.get(fn)
    if handler is None:
        json.dump({"ok": False, "error": f"unknown function: {fn}"}, sys.stdout)
        return 1

    try:
        result = handler(args)
        if isinstance(result, bytes):
            result = base64.b64encode(result).decode("ascii")
        json.dump({"ok": True, "result": result}, sys.stdout)
        return 0
    except Exception as e:
        json.dump({"ok": False, "error": f"{type(e).__name__}: {e}"}, sys.stdout)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
