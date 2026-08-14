#!/usr/bin/env python3
"""Independent validator for rustre-flirt crate.

Reimplements core primitives of the FLIRT engine in pure Python using only
the standard library, so results can be cross-checked against the Rust crate
without importing it or calling any MCP tool.

Functions implemented (mirroring the crate's public surface):
  - validator_crc16_flirt(data)            CRC-16/CCITT-reversed, poly 0x8408, init 0xFFFF
  - validator_crc16_ibm(data)              CRC-16/IBM,            poly 0xA001, init 0x0000
  - validator_flirt_arch_from_u8(n)        numeric -> arch string
  - validator_flirt_arch_to_u8(s)          arch string -> numeric
  - validator_pattern_hex(pattern)         bytes/wildcards -> hex string with ".."
  - validator_pattern_wildcard_ratio(p)    fraction of wildcard slots
  - validator_pattern_matches_initial(p,buf)
  - validator_pattern_matches_crc16(p,buf) CRC over [len(initial)..+crc_length]
  - validator_pattern_matches_tail(p,buf)
  - validator_pattern_matches_all(p,buf)
  - validator_parse_sig_header(data_hex)   IDA .sig IDASGN header sniff
  - validator_flirt_file_type_contains(bits,flag)

Input format (stdin JSON):
  { "function": "<name>", "input": <args> }
Output format:
  { "function": "<name>", "output": <result> }

If no stdin is provided, main() runs a small self-test battery.
"""

from __future__ import annotations

import json
import sys
from typing import Any, Dict, List, Optional, Tuple, Union

# ---------------------------------------------------------------------------
# CRC implementations
# ---------------------------------------------------------------------------

def validator_crc16_flirt(data: bytes) -> int:
    """CRC-16/CCITT reversed poly 0x8408, init 0xFFFF, no final XOR.
    Matches IDA FLIRT crc16 used over the variable-length region of a pattern.
    """
    crc = 0xFFFF
    for b in data:
        crc ^= b
        for _ in range(8):
            if crc & 1:
                crc = (crc >> 1) ^ 0x8408
            else:
                crc >>= 1
    # FLIRT historically returns (~crc) & 0xFFFF after a swap; the crate keeps
    # raw value. We mirror the crate: return crc as-is.
    return crc & 0xFFFF


def validator_crc16_ibm(data: bytes) -> int:
    """CRC-16/IBM (Modbus-like) poly 0xA001, init 0x0000."""
    crc = 0x0000
    for b in data:
        crc ^= b
        for _ in range(8):
            if crc & 1:
                crc = (crc >> 1) ^ 0xA001
            else:
                crc >>= 1
    return crc & 0xFFFF


# ---------------------------------------------------------------------------
# FlirtArch table
# ---------------------------------------------------------------------------

_ARCH_TABLE: List[Tuple[int, str]] = [
    (0,   "X86"),
    (1,   "Z80"),
    (2,   "I860"),
    (3,   "8051"),
    (4,   "Tms"),
    (5,   "6502"),
    (6,   "Pdp"),
    (7,   "68K"),
    (8,   "Java"),
    (9,   "6800"),
    (10,  "St7"),
    (11,  "Mc6812"),
    (12,  "Mips"),
    (13,  "ArmOld"),
    (14,  "Tms390c6"),
    (15,  "Ppc"),
    (16,  "Ia64"),
    (128, "Arm64"),
    (132, "X64"),
    (255, "Unknown"),
]
_ARCH_BY_U8 = {n: s for n, s in _ARCH_TABLE}
_ARCH_BY_STR = {s.lower(): n for n, s in _ARCH_TABLE}


def validator_flirt_arch_from_u8(n: int) -> str:
    return _ARCH_BY_U8.get(int(n) & 0xFF, "Unknown")


def validator_flirt_arch_to_u8(s: str) -> int:
    return _ARCH_BY_STR.get(str(s).lower(), 255)


# ---------------------------------------------------------------------------
# Pattern primitives
#
# A pattern dict has shape:
#   {
#     "initial":     [int|None, ...],   # None => wildcard
#     "crc_length":  int,
#     "crc16":       int,
#     "total_length":int,                # nominal function length covered
#     "tail":        [[off:int, val:int], ...],
#     "names":       [{name, offset, is_public}, ...]   # optional
#   }
# ---------------------------------------------------------------------------

def validator_pattern_hex(pattern: Dict[str, Any]) -> str:
    out = []
    for b in pattern["initial"]:
        if b is None:
            out.append("..")
        else:
            out.append(f"{int(b) & 0xFF:02X}")
    return "".join(out)


def validator_pattern_wildcard_ratio(pattern: Dict[str, Any]) -> float:
    init = pattern["initial"]
    if not init:
        return 0.0
    wc = sum(1 for b in init if b is None)
    return wc / len(init)


def validator_pattern_matches_initial(pattern: Dict[str, Any], buf: bytes) -> bool:
    init = pattern["initial"]
    if len(buf) < len(init):
        return False
    for i, b in enumerate(init):
        if b is None:
            continue
        if (int(b) & 0xFF) != buf[i]:
            return False
    return True


def validator_pattern_matches_crc16(pattern: Dict[str, Any], buf: bytes) -> bool:
    start = len(pattern["initial"])
    n = int(pattern.get("crc_length", 0))
    if n == 0:
        return True
    if len(buf) < start + n:
        return False
    actual = validator_crc16_flirt(bytes(buf[start:start + n]))
    return actual == (int(pattern["crc16"]) & 0xFFFF)


def validator_pattern_matches_tail(pattern: Dict[str, Any], buf: bytes) -> bool:
    for off, val in pattern.get("tail", []):
        if off >= len(buf):
            return False
        if buf[off] != (int(val) & 0xFF):
            return False
    return True


def validator_pattern_matches_all(pattern: Dict[str, Any], buf: bytes) -> bool:
    return (
        validator_pattern_matches_initial(pattern, buf)
        and validator_pattern_matches_crc16(pattern, buf)
        and validator_pattern_matches_tail(pattern, buf)
    )


# ---------------------------------------------------------------------------
# .sig header sniff
# ---------------------------------------------------------------------------

def validator_parse_sig_header(data: bytes) -> Dict[str, Any]:
    """Best-effort parse of an IDA FLIRT .sig header.

    Layout (v6-v10):
      0..6  magic "IDASGN"
      6     version (u8)
      7     arch    (u8)
      8..12 file_types (u32 LE)
      12..14 os_types (u16 LE)
      14..16 app_types(u16 LE)
      16    features (u8)
      17    old_n_functions (u16 LE) [v6 only]
      ...   crc16 (u16), ctype (12), library_name_len (u8), alt_n_functions (u16),
            library_name (variable)
    """
    if len(data) < 6 or data[:6] != b"IDASGN":
        return {"ok": False, "error": "bad_magic"}
    if len(data) < 17:
        return {"ok": False, "error": "truncated"}
    version = data[6]
    arch = data[7]
    if version < 6 or version > 10:
        return {"ok": False, "error": f"unsupported_version:{version}"}

    file_types = int.from_bytes(data[8:12], "little")
    os_types   = int.from_bytes(data[12:14], "little")
    app_types  = int.from_bytes(data[14:16], "little")
    features   = data[16]

    # Try to read library name (best-effort; layouts vary by version).
    # Common layout: at offset 23 there is name_len (u8), name follows.
    library_name = ""
    n_functions = 0
    try:
        # crc16 at 17..19, ctype 19..31, name_len at 31, n_functions at 32..34
        if len(data) >= 34:
            name_len = data[31]
            n_functions = int.from_bytes(data[32:34], "little")
            name_start = 34
            if name_start + name_len <= len(data):
                library_name = data[name_start:name_start + name_len].decode(
                    "ascii", errors="replace"
                )
    except Exception:
        pass

    return {
        "ok": True,
        "version": version,
        "arch": validator_flirt_arch_from_u8(arch),
        "arch_u8": arch,
        "file_types": file_types,
        "os_types": os_types,
        "app_types": app_types,
        "features": features,
        "n_functions": n_functions,
        "library_name": library_name,
    }


# ---------------------------------------------------------------------------
# FlirtFileType bitflag
# ---------------------------------------------------------------------------

def validator_flirt_file_type_contains(bits: int, flag: int) -> bool:
    return (int(bits) & int(flag)) == int(flag)


# ---------------------------------------------------------------------------
# Dispatcher
# ---------------------------------------------------------------------------

_DISPATCH = {
    "crc16_flirt":              lambda a: validator_crc16_flirt(bytes(a["data"])),
    "crc16_ibm":                lambda a: validator_crc16_ibm(bytes(a["data"])),
    "flirt_arch_from_u8":       lambda a: validator_flirt_arch_from_u8(a["n"]),
    "flirt_arch_to_u8":         lambda a: validator_flirt_arch_to_u8(a["s"]),
    "pattern_hex":              lambda a: validator_pattern_hex(a["pattern"]),
    "pattern_wildcard_ratio":   lambda a: validator_pattern_wildcard_ratio(a["pattern"]),
    "pattern_matches_initial":  lambda a: validator_pattern_matches_initial(a["pattern"], bytes(a["buf"])),
    "pattern_matches_crc16":    lambda a: validator_pattern_matches_crc16(a["pattern"], bytes(a["buf"])),
    "pattern_matches_tail":     lambda a: validator_pattern_matches_tail(a["pattern"], bytes(a["buf"])),
    "pattern_matches_all":      lambda a: validator_pattern_matches_all(a["pattern"], bytes(a["buf"])),
    "parse_sig_header":         lambda a: validator_parse_sig_header(bytes.fromhex(a["data_hex"])),
    "flirt_file_type_contains": lambda a: validator_flirt_file_type_contains(a["bits"], a["flag"]),
}


def dispatch(req: Dict[str, Any]) -> Dict[str, Any]:
    fn = req.get("function")
    if fn not in _DISPATCH:
        return {"function": fn, "error": f"unknown function: {fn}"}
    try:
        out = _DISPATCH[fn](req.get("input", {}))
    except Exception as e:
        return {"function": fn, "error": f"{type(e).__name__}: {e}"}
    return {"function": fn, "output": out}


# ---------------------------------------------------------------------------
# Self-test main
# ---------------------------------------------------------------------------

def _selftest() -> Dict[str, Any]:
    results = {}
    # CRCs against fixed vectors
    results["crc16_flirt_empty"] = hex(validator_crc16_flirt(b""))            # 0xFFFF
    results["crc16_flirt_123"]   = hex(validator_crc16_flirt(b"123456789"))
    results["crc16_ibm_empty"]   = hex(validator_crc16_ibm(b""))              # 0x0000
    results["crc16_ibm_123"]     = hex(validator_crc16_ibm(b"123456789"))     # 0x4B37
    # Arch table
    results["arch_0"]   = validator_flirt_arch_from_u8(0)     # X86
    results["arch_132"] = validator_flirt_arch_from_u8(132)   # X64
    results["arch_255"] = validator_flirt_arch_from_u8(255)   # Unknown
    results["arch_X64"] = validator_flirt_arch_to_u8("X64")   # 132
    # Pattern
    pat = {
        "initial":     [0x55, 0x8B, None, 0xE5],
        "crc_length":  0,
        "crc16":       0,
        "total_length":8,
        "tail":        [[6, 0xC3]],
    }
    results["pattern_hex"]            = validator_pattern_hex(pat)            # "558B..E5"
    results["pattern_wc_ratio"]       = validator_pattern_wildcard_ratio(pat) # 0.25
    results["pattern_match_ok"]       = validator_pattern_matches_all(
        pat, bytes([0x55, 0x8B, 0xEC, 0xE5, 0x00, 0x00, 0xC3])
    )
    results["pattern_match_bad_tail"] = validator_pattern_matches_all(
        pat, bytes([0x55, 0x8B, 0xEC, 0xE5, 0x00, 0x00, 0x90])
    )
    # File type bitflag
    results["filetype_contains"] = validator_flirt_file_type_contains(0b1011, 0b1010)
    # Sig header (synthesize a minimal valid v10 header)
    hdr = bytearray(b"IDASGN")
    hdr.append(10)        # version
    hdr.append(132)       # arch X64
    hdr += (0).to_bytes(4, "little")   # file_types
    hdr += (0).to_bytes(2, "little")   # os_types
    hdr += (0).to_bytes(2, "little")   # app_types
    hdr.append(0)         # features
    hdr += (0).to_bytes(2, "little")   # crc16
    hdr += b"\x00" * 12   # ctype
    hdr.append(4)         # name_len
    hdr += (7).to_bytes(2, "little")   # n_functions
    hdr += b"libc"
    results["sig_header"] = validator_parse_sig_header(bytes(hdr))
    return results


def main() -> None:
    # If stdin has data, process as JSON request
    data = sys.stdin.read() if not sys.stdin.isatty() else ""
    if data.strip():
        try:
            req = json.loads(data)
        except json.JSONDecodeError as e:
            print(json.dumps({"error": f"bad json: {e}"}))
            return
        if isinstance(req, list):
            print(json.dumps([dispatch(r) for r in req], indent=2))
        else:
            print(json.dumps(dispatch(req), indent=2))
        return

    print(json.dumps({"selftest": _selftest()}, indent=2, default=str))


if __name__ == "__main__":
    main()
