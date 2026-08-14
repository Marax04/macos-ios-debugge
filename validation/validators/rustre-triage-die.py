#!/usr/bin/env python3
"""Independent Python validator for rustre-triage-die crate.

Reimplements core Detect-It-Easy style detection primitives (Shannon entropy,
hex wildcard pattern search, minimal PE header walk, section enumeration with
entropy, entry-point bytes, import-table lookup, condition evaluation) with
pure stdlib so results can be cross-checked against the Rust implementation
described in validation/reports/rustre-triage-die.md.

Usage:
  echo '{"fn":"compute_entropy","args":{"data_b64":"..."}}' | \
      python rustre-triage-die.py
  python rustre-triage-die.py            # run smoke self-tests
"""
from __future__ import annotations

import base64
import json
import math
import struct
import sys
from collections import Counter
from typing import Any


# ---------------------------------------------------------------------------
# Entropy
# ---------------------------------------------------------------------------
def compute_entropy(data: bytes) -> float:
    """Shannon entropy in bits/byte. Returns 0.0 for empty input."""
    n = len(data)
    if n == 0:
        return 0.0
    counts = Counter(data)
    h = 0.0
    for c in counts.values():
        p = c / n
        h -= p * math.log2(p)
    return h


# ---------------------------------------------------------------------------
# Hex wildcard pattern search ("?? AA BB ??" — case-insensitive, ?? = wildcard)
# ---------------------------------------------------------------------------
def _parse_hex_pattern(hex_pattern: str) -> list[int | None]:
    """Return list of byte values or None for '??' wildcard."""
    s = hex_pattern.replace(" ", "").replace("\t", "")
    if len(s) % 2 != 0:
        raise ValueError("hex pattern must have even nibble count")
    out: list[int | None] = []
    for i in range(0, len(s), 2):
        tok = s[i : i + 2]
        if tok == "??":
            out.append(None)
        else:
            out.append(int(tok, 16))
    return out


def find_bytes(data: bytes, hex_pattern: str) -> int | None:
    """Search data for hex pattern with '??' wildcards. Returns offset or None."""
    pat = _parse_hex_pattern(hex_pattern)
    if not pat:
        return None
    plen = len(pat)
    dlen = len(data)
    if plen > dlen:
        return None
    for i in range(dlen - plen + 1):
        ok = True
        for j, p in enumerate(pat):
            if p is not None and data[i + j] != p:
                ok = False
                break
        if ok:
            return i
    return None


# ---------------------------------------------------------------------------
# Minimal PE walker (defensive; mirrors the Rust crate's intent)
# ---------------------------------------------------------------------------
def locate_pe(data: bytes) -> int | None:
    """Return offset of PE signature 'PE\\0\\0' or None."""
    if len(data) < 0x40 or data[:2] != b"MZ":
        return None
    e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
    if e_lfanew + 4 > len(data):
        return None
    if data[e_lfanew : e_lfanew + 4] != b"PE\x00\x00":
        return None
    return e_lfanew


def _coff_header(data: bytes, pe_off: int) -> tuple[int, int, int] | None:
    """Return (machine, num_sections, size_of_optional_header)."""
    coff = pe_off + 4
    if coff + 20 > len(data):
        return None
    machine = struct.unpack_from("<H", data, coff)[0]
    num_sections = struct.unpack_from("<H", data, coff + 2)[0]
    size_opt = struct.unpack_from("<H", data, coff + 16)[0]
    return machine, num_sections, size_opt


def _is_pe32_plus(data: bytes, opt_off: int) -> bool:
    if opt_off + 2 > len(data):
        return False
    magic = struct.unpack_from("<H", data, opt_off)[0]
    return magic == 0x20B  # PE32+ = 0x20B; PE32 = 0x10B


def pe_subsystem(data: bytes) -> int | None:
    pe_off = locate_pe(data)
    if pe_off is None:
        return None
    coff = _coff_header(data, pe_off)
    if coff is None:
        return None
    opt_off = pe_off + 4 + 20
    if not _is_pe32_plus(data, opt_off):
        sub_off = opt_off + 68
    else:
        sub_off = opt_off + 68
    if sub_off + 2 > len(data):
        return None
    return struct.unpack_from("<H", data, sub_off)[0]


def pe_machine(data: bytes) -> int | None:
    pe_off = locate_pe(data)
    if pe_off is None:
        return None
    coff = _coff_header(data, pe_off)
    if coff is None:
        return None
    return coff[0]


def read_pe_sections(data: bytes, cap: int = 96) -> list[tuple[str, float]]:
    """Return list of (section_name, entropy_of_raw_bytes), capped at `cap`."""
    pe_off = locate_pe(data)
    if pe_off is None:
        return []
    coff = _coff_header(data, pe_off)
    if coff is None:
        return []
    _, num_sections, size_opt = coff
    sect_off = pe_off + 4 + 20 + size_opt
    out: list[tuple[str, float]] = []
    for i in range(min(num_sections, cap)):
        off = sect_off + i * 40
        if off + 40 > len(data):
            break
        name = data[off : off + 8].rstrip(b"\x00").decode("ascii", "replace")
        raw_size = struct.unpack_from("<I", data, off + 16)[0]
        raw_ptr = struct.unpack_from("<I", data, off + 20)[0]
        if raw_ptr + raw_size > len(data) or raw_size == 0:
            out.append((name, 0.0))
            continue
        out.append((name, compute_entropy(data[raw_ptr : raw_ptr + raw_size])))
    return out


def read_section_count(data: bytes) -> int:
    pe_off = locate_pe(data)
    if pe_off is None:
        return 0
    coff = _coff_header(data, pe_off)
    if coff is None:
        return 0
    return coff[1]


def _entry_point_rva(data: bytes) -> int | None:
    pe_off = locate_pe(data)
    if pe_off is None:
        return None
    opt_off = pe_off + 4 + 20
    if opt_off + 20 > len(data):
        return None
    return struct.unpack_from("<I", data, opt_off + 16)[0]


def _rva_to_file_offset(data: bytes, rva: int) -> int | None:
    pe_off = locate_pe(data)
    if pe_off is None:
        return None
    coff = _coff_header(data, pe_off)
    if coff is None:
        return None
    _, num_sections, size_opt = coff
    sect_off = pe_off + 4 + 20 + size_opt
    for i in range(num_sections):
        off = sect_off + i * 40
        if off + 40 > len(data):
            return None
        v_size = struct.unpack_from("<I", data, off + 8)[0]
        v_addr = struct.unpack_from("<I", data, off + 12)[0]
        r_ptr = struct.unpack_from("<I", data, off + 20)[0]
        if v_addr <= rva < v_addr + max(v_size, 1):
            return r_ptr + (rva - v_addr)
    return None


def get_entry_point_bytes(data: bytes, n: int = 16) -> bytes:
    rva = _entry_point_rva(data)
    if rva is None:
        return b""
    foff = _rva_to_file_offset(data, rva)
    if foff is None or foff >= len(data):
        return b""
    return data[foff : foff + n]


# ---------------------------------------------------------------------------
# Condition evaluation (subset matching report)
# ---------------------------------------------------------------------------
def match_condition(cond: dict, data: bytes) -> bool:
    """Evaluate a single DieCondition encoded as {"kind":..., ...}."""
    k = cond.get("kind")
    if k == "SectionName":
        target = cond["name"]
        return any(n == target for n, _ in read_pe_sections(data))
    if k == "SectionCount":
        n = read_section_count(data)
        return cond["min"] <= n <= cond["max"]
    if k == "BytePattern":
        off = cond.get("offset", 0)
        idx = find_bytes(data[off:], cond["hex"])
        return idx is not None
    if k == "EntryPointHex":
        ep = get_entry_point_bytes(data, 32)
        return find_bytes(ep, cond["hex"]) is not None
    if k == "EntropyRange":
        secs = read_pe_sections(data)
        i = cond["section"]
        if i >= len(secs):
            return False
        h = secs[i][1]
        return cond["min"] <= h <= cond["max"]
    if k == "SubsystemType":
        return pe_subsystem(data) == cond["value"]
    if k == "MachineType":
        return pe_machine(data) == cond["value"]
    if k == "StringPresent":
        return cond["text"].encode("utf-8") in data
    return False


def match_rule_condition(rc: dict, data: bytes) -> bool:
    """Evaluate {"op":"All|Any|Not", "items":[...]} combinators."""
    op = rc.get("op")
    items = rc.get("items", [])
    if op == "All":
        return all(match_condition(c, data) for c in items)
    if op == "Any":
        return any(match_condition(c, data) for c in items)
    if op == "Not":
        return not match_condition(items[0], data) if items else True
    return False


# ---------------------------------------------------------------------------
# JSON RPC-style dispatcher
# ---------------------------------------------------------------------------
def _b64(args: dict, key: str = "data_b64") -> bytes:
    return base64.b64decode(args.get(key, ""))


_DISPATCH = {
    "compute_entropy": lambda a: compute_entropy(_b64(a)),
    "find_bytes": lambda a: find_bytes(_b64(a), a["hex"]),
    "read_pe_sections": lambda a: read_pe_sections(_b64(a)),
    "read_section_count": lambda a: read_section_count(_b64(a)),
    "pe_subsystem": lambda a: pe_subsystem(_b64(a)),
    "pe_machine": lambda a: pe_machine(_b64(a)),
    "get_entry_point_bytes": lambda a: get_entry_point_bytes(
        _b64(a), a.get("n", 16)
    ).hex(),
    "match_condition": lambda a: match_condition(a["cond"], _b64(a)),
    "match_rule_condition": lambda a: match_rule_condition(a["rc"], _b64(a)),
}


def _smoke() -> None:
    # entropy known answers
    assert abs(compute_entropy(b"\x00" * 1024) - 0.0) < 1e-9
    assert abs(compute_entropy(bytes(range(256))) - 8.0) < 1e-9
    assert abs(compute_entropy(b"AB" * 512) - 1.0) < 1e-9
    # hex wildcard
    assert find_bytes(b"\x00\xAA\xBB\xCC", "AA ?? CC") == 1
    assert find_bytes(b"\x00\xAA\xBB\xCC", "DE AD") is None
    # PE walker on non-PE
    assert locate_pe(b"not a pe") is None
    assert read_pe_sections(b"MZ" + b"\x00" * 64) == []
    print("smoke: OK")


def main() -> int:
    if sys.stdin.isatty():
        _smoke()
        return 0
    raw = sys.stdin.read().strip()
    if not raw:
        _smoke()
        return 0
    req = json.loads(raw)
    fn = req.get("fn")
    args = req.get("args", {})
    if fn not in _DISPATCH:
        print(json.dumps({"error": f"unknown fn {fn!r}"}))
        return 2
    try:
        result: Any = _DISPATCH[fn](args)
    except Exception as exc:  # pragma: no cover
        print(json.dumps({"error": str(exc)}))
        return 1
    print(json.dumps({"result": result}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
