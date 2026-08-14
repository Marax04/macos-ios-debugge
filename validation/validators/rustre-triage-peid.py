#!/usr/bin/env python3
"""Independent Python validator for rustre-triage-peid crate.

Reimplements core PEiD-style detection primitives in pure stdlib so results
can be cross-checked against the Rust implementation described in
validation/reports/rustre-triage-peid.md.

Covers:
  - PEiD hex pattern parsing ("60 BE ?? ?? 8D BE" -> [Some|None]*N)
  - Pattern matching at offset (`match_at_offset`)
  - PEiD userdb.txt parsing ([Name]/signature=/ep_only=/section_start=)
  - Confidence scoring (function of non-wildcard density)
  - Signature de-duplication / merging
  - Minimal PE walker (DOS/PE/COFF/sections/entry-point) to find EP file offset
  - Scanner that returns matches over data or only at EP
  - Rich header location + DanS XOR-key recovery
  - Shannon entropy + simple high-entropy section heuristic
  - PEiD category labels

Usage:
  echo '{"fn":"parse_peid_pattern","args":{"s":"60 BE ?? ?? 8D BE"}}' | \
      python rustre-triage-peid.py
  python rustre-triage-peid.py            # run smoke self-tests
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
# PEiD category labels (mirror PeidCategory::label)
# ---------------------------------------------------------------------------
_CATEGORY_LABELS = {
    "Packer": "packer",
    "Protector": "protector",
    "Compiler": "compiler",
    "Linker": "linker",
    "Installer": "installer",
    "Runtime": "runtime",
    "Other": "other",
    "Unknown": "unknown",
}


def category_label(cat: str) -> str:
    return _CATEGORY_LABELS.get(cat, "unknown")


# ---------------------------------------------------------------------------
# PEiD hex pattern parsing
# ---------------------------------------------------------------------------
def parse_peid_pattern(s: str) -> list[int | None]:
    """Parse "60 BE ?? ?? 8D BE" -> [0x60, 0xBE, None, None, 0x8D, 0xBE].

    Accepts whitespace separators, `??` and `?` as wildcards (full byte),
    and even-length contiguous hex. Raises ValueError on malformed input.
    """
    toks = s.replace("\t", " ").split()
    out: list[int | None] = []
    for t in toks:
        if t in ("??", "?"):
            out.append(None)
            continue
        # support concatenated hex like "60BE????8DBE"
        if len(t) > 2 and all(c in "0123456789abcdefABCDEF?" for c in t):
            i = 0
            while i < len(t):
                pair = t[i : i + 2]
                if pair in ("??", "?", "?" + (t[i + 1] if i + 1 < len(t) else "")):
                    out.append(None)
                elif len(pair) == 2 and all(c in "0123456789abcdefABCDEF" for c in pair):
                    out.append(int(pair, 16))
                else:
                    raise ValueError(f"bad token {pair!r} in pattern")
                i += 2
            continue
        if len(t) != 2:
            raise ValueError(f"bad pattern token {t!r}")
        if not all(c in "0123456789abcdefABCDEF" for c in t):
            raise ValueError(f"bad pattern token {t!r}")
        out.append(int(t, 16))
    return out


def match_at_offset(data: bytes, pattern: list[int | None], offset: int) -> bool:
    """Return True if pattern matches data starting at offset (None = wildcard)."""
    if offset < 0 or offset + len(pattern) > len(data):
        return False
    for j, p in enumerate(pattern):
        if p is not None and data[offset + j] != p:
            return False
    return True


def find_pattern(data: bytes, pattern: list[int | None], start: int = 0) -> int | None:
    """Linear search for `pattern` in `data`. Returns offset or None."""
    plen = len(pattern)
    if plen == 0:
        return None
    end = len(data) - plen + 1
    for i in range(start, end):
        if match_at_offset(data, pattern, i):
            return i
    return None


# ---------------------------------------------------------------------------
# Confidence scoring (mirrors PeidSignature::confidence intent)
# ---------------------------------------------------------------------------
def confidence(pattern: list[int | None]) -> float:
    """Confidence in [0.0, 1.0]: ratio of fixed bytes, weighted by length.

    Short or mostly-wildcard patterns score lower. A length-32 signature with
    no wildcards scores 1.0; a length-4 signature scores at most ~0.25 of the
    length factor; half-wildcards halve the score.
    """
    n = len(pattern)
    if n == 0:
        return 0.0
    fixed = sum(1 for p in pattern if p is not None)
    density = fixed / n
    # length factor: saturates around 32 bytes
    length_factor = min(1.0, n / 32.0)
    return density * (0.5 + 0.5 * length_factor)


# ---------------------------------------------------------------------------
# userdb.txt parser
# ---------------------------------------------------------------------------
def parse_userdb(text: str) -> list[dict]:
    """Parse a PEiD userdb.txt blob into a list of signature dicts.

    Each signature:
      {"name": str, "pattern": [int|None]*N, "ep_only": bool, "section_start": bool}
    """
    sigs: list[dict] = []
    cur: dict | None = None
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith(";"):
            continue
        if line.startswith("[") and line.endswith("]"):
            if cur and "pattern" in cur:
                sigs.append(cur)
            cur = {"name": line[1:-1].strip(), "ep_only": False, "section_start": False}
            continue
        if cur is None:
            continue
        if "=" not in line:
            continue
        k, _, v = line.partition("=")
        k = k.strip().lower()
        v = v.strip()
        if k == "signature":
            try:
                cur["pattern"] = parse_peid_pattern(v)
            except ValueError:
                cur = None  # drop malformed entry
        elif k == "ep_only":
            cur["ep_only"] = v.lower() in ("true", "1", "yes")
        elif k == "section_start":
            cur["section_start"] = v.lower() in ("true", "1", "yes")
    if cur and "pattern" in cur:
        sigs.append(cur)
    return sigs


def dedup_signatures(sigs: list[dict]) -> list[dict]:
    """Drop exact duplicates keyed by (name, pattern, ep_only)."""
    seen: set[tuple] = set()
    out: list[dict] = []
    for s in sigs:
        key = (s.get("name"), tuple(s.get("pattern", [])), bool(s.get("ep_only")))
        if key in seen:
            continue
        seen.add(key)
        out.append(s)
    return out


def merge_signatures(a: list[dict], b: list[dict]) -> list[dict]:
    """Merge two signature lists, de-duped."""
    return dedup_signatures(list(a) + list(b))


# ---------------------------------------------------------------------------
# Minimal PE walker
# ---------------------------------------------------------------------------
def locate_pe(data: bytes) -> int | None:
    if len(data) < 0x40 or data[:2] != b"MZ":
        return None
    e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
    if e_lfanew + 4 > len(data):
        return None
    if data[e_lfanew : e_lfanew + 4] != b"PE\x00\x00":
        return None
    return e_lfanew


def _coff(data: bytes, pe_off: int) -> tuple[int, int, int] | None:
    coff = pe_off + 4
    if coff + 20 > len(data):
        return None
    machine = struct.unpack_from("<H", data, coff)[0]
    nsec = struct.unpack_from("<H", data, coff + 2)[0]
    size_opt = struct.unpack_from("<H", data, coff + 16)[0]
    return machine, nsec, size_opt


def entry_point_rva(data: bytes) -> int | None:
    pe_off = locate_pe(data)
    if pe_off is None:
        return None
    opt_off = pe_off + 4 + 20
    if opt_off + 20 > len(data):
        return None
    return struct.unpack_from("<I", data, opt_off + 16)[0]


def rva_to_file_offset(data: bytes, rva: int) -> int | None:
    pe_off = locate_pe(data)
    if pe_off is None:
        return None
    c = _coff(data, pe_off)
    if c is None:
        return None
    _, nsec, size_opt = c
    sect_off = pe_off + 4 + 20 + size_opt
    for i in range(nsec):
        off = sect_off + i * 40
        if off + 40 > len(data):
            return None
        v_size = struct.unpack_from("<I", data, off + 8)[0]
        v_addr = struct.unpack_from("<I", data, off + 12)[0]
        r_ptr = struct.unpack_from("<I", data, off + 20)[0]
        if v_addr <= rva < v_addr + max(v_size, 1):
            return r_ptr + (rva - v_addr)
    return None


def entry_point_file_offset(data: bytes) -> int | None:
    rva = entry_point_rva(data)
    if rva is None:
        return None
    return rva_to_file_offset(data, rva)


def section_starts(data: bytes) -> list[int]:
    """Return list of section raw-data file offsets."""
    pe_off = locate_pe(data)
    if pe_off is None:
        return []
    c = _coff(data, pe_off)
    if c is None:
        return []
    _, nsec, size_opt = c
    sect_off = pe_off + 4 + 20 + size_opt
    out: list[int] = []
    for i in range(nsec):
        off = sect_off + i * 40
        if off + 40 > len(data):
            break
        r_ptr = struct.unpack_from("<I", data, off + 20)[0]
        out.append(r_ptr)
    return out


# ---------------------------------------------------------------------------
# Scanner
# ---------------------------------------------------------------------------
def scan(data: bytes, sigs: list[dict], ep_only_strict: bool = False) -> list[dict]:
    """Scan data with each signature; return list of match dicts.

    - If a sig has ep_only=True: only test at the entry point file offset.
    - If a sig has section_start=True: only test at each section's raw offset.
    - Otherwise: linear search across the buffer.
    - If ep_only_strict=True, non-ep_only sigs are skipped.
    """
    out: list[dict] = []
    ep = entry_point_file_offset(data)
    sect_starts = section_starts(data)
    for s in sigs:
        pat = s.get("pattern", [])
        if not pat:
            continue
        ep_only = bool(s.get("ep_only"))
        sec_start = bool(s.get("section_start"))
        if ep_only_strict and not ep_only:
            continue
        if ep_only:
            if ep is None:
                continue
            if match_at_offset(data, pat, ep):
                out.append({"name": s["name"], "offset": ep, "ep_only": True,
                            "confidence": confidence(pat)})
            continue
        if sec_start:
            for st in sect_starts:
                if match_at_offset(data, pat, st):
                    out.append({"name": s["name"], "offset": st, "ep_only": False,
                                "confidence": confidence(pat)})
                    break
            continue
        idx = find_pattern(data, pat)
        if idx is not None:
            out.append({"name": s["name"], "offset": idx, "ep_only": False,
                        "confidence": confidence(pat)})
    return out


# ---------------------------------------------------------------------------
# Rich header
# ---------------------------------------------------------------------------
def find_rich_header(data: bytes) -> dict | None:
    """Locate Rich header. Returns {"rich_off","dans_off","xor_key"} or None.

    The Rich block sits between the DOS stub and PE header; ends with the
    ASCII signature 'Rich' followed by the 4-byte XOR key. The start is
    marked by 'DanS' XOR key.
    """
    pe_off = locate_pe(data)
    if pe_off is None:
        return None
    blob = data[0x80:pe_off]
    rich = blob.rfind(b"Rich")
    if rich < 0 or rich + 8 > len(blob):
        return None
    key = blob[rich + 4 : rich + 8]
    # walk backwards searching for DanS xor key
    dans_target = bytes(a ^ b for a, b in zip(b"DanS", key))
    dans = blob.rfind(dans_target, 0, rich)
    if dans < 0:
        return None
    return {
        "rich_off": 0x80 + rich,
        "dans_off": 0x80 + dans,
        "xor_key": key.hex(),
    }


# ---------------------------------------------------------------------------
# Entropy helper (used by section heuristics)
# ---------------------------------------------------------------------------
def shannon_entropy(data: bytes) -> float:
    n = len(data)
    if n == 0:
        return 0.0
    counts = Counter(data)
    h = 0.0
    for c in counts.values():
        p = c / n
        h -= p * math.log2(p)
    return h


HIGH_ENTROPY_THRESHOLD = 7.0


def is_high_entropy(data: bytes, threshold: float = HIGH_ENTROPY_THRESHOLD) -> bool:
    return shannon_entropy(data) >= threshold


# ---------------------------------------------------------------------------
# JSON RPC-style dispatcher
# ---------------------------------------------------------------------------
def _b64(args: dict, key: str = "data_b64") -> bytes:
    return base64.b64decode(args.get(key, ""))


def _pattern_arg(a: dict) -> list[int | None]:
    if "pattern" in a:
        return [None if x is None else int(x) for x in a["pattern"]]
    return parse_peid_pattern(a["s"])


_DISPATCH = {
    "parse_peid_pattern": lambda a: [None if p is None else p for p in parse_peid_pattern(a["s"])],
    "match_at_offset": lambda a: match_at_offset(_b64(a), _pattern_arg(a), a["offset"]),
    "find_pattern": lambda a: find_pattern(_b64(a), _pattern_arg(a), a.get("start", 0)),
    "confidence": lambda a: confidence(_pattern_arg(a)),
    "parse_userdb": lambda a: parse_userdb(a["text"]),
    "dedup_signatures": lambda a: dedup_signatures(a["sigs"]),
    "merge_signatures": lambda a: merge_signatures(a["a"], a["b"]),
    "category_label": lambda a: category_label(a["cat"]),
    "entry_point_rva": lambda a: entry_point_rva(_b64(a)),
    "entry_point_file_offset": lambda a: entry_point_file_offset(_b64(a)),
    "rva_to_file_offset": lambda a: rva_to_file_offset(_b64(a), a["rva"]),
    "section_starts": lambda a: section_starts(_b64(a)),
    "scan": lambda a: scan(_b64(a), a["sigs"], a.get("ep_only_strict", False)),
    "find_rich_header": lambda a: find_rich_header(_b64(a)),
    "shannon_entropy": lambda a: shannon_entropy(_b64(a)),
    "is_high_entropy": lambda a: is_high_entropy(_b64(a), a.get("threshold", HIGH_ENTROPY_THRESHOLD)),
}


def _smoke() -> None:
    # parse pattern
    p = parse_peid_pattern("60 BE ?? ?? 8D BE")
    assert p == [0x60, 0xBE, None, None, 0x8D, 0xBE], p
    # match
    buf = b"\x00\x60\xBE\x11\x22\x8D\xBE\xFF"
    assert match_at_offset(buf, p, 1)
    assert not match_at_offset(buf, p, 0)
    assert find_pattern(buf, p) == 1
    # confidence
    c_full = confidence([0x90] * 32)
    assert abs(c_full - 1.0) < 1e-9, c_full
    c_short = confidence([0x90, 0x90])
    assert 0.5 < c_short < 0.6, c_short
    c_half = confidence([0x90, None] * 16)
    assert 0.4 < c_half < 0.6, c_half
    # userdb
    db = parse_userdb(
        "[UPX 3.x]\nsignature = 60 BE ?? ?? ?? ?? 8D BE\nep_only = true\n"
        "; comment\n[Foo]\nsignature=DEAD ?? BEEF\n"
    )
    assert len(db) == 2, db
    assert db[0]["name"] == "UPX 3.x" and db[0]["ep_only"] is True
    assert db[1]["pattern"] == [0xDE, 0xAD, None, 0xBE, 0xEF]
    # dedup
    assert len(dedup_signatures(db + db)) == 2
    # PE walker on non-PE
    assert locate_pe(b"not a pe") is None
    assert entry_point_rva(b"MZ" + b"\x00" * 64) is None
    # entropy
    assert abs(shannon_entropy(b"\x00" * 1024) - 0.0) < 1e-9
    assert abs(shannon_entropy(bytes(range(256))) - 8.0) < 1e-9
    assert is_high_entropy(bytes(range(256)))
    assert not is_high_entropy(b"\x00" * 1024)
    # categories
    assert category_label("Packer") == "packer"
    assert category_label("Bogus") == "unknown"
    # Rich header on non-PE returns None
    assert find_rich_header(b"not pe") is None
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
