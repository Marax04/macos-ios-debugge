#!/usr/bin/env python3
"""Independent stdlib validator for rustre-flirt-apply.

Implements:
- IDA .pat line parser (wildcards ??/./..)
- CRC-16/MCRF4XX (poly 0x8408 reflected, init 0xFFFF) — crc16_flirt
- Pattern matching with wildcards
- Confidence scoring: concrete ratio * 80 + length bonus (up to 20 for >=16), cap 100
- Linear scan with optional CRC verification
- library_marks_from_matches projection (filters empty lib_name)
- Auto-detect .sig (magic IDASGN) vs .pat
"""

import json
import os
import sys
from pathlib import Path


# -------- CRC-16/MCRF4XX --------
def crc16_flirt(data: bytes) -> int:
    crc = 0xFFFF
    for b in data:
        crc ^= b
        for _ in range(8):
            if crc & 1:
                crc = (crc >> 1) ^ 0x8408
            else:
                crc >>= 1
    return crc & 0xFFFF


# -------- Pattern model --------
class FlirtPattern:
    __slots__ = ("bytes_", "name", "lib_name", "crc_offset", "crc_len", "crc")

    def __init__(self, bytes_, name="", lib_name="", crc_offset=0, crc_len=0, crc=0):
        self.bytes_ = bytes_  # list[Optional[int]]
        self.name = name
        self.lib_name = lib_name
        self.crc_offset = crc_offset
        self.crc_len = crc_len
        self.crc = crc

    def pattern_len(self):
        return len(self.bytes_)

    def matches(self, data: bytes) -> bool:
        if len(data) < len(self.bytes_):
            return False
        for i, b in enumerate(self.bytes_):
            if b is not None and data[i] != b:
                return False
        return True


def from_pattern_str(pattern: str, name="", lib=""):
    toks = pattern.split()
    if len(toks) < 4:
        raise ValueError(f"PatternTooShort({len(toks)})")
    out = []
    for t in toks:
        if t in ("??", ".", ".."):
            out.append(None)
        else:
            try:
                out.append(int(t, 16))
            except ValueError:
                raise ValueError(f"Parse: invalid token {t!r}")
    return FlirtPattern(out, name, lib)


# -------- Confidence --------
def compute_confidence(pat: FlirtPattern) -> int:
    n = len(pat.bytes_)
    if n == 0:
        return 0
    concrete = sum(1 for b in pat.bytes_ if b is not None)
    ratio_score = (concrete * 80) // n
    length_bonus = 20 if n >= 16 else (n * 20) // 16
    score = ratio_score + length_bonus
    return min(score, 100)


# -------- Scanning --------
def scan_bytes(data: bytes, sigs, base_addr: int, min_conf: int = 60):
    """Returns list of (addr, name, confidence)."""
    matches = []
    for p in sigs:
        plen = p.pattern_len()
        if plen == 0:
            continue
        conf = compute_confidence(p)
        if conf < min_conf:
            continue
        # sliding window
        for off in range(0, len(data) - plen + 1):
            window = data[off:off + plen]
            if not p.matches(window):
                continue
            # CRC check
            if p.crc_len > 0:
                crc_start = off + p.crc_offset
                crc_end = crc_start + p.crc_len
                if crc_end > len(data):
                    continue
                if crc16_flirt(data[crc_start:crc_end]) != p.crc:
                    continue
            matches.append((base_addr + off, p.name, conf))
    return matches


# -------- Library marks --------
def library_marks_from_matches(matches):
    """matches: list of dicts with 'address','lib_name' or tuple-like; filter empty lib_name."""
    out = []
    for m in matches:
        if isinstance(m, dict):
            lib = m.get("lib_name", "")
            addr = m.get("address", 0)
        else:
            addr, lib = m[0], m[1]
        if lib:
            out.append((addr, lib))
    return out


# -------- File loader --------
SIG_MAGIC = b"IDASGN"


def detect_format(path: Path) -> str:
    with open(path, "rb") as f:
        head = f.read(6)
    return "sig" if head == SIG_MAGIC else "pat"


def load_pat_file(path: Path):
    """Minimal .pat parser. Lines like: 5589E5 ?? ?? ?? 00 0000 0010 :0000 funcname"""
    pats = []
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("---") or line.startswith(";"):
                continue
            toks = line.split()
            if len(toks) < 2:
                continue
            byte_str = toks[0]
            bytes_ = []
            i = 0
            while i + 1 < len(byte_str):
                pair = byte_str[i:i + 2]
                if pair in ("??", ".."):
                    bytes_.append(None)
                else:
                    try:
                        bytes_.append(int(pair, 16))
                    except ValueError:
                        bytes_.append(None)
                i += 2
            if len(bytes_) < 4:
                continue
            name = ""
            for t in toks:
                if t.startswith(":"):
                    idx = toks.index(t)
                    if idx + 1 < len(toks):
                        name = toks[idx + 1]
                    break
            pats.append(FlirtPattern(bytes_, name=name))
    return pats


# -------- Self-tests --------
def _selftest():
    # CRC test: known vector for empty -> 0xFFFF
    assert crc16_flirt(b"") == 0xFFFF
    # Pattern parse
    p = from_pattern_str("55 8B EC ?? 8B 45", "f", "lib")
    assert p.pattern_len() == 6
    assert p.bytes_[3] is None
    # Match
    assert p.matches(bytes([0x55, 0x8B, 0xEC, 0xAA, 0x8B, 0x45]))
    assert not p.matches(bytes([0x55, 0x8B, 0xED, 0xAA, 0x8B, 0x45]))
    # Too short
    try:
        from_pattern_str("55 8B EC", "x", "y")
        assert False, "expected PatternTooShort"
    except ValueError:
        pass
    # Confidence: all concrete, 16 bytes -> 100
    full = FlirtPattern([0x90] * 16)
    assert compute_confidence(full) == 100
    # Half wildcards, 16 bytes -> (8*80//16) + 20 = 40 + 20 = 60
    half = FlirtPattern([0x90 if i % 2 == 0 else None for i in range(16)])
    assert compute_confidence(half) == 60
    # Empty
    assert compute_confidence(FlirtPattern([])) == 0
    # Scan
    data = b"\x00\x00\x55\x8B\xEC\xAA\x8B\x45\x00"
    pats = [from_pattern_str("55 8B EC ?? 8B 45", "func", "lib")]
    ms = scan_bytes(data, pats, base_addr=0x1000, min_conf=0)
    assert any(m[0] == 0x1002 and m[1] == "func" for m in ms)
    # CRC scan
    body = bytes([0x55, 0x8B, 0xEC, 0x90])
    crc_region = bytes([0x11, 0x22, 0x33])
    expected_crc = crc16_flirt(crc_region)
    full_data = body + crc_region
    cp = FlirtPattern([0x55, 0x8B, 0xEC, 0x90], name="crcfunc", lib_name="L",
                      crc_offset=4, crc_len=3, crc=expected_crc)
    ms = scan_bytes(full_data, [cp], 0, min_conf=0)
    assert len(ms) == 1, f"expected 1 crc match, got {ms}"
    # CRC mismatch suppresses
    cp_bad = FlirtPattern([0x55, 0x8B, 0xEC, 0x90], name="x", lib_name="L",
                          crc_offset=4, crc_len=3, crc=expected_crc ^ 0xFFFF)
    ms = scan_bytes(full_data, [cp_bad], 0, min_conf=0)
    assert ms == []
    # library_marks projection
    marks = library_marks_from_matches([
        {"address": 1, "lib_name": "libc"},
        {"address": 2, "lib_name": ""},
        {"address": 3, "lib_name": "ntdll"},
    ])
    assert marks == [(1, "libc"), (3, "ntdll")]
    # Auto-detect
    import tempfile
    with tempfile.TemporaryDirectory() as td:
        sigp = Path(td) / "a.sig"
        sigp.write_bytes(SIG_MAGIC + b"\x00\x00")
        assert detect_format(sigp) == "sig"
        patp = Path(td) / "a.pat"
        patp.write_text("5589EC90 00 0000 0010 :0000 demo\n")
        assert detect_format(patp) == "pat"
        loaded = load_pat_file(patp)
        assert len(loaded) == 1 and loaded[0].name == "demo"
    return True


def main():
    ok = _selftest()
    out_dir = Path(__file__).resolve().parent.parent / "outputs"
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / "rustre-flirt-apply.json"
    result = {"crate": "rustre-flirt-apply", "saved": bool(ok)}
    out_path.write_text(json.dumps(result, indent=2))
    print(json.dumps(result))


if __name__ == "__main__":
    main()
