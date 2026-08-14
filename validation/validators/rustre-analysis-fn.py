#!/usr/bin/env python3
"""
Independent Python validator for crate `rustre-analysis-fn`.

Re-implements the testable, externally-verifiable logic of the crate
(prologue matching, x86/ARM64 CALL/BL target extraction, gap analysis,
padding skip, function-end estimation, basic PE .pdata parsing) using
ONLY the Python standard library (+ optional pefile for .pdata).

No imports from the Rust crate, no MCP calls.

Usage:
    python rustre-analysis-fn.py             # runs built-in self-tests
    echo '{"fn":"...","input":{...}}' | python rustre-analysis-fn.py --stdin
"""

import json
import os
import sys
import struct
import subprocess
from typing import List, Tuple, Optional, Dict, Any


# ---------------------------------------------------------------------------
# Optional dependency: pefile (only needed for parse_pdata on real PEs)
# ---------------------------------------------------------------------------
def _ensure_pefile():
    try:
        import pefile  # noqa: F401
        return True
    except ImportError:
        try:
            subprocess.check_call(
                [sys.executable, "-m", "pip", "install", "--quiet", "pefile"]
            )
            import pefile  # noqa: F401
            return True
        except Exception:
            return False


# ===========================================================================
# 1. ProloguePattern::matches  — pure byte compare with `None` wildcards
# ===========================================================================
# Pattern = list[Optional[int]]; None = wildcard byte.

X86_64_PROLOGUES: List[Tuple[str, List[Optional[int]], str]] = [
    # name, pattern, confidence
    ("push_rbp_mov_rbp_rsp",       [0x55, 0x48, 0x89, 0xE5], "High"),
    ("push_rbp",                   [0x55],                   "Medium"),
    ("sub_rsp_imm8",               [0x48, 0x83, 0xEC, None], "Medium"),
    ("sub_rsp_imm32",              [0x48, 0x81, 0xEC, None, None, None, None], "Medium"),
    ("mov_rdi_rcx",                [0x48, 0x89, 0xCF],       "Low"),
    ("endbr64",                    [0xF3, 0x0F, 0x1E, 0xFA], "High"),
]

X86_32_PROLOGUES: List[Tuple[str, List[Optional[int]], str]] = [
    ("push_ebp_mov_ebp_esp", [0x55, 0x89, 0xE5], "High"),
    ("push_ebp",             [0x55],             "Medium"),
    ("sub_esp_imm8",         [0x83, 0xEC, None], "Medium"),
    ("endbr32",              [0xF3, 0x0F, 0x1E, 0xFB], "High"),
]

# ARM64 prologues are 32-bit LE words. We model them as 4-byte patterns with
# wildcards for the bits encoding registers/immediates.
ARM64_PROLOGUES: List[Tuple[str, List[Optional[int]], str]] = [
    # stp x29, x30, [sp, #-imm]!   pattern roughly: A9 ?? ?? ??
    ("stp_fp_lr",  [None, None, None, 0xA9], "High"),
    # sub sp, sp, #imm             D1 ?? ?? FF (approx)
    ("sub_sp",     [None, None, None, 0xD1], "Medium"),
    # paciasp                      7F 23 03 D5
    ("paciasp",    [0x7F, 0x23, 0x03, 0xD5], "High"),
]


def prologue_matches(pattern: List[Optional[int]], data: bytes) -> bool:
    if len(data) < len(pattern):
        return False
    for i, p in enumerate(pattern):
        if p is None:
            continue
        if data[i] != p:
            return False
    return True


def validator_prologue_patterns_x86_64() -> List[Dict[str, Any]]:
    return [{"name": n, "len": len(p), "confidence": c} for n, p, c in X86_64_PROLOGUES]


def validator_prologue_patterns_x86_32() -> List[Dict[str, Any]]:
    return [{"name": n, "len": len(p), "confidence": c} for n, p, c in X86_32_PROLOGUES]


def validator_prologue_patterns_arm64() -> List[Dict[str, Any]]:
    return [{"name": n, "len": len(p), "confidence": c} for n, p, c in ARM64_PROLOGUES]


def validator_prologue_matches(pattern: List[Optional[int]], data_hex: str) -> bool:
    return prologue_matches(pattern, bytes.fromhex(data_hex))


# ===========================================================================
# 2. CallTargetCollector — x86 E8 imm32 / ARM64 BL imm26
# ===========================================================================
def validator_collect_x86_calls(base_va: int, data_hex: str,
                                min_target: Optional[int] = None,
                                max_target: Optional[int] = None) -> List[int]:
    """Scan for `E8 imm32`; target = next_pc + signed disp32."""
    data = bytes.fromhex(data_hex)
    targets = []
    i = 0
    n = len(data)
    while i + 5 <= n:
        if data[i] == 0xE8:
            disp = struct.unpack("<i", data[i + 1:i + 5])[0]
            next_pc = base_va + i + 5
            tgt = (next_pc + disp) & 0xFFFFFFFFFFFFFFFF
            if (min_target is None or tgt >= min_target) and \
               (max_target is None or tgt < max_target):
                targets.append(tgt)
            i += 5
        else:
            i += 1
    return sorted(set(targets))


def validator_collect_arm64_calls(base_va: int, data_hex: str,
                                  min_target: Optional[int] = None,
                                  max_target: Optional[int] = None) -> List[int]:
    """4-byte aligned, opcode top 6 bits = 100101 (BL); imm26 sign-extended * 4."""
    data = bytes.fromhex(data_hex)
    targets = []
    n = (len(data) // 4) * 4
    for i in range(0, n, 4):
        word = struct.unpack("<I", data[i:i + 4])[0]
        if (word >> 26) == 0b100101:
            imm26 = word & 0x3FFFFFF
            # sign-extend 26 bits
            if imm26 & (1 << 25):
                imm26 -= (1 << 26)
            pc = base_va + i
            tgt = (pc + imm26 * 4) & 0xFFFFFFFFFFFFFFFF
            if (min_target is None or tgt >= min_target) and \
               (max_target is None or tgt < max_target):
                targets.append(tgt)
    return sorted(set(targets))


# ===========================================================================
# 3. GapAnalyzer
# ===========================================================================
def validator_find_gaps(known_starts: List[int],
                        code_start: int, code_end: int,
                        min_gap_size: int = 1) -> List[Tuple[int, int]]:
    """Pure interval arithmetic over sorted starts inside [code_start, code_end)."""
    starts = sorted(s for s in known_starts if code_start <= s < code_end)
    gaps: List[Tuple[int, int]] = []
    cursor = code_start
    for s in starts:
        if s - cursor >= min_gap_size:
            gaps.append((cursor, s))
        cursor = max(cursor, s + 1)  # at least 1 byte for the function start
    if code_end - cursor >= min_gap_size:
        gaps.append((cursor, code_end))
    return gaps


def validator_first_code_byte(gap_start: int, gap_end: int,
                              base_va: int, data_hex: str) -> Optional[int]:
    """Skip leading 0x90 / 0xCC padding; return VA of first non-padding byte."""
    data = bytes.fromhex(data_hex)
    for va in range(gap_start, gap_end):
        off = va - base_va
        if off < 0 or off >= len(data):
            return None
        if data[off] not in (0x90, 0xCC):
            return va
    return None


# ===========================================================================
# 4. FunctionDetector::estimate_end
# ===========================================================================
# x86 terminators: C3 (ret), C2 (ret imm16), CB, CA (far ret), EB (jmp short),
# E9 (jmp rel32), F4 (HLT), FF /4 /5 (indirect jmp). Stray CC also a hint.
X86_TERMINATORS_SINGLE = {0xC3, 0xCB, 0xF4}
def validator_estimate_end_x86(start: int, base_va: int, data_hex: str,
                               max_scan: int = 4096) -> Optional[int]:
    data = bytes.fromhex(data_hex)
    off0 = start - base_va
    if off0 < 0 or off0 >= len(data):
        return None
    end_off = min(len(data), off0 + max_scan)
    i = off0
    while i < end_off:
        b = data[i]
        if b in X86_TERMINATORS_SINGLE:
            return base_va + i + 1
        if b == 0xC2 or b == 0xCA:  # ret imm16
            return base_va + i + 3
        if b == 0xEB:               # jmp short rel8
            return base_va + i + 2
        if b == 0xE9:               # jmp near rel32
            return base_va + i + 5
        i += 1
    return None


# ARM64: RET (D65F03C0), RETAA (D65F0BFF), RETAB (D65F0FFF),
# unconditional B (opcode 000101 in top 6 bits).
def validator_estimate_end_arm64(start: int, base_va: int, data_hex: str,
                                 max_scan: int = 4096) -> Optional[int]:
    data = bytes.fromhex(data_hex)
    off0 = start - base_va
    if off0 < 0 or off0 % 4 != 0:
        return None
    end_off = min(len(data) - (len(data) % 4), off0 + max_scan)
    i = off0
    while i + 4 <= end_off:
        w = struct.unpack("<I", data[i:i + 4])[0]
        if w == 0xD65F03C0 or w == 0xD65F0BFF or w == 0xD65F0FFF:
            return base_va + i + 4
        if (w >> 26) == 0b000101:  # unconditional B
            return base_va + i + 4
        i += 4
    return None


# ===========================================================================
# 5. detect_functions — combined prologue + call-target + gap pipeline
# ===========================================================================
CONF_RANK = {"Low": 1, "Medium": 2, "High": 3}


def _scan_prologues(base_va: int, data: bytes,
                    patterns: List[Tuple[str, List[Optional[int]], str]]
                    ) -> Dict[int, Tuple[str, str]]:
    """Return {va: (confidence, source_name)} keeping highest confidence per VA."""
    out: Dict[int, Tuple[str, str]] = {}
    for i in range(len(data)):
        for name, pat, conf in patterns:
            if prologue_matches(pat, data[i:i + len(pat)]):
                va = base_va + i
                prev = out.get(va)
                if prev is None or CONF_RANK[conf] > CONF_RANK[prev[0]]:
                    out[va] = (conf, f"prologue:{name}")
                break  # one prologue per offset is enough
    return out


def validator_detect_functions_x86_64(base_va: int, data_hex: str,
                                      min_size: int = 1) -> List[Dict[str, Any]]:
    data = bytes.fromhex(data_hex)
    prologues = _scan_prologues(base_va, data, X86_64_PROLOGUES)
    # call targets contribute Medium-confidence candidates inside the slice
    call_targets = validator_collect_x86_calls(
        base_va, data_hex,
        min_target=base_va, max_target=base_va + len(data),
    )
    candidates: Dict[int, Tuple[str, str]] = dict(prologues)
    for tgt in call_targets:
        if tgt not in candidates:
            candidates[tgt] = ("Medium", "call_target")
    result = []
    for va, (conf, src) in sorted(candidates.items()):
        end = validator_estimate_end_x86(va, base_va, data_hex)
        if end is not None and end - va < min_size:
            continue
        result.append({
            "start": va,
            "end": end,
            "confidence": conf,
            "source": src,
        })
    return result


# ===========================================================================
# 6. strategies::parse_pdata — PE32+ exception directory
# ===========================================================================
def validator_parse_pdata(pe_path: str) -> List[Dict[str, int]]:
    """Parse PE32+ .pdata RUNTIME_FUNCTION entries (BeginAddress, EndAddress,
    UnwindData). Returns list of dicts with image-VA addresses."""
    if not _ensure_pefile():
        return []
    import pefile
    pe = pefile.PE(pe_path, fast_load=True)
    pe.parse_data_directories(directories=[
        pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_EXCEPTION"]
    ])
    out = []
    image_base = pe.OPTIONAL_HEADER.ImageBase
    entries = getattr(pe, "DIRECTORY_ENTRY_EXCEPTION", None) or []
    for e in entries:
        sf = e.struct
        out.append({
            "begin_va": image_base + sf.BeginAddress,
            "end_va":   image_base + sf.EndAddress,
            "unwind":   image_base + sf.UnwindData,
        })
    return out


# ===========================================================================
# Dispatcher & self-tests
# ===========================================================================
FUNCTIONS_VALIDATED = [
    "prologue_patterns_x86_64",
    "prologue_patterns_x86_32",
    "prologue_patterns_arm64",
    "prologue_matches",
    "collect_x86_calls",
    "collect_arm64_calls",
    "find_gaps",
    "first_code_byte",
    "estimate_end_x86",
    "estimate_end_arm64",
    "detect_functions_x86_64",
    "parse_pdata",
]

LIBS_USED = ["stdlib(struct,hashlib,json,subprocess)", "pefile (optional, on demand)"]


DISPATCH = {
    "prologue_patterns_x86_64":   lambda i: validator_prologue_patterns_x86_64(),
    "prologue_patterns_x86_32":   lambda i: validator_prologue_patterns_x86_32(),
    "prologue_patterns_arm64":    lambda i: validator_prologue_patterns_arm64(),
    "prologue_matches":           lambda i: validator_prologue_matches(i["pattern"], i["data_hex"]),
    "collect_x86_calls":          lambda i: validator_collect_x86_calls(
        i["base_va"], i["data_hex"], i.get("min_target"), i.get("max_target")),
    "collect_arm64_calls":        lambda i: validator_collect_arm64_calls(
        i["base_va"], i["data_hex"], i.get("min_target"), i.get("max_target")),
    "find_gaps":                  lambda i: validator_find_gaps(
        i["known_starts"], i["code_start"], i["code_end"], i.get("min_gap_size", 1)),
    "first_code_byte":            lambda i: validator_first_code_byte(
        i["gap_start"], i["gap_end"], i["base_va"], i["data_hex"]),
    "estimate_end_x86":           lambda i: validator_estimate_end_x86(
        i["start"], i["base_va"], i["data_hex"], i.get("max_scan", 4096)),
    "estimate_end_arm64":         lambda i: validator_estimate_end_arm64(
        i["start"], i["base_va"], i["data_hex"], i.get("max_scan", 4096)),
    "detect_functions_x86_64":    lambda i: validator_detect_functions_x86_64(
        i["base_va"], i["data_hex"], i.get("min_size", 1)),
    "parse_pdata":                lambda i: validator_parse_pdata(i["path"]),
}


def _self_test() -> None:
    print("[*] Running self-tests")

    # 1. prologue_matches
    assert prologue_matches([0x55, 0x48, 0x89, 0xE5], b"\x55\x48\x89\xE5\x00")
    assert not prologue_matches([0x55, 0x48], b"\x90\x48")
    assert prologue_matches([0x48, 0x83, 0xEC, None], b"\x48\x83\xEC\x20")
    print("    prologue_matches OK")

    # 2. x86 CALL target: base=0x1000, E8 with disp -> next_pc + disp
    # E8 05 00 00 00 at offset 0 -> next_pc = 0x1005, target = 0x100A
    targets = validator_collect_x86_calls(0x1000, "E805000000")
    assert targets == [0x100A], targets
    # Negative disp
    targets = validator_collect_x86_calls(0x1000, "E8FBFFFFFF")
    assert targets == [0x1000], targets
    # Window filter
    assert validator_collect_x86_calls(0x1000, "E805000000",
                                       min_target=0x2000) == []
    print("    collect_x86_calls OK")

    # 3. ARM64 BL: BL +4 at PC=0x4000 -> target 0x4004
    # BL imm26 = 1 ; opcode 100101 -> word = (0x25<<26)|1 = 0x94000001
    bl = struct.pack("<I", 0x94000001).hex()
    assert validator_collect_arm64_calls(0x4000, bl) == [0x4004]
    # BL -4 -> imm26 = 0x3FFFFFF (-1) -> target 0x3FFC
    bl_neg = struct.pack("<I", 0x97FFFFFF).hex()
    assert validator_collect_arm64_calls(0x4000, bl_neg) == [0x3FFC]
    print("    collect_arm64_calls OK")

    # 4. find_gaps
    gaps = validator_find_gaps([0x100, 0x200], 0x0, 0x300, min_gap_size=1)
    assert gaps == [(0x0, 0x100), (0x101, 0x200), (0x201, 0x300)], gaps
    print("    find_gaps OK")

    # 5. first_code_byte: skip 90 90 CC then real byte
    fb = validator_first_code_byte(0x0, 0x10, 0x0, "9090CC55")
    assert fb == 0x3, fb
    print("    first_code_byte OK")

    # 6. estimate_end_x86 — prologue (4 bytes) + 3 bytes + C3 at offset 7
    end = validator_estimate_end_x86(0x0, 0x0, "554889E500000FC3")
    assert end == 0x8, hex(end) if end else end
    # JMP rel32 case
    end_jmp = validator_estimate_end_x86(0x0, 0x0, "E900000000")
    assert end_jmp == 0x5, end_jmp
    print("    estimate_end_x86 OK")

    # 7. estimate_end_arm64 — RET (D65F03C0) at offset 4
    arm_bytes = "1F2003D5" + "C0035FD6"  # NOP then RET
    end_a = validator_estimate_end_arm64(0x0, 0x0, arm_bytes)
    assert end_a == 0x8, end_a
    print("    estimate_end_arm64 OK")

    # 8. detect_functions_x86_64 — synthetic blob: prologue at 0, prologue at 16
    blob = (
        bytes([0x55, 0x48, 0x89, 0xE5]) + b"\x90" * 11 + b"\xC3"
        + bytes([0x55, 0x48, 0x89, 0xE5]) + b"\x90" * 11 + b"\xC3"
    )
    funcs = validator_detect_functions_x86_64(0x1000, blob.hex())
    starts = [f["start"] for f in funcs if f["confidence"] == "High"]
    assert 0x1000 in starts and 0x1010 in starts, starts
    print("    detect_functions_x86_64 OK")

    # 9. parse_pdata — only if pefile available and the user has cargo-zyphora.exe
    candidates = [
        r"C:\Users\Fra\Desktop\RustRE\fixtures\cargo-zyphora.exe",
        r"C:\Users\Fra\Desktop\RustRE\cargo-zyphora.exe",
    ]
    pe_path = next((p for p in candidates if os.path.isfile(p)), None)
    if pe_path and _ensure_pefile():
        entries = validator_parse_pdata(pe_path)
        print(f"    parse_pdata: {len(entries)} RUNTIME_FUNCTION entries from {pe_path}")
        assert len(entries) > 0
    else:
        print("    parse_pdata: skipped (no fixture / pefile)")

    print("[+] All self-tests passed")


def main() -> int:
    if "--stdin" in sys.argv:
        req = json.loads(sys.stdin.read())
        fn = req["fn"]
        if fn not in DISPATCH:
            print(json.dumps({"error": f"unknown fn: {fn}"}))
            return 1
        out = DISPATCH[fn](req.get("input", {}))
        print(json.dumps({"fn": fn, "output": out}, default=list))
        return 0
    _self_test()
    return 0


if __name__ == "__main__":
    sys.exit(main())
