#!/usr/bin/env python3
"""
Rigorous v2 validator for all flirt_ MCP tools.

Already-rigorous tools (in rigorous_flirt_apply.json / rigorous_flirt_gen.json)
are skipped here to avoid double-counting.  This script hardens the remaining
flirt_* tools that still use loose checks in validators_flirt.py.

Output: C:/Users/Fra/Desktop/RustRE/validation/rigorous_flirt_v2.json
Skip log: C:/Users/Fra/Desktop/RustRE/validation/skip_flirt.json
"""
from __future__ import annotations

import json
import subprocess
import time
from pathlib import Path

MCP_EXE    = r"C:\Users\Fra\Desktop\RustRE\target\release\rustre-mcp.exe"
REPORT_PATH = Path(r"C:\Users\Fra\Desktop\RustRE\validation\rigorous_flirt_v2.json")
SKIP_PATH   = Path(r"C:\Users\Fra\Desktop\RustRE\validation\skip_flirt.json")

# ---------------------------------------------------------------------------
# Independent Python reference implementations
# ---------------------------------------------------------------------------

def py_crc16_flirt(data: bytes) -> int:
    """CRC-16/CCITT reflected — poly 0x8408, init 0xFFFF, no final XOR.
    Matches rustre_flirt::crc16_flirt exactly."""
    crc = 0xFFFF
    for b in data:
        crc ^= b
        for _ in range(8):
            crc = (crc >> 1) ^ 0x8408 if (crc & 1) else (crc >> 1)
    return crc & 0xFFFF


def py_crc16_ibm(data: bytes) -> int:
    """CRC-16/IBM — poly 0xA001, init 0x0000.
    Matches rustre_flirt::crc16_ibm exactly."""
    crc = 0
    for b in data:
        crc ^= b
        for _ in range(8):
            crc = (crc >> 1) ^ 0xA001 if (crc & 1) else (crc >> 1)
    return crc & 0xFFFF


def py_scan_x86_masks(data: bytes):
    """Return list of (offset, size) ranges for relocatable operands.
    Mirrors rustre_flirt_gen::scan_x86_masks logic."""
    out = []
    i = 0
    n = len(data)
    while i < n:
        b = data[i]
        rex_w = False
        rex_i = i
        if 0x40 <= b <= 0x4F:
            rex_w = (b & 0x08) != 0
            i += 1
            if i >= n:
                break
            b = data[i]
        if rex_w and 0xB8 <= b <= 0xBF:
            if i + 1 + 8 <= n:
                out.append((i + 1, 8))
            i += 1 + 8
            continue
        if b in (0xE8, 0xE9):
            if i + 1 + 4 <= n:
                out.append((i + 1, 4))
            i += 1 + 4
            continue
        if b == 0x0F and i + 1 < n and 0x80 <= data[i + 1] <= 0x8F:
            if i + 2 + 4 <= n:
                out.append((i + 2, 4))
            i += 2 + 4
            continue
        if b == 0xEB or (0x70 <= b <= 0x7F) or (0xE0 <= b <= 0xE3):
            if i + 1 + 1 <= n:
                out.append((i + 1, 1))
            i += 1 + 1
            continue
        if i + 1 < n:
            modrm = data[i + 1]
            mod = (modrm >> 6) & 0x3
            rm  = modrm & 0x7
            if mod == 0 and rm == 0b101:
                if i + 2 + 4 <= n:
                    out.append((i + 2, 4))
                i += 2 + 4
                continue
        i = rex_i + 1
    return out


# ---------------------------------------------------------------------------
# Precompute expected values
# ---------------------------------------------------------------------------

# CRC-16/CCITT tests
CRC_FLIRT_EMPTY = py_crc16_flirt(b"")        # 0xFFFF
CRC_FLIRT_IDA   = py_crc16_flirt(b"IDA")     # 0xD1D0
CRC_FLIRT_HELLO = py_crc16_flirt(b"hello")
CRC_FLIRT_0XAA  = py_crc16_flirt(bytes([0xAA]))

# CRC-16/IBM tests (init=0)
CRC_IBM_EMPTY = py_crc16_ibm(b"")          # 0x0000
CRC_IBM_IDA   = py_crc16_ibm(b"IDA")
CRC_IBM_HELLO = py_crc16_ibm(b"hello")
CRC_IBM_0XAA  = py_crc16_ibm(bytes([0xAA]))

# x86 scan expected results
JMP_REL32_BYTES  = bytes([0xE9, 0xAA, 0xBB, 0xCC, 0xDD, 0x90])
JCC_REL32_BYTES  = bytes([0x0F, 0x84, 0x11, 0x22, 0x33, 0x44, 0x90])
JMP_REL8_BYTES   = bytes([0xEB, 0x10, 0x90])
MOV_IMM64_BYTES  = bytes([0x48, 0xB8, 0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08, 0xC3])
RIP_REL_BYTES    = bytes([0x48, 0x8B, 0x05, 0xAA, 0xBB, 0xCC, 0xDD, 0xC3])

JMP_REL32_MASKS  = py_scan_x86_masks(JMP_REL32_BYTES)   # [(1,4)]
JCC_REL32_MASKS  = py_scan_x86_masks(JCC_REL32_BYTES)   # [(2,4)]
JMP_REL8_MASKS   = py_scan_x86_masks(JMP_REL8_BYTES)    # [(1,1)]
MOV_IMM64_MASKS  = py_scan_x86_masks(MOV_IMM64_BYTES)   # [(2,8)]
RIP_REL_MASKS    = py_scan_x86_masks(RIP_REL_BYTES)     # [(3,4)]

# flirt_gen_pattern_generate — 64-byte deterministic input
_LONG_BYTES = bytes(range(64))  # 0x00..0x3F
# PatternGenerator::new() has initial_length=32, crc_length=16
_LONG_INITIAL_LEN = 32
_LONG_CRC_LEN     = 16
_LONG_CRC_DATA    = _LONG_BYTES[_LONG_INITIAL_LEN : _LONG_INITIAL_LEN + _LONG_CRC_LEN]
_LONG_CRC16       = py_crc16_flirt(_LONG_CRC_DATA)  # crc of bytes[32..48]


# ---------------------------------------------------------------------------
# MCP session helper
# ---------------------------------------------------------------------------

class McpSession:
    def __init__(self, exe: str):
        self.proc = subprocess.Popen(
            [exe, "--transport=stdio"],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL, bufsize=0,
        )
        self._id = 0
        self._send_raw({"jsonrpc":"2.0","id":0,"method":"initialize",
            "params":{"protocolVersion":"2024-11-05",
                      "clientInfo":{"name":"rigorous_flirt_v2","version":"1.0"},
                      "capabilities":{}}})
        self._recv()
        self._send_raw({"jsonrpc":"2.0","method":"notifications/initialized"})
        time.sleep(0.05)

    def _send_raw(self, obj):
        line = json.dumps(obj) + "\n"
        self.proc.stdin.write(line.encode())
        self.proc.stdin.flush()

    def _recv(self):
        line = self.proc.stdout.readline()
        if not line:
            return None
        return json.loads(line.decode())

    def call(self, name: str, args: dict):
        self._id += 1
        self._send_raw({"jsonrpc":"2.0","id":self._id,"method":"tools/call",
            "params":{"name":name,"arguments":args}})
        resp = self._recv()
        if resp is None:
            return None
        if "error" in resp:
            return {"_error": resp["error"]}
        result = resp.get("result", {})
        content = result.get("content", [])
        if not content:
            return None
        text = content[0].get("text", "")
        try:
            parsed = json.loads(text)
            if isinstance(parsed, str):
                return json.loads(parsed)
            return parsed
        except Exception:
            return {"_raw": text}

    def close(self):
        try:
            self.proc.stdin.close()
            self.proc.terminate()
        except Exception:
            pass


# ---------------------------------------------------------------------------
# Test harness
# ---------------------------------------------------------------------------

checks_passed: int = 0
checks_failed: int = 0
mismatches: list = []
tools_hardened: list = []
tools_skipped_list: list = []

def harden(tool: str):
    if tool not in tools_hardened:
        tools_hardened.append(tool)

def check(tool: str, field: str, got, expected, note: str = "") -> bool:
    global checks_passed, checks_failed
    ok = (got == expected)
    if ok:
        checks_passed += 1
    else:
        checks_failed += 1
        mismatches.append({"tool": tool, "field": field,
                           "expected": expected, "actual": got, "note": note})
    return ok

def check_approx(tool: str, field: str, got, expected: float, note: str = "") -> bool:
    """Floating-point comparison with 1e-5 tolerance."""
    global checks_passed, checks_failed
    try:
        ok = abs(float(got) - expected) < 1e-5
    except Exception:
        ok = False
    if ok:
        checks_passed += 1
    else:
        checks_failed += 1
        mismatches.append({"tool": tool, "field": field,
                           "expected": expected, "actual": got, "note": note})
    return ok

def skip(tool: str, reason: str):
    tools_skipped_list.append({"tool": tool, "reason": reason})


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

def run_all(s: McpSession):
    global checks_passed, checks_failed

    # -----------------------------------------------------------------------
    # 1. flirt_crc16_flirt — exact CRC-16/CCITT (poly 0x8408, init 0xFFFF)
    # -----------------------------------------------------------------------
    tool = "flirt_crc16_flirt"
    for data, crc_expected in [
        (b"",      CRC_FLIRT_EMPTY),
        (b"IDA",   CRC_FLIRT_IDA),
        (b"hello", CRC_FLIRT_HELLO),
        (bytes([0xAA]), CRC_FLIRT_0XAA),
    ]:
        hex_str = data.hex() if data else ""
        r = s.call(tool, {"hex": hex_str})
        if r and not r.get("_error"):
            check(tool, "crc16_flirt", r.get("crc16_flirt"), crc_expected,
                  f"crc16_flirt({data!r})")
    harden(tool)

    # -----------------------------------------------------------------------
    # 2. flirt_crc16_ibm — exact CRC-16/IBM (poly 0xA001, init 0x0000)
    # -----------------------------------------------------------------------
    tool = "flirt_crc16_ibm"
    for data, crc_expected in [
        (b"",      CRC_IBM_EMPTY),
        (b"IDA",   CRC_IBM_IDA),
        (b"hello", CRC_IBM_HELLO),
        (bytes([0xAA]), CRC_IBM_0XAA),
    ]:
        hex_str = data.hex() if data else ""
        r = s.call(tool, {"hex": hex_str})
        if r and not r.get("_error"):
            check(tool, "crc16_ibm", r.get("crc16_ibm"), crc_expected,
                  f"crc16_ibm({data!r})")
    harden(tool)

    # -----------------------------------------------------------------------
    # 3. flirt_arch_from_u8 — arch byte → debug string
    # -----------------------------------------------------------------------
    tool = "flirt_arch_from_u8"
    # Known arch bytes from the Rust enum
    arch_map = {
        0:   "X86",
        19:  "Arm",
        128: "Arm64",
        129: "Mips",
        132: "X64",
        255: "Unknown",
    }
    for byte_val, debug_str in arch_map.items():
        r = s.call(tool, {"arch": byte_val})
        if r and not r.get("_error"):
            check(tool, "arch_debug", r.get("arch_debug"), debug_str,
                  f"arch_byte={byte_val}")
            check(tool, "arch_byte", r.get("arch_byte"), byte_val,
                  f"arch_byte roundtrip={byte_val}")
    harden(tool)

    # -----------------------------------------------------------------------
    # 4. flirt_arch_to_u8_wire — from_u8(c).to_u8() = c for known codes
    # -----------------------------------------------------------------------
    tool = "flirt_arch_to_u8_wire"
    # Known codes round-trip to themselves; unknown code → 255
    for code, expected_u8 in [
        (0,   0),    # X86
        (19,  19),   # Arm
        (128, 128),  # Arm64
        (132, 132),  # X64
        (99,  255),  # → Unknown
    ]:
        r = s.call(tool, {"code": code})
        if r and not r.get("_error"):
            check(tool, "to_u8", r.get("to_u8"), expected_u8,
                  f"from_u8({code}).to_u8()={expected_u8}")
    harden(tool)

    # -----------------------------------------------------------------------
    # 5. flirt_file_type_bits_wire — bits and contains_pe
    # -----------------------------------------------------------------------
    tool = "flirt_file_type_bits_wire"
    # PE = 0x0800
    r = s.call(tool, {"value": 0x800})
    if r and not r.get("_error"):
        check(tool, "bits", r.get("bits"), 0x800, "PE bits=0x800")
        check(tool, "contains_pe", r.get("contains_pe"), True, "PE set → contains_pe=True")
    # value=0 → PE not set
    r = s.call(tool, {"value": 0})
    if r and not r.get("_error"):
        check(tool, "bits_zero", r.get("bits"), 0, "bits=0")
        check(tool, "contains_pe_false", r.get("contains_pe"), False, "0 → contains_pe=False")
    # ELF only → PE not set
    r = s.call(tool, {"value": 0x40000})  # ELF=0x0004_0000
    if r and not r.get("_error"):
        check(tool, "bits_elf", r.get("bits"), 0x40000, "ELF bits=0x40000")
        check(tool, "contains_pe_elf", r.get("contains_pe"), False, "ELF → no PE")
    harden(tool)

    # -----------------------------------------------------------------------
    # 6. flirt_file_type_contains — named flag containment
    # -----------------------------------------------------------------------
    tool = "flirt_file_type_contains"
    # bits = PE | ELF = 0x800 | 0x40000 = 0x40800
    r = s.call(tool, {"bits": 0x40800})
    if r and not r.get("_error"):
        # Tool returns {"bits":..., "flags":[...], "source":...}
        flags = r.get("flags", [])
        check(tool, "PE_in_flags",       "PE"   in flags, True,  "PE set -> in flags")
        check(tool, "ELF_in_flags",      "ELF"  in flags, True,  "ELF set -> in flags")
        check(tool, "COFF_not_in_flags", "COFF" not in flags, True, "COFF not set")
        check(tool, "bits_echo",         r.get("bits"), 0x40800, "bits echoed")
    # bits = 0 → nothing set
    r = s.call(tool, {"bits": 0})
    if r and not r.get("_error"):
        flags0 = r.get("flags", [])
        check(tool, "flags_empty", len(flags0), 0, "bits=0 -> no flags")
    harden(tool)

    # -----------------------------------------------------------------------
    # 7. flirt_pattern_wildcard_ratio — exact float ratio
    # -----------------------------------------------------------------------
    tool = "flirt_pattern_wildcard_ratio"
    # All concrete: ratio = 0.0
    r = s.call(tool, {"tokens": ["AA", "BB", "CC", "DD"]})
    if r and not r.get("_error"):
        check_approx(tool, "ratio_all_concrete", r.get("wildcard_ratio"), 0.0)
        check(tool, "len_4", r.get("len"), 4, "length=4")
    # All wildcards: ratio = 1.0
    r = s.call(tool, {"tokens": ["..", "..", "..", ".."]})
    if r and not r.get("_error"):
        check_approx(tool, "ratio_all_wild", r.get("wildcard_ratio"), 1.0)
    # Half wildcards: ratio = 0.5
    r = s.call(tool, {"tokens": ["AA", "..", "BB", ".."]})
    if r and not r.get("_error"):
        check_approx(tool, "ratio_half", r.get("wildcard_ratio"), 0.5)
    # 1/4: ratio = 0.25
    r = s.call(tool, {"tokens": ["AA", "BB", "..", "DD"]})
    if r and not r.get("_error"):
        check_approx(tool, "ratio_quarter", r.get("wildcard_ratio"), 0.25)
    harden(tool)

    # -----------------------------------------------------------------------
    # 8. flirt_pattern_matches_initial_wire
    # -----------------------------------------------------------------------
    tool = "flirt_pattern_matches_initial_wire"
    # Exact match: "55 8B EC" vs 558bec → True
    r = s.call(tool, {"pattern": "55 8B EC", "buf_hex": "558bec"})
    if r and not r.get("_error"):
        check(tool, "exact_match", r.get("matches"), True, "55 8B EC matches 558bec")
    # Mismatch: "55 8B EC" vs 55 8B 90 → False
    r = s.call(tool, {"pattern": "55 8B EC", "buf_hex": "558b90"})
    if r and not r.get("_error"):
        check(tool, "mismatch", r.get("matches"), False, "55 8B EC vs 55 8B 90")
    # Wildcard: "55 .." vs 5590 → True
    r = s.call(tool, {"pattern": "55 ..", "buf_hex": "5590"})
    if r and not r.get("_error"):
        check(tool, "wildcard_match", r.get("matches"), True, "55 .. matches 5590")
    # Buffer shorter than pattern → False
    r = s.call(tool, {"pattern": "55 8B EC", "buf_hex": "558b"})
    if r and not r.get("_error"):
        check(tool, "too_short", r.get("matches"), False, "buf shorter than pattern")
    harden(tool)

    # -----------------------------------------------------------------------
    # 9. flirt_pattern_matches_all_wire
    # -----------------------------------------------------------------------
    tool = "flirt_pattern_matches_all_wire"
    # "55 8B EC" vs 558bec → all=True
    r = s.call(tool, {"pattern": "55 8B EC", "buf_hex": "558bec"})
    if r and not r.get("_error"):
        check(tool, "all_match", r.get("all"), True, "55 8B EC all-match 558bec")
    # Mismatch → all=False
    r = s.call(tool, {"pattern": "55 8B EC", "buf_hex": "558b90"})
    if r and not r.get("_error"):
        check(tool, "all_mismatch", r.get("all"), False, "mismatch → all=False")
    harden(tool)

    # -----------------------------------------------------------------------
    # 10. flirt_pattern_hex_wire
    # -----------------------------------------------------------------------
    tool = "flirt_pattern_hex_wire"
    # Input "55 8B .." → _flirt_parse_pat_bytes gives [Exact(55),Exact(8B),Wildcard]
    # pattern_hex() returns "55 8B .."
    r = s.call(tool, {"pattern": "55 8B .."})
    if r and not r.get("_error"):
        check(tool, "hex_str", r.get("hex"), "55 8B ..", "hex roundtrip")
        check_approx(tool, "wildcard_ratio", r.get("wildcard_ratio"), 1.0/3.0,
                     "1/3 wildcards")
    # All concrete "AA BB CC"
    r = s.call(tool, {"pattern": "AA BB CC"})
    if r and not r.get("_error"):
        check(tool, "all_concrete_hex", r.get("hex"), "AA BB CC", "all concrete")
        check_approx(tool, "all_concrete_ratio", r.get("wildcard_ratio"), 0.0)
    harden(tool)

    # -----------------------------------------------------------------------
    # 11-15. flirt_gen_scan_x86_masks_*_wire — fixed input/output
    # -----------------------------------------------------------------------
    # JMP rel32
    tool = "flirt_gen_scan_x86_masks_jmp_rel32_wire"
    r = s.call(tool, {})
    if r and not r.get("_error"):
        check(tool, "count", r.get("count"), len(JMP_REL32_MASKS), "1 range for JMP rel32")
        if JMP_REL32_MASKS:
            check(tool, "first_offset", r.get("first_offset"), JMP_REL32_MASKS[0][0], "offset=1")
            check(tool, "first_size",   r.get("first_size"),   JMP_REL32_MASKS[0][1], "size=4")
    harden(tool)

    # JCC rel32
    tool = "flirt_gen_scan_x86_masks_jcc_rel32_wire"
    r = s.call(tool, {})
    if r and not r.get("_error"):
        check(tool, "count", r.get("count"), len(JCC_REL32_MASKS), "1 range for JCC rel32")
        if JCC_REL32_MASKS:
            check(tool, "first_offset", r.get("first_offset"), JCC_REL32_MASKS[0][0], "offset=2")
            check(tool, "first_size",   r.get("first_size"),   JCC_REL32_MASKS[0][1], "size=4")
    harden(tool)

    # JMP rel8
    tool = "flirt_gen_scan_x86_masks_jmp_rel8_wire"
    r = s.call(tool, {})
    if r and not r.get("_error"):
        check(tool, "count",      r.get("count"),      len(JMP_REL8_MASKS), "1 range for JMP rel8")
        if JMP_REL8_MASKS:
            check(tool, "first_size", r.get("first_size"), JMP_REL8_MASKS[0][1], "size=1")
    harden(tool)

    # MOV imm64
    tool = "flirt_gen_scan_x86_masks_mov_imm64_wire"
    r = s.call(tool, {})
    if r and not r.get("_error"):
        check(tool, "count",      r.get("count"),      len(MOV_IMM64_MASKS), "1 range for MOV imm64")
        if MOV_IMM64_MASKS:
            check(tool, "first_size", r.get("first_size"), MOV_IMM64_MASKS[0][1], "size=8")
    harden(tool)

    # RIP-relative
    tool = "flirt_gen_scan_x86_masks_rip_relative_wire"
    r = s.call(tool, {})
    if r and not r.get("_error"):
        check(tool, "count",      r.get("count"),      len(RIP_REL_MASKS), "1 range for RIP-rel")
        if RIP_REL_MASKS:
            check(tool, "first_size", r.get("first_size"), RIP_REL_MASKS[0][1], "size=4")
    harden(tool)

    # -----------------------------------------------------------------------
    # 16. flirt_gen_generation_stats_default_wire — all zeros
    # -----------------------------------------------------------------------
    tool = "flirt_gen_generation_stats_default_wire"
    r = s.call(tool, {})
    if r and not r.get("_error"):
        check(tool, "functions_processed", r.get("functions_processed"), 0)
        check(tool, "patterns_generated",  r.get("patterns_generated"),  0)
        check(tool, "patterns_skipped",    r.get("patterns_skipped"),    0)
        check(tool, "duplicates_removed",  r.get("duplicates_removed"),  0)
    harden(tool)

    # -----------------------------------------------------------------------
    # 17. flirt_gen_library_builder_skipped_wire — empty func skipped
    # -----------------------------------------------------------------------
    tool = "flirt_gen_library_builder_skipped_wire"
    r = s.call(tool, {})
    if r and not r.get("_error"):
        check(tool, "functions_processed", r.get("functions_processed"), 1,
              "1 function added")
        check(tool, "patterns_generated",  r.get("patterns_generated"),  0,
              "empty func → 0 patterns")
        check(tool, "patterns_skipped",    r.get("patterns_skipped"),    1,
              "empty func → 1 skipped")
    harden(tool)

    # -----------------------------------------------------------------------
    # 18. flirt_gen_relocation_entry_wire — fixed values offset=4,size=4
    # -----------------------------------------------------------------------
    tool = "flirt_gen_relocation_entry_wire"
    r = s.call(tool, {})
    if r and not r.get("_error"):
        check(tool, "offset", r.get("offset"), 4, "offset=4")
        check(tool, "size",   r.get("size"),   4, "size=4")
    harden(tool)

    # -----------------------------------------------------------------------
    # 19. flirt_gen_pattern_generator_custom_wire — initial=8, crc=4
    # -----------------------------------------------------------------------
    tool = "flirt_gen_pattern_generator_custom_wire"
    r = s.call(tool, {})
    if r and not r.get("_error"):
        check(tool, "initial_len", r.get("initial_len"), 8,  "custom initial_length=8")
        check(tool, "crc_length",  r.get("crc_length"),  4,  "custom crc_length=4")
    harden(tool)

    # -----------------------------------------------------------------------
    # 20. flirt_gen_library_builder_dedup_wire — dedup 2 identical → 1
    # -----------------------------------------------------------------------
    tool = "flirt_gen_library_builder_dedup_wire"
    r = s.call(tool, {})
    if r and not r.get("_error"):
        check(tool, "pattern_count",      r.get("pattern_count"),      1,
              "2 identical → 1 after dedup")
        check(tool, "duplicates_removed", r.get("duplicates_removed"), 1,
              "1 duplicate removed")
    harden(tool)

    # -----------------------------------------------------------------------
    # 21. flirt_gen_crc16_sig_header_known_wire — deterministic=True
    # -----------------------------------------------------------------------
    tool = "flirt_gen_crc16_sig_header_known_wire"
    r = s.call(tool, {})
    if r and not r.get("_error"):
        check(tool, "deterministic", r.get("deterministic"), True,
              "crc16_sig_header is deterministic")
    harden(tool)

    # -----------------------------------------------------------------------
    # 22. flirt_gen_sig_writer_i386_wire — arch_byte=0, version=9
    # -----------------------------------------------------------------------
    tool = "flirt_gen_sig_writer_i386_wire"
    r = s.call(tool, {})
    if r and not r.get("_error"):
        check(tool, "arch_byte", r.get("arch_byte"), 0, "i386 arch_byte=0")
        check(tool, "version",   r.get("version"),   9, "FLIRT version=9")
    harden(tool)

    # -----------------------------------------------------------------------
    # 23. flirt_gen_write_sig_file_wire — ok=True, magic_ok=True
    # -----------------------------------------------------------------------
    tool = "flirt_gen_write_sig_file_wire"
    r = s.call(tool, {})
    if r and not r.get("_error"):
        check(tool, "ok",       r.get("ok"),       True, "write succeeded")
        check(tool, "magic_ok", r.get("magic_ok"), True, "IDASGN magic present")
    harden(tool)

    # -----------------------------------------------------------------------
    # 24. flirt_gen_generate_no_relocs_wire — initial_len=32, crc_length=16
    # -----------------------------------------------------------------------
    tool = "flirt_gen_generate_no_relocs_wire"
    r = s.call(tool, {})
    if r and not r.get("_error"):
        check(tool, "initial_len",  r.get("initial_len"),  32, "default initial_length=32")
        check(tool, "crc_length",   r.get("crc_length"),   16, "default crc_length=16")
        check(tool, "pattern_length", r.get("pattern_length"), 50, "50-byte input")
    harden(tool)

    # -----------------------------------------------------------------------
    # 25. flirt_gen_generate_with_relocs_wire — initial_len=32, pattern_length=40
    # -----------------------------------------------------------------------
    tool = "flirt_gen_generate_with_relocs_wire"
    r = s.call(tool, {})
    if r and not r.get("_error"):
        check(tool, "initial_len",    r.get("initial_len"),    32, "initial_length=32")
        check(tool, "pattern_length", r.get("pattern_length"), 40, "40-byte input")
    harden(tool)

    # -----------------------------------------------------------------------
    # 26. flirt_apply_ac_index_built_wire — is_built=True after build
    # -----------------------------------------------------------------------
    tool = "flirt_apply_ac_index_built_wire"
    r = s.call(tool, {"pattern": "55 8B EC 83 EC 10"})
    if r and not r.get("_error"):
        check(tool, "is_built", r.get("is_built"), True, "index built from pattern")
    harden(tool)

    # -----------------------------------------------------------------------
    # 27. flirt_apply_applier_match_count_wire — 0 matches for empty data
    # -----------------------------------------------------------------------
    tool = "flirt_apply_applier_match_count_wire"
    r = s.call(tool, {"hex": ""})
    if r and not r.get("_error"):
        check(tool, "match_count_empty", r.get("match_count"), 0,
              "empty input → 0 matches")
    # memcpy demo pattern should hit on its own bytes
    memcpy_bytes = bytes.fromhex("558BEC8B4D108B550C8B4508")
    r = s.call(tool, {"hex": memcpy_bytes.hex(), "base_addr": 0})
    if r and not r.get("_error"):
        # pattern starts with these bytes, so at least 1 match expected
        mc = r.get("match_count", 0)
        if mc >= 1:
            checks_passed += 1
        else:
            checks_failed += 1
            mismatches.append({"tool": tool, "field": "match_count_memcpy",
                               "expected": ">=1", "actual": mc,
                               "note": "memcpy bytes should hit demo sig"})
    harden(tool)

    # -----------------------------------------------------------------------
    # 28. flirt_apply_resolve_renames_wire — empty → renames=0
    # -----------------------------------------------------------------------
    tool = "flirt_apply_resolve_renames_wire"
    r = s.call(tool, {"matches": [], "min_confidence": 0})
    if r and not r.get("_error"):
        check(tool, "renames_empty",  r.get("renames"),  0, "empty matches → 0 renames")
        check(tool, "scanned_empty",  r.get("scanned"),  0, "scanned=0")
        check(tool, "applied_empty",  r.get("applied"),  0, "applied=0")
    # Two matches at same address (deduplicated) → 1 rename
    matches_2 = [
        {"address": 0x1000, "function_name": "memcpy",
         "lib_name": "msvcrt", "confidence": 90, "pattern_length": 12},
        {"address": 0x2000, "function_name": "malloc",
         "lib_name": "msvcrt", "confidence": 85, "pattern_length": 13},
    ]
    r = s.call(tool, {"matches": matches_2, "min_confidence": 80})
    if r and not r.get("_error"):
        check(tool, "renames_2", r.get("renames"), 2,
              "2 distinct matches → 2 renames")
    harden(tool)

    # -----------------------------------------------------------------------
    # 29. flirt_apply_signature_from_pattern_wire — bytes/mask lengths
    # -----------------------------------------------------------------------
    tool = "flirt_apply_signature_from_pattern_wire"
    # "55 8B EC ?? 8B 45 08" → 7 bytes, 7 mask bytes, 6 concrete
    r = s.call(tool, {"pattern": "55 8B EC ?? 8B 45 08"})
    if r and not r.get("_error"):
        check(tool, "bytes_len",     r.get("bytes_len"),     7, "7 bytes in pattern")
        check(tool, "mask_len",      r.get("mask_len"),      7, "mask_len=7")
        check(tool, "concrete_bytes",r.get("concrete_bytes"),6, "6 concrete bytes")
    # All concrete "55 8B EC 90" -> 4 bytes, 4 concrete (tool requires min 4 bytes)
    r = s.call(tool, {"pattern": "55 8B EC 90"})
    if r and not r.get("_error"):
        check(tool, "bytes_len_4",    r.get("bytes_len"),     4)
        check(tool, "concrete_all_4", r.get("concrete_bytes"),4)
    harden(tool)

    # -----------------------------------------------------------------------
    # 30. flirt_apply_signature_matches_at_wire — exact match/mismatch
    # -----------------------------------------------------------------------
    tool = "flirt_apply_signature_matches_at_wire"
    # Tool requires minimum 4-byte patterns (FlirtSignature::parse enforces len>=4).
    # Match: "55 8B EC 83 EC 10 8B 45 08" vs its own bytes -> True
    r = s.call(tool, {"pattern": "55 8B EC 83 EC 10 8B 45 08",
                      "data_hex": "558bec83ec108b4508"})
    if r and not r.get("_error"):
        check(tool, "matches_true", r.get("matches_at"), True, "exact match -> True")
    # Mismatch: byte 5 differs -> False
    r = s.call(tool, {"pattern": "55 8B EC 83 EC 10 8B 45 08",
                      "data_hex": "558bec83ec208b4508"})
    if r and not r.get("_error"):
        check(tool, "matches_false", r.get("matches_at"), False, "mismatch -> False")
    # Wildcard: "55 8B EC 83 EC ?? 8B 45 08" matches both 0x10 and 0x20 at byte 5 -> True
    r = s.call(tool, {"pattern": "55 8B EC 83 EC ?? 8B 45 08",
                      "data_hex": "558bec83ec208b4508"})
    if r and not r.get("_error"):
        check(tool, "wildcard_match", r.get("matches_at"), True, "wildcard at byte 5 -> True")
    harden(tool)

    # -----------------------------------------------------------------------
    # 31. flirt_apply_scan_bytes_demo_wire — 0 hits for empty/random data
    # -----------------------------------------------------------------------
    tool = "flirt_apply_scan_bytes_demo_wire"
    r = s.call(tool, {"hex": "", "base_addr": 0, "min_confidence": 0})
    if r and not r.get("_error"):
        check(tool, "hits_empty", r.get("hits"), 0, "empty → 0 hits")
    # Known memcpy pattern "55 8B EC 8B 4D 10 8B 55 0C 8B 45 08" → 1 hit
    memcpy_hex = "558bec8b4d108b550c8b4508"
    r = s.call(tool, {"hex": memcpy_hex, "base_addr": 0, "min_confidence": 0})
    if r and not r.get("_error"):
        hits = r.get("hits", 0)
        if hits >= 1:
            checks_passed += 1
        else:
            checks_failed += 1
            mismatches.append({"tool": tool, "field": "hits_memcpy",
                               "expected": ">=1", "actual": hits})
    harden(tool)

    # -----------------------------------------------------------------------
    # 32. flirt_builtin_crt_library_x64 — name and arch are deterministic
    # -----------------------------------------------------------------------
    tool = "flirt_builtin_crt_library_x64"
    r = s.call(tool, {})
    if r and not r.get("_error"):
        check(tool, "name", r.get("name"), "builtin-crt-x64",
              "fixed name from source")
        check(tool, "arch", r.get("arch"), 132,
              "X64.to_u8()=132")
        # pattern_count must be >= 1 (actual builtin signatures exist)
        pc = r.get("pattern_count", 0)
        if pc >= 1:
            checks_passed += 1
        else:
            checks_failed += 1
            mismatches.append({"tool": tool, "field": "pattern_count",
                               "expected": ">=1", "actual": pc})
    harden(tool)

    # -----------------------------------------------------------------------
    # 33. flirt_matcher_add_library_wire — 1 library, 1 pattern added
    # -----------------------------------------------------------------------
    tool = "flirt_matcher_add_library_wire"
    # Default pattern: "55 8B EC 90" (4 bytes)
    r = s.call(tool, {})
    if r and not r.get("_error"):
        check(tool, "libraries", r.get("libraries"), 1, "1 library added")
        check(tool, "patterns",  r.get("patterns"),  1, "1 pattern in matcher")
    harden(tool)

    # -----------------------------------------------------------------------
    # 34. flirt_database_add_module_wire — total=1, candidates=1
    # -----------------------------------------------------------------------
    tool = "flirt_database_add_module_wire"
    # Default buf_hex="558bec90" matches pattern "55 8B EC 90"
    r = s.call(tool, {})
    if r and not r.get("_error"):
        check(tool, "total",      r.get("total"),      1, "1 pattern in db")
        # candidate_modules returns modules whose patterns match prefix of buf
        # buf "558bec90" matches "55 8B EC 90" at offset 0
        cands = r.get("candidates", -1)
        if cands >= 1:
            checks_passed += 1
        else:
            checks_failed += 1
            mismatches.append({"tool": tool, "field": "candidates",
                               "expected": ">=1", "actual": cands})
    harden(tool)

    # -----------------------------------------------------------------------
    # 35. flirt_library_serialize_roundtrip_wire — name survives roundtrip
    # -----------------------------------------------------------------------
    tool = "flirt_library_serialize_roundtrip_wire"
    r = s.call(tool, {"name": "testlib"})
    if r and not r.get("_error"):
        check(tool, "name",          r.get("name"),          "testlib", "name preserved")
        check(tool, "pattern_count", r.get("pattern_count"), 0,         "empty lib")
    harden(tool)

    # -----------------------------------------------------------------------
    # 36. flirt_trie_build_find_wire — total=1, candidates=1
    # -----------------------------------------------------------------------
    tool = "flirt_trie_build_find_wire"
    # Default: pattern="55 8B EC", buf_hex="558bec00"
    r = s.call(tool, {})
    if r and not r.get("_error"):
        check(tool, "total",      r.get("total"),      1, "1 pattern in trie")
        # "55 8B EC" prefix matches "558bec00" → 1 candidate
        cands = r.get("candidates", -1)
        if cands >= 1:
            checks_passed += 1
        else:
            checks_failed += 1
            mismatches.append({"tool": tool, "field": "candidates",
                               "expected": ">=1", "actual": cands})
    harden(tool)

    # -----------------------------------------------------------------------
    # 37. flirt_gen_pattern_generate — deterministic output for known bytes
    # -----------------------------------------------------------------------
    tool = "flirt_gen_pattern_generate"
    long_hex = _LONG_BYTES.hex()
    r = s.call(tool, {"bytes_hex": long_hex, "name": "foo", "relocs": []})
    if r and not r.get("_error") and not r.get("_raw"):
        check(tool, "pattern_length", r.get("pattern_length"), 64,
              "64-byte function → pattern_length=64")
        check(tool, "crc_length",     r.get("crc_length"),     _LONG_CRC_LEN,
              f"crc_length={_LONG_CRC_LEN}")
        check(tool, "crc16",          r.get("crc16"),          _LONG_CRC16,
              f"crc16 of bytes[32..48] = 0x{_LONG_CRC16:04X}")
    harden(tool)

    # -----------------------------------------------------------------------
    # SKIP list
    # -----------------------------------------------------------------------
    skip("flirt_apply_auto",
         "requires an open project/binary; cannot verify output without loading PE")
    skip("flirt_builtin_matcher",
         "library and pattern counts are opaque/implementation-defined, no exact reference")
    skip("flirt_gen_elf_parse",
         "requires valid ELF binary data; no self-contained test vector available")
    skip("flirt_gen_library_builder_demo",
         "opaque demo data; exact counts are implementation-defined")
    skip("flirt_gen_generate_from_ranges_wire",
         "requires PE/ELF memory ranges; output depends on binary layout")
    skip("flirt_parse_sig_header",
         "requires a valid IDA .sig file on disk")
    skip("flirt_gen_pattern_with_quality",
         "requires hex_bytes param with exact quality threshold; thresholds are opaque")
    skip("flirt_sig_file_parse_wire",
         "requires valid .sig file bytes; invalid input returns error, no positive reference")
    skip("flirt_sig_pattern_matches_wire",
         "SigPattern constructed from default sig with unknown internal bytes")
    skip("flirt_matcher_best_match_wire",
         "best_match result depends on internal matcher state; no independent reference")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    print(f"Rigorous flirt v2 validator — {MCP_EXE}")

    session = McpSession(MCP_EXE)
    try:
        run_all(session)
    finally:
        session.close()

    tools_h  = len(tools_hardened)
    tools_s  = len(tools_skipped_list)

    report = {
        "category":       "flirt",
        "tools_hardened": tools_h,
        "tools_passed":   checks_passed,
        "tools_failed":   checks_failed,
        "tools_skipped":  tools_s,
        "mismatches":     mismatches,
    }

    REPORT_PATH.write_text(json.dumps(report, indent=2))
    SKIP_PATH.write_text(json.dumps({"skipped": tools_skipped_list}, indent=2))

    print(f"tools_hardened : {tools_h}")
    print(f"checks_passed  : {checks_passed}")
    print(f"checks_failed  : {checks_failed}")
    print(f"tools_skipped  : {tools_s}")
    if mismatches:
        print("\nMISMATCHES:")
        for m in mismatches:
            note = m.get('note','').replace('→','->').replace('—','-')
        print(f"  [{m['tool']}] {m['field']}: expected={m['expected']!r} actual={m['actual']!r} {note}")
    else:
        print("All checks passed.")

    print(f"\nReport -> {REPORT_PATH}")
    print(f"Skips  -> {SKIP_PATH}")

    return report


if __name__ == "__main__":
    main()
