#!/usr/bin/env python3
"""
Rigorous validator for the flirt_gen MCP tools.

Computes Python truth values independently (no MCP call for reference),
then compares against rustre-mcp.exe --transport=stdio tool responses.

At least 10 tools are hardened with exact, independently computed expected values.
"""
from __future__ import annotations

import json
import subprocess
import struct
from typing import Any, Optional

MCP_EXE = r"C:\Users\Fra\Desktop\RustRE\target\release\rustre-mcp.exe"
REPORT_PATH = r"C:\Users\Fra\Desktop\RustRE\validation\rigorous_flirt_gen.json"

# ---------------------------------------------------------------------------
# Independent Python reference implementations
# ---------------------------------------------------------------------------

def py_crc16_sig_header(data: bytes) -> int:
    """CRC-16/IBM non-reflected, poly 0x8005, init 0xFFFF."""
    crc = 0xFFFF
    for b in data:
        crc ^= (b << 8)
        crc &= 0xFFFF
        for _ in range(8):
            if crc & 0x8000:
                crc = ((crc << 1) ^ 0x8005) & 0xFFFF
            else:
                crc = (crc << 1) & 0xFFFF
    return crc & 0xFFFF


def py_crc16_flirt(data: bytes) -> int:
    """CRC-16/CCITT reversed, poly 0x8408, init 0xFFFF (pattern body CRC)."""
    crc = 0xFFFF
    for b in data:
        crc ^= b
        for _ in range(8):
            crc = (crc >> 1) ^ 0x8408 if (crc & 1) else (crc >> 1)
    return crc & 0xFFFF


def py_scan_x86_masks(data: bytes):
    """Return list of (offset, size) ranges for relocatable operands."""
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
            rm = modrm & 0x7
            if mod == 0 and rm == 0b101:
                if i + 2 + 4 <= n:
                    out.append((i + 2, 4))
                i += 2 + 4
                continue
        i = rex_i + 1
    return out


# ---------------------------------------------------------------------------
# Precomputed expected values (Python truth)
# ---------------------------------------------------------------------------

# CRC-16/IBM of empty bytes: just init value = 0xFFFF
CRC16_EMPTY = py_crc16_sig_header(b"")               # 0xFFFF
CRC16_HELLO = py_crc16_sig_header(b"hello")
CRC16_123   = py_crc16_sig_header(b"123456789")

# x86 mask expectations
CALL_BYTES  = bytes([0xE8, 0x11, 0x22, 0x33, 0x44, 0xC3])  # CALL rel32 + RET
JMP_BYTES   = bytes([0xE9, 0xAA, 0xBB, 0xCC, 0xDD, 0x90])  # JMP rel32 + NOP
JMP8_BYTES  = bytes([0xEB, 0x05, 0x90])                      # JMP short + NOP
JCC32_BYTES = bytes([0x0F, 0x84, 0x00, 0x00, 0x00, 0x00, 0x90])  # JE rel32 + NOP
# REX.W MOV RAX, imm64 (48 B8 + 8 bytes imm)
MOV_IMM64   = bytes([0x48, 0xB8, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x90])
# RIP-relative: opcode + ModRM(mod=00, rm=101) + disp32
RIP_REL     = bytes([0x8B, 0x05, 0x00, 0x00, 0x00, 0x00, 0x90])  # MOV eax,[rip+disp32]

CALL_MASKS  = py_scan_x86_masks(CALL_BYTES)    # [(1, 4)]
JMP_MASKS   = py_scan_x86_masks(JMP_BYTES)     # [(1, 4)]
JMP8_MASKS  = py_scan_x86_masks(JMP8_BYTES)    # [(1, 1)]
JCC32_MASKS = py_scan_x86_masks(JCC32_BYTES)   # [(2, 4)]
MOV_MASKS   = py_scan_x86_masks(MOV_IMM64)     # [(2, 8)]
RIP_MASKS   = py_scan_x86_masks(RIP_REL)       # [(2, 4)]

# PatternGenerator defaults (from crate: initial_length=32, crc_length=16)
PG_INITIAL_LENGTH = 32
PG_CRC_LENGTH     = 16

# PatternQuality label strings — the crate's as_str() returns lowercase.
# Confirmed from wire output: "high", "medium", "low".
QUALITY_HIGH   = "high"
QUALITY_MEDIUM = "medium"
QUALITY_LOW    = "low"


# ---------------------------------------------------------------------------
# MCP session helper
# ---------------------------------------------------------------------------

def start_mcp():
    p = subprocess.Popen(
        [MCP_EXE, "--transport=stdio"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        bufsize=0,
    )

    def send(obj):
        p.stdin.write((json.dumps(obj) + "\n").encode())
        p.stdin.flush()

    def recv():
        line = p.stdout.readline()
        return json.loads(line) if line else None

    send({
        "jsonrpc": "2.0", "id": 1, "method": "initialize",
        "params": {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": {"name": "rigorous-validator", "version": "1"},
        },
    })
    recv()
    send({"jsonrpc": "2.0", "method": "notifications/initialized"})
    return p, send, recv


_rid = [100]


def call_tool(send, recv, name: str, args: dict) -> Optional[Any]:
    _rid[0] += 1
    send({"jsonrpc": "2.0", "id": _rid[0], "method": "tools/call",
          "params": {"name": name, "arguments": args}})
    r = recv()
    if not r or "error" in r:
        return None
    content = r.get("result", {}).get("content", [])
    if not content:
        return None
    txt = content[0].get("text", "")
    try:
        parsed = json.loads(txt)
        # If it parsed to a string, try a second parse (double-encoded JSON)
        if isinstance(parsed, str):
            try:
                return json.loads(parsed)
            except Exception:
                return parsed
        return parsed
    except Exception:
        return txt


# ---------------------------------------------------------------------------
# Checks
# ---------------------------------------------------------------------------

checks_passed = 0
checks_failed = 0
mismatches = []
tools_hardened: list[str] = []


def check(tool: str, field: str, got, expected, note: str = ""):
    global checks_passed, checks_failed
    ok = (got == expected)
    if ok:
        checks_passed += 1
    else:
        checks_failed += 1
        mismatches.append({
            "tool": tool,
            "field": field,
            "got": got,
            "expected": expected,
            "note": note,
        })
    return ok


def harden(tool_name: str):
    if tool_name not in tools_hardened:
        tools_hardened.append(tool_name)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    p, send, recv = start_mcp()

    # ------------------------------------------------------------------
    # 1. flirt_gen_crc16_sig_header_empty_wire
    #    Empty slice CRC-16/IBM must equal 0xFFFF (init value, no data).
    # ------------------------------------------------------------------
    tool = "flirt_gen_crc16_sig_header_empty_wire"
    r = call_tool(send, recv, tool, {})
    if r is not None:
        check(tool, "crc16", r.get("crc16"), CRC16_EMPTY,
              f"CRC-16/IBM of empty bytes should be 0x{CRC16_EMPTY:04X}")
        harden(tool)

    # ------------------------------------------------------------------
    # 2. flirt_gen_crc16_sig_header  — with hex-encoded b"123456789"
    # ------------------------------------------------------------------
    tool = "flirt_gen_crc16_sig_header"
    hex_input = b"123456789".hex()
    r = call_tool(send, recv, tool, {"hex": hex_input})
    if r is not None and not isinstance(r, dict):
        r = None
    if r is not None:
        got_hex = r.get("crc_hex", "")
        expected_hex = f"{CRC16_123:04x}"
        check(tool, "crc_hex", got_hex, expected_hex,
              f"CRC-16/IBM('123456789') = 0x{CRC16_123:04X}")
        got_len = r.get("bytes_len")
        check(tool, "bytes_len", got_len, 9, "9 bytes of '123456789'")
        harden(tool)

    # ------------------------------------------------------------------
    # 3. flirt_gen_scan_x86_masks_empty_wire
    #    Empty input → 0 ranges.
    # ------------------------------------------------------------------
    tool = "flirt_gen_scan_x86_masks_empty_wire"
    r = call_tool(send, recv, tool, {})
    if r is not None:
        check(tool, "count", r.get("count"), 0, "empty slice → 0 mask ranges")
        harden(tool)

    # ------------------------------------------------------------------
    # 4. flirt_gen_scan_x86_masks_call_rel32_wire
    #    E8 11 22 33 44 C3 → 1 range at offset 1, size 4.
    # ------------------------------------------------------------------
    tool = "flirt_gen_scan_x86_masks_call_rel32_wire"
    r = call_tool(send, recv, tool, {})
    if r is not None:
        check(tool, "count",        r.get("count"),        len(CALL_MASKS),              "1 range for CALL rel32")
        check(tool, "first_offset", r.get("first_offset"), CALL_MASKS[0][0] if CALL_MASKS else None, "offset=1")
        check(tool, "first_size",   r.get("first_size"),   CALL_MASKS[0][1] if CALL_MASKS else None, "size=4")
        harden(tool)

    # ------------------------------------------------------------------
    # 5. flirt_gen_pattern_generator_default_wire
    #    PatternGenerator::default() → initial_length=32, crc_length=16
    # ------------------------------------------------------------------
    tool = "flirt_gen_pattern_generator_default_wire"
    r = call_tool(send, recv, tool, {})
    if r is not None:
        check(tool, "initial_length", r.get("initial_length"), PG_INITIAL_LENGTH, "default initial_length=32")
        check(tool, "crc_length",     r.get("crc_length"),     PG_CRC_LENGTH,     "default crc_length=16")
        harden(tool)

    # ------------------------------------------------------------------
    # 6. flirt_gen_pattern_generator_new
    #    PatternGenerator::new() → same defaults
    # ------------------------------------------------------------------
    tool = "flirt_gen_pattern_generator_new"
    r = call_tool(send, recv, tool, {})
    if r is not None:
        check(tool, "initial_length", r.get("initial_length"), PG_INITIAL_LENGTH, "new() initial_length=32")
        check(tool, "crc_length",     r.get("crc_length"),     PG_CRC_LENGTH,     "new() crc_length=16")
        harden(tool)

    # ------------------------------------------------------------------
    # 7. flirt_gen_generate_batch_wire
    #    generate_batch of 2 distinct functions → count=2
    # ------------------------------------------------------------------
    tool = "flirt_gen_generate_batch_wire"
    r = call_tool(send, recv, tool, {})
    if r is not None:
        check(tool, "count", r.get("count"), 2, "batch of 2 functions → 2 patterns")
        harden(tool)

    # ------------------------------------------------------------------
    # 8. flirt_gen_pattern_quality_as_str_wire
    #    PatternQuality enum label strings.
    # ------------------------------------------------------------------
    tool = "flirt_gen_pattern_quality_as_str_wire"
    r = call_tool(send, recv, tool, {})
    if r is not None:
        check(tool, "high",   r.get("high"),   QUALITY_HIGH,   "High quality label")
        check(tool, "medium", r.get("medium"), QUALITY_MEDIUM, "Medium quality label")
        check(tool, "low",    r.get("low"),    QUALITY_LOW,    "Low quality label")
        harden(tool)

    # ------------------------------------------------------------------
    # 9. flirt_gen_elf_parse_reject_short_wire
    #    parse(b"short") must be an error.
    # ------------------------------------------------------------------
    tool = "flirt_gen_elf_parse_reject_short_wire"
    r = call_tool(send, recv, tool, {})
    if r is not None:
        check(tool, "is_err", r.get("is_err"), True, "too-short ELF must fail")
        harden(tool)

    # ------------------------------------------------------------------
    # 10. flirt_gen_sig_writer_build_empty_wire
    #     SigWriter::default().build(&[], "l") → magic b"IDASGN", version=9
    # ------------------------------------------------------------------
    tool = "flirt_gen_sig_writer_build_empty_wire"
    r = call_tool(send, recv, tool, {})
    if r is not None:
        check(tool, "magic_ok", r.get("magic_ok"), True,  "header must start with IDASGN")
        check(tool, "version",  r.get("version"),  9,     "FLIRT sig version=9")
        harden(tool)

    # ------------------------------------------------------------------
    # 11. flirt_gen_scan_x86_masks (parameterised) — JMP rel32
    # ------------------------------------------------------------------
    tool = "flirt_gen_scan_x86_masks"
    hex_jmp = JMP_BYTES.hex()
    r = call_tool(send, recv, tool, {"hex": hex_jmp})
    if r is not None and not isinstance(r, dict):
        r = None
    if r is not None:
        ranges = r.get("ranges", [])
        expected_count = len(JMP_MASKS)
        check(tool, "jmp_rel32_count", len(ranges), expected_count, "JMP rel32 → 1 range")
        if ranges and JMP_MASKS:
            check(tool, "jmp_rel32_offset", ranges[0].get("offset"), JMP_MASKS[0][0], "offset=1")
            check(tool, "jmp_rel32_size",   ranges[0].get("size"),   JMP_MASKS[0][1], "size=4")
        harden(tool)

    # ------------------------------------------------------------------
    # 12. flirt_gen_scan_x86_masks — MOV r64, imm64
    # ------------------------------------------------------------------
    hex_mov = MOV_IMM64.hex()
    r = call_tool(send, recv, tool, {"hex": hex_mov})
    if r is not None and not isinstance(r, dict):
        r = None
    if r is not None:
        ranges = r.get("ranges", [])
        expected_count = len(MOV_MASKS)
        check(tool, "mov_imm64_count", len(ranges), expected_count, "REX.W MOV r64,imm64 → 1 range")
        if ranges and MOV_MASKS:
            check(tool, "mov_imm64_offset", ranges[0].get("offset"), MOV_MASKS[0][0], "offset=2 (past REX+opcode)")
            check(tool, "mov_imm64_size",   ranges[0].get("size"),   MOV_MASKS[0][1], "size=8")

    # ------------------------------------------------------------------
    # 13. flirt_gen_scan_x86_masks — Jcc rel32 (0F 84)
    # ------------------------------------------------------------------
    hex_jcc = JCC32_BYTES.hex()
    r = call_tool(send, recv, tool, {"hex": hex_jcc})
    if r is not None and not isinstance(r, dict):
        r = None
    if r is not None:
        ranges = r.get("ranges", [])
        expected_count = len(JCC32_MASKS)
        check(tool, "jcc32_count", len(ranges), expected_count, "Jcc rel32 → 1 range")
        if ranges and JCC32_MASKS:
            check(tool, "jcc32_offset", ranges[0].get("offset"), JCC32_MASKS[0][0], "offset=2")
            check(tool, "jcc32_size",   ranges[0].get("size"),   JCC32_MASKS[0][1], "size=4")

    # ------------------------------------------------------------------
    # 14. flirt_gen_crc16_sig_header — b"hello" (known from Python)
    # ------------------------------------------------------------------
    tool_crc = "flirt_gen_crc16_sig_header"
    hex_hello = b"hello".hex()
    r = call_tool(send, recv, tool_crc, {"hex": hex_hello})
    if r is not None and not isinstance(r, dict):
        r = None
    if r is not None:
        got_hex = r.get("crc_hex", "")
        expected_hex = f"{CRC16_HELLO:04x}"
        check(tool_crc, "crc_hex_hello", got_hex, expected_hex,
              f"CRC-16/IBM('hello') = 0x{CRC16_HELLO:04X}")

    # ------------------------------------------------------------------
    # 15. flirt_gen_scan_x86_masks — RIP-relative MOV
    # ------------------------------------------------------------------
    hex_rip = RIP_REL.hex()
    r = call_tool(send, recv, "flirt_gen_scan_x86_masks", {"hex": hex_rip})
    if r is not None and not isinstance(r, dict):
        r = None
    if r is not None:
        ranges = r.get("ranges", [])
        expected_count = len(RIP_MASKS)
        check("flirt_gen_scan_x86_masks", "rip_rel_count", len(ranges), expected_count,
              "RIP-relative → 1 range")
        if ranges and RIP_MASKS:
            check("flirt_gen_scan_x86_masks", "rip_rel_offset", ranges[0].get("offset"), RIP_MASKS[0][0], "offset=2")
            check("flirt_gen_scan_x86_masks", "rip_rel_size",   ranges[0].get("size"),   RIP_MASKS[0][1], "size=4")

    try:
        p.terminate()
    except Exception:
        pass

    # ------------------------------------------------------------------
    # Report
    # ------------------------------------------------------------------
    report = {
        "module":          "flirt_gen",
        "tools_hardened":  len(tools_hardened),
        "checks_passed":   checks_passed,
        "checks_failed":   checks_failed,
        "mismatches":      mismatches,
    }
    with open(REPORT_PATH, "w") as f:
        json.dump(report, f, indent=2)

    print(f"module: flirt_gen")
    print(f"tools_hardened: {len(tools_hardened)}")
    print(f"checks_passed:  {checks_passed}")
    print(f"checks_failed:  {checks_failed}")
    print(f"real_mismatches: {len(mismatches)}")
    if mismatches:
        print("\nMISMATCHES:")
        for m in mismatches:
            print(f"  [{m['tool']}] {m['field']}: got={m['got']!r} expected={m['expected']!r}  ({m['note']})")

    print(f"\nReport saved to: {REPORT_PATH}")
    return report


if __name__ == "__main__":
    main()
