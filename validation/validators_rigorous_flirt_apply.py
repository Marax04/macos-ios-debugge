"""
Rigorous validator for the flirt_apply module.

Starts a fresh rustre-mcp.exe --transport=stdio session, calls at least 10
tools, and compares each output against an independently computed Python truth.
Report is saved to validation/rigorous_flirt_apply.json.
"""

import json
import subprocess
import sys
import time
import struct
from pathlib import Path

MCP_EXE = r"C:\Users\Fra\Desktop\RustRE\target\release\rustre-mcp.exe"
REPORT_PATH = Path(r"C:\Users\Fra\Desktop\RustRE\validation\rigorous_flirt_apply.json")

# ---------------------------------------------------------------------------
# Python reference implementations
# ---------------------------------------------------------------------------

def crc16_flirt(data: bytes) -> int:
    """CRC-16/MCRF4XX: poly 0x8408 (reflected), init 0xFFFF, no final XOR.
    Matches IDA FLIRT crc16.cpp and rustre_flirt_apply::crc16_flirt."""
    POLY = 0x8408
    crc = 0xFFFF
    for byte in data:
        crc ^= byte
        for _ in range(8):
            if crc & 1:
                crc = (crc >> 1) ^ POLY
            else:
                crc >>= 1
    return crc & 0xFFFF


def parse_pattern(pattern_str: str):
    """Parse FLIRT hex pattern string into (bytes_list, wildcard_count, length).
    Returns None if fewer than 4 bytes."""
    tokens = pattern_str.split()
    result = []
    for t in tokens:
        if t in ("??", ".", ".."):
            result.append(None)
        else:
            result.append(int(t, 16))
    if len(result) < 4:
        return None
    wildcards = sum(1 for b in result if b is None)
    return result, wildcards, len(result)


def pattern_matches(pattern_str: str, data: bytes) -> bool:
    """True if the pattern matches at the start of data."""
    parsed = parse_pattern(pattern_str)
    if parsed is None:
        return False
    pat_bytes, _, length = parsed
    if len(data) < length:
        return False
    for pb, db in zip(pat_bytes, data):
        if pb is not None and pb != db:
            return False
    return True


def wildcard_prefix_len(pattern_str: str) -> int:
    """Length of the leading concrete (non-wildcard) prefix."""
    parsed = parse_pattern(pattern_str)
    if parsed is None:
        return 0
    pat_bytes, _, _ = parsed
    count = 0
    for b in pat_bytes:
        if b is None:
            break
        count += 1
    return count


def library_marks_from_matches(matches):
    """Filter FlirtMatches to LibraryMark list (drop empty lib_name)."""
    return [
        {"address": m["address"], "lib_name": m["lib_name"]}
        for m in matches
        if m.get("lib_name", "")
    ]


def count_demo_sigs() -> int:
    """Count of valid patterns in FlirtSigDb::load_demo_sigs().
    Computed by replicating the add() logic with from_pattern_str (>=4 bytes check).
    All 18 entries in the Rust source pass the >=4 byte check.
    """
    patterns = [
        "55 8B EC 8B 4D 10 8B 55 0C 8B 45 08",          # memcpy
        "55 8B EC 8B 45 10 8B 4D 0C 8B 55 08",          # memset
        "8A 01 84 C0 74 ?? 41 8A 01 84 C0 74",          # strlen
        "55 8B EC 8B 55 08 8B 45 0C 8A 0A 88 08",       # strcpy
        "8B 44 24 04 8B 4C 24 08 8A 10 3A 01 75 ?? 84 D2",  # strcmp
        "55 8B EC FF 75 08 ?? ?? ?? ?? ?? 5D C3",        # malloc
        "55 8B EC FF 75 08 ?? ?? ?? ?? ?? 5D C3 90",     # free
        "55 8B EC 8D 45 0C 50 FF 75 08 ?? ?? ?? ?? ?? 5D C3",  # printf
        "55 8B EC 8D 45 10 50 8D 45 0C 50 FF 75 08 ?? ?? ?? ??",  # sprintf
        "55 8B EC 51 8B 4D 08 51 ?? ?? ?? ?? ?? 8B E5 5D C3",  # puts
        "55 8B EC FF 75 08 E8 ?? ?? ?? ?? 83 C4 04 33 C0 50",  # exit
        "E8 ?? ?? ?? ?? CC CC CC CC CC 55 8B EC",        # abort
        "55 8B EC 56 8B 75 0C 57 8B 7D 08 8B 4D 10",    # memmove
        "55 8B EC FF 75 0C FF 75 08 ?? ?? ?? ?? ?? 5D C3",  # fopen
        "55 8B EC FF 75 08 ?? ?? ?? ?? ?? 85 C0 5D C3",  # fclose
        "60 BE ?? ?? ?? ?? 8D BE ?? ?? ?? FF",           # UPX_decompress
        "B8 ?? 00 00 00 BA 00 D0 FE 7F FF D2 C2",       # NtAllocateVirtualMemory
        "FF 25 ?? ?? ?? ?? CC CC CC CC 55 8B EC",        # HeapAlloc_thunk
    ]
    count = 0
    for p in patterns:
        result = parse_pattern(p)
        if result is not None:
            count += 1
    return count


# ---------------------------------------------------------------------------
# MCP session helper
# ---------------------------------------------------------------------------

class McpSession:
    def __init__(self, exe: str):
        self.proc = subprocess.Popen(
            [exe, "--transport=stdio"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
        )
        self._id = 0
        # Send initialize
        self._send_raw({"jsonrpc": "2.0", "id": 0, "method": "initialize",
                        "params": {"protocolVersion": "2024-11-05",
                                   "clientInfo": {"name": "rigorous_validator", "version": "1.0"},
                                   "capabilities": {}}})
        self._recv()
        # Send initialized notification
        self._send_raw({"jsonrpc": "2.0", "method": "notifications/initialized"})
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

    def call_tool(self, name: str, arguments: dict):
        self._id += 1
        self._send_raw({
            "jsonrpc": "2.0",
            "id": self._id,
            "method": "tools/call",
            "params": {"name": name, "arguments": arguments},
        })
        resp = self._recv()
        if resp is None:
            return None
        result = resp.get("result", {})
        content = result.get("content", [])
        if content and isinstance(content, list):
            text = content[0].get("text", "")
            try:
                return json.loads(text)
            except Exception:
                return {"_raw": text}
        return result

    def close(self):
        try:
            self.proc.stdin.close()
            self.proc.terminate()
        except Exception:
            pass


# ---------------------------------------------------------------------------
# Test cases
# ---------------------------------------------------------------------------

def run_checks():
    session = McpSession(MCP_EXE)

    checks_passed = 0
    checks_failed = 0
    mismatches = []

    def check(tool, args, field, expected, label=None):
        nonlocal checks_passed, checks_failed
        tag = label or f"{tool}.{field}"
        try:
            resp = session.call_tool(tool, args)
            if resp is None:
                checks_failed += 1
                mismatches.append({"tool": tool, "check": tag, "error": "no response"})
                return
            got = resp.get(field)
            if got == expected:
                checks_passed += 1
            else:
                checks_failed += 1
                mismatches.append({
                    "tool": tool,
                    "check": tag,
                    "expected": expected,
                    "got": got,
                    "full_response": resp,
                })
        except Exception as e:
            checks_failed += 1
            mismatches.append({"tool": tool, "check": tag, "error": str(e)})

    # -----------------------------------------------------------------------
    # 1. flirt_crc16 — known test vector "IDA" → 0xD1D0
    # -----------------------------------------------------------------------
    # "IDA" in hex = 49 44 41
    ida_hex = "49 44 41"
    expected_crc = crc16_flirt(b"IDA")  # should be 0xD1D0
    assert expected_crc == 0xD1D0, f"Python CRC wrong: {expected_crc:#x}"

    check("flirt_crc16", {"hex": ida_hex}, "crc", expected_crc, "flirt_crc16.IDA")
    check("flirt_crc16", {"hex": ida_hex}, "crc_hex", f"{expected_crc:04x}", "flirt_crc16.IDA_hex")

    # 2. flirt_apply_crc16 — same test vector
    check("flirt_apply_crc16", {"hex": ida_hex}, "crc16", expected_crc, "flirt_apply_crc16.IDA")
    check("flirt_apply_crc16", {"hex": ida_hex}, "crc16_hex", f"{expected_crc:04x}", "flirt_apply_crc16.IDA_hex")

    # 3. flirt_apply_crc16_flirt_wire — same
    check("flirt_apply_crc16_flirt_wire", {"hex": ida_hex}, "crc", expected_crc, "flirt_apply_crc16_flirt_wire.IDA")

    # Additional CRC vectors
    # empty bytes: crc16_flirt([]) = 0xFFFF
    empty_crc = crc16_flirt(b"")
    assert empty_crc == 0xFFFF
    check("flirt_apply_crc16_flirt_wire", {"hex": ""}, "crc", empty_crc, "crc16_wire.empty")

    # [0x00]: crc16_flirt([0x00])
    zero_crc = crc16_flirt(bytes([0x00]))
    check("flirt_apply_crc16", {"bytes": [0]}, "crc16", zero_crc, "flirt_apply_crc16.zero")

    # -----------------------------------------------------------------------
    # 4. flirt_demo_sig_count — count from Python reference
    # -----------------------------------------------------------------------
    expected_count = count_demo_sigs()  # 18
    check("flirt_demo_sig_count", {}, "count", expected_count, "flirt_demo_sig_count.count")

    # 5. flirt_apply_demo_sigs_count_wire — same
    check("flirt_apply_demo_sigs_count_wire", {}, "count", expected_count, "demo_sigs_count_wire.count")

    # -----------------------------------------------------------------------
    # 6. flirt_parse_pattern — "55 8B EC ?? 8B 45 08" → 7 bytes, 1 wildcard
    # -----------------------------------------------------------------------
    pat1 = "55 8B EC ?? 8B 45 08"
    parsed1 = parse_pattern(pat1)
    assert parsed1 is not None
    pat1_bytes, pat1_wildcards, pat1_len = parsed1
    check("flirt_parse_pattern", {"pattern": pat1, "name": "fn1", "lib": "lib1"},
          "length", pat1_len, "flirt_parse_pattern.length")
    check("flirt_parse_pattern", {"pattern": pat1, "name": "fn1", "lib": "lib1"},
          "wildcards", pat1_wildcards, "flirt_parse_pattern.wildcards")

    # 7. flirt_apply_pattern_from_str_wire — same pattern
    check("flirt_apply_pattern_from_str_wire",
          {"pattern": pat1, "name": "fn1", "lib": "mylib"},
          "pattern_len", pat1_len, "pattern_from_str_wire.length")
    check("flirt_apply_pattern_from_str_wire",
          {"pattern": pat1, "name": "fn1", "lib": "mylib"},
          "wildcards", pat1_wildcards, "pattern_from_str_wire.wildcards")

    # -----------------------------------------------------------------------
    # 8. flirt_apply_pattern_matches_wire — exact match
    # -----------------------------------------------------------------------
    pat2 = "55 8B EC ?? 8B"
    data_match = [0x55, 0x8B, 0xEC, 0xAB, 0x8B]
    data_no_match = [0x55, 0x8B, 0xEC, 0xAB, 0x90]

    py_match = pattern_matches(pat2, bytes(data_match))
    py_no_match = pattern_matches(pat2, bytes(data_no_match))

    check("flirt_apply_pattern_matches_wire",
          {"pattern": pat2, "data_bytes": data_match},
          "matches", py_match, "pattern_matches_wire.match_true")
    check("flirt_apply_pattern_matches_wire",
          {"pattern": pat2, "data_bytes": data_no_match},
          "matches", py_no_match, "pattern_matches_wire.match_false")

    # -----------------------------------------------------------------------
    # 9. flirt_apply_pattern_new_wire — build pattern, check length
    # -----------------------------------------------------------------------
    name = "myfunc"
    data_bytes = [0x55, 0x8B, 0xEC, 0x83, 0xEC, 0x10]
    check("flirt_apply_pattern_new_wire",
          {"name": name, "bytes": data_bytes},
          "pattern_len", len(data_bytes), "pattern_new_wire.len")

    # -----------------------------------------------------------------------
    # 10. flirt_apply_sig_db_add_count_wire — add one pattern → count=1
    # -----------------------------------------------------------------------
    check("flirt_apply_sig_db_add_count_wire",
          {"pattern": "55 8B EC 83 EC 10"},
          "pattern_count", 1, "sig_db_add_count.one")

    # -----------------------------------------------------------------------
    # 11. flirt_apply_library_marks_from_matches — filter empty lib_name
    # -----------------------------------------------------------------------
    matches_input = [
        {"address": 0x1000, "function_name": "memcpy", "lib_name": "msvcrt",
         "confidence": 90, "pattern_length": 12},
        {"address": 0x2000, "function_name": "unknown", "lib_name": "",
         "confidence": 50, "pattern_length": 8},
        {"address": 0x3000, "function_name": "malloc", "lib_name": "msvcrt",
         "confidence": 85, "pattern_length": 13},
    ]
    py_marks = library_marks_from_matches(matches_input)
    expected_mark_count = len(py_marks)  # 2 (empty lib_name filtered out)
    check("flirt_apply_library_marks_from_matches",
          {"matches": matches_input},
          "count", expected_mark_count, "library_marks.count")
    check("flirt_apply_library_marks_from_matches",
          {"matches": matches_input},
          "input_matches", len(matches_input), "library_marks.input_count")

    # -----------------------------------------------------------------------
    # 12. flirt_apply_wildcard_prefix_wire — prefix before first wildcard
    # -----------------------------------------------------------------------
    pat3 = "55 8B EC ?? 8B 45 08"
    prefix_len = wildcard_prefix_len(pat3)  # 3 (stops at ??)
    check("flirt_apply_wildcard_prefix_wire",
          {"pattern": pat3},
          "prefix_len", prefix_len, "wildcard_prefix.len")

    # Pattern with no wildcards — prefix = full length
    pat4 = "55 8B EC 83 EC 10"
    prefix_len4 = wildcard_prefix_len(pat4)  # 6
    check("flirt_apply_wildcard_prefix_wire",
          {"pattern": pat4},
          "prefix_len", prefix_len4, "wildcard_prefix.all_concrete")

    session.close()
    return checks_passed, checks_failed, mismatches


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    print(f"Running rigorous flirt_apply validator against {MCP_EXE}")
    try:
        checks_passed, checks_failed, mismatches = run_checks()
    except Exception as e:
        print(f"FATAL: {e}", file=sys.stderr)
        report = {
            "module": "flirt_apply",
            "tools_hardened": 0,
            "checks_passed": 0,
            "checks_failed": 1,
            "mismatches": [{"error": str(e)}],
        }
        REPORT_PATH.write_text(json.dumps(report, indent=2))
        sys.exit(1)

    # Count unique tools hardened
    tools = [
        "flirt_crc16",
        "flirt_apply_crc16",
        "flirt_apply_crc16_flirt_wire",
        "flirt_demo_sig_count",
        "flirt_apply_demo_sigs_count_wire",
        "flirt_parse_pattern",
        "flirt_apply_pattern_from_str_wire",
        "flirt_apply_pattern_matches_wire",
        "flirt_apply_pattern_new_wire",
        "flirt_apply_sig_db_add_count_wire",
        "flirt_apply_library_marks_from_matches",
        "flirt_apply_wildcard_prefix_wire",
    ]

    report = {
        "module": "flirt_apply",
        "tools_hardened": len(tools),
        "checks_passed": checks_passed,
        "checks_failed": checks_failed,
        "mismatches": mismatches,
    }

    REPORT_PATH.write_text(json.dumps(report, indent=2))
    print(f"tools_hardened : {len(tools)}")
    print(f"checks_passed  : {checks_passed}")
    print(f"checks_failed  : {checks_failed}")
    if mismatches:
        print("MISMATCHES:")
        for m in mismatches:
            print(" ", json.dumps(m))
    else:
        print("All checks passed — no mismatches.")

    sys.exit(0 if checks_failed == 0 else 1)


if __name__ == "__main__":
    main()
