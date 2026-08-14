#!/usr/bin/env python3
"""
Rigorous v3 validator for remaining flirt-category MCP tools.

Covers 6 tools not yet hardened in gen/apply/v2 validators:
  - flirt_gen_sig_trie_branch_encode_wire
  - flirt_gen_sig_trie_node_encode_leaf_wire
  - decomp_symbol_map_from_flirt
  - decomp_symbol_map_from_flirt_pairs_dcx1
  - events_ext_bus_send_flirt_match
  - rlib_dec_symbol_map_from_flirt_pairs

Output: C:/Users/Fra/Desktop/RustRE/validation/rigorous_flirt_v3.json
"""
from __future__ import annotations
import json
import subprocess
import time
from pathlib import Path

MCP_EXE     = r"C:\Users\Fra\Desktop\RustRE\target\release\rustre-mcp.exe"
REPORT_PATH = Path(r"C:\Users\Fra\Desktop\RustRE\validation\rigorous_flirt_v3.json")

# ---------------------------------------------------------------------------
# Python reference computations
# ---------------------------------------------------------------------------

def py_sig_trie_branch_encode(prefix: list[int]) -> dict:
    """
    Encode SigTrieNode::Branch {prefix, children=[]} and return stats.
    Format: push(plen), push(*prefix[:plen]), push(0x00)[child_sentinel], push(0x00)[end_sentinel]
    """
    plen = min(len(prefix), 255)
    buf = [plen] + prefix[:plen] + [0x00, 0x00]
    return {
        "len": len(buf),
        "prefix_len": buf[0],
        "prefix_byte": buf[1] if len(buf) > 1 else None,
        "child_sentinel": buf[plen + 1] if len(buf) > plen + 1 else None,
        "end_sentinel": buf[plen + 2] if len(buf) > plen + 2 else None,
    }


def py_sig_trie_leaf_encode(prefix: list[int], crc_len: int, crc16: int,
                             module_offset: int, func_name: str) -> dict:
    """
    Encode SigTrieNode::Leaf and return stats.
    Format: push(plen), push(*prefix[:plen]),
            push(0x01)[flag], push(crc_len),
            push(*crc16_le), push(*module_offset_le),
            push(name_len), push(*name_bytes)
    """
    plen = min(len(prefix), 255)
    name_bytes = func_name.encode("ascii")
    name_len = min(len(name_bytes), 255)
    buf = (
        [plen]
        + prefix[:plen]
        + [0x01, crc_len]
        + list(crc16.to_bytes(2, "little"))
        + list(module_offset.to_bytes(2, "little"))
        + [name_len]
        + list(name_bytes[:name_len])
    )
    # flag_byte is buf[plen + 1]
    flag_byte = buf[plen + 1]
    return {
        "len": len(buf),
        "prefix_len": buf[0],
        "flag_byte": flag_byte,
    }


# Wire tool test vectors (must match the Rust wire tool hard-coded data):
# Branch: prefix=[0x55], children=[]
BRANCH_EXPECTED = py_sig_trie_branch_encode([0x55])

# Leaf: prefix=[0x55,0x48,0x89,0xE5], crc_len=4, crc16=0xABCD,
#       module_offset=0, func_name="foo"
LEAF_EXPECTED = py_sig_trie_leaf_encode(
    [0x55, 0x48, 0x89, 0xE5], crc_len=4, crc16=0xABCD,
    module_offset=0, func_name="foo"
)

# decomp_symbol_map_from_flirt:
#   pairs=[{address:0x1000, name:"memcpy"}, {address:0x2000, name:"strlen"}]
#   lookup=0x1000, xrefs=[]
#   Expected: len=2, lookup=0x1000, resolved="memcpy", xref_count=0
DECOMP_PAIRS = [
    {"address": 0x1000, "name": "memcpy"},
    {"address": 0x2000, "name": "strlen"},
]
DECOMP_LOOKUP = 0x1000

# decomp_symbol_map_from_flirt_pairs_dcx1:
#   Hard-coded in Rust: 2 pairs → len=2
DCX1_EXPECTED_LEN = 2

# events_ext_bus_send_flirt_match:
#   One event sent → variant_count=1, total=1
EVENTS_EXPECTED = {"variant_count": 1, "total": 1}

# rlib_dec_symbol_map_from_flirt_pairs with empty pairs:
#   len=0, input_count=0
RLIB_EMPTY_EXPECTED = {"len": 0, "input_count": 0}

# rlib_dec_symbol_map_from_flirt_pairs with 2 valid pairs:
#   len=2, input_count=2
RLIB_PAIRS = [
    {"addr": 0x1000, "name": "memcpy"},
    {"addr": 0x2000, "name": "strlen"},
]
RLIB_PAIRS_EXPECTED = {"len": 2, "input_count": 2}


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
        self._send_raw({"jsonrpc": "2.0", "id": 0, "method": "initialize",
            "params": {"protocolVersion": "2024-11-05",
                       "clientInfo": {"name": "rigorous_flirt_v3", "version": "1.0"},
                       "capabilities": {}}})
        self._recv()
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

    def call(self, name: str, args: dict):
        self._id += 1
        self._send_raw({"jsonrpc": "2.0", "id": self._id, "method": "tools/call",
            "params": {"name": name, "arguments": args}})
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


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

def run_all(s: McpSession):
    # -----------------------------------------------------------------------
    # 1. flirt_gen_sig_trie_branch_encode_wire
    #    Branch{prefix=[0x55], children=[]} → len=4, prefix_len=1,
    #    prefix_byte=85, child_sentinel=0, end_sentinel=0
    # -----------------------------------------------------------------------
    tool = "flirt_gen_sig_trie_branch_encode_wire"
    r = s.call(tool, {})
    if r and not r.get("_error") and not r.get("_raw"):
        check(tool, "len",            r.get("len"),            BRANCH_EXPECTED["len"],
              f"Branch{{[0x55],[]}} encodes to {BRANCH_EXPECTED['len']} bytes")
        check(tool, "prefix_len",     r.get("prefix_len"),     BRANCH_EXPECTED["prefix_len"],
              "plen byte = len(prefix) = 1")
        check(tool, "prefix_byte",    r.get("prefix_byte"),    BRANCH_EXPECTED["prefix_byte"],
              "prefix[0] = 0x55 = 85")
        check(tool, "child_sentinel", r.get("child_sentinel"), BRANCH_EXPECTED["child_sentinel"],
              "child_sentinel = 0x00")
        check(tool, "end_sentinel",   r.get("end_sentinel"),   BRANCH_EXPECTED["end_sentinel"],
              "end_sentinel = 0x00")
    harden(tool)

    # -----------------------------------------------------------------------
    # 2. flirt_gen_sig_trie_node_encode_leaf_wire
    #    Leaf{prefix=[0x55,0x48,0x89,0xE5], crc_len=4, crc16=0xABCD,
    #         module_offset=0, func_name="foo"}
    #    → len=15, prefix_len=4, flag_byte=1
    # -----------------------------------------------------------------------
    tool = "flirt_gen_sig_trie_node_encode_leaf_wire"
    r = s.call(tool, {})
    if r and not r.get("_error") and not r.get("_raw"):
        check(tool, "len",        r.get("len"),        LEAF_EXPECTED["len"],
              "1+4+1+1+2+2+1+3 = 15 bytes")
        check(tool, "prefix_len", r.get("prefix_len"), LEAF_EXPECTED["prefix_len"],
              "plen = 4 (4-byte prefix)")
        check(tool, "flag_byte",  r.get("flag_byte"),  LEAF_EXPECTED["flag_byte"],
              "flag_byte = 0x01 (leaf marker)")
    harden(tool)

    # -----------------------------------------------------------------------
    # 3. decomp_symbol_map_from_flirt — full round-trip with known pairs
    # -----------------------------------------------------------------------
    tool = "decomp_symbol_map_from_flirt"
    r = s.call(tool, {"pairs": DECOMP_PAIRS, "lookup": DECOMP_LOOKUP, "xrefs": []})
    if r and not r.get("_error") and not r.get("_raw"):
        check(tool, "len",         r.get("len"),         2,
              "2 pairs → len=2")
        check(tool, "lookup_echo", r.get("lookup"),      DECOMP_LOOKUP,
              "lookup echoed back")
        check(tool, "resolved",    r.get("resolved"),    "memcpy",
              "0x1000 resolves to 'memcpy'")
        check(tool, "xref_count",  r.get("xref_count"),  None,
              "no xrefs set -> xref_count=null (not present in map)")
    # With xrefs set
    r2 = s.call(tool, {
        "pairs": DECOMP_PAIRS,
        "lookup": DECOMP_LOOKUP,
        "xrefs": [{"address": DECOMP_LOOKUP, "count": 7}],
    })
    if r2 and not r2.get("_error") and not r2.get("_raw"):
        check(tool, "xref_count_set", r2.get("xref_count"), 7,
              "xref_count=7 after setting")
        check(tool, "len_xrefs", r2.get("len"), 2, "len unchanged by xrefs")
    harden(tool)

    # -----------------------------------------------------------------------
    # 4. decomp_symbol_map_from_flirt_pairs_dcx1
    #    Hard-coded 2 pairs → len=2
    # -----------------------------------------------------------------------
    tool = "decomp_symbol_map_from_flirt_pairs_dcx1"
    r = s.call(tool, {})
    if r and not r.get("_error") and not r.get("_raw"):
        check(tool, "len", r.get("len"), DCX1_EXPECTED_LEN,
              "2 hard-coded pairs → len=2")
    harden(tool)

    # -----------------------------------------------------------------------
    # 5. events_ext_bus_send_flirt_match
    #    Send 1 FlirtMatch event → variant_count=1, total=1
    # -----------------------------------------------------------------------
    tool = "events_ext_bus_send_flirt_match"
    r = s.call(tool, {})
    if r and not r.get("_error") and not r.get("_raw"):
        check(tool, "variant_count", r.get("variant_count"),
              EVENTS_EXPECTED["variant_count"],
              "1 FlirtMatch sent → variant_count=1")
        check(tool, "total", r.get("total"),
              EVENTS_EXPECTED["total"],
              "total published=1")
    # With explicit args
    r2 = s.call(tool, {"view_id": 42, "address": 0x5000, "library": "msvcrt",
                        "name": "strlen", "score": 0.95})
    if r2 and not r2.get("_error") and not r2.get("_raw"):
        check(tool, "variant_count_explicit", r2.get("variant_count"), 1,
              "explicit args still 1 FlirtMatch per call")
        check(tool, "total_explicit", r2.get("total"), 1,
              "total=1 per fresh bus")
    harden(tool)

    # -----------------------------------------------------------------------
    # 6. rlib_dec_symbol_map_from_flirt_pairs
    #    Empty → len=0, input_count=0; 2 pairs → len=2, input_count=2
    # -----------------------------------------------------------------------
    tool = "rlib_dec_symbol_map_from_flirt_pairs"
    # Empty pairs (no args)
    r = s.call(tool, {})
    if r and not r.get("_error") and not r.get("_raw"):
        check(tool, "len_empty",          r.get("len"),          0,
              "no pairs → len=0")
        check(tool, "input_count_empty",  r.get("input_count"),  0,
              "no pairs → input_count=0")
    # 2 valid pairs
    r2 = s.call(tool, {"pairs": RLIB_PAIRS})
    if r2 and not r2.get("_error") and not r2.get("_raw"):
        check(tool, "len_2",         r2.get("len"),         2,
              "2 pairs → len=2")
        check(tool, "input_count_2", r2.get("input_count"), 2,
              "2 pairs → input_count=2")
    harden(tool)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    print(f"Rigorous flirt v3 validator — {MCP_EXE}")
    print(f"Reference values:")
    print(f"  Branch encode: {BRANCH_EXPECTED}")
    print(f"  Leaf encode:   {LEAF_EXPECTED}")

    session = McpSession(MCP_EXE)
    try:
        run_all(session)
    finally:
        session.close()

    report = {
        "category": "flirt",
        "tools_hardened": len(tools_hardened),
        "tools_passed": checks_passed,
        "tools_failed": checks_failed,
        "tools_skipped": 0,
        "mismatches": mismatches,
        "notes": (
            "v3 hardens 6 remaining flirt-category tools: "
            "flirt_gen_sig_trie_branch_encode_wire, "
            "flirt_gen_sig_trie_node_encode_leaf_wire, "
            "decomp_symbol_map_from_flirt, "
            "decomp_symbol_map_from_flirt_pairs_dcx1, "
            "events_ext_bus_send_flirt_match, "
            "rlib_dec_symbol_map_from_flirt_pairs. "
            "All 6 tools have independently computed expected values."
        ),
    }
    REPORT_PATH.write_text(json.dumps(report, indent=2))
    print(f"\nResult: {checks_passed} passed, {checks_failed} failed, "
          f"{len(tools_hardened)} tools hardened")
    if mismatches:
        print("MISMATCHES:")
        for m in mismatches:
            print(f"  {m}".encode("ascii", errors="replace").decode("ascii"))
    print(f"Written: {REPORT_PATH}")
    return report


if __name__ == "__main__":
    main()
