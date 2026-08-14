#!/usr/bin/env python3
"""
Rigorous ground-truth validator for all MCP tools with prefix 'windbg_'.
Outputs rigorous_windbg_v2.json and skip_windbg.json.

All expected values are computed purely from Python stdlib and the Rust source
logic read from the codebase — no trust is placed in MCP output.
"""

import json
import struct
import subprocess
import sys
from pathlib import Path

EXE = r"C:\Users\Fra\Desktop\RustRE\target\release\rustre-mcp.exe"
OUT_RIGOROUS = r"C:\Users\Fra\Desktop\RustRE\validation\rigorous_windbg_v2.json"
OUT_SKIP = r"C:\Users\Fra\Desktop\RustRE\validation\skip_windbg.json"

# ---------------------------------------------------------------------------
# MCP plumbing (same pattern as exercise_v3.py)
# ---------------------------------------------------------------------------

def start_mcp():
    p = subprocess.Popen(
        [EXE, "--transport=stdio"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        bufsize=0,
    )
    _id = [0]

    def send(req):
        p.stdin.write((json.dumps(req) + "\n").encode())
        p.stdin.flush()

    def recv():
        line = p.stdout.readline()
        if not line:
            raise RuntimeError("MCP server died")
        return json.loads(line)

    _id[0] = 1
    send({"jsonrpc": "2.0", "id": _id[0], "method": "initialize",
          "params": {"protocolVersion": "2024-11-05", "capabilities": {},
                     "clientInfo": {"name": "rigorous-windbg", "version": "2"}}})
    recv()
    send({"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}})
    return p, send, recv, _id


def call_tool(send, recv, _id, name, args):
    _id[0] += 1
    send({"jsonrpc": "2.0", "id": _id[0], "method": "tools/call",
          "params": {"name": name, "arguments": args}})
    resp = recv()
    if "error" in resp:
        return None, f"JSONRPC_ERROR: {resp['error']}"
    result = resp.get("result", {})
    if result.get("isError"):
        txt = (result.get("content") or [{}])[0].get("text", "")
        return None, f"TOOL_ERROR: {txt[:200]}"
    content = result.get("content", [])
    if not content:
        return None, "EMPTY"
    txt = content[0].get("text", "")
    try:
        return json.loads(txt), None
    except Exception:
        return txt, None


def list_tools(send, recv, _id):
    _id[0] += 1
    send({"jsonrpc": "2.0", "id": _id[0], "method": "tools/list", "params": {}})
    return recv().get("result", {}).get("tools", [])


# ---------------------------------------------------------------------------
# Independent ground-truth reference implementations
# (derived from reading the Rust source in crates/rustre-debug-windbg/src/lib.rs
#  and crates/rustre-mcp-tools/src/wire_tools.rs)
# ---------------------------------------------------------------------------

# -- KdNetPacketType::type_id() mapping (from lib.rs lines 2514-2523) --
KDNET_TYPE_ID = {
    "breakpoint":      0x0003,
    "statechange":     0x0004,
    "state_change":    0x0004,
    "manipulatestate": 0x0005,
    "manipulate_state":0x0005,
    "controlrequest":  0x0006,
    "control_request": 0x0006,
    "acknowledge":     0x0000,
    "ack":             0x0000,
    "resend":          0x0001,
    "debug":           0x0002,
}

# -- KdNetPacketType::from_id() mapping (from lib.rs lines 2528-2539) --
KDNET_FROM_ID = {
    0x0000: "Acknowledge",
    0x0001: "Resend",
    0x0002: "Debug",
    0x0003: "Breakpoint",
    0x0004: "StateChange",
    0x0005: "ManipulateState",
    0x0006: "ControlRequest",
}

# -- MinidumpStreamType::name() (from lib.rs lines 2318-2340) --
MINIDUMP_STREAM_NAMES = {
    0:  "Unused",           # UnusedStream
    3:  "ThreadList",       # ThreadListStream
    4:  "ModuleList",       # ModuleListStream
    5:  "MemoryList",       # MemoryListStream
    6:  "Exception",        # ExceptionStream
    7:  "SystemInfo",       # SystemInfoStream
    9:  "Memory64List",     # Memory64ListStream
    10: "CommentA",
    11: "CommentW",
    12: "HandleData",
    14: "UnloadedModuleList",
    15: "MiscInfo",
    16: "MemoryInfoList",
    17: "ThreadInfoList",
    18: "HandleOperationList",
    19: "Token",
    20: "JavascriptData",
    21: "SystemMemoryInfo",
    22: "ProcessVmCounters",
    23: "IptTrace",
    0x7FFF: "User",
}

# -- ExtensionRegistry::standard() commands (from lib.rs lines 2238-2253) --
STANDARD_EXTENSION_NAMES = [
    "!analyze", "!heap", "!address", "!teb", "!peb",
    "!dh", "!lmi", "!gle", "!error",
    "!process", "!thread", "!handle", "!pool", "!drvobj", "!devobj",
]
STANDARD_EXTENSION_COUNT = len(STANDARD_EXTENSION_NAMES)  # 15

STANDARD_EXT_MAP = {
    "!analyze":  {"name": "!analyze",  "description": "Automatic crash analysis",       "dll_name": "ext.dll"},
    "!heap":     {"name": "!heap",     "description": "Heap inspection",                "dll_name": "ext.dll"},
    "!address":  {"name": "!address",  "description": "Virtual address information",    "dll_name": "ext.dll"},
    "!teb":      {"name": "!teb",      "description": "Thread environment block",       "dll_name": "ext.dll"},
    "!peb":      {"name": "!peb",      "description": "Process environment block",      "dll_name": "ext.dll"},
    "!dh":       {"name": "!dh",       "description": "Display image header",           "dll_name": "ext.dll"},
    "!lmi":      {"name": "!lmi",      "description": "Loaded module information",      "dll_name": "ext.dll"},
    "!gle":      {"name": "!gle",      "description": "Get last error",                 "dll_name": "ext.dll"},
    "!error":    {"name": "!error",    "description": "Decode error code",              "dll_name": "ext.dll"},
    "!process":  {"name": "!process",  "description": "Process information",            "dll_name": "nt.dll"},
    "!thread":   {"name": "!thread",   "description": "Thread information",             "dll_name": "nt.dll"},
    "!handle":   {"name": "!handle",   "description": "Handle table",                  "dll_name": "nt.dll"},
    "!pool":     {"name": "!pool",     "description": "Pool allocation information",    "dll_name": "nt.dll"},
    "!drvobj":   {"name": "!drvobj",   "description": "Driver object information",      "dll_name": "nt.dll"},
    "!devobj":   {"name": "!devobj",   "description": "Device object information",      "dll_name": "nt.dll"},
}


def ref_kdnet_checksum(data_hex: str) -> dict:
    """KdNetPacket::compute_checksum — wrapping additive sum of bytes."""
    data = bytes.fromhex(data_hex)
    csum = 0
    for b in data:
        csum = (csum + b) & 0xFFFFFFFF
    return {"checksum": csum}


def ref_kdnet_type_id(kind: str) -> dict:
    key = kind.lower().replace("-", "").replace(" ", "")
    if key not in KDNET_TYPE_ID:
        raise ValueError(f"unknown kind: {kind!r}")
    return {"type_id": KDNET_TYPE_ID[key]}


def ref_kdnet_from_id(type_id: int) -> dict:
    val = KDNET_FROM_ID.get(type_id)
    return {"kind": val}


def ref_kdnet_encode(packet_id: int, data_hex: str) -> dict:
    """Reproduce KdNetPacket::new(Debug, packet_id, data).encode()."""
    data = bytes.fromhex(data_hex) if data_hex else b""
    # type_id for Debug = 0x0002
    type_id = 0x0002
    checksum = 0
    for b in data:
        checksum = (checksum + b) & 0xFFFFFFFF
    leader = 0x30303030
    byte_count = len(data)
    # Header: 4(leader) + 2(type_id) + 2(byte_count) + 4(packet_id) + 4(checksum)
    header = struct.pack("<IHHI I", leader, type_id, byte_count, packet_id, checksum)
    encoded = header + data
    bytes_hex = encoded.hex()
    return {
        "bytes_hex": bytes_hex,
        "byte_count": byte_count,
        "checksum": checksum,
        "verified": True,
    }


def ref_minidump_stream_name(stream_id: int) -> dict:
    name = MINIDUMP_STREAM_NAMES.get(stream_id)
    return {"name": name}


def ref_module_contains(base: int, size: int, addr: int) -> dict:
    # Rust: addr >= base && addr < base.saturating_add(size)
    end = base + size  # Python ints don't overflow
    result = base <= addr < end
    return {"contains": result}


def ref_ext_registry_count() -> dict:
    return {"count": STANDARD_EXTENSION_COUNT}


def ref_ext_registry_find(name: str) -> dict:
    """ExtensionRegistry::find — case-insensitive, strips leading '!'."""
    normalized = name.lstrip("!")
    for cmd_name, cmd in STANDARD_EXT_MAP.items():
        if cmd_name.lstrip("!").lower() == normalized.lower():
            return {"command": cmd}
    return {"command": None}


# ---------------------------------------------------------------------------
# Test case definitions
# ---------------------------------------------------------------------------

def build_test_cases():
    """Returns list of (tool_name, args, expected_dict_or_skip)."""
    cases = []

    # windbg_kdnet_packet_checksum
    for hex_str in ["00000000", "deadbeef", "ffffffff", "01020304"]:
        cases.append(("windbg_kdnet_packet_checksum",
                       {"data_hex": hex_str},
                       ref_kdnet_checksum(hex_str)))

    # windbg_kdnet_packet_type_id
    for kind in ["breakpoint", "statechange", "manipulatestate",
                 "controlrequest", "acknowledge", "resend", "debug"]:
        cases.append(("windbg_kdnet_packet_type_id",
                       {"kind": kind},
                       ref_kdnet_type_id(kind)))

    # windbg_kdnet_packet_from_id
    for tid in [0, 1, 2, 3, 4, 5, 6, 99]:
        cases.append(("windbg_kdnet_packet_from_id",
                       {"type_id": tid},
                       ref_kdnet_from_id(tid)))

    # windbg_kdnet_packet_encode
    for pid, hex_str in [(0, "00000000"), (1, "deadbeef"), (0, "")]:
        cases.append(("windbg_kdnet_packet_encode",
                       {"packet_id": pid, "data_hex": hex_str},
                       ref_kdnet_encode(pid, hex_str)))

    # windbg_minidump_stream_type_name
    for sid in [0, 3, 4, 5, 6, 7, 9, 15, 16, 999]:
        cases.append(("windbg_minidump_stream_type_name",
                       {"stream_id": sid},
                       ref_minidump_stream_name(sid)))

    # windbg_dbg_module_info_contains
    for base, size, addr, expected in [
        (0x140000000, 0x10000, 0x140005000, True),
        (0x140000000, 0x10000, 0x140010000, False),  # at end, excluded
        (0x140000000, 0x10000, 0x13FFFFFFF, False),  # before base
        (0x140000000, 0x10000, 0x140000000, True),   # at base
        (0x140000000, 0x10000, 0x14000FFFF, True),   # last valid
    ]:
        cases.append(("windbg_dbg_module_info_contains",
                       {"base": base, "size": size, "addr": addr},
                       ref_module_contains(base, size, addr)))

    # windbg_extension_registry_standard_count
    cases.append(("windbg_extension_registry_standard_count",
                   {},
                   ref_ext_registry_count()))

    # windbg_extension_registry_find
    for name in ["!analyze", "analyze", "!heap", "!teb", "!peb",
                 "!process", "unknown", "dbgeng", "ntsdexts"]:
        cases.append(("windbg_extension_registry_find",
                       {"name": name},
                       ref_ext_registry_find(name)))

    return cases


# ---------------------------------------------------------------------------
# Comparison helpers
# ---------------------------------------------------------------------------

def strip_source(obj):
    """Remove the 'source' metadata key the Rust server always appends."""
    if isinstance(obj, dict):
        return {k: strip_source(v) for k, v in obj.items() if k != "source"}
    return obj


def values_match(got, expected):
    """Recursive comparison; dicts check only keys present in expected.
    Hex strings are compared case-insensitively (0xDEADBEEF == 0xdeadbeef)."""
    if isinstance(expected, dict):
        got2 = strip_source(got) if isinstance(got, dict) else got
        if not isinstance(got2, dict):
            return False
        for k, ev in expected.items():
            if not values_match(got2.get(k), ev):
                return False
        return True
    if isinstance(expected, list):
        if not isinstance(got, list) or len(got) != len(expected):
            return False
        return all(values_match(g, e) for g, e in zip(got, expected))
    # Hex string comparison: treat as equal if they differ only in case
    if isinstance(expected, str) and isinstance(got, str):
        return expected.lower() == got.lower()
    return got == expected


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    p, send, recv, _id = start_mcp()

    try:
        # Discover which windbg_ tools exist
        all_tools = list_tools(send, recv, _id)
        windbg_names = {t["name"] for t in all_tools if t["name"].startswith("windbg_")}
        print(f"[*] windbg_ tools available: {sorted(windbg_names)}")

        test_cases = build_test_cases()

        results = []
        skipped = []
        passed = 0
        failed = 0

        for tool_name, args, expected in test_cases:
            if tool_name not in windbg_names:
                skipped.append({
                    "tool": tool_name,
                    "reason": "tool not registered in MCP server",
                    "args": args,
                })
                continue

            actual, err = call_tool(send, recv, _id, tool_name, args)
            if err:
                results.append({
                    "tool": tool_name,
                    "args": args,
                    "status": "FAIL",
                    "expected": expected,
                    "actual": None,
                    "error": err,
                })
                failed += 1
                print(f"  FAIL  {tool_name} args={args}  error={err}")
                continue

            if values_match(actual, expected):
                results.append({
                    "tool": tool_name,
                    "args": args,
                    "status": "PASS",
                    "expected": expected,
                    "actual": strip_source(actual) if isinstance(actual, dict) else actual,
                })
                passed += 1
                print(f"  PASS  {tool_name}")
            else:
                results.append({
                    "tool": tool_name,
                    "args": args,
                    "status": "FAIL",
                    "expected": expected,
                    "actual": strip_source(actual) if isinstance(actual, dict) else actual,
                    "error": "value mismatch",
                })
                failed += 1
                exp_str = json.dumps(expected)
                act_str = json.dumps(strip_source(actual) if isinstance(actual, dict) else actual)
                print(f"  FAIL  {tool_name}  args={args}")
                print(f"        expected: {exp_str}")
                print(f"        actual  : {act_str}")

        # Tools that exist but have no test cases
        tested_tools = {tc[0] for tc in test_cases}
        for name in sorted(windbg_names - tested_tools):
            skipped.append({
                "tool": name,
                "reason": "no independent ground-truth test case (nondeterministic or complex output)",
            })

        # Write outputs
        rigorous = {
            "category": "windbg",
            "tools_hardened": len(windbg_names),
            "tools_passed": passed,
            "tools_failed": failed,
            "tools_skipped": len(skipped),
            "results": results,
        }
        with open(OUT_RIGOROUS, "w") as f:
            json.dump(rigorous, f, indent=2)

        with open(OUT_SKIP, "w") as f:
            json.dump(skipped, f, indent=2)

        print(f"\n[*] PASS={passed}  FAIL={failed}  SKIP={len(skipped)}")
        print(f"[*] Results -> {OUT_RIGOROUS}")
        print(f"[*] Skips   -> {OUT_SKIP}")

        # Compute summary
        mismatches = [r for r in results if r["status"] == "FAIL"]
        mismatch_list = [
            {"tool": r["tool"], "expected": r["expected"], "actual": r.get("actual")}
            for r in mismatches
        ]

        return {
            "category": "windbg",
            "tools_hardened": len(windbg_names),
            "tools_passed": passed,
            "tools_failed": failed,
            "tools_skipped": len(skipped),
            "mismatches": mismatch_list,
        }

    finally:
        try:
            p.stdin.close()
        except Exception:
            pass
        try:
            p.terminate()
            p.wait(timeout=5)
        except Exception:
            pass


if __name__ == "__main__":
    summary = main()
    print("\n[SUMMARY JSON]")
    print(json.dumps(summary, indent=2))
