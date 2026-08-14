"""
Rigorous validators for the ttd_replay / ttd_replayer module.

Each tool is called against the MCP binary and the output is compared to an
independently computed Python truth value.  No any_valid() shortcuts – every
check must verify a concrete expected value.
"""

from __future__ import annotations

import json
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

MCP_BIN = r"C:\Users\Fra\Desktop\RustRE\target\release\rustre-mcp.exe"
REPORT_PATH = Path(r"C:\Users\Fra\Desktop\RustRE\validation\rigorous_ttd_replay.json")

# ---------------------------------------------------------------------------
# MCP stdio helpers
# ---------------------------------------------------------------------------

class McpSession:
    def __init__(self, binary: str) -> None:
        self.proc = subprocess.Popen(
            [binary, "--transport=stdio"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
        )
        self._id = 0
        # initialise
        self._send({"jsonrpc": "2.0", "id": 0, "method": "initialize",
                     "params": {"protocolVersion": "2024-11-05",
                                "clientInfo": {"name": "rigorous-validator", "version": "1.0"},
                                "capabilities": {}}})
        self._recv()
        self._send({"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}})

    def _send(self, obj: dict) -> None:
        line = json.dumps(obj) + "\n"
        self.proc.stdin.write(line.encode())
        self.proc.stdin.flush()

    def _recv(self) -> dict:
        while True:
            raw = self.proc.stdout.readline()
            if not raw:
                raise RuntimeError("MCP process closed stdout unexpectedly")
            raw = raw.decode().strip()
            if not raw:
                continue
            return json.loads(raw)

    def call(self, tool: str, args: dict) -> Any:
        self._id += 1
        self._send({
            "jsonrpc": "2.0",
            "id": self._id,
            "method": "tools/call",
            "params": {"name": tool, "arguments": args},
        })
        resp = self._recv()
        if "error" in resp:
            raise RuntimeError(f"MCP error for {tool}: {resp['error']}")
        content = resp.get("result", {}).get("content", [])
        if not content:
            raise RuntimeError(f"Empty content for {tool}")
        return json.loads(content[0]["text"])

    def close(self) -> None:
        self.proc.terminate()


# ---------------------------------------------------------------------------
# Python reference implementations
# ---------------------------------------------------------------------------

def py_hex_dump(data: bytes) -> str:
    """Uppercase, space-separated hex bytes."""
    return " ".join(f"{b:02X}" for b in data)

def py_format_tick(tick: int) -> str:
    """Zero-padded decimal string, 16 digits wide."""
    return f"{tick:016d}"

def py_parse_hex(s: str) -> int | None:
    s = s.strip()
    for prefix in ("0x", "0X"):
        if s.startswith(prefix):
            s = s[len(prefix):]
            break
    try:
        return int(s, 16)
    except ValueError:
        return None

def py_mem_write_end_addr(addr: int, size: int) -> int:
    """end_addr = addr + size - 1 (saturating)."""
    return (addr + size - 1) & 0xFFFFFFFFFFFFFFFF

def py_mem_write_overlaps(wa: int, wl: int, ra: int, rs: int) -> bool:
    """Test whether write [wa, wa+wl) overlaps range [ra, ra+rs)."""
    if wl == 0 or rs == 0:
        return False
    self_last = wa + wl - 1
    range_last = ra + rs - 1
    return wa <= range_last and ra <= self_last

def py_bytes_in_range(wa: int, data: bytes, ra: int, rs: int) -> bytes:
    """Bytes of write that overlap [ra, ra+rs)."""
    range_end = ra + rs
    self_end = wa + len(data)
    start = max(wa, ra)
    end = min(self_end, range_end)
    if start >= end:
        return b""
    local_start = start - wa
    local_end = end - wa
    return data[local_start:local_end]

def py_trace_tick_bounds(n: int):
    """
    Synthetic trace with n SyscallEntry events at ticks 0..n-1.
    Returns (min_tick, max_tick, length, is_empty).
    """
    if n == 0:
        return (0, 0, 0, True)
    return (0, n - 1, n, False)

def py_query_parse_kind(q: str) -> str:
    """Map DSL string to AST kind name."""
    q_lower = q.strip().lower()
    table = {
        "max_tick": "MaxTick",
        "min_tick": "MinTick",
        "list_signals": "ListSignals",
    }
    if q_lower in table:
        return table[q_lower]
    if q_lower.startswith("read_mem"):
        return "ReadMem"
    if q_lower.startswith("find_writes"):
        return "FindWrites"
    if q_lower.startswith("last_write"):
        return "LastWrite"
    if q_lower.startswith("list_syscalls"):
        return "ListSyscalls"
    if q_lower.startswith("read_reg"):
        return "ReadReg"
    if q_lower.startswith("count_events"):
        return "CountEvents"
    if q_lower.startswith("root_cause"):
        return "RootCause"
    raise ValueError(f"Unknown query: {q}")


# ---------------------------------------------------------------------------
# Test cases
# ---------------------------------------------------------------------------

def run_checks(session: McpSession) -> tuple[list[dict], list[dict], list[dict]]:
    """Returns (passed, failed, mismatches)."""
    passed: list[dict] = []
    failed: list[dict] = []
    mismatches: list[dict] = []

    def ok(tool: str, note: str = ""):
        passed.append({"tool": tool, "note": note})

    def fail(tool: str, expected: Any, actual: Any):
        mismatches.append({"tool": tool, "expected": expected, "actual": actual})
        failed.append({"tool": tool, "expected": str(expected), "actual": str(actual)})

    # 1. ttd_replayer_hex_dump — [0xDE, 0xAD, 0xBE, 0xEF]
    data_bytes = bytes([0xDE, 0xAD, 0xBE, 0xEF])
    expected_dump = py_hex_dump(data_bytes)
    try:
        r = session.call("ttd_replayer_hex_dump", {"data_hex": "DEADBEEF"})
        actual_dump = r.get("dump")
        if actual_dump == expected_dump:
            ok("ttd_replayer_hex_dump", f"dump={actual_dump!r}")
        else:
            fail("ttd_replayer_hex_dump", expected_dump, actual_dump)
    except Exception as e:
        fail("ttd_replayer_hex_dump", expected_dump, f"ERROR: {e}")

    # 2. ttd_replayer_hex_dump — single byte
    expected2 = py_hex_dump(bytes([0xAB]))
    try:
        r = session.call("ttd_replayer_hex_dump", {"data_hex": "AB"})
        actual2 = r.get("dump")
        if actual2 == expected2:
            ok("ttd_replayer_hex_dump(single)", f"dump={actual2!r}")
        else:
            fail("ttd_replayer_hex_dump(single)", expected2, actual2)
    except Exception as e:
        fail("ttd_replayer_hex_dump(single)", expected2, f"ERROR: {e}")

    # 3. ttd_replayer_format_tick — tick=0
    expected_ft0 = py_format_tick(0)   # "0000000000000000"
    try:
        r = session.call("ttd_replayer_format_tick", {"tick": 0})
        actual_ft0 = r.get("formatted")
        if actual_ft0 == expected_ft0:
            ok("ttd_replayer_format_tick(0)", f"formatted={actual_ft0!r}")
        else:
            fail("ttd_replayer_format_tick(0)", expected_ft0, actual_ft0)
    except Exception as e:
        fail("ttd_replayer_format_tick(0)", expected_ft0, f"ERROR: {e}")

    # 4. ttd_replayer_format_tick — tick=255
    expected_ft255 = py_format_tick(255)  # "0000000000000255"
    try:
        r = session.call("ttd_replayer_format_tick", {"tick": 255})
        actual_ft255 = r.get("formatted")
        if actual_ft255 == expected_ft255:
            ok("ttd_replayer_format_tick(255)", f"formatted={actual_ft255!r}")
        else:
            fail("ttd_replayer_format_tick(255)", expected_ft255, actual_ft255)
    except Exception as e:
        fail("ttd_replayer_format_tick(255)", expected_ft255, f"ERROR: {e}")

    # 5. ttd_replayer_parse_hex — with 0x prefix (param name is "s")
    expected_ph = py_parse_hex("0xDEAD")  # 57005
    try:
        r = session.call("ttd_replayer_parse_hex", {"s": "0xDEAD"})
        actual_ph = r.get("value")
        if actual_ph == expected_ph:
            ok("ttd_replayer_parse_hex(0xDEAD)", f"value={actual_ph}")
        else:
            fail("ttd_replayer_parse_hex(0xDEAD)", expected_ph, actual_ph)
    except Exception as e:
        fail("ttd_replayer_parse_hex(0xDEAD)", expected_ph, f"ERROR: {e}")

    # 6. ttd_replayer_parse_hex — without prefix
    expected_ph2 = py_parse_hex("1234")  # 0x1234 = 4660
    try:
        r = session.call("ttd_replayer_parse_hex", {"s": "1234"})
        actual_ph2 = r.get("value")
        if actual_ph2 == expected_ph2:
            ok("ttd_replayer_parse_hex(1234)", f"value={actual_ph2}")
        else:
            fail("ttd_replayer_parse_hex(1234)", expected_ph2, actual_ph2)
    except Exception as e:
        fail("ttd_replayer_parse_hex(1234)", expected_ph2, f"ERROR: {e}")

    # 7. ttd_replayer_mem_write_info — addr=0x1000, data_len=8
    wa, wl = 0x1000, 8
    exp_end = py_mem_write_end_addr(wa, wl)  # 0x1007
    try:
        r = session.call("ttd_replayer_mem_write_info", {"addr": wa, "data_len": wl})
        actual_size = r.get("size")
        actual_end = r.get("end_addr")
        if actual_size == wl and actual_end == exp_end:
            ok("ttd_replayer_mem_write_info", f"size={actual_size} end_addr={actual_end:#x}")
        else:
            fail("ttd_replayer_mem_write_info", {"size": wl, "end_addr": exp_end},
                 {"size": actual_size, "end_addr": actual_end})
    except Exception as e:
        fail("ttd_replayer_mem_write_info", {"size": wl, "end_addr": exp_end}, f"ERROR: {e}")

    # 8. ttd_replayer_mem_write_overlaps — overlapping case
    exp_ov = py_mem_write_overlaps(0x1000, 8, 0x1004, 4)  # True
    try:
        r = session.call("ttd_replayer_mem_write_overlaps",
                         {"write_addr": 0x1000, "write_len": 8,
                          "range_addr": 0x1004, "range_size": 4})
        actual_ov = r.get("overlaps")
        if actual_ov == exp_ov:
            ok("ttd_replayer_mem_write_overlaps(overlap)", f"overlaps={actual_ov}")
        else:
            fail("ttd_replayer_mem_write_overlaps(overlap)", exp_ov, actual_ov)
    except Exception as e:
        fail("ttd_replayer_mem_write_overlaps(overlap)", exp_ov, f"ERROR: {e}")

    # 9. ttd_replayer_mem_write_overlaps — non-overlapping case
    exp_no_ov = py_mem_write_overlaps(0x1000, 8, 0x2000, 4)  # False
    try:
        r = session.call("ttd_replayer_mem_write_overlaps",
                         {"write_addr": 0x1000, "write_len": 8,
                          "range_addr": 0x2000, "range_size": 4})
        actual_no_ov = r.get("overlaps")
        if actual_no_ov == exp_no_ov:
            ok("ttd_replayer_mem_write_overlaps(no_overlap)", f"overlaps={actual_no_ov}")
        else:
            fail("ttd_replayer_mem_write_overlaps(no_overlap)", exp_no_ov, actual_no_ov)
    except Exception as e:
        fail("ttd_replayer_mem_write_overlaps(no_overlap)", exp_no_ov, f"ERROR: {e}")

    # 10. ttd_replayer_mem_write_bytes_in_range — partial overlap
    # Tool uses write_len to generate data internally (0..wl pattern), then calls bytes_in_range
    # write [0x1000, 0x1008) overlapping range [0x1004, 0x1008) → 4 bytes
    exp_bir_len = 4
    try:
        r = session.call("ttd_replayer_mem_write_bytes_in_range",
                         {"write_addr": 0x1000, "write_len": 8,
                          "range_addr": 0x1004, "range_size": 4})
        actual_len = r.get("len")
        if actual_len == exp_bir_len:
            ok("ttd_replayer_mem_write_bytes_in_range", f"len={actual_len}")
        else:
            fail("ttd_replayer_mem_write_bytes_in_range", exp_bir_len, actual_len)
    except Exception as e:
        fail("ttd_replayer_mem_write_bytes_in_range", exp_bir_len, f"ERROR: {e}")

    # 11. ttd_replayer_trace_tick_bounds — empty trace (n=0)
    try:
        r = session.call("ttd_replayer_trace_tick_bounds", {"n": 0})
        exp_empty = True
        actual_empty = r.get("is_empty")
        exp_len = 0
        actual_len = r.get("len")
        if actual_empty == exp_empty and actual_len == exp_len:
            ok("ttd_replayer_trace_tick_bounds(n=0)", "is_empty=True len=0")
        else:
            fail("ttd_replayer_trace_tick_bounds(n=0)",
                 {"is_empty": exp_empty, "len": exp_len},
                 {"is_empty": actual_empty, "len": actual_len})
    except Exception as e:
        fail("ttd_replayer_trace_tick_bounds(n=0)", {"is_empty": True, "len": 0}, f"ERROR: {e}")

    # 12. ttd_replayer_trace_tick_bounds — trace with 4 events
    try:
        r = session.call("ttd_replayer_trace_tick_bounds", {"n": 4})
        exp_len_4 = 4
        actual_len_4 = r.get("len")
        actual_empty_4 = r.get("is_empty")
        if actual_len_4 == exp_len_4 and actual_empty_4 == False:
            ok("ttd_replayer_trace_tick_bounds(n=4)", f"len={actual_len_4}")
        else:
            fail("ttd_replayer_trace_tick_bounds(n=4)",
                 {"len": exp_len_4, "is_empty": False},
                 {"len": actual_len_4, "is_empty": actual_empty_4})
    except Exception as e:
        fail("ttd_replayer_trace_tick_bounds(n=4)", {"len": 4, "is_empty": False}, f"ERROR: {e}")

    # 13. ttd_replayer_query_parse_kind — max_tick
    try:
        r = session.call("ttd_replayer_query_parse_kind", {"query": "max_tick"})
        exp_kind = "MaxTick"
        actual_kind = r.get("kind")
        actual_ok = r.get("ok")
        if actual_ok and actual_kind == exp_kind:
            ok("ttd_replayer_query_parse_kind(max_tick)", f"kind={actual_kind}")
        else:
            fail("ttd_replayer_query_parse_kind(max_tick)", {"ok": True, "kind": exp_kind},
                 {"ok": actual_ok, "kind": actual_kind})
    except Exception as e:
        fail("ttd_replayer_query_parse_kind(max_tick)", {"ok": True, "kind": "MaxTick"}, f"ERROR: {e}")

    # 14. ttd_replayer_query_parse_kind — min_tick
    try:
        r = session.call("ttd_replayer_query_parse_kind", {"query": "min_tick"})
        exp_kind2 = "MinTick"
        actual_kind2 = r.get("kind")
        if r.get("ok") and actual_kind2 == exp_kind2:
            ok("ttd_replayer_query_parse_kind(min_tick)", f"kind={actual_kind2}")
        else:
            fail("ttd_replayer_query_parse_kind(min_tick)", exp_kind2, actual_kind2)
    except Exception as e:
        fail("ttd_replayer_query_parse_kind(min_tick)", "MinTick", f"ERROR: {e}")

    # 15. ttd_replay_build_call_graph — n=0 → empty edges
    try:
        r = session.call("ttd_replay_build_call_graph", {"n": 0})
        actual_ec = r.get("edge_count", -1)
        if actual_ec == 0:
            ok("ttd_replay_build_call_graph(n=0)", "edge_count=0")
        else:
            fail("ttd_replay_build_call_graph(n=0)", 0, actual_ec)
    except Exception as e:
        fail("ttd_replay_build_call_graph(n=0)", 0, f"ERROR: {e}")

    # 16. ttd_replay_split_by_thread — n=0 → empty timelines
    try:
        r = session.call("ttd_replay_split_by_thread", {"n": 0})
        actual_tc = r.get("thread_count", -1)
        if actual_tc == 0:
            ok("ttd_replay_split_by_thread(n=0)", "thread_count=0")
        else:
            fail("ttd_replay_split_by_thread(n=0)", 0, actual_tc)
    except Exception as e:
        fail("ttd_replay_split_by_thread(n=0)", 0, f"ERROR: {e}")

    # 17. ttd_replayer_snapshot_boundary — interval=256, advance=0
    # Tool takes "interval" and "advance" params; snapshot_interval should echo back 256
    try:
        r = session.call("ttd_replayer_snapshot_boundary", {"interval": 256, "advance": 0})
        snap_interval = r.get("snapshot_interval")
        if snap_interval == 256:
            ok("ttd_replayer_snapshot_boundary", f"snapshot_interval={snap_interval}")
        else:
            fail("ttd_replayer_snapshot_boundary", 256, snap_interval)
    except Exception as e:
        fail("ttd_replayer_snapshot_boundary", 256, f"ERROR: {e}")

    return passed, failed, mismatches


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    print(f"Starting MCP session: {MCP_BIN}")
    session = McpSession(MCP_BIN)
    try:
        passed, failed, mismatches = run_checks(session)
    finally:
        session.close()

    tools_hardened = len(passed) + len(failed)
    report = {
        "module": "ttd_replay",
        "tools_hardened": tools_hardened,
        "checks_passed": len(passed),
        "checks_failed": len(failed),
        "mismatches": mismatches,
    }
    REPORT_PATH.write_text(json.dumps(report, indent=2))
    print(json.dumps(report, indent=2))

    if failed:
        print(f"\nFAILED {len(failed)} checks:")
        for f in failed:
            print(f"  {f['tool']}: expected={f['expected']!r} actual={f['actual']!r}")
    else:
        print("\nAll checks passed.")

    sys.exit(0 if not failed else 1)


if __name__ == "__main__":
    main()
