#!/usr/bin/env python3
"""
Rigorous TTD tool validator: calls each ttd_* MCP tool with known inputs,
computes expected output with an independent Python reference, and compares
byte-for-byte / value-for-value.

Communication: json-rpc-over-stdio (same mechanism as exercise_v3.py).
"""
import json
import struct
import subprocess
import sys

EXE = r"C:\Users\Fra\Desktop\RustRE\target\release\rustre-mcp.exe"
TARGET = r"C:\Users\Fra\Desktop\Zyphora\target\release\cargo-zyphora.exe"
OUT = r"C:\Users\Fra\Desktop\RustRE\validation\rigorous_ttd_v2.json"
SKIP_OUT = r"C:\Users\Fra\Desktop\RustRE\validation\skip_ttd.json"

# ── MCP helpers ───────────────────────────────────────────────────────────────

p = subprocess.Popen(
    [EXE, "--transport=stdio"],
    stdin=subprocess.PIPE,
    stdout=subprocess.PIPE,
    stderr=subprocess.DEVNULL,
    bufsize=0,
)

def send(req):
    p.stdin.write((json.dumps(req) + "\n").encode())
    p.stdin.flush()

def recv():
    line = p.stdout.readline()
    if not line:
        raise RuntimeError("MCP server died")
    try:
        return json.loads(line)
    except json.JSONDecodeError:
        return {"error": {"message": f"bad-line: {line[:120]!r}"}}

# Handshake
send({"jsonrpc":"2.0","id":1,"method":"initialize","params":{
    "protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"rigorous_ttd_v2","version":"1"}}})
recv()
send({"jsonrpc":"2.0","method":"notifications/initialized"})

# Open project so the binary_id is set
send({"jsonrpc":"2.0","id":2,"method":"tools/call","params":{
    "name":"project.open","arguments":{"path":TARGET}}})
op = recv()
try:
    op_data = json.loads(op["result"]["content"][0]["text"])
    BINARY_ID = op_data["binary_id"]
except Exception:
    BINARY_ID = ""

_rid = 100
def call_tool(name, args):
    global _rid
    _rid += 1
    send({"jsonrpc":"2.0","id":_rid,"method":"tools/call","params":{"name":name,"arguments":args}})
    resp = recv()
    if "error" in resp:
        return None, f"JSONRPC_ERROR: {resp['error']}"
    res = resp.get("result", {})
    is_err = res.get("isError", False)
    content = res.get("content", [])
    txt = content[0].get("text", "") if content else ""
    if is_err:
        return None, f"TOOL_ERROR: {txt[:200]}"
    try:
        return json.loads(txt), None
    except json.JSONDecodeError:
        return txt, None

# ── Python reference implementations ─────────────────────────────────────────

def ref_hex_dump(data: bytes) -> str:
    """Uppercase space-separated hex string."""
    return " ".join(f"{b:02X}" for b in data)

def ref_format_tick(tick: int) -> str:
    """16-digit zero-padded decimal."""
    return f"{tick:016d}"

def ref_parse_hex(s: str):
    """Parse hex string (with/without 0x prefix) to int, or None on error."""
    s = s.strip()
    if s.startswith("0x") or s.startswith("0X"):
        s = s[2:]
    try:
        return int(s, 16)
    except ValueError:
        return None

def ref_is_valid_extension(path: str) -> bool:
    """True if extension is .run or .ttd (case-insensitive)."""
    ext = path.rsplit(".", 1)[-1].lower() if "." in path else ""
    return ext in ("run", "ttd")

def ref_position_min(a_seq, a_step, b_seq, b_step):
    """Lexicographic minimum of two (sequence, step) positions."""
    if (a_seq, a_step) <= (b_seq, b_step):
        return (a_seq, a_step)
    return (b_seq, b_step)

def ref_position_max(a_seq, a_step, b_seq, b_step):
    """Lexicographic maximum of two (sequence, step) positions."""
    if (a_seq, a_step) >= (b_seq, b_step):
        return (a_seq, a_step)
    return (b_seq, b_step)

def ref_trace_position_as_u128(sequence: int, step: int) -> int:
    """(sequence << 64) | step."""
    return (sequence << 64) | step

def ref_trace_position_from_u128(v: int):
    """Reconstruct (sequence, step) from u128."""
    sequence = (v >> 64) & 0xFFFFFFFFFFFFFFFF
    step = v & 0xFFFFFFFFFFFFFFFF
    return (sequence, step)

def ref_memory_snapshot_contains(base: int, length: int, addr: int) -> bool:
    """Check base <= addr < base+length."""
    return base <= addr < base + length

def ref_memory_snapshot_end_address(base: int, length: int) -> int:
    """base + length (with saturating add simulation for large values)."""
    result = base + length
    if result > 0xFFFFFFFFFFFFFFFF:
        return 0xFFFFFFFFFFFFFFFF
    return result

def ref_memory_snapshot_read_u32_le(base: int, data: bytes, addr: int):
    """Read u32 LE from snapshot at addr, or None if out of range."""
    end = base + len(data)
    if addr < base or addr + 4 > end:
        return None
    off = addr - base
    return struct.unpack_from("<I", data, off)[0]

def ref_build_test_trace_event_count(n: int) -> int:
    """build_test_trace produces exactly n events."""
    return n

def ref_build_test_trace_thread_ids(n: int):
    """Single-thread trace: thread_ids = [1]."""
    return [1]

def ref_build_multi_thread_trace_event_count(n: int) -> int:
    return n

def ref_build_multi_thread_trace_thread_ids(n: int):
    """Two-thread trace: thread_ids = [1, 2] (always, regardless of n)."""
    return [1, 2]

def ref_build_syscall_summaries_count(n: int) -> int:
    # For i in 0..n: syscall_entry(i, ...) — unique nrs 0..n
    return n

def ref_build_syscall_summaries_total_bytes(n: int) -> int:
    # Each exit writes 8 bytes (vec![0u8; 8])
    return n * 8

def ref_scan_for_writes_hit_count(addr: int, size: int, n: int) -> int:
    # Writes at addr + i*4 (4 bytes each) for i in 0..n
    # Range [addr, addr+size)
    hits = 0
    for i in range(n):
        write_addr = addr + i * 4
        write_end = write_addr + 4  # inclusive last = write_addr+3
        # overlaps if write_addr < addr+size and addr < write_end
        if write_addr < addr + size and addr < write_end:
            hits += 1
    return hits

# ── Test cases ────────────────────────────────────────────────────────────────

results = []  # list of {tool, status, expected, actual, note}
skips = []

def record(tool, status, expected, actual, note=""):
    results.append({"tool": tool, "status": status,
                    "expected": expected, "actual": actual, "note": note})

def check(tool, args, field, expected, note=""):
    data, err = call_tool(tool, args)
    if err:
        record(tool, "FAIL", expected, err, note)
        return
    if data is None:
        record(tool, "FAIL", expected, None, note)
        return
    if isinstance(data, dict):
        actual = data.get(field)
    else:
        actual = data
    passed = (actual == expected)
    record(tool, "PASS" if passed else "FAIL", expected, actual, note)

def skip(tool, reason):
    skips.append({"tool": tool, "reason": reason})

# ── 1. ttd_recorder_position_start ───────────────────────────────────────────
data, err = call_tool("ttd_recorder_position_start", {})
if err:
    record("ttd_recorder_position_start", "FAIL", {"major": 0, "minor": 0}, err)
else:
    ok = (data.get("major") == 0 and data.get("minor") == 0)
    record("ttd_recorder_position_start", "PASS" if ok else "FAIL",
           {"major": 0, "minor": 0}, {"major": data.get("major"), "minor": data.get("minor")},
           "start position must be (0, 0)")

# ── 2. ttd_recorder_valid_extension ──────────────────────────────────────────
for path, expected_ok in [("trace.run", True), ("trace.ttd", True), ("trace.exe", False)]:
    data, err = call_tool("ttd_recorder_valid_extension", {"path": path})
    if err:
        record("ttd_recorder_valid_extension", "FAIL", expected_ok, err, f"path={path}")
    else:
        actual = data.get("is_valid_extension")
        ref = ref_is_valid_extension(path)
        ok = (actual == ref == expected_ok)
        record("ttd_recorder_valid_extension", "PASS" if ok else "FAIL",
               expected_ok, actual, f"path={path}")

# ── 3. ttd_replayer_hex_dump ─────────────────────────────────────────────────
test_cases_hex = [("deadbeef", b"\xde\xad\xbe\xef"), ("00112233", b"\x00\x11\x22\x33")]
for hex_in, raw in test_cases_hex:
    expected_dump = ref_hex_dump(raw)
    data, err = call_tool("ttd_replayer_hex_dump", {"data_hex": hex_in})
    if err:
        record("ttd_replayer_hex_dump", "FAIL", expected_dump, err, f"input={hex_in}")
    else:
        actual = data.get("dump")
        ok = (actual == expected_dump)
        record("ttd_replayer_hex_dump", "PASS" if ok else "FAIL",
               expected_dump, actual, f"input={hex_in}")

# ── 4. ttd_replayer_format_tick ──────────────────────────────────────────────
for tick in [0, 1, 42, 999999999999999]:
    expected_fmt = ref_format_tick(tick)
    data, err = call_tool("ttd_replayer_format_tick", {"tick": tick})
    if err:
        record("ttd_replayer_format_tick", "FAIL", expected_fmt, err, f"tick={tick}")
    else:
        actual = data.get("formatted")
        ok = (actual == expected_fmt)
        record("ttd_replayer_format_tick", "PASS" if ok else "FAIL",
               expected_fmt, actual, f"tick={tick}")

# ── 5. ttd_replayer_parse_hex ────────────────────────────────────────────────
for s, expected_val in [("DEAD", 0xDEAD), ("0xBEEF", 0xBEEF), ("0", 0), ("FFFFFFFFFFFFFFFF", 0xFFFFFFFFFFFFFFFF)]:
    data, err = call_tool("ttd_replayer_parse_hex", {"s": s})
    if err:
        record("ttd_replayer_parse_hex", "FAIL", expected_val, err, f"s={s}")
    else:
        actual = data.get("value")
        ok_flag = data.get("ok")
        ref = ref_parse_hex(s)
        ok = (actual == ref == expected_val) and ok_flag
        record("ttd_replayer_parse_hex", "PASS" if ok else "FAIL",
               expected_val, actual, f"s={s}")

# ── 6. ttd_build_test_trace ──────────────────────────────────────────────────
for n in [0, 1, 5, 10]:
    # thread_ids() reads from events, not metadata; n=0 → no events → []
    expected_tids = [1] if n > 0 else []
    data, err = call_tool("ttd_build_test_trace", {"n": n})
    if err:
        record("ttd_build_test_trace", "FAIL", {"event_count": n, "thread_ids": expected_tids}, err, f"n={n}")
    else:
        ec = data.get("event_count")
        tids = sorted(data.get("thread_ids", []))
        ok = (ec == ref_build_test_trace_event_count(n) and tids == expected_tids)
        record("ttd_build_test_trace", "PASS" if ok else "FAIL",
               {"event_count": n, "thread_ids": expected_tids},
               {"event_count": ec, "thread_ids": tids}, f"n={n}")

# ── 7. ttd_build_multi_thread_trace ──────────────────────────────────────────
for n in [4, 6]:
    data, err = call_tool("ttd_build_multi_thread_trace", {"n": n})
    if err:
        record("ttd_build_multi_thread_trace", "FAIL", {"event_count": n, "thread_ids": [1, 2]}, err, f"n={n}")
    else:
        ec = data.get("event_count")
        tids = sorted(data.get("thread_ids", []))
        ok = (ec == ref_build_multi_thread_trace_event_count(n) and tids == [1, 2])
        record("ttd_build_multi_thread_trace", "PASS" if ok else "FAIL",
               {"event_count": n, "thread_ids": [1, 2]},
               {"event_count": ec, "thread_ids": tids}, f"n={n}")

# ── 8. ttd_replayer_build_syscall_summaries ───────────────────────────────────
for n in [4, 8]:
    data, err = call_tool("ttd_replayer_build_syscall_summaries", {"n": n})
    if err:
        record("ttd_replayer_build_syscall_summaries", "FAIL",
               {"syscall_count": n, "total_bytes_written": n * 8}, err, f"n={n}")
    else:
        sc = data.get("syscall_count")
        tb = data.get("total_bytes_written")
        exp_sc = ref_build_syscall_summaries_count(n)
        exp_tb = ref_build_syscall_summaries_total_bytes(n)
        ok = (sc == exp_sc and tb == exp_tb)
        record("ttd_replayer_build_syscall_summaries", "PASS" if ok else "FAIL",
               {"syscall_count": exp_sc, "total_bytes_written": exp_tb},
               {"syscall_count": sc, "total_bytes_written": tb}, f"n={n}")

# ── 9. ttd_replayer_scan_for_writes ──────────────────────────────────────────
for addr, size, n in [(0x1000, 32, 8), (0x2000, 16, 4)]:
    exp_hits = ref_scan_for_writes_hit_count(addr, size, n)
    data, err = call_tool("ttd_replayer_scan_for_writes", {"addr": addr, "size": size, "n": n})
    if err:
        record("ttd_replayer_scan_for_writes", "FAIL", {"hit_count": exp_hits}, err,
               f"addr={hex(addr)} size={size} n={n}")
    else:
        actual_hits = data.get("hit_count")
        ok = (actual_hits == exp_hits)
        record("ttd_replayer_scan_for_writes", "PASS" if ok else "FAIL",
               {"hit_count": exp_hits}, {"hit_count": actual_hits},
               f"addr={hex(addr)} size={size} n={n}")

# ── 10. ttd_position_min ─────────────────────────────────────────────────────
for a_seq, a_step, b_seq, b_step, exp in [
    (5, 10, 6, 0, (5, 10)),
    (3, 100, 3, 50, (3, 50)),
    (0, 0, 0, 0, (0, 0)),
]:
    data, err = call_tool("ttd_position_min", {"a_seq": a_seq, "a_step": a_step, "b_seq": b_seq, "b_step": b_step})
    ref = ref_position_min(a_seq, a_step, b_seq, b_step)
    if err:
        record("ttd_position_min", "FAIL", exp, err, f"a=({a_seq},{a_step}) b=({b_seq},{b_step})")
    else:
        actual = (data.get("sequence"), data.get("step"))
        ok = (actual == ref == exp)
        record("ttd_position_min", "PASS" if ok else "FAIL", exp, actual,
               f"a=({a_seq},{a_step}) b=({b_seq},{b_step})")

# ── 11. ttd_position_max ─────────────────────────────────────────────────────
for a_seq, a_step, b_seq, b_step, exp in [
    (5, 10, 6, 0, (6, 0)),
    (3, 100, 3, 50, (3, 100)),
]:
    data, err = call_tool("ttd_position_max", {"a_seq": a_seq, "a_step": a_step, "b_seq": b_seq, "b_step": b_step})
    ref = ref_position_max(a_seq, a_step, b_seq, b_step)
    if err:
        record("ttd_position_max", "FAIL", exp, err, f"a=({a_seq},{a_step}) b=({b_seq},{b_step})")
    else:
        actual = (data.get("sequence"), data.get("step"))
        ok = (actual == ref == exp)
        record("ttd_position_max", "PASS" if ok else "FAIL", exp, actual,
               f"a=({a_seq},{a_step}) b=({b_seq},{b_step})")

# ── 12. ttd_trace_position_as_u128 ───────────────────────────────────────────
for seq, step in [(1, 2), (0, 0), (0xDEAD, 0xBEEF)]:
    exp_val = ref_trace_position_as_u128(seq, step)
    data, err = call_tool("ttd_trace_position_as_u128", {"sequence": seq, "step": step})
    if err:
        record("ttd_trace_position_as_u128", "FAIL", str(exp_val), err, f"seq={seq} step={step}")
    else:
        # MCP returns value as string (to avoid JSON u128 precision loss)
        actual_str = data.get("value")
        try:
            actual_int = int(actual_str)
        except (TypeError, ValueError):
            actual_int = None
        ok = (actual_int == exp_val)
        record("ttd_trace_position_as_u128", "PASS" if ok else "FAIL",
               str(exp_val), actual_str, f"seq={seq} step={step}")

# ── 13. ttd_trace_position_from_u128 ─────────────────────────────────────────
for val, exp_seq, exp_step in [(str((1 << 64) | 2), 1, 2), ("0", 0, 0)]:
    exp = (exp_seq, exp_step)
    data, err = call_tool("ttd_trace_position_from_u128", {"value": val})
    if err:
        record("ttd_trace_position_from_u128", "FAIL", exp, err, f"val={val}")
    else:
        actual = (data.get("sequence"), data.get("step"))
        ref = ref_trace_position_from_u128(int(val))
        ok = (actual == ref == exp)
        record("ttd_trace_position_from_u128", "PASS" if ok else "FAIL",
               exp, actual, f"val={val}")

# ── 14. ttd_trace_position_compare ───────────────────────────────────────────
for a_seq, a_step, b_seq, b_step, exp_before, exp_after, exp_equal in [
    (5, 10, 5, 20, True, False, False),
    (6, 5, 5, 100, False, True, False),
    (5, 10, 5, 10, False, False, True),
]:
    data, err = call_tool("ttd_trace_position_compare", {
        "a_seq": a_seq, "a_step": a_step, "b_seq": b_seq, "b_step": b_step})
    exp = {"is_before": exp_before, "is_after": exp_after, "equal": exp_equal}
    if err:
        record("ttd_trace_position_compare", "FAIL", exp, err)
    else:
        actual = {"is_before": data.get("is_before"), "is_after": data.get("is_after"), "equal": data.get("equal")}
        ok = (actual == exp)
        record("ttd_trace_position_compare", "PASS" if ok else "FAIL", exp, actual,
               f"a=({a_seq},{a_step}) b=({b_seq},{b_step})")

# ── 15. ttd_memory_snapshot_contains ─────────────────────────────────────────
for base, length, addr, exp_contains in [
    (0x1000, 0x100, 0x1050, True),
    (0x1000, 0x100, 0x1100, False),
    (0x1000, 0x100, 0x0FFF, False),
]:
    exp_end = ref_memory_snapshot_end_address(base, length)
    data, err = call_tool("ttd_memory_snapshot_contains", {"base": base, "len": length, "addr": addr})
    if err:
        record("ttd_memory_snapshot_contains", "FAIL",
               {"contains": exp_contains, "end_address": exp_end}, err,
               f"base={hex(base)} len={length} addr={hex(addr)}")
    else:
        actual_contains = data.get("contains")
        actual_end = data.get("end_address")
        exp_c = ref_memory_snapshot_contains(base, length, addr)
        ok = (actual_contains == exp_c == exp_contains) and (actual_end == exp_end)
        record("ttd_memory_snapshot_contains", "PASS" if ok else "FAIL",
               {"contains": exp_contains, "end_address": exp_end},
               {"contains": actual_contains, "end_address": actual_end},
               f"base={hex(base)} len={length} addr={hex(addr)}")

# ── 16. ttd_memory_snapshot_read_u32_le ──────────────────────────────────────
test_data = bytes([0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08])
data_hex = test_data.hex()
for base, addr, exp_val in [
    (0x1000, 0x1000, 0x04030201),  # read at base → first 4 bytes
    (0x1000, 0x1002, 0x06050403),  # offset +2
]:
    exp = ref_memory_snapshot_read_u32_le(base, test_data, addr)
    data_r, err = call_tool("ttd_memory_snapshot_read_u32_le",
                            {"base": base, "data_hex": data_hex, "addr": addr})
    if err:
        record("ttd_memory_snapshot_read_u32_le", "FAIL", exp, err,
               f"base={hex(base)} addr={hex(addr)}")
    else:
        actual = data_r.get("value")
        ok = (actual == exp == exp_val)
        record("ttd_memory_snapshot_read_u32_le", "PASS" if ok else "FAIL",
               exp, actual, f"base={hex(base)} addr={hex(addr)}")

# ── 17. ttd_trace_event_count ────────────────────────────────────────────────
for n in [0, 3, 7]:
    data, err = call_tool("ttd_trace_event_count", {"n": n})
    if err:
        record("ttd_trace_event_count", "FAIL", n, err, f"n={n}")
    else:
        actual = data.get("count")
        ok = (actual == n)
        record("ttd_trace_event_count", "PASS" if ok else "FAIL", n, actual, f"n={n}")

# ── Skip: tools that require real TTD trace files ────────────────────────────
skip("ttd_recorder_validate_trace", "Requires a real .run TTD trace file on disk — no deterministic fixture available")
skip("ttd_recorder_validation_is_perfect", "Requires a real .run TTD trace file on disk")
skip("ttd_replayer_find_root_cause", "Nondeterministic: depends on live trace state")
skip("ttd_replayer_step_forward", "Stateful: requires open replay session")
skip("ttd_replayer_goto", "Stateful: requires open replay session")
skip("ttd_recorder_check_platform_support", "Platform-dependent: true only on Windows with TTD kernel module installed")

# ── Teardown ─────────────────────────────────────────────────────────────────
try:
    p.stdin.close()
    p.terminate()
except Exception:
    pass

# ── Summarize ────────────────────────────────────────────────────────────────
passed = [r for r in results if r["status"] == "PASS"]
failed = [r for r in results if r["status"] == "FAIL"]
mismatches = [{"tool": r["tool"], "expected": r["expected"], "actual": r["actual"], "note": r["note"]}
              for r in failed]

tools_tested = len(set(r["tool"] for r in results))

output = {
    "category": "ttd",
    "tools_hardened": tools_tested,
    "tools_passed": len(set(r["tool"] for r in passed)),
    "tools_failed": len(set(r["tool"] for r in failed)),
    "tools_skipped": len(skips),
    "total_checks": len(results),
    "checks_passed": len(passed),
    "checks_failed": len(failed),
    "mismatches": mismatches,
    "skips": skips,
}

with open(OUT, "w") as f:
    json.dump(output, f, indent=2)

with open(SKIP_OUT, "w") as f:
    json.dump(skips, f, indent=2)

print(f"Rigorous TTD validation complete.")
print(f"  Tools hardened : {tools_tested}")
print(f"  Checks passed  : {len(passed)}/{len(results)}")
print(f"  Checks failed  : {len(failed)}")
print(f"  Tools skipped  : {len(skips)}")
if mismatches:
    print(f"\nMismatches:")
    for m in mismatches:
        print(f"  {m['tool']}: expected={m['expected']!r} actual={m['actual']!r} ({m['note']})")
