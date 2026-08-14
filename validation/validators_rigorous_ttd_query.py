"""
Rigorous validator for module 'ttd_query'.

Starts a rustre-mcp.exe --transport=stdio session and calls 12 tools,
comparing each MCP response against an independently computed Python truth
derived from the known synthetic test trace (build_query_test_trace).

Saves report to validation/rigorous_ttd_query.json.
"""

import json
import subprocess
import sys
import time
import pathlib

MCP_EXE = r"C:\Users\Fra\Desktop\RustRE\target\release\rustre-mcp.exe"
REPORT_PATH = pathlib.Path(r"C:\Users\Fra\Desktop\RustRE\validation\rigorous_ttd_query.json")

# ── Synthetic trace ground truth ───────────────────────────────────────────────
# Derived directly from build_query_test_trace() in
# crates/rustre-ttd-query/src/lib.rs.
#
# Events (index → (thread_id, kind)):
#   0  thread=1  MemRead{addr:0x1000, len:4}
#   1  thread=2  MemWrite{addr:0x2000, data:[0xde,0xad]}
#   2  thread=1  Call{from:0x3000, to:0x4000}
#   3  thread=2  Return{from:0x4000, to:0x3004}
#   4  thread=1  SyscallEnter{nr:1}
#   5  thread=2  SyscallExit{nr:1, ret:0}
#   6  thread=1  Exception{code:0xc0000005}
#   7  thread=2  ThreadCreate{tid:2}
#   8  thread=1  ThreadExit{tid:2}
#   9  thread=2  Breakpoint{addr:0x5000}
#  10  thread=1  MemWrite{addr:0x2000, data:[0xff]}
#  11  thread=2  Call{from:0x6000, to:0x4000}
#  12  thread=1  SyscallEnter{nr:2}
#  13  thread=2  SyscallExit{nr:2, ret:1}
#
# thread_id = 1 if i%2==0 else 2
TOTAL_EVENTS = 14

EXPECTED_HIST_BY_KIND = {
    "MemRead": 1,
    "MemWrite": 2,
    "Call": 2,
    "Return": 1,
    "SyscallEnter": 2,
    "SyscallExit": 2,
    "Exception": 1,
    "ThreadCreate": 1,
    "ThreadExit": 1,
    "Breakpoint": 1,
}

# thread 1: indices 0,2,4,6,8,10,12  → 7 events
# thread 2: indices 1,3,5,7,9,11,13  → 7 events
EXPECTED_THREAD_COUNTS = {1: 7, 2: 7}

# Only calls are at i=2 (to=0x4000) and i=11 (to=0x4000)  → 0x4000: 2
EXPECTED_CALL_FREQ = [{"addr": 0x4000, "count": 2}]

# MemRead at 0x1000 (1 access), MemWrite at 0x2000 (2 accesses)
# most_accessed top-2: [(0x2000, 2), (0x1000, 1)]
EXPECTED_MOST_ACCESSED_TOP2 = [
    {"addr": 0x2000, "count": 2},
    {"addr": 0x1000, "count": 1},
]

# Syscall summary via summarize_syscalls:
#   nr=1: call_count=1 (SyscallEnter), error_count=0 (ret=0, not < 0)
#   nr=2: call_count=1 (SyscallEnter), error_count=0 (ret=1, not < 0)
EXPECTED_SYSCALL_NRS = {1: {"calls": 1, "errors": 0}, 2: {"calls": 1, "errors": 0}}

# No recursive calls in the test trace (0x4000 called twice but not while already on stack)
EXPECTED_RECURSIVE_CHAINS = []

# TimeRange [0,5].contains(3) → True; contains(6) → False
EXPECTED_TIME_RANGE_IN = True
EXPECTED_TIME_RANGE_OUT = False

# ttd_query_exec_all_events → matched=14
EXPECTED_ALL_EVENTS_MATCHED = 14

# ttd_query_count_thread(tid=1) → 7
EXPECTED_COUNT_THREAD_1 = 7

# ttd_query_histogram_over_time(bucket_size=5):
# seq 0-4 → bucket 0 → sequence=0: count 5
# seq 5-9 → bucket 1 → sequence=5: count 5
# seq 10-13 → bucket 2 → sequence=10: count 4
EXPECTED_HIST_OVER_TIME_BUCKET5 = [
    {"sequence": 0, "count": 5},
    {"sequence": 5, "count": 5},
    {"sequence": 10, "count": 4},
]

# filter_by_address_range(0x1000, 0x3000) should hit MemRead@0x1000 and MemWrite@0x2000 (×2)
# → count=3
EXPECTED_FILTER_BY_ADDR_RANGE_COUNT = 3

# ── MCP session helpers ────────────────────────────────────────────────────────

def start_mcp():
    proc = subprocess.Popen(
        [MCP_EXE, "--transport=stdio"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    # Handshake: initialize
    _send(proc, {"jsonrpc": "2.0", "id": 0, "method": "initialize",
                  "params": {"protocolVersion": "2024-11-05",
                             "clientInfo": {"name": "rigorous-validator", "version": "1"},
                             "capabilities": {}}})
    _recv(proc)
    _send(proc, {"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}})
    return proc


def _send(proc, obj):
    line = json.dumps(obj) + "\n"
    proc.stdin.write(line)
    proc.stdin.flush()


def _recv(proc):
    while True:
        line = proc.stdout.readline()
        if not line:
            raise RuntimeError("MCP process closed unexpectedly")
        line = line.strip()
        if line:
            return json.loads(line)


_id_counter = 1

def call_tool(proc, name, args=None):
    global _id_counter
    req_id = _id_counter
    _id_counter += 1
    _send(proc, {
        "jsonrpc": "2.0",
        "id": req_id,
        "method": "tools/call",
        "params": {"name": name, "arguments": args or {}},
    })
    resp = _recv(proc)
    result = resp.get("result", {})
    content = result.get("content", [])
    if content and isinstance(content, list):
        text = content[0].get("text", "")
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            return {"raw": text}
    return result


# ── Check helpers ──────────────────────────────────────────────────────────────

def check(name, actual, expected, extractor, compare_fn=None):
    """Return a result dict for a single check."""
    try:
        got = extractor(actual)
        if compare_fn:
            ok = compare_fn(got, expected)
        else:
            ok = (got == expected)
        return {"tool": name, "ok": ok, "got": got, "expected": expected}
    except Exception as exc:
        return {"tool": name, "ok": False, "got": None, "expected": expected,
                "error": str(exc)}


# ── Main ───────────────────────────────────────────────────────────────────────

def main():
    proc = start_mcp()
    checks = []
    mismatches = []

    # 1. ttd_query_trace_event_count → event_count == 14
    r = call_tool(proc, "ttd_query_trace_event_count")
    c = check("ttd_query_trace_event_count", r, TOTAL_EVENTS,
              lambda x: x.get("event_count"))
    checks.append(c)

    # 2. ttd_query_histogram_by_kind → histogram == EXPECTED_HIST_BY_KIND
    r = call_tool(proc, "ttd_query_histogram_by_kind")
    c = check("ttd_query_histogram_by_kind", r, EXPECTED_HIST_BY_KIND,
              lambda x: x.get("histogram"))
    checks.append(c)

    # 3. ttd_query_count_thread(tid=1) → count == 7
    r = call_tool(proc, "ttd_query_count_thread", {"tid": 1})
    c = check("ttd_query_count_thread_tid1", r, EXPECTED_COUNT_THREAD_1,
              lambda x: x.get("count"))
    checks.append(c)

    # 4. ttd_query_count_thread(tid=2) → count == 7
    r = call_tool(proc, "ttd_query_count_thread", {"tid": 2})
    c = check("ttd_query_count_thread_tid2", r, 7,
              lambda x: x.get("count"))
    checks.append(c)

    # 5. ttd_query_first_occurrence_thread(tid=1) → found == True
    r = call_tool(proc, "ttd_query_first_occurrence_thread", {"tid": 1})
    c = check("ttd_query_first_occurrence_thread_tid1", r, True,
              lambda x: x.get("found"))
    checks.append(c)

    # 6. ttd_query_first_occurrence_thread(tid=99) → found == False (nonexistent thread)
    r = call_tool(proc, "ttd_query_first_occurrence_thread", {"tid": 99})
    c = check("ttd_query_first_occurrence_thread_tid99", r, False,
              lambda x: x.get("found"))
    checks.append(c)

    # 7. ttd_query_call_frequency → single entry for 0x4000 with count 2
    r = call_tool(proc, "ttd_query_call_frequency")
    def check_call_freq(items, expected):
        if not isinstance(items, list):
            return False
        if len(items) != len(expected):
            return False
        for exp in expected:
            if not any(it.get("addr") == exp["addr"] and it.get("count") == exp["count"]
                       for it in items):
                return False
        return True
    c = check("ttd_query_call_frequency", r, EXPECTED_CALL_FREQ,
              lambda x: x.get("items"), compare_fn=check_call_freq)
    checks.append(c)

    # 8. ttd_query_most_called(top_n=1) → [{addr:0x4000, count:2}]
    r = call_tool(proc, "ttd_query_most_called", {"top_n": 1})
    c = check("ttd_query_most_called_top1", r, EXPECTED_CALL_FREQ,
              lambda x: x.get("items"), compare_fn=check_call_freq)
    checks.append(c)

    # 9. ttd_query_most_accessed_addresses(top_n=2) → 0x2000:2, 0x1000:1
    r = call_tool(proc, "ttd_query_most_accessed_addresses", {"top_n": 2})
    def check_most_accessed(items, expected):
        if not isinstance(items, list):
            return False
        if len(items) != len(expected):
            return False
        for exp in expected:
            if not any(it.get("addr") == exp["addr"] and it.get("count") == exp["count"]
                       for it in items):
                return False
        return True
    c = check("ttd_query_most_accessed_addresses_top2", r, EXPECTED_MOST_ACCESSED_TOP2,
              lambda x: x.get("items"), compare_fn=check_most_accessed)
    checks.append(c)

    # 10. ttd_query_recursive_calls → no chains in test trace
    r = call_tool(proc, "ttd_query_recursive_calls")
    c = check("ttd_query_recursive_calls", r, 0,
              lambda x: len(x.get("chains", [])))
    checks.append(c)

    # 11. ttd_query_time_range_contains inside [0,5] → True
    r = call_tool(proc, "ttd_query_time_range_contains",
                  {"start_seq": 0, "end_seq": 5, "pos_seq": 3})
    c = check("ttd_query_time_range_contains_inside", r, EXPECTED_TIME_RANGE_IN,
              lambda x: x.get("contains"))
    checks.append(c)

    # 12. ttd_query_time_range_contains outside [0,5] → False
    r = call_tool(proc, "ttd_query_time_range_contains",
                  {"start_seq": 0, "end_seq": 5, "pos_seq": 6})
    c = check("ttd_query_time_range_contains_outside", r, EXPECTED_TIME_RANGE_OUT,
              lambda x: x.get("contains"))
    checks.append(c)

    # 13. ttd_query_exec_all_events → matched == 14
    r = call_tool(proc, "ttd_query_exec_all_events")
    c = check("ttd_query_exec_all_events", r, EXPECTED_ALL_EVENTS_MATCHED,
              lambda x: x.get("matched"))
    checks.append(c)

    # 14. ttd_query_histogram_over_time(bucket_size=5)
    r = call_tool(proc, "ttd_query_histogram_over_time", {"bucket_size": 5})
    def check_hist_time(buckets, expected):
        if not isinstance(buckets, list):
            return False
        # Sort by sequence for comparison
        got_sorted = sorted(buckets, key=lambda b: b.get("sequence", 0))
        exp_sorted = sorted(expected, key=lambda b: b["sequence"])
        return got_sorted == exp_sorted
    c = check("ttd_query_histogram_over_time_bucket5", r, EXPECTED_HIST_OVER_TIME_BUCKET5,
              lambda x: x.get("buckets"), compare_fn=check_hist_time)
    checks.append(c)

    # 15. ttd_query_filter_by_address_range(0x1000, 0x3000) → count 3
    r = call_tool(proc, "ttd_query_filter_by_address_range",
                  {"start": 0x1000, "end": 0x3000})
    c = check("ttd_query_filter_by_address_range", r, EXPECTED_FILTER_BY_ADDR_RANGE_COUNT,
              lambda x: x.get("count"))
    checks.append(c)

    # 16. ttd_query_syscall_summary → nr 1 and 2 with calls=1, errors=0 each
    r = call_tool(proc, "ttd_query_syscall_summary")
    def check_syscall_summary(items, expected_nrs):
        if not isinstance(items, list):
            return False
        found = {}
        for it in items:
            nr = it.get("nr")
            if nr in expected_nrs:
                found[nr] = {"calls": it.get("calls"), "errors": it.get("errors")}
        return found == expected_nrs
    c = check("ttd_query_syscall_summary", r, EXPECTED_SYSCALL_NRS,
              lambda x: x.get("syscalls"), compare_fn=check_syscall_summary)
    checks.append(c)

    proc.stdin.close()
    proc.wait(timeout=5)

    # Tally
    passed = sum(1 for c in checks if c["ok"])
    failed = sum(1 for c in checks if not c["ok"])
    for c in checks:
        if not c["ok"]:
            mismatches.append({
                "tool": c["tool"],
                "expected": c["expected"],
                "got": c.get("got"),
                "error": c.get("error"),
            })

    report = {
        "module": "ttd_query",
        "tools_hardened": len(checks),
        "checks_passed": passed,
        "checks_failed": failed,
        "mismatches": mismatches,
    }

    REPORT_PATH.write_text(json.dumps(report, indent=2, default=str), encoding="utf-8")
    print(json.dumps(report, indent=2, default=str))
    return report


if __name__ == "__main__":
    main()
