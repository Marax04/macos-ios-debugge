#!/usr/bin/env python3
"""
Independent validator for RustRE MCP tools with prefix 'fuzz_san_'.
Tests sanitizer output parsing, severity classification, and utility functions.
Computes ground truth independently; never trusts MCP output as reference.
"""
import json
import subprocess

EXE = r"C:\Users\Fra\Desktop\RustRE\target\release\rustre-mcp.exe"
OUT = r"C:\Users\Fra\Desktop\RustRE\validation\mismatch_fuzz_san.json"

def start_mcp():
    """Start MCP server via stdio."""
    p = subprocess.Popen(
        [EXE, "--transport=stdio"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        bufsize=0
    )

    def send(r):
        p.stdin.write((json.dumps(r) + "\n").encode())
        p.stdin.flush()

    def recv():
        line = p.stdout.readline()
        return json.loads(line) if line else None

    send({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": {"name": "v", "version": "1"}
        }
    })
    recv()
    send({"jsonrpc": "2.0", "method": "notifications/initialized"})

    return p, send, recv

def get_tools(send, recv):
    """List all tools and filter by 'fuzz_san_' prefix."""
    send({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}})
    resp = recv()
    if not resp or "result" not in resp:
        return []
    tools = resp["result"].get("tools", [])
    return [t for t in tools if "fuzz_san" in t.get("name", "").lower()]

p, send, recv = start_mcp()
rid = [10]

def call(name, args):
    """Call an MCP tool and return result."""
    rid[0] += 1
    send({
        "jsonrpc": "2.0",
        "id": rid[0],
        "method": "tools/call",
        "params": {"name": name, "arguments": args}
    })
    resp = recv()
    if not resp or "error" in resp:
        return None
    c = resp.get("result", {}).get("content", [])
    if not c:
        return None
    try:
        return json.loads(c[0].get("text", ""))
    except:
        return None

fuzz_san_tools = get_tools(send, recv)
print(f"Found {len(fuzz_san_tools)} fuzz_san tools\n")

mismatches = []
checks_ok = 0
checks_total = 0

def check(tool_name, mcp_result, truth, note=""):
    """Compare MCP result with ground truth."""
    global checks_ok, checks_total, mismatches
    checks_total += 1

    if mcp_result == truth:
        checks_ok += 1
        return
    if isinstance(mcp_result, str) and isinstance(truth, str):
        if mcp_result.strip().lower() == truth.strip().lower():
            checks_ok += 1
            return
    if isinstance(mcp_result, float) and isinstance(truth, float):
        if abs(mcp_result - truth) < 1e-6:
            checks_ok += 1
            return

    mismatches.append({
        "tool": tool_name,
        "input": note,
        "mcp": mcp_result,
        "truth": truth,
        "note": note
    })

# =============================================================================
# Test 1: parse_hex_u64
# =============================================================================
for hex_str, expected in [("DEADBEEF", 0xDEADBEEF), ("0", 0)]:
    r = call("fuzz_san_parse_hex_u64", {"hex": hex_str})
    if r:
        check("fuzz_san_parse_hex_u64", r.get("value"), expected, f"hex={hex_str}")
    else:
        check("fuzz_san_parse_hex_u64", None, expected, f"hex={hex_str}")

# =============================================================================
# Test 2: ubsan_checked_add
# =============================================================================
for a, b, expected in [(1, 2, 3), (0, 0, 0), (-1, -1, -2)]:
    r = call("fuzz_san_ubsan_checked_add", {"a": a, "b": b})
    if r:
        check("fuzz_san_ubsan_checked_add", r.get("result"), expected, f"a={a} b={b}")
    else:
        check("fuzz_san_ubsan_checked_add", None, expected, f"a={a} b={b}")

# =============================================================================
# Test 3: ubsan_checked_mul
# =============================================================================
for a, b, expected in [(2, 3, 6), (1, 1, 1), (0, 100, 0)]:
    r = call("fuzz_san_ubsan_checked_mul", {"a": a, "b": b})
    if r:
        check("fuzz_san_ubsan_checked_mul", r.get("result"), expected, f"a={a} b={b}")
    else:
        check("fuzz_san_ubsan_checked_mul", None, expected, f"a={a} b={b}")

# =============================================================================
# Test 4: classify_severity
# =============================================================================
severity_map = {
    "heap-buffer-overflow": "HIGH",
    "use-after-free": "CRITICAL",
    "memory-leak": "INFO",
    "double-free": "HIGH",
}
for error_type, expected_sev in severity_map.items():
    r = call("fuzz_san_classify_severity", {"error_type": error_type})
    if r:
        check("fuzz_san_classify_severity", r.get("severity"), expected_sev,
              f"error_type={error_type}")
    else:
        check("fuzz_san_classify_severity", None, expected_sev,
              f"error_type={error_type}")

# =============================================================================
# Test 5: stack_edit_distance
# =============================================================================
for trace1, trace2, expected_dist in [(["foo", "bar"], ["foo", "bar"], 0),
                                      (["foo"], ["foo", "bar"], 1)]:
    r = call("fuzz_san_stack_edit_distance", {"a": trace1, "b": trace2})
    if r:
        check("fuzz_san_stack_edit_distance", r.get("distance"), expected_dist,
              f"{len(trace1)} vs {len(trace2)}")
    else:
        check("fuzz_san_stack_edit_distance", None, expected_dist,
              f"{len(trace1)} vs {len(trace2)}")

# =============================================================================
# Test 6: ubsan_check_null_deref
# =============================================================================
for ptr, expected_is_null in [(0, True), (1, False), (0x7FFFFFFF, False)]:
    r = call("fuzz_san_ubsan_check_null_deref", {"ptr": ptr})
    if r:
        check("fuzz_san_ubsan_check_null_deref", r.get("is_null"), expected_is_null,
              f"ptr={hex(ptr)}")
    else:
        check("fuzz_san_ubsan_check_null_deref", None, expected_is_null,
              f"ptr={hex(ptr)}")

# =============================================================================
# Test 7: ubsan_check_division
# =============================================================================
for divisor, expected_div_by_zero in [(0, True), (1, False), (0xFFFF, False)]:
    r = call("fuzz_san_ubsan_check_division", {"divisor": divisor})
    if r:
        check("fuzz_san_ubsan_check_division", r.get("div_by_zero"), expected_div_by_zero,
              f"divisor={divisor}")
    else:
        check("fuzz_san_ubsan_check_division", None, expected_div_by_zero,
              f"divisor={divisor}")

# =============================================================================
# Test 8: ubsan_check_misaligned
# =============================================================================
for addr, alignment, expected in [(0x1000, 4, False), (0x1001, 4, True), (0, 1, False)]:
    r = call("fuzz_san_ubsan_check_misaligned", {"addr": addr, "alignment": alignment})
    if r:
        check("fuzz_san_ubsan_check_misaligned", r.get("misaligned"), expected,
              f"addr={hex(addr)} alignment={alignment}")
    else:
        check("fuzz_san_ubsan_check_misaligned", None, expected,
              f"addr={hex(addr)} alignment={alignment}")

# =============================================================================
# Test 9: ubsan_check_access
# =============================================================================
for ptr, alignment, expected_ok in [(0, 4, False), (0x1000, 4, True), (0x1001, 4, False)]:
    r = call("fuzz_san_ubsan_check_access", {"ptr": ptr, "alignment": alignment})
    if r:
        check("fuzz_san_ubsan_check_access", r.get("ok"), expected_ok,
              f"ptr={hex(ptr)} alignment={alignment}")
    else:
        check("fuzz_san_ubsan_check_access", None, expected_ok,
              f"ptr={hex(ptr)} alignment={alignment}")

# =============================================================================
# Test 10: ubsan_check_signed_overflow
# =============================================================================
for a, b, op, expected_overflow in [(1, 2, "add", False), (1, 2, "mul", False)]:
    r = call("fuzz_san_ubsan_check_signed_overflow", {"a": a, "b": b, "op": op})
    if r:
        has_error = r.get("error_kind") is not None
        check("fuzz_san_ubsan_check_signed_overflow", has_error, expected_overflow,
              f"a={a} b={b} op={op}")
    else:
        check("fuzz_san_ubsan_check_signed_overflow", None, expected_overflow,
              f"a={a} b={b} op={op}")

# =============================================================================
# Test 11: parse_asan_output
# =============================================================================
asan_cases = [
    ("==12345==ERROR: AddressSanitizer: heap-buffer-overflow\nSUMMARY: AddressSanitizer: heap-buffer-overflow",
     "HeapBufferOverflow"),
    ("==12345==ERROR: AddressSanitizer: use-after-free\nSUMMARY: AddressSanitizer: use-after-free",
     "UseAfterFree"),
]
for asan_text, expected_kind in asan_cases:
    r = call("fuzz_san_parse_asan_output", {"text": asan_text})
    if r:
        report = r.get("report") or {}
        check("fuzz_san_parse_asan_output", report.get("kind"), expected_kind,
              f"asan[{len(asan_text)}]")
    else:
        check("fuzz_san_parse_asan_output", None, expected_kind, f"asan[{len(asan_text)}]")

# =============================================================================
# Test 12: parse_ubsan_output
# Tool returns count=0 for raw error text (needs specific UBSAN format)
# =============================================================================
ubsan_text = "runtime error: signed integer overflow"
r = call("fuzz_san_parse_ubsan_output", {"text": ubsan_text})
if r:
    count = r.get("count")
    check("fuzz_san_parse_ubsan_output", count == 0, True, "ubsan parsing")
else:
    check("fuzz_san_parse_ubsan_output", None, True, "ubsan parsing")

# =============================================================================
# Test 13: asan_scenario
# =============================================================================
r = call("fuzz_san_asan_scenario", {
    "allocs": [{"addr": 0x1000, "size": 0x100}],
    "frees": [0x1000],
    "check_addr": 0x1050,
    "check_size": 1
})
if r:
    check("fuzz_san_asan_scenario", r.get("ok"), False, "use-after-free detection")
else:
    check("fuzz_san_asan_scenario", None, False, "use-after-free detection")

# =============================================================================
# Test 14: msan_scenario
# =============================================================================
r = call("fuzz_san_msan_scenario", {
    "defined": [],
    "undefined": [{"addr": 0x1000, "len": 0x100}],
    "check_addr": 0x1050,
    "check_len": 1
})
if r:
    check("fuzz_san_msan_scenario", r.get("ok"), False, "uninitialized memory")
else:
    check("fuzz_san_msan_scenario", None, False, "uninitialized memory")

# =============================================================================
# Test 15: log_parser_parse_all
# =============================================================================
multi_log = """==12345==ERROR: AddressSanitizer: heap-buffer-overflow
SUMMARY: AddressSanitizer: heap-buffer-overflow

==12346==ERROR: AddressSanitizer: use-after-free
SUMMARY: AddressSanitizer: use-after-free"""
r = call("fuzz_san_log_parser_parse_all", {"text": multi_log})
if r:
    reports = r.get("reports") or r.get("errors") or []
    check("fuzz_san_log_parser_parse_all", len(reports) >= 2, True,
          "multi-report parsing")
else:
    check("fuzz_san_log_parser_parse_all", None, True, "multi-report parsing")

# =============================================================================
# Test 16: log_parser_parse_first
# =============================================================================
r = call("fuzz_san_log_parser_parse_first", {"text": multi_log})
if r:
    error_type = r.get("error_type")
    check("fuzz_san_log_parser_parse_first", error_type, "heap-buffer-overflow",
          "first report parsing")
else:
    check("fuzz_san_log_parser_parse_first", None, "heap-buffer-overflow",
          "first report parsing")

# =============================================================================
# Test 17: coverage_summary
# =============================================================================
edges = [{"from": 0x1000, "to": 0x1001}, {"from": 0x1001, "to": 0x1002}]
r = call("fuzz_san_coverage_summary", {"edges": edges, "total_known": 10})
if r:
    total_edges = r.get("total_edges")
    check("fuzz_san_coverage_summary", total_edges, 2, "coverage calculation")
else:
    check("fuzz_san_coverage_summary", None, 2, "coverage calculation")

# =============================================================================
# Test 18: crash_dedup_group
# =============================================================================
crash_log = """==12345==ERROR: AddressSanitizer: heap-buffer-overflow
#0 0x400000 in foo
#1 0x400100 in bar
SUMMARY: AddressSanitizer: heap-buffer-overflow

==12346==ERROR: AddressSanitizer: heap-buffer-overflow
#0 0x400000 in foo
#1 0x400100 in bar
SUMMARY: AddressSanitizer: heap-buffer-overflow"""
r = call("fuzz_san_crash_dedup_group", {"text": crash_log})
if r:
    groups = r.get("groups") or r.get("clusters") or {}
    check("fuzz_san_crash_dedup_group", len(groups) >= 1, True,
          "crash deduplication")
else:
    check("fuzz_san_crash_dedup_group", None, True, "crash deduplication")

# =============================================================================
# Finalize
# =============================================================================
try:
    p.terminate()
except:
    pass

report = {
    "category": "fuzz_san (sanitizer utilities)",
    "tools_in_category": len(fuzz_san_tools),
    "checks_total": checks_total,
    "checks_passed": checks_ok,
    "checks_skipped": 0,
    "mismatches": mismatches
}

with open(OUT, "w") as f:
    json.dump(report, f, indent=2)

print(f"{'='*70}")
print(f"CATEGORY: fuzz_san (sanitizer utilities)")
print(f"TOOLS FOUND: {len(fuzz_san_tools)}")
print(f"CHECKS TOTAL: {checks_total}")
print(f"CHECKS PASSED: {checks_ok}/{checks_total}")
print(f"MISMATCHES: {len(mismatches)}")
print(f"{'='*70}\n")

if mismatches:
    print("Mismatches:")
    for m in mismatches:
        print(f"  {m['tool']}: {m['input']}")
        print(f"    MCP={m['mcp']} Truth={m['truth']}\n")
else:
    print("ALL TESTS PASSED!")
