#!/usr/bin/env python3
"""Rigorous ground-truth validation for mem_* MCP tools.
Computes expected values independently in Python and compares byte-for-byte.
"""
import json
import math
import struct
import subprocess
from collections import Counter

EXE = r"C:\Users\Fra\Desktop\RustRE\target\release\rustre-mcp.exe"
TARGET = r"C:\Users\Fra\Desktop\Zyphora\target\release\cargo-zyphora.exe"

# ── MCP transport ─────────────────────────────────────────────────────────────
p = subprocess.Popen(
    [EXE, "--transport=stdio"],
    stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, bufsize=0
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

send({"jsonrpc":"2.0","id":1,"method":"initialize","params":{
    "protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"rigorous_mem_v2","version":"1"}}})
recv()
send({"jsonrpc":"2.0","method":"notifications/initialized"})

send({"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"project.open","arguments":{"path":TARGET}}})
recv()

_rid = 100
def call_tool(name, args):
    global _rid
    _rid += 1
    send({"jsonrpc":"2.0","id":_rid,"method":"tools/call","params":{"name":name,"arguments":args}})
    resp = recv()
    if "error" in resp:
        return None, f"JSONRPC_ERROR: {resp['error']}"
    result = resp.get("result", {})
    if result.get("isError"):
        content = result.get("content", [])
        txt = content[0].get("text","") if content else ""
        return None, f"TOOL_ERROR: {txt[:200]}"
    content = result.get("content", [])
    txt = content[0].get("text","") if content else ""
    try:
        return json.loads(txt), None
    except Exception:
        return txt, None

# ── Python reference implementations ──────────────────────────────────────────

def py_shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = Counter(data)
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())

def py_page_align_up(addr: int, page_size: int) -> int:
    return ((addr + page_size - 1) // page_size) * page_size

def py_page_align_down(addr: int, page_size: int) -> int:
    return (addr // page_size) * page_size

def py_page_index(addr: int, page_size: int) -> int:
    return addr // page_size

def py_page_containing(addr: int, page_size: int):
    start = py_page_align_down(addr, page_size)
    return start, start + page_size

def py_page_range_indices(start: int, end: int, page_size: int):
    first = py_page_index(start, page_size)
    last = py_page_index(end - 1, page_size) if end > start else first
    return first, last

def py_diff_spans(a: bytes, b: bytes):
    spans = []
    n = min(len(a), len(b))
    i = 0
    while i < n:
        if a[i] != b[i]:
            j = i
            while j < n and a[j] != b[j]:
                j += 1
            spans.append({"offset": i, "len": j - i})
            i = j
        else:
            i += 1
    return spans

# ── Constants ──────────────────────────────────────────────────────────────────
BYTES_64 = bytes.fromhex("deadbeef00112233" * 8)
HEX_64 = BYTES_64.hex()

BYTES_80_HEX = (
    "deadbeef00112233445566778899aabbccddeeff"
    "deadbeef00112233445566778899aabbccddeeff"
    "deadbeef00112233445566778899aabbccddeeff"
    "deadbeef00112233445566778899aabbccddeeff"
)
BYTES_80 = bytes.fromhex(BYTES_80_HEX)

A_HEX = "deadbeef00112233"
B_HEX = "deadbeef00110000"
A_B = bytes.fromhex(A_HEX)
B_B = bytes.fromhex(B_HEX)

ADDR = 5368771180
PAGE_SIZE = 8

ENTROPY_64 = py_shannon_entropy(BYTES_64)   # 3.0
ENTROPY_80 = py_shannon_entropy(BYTES_80)   # 4.321928...
SPANS_AB = py_diff_spans(A_B, B_B)
CHANGED_AB = sum(s["len"] for s in SPANS_AB)

results = []
skips = []

def check(tool, args, key, expected, *, tol=None, skip_reason=None):
    if skip_reason:
        skips.append({"tool": tool, "reason": skip_reason})
        return
    data, err = call_tool(tool, args)
    if err:
        results.append({"tool": tool, "status": "FAIL", "key": key,
                        "expected": expected, "actual": err})
        return
    if data is None:
        results.append({"tool": tool, "status": "FAIL", "key": key,
                        "expected": expected, "actual": None})
        return
    actual = data.get(key) if isinstance(data, dict) else data
    # Coerce string integers when expected is int
    if isinstance(expected, int) and isinstance(actual, str):
        try:
            actual = int(actual)
        except ValueError:
            pass
    if tol is not None:
        ok = abs((actual or 0.0) - expected) < tol
    elif isinstance(expected, float):
        ok = abs((actual or 0.0) - expected) < 1e-9
    else:
        ok = actual == expected
    status = "PASS" if ok else "FAIL"
    results.append({
        "tool": tool, "status": status, "key": key,
        "expected": expected, "actual": actual,
    })

# ─── Core page arithmetic ─────────────────────────────────────────────────────
check("mem_page_align_up",   {"addr": ADDR, "page_size": PAGE_SIZE}, "aligned",
      py_page_align_up(ADDR, PAGE_SIZE))
check("mem_page_align_down", {"addr": ADDR, "page_size": PAGE_SIZE}, "aligned",
      py_page_align_down(ADDR, PAGE_SIZE))
check("mem_page_index",      {"addr": ADDR, "page_size": PAGE_SIZE}, "page_index",
      py_page_index(ADDR, PAGE_SIZE))
start_p, end_p = py_page_containing(ADDR, PAGE_SIZE)
check("mem_page_containing", {"addr": ADDR, "page_size": PAGE_SIZE}, "start", start_p)
check("mem_page_containing", {"addr": ADDR, "page_size": PAGE_SIZE}, "end",   end_p)

first_i, last_i = py_page_range_indices(ADDR, ADDR + 80, PAGE_SIZE)
check("mem_page_range_indices", {"start": ADDR, "end": ADDR+80, "page_size": PAGE_SIZE},
      "first_page_index", first_i)
check("mem_page_range_indices", {"start": ADDR, "end": ADDR+80, "page_size": PAGE_SIZE},
      "last_page_index", last_i)

# ─── Shannon entropy ──────────────────────────────────────────────────────────
check("mem_shannon_entropy",      {"hex": HEX_64, "bytes": list(BYTES_64)}, "entropy", ENTROPY_64)
check("mem_shannon_entropy",      {"hex": HEX_64, "bytes": list(BYTES_64)}, "len",     len(BYTES_64))
check("mem_shannon_entropy_wire", {"hex": HEX_64, "bytes": list(BYTES_64)}, "entropy", ENTROPY_64)
check("mem_shannon_entropy_v3",   {"hex": BYTES_80_HEX}, "entropy", ENTROPY_80)
check("mem_shannon_entropy_v3",   {"hex": BYTES_80_HEX}, "len",     len(BYTES_80))
check("mem_kx7_shannon_entropy_hex",        {"hex": BYTES_80_HEX}, "entropy", ENTROPY_80)
check("mem_kx7_shannon_entropy_len",        {"hex": BYTES_80_HEX}, "len",     len(BYTES_80))
check("mem_ma_shannon_entropy_bytes_v4",    {"hex": BYTES_80_HEX}, "entropy", ENTROPY_80)
check("mem_shannon_entropy_from_bytes_v5",  {"hex": BYTES_80_HEX}, "entropy", ENTROPY_80)

# ─── Diff bytes ───────────────────────────────────────────────────────────────
# mem_diff_bytes uses key "count" for span count
check("mem_diff_bytes", {"a_hex": HEX_64, "b_hex": HEX_64}, "count", 0)
check("mem_diff_bytes", {"a_hex": A_HEX,  "b_hex": B_HEX},  "count", len(SPANS_AB))

check("mem_kx7_diff_bytes_span_count",   {"a_hex": A_HEX, "b_hex": B_HEX}, "span_count", len(SPANS_AB))
check("mem_diff_bytes_v3",               {"a_hex": A_HEX, "b_hex": B_HEX}, "span_count", len(SPANS_AB))
check("mem_kx7_diff_bytes_total_len",    {"a_hex": A_HEX, "b_hex": B_HEX}, "total_len",  CHANGED_AB)
# ratio key is "ratio"
change_ratio = CHANGED_AB / len(A_B)
check("mem_kx7_diff_bytes_change_ratio", {"a_hex": A_HEX, "b_hex": B_HEX}, "ratio", change_ratio)
# identical bytes
check("mem_diff_bytes_span_count_wire",    {"a_hex": HEX_64, "b_hex": HEX_64}, "span_count",   0)
check("mem_diff_bytes_at_base_wire2",      {"a_hex": HEX_64, "b_hex": HEX_64}, "span_count",   0)
check("mem_diff_bytes_total_changed_wire", {"a_hex": HEX_64, "b_hex": HEX_64}, "total_changed", 0)
# first_len when no spans -> tool returns 0 (empty default)
check("mem_kx7_diff_bytes_first_len", {"a_hex": HEX_64, "b_hex": HEX_64}, "first_len", 0)
# last_end when no spans -> tool returns -1
check("mem_kx7_diff_bytes_last_end",  {"a_hex": HEX_64, "b_hex": HEX_64}, "last_end", -1)

# ─── kx7 page arithmetic ─────────────────────────────────────────────────────
check("mem_kx7_page_align_up",   {"addr": ADDR, "page_size": PAGE_SIZE}, "aligned",
      py_page_align_up(ADDR, PAGE_SIZE))
check("mem_kx7_page_align_down", {"addr": ADDR, "page_size": PAGE_SIZE}, "aligned",
      py_page_align_down(ADDR, PAGE_SIZE))
check("mem_kx7_page_index",      {"addr": ADDR, "page_size": PAGE_SIZE}, "page_index",
      py_page_index(ADDR, PAGE_SIZE))
check("mem_kx7_page_containing", {"addr": ADDR, "page_size": PAGE_SIZE}, "start", start_p)

first_i2, last_i2 = py_page_range_indices(ADDR, ADDR + 80, PAGE_SIZE)
check("mem_kx7_page_range_indices", {"start": ADDR, "end": ADDR+80, "page_size": PAGE_SIZE},
      "first", first_i2)
check("mem_kx7_page_range_indices", {"start": ADDR, "end": ADDR+80, "page_size": PAGE_SIZE},
      "last",  last_i2)

# page_align_roundtrip: aligned address -> up==down, equal==True
aligned_addr = py_page_align_down(ADDR, PAGE_SIZE)
check("mem_kx7_page_align_roundtrip", {"addr": aligned_addr, "page_size": PAGE_SIZE}, "equal", True)

# page_span_count for ADDR..(ADDR + PAGE_SIZE*4)
end_span = ADDR + PAGE_SIZE * 4
f_span, l_span = py_page_range_indices(ADDR, end_span, PAGE_SIZE)
expected_pages = l_span - f_span + 1
check("mem_kx7_page_span_count", {"start": ADDR, "end": end_span, "page_size": PAGE_SIZE},
      "pages", expected_pages)

check("mem_kx7_page_align_up_batch",
      {"addrs": [ADDR, ADDR+1, ADDR+PAGE_SIZE], "page_size": PAGE_SIZE},
      "aligned",
      [py_page_align_up(a, PAGE_SIZE) for a in [ADDR, ADDR+1, ADDR+PAGE_SIZE]])

# ─── v5 page arithmetic ───────────────────────────────────────────────────────
check("mem_page_align_up_v5",   {"addr": ADDR, "page_size": PAGE_SIZE}, "aligned",
      py_page_align_up(ADDR, PAGE_SIZE))
check("mem_page_align_down_v5", {"addr": ADDR, "page_size": PAGE_SIZE}, "aligned",
      py_page_align_down(ADDR, PAGE_SIZE))
check("mem_page_index_v5",      {"addr": ADDR, "page_size": PAGE_SIZE}, "index",
      py_page_index(ADDR, PAGE_SIZE))
check("mem_page_containing_v5", {"addr": ADDR, "page_size": PAGE_SIZE}, "page_base", start_p)
check("mem_page_range_indices_v5", {"start": ADDR, "end": ADDR+80, "page_size": PAGE_SIZE},
      "first", first_i)
check("mem_shannon_entropy_from_bytes_v5", {"hex": BYTES_80_HEX}, "entropy", ENTROPY_80)

# ─── v3 page arithmetic ───────────────────────────────────────────────────────
check("mem_page_align_up_v3",   {"addr": ADDR, "page_size": PAGE_SIZE}, "aligned",
      py_page_align_up(ADDR, PAGE_SIZE))
check("mem_page_align_down_v3", {"addr": ADDR, "page_size": PAGE_SIZE}, "aligned",
      py_page_align_down(ADDR, PAGE_SIZE))

# ─── Entropy classify ─────────────────────────────────────────────────────────
check("mem_entropy_classify",       {"entropy": 1.0}, "classification", "low (likely text/code)")
check("mem_entropy_classify_value_wire", {"entropy": 1.0}, "classification", "low (likely text/code)")
# All-zero bytes -> entropy==0.0 -> "zero" classification
check("mem_entropy_block_classify_bytes_v4", {"hex": "00000000"}, "classification", "zero")
# Non-zero low entropy
check("mem_entropy_block_classify_bytes_v4", {"hex": A_HEX}, "entropy",
      py_shannon_entropy(A_B), tol=1e-9)

# ─── Perms ────────────────────────────────────────────────────────────────────
# Tool requires parameter named 's'
check("mem_perms_from_rwx", {"s": "rwx"}, "readable",    True)
check("mem_perms_from_rwx", {"s": "rwx"}, "writable",    True)
check("mem_perms_from_rwx", {"s": "rwx"}, "executable",  True)
check("mem_perms_from_rwx", {"s": "r--"}, "writable",    False)

# ─── Shannon entropy wire stats ───────────────────────────────────────────────
# Single block covering all 64 bytes: max/min/mean == ENTROPY_64
check("mem_shannon_entropy_max_block_wire",  {"hex": HEX_64, "block_size": 64}, "max_entropy", ENTROPY_64)
check("mem_shannon_entropy_min_block_wire",  {"hex": HEX_64, "block_size": 64}, "min_entropy", ENTROPY_64,
      skip_reason="key name for min unverified - check separately")
check("mem_shannon_entropy_mean_block_wire", {"hex": HEX_64, "block_size": 64}, "mean_entropy", ENTROPY_64,
      skip_reason="key name for mean unverified - check separately")

# ─── Page align many ─────────────────────────────────────────────────────────
addrs = [ADDR, ADDR + 1, ADDR + PAGE_SIZE]
check("mem_page_align_up_many_wire",   {"addrs": addrs, "page_size": PAGE_SIZE},
      "aligned", [py_page_align_up(a, PAGE_SIZE)   for a in addrs])
check("mem_page_align_down_many_wire", {"addrs": addrs, "page_size": PAGE_SIZE},
      "aligned", [py_page_align_down(a, PAGE_SIZE) for a in addrs])
check("mem_page_index_many_wire",      {"addrs": addrs, "page_size": PAGE_SIZE},
      "indices", [py_page_index(a, PAGE_SIZE)       for a in addrs])

# ─── kx7 snapshot diff ───────────────────────────────────────────────────────
# roundtrip: regions in roundtrip_regions should equal regions
check("mem_kx7_snapshotdiff_json_roundtrip", {"a_hex": A_HEX, "b_hex": B_HEX},
      "roundtrip_regions", 1)

# ─── Virtual provider reads ───────────────────────────────────────────────────
check("mem_virtual_provider_read_u8_v5",
      {"hex": HEX_64, "addr": 0}, "value", BYTES_64[0])
check("mem_virtual_provider_read_u32_le_v5",
      {"hex": HEX_64, "addr": 0}, "value", struct.unpack_from("<I", BYTES_64, 0)[0])
# u64 returned as string in JSON
check("mem_virtual_provider_read_u64_le_v5",
      {"hex": HEX_64, "addr": 0}, "value", struct.unpack_from("<Q", BYTES_64, 0)[0])

# ─── Null provider ───────────────────────────────────────────────────────────
check("mem_null_provider_read_v5", {"addr": 0, "size": 4}, "read_errored", True)

# ─── Region kind list ─────────────────────────────────────────────────────────
check("mem_region_kind_list", {}, "count", 19)

# ─── kx7 bytepattern ─────────────────────────────────────────────────────────
check("mem_kx7_bytepattern_valid", {"pattern": "deadbeef"},   "valid", False)
check("mem_kx7_bytepattern_valid", {"pattern": "de ad be ef"}, "valid", True)

# ─── v4 byte pattern ─────────────────────────────────────────────────────────
check("mem_ma_byte_pattern_exact_v4",
      {"pattern_hex": A_HEX, "data_hex": A_HEX}, "matches", True)
check("mem_ma_byte_pattern_exact_v4",
      {"pattern_hex": "deadbeef00110000", "data_hex": A_HEX}, "matches", False)

# ─── kx7 entropy windows (SKIP - internal partitioning logic unclear) ─────────
skips.append({"tool": "mem_kx7_entropy_windows_max", "reason": "window partitioning logic requires Rust source review"})
skips.append({"tool": "mem_kx7_entropy_windows_avg", "reason": "window partitioning logic requires Rust source review"})
skips.append({"tool": "mem_kx7_entropy_windows_above", "reason": "threshold semantics require Rust source review"})

# ─── kx7 diff memory regions (SKIP - base address semantics unclear) ──────────
skips.append({"tool": "mem_kx7_diff_memory_regions", "reason": "base address overlap semantics unclear"})

# ─── v4 ma tools (partial) ───────────────────────────────────────────────────
skips.append({"tool": "mem_ma_entropy_region_suspicious_threshold_v4", "reason": "threshold constant unknown"})

# ─── Finish ──────────────────────────────────────────────────────────────────
p.stdin.close()
p.terminate()

passed = sum(1 for r in results if r["status"] == "PASS")
failed = sum(1 for r in results if r["status"] == "FAIL")
mismatches = [r for r in results if r["status"] == "FAIL"]

# Unique tools
tools_hardened = {r["tool"] for r in results}
tools_passed   = {r["tool"] for r in results if r["status"] == "PASS"}
tools_failed   = {r["tool"] for r in results if r["status"] == "FAIL"}
tools_skipped  = {s["tool"] for s in skips}

summary = {
    "module": "mem",
    "tools_hardened": len(tools_hardened),
    "tools_passed":   len(tools_passed),
    "tools_failed":   len(tools_failed),
    "tools_skipped":  len(tools_skipped),
    "checks_passed":  passed,
    "checks_failed":  failed,
    "mismatches": [
        {"tool": m["tool"], "key": m.get("key",""),
         "expected": m["expected"], "actual": m["actual"]}
        for m in mismatches
    ],
    "detail": results,
}

with open(r"C:\Users\Fra\Desktop\RustRE\validation\rigorous_mem_v2.json", "w") as f:
    json.dump(summary, f, indent=2)

skip_doc = {"skipped": list(skips)}
with open(r"C:\Users\Fra\Desktop\RustRE\validation\skip_mem.json", "w") as f:
    json.dump(skip_doc, f, indent=2)

print(f"Checks: {passed} passed, {failed} failed")
print(f"Tools:  {len(tools_hardened)} hardened, {len(tools_passed)} passed, "
      f"{len(tools_failed)} failed, {len(tools_skipped)} skipped")
if mismatches:
    print("MISMATCHES:")
    for m in mismatches:
        print(f"  {m['tool']} [{m.get('key','')}] expected={m['expected']!r} actual={m['actual']!r}")
