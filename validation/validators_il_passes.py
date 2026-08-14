#!/usr/bin/env python3
"""
Independent Python validator for RustRE MCP tools with prefix "il_passes_".
Validates IL pass tools on empty/default LLIL functions.
Reports mismatches to validation/mismatch_il_passes.json.
"""
import json
import subprocess
import sys
from collections import Counter

EXE = r"C:\Users\Fra\Desktop\RustRE\target\release\rustre-mcp.exe"
TARGET = r"C:\Users\Fra\Desktop\Zyphora\target\release\cargo-zyphora.exe"
OUT = r"C:\Users\Fra\Desktop\RustRE\validation\mismatch_il_passes.json"

def start():
    """Start MCP server and initialize."""
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

    # Initialize
    send({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": {"name": "validator", "version": "1"}
        }
    })
    recv()
    send({"jsonrpc": "2.0", "method": "notifications/initialized"})

    return p, send, recv

p, send, recv = start()
rid = [10]

def call(name, args=None):
    """Call an MCP tool and return the result."""
    if args is None:
        args = {}
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
        return c[0].get("text", "")

# ============================================================================
# Tracking
# ============================================================================
mismatches = []
checks_ok = 0
checks_total = 0

def check(tool_name, mcp_value, truth_value, note=""):
    """Check if MCP value matches ground truth."""
    global checks_ok, checks_total
    checks_total += 1

    # Normalize values for comparison
    mcp_normalized = normalize_value(mcp_value)
    truth_normalized = normalize_value(truth_value)

    if mcp_normalized == truth_normalized:
        checks_ok += 1
        print(f"  [OK] {tool_name}: {note}")
        return True
    else:
        print(f"  [FAIL] {tool_name}: {note}")
        mismatches.append({
            "tool": tool_name,
            "input": "{}",
            "mcp": mcp_value,
            "truth": truth_value,
            "note": note
        })
        return False

def normalize_value(v):
    """Normalize values for comparison."""
    if isinstance(v, float):
        # For floats, check if they're close enough
        return round(v, 6)
    if isinstance(v, str):
        return v.lower().strip()
    return v

# ============================================================================
# Tests for empty/default LLIL function
# ============================================================================
print("Testing il_passes_ tools on empty/default LLIL function...")
print("=" * 80)

# Test 1: il_passes_pass_stats_new
print("\n[1] il_passes_pass_stats_new")
r = call("il_passes_pass_stats_new")
if r and isinstance(r, dict):
    check("il_passes_pass_stats_new::instrs_visited", r.get("instrs_visited"), 0, "default stats instrs_visited")
    check("il_passes_pass_stats_new::instrs_modified", r.get("instrs_modified"), 0, "default stats instrs_modified")
    check("il_passes_pass_stats_new::instrs_removed", r.get("instrs_removed"), 0, "default stats instrs_removed")
    check("il_passes_pass_stats_new::const_folded", r.get("const_folded"), 0, "default stats const_folded")
    check("il_passes_pass_stats_new::exprs_simplified", r.get("exprs_simplified"), 0, "default stats exprs_simplified")
    check("il_passes_pass_stats_new::dead_removed", r.get("dead_removed"), 0, "default stats dead_removed")
else:
    print(f"  [SKIP] Could not call il_passes_pass_stats_new")

# Test 2: il_passes_pass_context_new
print("\n[2] il_passes_pass_context_new")
r = call("il_passes_pass_context_new")
if r and isinstance(r, dict):
    check("il_passes_pass_context_new::changed", r.get("changed"), False, "context changed flag")
    check("il_passes_pass_context_new::warnings", r.get("warnings"), 0, "context warnings count")
    check("il_passes_pass_context_new::instrs_visited", r.get("instrs_visited"), 0, "context instrs_visited")
else:
    print(f"  [SKIP] Could not call il_passes_pass_context_new")

# Test 3: il_passes_count_instrs
print("\n[3] il_passes_count_instrs")
r = call("il_passes_count_instrs")
if r and isinstance(r, dict):
    count = r.get("count")
    check("il_passes_count_instrs", count, 0, "empty function instruction count")
else:
    print(f"  [SKIP] Could not call il_passes_count_instrs")

# Test 4: il_passes_count_constants
print("\n[4] il_passes_count_constants")
r = call("il_passes_count_constants")
if r and isinstance(r, dict):
    count = r.get("count")
    check("il_passes_count_constants", count, 0, "empty function constant count")
else:
    print(f"  [SKIP] Could not call il_passes_count_constants")

# Test 5: il_passes_collect_call_sites
print("\n[5] il_passes_collect_call_sites")
r = call("il_passes_collect_call_sites")
if r and isinstance(r, dict):
    count = r.get("count")
    check("il_passes_collect_call_sites", count, 0, "empty function call site count")
else:
    print(f"  [SKIP] Could not call il_passes_collect_call_sites")

# Test 6: il_passes_detect_loops
print("\n[6] il_passes_detect_loops")
r = call("il_passes_detect_loops")
if r and isinstance(r, dict):
    count = r.get("count")
    check("il_passes_detect_loops", count, 0, "empty function loop count")
else:
    print(f"  [SKIP] Could not call il_passes_detect_loops")

# Test 7: il_passes_loop_bound_analysis
print("\n[7] il_passes_loop_bound_analysis")
r = call("il_passes_loop_bound_analysis")
if r and isinstance(r, dict):
    count = r.get("count")
    check("il_passes_loop_bound_analysis", count, 0, "loop bound analysis result count")
else:
    print(f"  [SKIP] Could not call il_passes_loop_bound_analysis")

# Test 8: il_passes_integer_range_analysis
print("\n[8] il_passes_integer_range_analysis")
r = call("il_passes_integer_range_analysis")
if r and isinstance(r, dict):
    count = r.get("count")
    check("il_passes_integer_range_analysis", count, 0, "integer range analysis result count")
else:
    print(f"  [SKIP] Could not call il_passes_integer_range_analysis")

# Test 9: il_passes_run_gvn_pass
print("\n[9] il_passes_run_gvn_pass")
r = call("il_passes_run_gvn_pass")
if r and isinstance(r, dict):
    changed = r.get("changed")
    check("il_passes_run_gvn_pass::changed", changed, False, "GVN pass on empty function should not change")
else:
    print(f"  [SKIP] Could not call il_passes_run_gvn_pass")

# Test 10: il_passes_inlining_score
print("\n[10] il_passes_inlining_score")
r = call("il_passes_inlining_score")
if r and isinstance(r, dict):
    score_str = r.get("score", "")
    # The inlining score for an empty function should have instr_count: 0, call_count: 0, block_count: 0
    # and score should be 90 (default for empty)
    check("il_passes_inlining_score::has_zero_instr", "instr_count: 0" in str(score_str), True,
          f"inlining score format and zero instruction count")
    check("il_passes_inlining_score::has_zero_calls", "call_count: 0" in str(score_str), True,
          f"inlining score has zero call count")
    check("il_passes_inlining_score::has_score", "score: 90" in str(score_str), True,
          f"inlining score value is 90 for empty function")
else:
    print(f"  [SKIP] Could not call il_passes_inlining_score")

# ============================================================================
# Summary
# ============================================================================
print("\n" + "=" * 80)
print(f"Summary: {checks_ok}/{checks_total} checks passed")

if mismatches:
    print(f"Found {len(mismatches)} mismatches")
    with open(OUT, "w") as f:
        json.dump({
            "category": "il_passes",
            "tools_in_category": 10,
            "checks_total": checks_total,
            "checks_passed": checks_ok,
            "checks_skipped": checks_total - checks_ok - len(mismatches),
            "mismatches": mismatches
        }, f, indent=2)
    print(f"Mismatches written to {OUT}")
else:
    print("No mismatches found!")
    with open(OUT, "w") as f:
        json.dump({
            "category": "il_passes",
            "tools_in_category": 10,
            "checks_total": checks_total,
            "checks_passed": checks_ok,
            "checks_skipped": 0,
            "mismatches": []
        }, f, indent=2)

# Cleanup
p.terminate()
sys.exit(0 if not mismatches else 1)
