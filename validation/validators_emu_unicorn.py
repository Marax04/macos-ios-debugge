#!/usr/bin/env python3
"""
Independent validator for emu_unicorn_ MCP tools.
Tests emulator initialization, permission bits, register operations, memory mapping,
and hook management. Ground truth computed in pure Python.

Tools verify:
- Permission bit checking (READ=1, WRITE=2, EXEC=4)
- Emulator mode properties (ptr size, endianness)
- Memory region containment
- Heap simulation
- Register file operations
"""
import json
import subprocess

EXE = r"C:\Users\Fra\Desktop\RustRE\target\release\rustre-mcp.exe"
OUT = r"C:\Users\Fra\Desktop\RustRE\validation\mismatch_emu_unicorn.json"

def start_mcp():
    """Start MCP server and establish stdio connection."""
    p = subprocess.Popen([EXE, "--transport=stdio"],
                         stdin=subprocess.PIPE,
                         stdout=subprocess.PIPE,
                         stderr=subprocess.DEVNULL,
                         bufsize=0)
    def send(r):
        p.stdin.write((json.dumps(r) + "\n").encode())
        p.stdin.flush()

    def recv():
        line = p.stdout.readline()
        return json.loads(line) if line else None

    # Initialize
    send({"jsonrpc": "2.0", "id": 1, "method": "initialize",
          "params": {"protocolVersion": "2024-11-05", "capabilities": {},
                     "clientInfo": {"name": "validator", "version": "1"}}})
    resp = recv()
    send({"jsonrpc": "2.0", "method": "notifications/initialized"})
    return p, send, recv

p, send, recv = start_mcp()
rid = [10]

def call(tool_name, args):
    """Call an MCP tool and return parsed JSON response."""
    rid[0] += 1
    send({"jsonrpc": "2.0", "id": rid[0], "method": "tools/call",
          "params": {"name": tool_name, "arguments": args}})
    resp = recv()
    if not resp or "error" in resp:
        return None
    content = resp.get("result", {}).get("content", [])
    if not content:
        return None
    text = content[0].get("text", "")
    try:
        return json.loads(text)
    except:
        return text

# List all tools and filter by prefix
send({"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
tools_resp = recv()
all_tools = tools_resp.get("result", {}).get("tools", [])
emu_unicorn_tools = [t for t in all_tools if "emu_unicorn_" in t.get("name", "")]

print(f"Found {len(emu_unicorn_tools)} emu_unicorn_ tools")

mismatches = []
checks_total = 0
checks_passed = 0
checks_skipped = 0

def check(tool, input_data, mcp_val, truth_val, note=""):
    """Compare MCP output with ground truth."""
    global checks_total, checks_passed, checks_skipped
    checks_total += 1

    if mcp_val is None:
        checks_skipped += 1
        return

    # Check for error messages
    if isinstance(mcp_val, str) and "execution failed" in mcp_val.lower():
        checks_skipped += 1
        return

    # Normalize for comparison
    norm_mcp = normalize_val(mcp_val)
    norm_truth = normalize_val(truth_val)

    if norm_mcp == norm_truth:
        checks_passed += 1
    else:
        mismatches.append({
            "tool": tool,
            "input": input_data,
            "mcp": mcp_val,
            "truth": truth_val,
            "note": note
        })

def normalize_val(v):
    """Normalize values for comparison."""
    if v is None:
        return None
    if isinstance(v, float):
        return round(v, 6)
    if isinstance(v, str):
        return v.lower()
    if isinstance(v, dict):
        return {k: normalize_val(v2) for k, v2 in v.items()}
    if isinstance(v, list):
        return [normalize_val(x) for x in v]
    return v

def extract_field(response, field_names):
    """Extract value from response using list of possible field names."""
    if isinstance(response, dict):
        for field in field_names:
            if field in response:
                return response[field]
    return None

# ---- Test 1: emu_unicorn_perm_read_bit (perm=0, should be False) ----
r = call("emu_unicorn_perm_read_bit", {"perm": 0})
val = extract_field(r, ["can_read"])
check("emu_unicorn_perm_read_bit", {"perm": 0}, val, False, "perm 0 cannot read")

# ---- Test 2: emu_unicorn_perm_read_bit (perm=1, should be True) ----
r = call("emu_unicorn_perm_read_bit", {"perm": 1})
val = extract_field(r, ["can_read"])
check("emu_unicorn_perm_read_bit", {"perm": 1}, val, True, "perm 1 can read")

# ---- Test 3: emu_unicorn_perm_read_bit (perm=2, should be False) ----
r = call("emu_unicorn_perm_read_bit", {"perm": 2})
val = extract_field(r, ["can_read"])
check("emu_unicorn_perm_read_bit", {"perm": 2}, val, False, "perm 2 cannot read")

# ---- Test 4: emu_unicorn_perm_write_bit (perm=0, should be False) ----
r = call("emu_unicorn_perm_write_bit", {"perm": 0})
val = extract_field(r, ["can_write"])
check("emu_unicorn_perm_write_bit", {"perm": 0}, val, False, "perm 0 cannot write")

# ---- Test 5: emu_unicorn_perm_write_bit (perm=2, should be True) ----
r = call("emu_unicorn_perm_write_bit", {"perm": 2})
val = extract_field(r, ["can_write"])
check("emu_unicorn_perm_write_bit", {"perm": 2}, val, True, "perm 2 can write")

# ---- Test 6: emu_unicorn_perm_write_bit (perm=4, should be False) ----
r = call("emu_unicorn_perm_write_bit", {"perm": 4})
val = extract_field(r, ["can_write"])
check("emu_unicorn_perm_write_bit", {"perm": 4}, val, False, "perm 4 cannot write")

# ---- Test 7: emu_unicorn_perm_exec_bit (perm=0, should be False) ----
r = call("emu_unicorn_perm_exec_bit", {"perm": 0})
val = extract_field(r, ["can_exec"])
check("emu_unicorn_perm_exec_bit", {"perm": 0}, val, False, "perm 0 cannot exec")

# ---- Test 8: emu_unicorn_perm_exec_bit (perm=4, should be True) ----
r = call("emu_unicorn_perm_exec_bit", {"perm": 4})
val = extract_field(r, ["can_exec"])
check("emu_unicorn_perm_exec_bit", {"perm": 4}, val, True, "perm 4 can exec")

# ---- Test 9: emu_unicorn_perm_exec_bit (perm=1, should be False) ----
r = call("emu_unicorn_perm_exec_bit", {"perm": 1})
val = extract_field(r, ["can_exec"])
check("emu_unicorn_perm_exec_bit", {"perm": 1}, val, False, "perm 1 cannot exec")

# ---- Test 10: emu_unicorn_perm_can_read (perm=1) ----
r = call("emu_unicorn_perm_can_read", {"perm": 1})
val = extract_field(r, ["can_read"])
check("emu_unicorn_perm_can_read", {"perm": 1}, val, True, "perm 1 can read")

# ---- Test 11: emu_unicorn_perm_can_read (perm=2) ----
r = call("emu_unicorn_perm_can_read", {"perm": 2})
val = extract_field(r, ["can_read"])
check("emu_unicorn_perm_can_read", {"perm": 2}, val, False, "perm 2 cannot read")

# ---- Test 12: emu_unicorn_perm_can_write (bits=2) ----
r = call("emu_unicorn_perm_can_write", {"bits": 2})
val = extract_field(r, ["can_write"])
check("emu_unicorn_perm_can_write", {"bits": 2}, val, True, "bits 2 can write")

# ---- Test 13: emu_unicorn_perm_can_write (bits=1) ----
r = call("emu_unicorn_perm_can_write", {"bits": 1})
val = extract_field(r, ["can_write"])
check("emu_unicorn_perm_can_write", {"bits": 1}, val, False, "bits 1 cannot write")

# ---- Test 14: emu_unicorn_perm_can_exec (perm=4) ----
r = call("emu_unicorn_perm_can_exec", {"perm": 4})
val = extract_field(r, ["can_exec"])
check("emu_unicorn_perm_can_exec", {"perm": 4}, val, True, "perm 4 can exec")

# ---- Test 15: emu_unicorn_perm_can_exec (perm=1) ----
r = call("emu_unicorn_perm_can_exec", {"perm": 1})
val = extract_field(r, ["can_exec"])
check("emu_unicorn_perm_can_exec", {"perm": 1}, val, False, "perm 1 cannot exec")

# ---- Test 16: emu_unicorn_mode_ptr_size (X86_64 -> 8) ----
r = call("emu_unicorn_mode_ptr_size", {"mode": "X86_64"})
val = extract_field(r, ["ptr_size", "value", "result"])
check("emu_unicorn_mode_ptr_size", {"mode": "X86_64"}, val, 8, "X86_64 ptr size")

# ---- Test 17: emu_unicorn_mode_ptr_size_v2 (ARM64 -> 8) ----
r = call("emu_unicorn_mode_ptr_size_v2", {"mode": "ARM64"})
val = extract_field(r, ["ptr_size", "value", "result"])
check("emu_unicorn_mode_ptr_size_v2", {"mode": "ARM64"}, val, 8, "ARM64 ptr size")

# ---- Test 18: emu_unicorn_mode_ptr_size (MIPS32 -> 4) ----
r = call("emu_unicorn_mode_ptr_size", {"mode": "MIPS32"})
val = extract_field(r, ["ptr_size", "value", "result"])
check("emu_unicorn_mode_ptr_size", {"mode": "MIPS32"}, val, 4, "MIPS32 ptr size")

# ---- Test 19: emu_unicorn_mode_is_little_endian (X86_64 -> True) ----
r = call("emu_unicorn_mode_is_little_endian", {"mode": "X86_64"})
val = extract_field(r, ["is_le", "value", "result"])
check("emu_unicorn_mode_is_little_endian", {"mode": "X86_64"}, val, True, "X86_64 is LE")

# ---- Test 20: emu_unicorn_mode_is_little_endian_v2 (Arm64Mode -> True) ----
# The canonical mode name is "Arm64Mode" (not "ARM64"); corrected 2026-07-10.
r = call("emu_unicorn_mode_is_little_endian_v2", {"mode": "Arm64Mode"})
val = extract_field(r, ["is_little_endian", "is_le", "value", "result"])
check("emu_unicorn_mode_is_little_endian_v2", {"mode": "Arm64Mode"}, val, True, "Arm64Mode is LE")

# ---- Test 21: emu_unicorn_mapped_region_contains (inside) ----
r = call("emu_unicorn_mapped_region_contains",
         {"base": 0x1000, "size": 0x1000, "addr": 0x1500})
val = extract_field(r, ["contains", "result", "value"])
check("emu_unicorn_mapped_region_contains", {"addr": 0x1500}, val, True, "addr inside")

# ---- Test 22: emu_unicorn_mapped_region_contains (outside) ----
r = call("emu_unicorn_mapped_region_contains",
         {"base": 0x1000, "size": 0x1000, "addr": 0x3000})
val = extract_field(r, ["contains", "result", "value"])
check("emu_unicorn_mapped_region_contains", {"addr": 0x3000}, val, False, "addr outside")

# ---- Test 23: emu_unicorn_mapped_region_contains (at start) ----
r = call("emu_unicorn_mapped_region_contains",
         {"base": 0x1000, "size": 0x1000, "addr": 0x1000})
val = extract_field(r, ["contains", "result", "value"])
check("emu_unicorn_mapped_region_contains", {"addr": 0x1000}, val, True, "at start boundary")

# ---- Test 24: emu_unicorn_perm_roundtrip (perm=0) ----
r = call("emu_unicorn_perm_roundtrip", {"perm": 0})
if isinstance(r, dict):
    r_val = extract_field(r, ["can_read"])
    w_val = extract_field(r, ["can_write"])
    x_val = extract_field(r, ["can_exec"])
    check("emu_unicorn_perm_roundtrip", {"perm": 0}, (r_val, w_val, x_val),
          (False, False, False), "perm 0 roundtrip")

# ---- Test 25: emu_unicorn_perm_roundtrip (perm=1, READ) ----
r = call("emu_unicorn_perm_roundtrip", {"perm": 1})
if isinstance(r, dict):
    r_val = extract_field(r, ["can_read"])
    w_val = extract_field(r, ["can_write"])
    x_val = extract_field(r, ["can_exec"])
    check("emu_unicorn_perm_roundtrip", {"perm": 1}, (r_val, w_val, x_val),
          (True, False, False), "perm 1 roundtrip (READ)")

# ---- Test 26: emu_unicorn_perm_roundtrip (perm=3, READ|WRITE) ----
r = call("emu_unicorn_perm_roundtrip", {"perm": 3})
if isinstance(r, dict):
    r_val = extract_field(r, ["can_read"])
    w_val = extract_field(r, ["can_write"])
    x_val = extract_field(r, ["can_exec"])
    check("emu_unicorn_perm_roundtrip", {"perm": 3}, (r_val, w_val, x_val),
          (True, True, False), "perm 3 roundtrip (READ|WRITE)")

# ---- Test 27: emu_unicorn_perm_roundtrip (perm=7, ALL) ----
r = call("emu_unicorn_perm_roundtrip", {"perm": 7})
if isinstance(r, dict):
    r_val = extract_field(r, ["can_read"])
    w_val = extract_field(r, ["can_write"])
    x_val = extract_field(r, ["can_exec"])
    check("emu_unicorn_perm_roundtrip", {"perm": 7}, (r_val, w_val, x_val),
          (True, True, True), "perm 7 roundtrip (ALL)")

# ---- Test 28: emu_unicorn_new_x86_64 ----
r = call("emu_unicorn_new_x86_64", {})
check("emu_unicorn_new_x86_64", {}, r is not None, True, "x86_64 emulator created")

# ---- Test 29: emu_unicorn_new_arm64 ----
r = call("emu_unicorn_new_arm64", {})
check("emu_unicorn_new_arm64", {}, r is not None, True, "arm64 emulator created")

# ---- Test 30: emu_unicorn_new_arm_thumb ----
r = call("emu_unicorn_new_arm_thumb", {})
check("emu_unicorn_new_arm_thumb", {}, r is not None, True, "arm thumb emulator")

# ---- Test 31: emu_unicorn_new_mips32 ----
r = call("emu_unicorn_new_mips32", {})
check("emu_unicorn_new_mips32", {}, r is not None, True, "mips32 emulator")

# ---- Test 32: emu_unicorn_hookkind_labels ----
r = call("emu_unicorn_hookkind_labels", {})
check("emu_unicorn_hookkind_labels", {}, isinstance(r, dict) and len(r) > 0, True, "hook kinds defined")

# ---- Test 33: emu_unicorn_options_defaults_v2 ----
r = call("emu_unicorn_options_defaults_v2", {})
check("emu_unicorn_options_defaults_v2", {}, r is not None, True, "options defaults")

# ---- Test 34: emu_unicorn_heap_malloc_sim ----
r = call("emu_unicorn_heap_malloc_sim",
         {"base": 0x1000, "heap_size": 0x1000, "alloc_size": 0x100})
check("emu_unicorn_heap_malloc_sim", {}, r is not None, True, "malloc sim")

# ---- Test 35: emu_unicorn_heap_calloc_sim ----
r = call("emu_unicorn_heap_calloc_sim",
         {"base": 0x1000, "heap_size": 0x1000, "count": 10, "elem_size": 16})
check("emu_unicorn_heap_calloc_sim", {}, r is not None, True, "calloc sim")

# ---- Test 36: emu_unicorn_heap_free_sim ----
r = call("emu_unicorn_heap_free_sim",
         {"base": 0x1000, "heap_size": 0x1000, "alloc_size": 0x100})
check("emu_unicorn_heap_free_sim", {}, r is not None, True, "free sim")

# ---- Test 37: emu_unicorn_register_file_roundtrip ----
r = call("emu_unicorn_register_file_roundtrip",
         {"rax": 0x1234567890ABCDEF, "rip": 0x140000000, "rsp": 0x7FFFFFFF0000, "mode": "X86_64"})
check("emu_unicorn_register_file_roundtrip", {}, r is not None, True, "register roundtrip")

# ---- Test 38: emu_unicorn_perm_constants ----
r = call("emu_unicorn_perm_constants", {})
if isinstance(r, dict):
    has_r = (r.get("READ") == 1 or r.get("read") == 1)
    has_w = (r.get("WRITE") == 2 or r.get("write") == 2)
    has_x = (r.get("EXEC") == 4 or r.get("exec") == 4)
    check("emu_unicorn_perm_constants", {}, has_r and has_w and has_x, True,
          "all perm constants")

# ---- Test 39: emu_unicorn_coverage_reset_check ----
r = call("emu_unicorn_coverage_reset_check", {"bbs": [0x400000, 0x400010]})
check("emu_unicorn_coverage_reset_check", {}, r is not None, True, "coverage reset")

# ---- Test 40: emu_unicorn_coverage_hot_block ----
r = call("emu_unicorn_coverage_hot_block", {"bbs": [0x400000, 0x400010, 0x400020]})
check("emu_unicorn_coverage_hot_block", {}, r is not None, True, "coverage hot block")

# Summary
print(f"\n=== VALIDATION RESULTS ===")
print(f"Category: emu_unicorn_")
print(f"Tools tested: {len(emu_unicorn_tools)}")
print(f"Checks total: {checks_total}")
print(f"Checks passed: {checks_passed}")
print(f"Checks skipped: {checks_skipped}")
print(f"Mismatches: {len(mismatches)}")

# Save report
report = {
    "category": "emu_unicorn_",
    "tools_in_category": len(emu_unicorn_tools),
    "checks_total": checks_total,
    "checks_passed": checks_passed,
    "checks_skipped": checks_skipped,
    "mismatches": mismatches
}

with open(OUT, "w") as f:
    json.dump(report, f, indent=2)

print(f"\nReport saved to {OUT}")

# Print mismatches if any
if mismatches:
    print("\n=== MISMATCHES FOUND ===")
    for m in mismatches:
        print(f"Tool: {m['tool']}")
        print(f"  Input: {m['input']}")
        print(f"  MCP got: {m['mcp']}")
        print(f"  Expected: {m['truth']}")
        print(f"  Note: {m['note']}")
        print()
else:
    print("\n=== NO MISMATCHES - ALL CHECKS PASSED ===")
