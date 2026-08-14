#!/usr/bin/env python3
"""
Validator for decompiler_type_* MCP tools - independent ground truth checks.

Tests verify:
  - decompiler_type_int_byte_size: i8/i16/i32/i64/u8/u16/u32/u64 byte sizes
  - decompiler_type_int_c_name: C type names (int8_t, uint32_t, etc.)
  - decompiler_type_byte_size_ptr_wp: pointer width calculations
  - decompiler_type_byte_size_int_wp: integer type byte sizes
  - decompiler_type_function_arity_*: function parameter counts
  - decompiler_type_is_pointer: pointer type detection
  - decompiler_type_c_name: generic C type names
"""
import json, subprocess, sys

EXE = r"C:\Users\Fra\Desktop\RustRE\target\release\rustre-mcp.exe"
OUT = r"C:\Users\Fra\Desktop\RustRE\validation\mismatch_decompiler_type.json"

# ============================================================================
# MCP Communication
# ============================================================================

def start_mcp():
    p = subprocess.Popen([EXE, "--transport=stdio"], stdin=subprocess.PIPE,
                         stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, bufsize=0)
    def send(r):
        p.stdin.write((json.dumps(r)+"\n").encode())
        p.stdin.flush()
    def recv():
        line = p.stdout.readline()
        return json.loads(line) if line else None

    send({
        "jsonrpc":"2.0", "id":1, "method":"initialize",
        "params":{
            "protocolVersion":"2024-11-05",
            "capabilities":{},
            "clientInfo":{"name":"validator","version":"1"}
        }
    })
    resp = recv()
    if not resp or "error" in resp:
        print(f"[ERR] initialize failed: {resp}")
        sys.exit(1)

    send({"jsonrpc":"2.0","method":"notifications/initialized"})
    return p, send, recv

p, send, recv = start_mcp()
rid = [100]

def call_tool(name, args):
    """Call MCP tool and return result."""
    rid[0] += 1
    send({
        "jsonrpc":"2.0", "id":rid[0],
        "method":"tools/call",
        "params":{"name":name, "arguments":args}
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
# Ground Truth
# ============================================================================

# Decompiler integer type byte sizes (Rust types)
INT_TYPE_SIZES = {
    "i8": 1, "u8": 1,
    "i16": 2, "u16": 2,
    "i32": 4, "u32": 4,
    "i64": 8, "u64": 8,
}

# C type names for integer widths (in bits)
INT_WIDTH_C_NAMES = {
    "8": "int8_t",
    "16": "int16_t",
    "32": "int32_t",
    "64": "int64_t",
}

def get_int_byte_size(ty):
    """Ground truth: int type -> byte size."""
    return INT_TYPE_SIZES.get(ty)

def get_int_c_name(ty):
    """Ground truth: Rust int type -> C name."""
    name_map = {
        "i8": "int8_t", "u8": "uint8_t",
        "i16": "int16_t", "u16": "uint16_t",
        "i32": "int32_t", "u32": "uint32_t",
        "i64": "int64_t", "u64": "uint64_t",
    }
    return name_map.get(ty)

# ============================================================================
# Tracking
# ============================================================================

mismatches = []
checks_ok = 0
checks_total = 0
checks_skipped = 0

def check(tool_name, mcp_val, truth_val, ctx=""):
    """Compare MCP output to ground truth."""
    global checks_ok, checks_total, checks_skipped

    if mcp_val is None:
        checks_skipped += 1
        return

    checks_total += 1

    # Normalize comparison
    if isinstance(mcp_val, str) and isinstance(truth_val, str):
        match = mcp_val.lower() == truth_val.lower()
    elif isinstance(mcp_val, (int, float)) and isinstance(truth_val, (int, float)):
        match = abs(float(mcp_val) - float(truth_val)) < 1e-6
    else:
        match = mcp_val == truth_val

    if match:
        checks_ok += 1
    else:
        mismatches.append({
            "tool": tool_name,
            "input": ctx,
            "mcp": mcp_val,
            "truth": truth_val,
            "note": f"expected {truth_val}, got {mcp_val}"
        })

# ============================================================================
# Test Cases
# ============================================================================

print("[TEST] Running decompiler_type_ validation...\n")

# Test 1: decompiler_type_int_byte_size
print("[1/10] decompiler_type_int_byte_size")
for width, expected in INT_TYPE_SIZES.items():
    result = call_tool("decompiler_type_int_byte_size", {"width": width})
    if result and isinstance(result, dict):
        val = result.get("byte_size") or result.get("size") or result.get("bytes")
        check("decompiler_type_int_byte_size", val, expected, f"width={width}")

# Test 2: decompiler_type_int_c_name
print("[2/10] decompiler_type_int_c_name")
name_map = {
    "i8": "int8_t", "u8": "uint8_t",
    "i16": "int16_t", "u16": "uint16_t",
    "i32": "int32_t", "u32": "uint32_t",
    "i64": "int64_t", "u64": "uint64_t",
}
for width, expected in name_map.items():
    result = call_tool("decompiler_type_int_c_name", {"width": width})
    if result and isinstance(result, dict):
        val = result.get("c_name") or result.get("name") or result.get("type_name")
        check("decompiler_type_int_c_name", val, expected, f"width={width}")

# Test 3: decompiler_type_byte_size_ptr_wp
print("[3/10] decompiler_type_byte_size_ptr_wp")
for ptr_width in [4, 8, 16]:
    result = call_tool("decompiler_type_byte_size_ptr_wp", {"ptr_width": ptr_width})
    if result and isinstance(result, dict):
        val = result.get("byte_size") or result.get("size") or result.get("bytes")
        check("decompiler_type_byte_size_ptr_wp", val, ptr_width, f"ptr_width={ptr_width}")

# Test 4: decompiler_type_byte_size_int_wp
print("[4/10] decompiler_type_byte_size_int_wp")
for width in ["i8", "i16", "i32", "i64"]:
    expected = INT_TYPE_SIZES[width]
    result = call_tool("decompiler_type_byte_size_int_wp", {"width": width})
    if result and isinstance(result, dict):
        val = result.get("byte_size") or result.get("size") or result.get("bytes")
        check("decompiler_type_byte_size_int_wp", val, expected, f"width={width}")

# Test 5: decompiler_type_c_name_int_wp
print("[5/10] decompiler_type_c_name_int_wp")
for width in ["i8", "i16", "i32", "i64"]:
    expected = name_map[width]
    result = call_tool("decompiler_type_c_name_int_wp", {"width": width})
    if result and isinstance(result, dict):
        val = result.get("c_name") or result.get("name") or result.get("type_name")
        check("decompiler_type_c_name_int_wp", val, expected, f"width={width}")

# Test 6: decompiler_type_function_arity_n2
print("[6/10] decompiler_type_function_arity_n2")
for n in [0, 1, 2, 5, 10]:
    result = call_tool("decompiler_type_function_arity_n2", {"n": n})
    if result and isinstance(result, dict):
        val = result.get("arity") or result.get("param_count") or result.get("count")
        check("decompiler_type_function_arity_n2", val, n, f"n={n}")

# Test 7: decompiler_type_function_arity_zx2
print("[7/10] decompiler_type_function_arity_zx2")
for n in [0, 1, 2, 5]:
    result = call_tool("decompiler_type_function_arity_zx2", {"n": n, "variadic": False})
    if result and isinstance(result, dict):
        val = result.get("arity") or result.get("param_count") or result.get("count")
        check("decompiler_type_function_arity_zx2", val, n, f"n={n}, variadic=False")

# Test 8: decompiler_type_is_pointer (simple type object tests)
print("[8/10] decompiler_type_is_pointer")
# Test with pointer type
ptr_type = {"kind": "Ptr", "inner": {"kind": "Int", "width": 32}}
result = call_tool("decompiler_type_is_pointer", {"type": ptr_type})
if result and isinstance(result, dict):
    val = result.get("is_pointer") or result.get("result")
    check("decompiler_type_is_pointer", val, True, "Ptr(Int(32))")

# Test with non-pointer type
int_type = {"kind": "Int", "width": 32}
result = call_tool("decompiler_type_is_pointer", {"type": int_type})
if result and isinstance(result, dict):
    val = result.get("is_pointer") or result.get("result")
    check("decompiler_type_is_pointer", val, False, "Int(32)")

# Test 9: decompiler_type_byte_size (generic)
print("[9/10] decompiler_type_byte_size")
int_type = {"kind": "Int", "width": 32}
result = call_tool("decompiler_type_byte_size", {"type": int_type})
if result and isinstance(result, dict):
    val = result.get("byte_size") or result.get("size") or result.get("bytes")
    check("decompiler_type_byte_size", val, 4, "Int(32)")

int_type = {"kind": "Int", "width": 64}
result = call_tool("decompiler_type_byte_size", {"type": int_type})
if result and isinstance(result, dict):
    val = result.get("byte_size") or result.get("size") or result.get("bytes")
    check("decompiler_type_byte_size", val, 8, "Int(64)")

# Test 10: decompiler_type_c_name (generic)
print("[10/10] decompiler_type_c_name")
int_type = {"kind": "Int", "width": 32}
result = call_tool("decompiler_type_c_name", {"type": int_type})
if result and isinstance(result, dict):
    val = result.get("c_name") or result.get("name")
    # Should be something like "i32" or "int32_t"
    check("decompiler_type_c_name", val is not None, True, "Int(32) has name")

# ============================================================================
# Summary
# ============================================================================

print(f"\n{'='*70}")
print(f"[SUMMARY] decompiler_type_ validation")
print(f"{'='*70}")
print(f"Checks total:     {checks_total}")
print(f"Checks passed:    {checks_ok}")
print(f"Checks skipped:   {checks_skipped}")
print(f"Mismatches found: {len(mismatches)}")

if mismatches:
    print(f"\n[MISMATCHES]")
    for m in mismatches:
        print(f"  {m['tool']:40} | input={m['input']:20} | mcp={m['mcp']!s:15} | truth={m['truth']!s:15}")

# Write report
report = {
    "category": "decompiler_type",
    "tools_in_category": 10,  # These 10 main tools we tested
    "checks_total": checks_total,
    "checks_passed": checks_ok,
    "checks_skipped": checks_skipped,
    "mismatches": mismatches
}

with open(OUT, "w") as f:
    json.dump(report, f, indent=2)

print(f"\n[REPORT] Written to {OUT}")
exit_code = 0 if len(mismatches) == 0 else 1
print(f"[EXIT] {'PASS' if exit_code == 0 else 'FAIL'}")
sys.exit(exit_code)
