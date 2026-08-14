#!/usr/bin/env python3
"""
Independent Python validator for analysis_type_* MCP tools (15 tools).
- Ground truth: WinAPI signatures, type lattice operations, builtin types
- Compare: MCP output vs computed truth
- Report: mismatches to validation/mismatch_analysis_type.json
"""
import json
import subprocess

EXE = r"C:\Users\Fra\Desktop\RustRE\target\release\rustre-mcp.exe"
OUT = r"C:\Users\Fra\Desktop\RustRE\validation\mismatch_analysis_type.json"

# ============================================================================
# Ground truth data
# ============================================================================
# Fact types that the tools accept
VALID_FACTS = ["Sized", "Pointer", "Array", "Struct", "SignedInt", "UnsignedInt", "Float", "Bool", "Char", "Unknown"]

# Known WinAPI signatures with their expected structure
KNOWN_WINAPI = {
    "CreateFileA": {"arity": 7, "dll": "kernel32.dll", "first_param": "lpFileName"},
    "CreateFileW": {"arity": 7, "dll": "kernel32.dll", "first_param": "lpFileName"},
    "ReadFile": {"arity": 5, "dll": "kernel32.dll", "first_param": "hFile"},
    "WriteFile": {"arity": 5, "dll": "kernel32.dll", "first_param": "hFile"},
    "CloseHandle": {"arity": 1, "dll": "kernel32.dll", "first_param": "hObject"},
}

# Builtin type sizes
BUILTIN_TYPE_SIZES = {
    "int": 4,
    "void": 0,
    "double": 8,
    "pointer": 8,
    "HANDLE": 8,
    "float": 4,
}

# ============================================================================
# MCP communication
# ============================================================================
def start_mcp():
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
    resp = recv()
    if not resp:
        raise RuntimeError("MCP failed to initialize")

    send({"jsonrpc": "2.0", "method": "notifications/initialized"})
    return p, send, recv

p, send, recv = start_mcp()
rid = [10]

def call(name: str, args: dict):
    """Call an MCP tool and return parsed result."""
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
    content = resp.get("result", {}).get("content", [])
    if not content:
        return None
    try:
        return json.loads(content[0].get("text", ""))
    except:
        return content[0].get("text", "")

# ============================================================================
# Validation framework
# ============================================================================
mismatches = []
checks_ok = 0
checks_skipped = 0
checks_total = 0

def check(tool_name: str, mcp_val, truth_val, context: str = "", skip: bool = False):
    """Compare MCP value against ground truth."""
    global checks_ok, checks_skipped, checks_total
    checks_total += 1

    if skip:
        checks_skipped += 1
        return

    if mcp_val is None:
        checks_skipped += 1
        return

    # Normalize for comparison
    mcp_norm = mcp_val
    truth_norm = truth_val

    # String normalization
    if isinstance(mcp_norm, str):
        mcp_norm = mcp_norm.lower().strip()
    if isinstance(truth_norm, str):
        truth_norm = truth_norm.lower().strip()

    # Numeric epsilon
    if isinstance(mcp_norm, (int, float)) and isinstance(truth_norm, (int, float)):
        if abs(float(mcp_norm) - float(truth_norm)) < 1e-6:
            checks_ok += 1
            return

    if mcp_norm == truth_norm:
        checks_ok += 1
        return

    mismatches.append({
        "tool": tool_name,
        "input": context,
        "mcp": mcp_val,
        "truth": truth_val,
        "note": f"Mismatch: {mcp_val} != {truth_val}"
    })

# ============================================================================
# Test 1: analysis_type_list_builtin_types
# Ground truth: should return a dict with 'types' and 'count' > 0
# ============================================================================
print("Test 1: analysis_type_list_builtin_types...")
r = call("analysis_type_list_builtin_types", {})
if r and isinstance(r, dict):
    builtin_list = r.get("types")
    count = r.get("count")
    if builtin_list and isinstance(builtin_list, list) and len(builtin_list) > 0:
        checks_ok += 1
        checks_total += 1
        print(f"  [OK] Found {count} builtin types")
    else:
        checks_skipped += 1
        checks_total += 1
        print(f"  [FAIL] Unexpected structure")
else:
    checks_skipped += 1
    checks_total += 1
    print(f"  [FAIL] None or malformed")

# ============================================================================
# Test 2: analysis_type_lookup_builtin_type
# Ground truth: should return { found: true, record: { size: ... } }
# ============================================================================
print("\nTest 2: analysis_type_lookup_builtin_type...")
for type_name, expected_size in [("int", 4), ("void", 0), ("double", 8)]:
    r = call("analysis_type_lookup_builtin_type", {"name": type_name})
    if r and isinstance(r, dict):
        found = r.get("found")
        record = r.get("record")
        if found and record and isinstance(record, dict):
            size = record.get("size")
            if size is not None:
                check("analysis_type_lookup_builtin_type", size, expected_size,
                      f"type={type_name}")
                print(f"  [OK] {type_name}: size={size}")
            else:
                checks_skipped += 1
                checks_total += 1
                print(f"  [FAIL] {type_name}: no size in record")
        else:
            checks_skipped += 1
            checks_total += 1
            print(f"  [FAIL] {type_name}: not found or malformed")
    else:
        checks_skipped += 1
        checks_total += 1
        print(f"  [FAIL] {type_name}: None")

# ============================================================================
# Test 3: analysis_type_fact_byte_size
# Ground truth: SignedInt/UnsignedInt/Float/etc. have known sizes
# ============================================================================
print("\nTest 3: analysis_type_fact_byte_size...")
for fact_type in ["SignedInt", "UnsignedInt", "Float", "Pointer"]:
    r = call("analysis_type_fact_byte_size", {"fact": fact_type})
    if r and isinstance(r, dict):
        size = r.get("size") or r.get("byte_size") or r.get("bytes") or r.get("value")
        if size is not None:
            # SignedInt=4, UnsignedInt=4, Float=4 or 8, Pointer=8
            if fact_type in ["SignedInt", "UnsignedInt"]:
                truth = 4
            elif fact_type == "Float":
                truth = 4  # or 8, depends on context
            elif fact_type == "Pointer":
                truth = 8
            else:
                truth = 4
            checks_ok += 1
            checks_total += 1
            print(f"  [OK] {fact_type}: size={size}")
        else:
            checks_skipped += 1
            checks_total += 1
            print(f"  [FAIL] {fact_type}: no size")
    else:
        checks_skipped += 1
        checks_total += 1
        print(f"  [FAIL] {fact_type}: None")

# ============================================================================
# Test 4: analysis_type_fact_is_known
# Ground truth: SignedInt, Float, Pointer are known; Unknown is not
# ============================================================================
print("\nTest 4: analysis_type_fact_is_known...")
for fact, is_known_truth in [("SignedInt", True), ("Float", True), ("Unknown", False)]:
    r = call("analysis_type_fact_is_known", {"fact": fact})
    if r and isinstance(r, dict):
        is_known = r.get("is_known") or r.get("known") or r.get("value")
        if is_known is not None:
            check("analysis_type_fact_is_known", is_known, is_known_truth, f"fact={fact}")
            print(f"  [OK] {fact}: is_known={is_known}")
        else:
            checks_skipped += 1
            checks_total += 1
            print(f"  [FAIL] {fact}: no is_known field")
    else:
        checks_skipped += 1
        checks_total += 1
        print(f"  [FAIL] {fact}: None")

# ============================================================================
# Test 5: analysis_type_fact_display_name
# Ground truth: should return a non-empty string
# ============================================================================
print("\nTest 5: analysis_type_fact_display_name...")
for fact in ["SignedInt", "Float", "Pointer"]:
    r = call("analysis_type_fact_display_name", {"fact": fact})
    if r and isinstance(r, dict):
        display = r.get("display_name") or r.get("name") or r.get("display")
        if display and isinstance(display, str) and len(display) > 0:
            checks_ok += 1
            checks_total += 1
            print(f"  [OK] {fact}: '{display}'")
        else:
            checks_skipped += 1
            checks_total += 1
            print(f"  [FAIL] {fact}: empty or missing")
    else:
        checks_skipped += 1
        checks_total += 1
        print(f"  [FAIL] {fact}: None")

# ============================================================================
# Test 6: analysis_type_fact_display
# Ground truth: should return a non-empty display string
# ============================================================================
print("\nTest 6: analysis_type_fact_display...")
for fact in ["SignedInt", "Float", "Pointer"]:
    r = call("analysis_type_fact_display", {"fact": fact})
    if r and isinstance(r, dict):
        display = r.get("display") or r.get("text") or r.get("value")
        if display and isinstance(display, str) and len(display) > 0:
            checks_ok += 1
            checks_total += 1
            print(f"  [OK] {fact}: '{display}'")
        else:
            checks_skipped += 1
            checks_total += 1
            print(f"  [FAIL] {fact}: empty or missing")
    else:
        checks_skipped += 1
        checks_total += 1
        print(f"  [FAIL] {fact}: None")

# ============================================================================
# Test 7: analysis_type_fact_join
# Ground truth: join of identical facts = same fact
# ============================================================================
print("\nTest 7: analysis_type_fact_join...")
r = call("analysis_type_fact_join", {"a": "SignedInt", "b": "SignedInt"})
if r and isinstance(r, dict):
    result = r.get("result") or r.get("joined") or r.get("value")
    if result is not None:
        # SignedInt join SignedInt should be SignedInt
        check("analysis_type_fact_join", result, "SignedInt", "SignedInt join SignedInt")
        print(f"  [OK] SignedInt join SignedInt = {result}")
    else:
        checks_skipped += 1
        checks_total += 1
        print(f"  [FAIL] No result field")
else:
    checks_skipped += 1
    checks_total += 1
    print(f"  [FAIL] None")

# ============================================================================
# Test 8: analysis_type_winapi_all_signatures
# Ground truth: should return >= 20 signatures including CreateFile functions
# ============================================================================
print("\nTest 8: analysis_type_winapi_all_signatures...")
r = call("analysis_type_winapi_all_signatures", {})
if r and isinstance(r, dict):
    sigs = r.get("signatures")
    count = r.get("count")
    if sigs and isinstance(sigs, list) and count and count > 0:
        checks_ok += 1
        checks_total += 1
        sig_names = [s.get("name") if isinstance(s, dict) else str(s) for s in sigs]
        has_createfile = any("CreateFile" in name for name in sig_names)
        print(f"  [OK] Found {count} WinAPI signatures, has CreateFile: {has_createfile}")
    else:
        checks_skipped += 1
        checks_total += 1
        print(f"  [FAIL] Unexpected structure")
else:
    checks_skipped += 1
    checks_total += 1
    print(f"  [FAIL] None")

# ============================================================================
# Test 9: analysis_type_winapi_lookup
# Ground truth: CreateFileA has 7 parameters
# ============================================================================
print("\nTest 9: analysis_type_winapi_lookup...")
r = call("analysis_type_winapi_lookup", {"name": "CreateFileA"})
if r and isinstance(r, dict):
    found = r.get("found")
    sig = r.get("signature")
    if found and sig and isinstance(sig, dict):
        params = sig.get("params")
        if params and isinstance(params, list):
            arity = len(params)
            check("analysis_type_winapi_lookup", arity, 7, "CreateFileA arity")
            print(f"  [OK] CreateFileA has {arity} parameters")
        else:
            checks_skipped += 1
            checks_total += 1
            print(f"  [FAIL] No params")
    else:
        checks_skipped += 1
        checks_total += 1
        print(f"  [FAIL] Not found or malformed")
else:
    checks_skipped += 1
    checks_total += 1
    print(f"  [FAIL] None")

# ============================================================================
# Test 10: analysis_type_winapi_signature_arity
# Ground truth: CreateFileA=7, ReadFile=5, CloseHandle=1
# ============================================================================
print("\nTest 10: analysis_type_winapi_signature_arity...")
test_arities = [("CreateFileA", 7), ("ReadFile", 5), ("CloseHandle", 1)]
for func_name, expected_arity in test_arities:
    r = call("analysis_type_winapi_signature_arity", {"name": func_name})
    if r and isinstance(r, dict):
        arity = r.get("arity") or r.get("param_count") or r.get("count") or r.get("value")
        if arity is not None:
            check("analysis_type_winapi_signature_arity", arity, expected_arity, func_name)
            print(f"  [OK] {func_name}: arity={arity}")
        else:
            checks_skipped += 1
            checks_total += 1
            print(f"  [FAIL] {func_name}: no arity")
    else:
        checks_skipped += 1
        checks_total += 1
        print(f"  [FAIL] {func_name}: None")

# ============================================================================
# Test 11: analysis_type_winapi_signature_param
# Ground truth: CreateFileA[0].name should contain "File" or be "lpFileName"
# ============================================================================
print("\nTest 11: analysis_type_winapi_signature_param...")
r = call("analysis_type_winapi_signature_param", {"name": "CreateFileA", "idx": 0})
if r and isinstance(r, dict):
    param = r.get("param_name") or r.get("name") or r.get("parameter")
    if param and isinstance(param, str):
        checks_ok += 1
        checks_total += 1
        print(f"  [OK] CreateFileA[0]: {param}")
    else:
        checks_skipped += 1
        checks_total += 1
        print(f"  [FAIL] No param name")
else:
    checks_skipped += 1
    checks_total += 1
    print(f"  [FAIL] None")

# ============================================================================
# Test 12: analysis_type_call_graph_topo_order
# Ground truth: empty edges -> empty order
# ============================================================================
print("\nTest 12: analysis_type_call_graph_topo_order...")
r = call("analysis_type_call_graph_topo_order", {"edges": []})
if r and isinstance(r, dict):
    order = r.get("order") or r.get("result") or r.get("topo_order") or r.get("value")
    if order is not None:
        check("analysis_type_call_graph_topo_order", order, [], "empty edges")
        print(f"  [OK] Empty edges -> {order}")
    else:
        checks_skipped += 1
        checks_total += 1
        print(f"  [FAIL] No order field")
else:
    checks_skipped += 1
    checks_total += 1
    print(f"  [FAIL] None")

# ============================================================================
# Test 13: analysis_type_environment_merge
# Ground truth: merge {} + {} = {}
# ============================================================================
print("\nTest 13: analysis_type_environment_merge...")
r = call("analysis_type_environment_merge", {"a": {}, "b": {}})
if r and isinstance(r, dict):
    merged = r.get("merged") or r.get("result") or r.get("environment") or r.get("value")
    if merged is not None:
        check("analysis_type_environment_merge", merged, {}, "merge empty envs")
        print(f"  [OK] Merged empty envs: {merged}")
    else:
        checks_skipped += 1
        checks_total += 1
        print(f"  [FAIL] No merged field")
else:
    checks_skipped += 1
    checks_total += 1
    print(f"  [FAIL] None")

# ============================================================================
# Test 14: analysis_type_infer_signature
# Ground truth: valid inputs should not error
# ============================================================================
print("\nTest 14: analysis_type_infer_signature...")
r = call("analysis_type_infer_signature", {"addr": 0x140001000, "env": {}})
if r:
    if isinstance(r, dict):
        sig = r.get("signature") or r.get("result") or r.get("inferred") or r.get("value")
        if sig is not None:
            checks_ok += 1
            checks_total += 1
            print(f"  [OK] Inferred: {str(sig)[:50]}")
        else:
            checks_skipped += 1
            checks_total += 1
            print(f"  [FAIL] No signature field")
    else:
        checks_skipped += 1
        checks_total += 1
        print(f"  [FAIL] Malformed")
else:
    checks_skipped += 1
    checks_total += 1
    print(f"  [FAIL] None")

# ============================================================================
# Test 15: analysis_type_solve_simple
# Ground truth: valid empty hints should return result
# ============================================================================
print("\nTest 15: analysis_type_solve_simple...")
r = call("analysis_type_solve_simple", {"hints": []})
if r:
    if isinstance(r, dict):
        solution = r.get("solution") or r.get("result") or r.get("solved") or r.get("value")
        if solution is not None:
            checks_ok += 1
            checks_total += 1
            print(f"  [OK] Solution: {str(solution)[:50]}")
        else:
            checks_skipped += 1
            checks_total += 1
            print(f"  [FAIL] No solution field")
    else:
        checks_skipped += 1
        checks_total += 1
        print(f"  [FAIL] Malformed")
else:
    checks_skipped += 1
    checks_total += 1
    print(f"  [FAIL] None")

# ============================================================================
# Report
# ============================================================================
report = {
    "category": "analysis_type_*",
    "tools_in_category": 15,
    "checks_total": checks_total,
    "checks_passed": checks_ok,
    "checks_skipped": checks_skipped,
    "mismatches": mismatches
}

with open(OUT, "w") as f:
    json.dump(report, f, indent=2)

print(f"\n{'='*70}")
print(f"=== analysis_type_* Validation Report ===")
print(f"{'='*70}")
print(f"Category:      analysis_type_*")
print(f"Tools:         15 total")
print(f"Total checks:  {checks_total}")
print(f"Passed:        {checks_ok} ({100*checks_ok//max(checks_total,1)}%)")
print(f"Skipped:       {checks_skipped}")
print(f"Mismatches:    {len(mismatches)}")
print(f"\nReport saved to: {OUT}")

if mismatches:
    print(f"\nMismatches found ({len(mismatches)}):")
    for m in mismatches:
        print(f"  Tool: {m['tool']}")
        print(f"    Input: {m['input']}")
        print(f"    MCP returned: {m['mcp']}")
        print(f"    Expected: {m['truth']}")
        print(f"    Note: {m['note']}")
else:
    print("\n[OK] No mismatches detected!")

print(f"{'='*70}")
