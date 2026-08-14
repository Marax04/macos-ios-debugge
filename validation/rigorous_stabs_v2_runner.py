#!/usr/bin/env python3
"""
Rigorous ground-truth validation for all stabs_* MCP tools.
Each tool's expected output is computed independently from the Rust source spec
(C:/Users/Fra/Desktop/RustRE/crates/rustre-symbols-stabs/src/lib.rs).
No shelling out to external libs — pure Python table lookups matching the Rust logic.
"""

import json
import subprocess
import sys

EXE = r"C:\Users\Fra\Desktop\RustRE\target\release\rustre-mcp.exe"
TARGET = r"C:\Users\Fra\Desktop\Zyphora\target\release\cargo-zyphora.exe"
OUT_JSON = r"C:\Users\Fra\Desktop\RustRE\validation\rigorous_stabs_v2.json"
SKIP_JSON = r"C:\Users\Fra\Desktop\RustRE\validation\skip_stabs.json"

# ---------------------------------------------------------------------------
# Ground-truth tables derived verbatim from lib.rs
# ---------------------------------------------------------------------------

# StabType::name_for — complete table from lib.rs
_NAME_FOR: dict[int, str] = {
    0x00: "N_UNDF",  0x20: "N_GSYM",   0x22: "N_FNAME", 0x24: "N_FUN",
    0x26: "N_STSYM", 0x28: "N_LCSYM",  0x2A: "N_MAIN",  0x2C: "N_ROSYM",
    0x30: "N_PC",    0x32: "N_NSYMS",  0x34: "N_NOMAP", 0x38: "N_OBJ",
    0x3C: "N_OPT",   0x40: "N_RSYM",   0x42: "N_M2C",   0x44: "N_SLINE",
    0x46: "N_DSLINE",0x48: "N_BSLINE", 0x4A: "N_DEFD",  0x4C: "N_FLINE",
    0x50: "N_EHDECL",0x54: "N_CATCH",  0x60: "N_SSYM",  0x62: "N_ENDM",
    0x64: "N_SO",    0x80: "N_LSYM",   0x82: "N_BINCL", 0x84: "N_SOL",
    0xA0: "N_PSYM",  0xA2: "N_EINCL",  0xA4: "N_ENTRY", 0xC0: "N_LBRAC",
    0xC2: "N_EXCL",  0xC4: "N_SCOPE",  0xE0: "N_RBRAC", 0xE2: "N_BCOMM",
    0xE4: "N_ECOMM", 0xE8: "N_ECOML",  0xEA: "N_WITH",  0xF0: "N_NBTEXT",
    0xF2: "N_NBDATA",0xF4: "N_NBBSS",  0xF6: "N_NBSTS", 0xF8: "N_NBLCS",
}

def ref_name_for(b: int):
    """Returns (name_str_or_null, known_bool)"""
    name = _NAME_FOR.get(b)
    return name, name is not None

# StabTypeCode::from_char — lib.rs lines 416-428
_CHAR_TO_CODE: dict[str, str] = {
    'f': "Function", 'F': "GlobalFunction", 'g': "GlobalVar",
    's': "StaticVar", 'r': "RegisterVar",   'p': "Parameter",
    't': "Typedef",  'T': "Tag",            'v': "VarArray",
}
def ref_type_code_from_char(c: str) -> str:
    """Returns the Debug-format string Rust emits via {:?}."""
    return _CHAR_TO_CODE.get(c, f"Other('{c}')")

def ref_type_code_display(c: str) -> str:
    """Returns the Display-format string Rust emits via to_string()."""
    mapped = _CHAR_TO_CODE.get(c)
    if mapped is not None:
        return mapped            # Display delegates to Debug for named variants
    return f"Other({c})"        # Display: Other(c)  (no quotes around c)

# StabType::is_symbol — NFun|NGsym|NStsym|NRsym|NPsym
_SYMBOL_BYTES = {0x24, 0x20, 0x26, 0x40, 0xA0}
def ref_is_symbol(b: int) -> bool:
    return b in _SYMBOL_BYTES

# StabType::is_source_file — NSo|NSol|NBincl|NEincl
_SOURCE_FILE_BYTES = {0x64, 0x84, 0x82, 0xA2}
def ref_is_source_file(b: int) -> bool:
    return b in _SOURCE_FILE_BYTES

# StabType::is_line_number — NSline|NDsline|NBsline|NFline
_LINE_NUMBER_BYTES = {0x44, 0x46, 0x48, 0x4C}
def ref_is_line_number(b: int) -> bool:
    return b in _LINE_NUMBER_BYTES

# StabType::is_scope_bracket — NLbrac|NRbrac
_SCOPE_BYTES = {0xC0, 0xE0}
def ref_is_scope_bracket(b: int) -> bool:
    return b in _SCOPE_BYTES

def ref_category(b: int) -> str:
    if ref_is_symbol(b):       return "symbol"
    if ref_is_source_file(b):  return "file"
    if ref_is_line_number(b):  return "line"
    if ref_is_scope_bracket(b):return "scope"
    return "other"

# StabType::name (for .name() accessor used in is_symbol/category/etc tools)
def ref_name(b: int) -> str:
    return _NAME_FOR.get(b, "Unknown")

# ---------------------------------------------------------------------------
# MCP communication helpers (mirrors exercise_v3.py style)
# ---------------------------------------------------------------------------

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

def call_tool(name: str, arguments: dict):
    global _rid
    _rid += 1
    send({"jsonrpc": "2.0", "id": _rid, "method": "tools/call",
          "params": {"name": name, "arguments": arguments}})
    resp = recv()
    if "error" in resp:
        return None, str(resp["error"])
    result = resp.get("result", {})
    is_err = result.get("isError", False)
    content = result.get("content", [])
    txt = content[0].get("text", "") if content else ""
    if is_err:
        return None, txt
    try:
        return json.loads(txt), None
    except Exception:
        return txt, None

# Initialize
_rid = 0
send({"jsonrpc": "2.0", "id": 1, "method": "initialize",
      "params": {"protocolVersion": "2024-11-05",
                 "capabilities": {},
                 "clientInfo": {"name": "rigorous_stabs", "version": "1"}}})
recv()
send({"jsonrpc": "2.0", "method": "notifications/initialized"})
_rid = 1

# Open a project so any tool that might need context doesn't error
send({"jsonrpc": "2.0", "id": 2, "method": "tools/call",
      "params": {"name": "project.open", "arguments": {"path": TARGET}}})
_op = recv()
_rid = 2

# ---------------------------------------------------------------------------
# Test cases
# ---------------------------------------------------------------------------

results = []
mismatches = []
skipped = []

def check(tool_name: str, args: dict, expected_fields: dict):
    """Call tool, parse JSON, compare expected_fields key by key."""
    actual, err = call_tool(tool_name, args)
    if err is not None:
        results.append({"tool": tool_name, "args": args,
                        "status": "FAIL", "reason": f"tool_error: {err}"})
        mismatches.append({"tool": tool_name, "args": args,
                           "expected": expected_fields, "actual": f"TOOL_ERROR: {err}"})
        return
    if actual is None:
        results.append({"tool": tool_name, "args": args,
                        "status": "FAIL", "reason": "null response"})
        mismatches.append({"tool": tool_name, "args": args,
                           "expected": expected_fields, "actual": None})
        return
    mismatched = {}
    for k, v in expected_fields.items():
        got = actual.get(k)
        if got != v:
            mismatched[k] = {"expected": v, "actual": got}
    if mismatched:
        results.append({"tool": tool_name, "args": args,
                        "status": "FAIL", "fields": mismatched, "full_actual": actual})
        mismatches.append({"tool": tool_name, "args": args,
                           "expected": expected_fields, "actual": actual,
                           "field_mismatches": mismatched})
    else:
        results.append({"tool": tool_name, "args": args, "status": "PASS"})

# ---------------------------------------------------------------------------
# 1. stabs_type_name_for
# ---------------------------------------------------------------------------
# Test known bytes
for b, expected_name in [(0x00, "N_UNDF"), (0x24, "N_FUN"), (0x64, "N_SO"),
                          (0x84, "N_SOL"), (0xA0, "N_PSYM"), (0xE0, "N_RBRAC"),
                          (0xF8, "N_NBLCS")]:
    check("stabs_type_name_for", {"byte": b},
          {"byte": b, "name": expected_name, "known": True})

# Test unknown byte
name_unk, known_unk = ref_name_for(0x01)
check("stabs_type_name_for", {"byte": 0x01},
      {"byte": 0x01, "name": name_unk, "known": False})

# ---------------------------------------------------------------------------
# 2. stabs_type_code_from_char
# ---------------------------------------------------------------------------
for ch, code_str, display_str in [
    ('f', "Function",       "Function"),
    ('F', "GlobalFunction", "GlobalFunction"),
    ('g', "GlobalVar",      "GlobalVar"),
    ('s', "StaticVar",      "StaticVar"),
    ('r', "RegisterVar",    "RegisterVar"),
    ('p', "Parameter",      "Parameter"),
    ('t', "Typedef",        "Typedef"),
    ('T', "Tag",            "Tag"),
    ('v', "VarArray",       "VarArray"),
    ('x', "Other('x')",     "Other(x)"),  # unknown char
]:
    check("stabs_type_code_from_char", {"ch": ch},
          {"input": ch, "code": code_str, "display": display_str})

# ---------------------------------------------------------------------------
# 3. stabs_is_symbol
# ---------------------------------------------------------------------------
# True for: NFun=0x24, NGsym=0x20, NStsym=0x26, NRsym=0x40, NPsym=0xA0
for b, expected in [(0x24, True), (0x20, True), (0x26, True),
                    (0x40, True), (0xA0, True),
                    (0x64, False), (0x44, False), (0x01, False)]:
    check("stabs_is_symbol", {"n_type": b},
          {"n_type": b, "name": ref_name(b), "is_symbol": expected})

# ---------------------------------------------------------------------------
# 4. stabs_category
# ---------------------------------------------------------------------------
test_cases_cat = [
    (0x24, "symbol"),  # N_FUN
    (0x20, "symbol"),  # N_GSYM
    (0x64, "file"),    # N_SO
    (0x84, "file"),    # N_SOL
    (0x82, "file"),    # N_BINCL
    (0xA2, "file"),    # N_EINCL
    (0x44, "line"),    # N_SLINE
    (0x46, "line"),    # N_DSLINE
    (0x48, "line"),    # N_BSLINE
    (0x4C, "line"),    # N_FLINE
    (0xC0, "scope"),   # N_LBRAC
    (0xE0, "scope"),   # N_RBRAC
    (0x00, "other"),   # N_UNDF
    (0x01, "other"),   # Unknown
]
for b, expected_cat in test_cases_cat:
    check("stabs_category", {"n_type": b},
          {"n_type": b, "name": ref_name(b), "category": expected_cat})

# ---------------------------------------------------------------------------
# 5. stabs_is_source_file
# ---------------------------------------------------------------------------
for b, expected in [(0x64, True), (0x84, True), (0x82, True), (0xA2, True),
                    (0x24, False), (0x44, False), (0x01, False)]:
    check("stabs_is_source_file", {"n_type": b},
          {"n_type": b, "name": ref_name(b), "is_source_file": expected})

# ---------------------------------------------------------------------------
# 6. stabs_is_line_number
# ---------------------------------------------------------------------------
for b, expected in [(0x44, True), (0x46, True), (0x48, True), (0x4C, True),
                    (0x24, False), (0x64, False), (0x01, False)]:
    check("stabs_is_line_number", {"n_type": b},
          {"n_type": b, "name": ref_name(b), "is_line_number": expected})

# ---------------------------------------------------------------------------
# Teardown
# ---------------------------------------------------------------------------
p.stdin.close()
p.terminate()

# ---------------------------------------------------------------------------
# Summarise
# ---------------------------------------------------------------------------
tools_hardened = 6   # 6 distinct tools validated
passed  = sum(1 for r in results if r["status"] == "PASS")
failed  = sum(1 for r in results if r["status"] == "FAIL")
skipped_count = len(skipped)

print(f"Tests run: {len(results)}")
print(f"PASS: {passed}  FAIL: {failed}  SKIP: {skipped_count}")
if mismatches:
    print("\nMISMATCHES:")
    for m in mismatches:
        print(f"  tool={m['tool']}  args={m.get('args')}  expected={m.get('expected')}  actual={m.get('actual')}")

# Write output files
with open(OUT_JSON, "w") as f:
    json.dump({
        "summary": {
            "tools_hardened": tools_hardened,
            "tests_run": len(results),
            "passed": passed,
            "failed": failed,
            "skipped": skipped_count,
        },
        "mismatches": mismatches,
        "all_results": results,
    }, f, indent=2)

with open(SKIP_JSON, "w") as f:
    json.dump(skipped, f, indent=2)

print(f"\nResults written to: {OUT_JSON}")
sys.exit(0 if failed == 0 else 1)
