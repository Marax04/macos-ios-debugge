#!/usr/bin/env python3
"""
Rigorous validator for dotnet_metadata_ MCP tools in RustRE.

Calls rustre-mcp.exe --transport=stdio and compares outputs against
independently computed Python truth values derived from ECMA-335 spec.

No pefile required. All truth is computed from the spec directly.
"""

import json
import subprocess
import sys
from pathlib import Path

MCP_EXE = r"C:\Users\Fra\Desktop\RustRE\target\release\rustre-mcp.exe"
REPORT_OUT = Path(r"C:\Users\Fra\Desktop\RustRE\validation\rigorous_dotnet_metadata.json")

# ─── MCP stdio helpers ───────────────────────────────────────────────────────

proc = subprocess.Popen(
    [MCP_EXE, "--transport=stdio"],
    stdin=subprocess.PIPE,
    stdout=subprocess.PIPE,
    stderr=subprocess.DEVNULL,
    bufsize=0,
)

_rid = 0

def send(req: dict):
    line = json.dumps(req) + "\n"
    proc.stdin.write(line.encode())
    proc.stdin.flush()

def recv() -> dict:
    line = proc.stdout.readline()
    if not line:
        raise RuntimeError("MCP server died")
    return json.loads(line)

def call_tool(name: str, args: dict) -> dict:
    global _rid
    _rid += 1
    send({"jsonrpc": "2.0", "id": _rid, "method": "tools/call",
          "params": {"name": name, "arguments": args}})
    resp = recv()
    if "error" in resp:
        return {"__mcp_error__": resp["error"]}
    content = resp.get("result", {}).get("content", [{}])
    text = content[0].get("text", "{}") if content else "{}"
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return {"__raw__": text}

# Initialize MCP session
send({"jsonrpc": "2.0", "id": 1, "method": "initialize",
      "params": {"protocolVersion": "2024-11-05", "capabilities": {},
                 "clientInfo": {"name": "rigorous-dotnet", "version": "1"}}})
recv()
send({"jsonrpc": "2.0", "method": "notifications/initialized"})
_rid = 1

# ─── Test helpers ────────────────────────────────────────────────────────────

checks_passed = 0
checks_failed = 0
mismatches = []
tools_hardened = set()

def check(tool: str, description: str, got, expected, key: str = None):
    """
    Assert got == expected (or got[key] == expected if key given).
    Records pass/fail and appends mismatch if needed.
    """
    global checks_passed, checks_failed
    tools_hardened.add(tool)
    actual = got.get(key) if key and isinstance(got, dict) else got
    if "__mcp_error__" in (got if isinstance(got, dict) else {}):
        checks_failed += 1
        mismatches.append({
            "tool": tool,
            "description": description,
            "error": got["__mcp_error__"],
        })
        print(f"  FAIL (MCP error): {description}")
        return
    if actual == expected:
        checks_passed += 1
        print(f"  PASS: {description}")
    else:
        checks_failed += 1
        mismatches.append({
            "tool": tool,
            "description": description,
            "expected": expected,
            "got": actual,
            "full_response": got,
        })
        print(f"  MISMATCH: {description}")
        print(f"    expected={expected!r}")
        print(f"    got     ={actual!r}")

# ─── Tests ───────────────────────────────────────────────────────────────────

print("\n=== dotnet_metadata rigorous validator ===\n")

# ── 1. parse_field_sig_blob: field of type int (0x08) ────────────────────────
# ECMA-335 §II.23.2.4: FieldSig = 0x06 <Type>; ElementType.I4 = 0x08 → "int"
print("[1] dotnet_metadata_parse_field_sig_blob — int field")
r = call_tool("dotnet_metadata_parse_field_sig_blob", {"blob_hex": "0608"})
check("dotnet_metadata_parse_field_sig_blob", "FieldSig(0x06 0x08) → type_name='int'",
      r, "int", key="type_name")

# ── 2. parse_field_sig_blob: field of type string (0x0E) ─────────────────────
print("[2] dotnet_metadata_parse_field_sig_blob — string field")
r = call_tool("dotnet_metadata_parse_field_sig_blob", {"blob_hex": "060e"})
check("dotnet_metadata_parse_field_sig_blob", "FieldSig(0x06 0x0E) → type_name='string'",
      r, "string", key="type_name")

# ── 3. parse_field_sig_blob: field of type bool (0x02) ───────────────────────
print("[3] dotnet_metadata_parse_field_sig_blob — bool field")
r = call_tool("dotnet_metadata_parse_field_sig_blob", {"blob_hex": "0602"})
check("dotnet_metadata_parse_field_sig_blob", "FieldSig(0x06 0x02) → type_name='bool'",
      r, "bool", key="type_name")

# ── 4. parse_field_sig_blob: field of type double (0x0D) ─────────────────────
print("[4] dotnet_metadata_parse_field_sig_blob — double field")
r = call_tool("dotnet_metadata_parse_field_sig_blob", {"blob_hex": "060d"})
check("dotnet_metadata_parse_field_sig_blob", "FieldSig(0x06 0x0D) → type_name='double'",
      r, "double", key="type_name")

# ── 5. parse_method_sig_blob: default CC, 0 params, void return ──────────────
# ECMA-335 §II.23.2.1: CallingConvention=0x00, ParamCount=0, RetType=void(0x01)
print("[5] dotnet_metadata_parse_method_sig_blob — () void, default CC")
r = call_tool("dotnet_metadata_parse_method_sig_blob", {"blob_hex": "000001"})
check("dotnet_metadata_parse_method_sig_blob", "MethodSig(0x00 0x00 0x01) → is_instance=false",
      r, False, key="is_instance")
check("dotnet_metadata_parse_method_sig_blob", "MethodSig(0x00 0x00 0x01) → return_type='void'",
      r, "void", key="return_type")
check("dotnet_metadata_parse_method_sig_blob", "MethodSig(0x00 0x00 0x01) → params=[]",
      r, [], key="params")

# ── 6. parse_method_sig_blob: HasThis, 0 params, void return ─────────────────
# CallingConvention=0x20 (HasThis), ParamCount=0, RetType=void(0x01)
print("[6] dotnet_metadata_parse_method_sig_blob — () void, HasThis")
r = call_tool("dotnet_metadata_parse_method_sig_blob", {"blob_hex": "200001"})
check("dotnet_metadata_parse_method_sig_blob", "MethodSig(0x20 0x00 0x01) → is_instance=true",
      r, True, key="is_instance")

# ── 7. parse_method_sig_blob: 1 param int, void return ───────────────────────
# CallingConvention=0x00, ParamCount=1, RetType=void(0x01), Param=int(0x08)
print("[7] dotnet_metadata_parse_method_sig_blob — (int) void")
r = call_tool("dotnet_metadata_parse_method_sig_blob", {"blob_hex": "00010108"})
check("dotnet_metadata_parse_method_sig_blob", "MethodSig(0x00 0x01 0x01 0x08) → params=['int']",
      r, ["int"], key="params")

# ── 8. parse_local_var_sig: 1 local int ──────────────────────────────────────
# ECMA-335 §II.23.2.6: LOCAL_SIG=0x07, Count=1, Type=int(0x08)
print("[8] dotnet_metadata_parse_local_var_sig — 1 local int")
r = call_tool("dotnet_metadata_parse_local_var_sig", {"blob_hex": "070108"})
check("dotnet_metadata_parse_local_var_sig", "LocalVarSig(0x07 0x01 0x08) → count=1",
      r, 1, key="count")
check("dotnet_metadata_parse_local_var_sig", "LocalVarSig(0x07 0x01 0x08) → locals=['int']",
      r, ["int"], key="locals")

# ── 9. parse_local_var_sig: 2 locals int+string ──────────────────────────────
print("[9] dotnet_metadata_parse_local_var_sig — 2 locals int+string")
r = call_tool("dotnet_metadata_parse_local_var_sig", {"blob_hex": "0702080e"})
check("dotnet_metadata_parse_local_var_sig", "LocalVarSig(int,string) → count=2",
      r, 2, key="count")
check("dotnet_metadata_parse_local_var_sig", "LocalVarSig(int,string) → locals=['int','string']",
      r, ["int", "string"], key="locals")

# ── 10. pretty_print_type_sig: I4 (0x08) ─────────────────────────────────────
# ElementType.I4 = 0x08 → "int"
print("[10] dotnet_metadata_pretty_print_type_sig — 0x08 → int")
r = call_tool("dotnet_metadata_pretty_print_type_sig", {"blob_hex": "08"})
check("dotnet_metadata_pretty_print_type_sig", "TypeSig(0x08) → 'int'",
      r, "int", key="pretty")

# ── 11. pretty_print_type_sig: String (0x0E) ─────────────────────────────────
print("[11] dotnet_metadata_pretty_print_type_sig — 0x0e → string")
r = call_tool("dotnet_metadata_pretty_print_type_sig", {"blob_hex": "0e"})
check("dotnet_metadata_pretty_print_type_sig", "TypeSig(0x0E) → 'string'",
      r, "string", key="pretty")

# ── 12. pretty_print_type_sig: Boolean (0x02) ────────────────────────────────
print("[12] dotnet_metadata_pretty_print_type_sig — 0x02 → bool")
r = call_tool("dotnet_metadata_pretty_print_type_sig", {"blob_hex": "02"})
check("dotnet_metadata_pretty_print_type_sig", "TypeSig(0x02) → 'bool'",
      r, "bool", key="pretty")

# ── 13. parse_array_shape: rank=1, no sizes, no bounds ───────────────────────
# ECMA-335 §II.23.2.13: Rank=1 (compressed), NumSizes=0, NumLoBounds=0
print("[13] dotnet_metadata_parse_array_shape — rank=1 [][]")
r = call_tool("dotnet_metadata_parse_array_shape", {"blob_hex": "010000"})
check("dotnet_metadata_parse_array_shape", "ArrayShape(rank=1, sizes=[], lo=[]) → rank=1",
      r, 1, key="rank")
check("dotnet_metadata_parse_array_shape", "ArrayShape(rank=1) → sizes=[]",
      r, [], key="sizes")
check("dotnet_metadata_parse_array_shape", "ArrayShape(rank=1) → lower_bounds=[]",
      r, [], key="lower_bounds")

# ── 14. parse_array_shape: rank=2 ────────────────────────────────────────────
print("[14] dotnet_metadata_parse_array_shape — rank=2")
r = call_tool("dotnet_metadata_parse_array_shape", {"blob_hex": "020000"})
check("dotnet_metadata_parse_array_shape", "ArrayShape(rank=2, no sizes/bounds) → rank=2",
      r, 2, key="rank")

# ── 15. parse_custom_attribute_blob: minimal prolog, 0 named args ─────────────
# ECMA-335 §II.23.3: prolog=0x0001, then fixed args (none), then NamedArgCount (u16 LE)
# blob: 01 00 00 00 → prolog OK, 0 fixed (no method sig), 0 named args
print("[15] dotnet_metadata_parse_custom_attribute_blob — minimal prolog")
r = call_tool("dotnet_metadata_parse_custom_attribute_blob", {"blob_hex": "01000000"})
check("dotnet_metadata_parse_custom_attribute_blob",
      "CustomAttributeBlob(prolog=0x0001, 0 named) → fixed_arg_count=0",
      r, 0, key="fixed_arg_count")
check("dotnet_metadata_parse_custom_attribute_blob",
      "CustomAttributeBlob(prolog=0x0001, 0 named) → named_arg_count=0",
      r, 0, key="named_arg_count")

# ── 16. parse_method_body: tiny format, 1-byte body (ret=0x2A) ───────────────
# Tiny header: low 2 bits = 0b10, code_size = byte >> 2
# 0x06 = 0b00000110 → bits[1:0]=10 (tiny), code_size = 6>>2 = 1
# Body = [0x06, 0x2A]; offset=0
print("[16] dotnet_metadata_parse_method_body — tiny format, 1 byte")
r = call_tool("dotnet_metadata_parse_method_body", {"image_hex": "062a", "file_offset": 0})
check("dotnet_metadata_parse_method_body", "TinyMethodBody → code_size=1",
      r, 1, key="code_size")
check("dotnet_metadata_parse_method_body", "TinyMethodBody → init_locals=false",
      r, False, key="init_locals")
check("dotnet_metadata_parse_method_body", "TinyMethodBody → max_stack=8",
      r, 8, key="max_stack")
check("dotnet_metadata_parse_method_body", "TinyMethodBody → exception_clause_count=0",
      r, 0, key="exception_clause_count")

# ── 17. parse_method_body: tiny format, 3-byte body ──────────────────────────
# 0x0E = 0b00001110 → bits[1:0]=10 (tiny), code_size = 0x0E>>2 = 3
# Body = [0x0E, 0x16, 0x58, 0x2A]; 3 bytes code: ldc.i4.0, add, ret
print("[17] dotnet_metadata_parse_method_body — tiny, 3-byte body")
r = call_tool("dotnet_metadata_parse_method_body", {"image_hex": "0e16582a", "file_offset": 0})
check("dotnet_metadata_parse_method_body", "TinyMethodBody(3 bytes) → code_size=3",
      r, 3, key="code_size")

# ─── Finalize ────────────────────────────────────────────────────────────────

proc.stdin.close()
proc.wait(timeout=5)

total_checks = checks_passed + checks_failed
report = {
    "module": "dotnet_metadata",
    "tools_hardened": len(tools_hardened),
    "checks_passed": checks_passed,
    "checks_failed": checks_failed,
    "real_mismatches": len(mismatches),
    "mismatches": mismatches,
}

print(f"\n=== REPORT ===")
print(f"  tools_hardened : {report['tools_hardened']}")
print(f"  checks_passed  : {checks_passed}")
print(f"  checks_failed  : {checks_failed}")
print(f"  real_mismatches: {len(mismatches)}")

REPORT_OUT.parent.mkdir(parents=True, exist_ok=True)
REPORT_OUT.write_text(json.dumps(report, indent=2))
print(f"\nReport saved to {REPORT_OUT}")

sys.exit(0 if checks_failed == 0 else 1)
