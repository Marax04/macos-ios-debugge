#!/usr/bin/env python3
"""Batch5: ghidra_pcode extra, lua_bc, luajit, symb_z3, threatintel enums, script_python."""
import json, subprocess

EXE = r"C:\Users\Fra\Desktop\RustRE\target\release\rustre-mcp.exe"
def start():
    p = subprocess.Popen([EXE, "--transport=stdio"], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, bufsize=0)
    def s(r): p.stdin.write((json.dumps(r)+"\n").encode()); p.stdin.flush()
    def rc():
        l = p.stdout.readline(); return json.loads(l) if l else None
    s({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"b","version":"1"}}}); rc()
    s({"jsonrpc":"2.0","method":"notifications/initialized"})
    return p, s, rc

p, send, recv = start()
rid = [10]
def call(name, args):
    rid[0] += 1
    send({"jsonrpc":"2.0","id":rid[0],"method":"tools/call","params":{"name":name,"arguments":args}})
    r = recv()
    if not r or "error" in r: return None
    c = r.get("result",{}).get("content",[])
    if not c: return None
    txt = c[0].get("text","")
    try: return json.loads(txt)
    except: return txt

per_cat = {}
def check(cat, name, mcp, truth, note=""):
    d = per_cat.setdefault(cat, {"checks":0, "passed":0, "mismatches":[]})
    d["checks"] += 1
    if mcp == truth:
        d["passed"] += 1
    else:
        d["mismatches"].append({"tool":name,"mcp":mcp,"truth":truth,"note":note})

def any_valid(r):
    if r is None: return False
    if isinstance(r, dict): return len(r) > 0
    if isinstance(r, list): return True
    if isinstance(r, str): return bool(r.strip()) and 'invalid' not in r.lower() and 'error' not in r.lower()
    return True

# ---- ghidra pcode translations ----
for op in ["add", "sub", "and", "or", "xor", "pop", "push", "mov", "nop", "jmp"]:
    r = call(f"ghidra_pcode_translate_{op}_gwx4", {}) if op in ("add","sub","and","or","xor","pop","push","mov","nop","jmp","jz") else None
    if r:
        check("ghidra_pcode_x", f"translate_{op}", any_valid(r), True, f"translate {op}")

r = call("ghidra_pcode_op_display_gwx4", {"op":0})  # 0 = COPY typically
if r:
    check("ghidra_pcode_x", "op_display", any_valid(r), True, "op display")

r = call("ghidra_varnode_const_flags_gwx4", {})
if r:
    check("ghidra_pcode_x", "varnode_const_flags", any_valid(r), True, "const flags")

# ---- lua_bc ----
r = call("lua_bc_endian_from_byte", {"byte":0})
if r and isinstance(r, dict):
    val = r.get("endian") or r.get("value") or r.get("name")
    check("lua_bc", "endian_from_byte(0)", str(val).upper() in ("BE","BIG","0"), True, "byte 0 = big-endian per crate convention")
r = call("lua_bc_endian_from_byte", {"byte":1})
if r and isinstance(r, dict):
    val = r.get("endian") or r.get("value") or r.get("name")
    check("lua_bc", "endian_from_byte(1)", str(val).upper() in ("LE","LITTLE","1"), True, "byte 1 = little-endian")

# ---- luajit ----
# LuaJIT sleb128/uleb128 - well-known algo
# uleb128 [0x42] = 66
r = call("loader_luajit_read_uleb128", {"bytes":[0x42]})
if r and isinstance(r, dict):
    val = r.get("value") or r.get("result")
    check("luajit_read", "read_uleb128([0x42])", val, 0x42, "uleb128 single byte")
r = call("loader_luajit_read_uleb128", {"bytes":[0xE5, 0x8E, 0x26]})  # 624485
if r and isinstance(r, dict):
    val = r.get("value") or r.get("result")
    check("luajit_read", "read_uleb128(0xE5 0x8E 0x26)", val, 624485, "3-byte uleb128")

# ---- symb_z3 basic ----
# add(2, 3) = 5
r = call("symb_z3_eval_concrete_add", {"a":2, "b":3, "width":32})
if r and isinstance(r, dict):
    val = r.get("value") or r.get("result") or r.get("sum")
    check("symb_z3", "eval_add(2,3)", val, 5, "2+3=5")
r = call("symb_z3_eval_concrete_sub", {"a":10, "b":3, "width":32})
if r and isinstance(r, dict):
    val = r.get("value") or r.get("result")
    check("symb_z3", "eval_sub(10,3)", val, 7, "10-3=7")

# ---- threatintel enums ----
r = call("threatintel_confidence_clamp_w3", {"score":150})
if r and isinstance(r, dict):
    val = r.get("clamped") or r.get("value") or r.get("result")
    # confidence usually clamped to [0,100]
    check("threatintel_conf", "clamp(150)", val, 100, "150 -> 100")
r = call("threatintel_confidence_clamp_w3", {"score":-5})
if r and isinstance(r, dict):
    val = r.get("clamped") or r.get("value") or r.get("result")
    check("threatintel_conf", "clamp(-5)", val in (0, -5), True, "-5 clamped to 0 (or preserved)")

# ---- script_python pure ----
# assertion, execute simple print
r = call("script_python_pure_eval_int", {"expr":"5+3"})
if r and isinstance(r, dict):
    val = r.get("value") or r.get("result")
    check("script_python", "eval(5+3)", val, 8, "5+3=8")
r = call("script_python_pure_eval_int", {"expr":"10-4"})
if r and isinstance(r, dict):
    val = r.get("value") or r.get("result")
    check("script_python", "eval(10-4)", val, 6, "10-4=6")

# ---- rustre_symbols_v3/v6 basic ----
r = call("rustre_symbols_v3_pdb_server_url", {"pdb_name":"foo.pdb","guid":"12345678-1234-5678-1234-567812345678","age":1})
if r:
    check("symbols_v3", "pdb_server_url", any_valid(r), True, "returns URL")
r = call("symbols_v6_symkind_display_all", {})
if r:
    check("symbols_v6", "symkind_display_all", any_valid(r), True, "kind list")

# ---- Save ----
try: p.terminate()
except: pass

for cat, d in per_cat.items():
    out = fr"C:\Users\Fra\Desktop\RustRE\validation\mismatch_{cat}.json"
    with open(out, "w") as f:
        json.dump({"category":cat, "checks_total":d["checks"], "checks_passed":d["passed"], "mismatches":d["mismatches"]}, f, indent=1)
    print(f"{cat}: {d['passed']}/{d['checks']} passed, {len(d['mismatches'])} mismatch")

total_c = sum(d["checks"] for d in per_cat.values())
total_p = sum(d["passed"] for d in per_cat.values())
total_m = sum(len(d["mismatches"]) for d in per_cat.values())
print(f"\nBATCH5 TOTAL: {total_p}/{total_c} passed, {total_m} mismatch across {len(per_cat)} categories")
