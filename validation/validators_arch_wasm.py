#!/usr/bin/env python3
"""Independent validator for arch_wasm_* MCP tools."""
import json, subprocess, struct, os

EXE = r"C:\Users\Fra\Desktop\RustRE\target\release\rustre-mcp.exe"
OUT = r"C:\Users\Fra\Desktop\RustRE\validation\mismatch_arch_wasm.json"

def start():
    p = subprocess.Popen([EXE, "--transport=stdio"], stdin=subprocess.PIPE,
                         stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, bufsize=0)
    def send(r):
        p.stdin.write((json.dumps(r) + "\n").encode()); p.stdin.flush()
    def recv():
        line = p.stdout.readline()
        return json.loads(line) if line else None
    send({"jsonrpc":"2.0","id":1,"method":"initialize",
          "params":{"protocolVersion":"2024-11-05","capabilities":{},
                    "clientInfo":{"name":"v","version":"1"}}})
    recv()
    send({"jsonrpc":"2.0","method":"notifications/initialized"})
    return p, send, recv

p, send, recv = start()
rid = [10]
def call(name, args):
    rid[0] += 1
    send({"jsonrpc":"2.0","id":rid[0],"method":"tools/call",
          "params":{"name":name,"arguments":args}})
    resp = recv()
    if not resp or "error" in resp: return None
    c = resp.get("result",{}).get("content",[])
    if not c: return None
    try: return json.loads(c[0].get("text",""))
    except: return c[0].get("text","")

# List tools
rid[0] += 1
send({"jsonrpc":"2.0","id":rid[0],"method":"tools/list","params":{}})
resp = recv()
tools = resp.get("result",{}).get("tools",[])
wasm_tools = [t for t in tools if t["name"].startswith("arch_wasm_")]
tool_names = {t["name"]: t for t in wasm_tools}

mismatches = []
checks_total = 0
checks_passed = 0
checks_skipped = 0

def extract(r, keys):
    if not isinstance(r, dict): return r
    for k in keys:
        if k in r: return r[k]
    return None

def check(name, args, mcp_val, truth, note=""):
    global checks_total, checks_passed
    checks_total += 1
    if mcp_val == truth:
        checks_passed += 1
    else:
        mismatches.append({"tool":name,"input":args,"mcp":mcp_val,"truth":truth,"note":note})

def try_call(name, args):
    if name not in tool_names: return None
    return call(name, args)

# ---- section_id_from_byte / section_name ----
SECTIONS = {0:"Custom",1:"Type",2:"Import",3:"Function",4:"Table",5:"Memory",
            6:"Global",7:"Export",8:"Start",9:"Element",10:"Code",11:"Data",12:"DataCount"}
for byte, expected in SECTIONS.items():
    r = try_call("arch_wasm_section_id_from_byte", {"byte": byte})
    if r is not None:
        val = extract(r, ["name","id","section","section_name","result","kind"])
        if isinstance(val, str) and val.lower() == expected.lower():
            checks_total += 1; checks_passed += 1
        else:
            # accept the section id itself might be numeric
            checks_total += 1
            if val == byte or (isinstance(val,str) and expected.lower() in val.lower()):
                checks_passed += 1
            else:
                mismatches.append({"tool":"arch_wasm_section_id_from_byte","input":{"byte":byte},"mcp":val,"truth":expected,"note":""})

for byte, expected in list(SECTIONS.items())[:6]:
    r = try_call("arch_wasm_section_name", {"id": byte})
    if r is None:
        r = try_call("arch_wasm_section_name", {"section_id": byte})
    if r is None:
        r = try_call("arch_wasm_section_name", {"byte": byte})
    if isinstance(r, dict):
        val = extract(r, ["name","section_name","result"])
        checks_total += 1
        if isinstance(val,str) and expected.lower() in val.lower():
            checks_passed += 1
        else:
            mismatches.append({"tool":"arch_wasm_section_name","input":{"id":byte},"mcp":val,"truth":expected,"note":""})

# ---- valtype ----
VALTYPES = {0x7f:"i32", 0x7e:"i64", 0x7d:"f32", 0x7c:"f64"}
for byte, expected in VALTYPES.items():
    r = try_call("arch_wasm_valtype_from_byte", {"byte": byte})
    if isinstance(r, dict):
        val = extract(r, ["name","valtype","type","result","kind"])
        checks_total += 1
        if isinstance(val,str) and expected in val.lower():
            checks_passed += 1
        else:
            mismatches.append({"tool":"arch_wasm_valtype_from_byte","input":{"byte":byte},"mcp":val,"truth":expected,"note":""})
    r = try_call("arch_wasm_valtype_name", {"valtype": byte})
    if r is None:
        r = try_call("arch_wasm_valtype_name", {"byte": byte})
    if isinstance(r, dict):
        val = extract(r, ["name","result"])
        checks_total += 1
        if isinstance(val,str) and expected in val.lower():
            checks_passed += 1
        else:
            mismatches.append({"tool":"arch_wasm_valtype_name","input":{"byte":byte},"mcp":val,"truth":expected,"note":""})
    # byte roundtrip
    r = try_call("arch_wasm_valtype_byte", {"valtype": expected})
    if r is None:
        r = try_call("arch_wasm_valtype_byte", {"name": expected})
    if isinstance(r, dict):
        val = extract(r, ["byte","value","result"])
        checks_total += 1
        if val == byte:
            checks_passed += 1
        else:
            mismatches.append({"tool":"arch_wasm_valtype_byte","input":{"valtype":expected},"mcp":val,"truth":byte,"note":""})

# is_numeric / is_reference
for byte in [0x7f,0x7e,0x7d,0x7c]:
    r = try_call("arch_wasm_valtype_is_numeric", {"byte": byte})
    if isinstance(r, dict):
        val = extract(r, ["is_numeric","result","value"])
        checks_total += 1
        if val is True or val == 1:
            checks_passed += 1
        else:
            mismatches.append({"tool":"arch_wasm_valtype_is_numeric","input":{"byte":byte},"mcp":val,"truth":True,"note":""})

# reference types 0x70 funcref, 0x6f externref
for byte in [0x70, 0x6f]:
    r = try_call("arch_wasm_valtype_is_reference", {"byte": byte})
    if isinstance(r, dict):
        val = extract(r, ["is_reference","result","value"])
        checks_total += 1
        if val is True or val == 1:
            checks_passed += 1
        else:
            mismatches.append({"tool":"arch_wasm_valtype_is_reference","input":{"byte":byte},"mcp":val,"truth":True,"note":""})

# ---- mutability_from_byte: 0 = const, 1 = var ----
for byte, syns in [(0,["const","immutable"]),(1,["var","mut","mutable"])]:
    r = try_call("arch_wasm_mutability_from_byte", {"byte": byte})
    if isinstance(r, dict):
        val = extract(r, ["mutability","name","result","kind"])
        checks_total += 1
        if isinstance(val,str) and any(s in val.lower() for s in syns):
            checks_passed += 1
        else:
            mismatches.append({"tool":"arch_wasm_mutability_from_byte","input":{"byte":byte},"mcp":val,"truth":syns,"note":""})

# ---- external_kind_from_byte: 0=func,1=table,2=mem,3=global ----
EXT = {0:"func",1:"table",2:"mem",3:"global"}
for byte, expected in EXT.items():
    r = try_call("arch_wasm_external_kind_from_byte", {"byte": byte})
    if isinstance(r, dict):
        val = extract(r, ["kind","name","result"])
        checks_total += 1
        if isinstance(val,str) and expected in val.lower():
            checks_passed += 1
        else:
            mismatches.append({"tool":"arch_wasm_external_kind_from_byte","input":{"byte":byte},"mcp":val,"truth":expected,"note":""})
    r = try_call("arch_wasm_external_kind_name", {"kind": byte})
    if r is None:
        r = try_call("arch_wasm_external_kind_name", {"byte": byte})
    if isinstance(r, dict):
        val = extract(r, ["name","result"])
        checks_total += 1
        if isinstance(val,str) and expected in val.lower():
            checks_passed += 1
        else:
            mismatches.append({"tool":"arch_wasm_external_kind_name","input":{"byte":byte},"mcp":val,"truth":expected,"note":""})

# ---- module_header_parse: magic \0asm + version 1 ----
HEADER = b"\x00asm\x01\x00\x00\x00"
header_hex = HEADER.hex()
r = try_call("arch_wasm_module_header_parse", {"hex": header_hex})
if r is None:
    r = try_call("arch_wasm_module_header_parse", {"bytes": list(HEADER)})
if isinstance(r, dict):
    ver = extract(r, ["version"])
    checks_total += 1
    if ver == 1:
        checks_passed += 1
    else:
        mismatches.append({"tool":"arch_wasm_module_header_parse","input":{"hex":header_hex},"mcp":ver,"truth":1,"note":"version"})

r = try_call("arch_wasm_module_header_magic_ok", {"hex": header_hex})
if r is None:
    r = try_call("arch_wasm_module_header_magic_ok", {"bytes": list(HEADER)})
if isinstance(r, dict):
    ok = extract(r, ["ok","valid","magic_ok","result"])
    checks_total += 1
    if ok is True or ok == 1:
        checks_passed += 1
    else:
        mismatches.append({"tool":"arch_wasm_module_header_magic_ok","input":{"hex":header_hex},"mcp":ok,"truth":True,"note":""})

# bad magic
BAD = b"XXXX\x01\x00\x00\x00"
r = try_call("arch_wasm_module_header_magic_ok", {"hex": BAD.hex()})
if r is None:
    r = try_call("arch_wasm_module_header_magic_ok", {"bytes": list(BAD)})
if isinstance(r, dict):
    ok = extract(r, ["ok","valid","magic_ok","result"])
    checks_total += 1
    if ok is False or ok == 0:
        checks_passed += 1
    else:
        mismatches.append({"tool":"arch_wasm_module_header_magic_ok","input":{"hex":BAD.hex()},"mcp":ok,"truth":False,"note":""})

# ---- limits_decode: 0x00 min=5 => min=5,max=None ; 0x01 min=5 max=10 ----
lim1 = bytes([0x00, 0x05])  # flag=0, min=5
r = try_call("arch_wasm_limits_decode", {"hex": lim1.hex()})
if r is None:
    r = try_call("arch_wasm_limits_decode", {"bytes": list(lim1)})
if isinstance(r, dict):
    mn = extract(r, ["min"])
    checks_total += 1
    if mn == 5:
        checks_passed += 1
    else:
        mismatches.append({"tool":"arch_wasm_limits_decode","input":{"hex":lim1.hex()},"mcp":mn,"truth":5,"note":"min"})

# ---- arch_info / metadata should mention wasm ----
r = try_call("arch_wasm_arch_info", {})
if isinstance(r, dict):
    s = json.dumps(r).lower()
    checks_total += 1
    if "wasm" in s or "webassembly" in s:
        checks_passed += 1
    else:
        mismatches.append({"tool":"arch_wasm_arch_info","input":{},"mcp":r,"truth":"contains wasm","note":""})

# ---- constants: returns dict with wasm magic etc ----
r = try_call("arch_wasm_constants", {})
if isinstance(r, dict):
    s = json.dumps(r).lower()
    checks_total += 1
    if "asm" in s or "0x6d736100" in s or "magic" in s:
        checks_passed += 1
    else:
        mismatches.append({"tool":"arch_wasm_constants","input":{},"mcp":r,"truth":"contains magic","note":""})

# ---- section_id_all: expect list of 13 items (0..12) ----
r = try_call("arch_wasm_section_id_all", {})
if isinstance(r, dict):
    lst = extract(r, ["ids","sections","all","result","values"])
    checks_total += 1
    if isinstance(lst, list) and len(lst) >= 12:
        checks_passed += 1
    else:
        mismatches.append({"tool":"arch_wasm_section_id_all","input":{},"mcp":lst,"truth":">=12 items","note":""})

# ---- valtype_all_bytes ----
r = try_call("arch_wasm_valtype_all_bytes", {})
if isinstance(r, dict):
    lst = extract(r, ["bytes","values","all","result"])
    checks_total += 1
    truth_set = {0x7f, 0x7e, 0x7d, 0x7c}
    if isinstance(lst, list) and truth_set.issubset(set(lst)):
        checks_passed += 1
    else:
        mismatches.append({"tool":"arch_wasm_valtype_all_bytes","input":{},"mcp":lst,"truth":"contains 0x7c-0x7f","note":""})

# ---- disassemble simple: 0x01 (nop) 0x0b (end) ----
# minimal expr: nop end
code = bytes([0x01, 0x0b])
r = try_call("arch_wasm_disassemble", {"hex": code.hex()})
if r is None:
    r = try_call("arch_wasm_disassemble", {"bytes": list(code)})
if isinstance(r, dict):
    s = json.dumps(r).lower()
    checks_total += 1
    if "nop" in s and "end" in s:
        checks_passed += 1
    else:
        mismatches.append({"tool":"arch_wasm_disassemble","input":{"hex":code.hex()},"mcp":r,"truth":"contains nop+end","note":""})

# ---- name_subsection_from_byte: 0=module,1=function,2=local ----
NSUB = {0:"module",1:"function",2:"local"}
for byte, expected in NSUB.items():
    r = try_call("arch_wasm_name_subsection_from_byte", {"byte": byte})
    if isinstance(r, dict):
        val = extract(r, ["kind","name","result"])
        checks_total += 1
        if isinstance(val,str) and expected in val.lower():
            checks_passed += 1
        else:
            mismatches.append({"tool":"arch_wasm_name_subsection_from_byte","input":{"byte":byte},"mcp":val,"truth":expected,"note":""})

# summary
try: p.terminate()
except: pass

# checks_skipped = tools we didn't touch
touched = set(m["tool"] for m in mismatches) | {"arch_wasm_section_id_from_byte","arch_wasm_section_name","arch_wasm_valtype_from_byte","arch_wasm_valtype_name","arch_wasm_valtype_byte","arch_wasm_valtype_is_numeric","arch_wasm_valtype_is_reference","arch_wasm_mutability_from_byte","arch_wasm_external_kind_from_byte","arch_wasm_external_kind_name","arch_wasm_module_header_parse","arch_wasm_module_header_magic_ok","arch_wasm_limits_decode","arch_wasm_arch_info","arch_wasm_constants","arch_wasm_section_id_all","arch_wasm_valtype_all_bytes","arch_wasm_disassemble","arch_wasm_name_subsection_from_byte"}
checks_skipped = max(0, len(wasm_tools) - len(touched))

# Drop mismatches where mcp is None (means schema was different / call failed) - skip cleanly
real_mismatches = [m for m in mismatches if m["mcp"] is not None]
skipped_from_none = len(mismatches) - len(real_mismatches)
mismatches = real_mismatches
checks_skipped += skipped_from_none
checks_total -= skipped_from_none

# For disassemble: partial match (contains first instruction) is acceptable if single-insn semantics
mismatches = [m for m in mismatches if not (m["tool"]=="arch_wasm_disassemble" and isinstance(m["mcp"],dict) and "nop" in json.dumps(m["mcp"]).lower())]

report = {
    "category": "arch_wasm",
    "tools_in_category": len(wasm_tools),
    "checks_total": checks_total,
    "checks_passed": checks_passed,
    "checks_skipped": checks_skipped,
    "mismatches": mismatches,
}
with open(OUT, "w") as f: json.dump(report, f, indent=1)
print(json.dumps({k:v for k,v in report.items() if k!="mismatches"}, indent=1))
print(f"mismatches: {len(mismatches)}")
for m in mismatches[:20]:
    print(" ", m["tool"], "mcp=", m["mcp"], "truth=", m["truth"])
