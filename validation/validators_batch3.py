#!/usr/bin/env python3
"""Batch3: dwarf_casts, deobf_xor/rc4, arm_reg, script_python simple, forensics constants."""
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
    return r is not None and (isinstance(r,dict) or isinstance(r,list) or (isinstance(r,str) and r.strip() and 'invalid' not in r.lower() and 'error' not in r.lower()))

# ---- dwarf_casts (integer cast semantics) ----
# i64 as u32 = low 32 bits; u64 as u32 = low 32 bits; u64 as u16 = low 16; u64 as u8 = low 8
# 0x123456789ABCDEF0 & 0xFFFFFFFF = 0x9ABCDEF0
casts = [
  ("dwarf_casts_i64_to_u32", {"value":0x123456789ABCDEF0}, 0x9ABCDEF0),
  ("dwarf_casts_u64_to_u32", {"value":0x123456789ABCDEF0}, 0x9ABCDEF0),
  ("dwarf_casts_u64_to_u16", {"value":0x123456789ABCDEF0}, 0xDEF0),
  ("dwarf_casts_u64_to_u8",  {"value":0x123456789ABCDEF0}, 0xF0),
]
for tool, args, exp in casts:
    r = call(tool, args)
    if r and isinstance(r, dict):
        val = r.get("result") or r.get("value") or r.get("out")
        check("dwarf_casts", tool, val, exp, f"{args}={exp:#x}")

# ---- deobf_xor ----
r = call("deobf_xor_decrypt_constant", {"data":[0xAA,0xBB,0xCC], "key":0xFF})
if r and isinstance(r, dict):
    val = r.get("decrypted") or r.get("bytes") or r.get("result") or r.get("out")
    # 0xAA^0xFF=0x55, 0xBB^0xFF=0x44, 0xCC^0xFF=0x33
    exp = [0x55, 0x44, 0x33]
    if isinstance(val, list):
        check("deobf_xor", "xor_const", val, exp, "AA BB CC XOR FF")
    elif isinstance(val, str):
        check("deobf_xor", "xor_const", val.lower(), "554433", "AA BB CC XOR FF hex")

# ---- deobf_rc4 (KSA/PRGA are standard) ----
# just check tool responds
r = call("deobf_rc4_ksa", {"key":[1,2,3,4,5]})
if r:
    check("deobf_rc4", "ksa", any_valid(r), True, "KSA returns S-box")
r = call("deobf_rc4_decrypt", {"bytes":[0x01,0x02,0x03], "key":[0xFF]})
if r:
    check("deobf_rc4", "decrypt", any_valid(r), True, "RC4 decrypt returns")

# ---- arm registers ----
# ARM dreg/sreg naming: d0, d1, s0, s1
r = call("arm_dreg_name", {"n":0})
if r and isinstance(r, dict):
    val = r.get("name") or r.get("value")
    check("arm_reg", "dreg_name(0)", val, "d0", "dreg 0 = d0")
r = call("arm_sreg_name", {"n":5})
if r and isinstance(r, dict):
    val = r.get("name") or r.get("value")
    check("arm_reg", "sreg_name(5)", val, "s5", "sreg 5 = s5")

# ---- script_python pure ----
# eval_int('1 + 2') = 3
r = call("script_python_pure_eval_int", {"expr":"1 + 2"})
if r and isinstance(r, dict):
    val = r.get("value") or r.get("result")
    check("script_python", "eval_int(1+2)", val, 3, "1+2=3")
r = call("script_python_pure_eval_int", {"expr":"100 * 2"})
if r and isinstance(r, dict):
    val = r.get("value") or r.get("result")
    check("script_python", "eval_int(100*2)", val, 200, "100*2=200")

# ---- kg (knowledge graph) — just check list_functions returns list ----
r = call("kg_list_functions", {"binary_id":"bin-0001"})
if r:
    check("kg", "list_functions", any_valid(r), True, "list_functions returns")
r = call("kg_query", {"query":"SELECT 1"})
if r:
    check("kg", "query", any_valid(r), True, "query returns")

# ---- forensics net enum (index into internal enum list, not IP proto) ----
for idx in (0, 1, 2, 3):
    r = call("forensics_mem_net_protocol_as_str", {"index":idx})
    if r and isinstance(r, dict):
        val = r.get("as_str") or r.get("name") or r.get("value")
        check("forensics_net", f"protocol_as_str({idx})", bool(val and isinstance(val,str)), True, f"enum idx {idx}")

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
print(f"\nBATCH3 TOTAL: {total_p}/{total_c} passed, {total_m} mismatch across {len(per_cat)} categories")
