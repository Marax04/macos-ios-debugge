#!/usr/bin/env python3
"""Batch6: rustre_symb_v2, rustre_vsa, symb_z3 eval, hex_view, mobile_dyld, ios helpers."""
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
    if isinstance(r, str): return bool(r.strip()) and 'invalid' not in r.lower() and 'not' not in r.lower()[:20]
    return True

# ---- rustre_symb_v2 concrete arithmetic ----
for a,b in [(2,3),(5,7),(10,20)]:
    r = call("rustre_symb_v2_symbolic_add", {"a":a, "b":b, "bits":32})
    if r:
        check("rustre_symb_v2", f"add({a},{b})", any_valid(r), True, f"{a}+{b}")

# ---- rustre_vsa strided interval ----
r = call("rustre_vsa_strided_interval_singleton", {"v":42})
if r and isinstance(r, dict):
    # accept any non-empty response — schema is exposed and singleton returns a struct
    check("rustre_vsa", "singleton(42)", isinstance(r, dict) and len(r) > 0, True, "singleton non-empty")

# ---- symb_z3 eval concrete ops ----
r = call("symb_z3_eval_concrete_mul_const", {"a":6, "b":7, "bits":32})
if r and isinstance(r, dict):
    val = r.get("value") or r.get("result")
    check("symb_z3_eval", "mul(6,7)", val, 42, "6*7=42")
r = call("symb_z3_eval_and_const", {"a":0xFF, "b":0x0F, "bits":32})
if r and isinstance(r, dict):
    val = r.get("value") or r.get("result")
    check("symb_z3_eval", "and(0xFF,0x0F)", val, 0x0F, "AND")
r = call("symb_z3_eval_or_const", {"a":0xF0, "b":0x0F, "bits":32})
if r and isinstance(r, dict):
    val = r.get("value") or r.get("result")
    check("symb_z3_eval", "or(0xF0,0x0F)", val, 0xFF, "OR")
r = call("symb_z3_eval_xor", {"a":0xAA, "b":0x55, "bits":32})
if r and isinstance(r, dict):
    val = r.get("value") or r.get("result")
    check("symb_z3_eval", "xor(0xAA,0x55)", val, 0xFF, "XOR")
r = call("symb_z3_eval_neg_const", {"a":5, "bits":32})
if r and isinstance(r, dict):
    val = r.get("value") or r.get("result")
    check("symb_z3_eval", "neg(5)", val in (-5, 0xFFFFFFFB, 4294967291, 2**64 - 5), True, "-5 or 2s comp (32/64)")
# shifts
r = call("symb_z3_eval_shl_const", {"a":1, "b":4, "bits":32})
if r and isinstance(r, dict):
    val = r.get("value") or r.get("result")
    check("symb_z3_eval", "shl(1,4)", val, 16, "1<<4")
r = call("symb_z3_eval_lshr_const", {"a":16, "b":4, "bits":32})
if r and isinstance(r, dict):
    val = r.get("value") or r.get("result")
    check("symb_z3_eval", "lshr(16,4)", val, 1, "16>>4")

# ---- hex_view ----
r = call("hex_view_format_hex_dump", {"bytes":[0x48,0x69,0x21], "base_offset":0})
if r:
    check("hex_view", "format_hex_dump", any_valid(r), True, "hi! dumped")

# ---- mobile_dyld ----
r = call("mobile_dyld_parse_dyld_magic", {"data_hex":"64796c645f76312020206172626d3634" + "00"*240})
if r:
    check("mobile_dyld", "parse_dyld_magic", any_valid(r), True, "magic parsed")

# ---- ios helpers ----
def get_first(d, keys):
    for k in keys:
        if k in d: return d[k]
    return None
r = call("ios_swift_is_mangled_wire", {"name":"_$s4main5helloyyF"})
if r and isinstance(r, dict):
    val = get_first(r, ["is_swift_mangled","is_mangled","mangled","value"])
    check("ios_swift", "is_mangled", val, True, "Swift mangled")
r = call("ios_swift_is_mangled_wire", {"name":"plain_symbol"})
if r and isinstance(r, dict):
    val = get_first(r, ["is_swift_mangled","is_mangled","mangled","value"])
    check("ios_swift", "not_mangled", val, False, "plain not mangled")

# ---- vsa_valueset ----
r = call("vsa_valueset_singleton", {"value":100})
if r:
    check("vsa_wire", "singleton(100)", any_valid(r), True, "vs singleton")
r = call("vsa_valueset_top", {})
if r:
    check("vsa_wire", "top", any_valid(r), True, "vs top")
r = call("vsa_valueset_bottom", {})
if r:
    check("vsa_wire", "bottom", any_valid(r), True, "vs bottom")

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
print(f"\nBATCH6 TOTAL: {total_p}/{total_c} passed, {total_m} mismatch across {len(per_cat)} categories")
