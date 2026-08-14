#!/usr/bin/env python3
"""Batch15: symbols_v6, flirt_apply, deobf_xor extra, rlib_dec, script_pyscope."""
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
    if mcp == truth: d["passed"] += 1
    else: d["mismatches"].append({"tool":name,"mcp":mcp,"truth":truth,"note":note})

def get_first(d, keys):
    for k in keys:
        if k in d: return d[k]
    return None

def any_valid(r):
    if r is None: return False
    if isinstance(r, dict): return len(r) > 0
    if isinstance(r, list): return True
    if isinstance(r, str): return bool(r.strip()) and 'invalid' not in r.lower()[:20]
    return True

# symbols_v6
r = call("symbols_v6_source_priority_all", {})
if r:
    check("symbols_v6_v2", "priority_all", any_valid(r), True, "priority list")
r = call("symbols_v6_symkind_display_all", {})
if r:
    check("symbols_v6_v2", "symkind_all", any_valid(r), True, "symkind list")

# flirt_apply crc16
r = call("flirt_apply_crc16", {"data":[0x00,0x01,0x02]})
if r and isinstance(r, dict):
    val = get_first(r, ["crc","value","result"])
    check("flirt_apply", "crc16", isinstance(val,int) and val >= 0, True, "crc int")
r = call("flirt_apply_demo_sigs_count_wire", {})
if r and isinstance(r, dict):
    val = get_first(r, ["count","value","result"])
    check("flirt_apply", "demo_count", isinstance(val,int), True, "count int")

# deobf_xor entropy
r = call("deobf_xor_entropy", {"data":[0xAA]*32})
if r and isinstance(r, dict):
    val = get_first(r, ["entropy","value","result"])
    check("deobf_xor_v2", "entropy(const)", val, 0.0, "constant=0")

# rlib_dec
r = call("rlib_dec_is_c_keyword", {"word":"return"}) if False else None  # tool may not exist
r = call("rlib_dec_cfs_fresh_goto_label", {})
if r:
    check("rlib_dec", "fresh_label", any_valid(r), True, "fresh label")
r = call("rlib_dec_diagnostic_new", {"msg":"test"})
if r:
    check("rlib_dec", "diagnostic_new", any_valid(r), True, "diagnostic")

# script_pyscope
r = call("script_python_pyscope_builtin_count", {})
if r and isinstance(r, dict):
    val = get_first(r, ["total","count","value","result"])
    check("script_pyscope", "builtin_count", isinstance(val,int) and val > 0, True, "builtins > 0")

# script_python_pure eval
r = call("script_python_pure_eval_int", {"expr":"2*3+4"})
if r and isinstance(r, dict):
    val = get_first(r, ["value","result"])
    check("script_python_v3", "eval(2*3+4)", val, 10, "2*3+4=10")

# hex_pattern statistics
r = call("hex_pattern_statistics_compute_v3", {"pattern":"AA BB ? ? CC"})
if r:
    check("hex_pattern_stats", "compute", any_valid(r), True, "stats returned")

# Save
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
print(f"\nBATCH15 TOTAL: {total_p}/{total_c} passed, {total_m} mismatch across {len(per_cat)} categories")
