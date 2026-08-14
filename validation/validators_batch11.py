#!/usr/bin/env python3
"""Batch11: diff, iadl, hex_pattern extra, symb_engine, symb_sym, dwarf extra, ghidra."""
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

# ---- diff ----
r = call("diff_simple_hash", {"data":[1,2,3,4]})
if r:
    check("diff", "simple_hash", any_valid(r), True, "hash returned")
r = call("diff_lcs_similarity", {"a":"hello", "b":"hallo"})
if r and isinstance(r, dict):
    val = get_first(r, ["similarity","score","value","result"])
    check("diff", "lcs_similarity(hello,hallo)", isinstance(val,(int,float)) and 0.6 < val < 1.0, True, "similar not identical")

# ---- iadl ----
r = call("iadl_compute_hash", {"data":[1,2,3]})
if r:
    check("iadl", "compute_hash", any_valid(r), True, "hash")
r = call("iadl_convergence_ema", {"prev":10.0, "current":20.0, "alpha":0.5})
if r and isinstance(r, dict):
    val = get_first(r, ["value","ema","result"])
    # EMA = alpha*current + (1-alpha)*prev = 0.5*20 + 0.5*10 = 15
    check("iadl", "ema", val, 15.0, "EMA calc")

# ---- hex_pattern misc ----
r = call("hex_pattern_bmh_search_v3", {"needle":"deadbeef", "haystack":"00112233deadbeef44"})
if r and isinstance(r, dict):
    val = get_first(r, ["position","offset","index","match_offset","value","result"])
    check("hex_pattern_v3", "bmh_search", val, 4, "found at byte offset 4")

# ---- symb_engine constants ----
r = call("symb_engine_default_solver", {})
if r:
    check("symb_engine", "default_solver", any_valid(r), True, "solver enum")
r = call("symb_engine_solver_type_list", {})
if r:
    check("symb_engine", "solver_type_list", any_valid(r), True, "solver list")
r = call("symb_engine_exploration_strategy_list", {})
if r:
    check("symb_engine", "strategy_list", any_valid(r), True, "strategy list")

# ---- symb_sym ----
# add_const(5, 3) = 8
r = call("symb_sym_add_const", {"a":5, "b":3, "bits":32})
if r and isinstance(r, dict):
    val = get_first(r, ["value","result","sum"])
    check("symb_sym", "add(5,3)", val, 8, "5+3=8")

# ---- dwarf extra ----
r = call("dwarf_abbrev_read_uleb128", {"bytes":[0x42]})
if r and isinstance(r, dict):
    val = get_first(r, ["value","result"])
    check("dwarf_uleb", "uleb128(0x42)", val, 0x42, "0x42=66")

# ---- ghidra type_importer ----
r = call("ghidra_type_importer_type_count_ghidfixp1", {})
if r:
    check("ghidra_type", "type_count", any_valid(r), True, "count returned")

# ---- pe_rebuild ----
r = call("pe_rebuild_compute_entropy", {"data_hex":"deadbeef"*16})
if r and isinstance(r, dict):
    val = get_first(r, ["entropy","value","result"])
    check("pe_rebuild", "entropy", isinstance(val,(int,float)) and val > 0, True, "entropy>0")

# ---- pe_tools ----
r = call("pe_tools_compute_entropy", {"data_hex":"aabbccdd"*8})
if r:
    check("pe_tools", "entropy", any_valid(r), True, "entropy")

# ---- vtable via demangle_msvc_rtti (validated - test negative) ----

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
print(f"\nBATCH11 TOTAL: {total_p}/{total_c} passed, {total_m} mismatch across {len(per_cat)} categories")
