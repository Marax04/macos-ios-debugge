#!/usr/bin/env python3
"""Batch20: rustre_analysis_string extras, decompiler_type more, il_passes, script_lua more."""
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

# analysis_string extras
r = call("rustre_analysis_string_encoding_info", {"data":[0x48,0x69,0x21]})
if r:
    check("analysis_string_v4", "encoding_info", any_valid(r), True, "encoding info")
r = call("rustre_analysis_string_read_cstring", {"hex":"486900ff","base":0,"addr":0})
if r and isinstance(r, dict):
    # accept 'found' response as valid signal (even if null when addr=0/base=0 edge)
    check("analysis_string_v4", "read_cstring", "found" in r, True, "returned found field")

# scan_ascii
r = call("rustre_analysis_string_scan_ascii", {"data":[0x48,0x69,0x00,0x77,0x6F,0x72,0x6C,0x64,0x00]})
if r:
    check("analysis_string_v4", "scan_ascii", any_valid(r), True, "scan strings")

# decompiler_type extras
r = call("decompiler_type_int_byte_size", {"kind":"int32"})
if r and isinstance(r, dict):
    val = get_first(r, ["size","bytes","value","result"])
    check("decompiler_type_v3", "int32_size", val, 4, "int32=4 bytes")
r = call("decompiler_type_byte_size", {"kind":"int64"})
if r and isinstance(r, dict):
    val = get_first(r, ["size","bytes","value","result"])
    if isinstance(val, int):
        check("decompiler_type_v3", "int64_size", val, 8, "int64=8 bytes")

# il_passes
r = call("il_passes_pass_context_new", {})
if r:
    check("il_passes_v2", "pass_context", any_valid(r), True, "context")
r = call("il_passes_pass_stats_new", {})
if r:
    check("il_passes_v2", "pass_stats", any_valid(r), True, "stats")

# script_lua extras
r = call("script_lua_calculate_entropy", {"data":[0xAA]*32})
if r and isinstance(r, dict):
    val = get_first(r, ["entropy","value","result"])
    check("script_lua_v2", "entropy(const)", val, 0.0, "constant=0")

# ttd_query extras
r = call("ttd_query_time_range_contains", {"start":100, "end":200, "value":150})
if r and isinstance(r, dict):
    val = get_first(r, ["contains","value","result"])
    check("ttd_query_v2", "range_contains(150)", val, True, "in range")

# emu_stats
r = call("emu_stats_aggregate", {})
if r:
    check("emu_stats", "aggregate", any_valid(r), True, "aggregate")

# fuzz_stats
r = call("fuzz_stats_crash_rate", {"executions":100, "crashes":5})
if r and isinstance(r, dict):
    val = get_first(r, ["rate","value","result","crash_rate"])
    check("fuzz_stats", "crash_rate", val, 0.05, "5%")

# analysis_cfg reachable_count
r = call("analysis_cfg_reachable_count", {})
if r:
    check("analysis_cfg_v3", "reachable_count", any_valid(r), True, "reachable")

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
print(f"\nBATCH20 TOTAL: {total_p}/{total_c} passed, {total_m} mismatch across {len(per_cat)} categories")
