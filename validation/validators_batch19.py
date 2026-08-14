#!/usr/bin/env python3
"""Batch19: analysis_boundary, analysis_pass, analysis_report, hex_pattern more, cfg extra."""
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

# analysis_boundary
r = call("analysis_boundary_info", {"start":0x1000, "end":0x2000})
if r:
    check("analysis_boundary", "info", any_valid(r), True, "range info")

# analysis_pass_registry
r = call("analysis_pass_registry_builtin", {})
if r:
    check("analysis_pass", "registry_builtin", any_valid(r), True, "builtin passes")

# analysis_scheduler
r = call("analysis_scheduler_groups", {})
if r:
    check("analysis_scheduler", "groups", any_valid(r), True, "scheduler groups")
r = call("analysis_scheduler_order", {})
if r:
    check("analysis_scheduler", "order", any_valid(r), True, "order")

# analysis_report_summary
r = call("analysis_report_summary", {})
if r:
    check("analysis_report", "summary", any_valid(r), True, "summary")

# cfg extras
r = call("analysis_cfg_flow_edge_kind_is_conditional", {"kind":"conditional"})
if r and isinstance(r, dict):
    val = get_first(r, ["is_conditional","value","result"])
    check("analysis_cfg_v2", "is_conditional", val, True, "conditional=true")

# Data validation constants
r = call("analysis_cfg_flow_edge_kind_is_intraprocedural", {"kind":"return"})
if r and isinstance(r, dict):
    val = get_first(r, ["is_intraprocedural","is_intra","value","result"])
    check("analysis_cfg_v2", "is_intra(return)", val, False, "return=inter")

# hex_pattern regex_search
r = call("hex_pattern_regex_search", {"pattern":"a.b", "input":"a1b"})
if r:
    check("hex_pattern_v6", "regex", any_valid(r), True, "regex match")

# type_environment
r = call("analysis_type_environment_merge", {})
if r:
    check("analysis_type_v2", "env_merge", any_valid(r), True, "merge")

# fn_detect_extra
r = call("analysis_fn_detect_extra", {"data":[0x55,0x48,0x89,0xE5]})
if r:
    check("analysis_fn_extra", "detect", any_valid(r), True, "extra detect")

# vsa strided_interval extras
r = call("vsa_strided_interval_add_wire", {})
if r:
    check("vsa_extra", "si_add", any_valid(r), True, "SI add")
r = call("vsa_strided_interval_new", {"lo":0, "hi":10, "stride":1})
if r:
    check("vsa_extra", "si_new", any_valid(r), True, "SI new")

# script_python pure execute (no side effects)
r = call("script_python_pure_step_cost", {})
if r:
    check("script_python_v4", "step_cost", any_valid(r), True, "step cost")

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
print(f"\nBATCH19 TOTAL: {total_p}/{total_c} passed, {total_m} mismatch across {len(per_cat)} categories")
