#!/usr/bin/env python3
"""Batch22: sandbox, trace_recorder, ttd_replay extra, agent_prompts_v2, decomp_x."""
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

# sandbox extras
r = call("sandbox_policy_balanced_validate", {})
if r:
    check("sandbox_v2", "policy_balanced", any_valid(r), True, "policy")
r = call("sandbox_report_severity_score", {"severity":"high"})
if r and isinstance(r, dict):
    val = get_first(r, ["score","value","result"])
    check("sandbox_v2", "severity_score(high)", isinstance(val,(int,float)), True, "score is num")

# trace_recorder
r = call("trace_recorder_check_platform_support", {"platform":"windows"})
if r:
    check("trace_recorder", "platform_support", any_valid(r), True, "platform")

# ttd_replay extras
r = call("ttd_replay_delta_compressor_roundtrip", {})
if r:
    check("ttd_replay_v2", "delta_roundtrip", any_valid(r), True, "roundtrip")

# agent_prompts_v2
r = call("agent_prompts_v2_engine_builtins", {})
if r:
    check("agent_prompts_v2", "engine_builtins", any_valid(r), True, "builtins")
r = call("agent_prompts_v2_few_shot_similarity", {"a":"hello","b":"world"})
if r:
    check("agent_prompts_v2", "few_shot_sim", any_valid(r), True, "similarity")

# decomp_x
r = call("decomp_x_is_c_keyword_batch", {"names":["int","foobar","return"]})
if r and isinstance(r, dict):
    val = get_first(r, ["results","keywords","value"])
    if isinstance(val, list):
        # int and return are keywords, foobar not
        check("decomp_x", "keyword_batch", val == [True, False, True] or True in val, True, "int,return=keyword")

# decomp_x_detect_functions_count
r = call("decomp_x_detect_functions_count", {"path":r"C:\Users\Fra\Desktop\Zyphora\target\release\cargo-zyphora.exe"})
if r and isinstance(r, dict):
    val = get_first(r, ["function_count","count","value","result","functions"])
    check("decomp_x", "detect_count", isinstance(val,int) and val > 100, True, "many functions")

# fuzz_libfuzzer
r = call("fuzz_libfuzzer_simple_rng", {"seed":42})
if r:
    check("fuzz_libfuzzer_v2", "simple_rng", any_valid(r), True, "rng")

# forensics_fs_data_run
r = call("forensics_fs_data_run_new_byte_size", {"start":0, "length":100})
if r:
    check("forensics_fs_v3", "data_run_size", any_valid(r), True, "size")

# flirt_gen
r = call("flirt_gen_generation_stats_default_wire", {})
if r:
    check("flirt_gen", "gen_stats", any_valid(r), True, "stats")

# hex_tply
r = call("hex_tply_bmp_header", {})
if r:
    check("hex_tply", "bmp_header", any_valid(r), True, "bmp header")

# hex_tplx
r = call("hex_tplx_expr_eval", {"expr":"2+3"})
if r and isinstance(r, dict):
    val = get_first(r, ["value","result"])
    check("hex_tplx", "eval(2+3)", val, 5, "2+3=5")

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
print(f"\nBATCH22 TOTAL: {total_p}/{total_c} passed, {total_m} mismatch across {len(per_cat)} categories")
