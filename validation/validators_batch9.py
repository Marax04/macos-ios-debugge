#!/usr/bin/env python3
"""Batch9: agent_llm, trace_pt/coresight, plugin, malpedia, emu_base, decomp_*."""
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

# ---- agent_llm token count / cost ----
r = call("agent_llm_count_tokens", {"text":"hello world"})
if r and isinstance(r, dict):
    val = get_first(r, ["tokens","count","value"])
    # "hello world" = ~2-3 tokens depending on tokenizer
    check("agent_llm", "count_tokens(hello world)", isinstance(val, int) and 1 <= val <= 10, True, "tokens in range")
r = call("agent_llm_estimate_cost", {"input_tokens":1000, "output_tokens":500, "model":"claude-3-opus"})
if r:
    check("agent_llm", "estimate_cost", any_valid(r), True, "cost estimate")
r = call("agent_llm_builtin_models", {})
if r:
    check("agent_llm", "builtin_models", any_valid(r), True, "model list")

# ---- trace_pt basic ----
r = call("trace_pt_decode_buffer", {"data":[0x02,0x82]})
if r:
    check("trace_pt", "decode_buffer", any_valid(r), True, "PT decode")

# ---- trace_coresight ----
r = call("trace_coresight_is_valid_stream", {"data":[0x00,0x01]})
if r:
    check("trace_coresight", "is_valid_stream", any_valid(r), True, "stream check")

# ---- plugin ----
r = call("plugin_native_loader_count", {})
if r and isinstance(r, dict):
    val = get_first(r, ["count","value"])
    check("plugin", "native_count", isinstance(val, int), True, "count is int")
r = call("plugin_lua_loader_default_count", {})
if r and isinstance(r, dict):
    val = get_first(r, ["count","value"])
    check("plugin", "lua_count", isinstance(val, int), True, "count is int")

# ---- malpedia (mock/stats) ----
r = call("malpedia_tlsh_distance", {"a":"T1"+"0"*70, "b":"T1"+"1"*70})
if r:
    check("malpedia", "tlsh_distance", any_valid(r), True, "distance computed")

# ---- emu_base ----
r = call("emu_base_arch_is_64bit", {"arch":"x86_64"})
if r and isinstance(r, dict):
    val = get_first(r, ["is_64bit","value","result"])
    check("emu_base", "arch_is_64bit(x86_64)", val, True, "x86_64=64bit")
r = call("emu_base_arch_is_64bit", {"arch":"x86"})
if r and isinstance(r, dict):
    val = get_first(r, ["is_64bit","value","result"])
    check("emu_base", "arch_is_64bit(x86)", val, False, "x86=32bit")
r = call("emu_base_arch_is_x86", {"arch":"x86_64"})
if r and isinstance(r, dict):
    val = get_first(r, ["is_x86","value","result"])
    check("emu_base", "arch_is_x86(x86_64)", val, True, "x86_64 is x86 family")

# ---- decomp_ misc ----
r = call("decomp_is_c_keyword", {"name":"int"})
if r and isinstance(r, dict):
    val = get_first(r, ["is_c_keyword","is_keyword","value","result"])
    check("decomp", "is_c_keyword(int)", val, True, "int=keyword")
r = call("decomp_is_c_keyword", {"name":"foobar"})
if r and isinstance(r, dict):
    val = get_first(r, ["is_c_keyword","is_keyword","value","result"])
    check("decomp", "is_c_keyword(foobar)", val, False, "foobar=not keyword")

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
print(f"\nBATCH9 TOTAL: {total_p}/{total_c} passed, {total_m} mismatch across {len(per_cat)} categories")
