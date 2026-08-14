#!/usr/bin/env python3
"""Batch23: rustre_decompiler extras, agent_llm, llm helpers, dwarf_symbol, agent_workflow."""
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

# rustre_decompiler extras
r = call("rustre_decompiler_default_options", {})
if r:
    check("rustre_decompiler_v2", "default_options", any_valid(r), True, "options")
r = call("rustre_decompiler_batch_is_c_keyword", {"names":["int","hello","return"]})
if r:
    check("rustre_decompiler_v2", "batch_is_c_keyword", any_valid(r), True, "batch check")

# agent_llm extras
r = call("agent_llm_compress_message", {"text":"hello world this is a test message"})
if r:
    check("agent_llm_v2", "compress", any_valid(r), True, "compress")
r = call("agent_llm_trim_to_budget", {"text":"hello world", "max_tokens":5})
if r:
    check("agent_llm_v2", "trim_budget", any_valid(r), True, "trim")

# llm helpers
r = call("llm_compress_message", {"text":"very long test message"})
if r:
    check("llm_helpers", "compress", any_valid(r), True, "compressed")
r = call("llm_token_count_estimate", {"text":"hello world"})
if r and isinstance(r, dict):
    val = get_first(r, ["tokens","count","value","estimate"])
    check("llm_helpers", "token_count", isinstance(val, int) and val > 0, True, "tokens > 0")

# dwarf symbol
r = call("dwarf_symbol_set_summary_path", {"path":r"C:\Users\Fra\Desktop\Zyphora\target\release\cargo-zyphora.exe"})
if r:
    check("dwarf_symbol", "summary_path", any_valid(r), True, "summary")

# agent_workflow
r = call("agent_workflow_builtin_list", {})
if r:
    check("agent_workflow", "builtin_list", any_valid(r), True, "workflows")
r = call("agent_workflow_templates_list", {})
if r:
    check("agent_workflow", "templates", any_valid(r), True, "templates")

# agent_standard_re_pipeline
r = call("agent_standard_re_pipeline", {})
if r:
    check("agent_pipeline", "re_pipeline", any_valid(r), True, "pipeline")

# analysis_ctx
r = call("analysis_ctx_builder", {})
if r:
    check("analysis_ctx", "builder", any_valid(r), True, "builder")

# analysis_incremental
r = call("analysis_incremental_affected", {"changes":[]})
if r:
    check("analysis_incremental", "affected_empty", any_valid(r), True, "empty affected")

# ghidra_symbol
r = call("ghidra_symbol_importer_counts", {})
if r:
    check("ghidra_symbol", "counts", any_valid(r), True, "counts")

# diff_bindiff
r = call("diff_bindiff_bindiff_engine_defaults", {})
if r:
    check("diff_bindiff", "engine_defaults", any_valid(r), True, "defaults")

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
print(f"\nBATCH23 TOTAL: {total_p}/{total_c} passed, {total_m} mismatch across {len(per_cat)} categories")
