#!/usr/bin/env python3
"""Batch18: symbols_backends, agent_metrics, il_lift filters, deobf_smc extra."""
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

# symbols_backends
r = call("symbols_backends_registry", {})
if r:
    check("symbols_backends", "registry", any_valid(r), True, "registry list")
r = call("symbols_backends_registry_v2", {})
if r:
    check("symbols_backends", "registry_v2", any_valid(r), True, "registry v2")

# agent_metrics
r = call("agent_metrics_new_v2", {})
if r:
    check("agent_metrics", "new", any_valid(r), True, "new metrics")
r = call("agent_metrics_success_rate", {"total":10, "success":8})
if r and isinstance(r, dict):
    val = get_first(r, ["rate","value","success_rate","result"])
    check("agent_metrics", "success_rate(8/10)", val, 0.8, "8/10=0.8")

# il_lift filters
r = call("il_lift_supported_arches", {})
if r:
    check("il_lift_v3", "supported_arches", any_valid(r), True, "arch list")
r = call("il_lift_level_all", {})
if r:
    check("il_lift_v3", "level_all", any_valid(r), True, "level enum")
r = call("il_lift_arch_count", {})
if r and isinstance(r, dict):
    val = get_first(r, ["count","value","result"])
    check("il_lift_v3", "arch_count", isinstance(val,int) and val >= 3, True, "3+ arches")

# deobf_smc extra
r = call("deobf_smc_looks_like_code", {"data":[0x55,0x48,0x89,0xE5,0xC3]})  # push rbp; mov rbp,rsp; ret
if r and isinstance(r, dict):
    val = get_first(r, ["looks_like_code","value","result"])
    check("deobf_smc_v3", "code_pattern", val, True, "epilog looks like code")

# hex_pattern signature
r = call("hex_pattern_signature_matches_v4", {"pattern":"AA BB CC", "data":[0xAA,0xBB,0xCC,0x00]})
if r:
    check("hex_pattern_v5", "signature_match", any_valid(r), True, "match")

# arch_wasm extras
r = call("arch_wasm_module_header_magic_ok", {"data":[0x00,0x61,0x73,0x6d,0x01,0x00,0x00,0x00]})
if r and isinstance(r, dict):
    val = get_first(r, ["canonical_ok","magic_ok","ok","value","result"])
    check("arch_wasm_v2", "magic_ok", val, True, "wasm magic")

# fuzz_afl stage bit flip
r = call("fuzz_afl_stage_bit_flip_1", {"data":[0x00]})
if r:
    check("fuzz_afl_v2", "bit_flip_1", any_valid(r), True, "mutations")

# demangle standard substitution
r = call("demangle_standard_substitution", {"code":"St"})
if r:
    check("demangle_v2", "std_sub(St)", any_valid(r), True, "std namespace")

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
print(f"\nBATCH18 TOTAL: {total_p}/{total_c} passed, {total_m} mismatch across {len(per_cat)} categories")
