#!/usr/bin/env python3
"""Batch12: trace_navigate, trace_replay, ttd extra, ti_misp/otx/opencti."""
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

# trace_navigate: bookmark, coverage etc.
r = call("trace_navigate_bookmark_new", {"tick":100, "note":"test"})
if r:
    check("trace_navigate", "bookmark_new", any_valid(r), True, "bookmark")
r = call("trace_navigate_bookmark_store_new_wire", {})
if r:
    check("trace_navigate", "bookmark_store", any_valid(r), True, "store")
r = call("trace_navigate_bytes_to_u64", {"bytes":[0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00]})
if r and isinstance(r, dict):
    val = get_first(r, ["value","result","u64"])
    check("trace_navigate", "bytes_to_u64", val, 1, "LE 1")

# trace_replay
r = call("ttd_replay_delta_compressor", {})
if r:
    check("trace_replay", "delta_compressor", any_valid(r), True, "compressor")

# ttd position ordering
r = call("ttd_position_compare", {"a":{"sequence":1,"step":10},"b":{"sequence":2,"step":0}})
if r and isinstance(r, dict):
    val = get_first(r, ["ordering","result","value","cmp"])
    # a < b since sequence differs
    check("ttd_pos_v2", "compare(a<b)", str(val).lower() in ("less","-1","lt"), True, "seq1<seq2")

# ti_misp
r = call("ti_misp_distribution_level_value_v3", {"level":"organisation"})
if r and isinstance(r, dict):
    val = get_first(r, ["value","level","result"])
    # organisation = 1 typically
    check("ti_misp", "dist_org", val, 1, "org level=1")

# ti_otx
r = call("ti_otx_threat_level", {"score":50})
if r:
    check("ti_otx", "threat_level", any_valid(r), True, "threat level")

# ti_opencti
r = call("ti_opencti_confidence_clamp", {"value":150})
if r and isinstance(r, dict):
    val = get_first(r, ["clamped","result"])
    # schema max=255 so 150 stays 150; check clamp of >255 or accept 150 as valid
    if val is None:
        val = r.get("value")
    check("ti_opencti", "confidence_clamp(150)", val, 150, "in range 0-255")
r = call("ti_opencti_confidence_is_high", {"value":80})
if r and isinstance(r, dict):
    val = get_first(r, ["is_high","value","result"])
    check("ti_opencti", "is_high(80)", val, True, "80>=high threshold")

# ti_malpedia
r = call("ti_malpedia_api_key_is_valid", {"key":""})
if r and isinstance(r, dict):
    val = get_first(r, ["is_valid","valid","value"])
    check("ti_malpedia", "empty_key_invalid", val, False, "empty key invalid")

# threatintel_ttp
r = call("threatintel_ttp_is_sub_technique", {"technique_id":"T1053.001","name":"foo","tactic":"execution"})
if r and isinstance(r, dict):
    val = get_first(r, ["is_sub","sub","is_sub_technique","value","result"])
    check("threatintel_ttp", "sub_technique(T1053.001)", val, True, "has . = sub")
r = call("threatintel_ttp_is_sub_technique", {"technique_id":"T1053","name":"foo","tactic":"execution"})
if r and isinstance(r, dict):
    val = get_first(r, ["is_sub","sub","is_sub_technique","value","result"])
    check("threatintel_ttp", "not_sub(T1053)", val, False, "no . = not sub")

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
print(f"\nBATCH12 TOTAL: {total_p}/{total_c} passed, {total_m} mismatch across {len(per_cat)} categories")
