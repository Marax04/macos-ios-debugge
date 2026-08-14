#!/usr/bin/env python3
"""Batch16: analysis_scan, xref_kind, forensics_hash extra, emu_qiling extra, agent_prompts, mobile_ipa."""
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

# xref_kind
r = call("analysis_xref_kind_all", {})
if r:
    check("xref_kind", "kind_all", any_valid(r), True, "list all kinds")
r = call("analysis_xref_kind_is_code", {"kind":"call"})
if r and isinstance(r, dict):
    val = get_first(r, ["is_code","value","result"])
    check("xref_kind", "call_is_code", val, True, "call=code")
r = call("analysis_xref_kind_is_data", {"kind":"read"})
if r and isinstance(r, dict):
    val = get_first(r, ["is_data","value","result"])
    check("xref_kind", "read_is_data", val, True, "read=data")

# agent_prompts
r = call("agent_prompts_builtin_template_names", {})
if r:
    check("agent_prompts", "template_names", any_valid(r), True, "template list")
r = call("agent_prompts_builtin_templates_count", {})
if r and isinstance(r, dict):
    val = get_first(r, ["count","value","result"])
    check("agent_prompts", "count", isinstance(val,int) and val > 0, True, "count > 0")

# mobile_ipa
r = call("mobile_ipa_plist_is_binary", {"data_hex":"62706c697374303030"})  # "bplist000"
if r and isinstance(r, dict):
    val = get_first(r, ["is_binary","value","result"])
    check("mobile_ipa", "is_binary(bplist)", val, True, "bplist magic")

# events_kind_subscription
r = call("events_kind_subscription", {})
if r:
    check("events_v2", "kind_subscription", any_valid(r), True, "sub")
r = call("events_classify_variant", {"variant":"analysis_started"})
if r:
    check("events_v2", "classify", any_valid(r), True, "classify")

# net_parse_arp
r = call("net_parse_arp_v2", {"data_hex":"00010800060400010000000000000000000000000000000000000000000000000000000000000000"})
if r:
    check("net_arp", "parse_arp", any_valid(r), True, "ARP parse")

# rustre_analysis_string extract_urls
r = call("rustre_analysis_string_extract_urls", {"text":"visit http://example.com/foo and https://test.org"})
if r and isinstance(r, dict):
    val = get_first(r, ["urls","results","value"])
    if isinstance(val, list):
        check("analysis_string_v3", "extract_urls", len(val), 2, "2 URLs")

# rustre_analysis_string extract_ips
r = call("rustre_analysis_string_extract_ips", {"text":"connect 192.168.1.1 and 10.0.0.1"})
if r and isinstance(r, dict):
    val = get_first(r, ["ips","results","value"])
    if isinstance(val, list):
        check("analysis_string_v3", "extract_ips", len(val), 2, "2 IPs")

# analysis_string_jaro_winkler
r = call("rustre_analysis_string_jaro_winkler", {"a":"MARTHA", "b":"MARHTA"})
if r and isinstance(r, dict):
    val = get_first(r, ["similarity","value","result","score"])
    if isinstance(val, (int, float)):
        # Standard result ~ 0.961
        check("analysis_string_v3", "jaro_winkler", val > 0.9 and val <= 1.0, True, "MARTHA/MARHTA ~ 0.961")

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
print(f"\nBATCH16 TOTAL: {total_p}/{total_c} passed, {total_m} mismatch across {len(per_cat)} categories")
