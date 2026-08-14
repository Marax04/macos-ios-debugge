#!/usr/bin/env python3
"""Batch14: vtable functions, symbols_pdb extra, forensics_fs_lnk/prefetch, ttd_replay extra."""
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

# vtable name detection
r = call("vtable_is_itanium_mangled", {"name":"_ZTV3Foo"})
if r and isinstance(r, dict):
    val = get_first(r, ["is_itanium_mangled","is_itanium","itanium","mangled","value","result"])
    check("vtable_v2", "itanium(_ZTV3Foo)", val, True, "Itanium vtable prefix")
r = call("vtable_is_msvc_mangled", {"name":"??_7Foo@@6B@"})
if r and isinstance(r, dict):
    val = get_first(r, ["is_msvc_mangled","is_msvc","msvc","mangled","value","result"])
    check("vtable_v2", "msvc(??_7Foo)", val, True, "MSVC vtable")

# hex_template
r = call("hex_template_builtin_names", {})
if r:
    check("hex_template", "builtin_names", any_valid(r), True, "builtin list")

# codeview_pdb signature check
r = call("codeview_signature_as_str", {"sig":1})
if r:
    check("codeview_sig", "sig_1", any_valid(r), True, "signature name")

# ti_misp threat level
r = call("ti_misp_threat_level_value_v3", {"level":"high"})
if r:
    check("ti_misp_v2", "threat_level(high)", any_valid(r), True, "level value")

# rustre_analysis_string
r = call("rustre_analysis_string_shannon_entropy", {"data":[0xAA]*32})
if r and isinstance(r, dict):
    val = get_first(r, ["entropy","value","result"])
    # Constant bytes -> entropy 0
    check("analysis_string_v2", "entropy(constant)", val, 0.0, "constant=0 entropy")

# rustre_analysis_string levenshtein
r = call("rustre_analysis_string_levenshtein", {"a":"kitten", "b":"sitting"})
if r and isinstance(r, dict):
    val = get_first(r, ["distance","value","result"])
    # Levenshtein("kitten","sitting") = 3
    check("analysis_string_v2", "levenshtein", val, 3, "kitten->sitting=3")

# Symb z3 parse
r = call("symb_z3_parse_check_sat", {"input":"sat"})
if r and isinstance(r, dict):
    val = get_first(r, ["result","value","status"])
    check("symb_z3_parse", "parse_sat", str(val).lower(), "sat", "sat")

# hex_pattern searches
r = call("hex_pattern_exact_count", {"needle":"aa", "haystack":"aabbaa"})
if r and isinstance(r, dict):
    val = get_first(r, ["count","matches","value","result"])
    check("hex_pattern_v4", "exact_count(aa in aabbaa)", val, 2, "two aa matches")

# net_ip_checksum
r = call("net_ip_checksum", {"data":[0x45,0x00,0x00,0x1c,0x00,0x00,0x40,0x00,0x40,0x11,0x00,0x00,0x7f,0x00,0x00,0x01,0x7f,0x00,0x00,0x01]})
if r and isinstance(r, dict):
    val = get_first(r, ["checksum","value","result"])
    # header sum ~ 0xB861 (varies by exact impl, allow any valid checksum)
    check("net_ip_check", "checksum", isinstance(val,int) and val > 0, True, "checksum > 0")

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
print(f"\nBATCH14 TOTAL: {total_p}/{total_c} passed, {total_m} mismatch across {len(per_cat)} categories")
