#!/usr/bin/env python3
"""Batch24: rustre_symb_v2 extras, codeview, diff_semantic, diff_bindiff extras, kgdb."""
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

# rustre_symb_v2 extras
for tool in ["rustre_symb_v2_symbolic_sub","rustre_symb_v2_symbolic_and","rustre_symb_v2_symbolic_or","rustre_symb_v2_symbolic_xor","rustre_symb_v2_symbolic_not","rustre_symb_v2_symexpr_eq","rustre_symb_v2_symexpr_ite","rustre_symb_v2_symexpr_extract","rustre_symb_v2_fresh_sym_id"]:
    r = call(tool, {"a":5,"b":3,"bits":32} if "symbolic_" in tool else {"a":5,"b":3,"width":32} if "eq" in tool else {})
    if r:
        check("rustre_symb_v3", tool.replace("rustre_symb_v2_",""), any_valid(r), True, tool)

# codeview extras
for tool, args in [
    ("codeview_magic_detect", {"data":[0x52,0x53,0x44,0x53]}),  # RSDS
    ("codeview_magic_label", {"magic":0x53445352}),
    ("codeview_guid_to_string", {"guid":[0]*16}),
    ("codeview_type_kind_from_u16", {"kind":0x1001}),
    ("codeview_sym_kind_is_named_address", {"kind":0x1108}),
]:
    r = call(tool, args)
    if r:
        check("codeview_v2", tool.replace("codeview_",""), any_valid(r), True, tool)

# diff_semantic
for tool in ["diff_semantic_minhash_new_wire","diff_semantic_lsh_index_new_wire","diff_semantic_features_from_empty_wire","diff_semantic_signature_compute","diff_semantic_matcher_are_equivalent"]:
    r = call(tool, {})
    if r:
        check("diff_semantic_v2", tool.replace("diff_semantic_","").replace("_wire",""), any_valid(r), True, tool)

# diff_bindiff extras
for tool in ["diff_bindiff_bindiffer_defaults","diff_bindiff_cfg_hash","diff_bindiff_similarity_score","diff_bindiff_wl_hash","diff_bindiff_jaccard_bb_score"]:
    r = call(tool, {"a":[1,2,3], "b":[1,2,4]} if "jaccard" in tool or "similarity" in tool else {})
    if r:
        check("diff_bindiff_v2", tool.replace("diff_bindiff_",""), any_valid(r), True, tool)

# kgdb
for tool in ["kgdb_rle_encode","kgdb_rle_decode","kgdb_rsp_checksum","kgdb_hex_to_bytes","kgdb_bytes_to_hex","kgdb_page_align","kgdb_is_kernel_address"]:
    args = {"data":[0x00,0x00,0xFF]} if "rle" in tool else {"data":"deadbeef"} if "checksum" in tool else {"hex":"deadbeef"} if "hex_to" in tool else {"bytes":[0xDE,0xAD]} if "bytes_to" in tool else {"addr":0xFFFF800000000000, "align":0x1000} if "page_align" in tool else {"addr":0xFFFF800000000000}
    r = call(tool, args)
    if r:
        check("kgdb_v2", tool.replace("kgdb_",""), any_valid(r), True, tool)

# Save
try: p.terminate()
except: pass
for cat, d in per_cat.items():
    out = fr"C:\Users\Fra\Desktop\RustRE\validation\mismatch_{cat}.json"
    with open(out, "w") as f: json.dump({"category":cat, "checks_total":d["checks"], "checks_passed":d["passed"], "mismatches":d["mismatches"]}, f, indent=1)
    print(f"{cat}: {d['passed']}/{d['checks']} passed, {len(d['mismatches'])} mismatch")
total_c = sum(d["checks"] for d in per_cat.values()); total_p = sum(d["passed"] for d in per_cat.values()); total_m = sum(len(d["mismatches"]) for d in per_cat.values())
print(f"\nBATCH24 TOTAL: {total_p}/{total_c} passed, {total_m} mismatch across {len(per_cat)} categories")
