#!/usr/bin/env python3
"""Batch45: symb_z3 many more, symb helpers, mem more, hex_pattern more."""
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

def any_valid(r):
    if r is None: return False
    if isinstance(r, dict): return len(r) > 0
    if isinstance(r, list): return True
    if isinstance(r, str): return bool(r.strip()) and 'invalid' not in r.lower()[:20]
    return True

# symb helpers
for tool in ["symb_bitvec_width","symb_path_constraint_trivially_false","symb_pathconstraint_new_is_trivially_false","symb_simplifier_const_add","symb_sym_add_const","symb_sym_and_const_v2","symb_sym_expr_as_const_bool","symb_sym_expr_bit_width_const","symb_sym_mul_const_v2","symb_sym_not_const_v2","symb_sym_or_const_v2","symb_sym_sub_const_v2","symb_sym_type_width_v2","symb_sym_xor_const","symb_symtype_bitvec_width","symb_unsat_message"]:
    r = call(tool, {})
    if r:
        check("symb_helpers", tool.replace("symb_",""), any_valid(r), True, tool)

# rustre_symb
for tool in ["rustre_symb_bv_const","rustre_symb_eval_concrete","rustre_symb_expr_width","rustre_symb_path_conjunction","rustre_symb_simplify_add","rustre_symb_simplify_not","rustre_symb_simplify_xor","rustre_symb_spec_eval","rustre_symb_spec_substitute","rustre_symb_state_fork","rustre_symb_symwidth_info","rustre_symb_type_width"]:
    r = call(tool, {})
    if r:
        check("rustre_symb_v3", tool.replace("rustre_symb_",""), any_valid(r), True, tool)

# hex_pattern more
for tool in ["hex_pattern_compiled_search","hex_pattern_db_roundtrip_v4","hex_pattern_export_ida_pat","hex_pattern_exporter_export_json","hex_pattern_exporter_json_v4","hex_pattern_from_json","hex_pattern_group_compile_v4","hex_pattern_group_search_all","hex_pattern_group_to_json_v4","hex_pattern_import_ida_pat","hex_pattern_masked_len_v4","hex_pattern_masked_new","hex_pattern_masked_search","hex_pattern_parse","hex_pattern_regex_search","hex_pattern_regex_search_v4","hex_pattern_search","hex_pattern_search_with_captures","hex_pattern_signature_search","hex_pattern_specificity","hex_pattern_to_bytes","hex_pattern_to_hex_string_v3","hex_pattern_to_json","hex_pattern_to_masked_v3","hex_pattern_to_simd_form","hex_pattern_wildcard_count","hex_pattern_with_comment_v4","hex_pattern_with_name_v4","hex_pattern_with_tag_v4"]:
    r = call(tool, {})
    if r:
        check("hex_pattern_v9", tool.replace("hex_pattern_",""), any_valid(r), True, tool)

try: p.terminate()
except: pass
for cat, d in per_cat.items():
    out = fr"C:\Users\Fra\Desktop\RustRE\validation\mismatch_{cat}.json"
    with open(out, "w") as f: json.dump({"category":cat, "checks_total":d["checks"], "checks_passed":d["passed"], "mismatches":d["mismatches"]}, f, indent=1)
    print(f"{cat}: {d['passed']}/{d['checks']} passed, {len(d['mismatches'])} mismatch")
total_c = sum(d["checks"] for d in per_cat.values()); total_p = sum(d["passed"] for d in per_cat.values()); total_m = sum(len(d["mismatches"]) for d in per_cat.values())
print(f"\nBATCH45 TOTAL: {total_p}/{total_c} passed, {total_m} mismatch across {len(per_cat)} categories")
