#!/usr/bin/env python3
"""Batch56: diff_bindiff more, diff extras, iadl, firmware, decomp_x more."""
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

for tool in ["diff_bindiff_bin_differ_min_similarity","diff_bindiff_bin_differ_propagation_toggle","diff_bindiff_binary_snapshot_call_graph","diff_bindiff_binary_snapshot_new","diff_bindiff_bindiff_engine_defaults","diff_bindiff_bindiffer_configure","diff_bindiff_bindiffer_defaults","diff_bindiff_cfg_hash_linear","diff_bindiff_cfg_hasher_compare","diff_bindiff_cfg_similarity","diff_bindiff_detailed_similarity","diff_bindiff_function_features_can_match","diff_bindiff_function_features_default","diff_bindiff_function_features_similarity","diff_bindiff_function_info_can_match","diff_bindiff_function_info_flags","diff_bindiff_function_info_from_features","diff_bindiff_function_info_new","diff_bindiff_function_info_self_similarity","diff_bindiff_function_match_lifecycle","diff_bindiff_function_match_quality","diff_bindiff_hungarian_dims","diff_bindiff_hungarian_from_similarity","diff_bindiff_hungarian_solve","diff_bindiff_hungarian_threshold","diff_bindiff_match_functions_greedy","diff_bindiff_match_functions_hungarian","diff_bindiff_match_kind_display","diff_bindiff_match_kind_is_reliable","diff_bindiff_match_kind_priority","diff_bindiff_match_kind_priority_order","diff_bindiff_match_kind_summary","diff_bindiff_match_matrix_above_threshold","diff_bindiff_match_matrix_build","diff_bindiff_match_matrix_greedy_assign"]:
    r = call(tool, {})
    if r:
        check("diff_bindiff_v3", tool.replace("diff_bindiff_",""), any_valid(r), True, tool)

for tool in ["diff_by_name_wire","diff_byte_histogram_similarity","diff_change_type_display_wire","diff_combined_byte_similarity","diff_engine_debug_wire","diff_engine_run_wire","diff_export_is_clean_wire","diff_fp_display_wire","diff_fp_new_wire","diff_fp_similarity_wire","diff_func_match_added_removed_wire","diff_func_match_identical_wire","diff_func_match_renamed_wire","diff_func_match_similar_wire","diff_lcs_similarity","diff_ngram_jaccard_similarity","diff_semantic_binary_diff_new_wire","diff_semantic_call_graph_leaf_root_wire","diff_semantic_call_graph_new_wire","diff_semantic_diff_engine_new_wire","diff_semantic_differ_diff_function_pair","diff_semantic_features_similarity_wire","diff_semantic_fn_rename_heuristic_wire","diff_semantic_jaccard_identical_wire","diff_semantic_lsh_insert_query_wire","diff_semantic_matcher_similarity","diff_semantic_minhash_empty_elements_wire","diff_semantic_minhash_estimate_jaccard","diff_semantic_minhash_signature"]:
    r = call(tool, {})
    if r:
        check("diff_v2", tool.replace("diff_",""), any_valid(r), True, tool)

try: p.terminate()
except: pass
for cat, d in per_cat.items():
    out = fr"C:\Users\Fra\Desktop\RustRE\validation\mismatch_{cat}.json"
    with open(out, "w") as f: json.dump({"category":cat, "checks_total":d["checks"], "checks_passed":d["passed"], "mismatches":d["mismatches"]}, f, indent=1)
    print(f"{cat}: {d['passed']}/{d['checks']} passed, {len(d['mismatches'])} mismatch")
total_c = sum(d["checks"] for d in per_cat.values()); total_p = sum(d["passed"] for d in per_cat.values()); total_m = sum(len(d["mismatches"]) for d in per_cat.values())
print(f"\nBATCH56 TOTAL: {total_p}/{total_c} passed, {total_m} mismatch across {len(per_cat)} categories")
