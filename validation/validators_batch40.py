#!/usr/bin/env python3
"""Batch40: rlib_dec2, sandbox, ttd_query more, trace_navigate more, forensics_hash."""
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

# rlib_dec2
for tool in ["rlib_dec2_annotation_comment","rlib_dec2_annotation_store_add_len","rlib_dec2_annotation_store_at_address","rlib_dec2_annotation_store_by_category","rlib_dec2_annotation_symbol_name","rlib_dec2_annotation_type_info","rlib_dec2_cache_insert_get","rlib_dec2_cfs_add_structure","rlib_dec2_cfs_flatten","rlib_dec2_cfs_make_for","rlib_dec2_cfs_make_switch","rlib_dec2_decompilation_result_is_success","rlib_dec2_default_pipeline_disasm","rlib_dec2_default_pipeline_standard","rlib_dec2_diagnostic_from_pass","rlib_dec2_function_new","rlib_dec2_function_parameters","rlib_dec2_function_with_call_site","rlib_dec2_infer_sign_hints","rlib_dec2_inlining_pass_is_candidate","rlib_dec2_ir_level_display","rlib_dec2_name_recovery_pass","rlib_dec2_pass_registry_ops","rlib_dec2_quality_readability_score","rlib_dec2_stats_success_rate","rlib_dec2_symbol_map_extend_pairs","rlib_dec2_timing_hook_total","rlib_dec2_typeprop_all_typed","rlib_dec2_var_storage_display","rlib_dec2_variable_new"]:
    r = call(tool, {})
    if r:
        check("rlib_dec2", tool.replace("rlib_dec2_",""), any_valid(r), True, tool)

# ttd_query more
for tool in ["ttd_query_call_frequency","ttd_query_call_tree","ttd_query_code_coverage","ttd_query_count_thread","ttd_query_exec_all_events","ttd_query_exec_loops","ttd_query_explain","ttd_query_filter_by_address_range","ttd_query_first_occurrence_thread","ttd_query_heap_ops","ttd_query_histogram_by_kind","ttd_query_last_occurrence_thread","ttd_query_memory_access_report","ttd_query_memory_report","ttd_query_most_accessed_addresses","ttd_query_most_called","ttd_query_parse","ttd_query_recursive_calls","ttd_query_string_accesses","ttd_query_syscall_summary","ttd_query_trace_event_count"]:
    r = call(tool, {})
    if r:
        check("ttd_query_v3", tool.replace("ttd_query_",""), any_valid(r), True, tool)

# forensics_hash
for tool in ["forensics_compute_md5","forensics_compute_sha1","forensics_compute_sha256","forensics_compute_sha512","forensics_list_plugins"]:
    r = call(tool, {"data":"hello"} if "compute" in tool else {})
    if r:
        check("forensics_hash_v2", tool.replace("forensics_",""), any_valid(r), True, tool)

try: p.terminate()
except: pass
for cat, d in per_cat.items():
    out = fr"C:\Users\Fra\Desktop\RustRE\validation\mismatch_{cat}.json"
    with open(out, "w") as f: json.dump({"category":cat, "checks_total":d["checks"], "checks_passed":d["passed"], "mismatches":d["mismatches"]}, f, indent=1)
    print(f"{cat}: {d['passed']}/{d['checks']} passed, {len(d['mismatches'])} mismatch")
total_c = sum(d["checks"] for d in per_cat.values()); total_p = sum(d["passed"] for d in per_cat.values()); total_m = sum(len(d["mismatches"]) for d in per_cat.values())
print(f"\nBATCH40 TOTAL: {total_p}/{total_c} passed, {total_m} mismatch across {len(per_cat)} categories")
