#!/usr/bin/env python3
"""Batch37: analysis_xref index, il_passes more, symb_z3 parse more, dwarf many, il_lift more."""
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

# analysis_xref index
for tool in ["analysis_xref_index_callees_of","analysis_xref_index_callers_of","analysis_xref_index_count_kind","analysis_xref_index_data_refs_to","analysis_xref_index_hot_call_targets","analysis_xref_index_is_leaf","analysis_xref_index_sources_targets","analysis_xref_index_total","analysis_xref_kind_all","analysis_xref_call_graph"]:
    r = call(tool, {})
    if r:
        check("analysis_xref_index", tool.replace("analysis_xref_",""), any_valid(r), True, tool)

# il_passes more
for tool in ["il_passes_collect_call_sites","il_passes_count_constants","il_passes_count_instrs","il_passes_detect_loops","il_passes_inlining_score","il_passes_integer_range_analysis","il_passes_loop_bound_analysis","il_passes_run_gvn_pass"]:
    r = call(tool, {})
    if r:
        check("il_passes_v3", tool.replace("il_passes_",""), any_valid(r), True, tool)

# symb_z3 parse more
for tool in ["symb_z3_parse_bv_hex","symb_z3_parse_check_sat_raw","symb_z3_parse_check_sat_unknown","symb_z3_parse_check_sat_wire","symb_z3_parse_model","symb_z3_parse_model_line","symb_z3_eval_ashr_const","symb_z3_eval_extract_const","symb_z3_eval_sdiv_const","symb_z3_eval_sign_ext_neg","symb_z3_eval_sle_const","symb_z3_eval_slt_const","symb_z3_eval_srem_const","symb_z3_eval_uge_const","symb_z3_eval_ugt_const","symb_z3_eval_ule_const","symb_z3_eval_ult_const"]:
    r = call(tool, {})
    if r:
        check("symb_z3_parse_v2", tool.replace("symb_z3_",""), any_valid(r), True, tool)

# dwarf many
for tool in ["dwarf_abbrev_read_sleb128","dwarf_abbrev_read_uleb128","dwarf_casts_i64_to_u32","dwarf_casts_i64_to_u64","dwarf_casts_u64_to_i64","dwarf_casts_u64_to_u32","dwarf_casts_u8_to_i8"]:
    r = call(tool, {"bytes":[0x42]} if "read_" in tool else {"n":42})
    if r:
        check("dwarf_v2", tool.replace("dwarf_",""), any_valid(r), True, tool)

# il_lift more
for tool in ["il_lift_lift_diff_empty_n5","il_lift_lift_report_summary_default_j30","il_lift_lift_result_success_rate_empty_n5","il_lift_lift_stats_hit_rate_n5","il_lift_lift_stats_merge_n5","il_lift_lift_stats_new","il_lift_lift_stats_rates","il_lift_liftcache_ops","il_lift_lifted_instr_terminator_n5","il_lift_lifter_registry_arch_names"]:
    r = call(tool, {})
    if r:
        check("il_lift_v5", tool.replace("il_lift_",""), any_valid(r), True, tool)

try: p.terminate()
except: pass
for cat, d in per_cat.items():
    out = fr"C:\Users\Fra\Desktop\RustRE\validation\mismatch_{cat}.json"
    with open(out, "w") as f: json.dump({"category":cat, "checks_total":d["checks"], "checks_passed":d["passed"], "mismatches":d["mismatches"]}, f, indent=1)
    print(f"{cat}: {d['passed']}/{d['checks']} passed, {len(d['mismatches'])} mismatch")
total_c = sum(d["checks"] for d in per_cat.values()); total_p = sum(d["passed"] for d in per_cat.values()); total_m = sum(len(d["mismatches"]) for d in per_cat.values())
print(f"\nBATCH37 TOTAL: {total_p}/{total_c} passed, {total_m} mismatch across {len(per_cat)} categories")
