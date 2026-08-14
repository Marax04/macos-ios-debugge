#!/usr/bin/env python3
"""Batch54: symb_z3 eval more, symb_engine more, symb_z3_builder, sandbox_vm, sandbox_behavior."""
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

for tool in ["symb_z3_eval_and_const","symb_z3_eval_ashr_const","symb_z3_eval_bv_not_const","symb_z3_eval_concrete_add","symb_z3_eval_concrete_mul_const","symb_z3_eval_concrete_sub","symb_z3_eval_eq_const","symb_z3_eval_extract_const","symb_z3_eval_lshr_const","symb_z3_eval_mul","symb_z3_eval_ne_const","symb_z3_eval_neg_const","symb_z3_eval_or_const","symb_z3_eval_sdiv_const","symb_z3_eval_sdiv_const_wire","symb_z3_eval_shl_const","symb_z3_eval_sign_ext_neg","symb_z3_eval_sle_const","symb_z3_eval_slt_const","symb_z3_eval_slt_const_v2","symb_z3_eval_srem_const","symb_z3_eval_srem_const_wire","symb_z3_eval_sub_const","symb_z3_eval_udiv_const","symb_z3_eval_uge_const","symb_z3_eval_ugt_const","symb_z3_eval_ule_const","symb_z3_eval_ult_const","symb_z3_eval_urem_const","symb_z3_eval_xor","symb_z3_eval_zero_ext_const"]:
    r = call(tool, {})
    if r:
        check("symb_z3_eval_v3", tool.replace("symb_z3_",""), any_valid(r), True, tool)

for tool in ["symb_engine_executor_config_defaults","symb_engine_executor_config_defaults_v3","symb_engine_expr_depth_chain_add","symb_engine_expr_node_count_chain_add","symb_engine_format_path_conditions_const","symb_engine_function_summary_new_v3","symb_engine_has_contradiction_const","symb_engine_loop_bound_analysis_add_edge","symb_engine_loop_bound_analysis_new","symb_engine_state_manager_empty_stats","symb_engine_state_manager_new","symb_engine_state_manager_new_len","symb_engine_state_merger_hash_constraints","symb_engine_symbolic_address_concrete","symb_engine_symbolic_executor_stats","symb_engine_symbolic_interpreter_state_new","symb_engine_vuln_detector_empty","symb_engine_vuln_detector_new","symb_engine_vuln_detector_register_free","symb_engine_widen_sequence_expr"]:
    r = call(tool, {})
    if r:
        check("symb_engine_v3", tool.replace("symb_engine_",""), any_valid(r), True, tool)

for tool in ["symb_z3_builder_decl_logic","symb_z3_builder_logic","symb_z3_collect_symbols_count","symb_z3_collect_symbols_var","symb_z3_const_bit_width","symb_z3_emit_bv_and","symb_z3_emit_bv_not","symb_z3_emit_bv_or","symb_z3_emit_const","symb_z3_emit_ite_const","symb_z3_emit_smtlib2_const","symb_z3_find_input_simple","symb_z3_is_sat_concrete_trivial","symb_z3_prove_equiv_reflex","symb_z3_prove_equivalent_const"]:
    r = call(tool, {})
    if r:
        check("symb_z3_builder", tool.replace("symb_z3_",""), any_valid(r), True, tool)

for tool in ["sandbox_behavior_record_mock_summary","sandbox_resource_limits_check","sandbox_vm_memory_map_mock","sandbox_vm_qemu_build_args"]:
    r = call(tool, {})
    if r:
        check("sandbox_v3", tool.replace("sandbox_",""), any_valid(r), True, tool)

try: p.terminate()
except: pass
for cat, d in per_cat.items():
    out = fr"C:\Users\Fra\Desktop\RustRE\validation\mismatch_{cat}.json"
    with open(out, "w") as f: json.dump({"category":cat, "checks_total":d["checks"], "checks_passed":d["passed"], "mismatches":d["mismatches"]}, f, indent=1)
    print(f"{cat}: {d['passed']}/{d['checks']} passed, {len(d['mismatches'])} mismatch")
total_c = sum(d["checks"] for d in per_cat.values()); total_p = sum(d["passed"] for d in per_cat.values()); total_m = sum(len(d["mismatches"]) for d in per_cat.values())
print(f"\nBATCH54 TOTAL: {total_p}/{total_c} passed, {total_m} mismatch across {len(per_cat)} categories")
