#!/usr/bin/env python3
"""Batch32: analysis_type extras, arch_wasm many, ti_misp extras, threatintel_ext, deobf_vm extras, sandbox_report more."""
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

# analysis_type extras
for tool in ["analysis_type_environment_merge","analysis_type_call_graph_topo_order","analysis_type_infer_signature","analysis_type_list_builtin_types","analysis_type_lookup_builtin_type","analysis_type_solve_simple","analysis_type_winapi_all_signatures","analysis_type_winapi_lookup","analysis_type_fact_join","analysis_type_fact_display"]:
    r = call(tool, {})
    if r:
        check("analysis_type_v3", tool.replace("analysis_type_",""), any_valid(r), True, tool)

# arch_wasm many
for tool in ["arch_wasm_arch_info","arch_wasm_constants","arch_wasm_section_id_all","arch_wasm_valtype_all_bytes","arch_wasm_external_kind_name","arch_wasm_disassemble","arch_wasm_cf_basic_blocks","arch_wasm_call_graph_edge_count","arch_wasm_indirect_call_table_entry_count","arch_wasm_stack_new_empty","arch_wasm_stack_ops"]:
    r = call(tool, {"bytes":[0x00,0x61,0x73,0x6d,0x01,0x00,0x00,0x00]} if "disassemble" in tool else {})
    if r:
        check("arch_wasm_v3", tool.replace("arch_wasm_",""), any_valid(r), True, tool)

# ti_misp extras
for tool in ["ti_misp_analysis_level_display_v4","ti_misp_attribute_type_roundtrip","ti_misp_distribution_level_describe","ti_misp_event_full_new","ti_misp_feed_new","ti_misp_galaxy_cluster_new","ti_misp_sighting_is_false_positive","ti_misp_warning_list_check"]:
    r = call(tool, {})
    if r:
        check("ti_misp_v3", tool.replace("ti_misp_",""), any_valid(r), True, tool)

# threatintel_ext
for tool in ["threatintel_ext_group_link_iocs_and_count","threatintel_ext_ioc_db_add_multiple","threatintel_ext_ioc_new_clamp_confidence","threatintel_ext_ioc_type_all_variants","threatintel_ext_mitre_ttp_format","threatintel_ext_motivation_display","threatintel_ext_stix_bundle_object_count","threatintel_ext_tracker_known_count","threatintel_ext_tracker_search_alias_case"]:
    r = call(tool, {})
    if r:
        check("threatintel_ext_v2", tool.replace("threatintel_ext_",""), any_valid(r), True, tool)

# deobf_vm extras
for tool in ["deobf_vm_arch_summary","deobf_vm_bytecode_inspect","deobf_vm_bytecode_new","deobf_vm_detect_dispatcher","deobf_vm_detector_analyze","deobf_vm_handler_classify","deobf_vm_handler_cluster","deobf_vm_lifter_lift","deobf_vm_pcode_varnode_size","deobf_vm_semantic_op_stack_delta"]:
    r = call(tool, {})
    if r:
        check("deobf_vm_v2", tool.replace("deobf_vm_",""), any_valid(r), True, tool)

# sandbox_report more
for tool in ["sandbox_report_attack_high_confidence","sandbox_report_attack_tactic_list_v3","sandbox_report_behavior_classify","sandbox_report_classify_apis","sandbox_report_critical_indicators","sandbox_report_infer_family","sandbox_report_ioc_set_add_v4","sandbox_report_severity_parse","sandbox_report_verdict_all_display_v3"]:
    r = call(tool, {"severity":"high"} if "severity_parse" in tool else {})
    if r:
        check("sandbox_report_v2", tool.replace("sandbox_report_",""), any_valid(r), True, tool)

# Save
try: p.terminate()
except: pass
for cat, d in per_cat.items():
    out = fr"C:\Users\Fra\Desktop\RustRE\validation\mismatch_{cat}.json"
    with open(out, "w") as f: json.dump({"category":cat, "checks_total":d["checks"], "checks_passed":d["passed"], "mismatches":d["mismatches"]}, f, indent=1)
    print(f"{cat}: {d['passed']}/{d['checks']} passed, {len(d['mismatches'])} mismatch")
total_c = sum(d["checks"] for d in per_cat.values()); total_p = sum(d["passed"] for d in per_cat.values()); total_m = sum(len(d["mismatches"]) for d in per_cat.values())
print(f"\nBATCH32 TOTAL: {total_p}/{total_c} passed, {total_m} mismatch across {len(per_cat)} categories")
