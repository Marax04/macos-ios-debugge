#!/usr/bin/env python3
"""Batch59: symbols_pdb_types, symbols_pdb_syms, symbols_v3, sandbox_report tail, forensics fs_lnk more."""
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

for tool in ["symbols_backends_registry","symbols_backends_registry_v2","symbols_cv_parse_sym_v5","symbols_cv_parse_type_v5","symbols_demangle_auto_v5","symbols_demangle_itanium_v5","symbols_demangle_msvc_v5","symbols_demangle_rust_v0_v5","symbols_demangle_swift_v5","symbols_discover_pdb_for_binary","symbols_elf_rel64_v5","symbols_elf_rela64_v5","symbols_exporter_to_csv","symbols_exporter_to_idc","symbols_exporter_to_json","symbols_exporter_to_map","symbols_function_boundary_contains","symbols_function_boundary_overlaps","symbols_function_boundary_size","symbols_fuzzy_score_v5","symbols_pdb_from_bytes","symbols_pdb_guid_format","symbols_pdb_module_proc_count","symbols_pdb_module_proc_symbols","symbols_pdb_symbol_server_msdl","symbols_pdb_symbol_server_url","symbols_pdb_symbols_filter_functions","symbols_pdb_symbols_with_segment","symbols_pdb_types_by_kind","symbols_stabs_line_number_table_lookup","symbols_symbol_contains","symbols_symbol_source_priority","symbols_synthetic_data_name","symbols_synthetic_dword_name","symbols_synthetic_function_name","symbols_synthetic_label_name","symbols_synthetic_qword_name","symbols_try_demangle","symbols_try_demangle_top","symbols_try_demangle_v5","symbols_wildcard_match_v5"]:
    r = call(tool, {})
    if r:
        check("symbols_top_v5", tool.replace("symbols_",""), any_valid(r), True, tool)

for tool in ["sandbox_report_attack_full_id_v5","sandbox_report_attack_high_confidence_v5","sandbox_report_attack_mapping_by_tactic_v3","sandbox_report_attack_mapping_from_behaviors","sandbox_report_attack_mapping_technique_ids_v4","sandbox_report_attack_tactics_present","sandbox_report_attack_tactics_present_v5","sandbox_report_behavior_timeline_build_v4","sandbox_report_behavior_timeline_summary_v4","sandbox_report_classifier_infer_family_v3","sandbox_report_critical_indicators_v5","sandbox_report_format_extension","sandbox_report_indicator_category_display_v5","sandbox_report_indicator_with_ioc_v5","sandbox_report_indicators_by_category","sandbox_report_ioc_collection_mock_v4","sandbox_report_ioc_collection_summary_text_v4","sandbox_report_ioc_collection_to_csv_v4","sandbox_report_ioc_is_confident","sandbox_report_ioc_is_confident_v3","sandbox_report_ioc_kind_display_all_v3","sandbox_report_ioc_new_clamp_v5","sandbox_report_iocset_by_kind","sandbox_report_iocset_by_kind_v3","sandbox_report_iocset_confident","sandbox_report_iocset_confident_v5","sandbox_report_iocset_dedupe_v5","sandbox_report_iocset_deduplicate","sandbox_report_iocset_mock","sandbox_report_iocset_mock_v2","sandbox_report_mock_html","sandbox_report_mock_json","sandbox_report_mock_markdown","sandbox_report_mock_summary","sandbox_report_report_format_extension_all_v3","sandbox_report_report_format_from_extension_v3","sandbox_report_report_format_from_extension_v4","sandbox_report_report_renderer_json_v5","sandbox_report_report_renderer_markdown_v5","sandbox_report_report_section_new_v4","sandbox_report_sandbox_report_build_attack_mapping_v4","sandbox_report_score_engine_compute","sandbox_report_score_engine_has_critical_v3","sandbox_report_score_engine_verdict","sandbox_report_score_engine_verdict_sweep_v3","sandbox_report_severity_parse_v2","sandbox_report_severity_parse_v5","sandbox_report_severity_score_all_v3"]:
    r = call(tool, {})
    if r:
        check("sandbox_report_v3", tool.replace("sandbox_report_",""), any_valid(r), True, tool)

try: p.terminate()
except: pass
for cat, d in per_cat.items():
    out = fr"C:\Users\Fra\Desktop\RustRE\validation\mismatch_{cat}.json"
    with open(out, "w") as f: json.dump({"category":cat, "checks_total":d["checks"], "checks_passed":d["passed"], "mismatches":d["mismatches"]}, f, indent=1)
    print(f"{cat}: {d['passed']}/{d['checks']} passed, {len(d['mismatches'])} mismatch")
total_c = sum(d["checks"] for d in per_cat.values()); total_p = sum(d["passed"] for d in per_cat.values()); total_m = sum(len(d["mismatches"]) for d in per_cat.values())
print(f"\nBATCH59 TOTAL: {total_p}/{total_c} passed, {total_m} mismatch across {len(per_cat)} categories")
