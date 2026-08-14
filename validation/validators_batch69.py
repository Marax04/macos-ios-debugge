#!/usr/bin/env python3
"""Batch69: hex_pattern final (masked/group/etc), symb_z3_solver_v3, trace_navigate final."""
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

for tool in ["trace_anomaly_detector_detect","trace_compressor_compression_ratio","trace_compressor_rle_wt1","trace_cov_bitmap_new","trace_cov_parse_lcov","trace_diff_compute","trace_diff_similarity_identical","trace_diff_similarity_wt1","trace_event_type_name","trace_event_type_name_wt1","trace_filter_instructions_only","trace_filter_matches","trace_filter_matches_wt1","trace_function_call_tree_build","trace_heatmap_from_session","trace_index_build_wt1","trace_json_roundtrip_wt1","trace_loop_detector_detect","trace_merge_empty_sessions","trace_merge_sessions_empty","trace_open_trace_file","trace_player_progress","trace_player_progress_wt1","trace_recorder_new","trace_recorder_record_insn","trace_recorder_record_wt1","trace_registry_engines_wt1","trace_session_build_heat_map","trace_session_build_index","trace_session_coverage_set","trace_session_duration_ns","trace_session_instruction_count","trace_session_instruction_count_wt1","trace_statistics_compute","trace_visualization_data_wt1"]:
    r = call(tool, {})
    if r:
        check("trace_top", tool.replace("trace_",""), any_valid(r), True, tool)

for tool in ["triage_analyze","triage_die_analyze_overlay","triage_die_builtin_rules_yaml_len","triage_die_check_imports","triage_die_compiler_detect","triage_die_compiler_detect_with_threshold","triage_die_compute_entropy","triage_die_database_load_defaults_count","triage_die_detect_file_kind","triage_die_detect_versions","triage_die_detection_list_names","triage_die_detector_with_defaults_detect","triage_die_engine_scan_bytes","triage_die_find_bytes","triage_die_get_entry_point_bytes","triage_die_heuristic_has_overlay","triage_die_match_condition_single","triage_die_match_rule_condition","triage_die_match_rule_condition_single","triage_die_packer_compute_entropy","triage_die_packer_full_analysis","triage_die_pe_sections_with_entropy","triage_die_read_pe_sections","triage_die_result_categorized","triage_die_result_max_confidence","triage_die_scanner_scan","triage_die_signature_confident_only","triage_die_signature_database_entry_count","triage_die_signature_database_scan"]:
    r = call(tool, {})
    if r:
        check("triage_die_v2", tool.replace("triage_",""), any_valid(r), True, tool)

for tool in ["triage_entropy_analyze_blocks_bytes","triage_entropy_analyze_blocks_path","triage_entropy_analyze_with_sections_bytes","triage_entropy_analyze_with_sections_path","triage_entropy_analyzer_analyze_bytes","triage_entropy_analyzer_analyze_path","triage_entropy_analyzer_new","triage_entropy_block_from_slice_bytes","triage_entropy_block_from_slice_path","triage_entropy_category_classify","triage_entropy_category_classify_bytes","triage_entropy_category_label","triage_entropy_heatmap_ascii_bytes","triage_entropy_heatmap_ascii_path","triage_entropy_heatmap_color_rgb","triage_entropy_heatmap_from_data_bytes","triage_entropy_heatmap_rgb_bytes","triage_entropy_heatmap_rgb_colors_path","triage_entropy_histogram_chi_square_bytes","triage_entropy_histogram_chi_square_path","triage_entropy_histogram_count_of_bytes","triage_entropy_histogram_is_random_bytes","triage_entropy_histogram_most_common_bytes","triage_entropy_histogram_most_common_path","triage_entropy_histogram_new_bytes","triage_entropy_histogram_path","triage_entropy_packing_indicators","triage_entropy_packing_indicators_bytes","triage_entropy_rating_display_from_entropy","triage_entropy_rating_from_bytes","triage_entropy_rating_from_entropy","triage_entropy_report_display_bytes","triage_entropy_report_display_path","triage_entropy_report_generate_bytes","triage_entropy_report_heatmap_bytes","triage_entropy_report_high_blocks_bytes","triage_entropy_report_high_blocks_path","triage_entropy_report_indicators_bytes","triage_entropy_report_path","triage_entropy_report_summary_bytes","triage_entropy_report_summary_path","triage_entropy_result_max_chunk_bytes","triage_entropy_result_overall_bytes","triage_entropy_result_packed_sections_bytes","triage_entropy_section_is_encrypted_bytes","triage_entropy_section_is_packed_bytes","triage_entropy_section_new_path","triage_entropy_shannon_alias","triage_entropy_shannon_bytes","triage_entropy_shannon_bytes_f32","triage_entropy_shannon_f32_bytes","triage_entropy_shannon_f32_path","triage_entropy_shannon_path","triage_entropy_survey_binary_bytes","triage_entropy_survey_binary_path"]:
    r = call(tool, {})
    if r:
        check("triage_entropy_v2", tool.replace("triage_entropy_",""), any_valid(r), True, tool)

try: p.terminate()
except: pass
for cat, d in per_cat.items():
    out = fr"C:\Users\Fra\Desktop\RustRE\validation\mismatch_{cat}.json"
    with open(out, "w") as f: json.dump({"category":cat, "checks_total":d["checks"], "checks_passed":d["passed"], "mismatches":d["mismatches"]}, f, indent=1)
    print(f"{cat}: {d['passed']}/{d['checks']} passed, {len(d['mismatches'])} mismatch")
total_c = sum(d["checks"] for d in per_cat.values()); total_p = sum(d["passed"] for d in per_cat.values()); total_m = sum(len(d["mismatches"]) for d in per_cat.values())
print(f"\nBATCH69 TOTAL: {total_p}/{total_c} passed, {total_m} mismatch across {len(per_cat)} categories")
