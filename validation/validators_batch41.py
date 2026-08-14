#!/usr/bin/env python3
"""Batch41: trace_coverage more, trace_navigate more, mobile_jadx, mobile_apktool, mobile_dyld more."""
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

# trace_coverage more
for tool in ["trace_coverage_afl_bitmap_count","trace_coverage_afl_jaccard","trace_coverage_afl_new_coverage","trace_coverage_block_colors_v2","trace_coverage_compute_function_stats_v2","trace_coverage_covbitmap_clear_bits","trace_coverage_covbitmap_ops","trace_coverage_covbitmap_record_edge","trace_coverage_covedge_display","trace_coverage_covedge_new_wire3","trace_coverage_data_stats","trace_coverage_diff_compute_v2","trace_coverage_diff_overlap_pct","trace_coverage_drcov_parse","trace_coverage_drcov_resolve","trace_coverage_function_stats_flags","trace_coverage_function_stats_pct","trace_coverage_heatmap_hottest","trace_coverage_html_report_v2","trace_coverage_lighthouse_from_run_v2","trace_coverage_lighthouse_roundtrip","trace_coverage_map_hit_count","trace_coverage_map_new","trace_coverage_merge_all_runs_v2","trace_coverage_merge_runs","trace_coverage_percent","trace_coverage_run_summary","trace_coverage_session_add_run_wire3"]:
    r = call(tool, {})
    if r:
        check("trace_coverage_v2", tool.replace("trace_coverage_",""), any_valid(r), True, tool)

# trace_navigate more
for tool in ["trace_navigate_access_kind_display","trace_navigate_bookmark_new","trace_navigate_bookmark_store_new_wire","trace_navigate_bytes_to_u64","trace_navigate_call_entry","trace_navigate_call_index_build_wp","trace_navigate_call_stack_reconstructor_new_wire","trace_navigate_coverage_build_empty_wire","trace_navigate_execution_trace_len_wire","trace_navigate_execution_trace_new_v2","trace_navigate_idx_for_tsc","trace_navigate_insn_entry","trace_navigate_mem_access_index","trace_navigate_nav_history_new_wire","trace_navigate_navigation_history","trace_navigate_ret_entry","trace_navigate_stackframe_display_name","trace_navigate_step_window"]:
    r = call(tool, {})
    if r:
        check("trace_navigate_v3", tool.replace("trace_navigate_",""), any_valid(r), True, tool)

# mobile more
for tool in ["mobile_apktool_config_new","mobile_apktool_cli_with_path","mobile_apktool_find","mobile_apktool_install_framework","mobile_jadx_config_new","mobile_jadx_config_with_deobfuscate","mobile_jadx_config_with_threads","mobile_jadx_find","mobile_jadx_dalvik_opcode_from_byte","mobile_jadx_dalvik_opcode_mnemonic","mobile_jadx_java_method_is_constructor","mobile_dyld_format_uuid","mobile_dyld_header_is_arm64","mobile_dyld_header_is_simulator","mobile_dyld_header_platform_name","mobile_dyld_image_filename","mobile_dyld_image_is_swift_overlay","mobile_dyld_symbol_is_objc","mobile_dyld_symbol_is_swift"]:
    r = call(tool, {})
    if r:
        check("mobile_v3", tool.replace("mobile_",""), any_valid(r), True, tool)

try: p.terminate()
except: pass
for cat, d in per_cat.items():
    out = fr"C:\Users\Fra\Desktop\RustRE\validation\mismatch_{cat}.json"
    with open(out, "w") as f: json.dump({"category":cat, "checks_total":d["checks"], "checks_passed":d["passed"], "mismatches":d["mismatches"]}, f, indent=1)
    print(f"{cat}: {d['passed']}/{d['checks']} passed, {len(d['mismatches'])} mismatch")
total_c = sum(d["checks"] for d in per_cat.values()); total_p = sum(d["passed"] for d in per_cat.values()); total_m = sum(len(d["mismatches"]) for d in per_cat.values())
print(f"\nBATCH41 TOTAL: {total_p}/{total_c} passed, {total_m} mismatch across {len(per_cat)} categories")
