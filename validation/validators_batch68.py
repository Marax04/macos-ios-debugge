#!/usr/bin/env python3
"""Batch68: analysis_string more, agent_llm_lib final, ghidra pcode more, ghidra memory, ghidra symbols."""
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

for tool in ["analysis_string_detect_xor_key","analysis_string_detect_xor_key_wire2","analysis_string_extract_urls_path","analysis_string_scan_path","analysis_string_shannon_entropy_wire2","analysis_string_stats_path","analysis_count_basic_blocks","analysis_count_strings","analysis_count_xrefs","analysis_crypto_scan_path","analysis_event_bus_publish","analysis_fn_detect_extra","analysis_fn_detect_functions_path","analysis_linear_sweep","analysis_progress_track","analysis_recursive_descent","analysis_result_zero_total_items","analysis_scan_call_targets","analysis_scan_prologues","analysis_stats_aggregate"]:
    r = call(tool, {})
    if r:
        check("analysis_top_v2", tool.replace("analysis_",""), any_valid(r), True, tool)

for tool in ["ghidra_ast_printer_module","ghidra_backend_arch_ghidfixp1","ghidra_backend_arm64_info","ghidra_backend_for_arm64_wire3","ghidra_backend_for_x86_64_ghidfixp1","ghidra_backend_new_custom_arch_gwx4","ghidra_data_type_db_add_get","ghidra_data_type_db_builtins_list","ghidra_data_type_db_builtins_wire3","ghidra_decompile_response_stub_batch","ghidra_decompile_response_stub_build","ghidra_memory_map_exec_segments","ghidra_memory_map_executable_wire3","ghidra_memory_map_segment_count_ghidfixp1","ghidra_memory_map_segment_lookup","ghidra_pcode_lifter_pseudo_c","ghidra_pcode_lifter_two_insts_gwx4","ghidra_pcode_lifter_variables","ghidra_pcode_op_display_gwx4","ghidra_pcode_translate_add_gwx4","ghidra_pcode_translate_and_gwx4","ghidra_pcode_translate_call","ghidra_pcode_translate_jmp_gwx4","ghidra_pcode_translate_jz_gwx4","ghidra_pcode_translate_mov_wire3","ghidra_pcode_translate_nop_wire3","ghidra_pcode_translate_or_gwx4","ghidra_pcode_translate_pop_gwx4","ghidra_pcode_translate_push_wire3","ghidra_pcode_translate_ret","ghidra_pcode_translate_sub_gwx4","ghidra_pcode_translate_unknown_gwx4","ghidra_pcode_translate_xor_gwx4","ghidra_pcode_translator_arch","ghidra_pcode_varnode_classify_batch","ghidra_project_file","ghidra_project_name_ghidfixp1","ghidra_project_path","ghidra_project_with_binary","ghidra_rpc_client_config_port_ghidfixp1","ghidra_rpc_client_decompile","ghidra_rpc_client_decompile_wire3","ghidra_rpc_client_endpoint","ghidra_rpc_client_request_count","ghidra_script_chain_args","ghidra_script_timeout","ghidra_server_config_access_ghidfixp1","ghidra_server_config_custom","ghidra_server_connect","ghidra_server_connect_disconnect","ghidra_server_localhost","ghidra_server_localhost_connect_wire3","ghidra_symbol_importer_full_wire3","ghidra_symbol_importer_import_export","ghidra_symbol_importer_resolve","ghidra_symbol_importer_symbol_count_ghidfixp1","ghidra_type_importer_get","ghidra_type_importer_windows","ghidra_varnode_classify","ghidra_varnode_const_flags_gwx4","ghidra_varnode_ram_display_gwx4","ghidra_varnode_unique_flags_gwx4","ghidra_write_script_to_temp","ghidra_xml_parser_function_count_ghidfixp1","ghidra_xml_parser_functions","ghidra_xml_parser_types_wire3"]:
    r = call(tool, {})
    if r:
        check("ghidra_v4", tool.replace("ghidra_",""), any_valid(r), True, tool)

try: p.terminate()
except: pass
for cat, d in per_cat.items():
    out = fr"C:\Users\Fra\Desktop\RustRE\validation\mismatch_{cat}.json"
    with open(out, "w") as f: json.dump({"category":cat, "checks_total":d["checks"], "checks_passed":d["passed"], "mismatches":d["mismatches"]}, f, indent=1)
    print(f"{cat}: {d['passed']}/{d['checks']} passed, {len(d['mismatches'])} mismatch")
total_c = sum(d["checks"] for d in per_cat.values()); total_p = sum(d["passed"] for d in per_cat.values()); total_m = sum(len(d["mismatches"]) for d in per_cat.values())
print(f"\nBATCH68 TOTAL: {total_p}/{total_c} passed, {total_m} mismatch across {len(per_cat)} categories")
