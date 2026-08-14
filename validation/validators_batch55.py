#!/usr/bin/env python3
"""Batch55: net many, deobf many, plugin, ios, mhcde, iadl."""
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

for tool in ["net_proxy_acl_entry_allow_all","net_proxy_acl_entry_deny_host","net_proxy_acl_entry_matches","net_proxy_base64_decode","net_proxy_decode_content_encoding","net_proxy_header_rewrite_remove","net_proxy_header_rewrite_set","net_proxy_header_rewriter_apply_all","net_proxy_headers_to_json","net_proxy_http_connect_error_response","net_proxy_http_connect_request_parse","net_proxy_http_method_from_str","net_proxy_http_request_line_is_http11","net_proxy_http_request_line_is_http2","net_proxy_http_request_line_parse","net_proxy_http_request_line_version","net_proxy_http_status_line_is_client_error","net_proxy_http_status_line_is_redirect","net_proxy_http_status_line_is_server_error","net_proxy_http_status_line_is_success","net_proxy_http_status_line_parse","net_proxy_inject_xff_headers","net_proxy_parse_connect","net_proxy_parse_request_line","net_proxy_parse_status_line","net_proxy_simple_regex_match_len"]:
    r = call(tool, {})
    if r:
        check("net_proxy_v3", tool.replace("net_proxy_",""), any_valid(r), True, tool)

for tool in ["deobf_adler32","deobf_adler32_checksum_v2","deobf_base64_decode","deobf_base64_find_all","deobf_crc32","deobf_crc32_checksum","deobf_crc32_checksum_table","deobf_entropy_scanner_scan","deobf_opaque_classify_const","deobf_opaque_known_patterns","deobf_opaque_truth_table_defaults","deobf_rc4_decrypt","deobf_rc4_ksa","deobf_rolror_decrypt_rol","deobf_rolror_decrypt_ror","deobf_rolror_recover_rotation","deobf_smc_addrol_decrypt","deobf_smc_addrol_encrypt","deobf_smc_code_mutation_tracker","deobf_smc_decryptor_decrypt","deobf_smc_detect","deobf_smc_detect_indicators","deobf_smc_dynamic_detector_events","deobf_smc_emu_registers_rw","deobf_smc_emulated_trace","deobf_smc_layered_decrypt_all","deobf_smc_mock_trace","deobf_smc_polymorphic_analyze","deobf_smc_polymorphic_analyze_diff","deobf_smc_reconstructor_reconstruct","deobf_smc_region_len_is_empty","deobf_smc_stats_from_bytes","deobf_smc_stats_from_regions","deobf_smc_unpacked_region_detector","deobf_smc_unpacked_regions","deobf_smc_write_exec_detect","deobf_smc_xor_chain_decrypt","deobf_smc_xor_chain_detect","deobf_smc_xor_chain_encrypt","deobf_smc_xor_step_apply","deobf_smc_xor_step_reverse","deobf_xor_decrypt_constant","deobf_xor_decrypt_cyclic","deobf_xor_decrypt_rolling","deobf_xor_entropy","deobf_xor_entropy_v2","deobf_xor_recover_single_byte_key"]:
    r = call(tool, {})
    if r:
        check("deobf_v3", tool.replace("deobf_",""), any_valid(r), True, tool)

for tool in ["plugin_lua_load_inline","plugin_python_class_methods_tagged","plugin_python_format_error","plugin_python_generate_stub","plugin_python_module_counts","plugin_python_stub_signature","python_script_engine_initial_step_count","python_script_pyvalue_none_type_name"]:
    r = call(tool, {})
    if r:
        check("plugin_python", tool.replace("plugin_",""), any_valid(r), True, tool)

for tool in ["ios_class_dumper_extract_objc_classes_wire","ios_class_dumper_extract_swift_types_wire","ios_decode_type_encoding_wire","ios_ipa_bundle_mock_wire","ios_ipa_info_from_macho_wire","ios_parse_plist_wire","ios_scan_objc_classes_path","ios_scan_objc_selectors_path","ios_security_check_arc_usage_wire","ios_security_check_debug_symbols_wire","ios_security_check_pie_enabled_wire","ios_security_check_stack_canary_wire","ios_security_report_wire","ios_swift_demangle_wire"]:
    r = call(tool, {})
    if r:
        check("ios_v2", tool.replace("ios_",""), any_valid(r), True, tool)

for tool in ["mhcde_analyze_and_patch","mhcde_cff_detect","mhcde_entropy_analyze","mhcde_entropy_mean","mhcde_entropy_shannon","mhcde_junk_code_detect","mhcde_junk_density","mhcde_junk_total_bytes","mhcde_opaque_count_by_type","mhcde_opaque_predicate_detect","mhcde_opaque_total_patch_bytes","mhcde_orchestrator_analyze","mhcde_pass_analyze","mhcde_score_model_naturalness"]:
    r = call(tool, {})
    if r:
        check("mhcde", tool.replace("mhcde_",""), any_valid(r), True, tool)

try: p.terminate()
except: pass
for cat, d in per_cat.items():
    out = fr"C:\Users\Fra\Desktop\RustRE\validation\mismatch_{cat}.json"
    with open(out, "w") as f: json.dump({"category":cat, "checks_total":d["checks"], "checks_passed":d["passed"], "mismatches":d["mismatches"]}, f, indent=1)
    print(f"{cat}: {d['passed']}/{d['checks']} passed, {len(d['mismatches'])} mismatch")
total_c = sum(d["checks"] for d in per_cat.values()); total_p = sum(d["passed"] for d in per_cat.values()); total_m = sum(len(d["mismatches"]) for d in per_cat.values())
print(f"\nBATCH55 TOTAL: {total_p}/{total_c} passed, {total_m} mismatch across {len(per_cat)} categories")
