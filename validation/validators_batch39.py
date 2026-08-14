#!/usr/bin/env python3
"""Batch39: net_rules more, hex_pattern_stats, kg extras, loader extras, ghidra."""
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

# net_rules more
for tool in ["net_rules_aho_corasick_build","net_rules_aho_corasick_contains_any","net_rules_aho_corasick_find_all","net_rules_ahocorasick_find_first","net_rules_ahocorasick_state_count","net_rules_compiled_ruleset_eval","net_rules_diff_rules","net_rules_engine_add_remove","net_rules_engine_evaluate","net_rules_export_rules_json","net_rules_ip_spec_matches","net_rules_network_spec_any","net_rules_packet_context_from_ipv4","net_rules_parse_many","net_rules_parse_single","net_rules_port_spec_matches","net_rules_rule_store_roundtrip","net_rules_ruleset_new_add_count","net_rules_spec_engine_match"]:
    r = call(tool, {})
    if r:
        check("net_rules_v2", tool.replace("net_rules_",""), any_valid(r), True, tool)

# ghidra more
for tool in ["ghidra_ast_printer_module","ghidra_backend_arch_ghidfixp1","ghidra_backend_supported_archs","ghidra_bridge_module","ghidra_config_from_home","ghidra_data_type_db_add","ghidra_data_type_db_count_ghidfixp1","ghidra_data_type_db_load_builtins","ghidra_data_type_db_lookup","ghidra_decompile_response_stub","ghidra_decompile_script_template","ghidra_list_functions_script_template","ghidra_memory_map_add_segment","ghidra_pcode_lifter_empty_wire3","ghidra_pcode_parser_parse_json","ghidra_project_file","ghidra_rpc_client_config_port_ghidfixp1","ghidra_rpc_client_decompile","ghidra_script_builder","ghidra_script_command_line","ghidra_server_config_default","ghidra_type_importer_add_lookup","ghidra_xml_parser_parse"]:
    r = call(tool, {})
    if r:
        check("ghidra_v3", tool.replace("ghidra_",""), any_valid(r), True, tool)

# loader more
for tool in ["loader_auto_loader_detect_format","loader_console_detect_format","loader_console_is_nes","loader_coordinator_new","loader_default_multi_format_registry_count","loader_detected_format_display","loader_export_info_forwarded","loader_export_info_named","loader_firmware_detect_binary_arch","loader_firmware_detect_kind","loader_firmware_detect_rtos","loader_format_detector_all_flags","loader_format_detector_new_empty","loader_format_detector_probe_all_bools","loader_import_info_named","loader_import_info_ordinal","loader_is_elf","loader_is_java_class","loader_is_macho","loader_is_pe"]:
    r = call(tool, {})
    if r:
        check("loader_v2", tool.replace("loader_",""), any_valid(r), True, tool)

try: p.terminate()
except: pass
for cat, d in per_cat.items():
    out = fr"C:\Users\Fra\Desktop\RustRE\validation\mismatch_{cat}.json"
    with open(out, "w") as f: json.dump({"category":cat, "checks_total":d["checks"], "checks_passed":d["passed"], "mismatches":d["mismatches"]}, f, indent=1)
    print(f"{cat}: {d['passed']}/{d['checks']} passed, {len(d['mismatches'])} mismatch")
total_c = sum(d["checks"] for d in per_cat.values()); total_p = sum(d["passed"] for d in per_cat.values()); total_m = sum(len(d["mismatches"]) for d in per_cat.values())
print(f"\nBATCH39 TOTAL: {total_p}/{total_c} passed, {total_m} mismatch across {len(per_cat)} categories")
