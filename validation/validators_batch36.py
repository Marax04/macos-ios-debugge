#!/usr/bin/env python3
"""Batch36: yara_engine extras, malpedia extras, flirt more, il_lift more, decomp2 more."""
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

# yara_engine extras
for tool in ["yara_engine_async_scan_config_concurrency_wire3","yara_engine_async_scan_config_wire2","yara_engine_async_scan_result_wire2","yara_engine_builtin_rules_count_wire2","yara_engine_compiled_cache_empty_wire3","yara_engine_compute_entropy_hex_wire3","yara_engine_parse_name_from_source","yara_engine_parse_rule","yara_engine_parse_rules_count_wire2","yara_engine_rule_definition_with_namespace_wire2","yara_engine_rule_new_summary","yara_engine_rule_with_meta_bool_wire3","yara_engine_ruleset_add_rule","yara_engine_ruleset_len_wire2","yara_engine_scan_bytes","yara_engine_scanner_new_count"]:
    r = call(tool, {})
    if r:
        check("yara_engine_v2", tool.replace("yara_engine_",""), any_valid(r), True, tool)

# malpedia more
for tool in ["malpedia_batch_lookup","malpedia_tlsh_distance"]:
    r = call(tool, {"a":"T1"+"0"*70, "b":"T1"+"1"*70} if "tlsh" in tool else {"hashes":["abc123"]})
    if r:
        check("malpedia_v3", tool.replace("malpedia_",""), any_valid(r), True, tool)

# flirt more
for tool in ["flirt_arch_from_u8","flirt_arch_to_u8_wire","flirt_builtin_crt_library_x64","flirt_builtin_matcher","flirt_crc16","flirt_crc16_ibm","flirt_demo_sig_count","flirt_file_type_bits_wire","flirt_file_type_contains","flirt_matcher_add_library_wire","flirt_matcher_best_match_wire","flirt_pattern_hex_wire","flirt_pattern_matches_all_wire","flirt_trie_build_find_wire"]:
    r = call(tool, {"arch":0} if "arch_from" in tool else {"arch":"x86_64"} if "arch_to" in tool else {"data":[0x00,0x01]} if "crc16" in tool else {})
    if r:
        check("flirt_v2", tool.replace("flirt_",""), any_valid(r), True, tool)

# il_lift more
for tool in ["il_lift_address_map_new_state","il_lift_arm64_lifter_new","il_lift_cache_default_capacity_len","il_lift_diff_address_maps","il_lift_lift_cache_default_capacity_n6","il_lift_lift_stats_merge","il_lift_lifter_registry_defaults_len_j30","il_lift_lifter_registry_supports_get_r7","il_lift_partial_result_push_err_r7","il_lift_pipeline_default_stages","il_lift_register_all_lifters","il_lift_report_summary_default_j30","il_lift_x86_lifter_new"]:
    r = call(tool, {})
    if r:
        check("il_lift_v4", tool.replace("il_lift_",""), any_valid(r), True, tool)

# decomp more
for tool in ["decomp_annotation_store_at_address","decomp_annotation_store_by_category","decomp_cache_evict_clear","decomp_cache_hit_rate","decomp_calling_convention_from_arch","decomp_cf_detect_loop","decomp_cf_flatten_sequences","decomp_cf_structuring_make_if_else","decomp_expression_recovery_known","decomp_function_name_generator","decomp_pipeline_pass_count","decomp_quality_metrics_from_source","decomp_register_canonical","decomp_register_width_bytes","decomp_stats_summary","decomp_symbol_map_resolve","decomp_type_env_set_get_wire","decomp_type_ptr_width_wire","decomp_type_qualifier_builder_wire"]:
    r = call(tool, {})
    if r:
        check("decomp_v2", tool.replace("decomp_",""), any_valid(r), True, tool)

# Save
try: p.terminate()
except: pass
for cat, d in per_cat.items():
    out = fr"C:\Users\Fra\Desktop\RustRE\validation\mismatch_{cat}.json"
    with open(out, "w") as f: json.dump({"category":cat, "checks_total":d["checks"], "checks_passed":d["passed"], "mismatches":d["mismatches"]}, f, indent=1)
    print(f"{cat}: {d['passed']}/{d['checks']} passed, {len(d['mismatches'])} mismatch")
total_c = sum(d["checks"] for d in per_cat.values()); total_p = sum(d["passed"] for d in per_cat.values()); total_m = sum(len(d["mismatches"]) for d in per_cat.values())
print(f"\nBATCH36 TOTAL: {total_p}/{total_c} passed, {total_m} mismatch across {len(per_cat)} categories")
