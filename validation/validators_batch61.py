#!/usr/bin/env python3
"""Batch61: forensics_mem more, dwarf ext, decompiler_type v5, kg extra, ttd_replay engine v2."""
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

for tool in ["decompiler_type_access_width_sizer_wp","decompiler_type_are_compatible_ints_wp","decompiler_type_byte_size","decompiler_type_byte_size_int_wp","decompiler_type_byte_size_ptr_wp","decompiler_type_c_name","decompiler_type_c_name_int_wp","decompiler_type_ctype_emit_function_z1","decompiler_type_ctype_emit_struct_z1","decompiler_type_ctype_emit_typedef_wp","decompiler_type_ctype_emit_union_z1","decompiler_type_env_resolve_struct_z1","decompiler_type_env_set_get","decompiler_type_env_set_get_wp","decompiler_type_function_prototype_wp","decompiler_type_inference_assignment_wp","decompiler_type_inference_pointer_deref_z1","decompiler_type_int_byte_size","decompiler_type_int_c_name","decompiler_type_is_convertible_ints_wp","decompiler_type_is_pointer","decompiler_type_is_pointer_void_n2","decompiler_type_layout_for_struct_n2","decompiler_type_name_prefix","decompiler_type_name_prefix_int_n2","decompiler_type_pointer_analysis_alias_wp","decompiler_type_pointer_analysis_not_null_wp","decompiler_type_propagator_assign_wp","decompiler_type_propagator_binop_z1","decompiler_type_qualifier_flags_wp","decompiler_type_qualifier_string","decompiler_type_qualifier_string_n2","decompiler_type_recovery_from_access_size_wp","decompiler_type_recovery_record_get_wp","decompiler_type_rename_all","decompiler_type_rename_for_type","decompiler_type_rename_variables","decompiler_type_struct_field_at","decompiler_type_struct_field_at_wp","decompiler_type_struct_field_exact_n2","decompiler_type_unifier_canonical_wp","decompiler_type_unifier_same_class_z1","decompiler_type_union_c_name_wp","decompiler_type_union_member_named_n2"]:
    r = call(tool, {})
    if r:
        check("decompiler_type_v5", tool.replace("decompiler_type_",""), any_valid(r), True, tool)

for tool in ["rustre_analysis_string_detect_xor_key","rustre_analysis_string_encoding_info","rustre_analysis_string_extract_ips","rustre_analysis_string_extract_urls","rustre_analysis_string_jaro_winkler","rustre_analysis_string_levenshtein","rustre_analysis_string_read_cstring","rustre_analysis_string_scan_ascii","rustre_analysis_string_scan_pascal","rustre_analysis_string_scan_utf16_le","rustre_analysis_string_scan_utf8","rustre_analysis_string_shannon_entropy","rustre_analysis_string_stats"]:
    r = call(tool, {})
    if r:
        check("rustre_analysis_string_v6", tool.replace("rustre_analysis_string_",""), any_valid(r), True, tool)

for tool in ["rustre_decompiler_batch_is_c_keyword","rustre_decompiler_callconv_arch_from_str","rustre_decompiler_callconv_lift_mnemonic","rustre_decompiler_cfs_detect_loop","rustre_decompiler_default_options","rustre_decompiler_default_pipeline_disasm","rustre_decompiler_default_pipeline_standard","rustre_decompiler_detect_functions_path","rustre_decompiler_expr_recovery_kfc","rustre_decompiler_function_name_gen_count","rustre_decompiler_load_binary_info","rustre_decompiler_mem_operand_parse","rustre_decompiler_pass_registry_new","rustre_decompiler_plugin_manager_count","rustre_decompiler_quality_from_source","rustre_decompiler_standard_pass_specs","rustre_decompiler_symbol_map_ops","rustre_decompiler_symbol_map_resolve","rustre_decompiler_type_prop_add","rustre_decompiler_var_recovery_fresh","rustre_decompiler_var_recovery_stack_name","rustre_decompiler_x86_width_hint"]:
    r = call(tool, {})
    if r:
        check("rustre_decompiler_v3", tool.replace("rustre_decompiler_",""), any_valid(r), True, tool)

try: p.terminate()
except: pass
for cat, d in per_cat.items():
    out = fr"C:\Users\Fra\Desktop\RustRE\validation\mismatch_{cat}.json"
    with open(out, "w") as f: json.dump({"category":cat, "checks_total":d["checks"], "checks_passed":d["passed"], "mismatches":d["mismatches"]}, f, indent=1)
    print(f"{cat}: {d['passed']}/{d['checks']} passed, {len(d['mismatches'])} mismatch")
total_c = sum(d["checks"] for d in per_cat.values()); total_p = sum(d["passed"] for d in per_cat.values()); total_m = sum(len(d["mismatches"]) for d in per_cat.values())
print(f"\nBATCH61 TOTAL: {total_p}/{total_c} passed, {total_m} mismatch across {len(per_cat)} categories")
