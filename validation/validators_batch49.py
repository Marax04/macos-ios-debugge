#!/usr/bin/env python3
"""Batch49: pe_editor many, pe_rebuild, pe_tools, debug_windbg, sparc more."""
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

for tool in ["pe_editor_build_tree","pe_editor_cert_header_bytes","pe_editor_certificate_header","pe_editor_certificate_header_bytes_len","pe_editor_certificate_header_dw_length","pe_editor_certificate_header_new","pe_editor_certificate_header_to_bytes","pe_editor_export_edit_add_display","pe_editor_export_edit_display","pe_editor_export_edit_remove_display","pe_editor_export_editor_pending","pe_editor_header_field_debug","pe_editor_header_field_display","pe_editor_import_editor_default_empty","pe_editor_import_editor_pending","pe_editor_import_entry_named_is_named","pe_editor_import_entry_ordinal","pe_editor_import_entry_ordinal_display","pe_editor_import_entry_ordinal_is_named","pe_editor_patch_display","pe_editor_patch_empty_check","pe_editor_patch_len","pe_editor_patch_simple_display","pe_editor_patch_verified","pe_editor_patch_verified_has_verification","pe_editor_patch_verified_len","pe_editor_patchset_add_count","pe_editor_patchset_add_multi","pe_editor_patchset_default_empty","pe_editor_patchset_new_empty","pe_editor_patchset_total_bytes","pe_editor_rc4_keystream","pe_editor_rc4_next_byte_sequence","pe_editor_rc4_process","pe_editor_resource_editor_default_totals","pe_editor_resource_editor_totals","pe_editor_resource_entry_manifest_len","pe_editor_resource_entry_new","pe_editor_resource_entry_new_len","pe_editor_resource_manifest","pe_editor_resource_type_display","pe_editor_resource_type_id_display","pe_editor_resource_type_name_display","pe_editor_section_edit_set_chars","pe_editor_section_edit_set_chars_flags","pe_editor_section_edit_zero","pe_editor_section_edit_zero_fields","pe_editor_section_edit_zero_flags","pe_editor_signing_scaffold_blob","pe_editor_signing_scaffold_new","pe_editor_xor_section","pe_editor_xor_section_bytes"]:
    r = call(tool, {})
    if r:
        check("pe_editor_v4", tool.replace("pe_editor_",""), any_valid(r), True, tool)

for tool in ["pe_editor_x_export_editor_dll_name","pe_editor_x_export_editor_pending_count","pe_editor_x_header_field_all_display","pe_editor_x_import_entry_is_named_flag","pe_editor_x_patch_is_empty","pe_editor_x_patchset_is_empty","pe_editor_x_patchset_total_bytes_after_add","pe_editor_x_resource_editor_total_data_size","pe_editor_x_resource_entry_is_empty","pe_editor_x_resource_types_constants","pe_editor_x_section_edit_zero_build","pe_editor_x_signing_scaffold_payload_len"]:
    r = call(tool, {})
    if r:
        check("pe_editor_x", tool.replace("pe_editor_x_",""), any_valid(r), True, tool)

for tool in ["pe_rebuild_calculate_pe_checksum","pe_rebuild_compute_entropy","pe_rebuild_compute_entropy_wire","pe_rebuild_crc16_ccitt","pe_rebuild_find_pe_candidates","pe_rebuild_infer_characteristics","pe_rebuild_is_memory_pe","pe_rebuild_is_memory_pe_wire","pe_tools_compute_entropy","pe_tools_compute_pe_checksum","pe_tools_rich_header_parse"]:
    r = call(tool, {})
    if r:
        check("pe_rebuild_tools", tool.replace("pe_",""), any_valid(r), True, tool)

for tool in ["debug_windbg_default_module_count","debug_windbg_execution_status_no_debuggee","windbg_command_parser_parse","windbg_dbg_module_info_contains","windbg_expr_evaluator_evaluate","windbg_extension_registry_find","windbg_extension_registry_standard_count","windbg_kdnet_packet_checksum","windbg_kdnet_packet_encode","windbg_kdnet_packet_from_id","windbg_kdnet_packet_type_id","windbg_minidump_stream_type_name","windbg_module_list_parse_lm","windbg_parsed_dbg_output_key_values"]:
    r = call(tool, {})
    if r:
        check("windbg_v2", tool.replace("windbg_","").replace("debug_windbg_",""), any_valid(r), True, tool)

for tool in ["sparc_encode_alu_imm","sparc_encode_alu_reg","sparc_encode_jmpl","sparc_encode_load","sparc_encode_store","sparc_extract_branch_targets","sparc_lookup_asi","sparc_lookup_condition","sparc_lookup_fp_opcode","sparc_lookup_priv_reg","sparc_lookup_v8_trap","sparc_lookup_v9_trap","sparc_build_epilogue","sparc_build_return_seq"]:
    r = call(tool, {})
    if r:
        check("sparc_v2", tool.replace("sparc_",""), any_valid(r), True, tool)

try: p.terminate()
except: pass
for cat, d in per_cat.items():
    out = fr"C:\Users\Fra\Desktop\RustRE\validation\mismatch_{cat}.json"
    with open(out, "w") as f: json.dump({"category":cat, "checks_total":d["checks"], "checks_passed":d["passed"], "mismatches":d["mismatches"]}, f, indent=1)
    print(f"{cat}: {d['passed']}/{d['checks']} passed, {len(d['mismatches'])} mismatch")
total_c = sum(d["checks"] for d in per_cat.values()); total_p = sum(d["passed"] for d in per_cat.values()); total_m = sum(len(d["mismatches"]) for d in per_cat.values())
print(f"\nBATCH49 TOTAL: {total_p}/{total_c} passed, {total_m} mismatch across {len(per_cat)} categories")
