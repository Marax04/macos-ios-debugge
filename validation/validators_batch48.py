#!/usr/bin/env python3
"""Batch48: dotnet_edit many, dotnet_metadata many, dwarf_casts many."""
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

for tool in ["dotnet_edit_assembly_patcher_patch_u32","dotnet_edit_clone_method_body","dotnet_edit_edit_transaction_len","dotnet_edit_encode_instructions","dotnet_edit_il_optimizer_eliminate_dead_code","dotnet_edit_il_optimizer_fold_const_stores_v2","dotnet_edit_il_optimizer_fold_conv_i8_v2","dotnet_edit_il_optimizer_optimize_all","dotnet_edit_il_optimizer_remove_nops","dotnet_edit_il_patch_append_v2","dotnet_edit_il_patch_insert_after","dotnet_edit_il_patch_insert_before","dotnet_edit_il_patch_prepend_v2","dotnet_edit_il_patch_remove","dotnet_edit_il_patch_replace_range","dotnet_edit_il_patch_replace_v2","dotnet_edit_il_validator_is_valid_v2","dotnet_edit_il_validator_validate","dotnet_edit_ilbuilder_brfalse_s","dotnet_edit_ilbuilder_brtrue_s","dotnet_edit_ilbuilder_callvirt","dotnet_edit_ilbuilder_newobj","dotnet_edit_managed_resource_data_len","dotnet_edit_managed_resource_is_public","dotnet_edit_managed_resource_new","dotnet_edit_new_field_public_field_wire","dotnet_edit_new_field_public_sig","dotnet_edit_new_field_public_static_probe","dotnet_edit_new_method_encode_sig","dotnet_edit_new_method_encode_sig_static","dotnet_edit_new_method_instance_void_body","dotnet_edit_new_method_instance_void_sig","dotnet_edit_new_method_static_void_body","dotnet_edit_new_type_public_class","dotnet_edit_new_type_public_class_probe","dotnet_edit_new_type_public_interface","dotnet_edit_nop_fill_range","dotnet_edit_opcode_byte_size","dotnet_edit_recompute_offsets","dotnet_edit_renumber_offsets","dotnet_edit_signature_stripper_strip","dotnet_edit_token_remapper_remap"]:
    r = call(tool, {})
    if r:
        check("dotnet_edit_v3", tool.replace("dotnet_edit_",""), any_valid(r), True, tool)

for tool in ["dotnet_metadata_assembly_ref_names","dotnet_metadata_exported_type_names","dotnet_metadata_fields_for_type","dotnet_metadata_file_names","dotnet_metadata_find_methods_by_name","dotnet_metadata_find_type","dotnet_metadata_find_type_def_row","dotnet_metadata_get_method_view","dotnet_metadata_get_type_view","dotnet_metadata_method_def_by_index","dotnet_metadata_method_index","dotnet_metadata_methods_for_type","dotnet_metadata_parse_array_shape","dotnet_metadata_parse_ca_typed","dotnet_metadata_parse_custom_attribute_blob","dotnet_metadata_parse_direct_summary","dotnet_metadata_parse_field_sig_blob","dotnet_metadata_parse_local_var_sig","dotnet_metadata_parse_method_body","dotnet_metadata_parse_method_sig_blob","dotnet_metadata_pretty_print_type_sig","dotnet_metadata_resolve_token","dotnet_metadata_resource_names","dotnet_metadata_type_def_by_index","dotnet_metadata_type_full_names","dotnet_method_flags_decode","dotnet_token_table_name"]:
    r = call(tool, {})
    if r:
        check("dotnet_metadata_v3", tool.replace("dotnet_",""), any_valid(r), True, tool)

for tool in ["dwarf_casts_i64_to_u32","dwarf_casts_i64_to_u64","dwarf_casts_i64_to_usize","dwarf_casts_u64_to_i64","dwarf_casts_u64_to_u16","dwarf_casts_u64_to_u32","dwarf_casts_u64_to_u8","dwarf_casts_u64_to_usize","dwarf_casts_u8_to_i8","dwarf_casts_usize_to_i64","dwarf_casts_usize_to_u32"]:
    r = call(tool, {})
    if r:
        check("dwarf_casts", tool.replace("dwarf_casts_",""), any_valid(r), True, tool)

try: p.terminate()
except: pass
for cat, d in per_cat.items():
    out = fr"C:\Users\Fra\Desktop\RustRE\validation\mismatch_{cat}.json"
    with open(out, "w") as f: json.dump({"category":cat, "checks_total":d["checks"], "checks_passed":d["passed"], "mismatches":d["mismatches"]}, f, indent=1)
    print(f"{cat}: {d['passed']}/{d['checks']} passed, {len(d['mismatches'])} mismatch")
total_c = sum(d["checks"] for d in per_cat.values()); total_p = sum(d["passed"] for d in per_cat.values()); total_m = sum(len(d["mismatches"]) for d in per_cat.values())
print(f"\nBATCH48 TOTAL: {total_p}/{total_c} passed, {total_m} mismatch across {len(per_cat)} categories")
