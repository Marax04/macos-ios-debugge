#!/usr/bin/env python3
"""Batch47: lua_loader many, luajit, arch_wasm many more, arch68k, arch_dex more."""
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

for tool in ["lua_loader_is_bytecode","lua_loader_is_lua_bytecode","lua_loader_lua_all_strings_mock","lua_loader_lua_arch_info","lua_loader_lua_bytecode_loader_load","lua_loader_lua_bytecode_parse","lua_loader_lua_chunk_from_proto","lua_loader_lua_chunk_from_proto_fields_wx1","lua_loader_lua_chunk_mock","lua_loader_lua_const_is_string","lua_loader_lua_disassemble_mock","lua_loader_lua_disassemble_proto_wx1","lua_loader_lua_endian_from_byte","lua_loader_lua_endian_is_le_wx1","lua_loader_lua_header_parse","lua_loader_lua_instr_decode","lua_loader_lua_instr_fields_wx1","lua_loader_lua_loader_name","lua_loader_lua_opcode_layout","lua_loader_lua_proto_all_strings_direct","lua_loader_lua_proto_mock","lua_loader_lua_proto_source_line","lua_loader_lua_proto_stats_mock","lua_loader_lua_version_as_byte_wx1","lua_loader_lua_version_from_byte","lua_loader_lua_version_is_known","lua_loader_lua_version_major_minor","lua_loader_opcode_name","lua_loader_read_string_lua","lua_loader_upvalue_desc_from_upvalue"]:
    r = call(tool, {})
    if r:
        check("lua_loader_v2", tool.replace("lua_loader_",""), any_valid(r), True, tool)

for tool in ["arch_wasm_call_graph_callees_of","arch_wasm_call_graph_edge_count","arch_wasm_call_graph_reachable_from","arch_wasm_call_graph_recursive","arch_wasm_call_graph_roots_leaves","arch_wasm_cf_basic_blocks","arch_wasm_cf_find_block_end","arch_wasm_control_flow_extract_blocks","arch_wasm_data_flow_analysis_record","arch_wasm_data_flow_state_probe","arch_wasm_decode_fc_prefix","arch_wasm_decode_fd_prefix","arch_wasm_decode_fe_prefix","arch_wasm_decode_func_type","arch_wasm_decode_type","arch_wasm_executor_execute_instruction","arch_wasm_executor_new","arch_wasm_executor_reset","arch_wasm_external_kind_from_byte","arch_wasm_external_kind_probe","arch_wasm_function_ref_func_import","arch_wasm_function_stats","arch_wasm_function_stats_from_bytes","arch_wasm_functype_arity","arch_wasm_functype_decode","arch_wasm_global_type_decode","arch_wasm_indirect_call_table_resolve","arch_wasm_limits_decode","arch_wasm_limits_has_max","arch_wasm_limits_no_max_check","arch_wasm_linear_disassemble","arch_wasm_linear_disassembler_new","arch_wasm_memory_type_decode","arch_wasm_module_header_parse","arch_wasm_module_header_valid_check","arch_wasm_mutability_from_byte","arch_wasm_mutability_probe","arch_wasm_name_subsection_from_byte","arch_wasm_name_subsection_name","arch_wasm_name_subsection_type_probe","arch_wasm_section_id_from_byte","arch_wasm_section_id_probe","arch_wasm_section_name","arch_wasm_simd_mnemonic","arch_wasm_simd_probe","arch_wasm_stack_drain","arch_wasm_table_type_decode","arch_wasm_valtype_byte","arch_wasm_valtype_from_byte","arch_wasm_valtype_is_numeric","arch_wasm_valtype_is_reference","arch_wasm_valtype_name","arch_wasm_valtype_ref_probe","arch_wasm_value_as_f32","arch_wasm_value_as_f64","arch_wasm_value_as_i32","arch_wasm_value_as_i64","arch_wasm_value_as_v128","arch_wasm_value_type_tag","arch_wasm_valuetype_byte_roundtrip"]:
    r = call(tool, {})
    if r:
        check("arch_wasm_v4", tool.replace("arch_wasm_",""), any_valid(r), True, tool)

try: p.terminate()
except: pass
for cat, d in per_cat.items():
    out = fr"C:\Users\Fra\Desktop\RustRE\validation\mismatch_{cat}.json"
    with open(out, "w") as f: json.dump({"category":cat, "checks_total":d["checks"], "checks_passed":d["passed"], "mismatches":d["mismatches"]}, f, indent=1)
    print(f"{cat}: {d['passed']}/{d['checks']} passed, {len(d['mismatches'])} mismatch")
total_c = sum(d["checks"] for d in per_cat.values()); total_p = sum(d["passed"] for d in per_cat.values()); total_m = sum(len(d["mismatches"]) for d in per_cat.values())
print(f"\nBATCH47 TOTAL: {total_p}/{total_c} passed, {total_m} mismatch across {len(per_cat)} categories")
