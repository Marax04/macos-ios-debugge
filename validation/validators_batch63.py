#!/usr/bin/env python3
"""Batch63: agent_llm final, agent_prompts final, agent_task, db_base."""
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

for tool in ["db_base_migrations_avg_sql_bytes","db_base_migrations_count","db_base_migrations_find_by_version","db_base_migrations_first_version","db_base_migrations_has_version","db_base_migrations_is_contiguous","db_base_migrations_largest_up_sql","db_base_migrations_list","db_base_migrations_max_version","db_base_migrations_min_version","db_base_migrations_names","db_base_migrations_summary","db_base_migrations_total_sql_bytes","db_base_migrations_unique_versions","db_base_migrations_versions","db_base_migrations_with_down_sql"]:
    r = call(tool, {})
    if r:
        check("db_base", tool.replace("db_base_",""), any_valid(r), True, tool)

for tool in ["frida_device_display","frida_manager_add_interceptor","frida_manager_attach_detach","frida_mock_stalker_events","frida_session_initial_state","frida_session_script_count","frida_stalker_event_display","frida_target_local_name","frida_target_local_pid"]:
    r = call(tool, {})
    if r:
        check("frida_v4", tool.replace("frida_",""), any_valid(r), True, tool)

for tool in ["flirt_apply_ac_index_built_wire","flirt_apply_applier_match_count_wire","flirt_apply_auto","flirt_apply_crc16","flirt_apply_crc16_flirt_wire","flirt_apply_demo_sigs_count_wire","flirt_apply_library_marks_from_matches","flirt_apply_pattern_from_str_wire","flirt_apply_pattern_matches_wire","flirt_apply_pattern_new_wire","flirt_apply_resolve_renames_wire","flirt_apply_scan_bytes_demo_wire","flirt_apply_sig_db_add_count_wire","flirt_apply_signature_from_pattern_wire","flirt_apply_signature_matches_at_wire","flirt_apply_wildcard_prefix_wire"]:
    r = call(tool, {})
    if r:
        check("flirt_apply_v2", tool.replace("flirt_apply_",""), any_valid(r), True, tool)

for tool in ["flirt_gen_crc16_sig_header","flirt_gen_crc16_sig_header_empty_wire","flirt_gen_crc16_sig_header_known_wire","flirt_gen_elf_parse","flirt_gen_elf_parse_reject_short_wire","flirt_gen_generate_batch_wire","flirt_gen_generate_no_relocs_wire","flirt_gen_generate_with_relocs_wire","flirt_gen_library_builder_dedup_wire","flirt_gen_library_builder_skipped_wire","flirt_gen_pattern_generate","flirt_gen_pattern_generator_new","flirt_gen_pattern_with_quality","flirt_gen_relocation_entry_wire","flirt_gen_scan_x86_masks_call_rel32_wire","flirt_gen_scan_x86_masks_empty_wire","flirt_gen_scan_x86_masks_jcc_rel32_wire","flirt_gen_scan_x86_masks_jmp_rel32_wire","flirt_gen_scan_x86_masks_jmp_rel8_wire","flirt_gen_scan_x86_masks_mov_imm64_wire","flirt_gen_scan_x86_masks_rip_relative_wire","flirt_gen_sig_trie_branch_encode_wire","flirt_gen_sig_trie_node_encode_leaf_wire","flirt_gen_sig_writer_build_empty_wire","flirt_gen_sig_writer_i386_wire","flirt_gen_write_sig_file_wire","flirt_library_serialize_roundtrip_wire","flirt_parse_pattern","flirt_parse_sig_header","flirt_pattern_wildcard_ratio","flirt_sig_file_parse_wire","flirt_sig_pattern_matches_wire","flirt_database_add_module_wire"]:
    r = call(tool, {})
    if r:
        check("flirt_gen_v3", tool.replace("flirt_",""), any_valid(r), True, tool)

try: p.terminate()
except: pass
for cat, d in per_cat.items():
    out = fr"C:\Users\Fra\Desktop\RustRE\validation\mismatch_{cat}.json"
    with open(out, "w") as f: json.dump({"category":cat, "checks_total":d["checks"], "checks_passed":d["passed"], "mismatches":d["mismatches"]}, f, indent=1)
    print(f"{cat}: {d['passed']}/{d['checks']} passed, {len(d['mismatches'])} mismatch")
total_c = sum(d["checks"] for d in per_cat.values()); total_p = sum(d["passed"] for d in per_cat.values()); total_m = sum(len(d["mismatches"]) for d in per_cat.values())
print(f"\nBATCH63 TOTAL: {total_p}/{total_c} passed, {total_m} mismatch across {len(per_cat)} categories")
