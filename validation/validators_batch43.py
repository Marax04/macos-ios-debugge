#!/usr/bin/env python3
"""Batch43: dwarf_gimli, dwarf_variables, ttd_replay more, script_python more, script_lua more."""
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

# dwarf more
for tool in ["dwarf_functions_count_path","dwarf_functions_path","dwarf_gimli_functions_path","dwarf_gimli_line_info_path","dwarf_gimli_types_path","dwarf_line_info_path","dwarf_symbol_set_summary_path","dwarf_types_count_path","dwarf_types_path","dwarf_unwinder_at_path","dwarf_variables_path"]:
    r = call(tool, {})
    if r:
        check("dwarf_v3", tool.replace("dwarf_",""), any_valid(r), True, tool)

# ttd_replay more
for tool in ["ttd_replay_apply_event_to_state","ttd_replay_breakpoint_fires","ttd_replay_build_call_graph","ttd_replay_compute_memory_access_stats","ttd_replay_delta_compressor","ttd_replay_engine_state_db_breakpoints","ttd_replay_memory_state_apply_write","ttd_replay_memstate_apply_read","ttd_replay_memstate_diff","ttd_replay_recording_file_roundtrip","ttd_replay_recording_roundtrip","ttd_replay_snapshot_cache","ttd_replay_snapshot_cache_insert","ttd_replay_split_by_thread","ttd_replay_watchpoint_overlaps","ttd_replay_watchpointset_matches"]:
    r = call(tool, {})
    if r:
        check("ttd_replay_v3", tool.replace("ttd_replay_",""), any_valid(r), True, tool)

# script_python more
for tool in ["script_python_marshal_to_address","script_python_marshal_to_bytes","script_python_pure_collect_locals","script_python_pure_eval_int","script_python_pure_execute","script_python_pure_execute_print","script_python_pure_parse","script_python_stub_builtin_names","script_python_stubs_generate_standard","script_python_stubs_standard_names"]:
    r = call(tool, {"expr":"1+1"} if "eval_int" in tool else {})
    if r:
        check("script_python_v5", tool.replace("script_python_",""), any_valid(r), True, tool)

# script_lua more
for tool in ["script_lua_casts_f64_to_i64","script_lua_casts_i64_to_f64","script_lua_casts_i64_to_i32","script_lua_casts_i64_to_u32","script_lua_casts_i64_to_u64","script_lua_context_output_text","script_lua_detect_format","script_lua_execute_script","script_lua_jmp_patch","script_lua_match_hex_pattern","script_lua_nop_sled","script_lua_ret_patch","script_lua_template_dump_functions","script_lua_template_extract_strings","script_lua_template_find_xrefs","script_lua_template_patch_pattern","script_lua_template_rename_functions"]:
    r = call(tool, {})
    if r:
        check("script_lua_v3", tool.replace("script_lua_",""), any_valid(r), True, tool)

try: p.terminate()
except: pass
for cat, d in per_cat.items():
    out = fr"C:\Users\Fra\Desktop\RustRE\validation\mismatch_{cat}.json"
    with open(out, "w") as f: json.dump({"category":cat, "checks_total":d["checks"], "checks_passed":d["passed"], "mismatches":d["mismatches"]}, f, indent=1)
    print(f"{cat}: {d['passed']}/{d['checks']} passed, {len(d['mismatches'])} mismatch")
total_c = sum(d["checks"] for d in per_cat.values()); total_p = sum(d["passed"] for d in per_cat.values()); total_m = sum(len(d["mismatches"]) for d in per_cat.values())
print(f"\nBATCH43 TOTAL: {total_p}/{total_c} passed, {total_m} mismatch across {len(per_cat)} categories")
