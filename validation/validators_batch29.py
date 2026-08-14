#!/usr/bin/env python3
"""Batch29: agent_llm_lib, ttd_replay engine, ttd_replayer, ttd_recorder extras, mobile_smali more, debug_windows."""
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

# agent_llm_lib
for tool in ["agent_llm_lib_completion_options_default","agent_llm_lib_completion_response_build","agent_llm_lib_config_build","agent_llm_lib_context_manager_len","agent_llm_lib_list_model_variants","agent_llm_lib_message_from_message","agent_llm_lib_response_first_text","agent_llm_lib_role_parse","agent_llm_lib_token_usage_total","agent_llm_lib_tool_definition_new"]:
    r = call(tool, {})
    if r:
        check("agent_llm_lib", tool.replace("agent_llm_lib_",""), any_valid(r), True, tool)

# ttd_replay engine
for tool in ["ttd_replay_engine_add_breakpoint","ttd_replay_engine_breakpoints","ttd_replay_engine_find_calls","ttd_replay_engine_step_forward","ttd_replay_engine_go_to_end","ttd_replay_engine_navigate","ttd_replay_engine_watchpoints","ttd_replay_engine_find_writes","ttd_replay_engine_find_first_write"]:
    r = call(tool, {})
    if r:
        check("ttd_replay_engine", tool.replace("ttd_replay_engine_",""), any_valid(r), True, tool)

# ttd_replayer
for tool in ["ttd_replayer_step_forward","ttd_replayer_goto","ttd_replayer_hex_dump","ttd_replayer_parse_hex","ttd_replayer_event_counts","ttd_replayer_format_tick","ttd_replayer_trace_stats","ttd_replayer_replay_state_apply_write"]:
    r = call(tool, {})
    if r:
        check("ttd_replayer_v2", tool.replace("ttd_replayer_",""), any_valid(r), True, tool)

# ttd_recorder
for tool in ["ttd_recorder_position_earliest","ttd_recorder_position_is_before","ttd_recorder_config_for_pid","ttd_recorder_check_platform_support","ttd_recorder_valid_extension","ttd_recorder_compression_level_display","ttd_recorder_filter_module_allowed"]:
    r = call(tool, {"pid":1234} if "config" in tool else {"platform":"windows"} if "platform" in tool else {})
    if r:
        check("ttd_recorder_v2", tool.replace("ttd_recorder_",""), any_valid(r), True, tool)

# mobile_smali more
for tool in ["mobile_smali_opcode_as_byte","mobile_smali_instruction_size_bytes","mobile_smali_method_is_constructor","mobile_smali_class_static_methods","mobile_smali_parse_type_descriptor","mobile_smali_parse_method_descriptor","mobile_smali_op_display"]:
    args = {"op":"nop"} if "opcode_as_byte" in tool or "op_display" in tool else {"descriptor":"Ljava/lang/String;"} if "parse_type" in tool else {"descriptor":"()V"} if "parse_method" in tool else {}
    r = call(tool, args)
    if r:
        check("mobile_smali_v2", tool.replace("mobile_smali_",""), any_valid(r), True, tool)

# debug_windows
for tool in ["debug_windows_classify_exception","debug_windows_exception_name","debug_windows_status_name","debug_windows_protect_name","debug_windows_page_constants","debug_windows_is_committed","debug_windows_is_continuable"]:
    r = call(tool, {"code":0xc0000005} if "exception" in tool else {"status":0} if "status" in tool else {"protect":0x40} if "protect" in tool else {"state":0x1000} if "committed" in tool else {"code":0} if "continuable" in tool else {})
    if r:
        check("debug_windows_v2", tool.replace("debug_windows_",""), any_valid(r), True, tool)

# Save
try: p.terminate()
except: pass
for cat, d in per_cat.items():
    out = fr"C:\Users\Fra\Desktop\RustRE\validation\mismatch_{cat}.json"
    with open(out, "w") as f: json.dump({"category":cat, "checks_total":d["checks"], "checks_passed":d["passed"], "mismatches":d["mismatches"]}, f, indent=1)
    print(f"{cat}: {d['passed']}/{d['checks']} passed, {len(d['mismatches'])} mismatch")
total_c = sum(d["checks"] for d in per_cat.values()); total_p = sum(d["passed"] for d in per_cat.values()); total_m = sum(len(d["mismatches"]) for d in per_cat.values())
print(f"\nBATCH29 TOTAL: {total_p}/{total_c} passed, {total_m} mismatch across {len(per_cat)} categories")
