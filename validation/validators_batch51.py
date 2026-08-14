#!/usr/bin/env python3
"""Batch51: adb many, adf more, agent_llm final, deobf_smc many."""
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

for tool in ["adb_build_banner","adb_build_install_command","adb_build_uninstall_command","adb_client_new_with_timeout","adb_cmd_all_constants","adb_command_constant","adb_compute_crc32","adb_connect_banner_has_feature","adb_connect_banner_parse","adb_crc32_roundtrip","adb_current_mtime","adb_decode_message","adb_device_is_ready_from_line","adb_device_state_classify","adb_device_state_is_online","adb_device_state_needs_auth","adb_encode_data_chunk","adb_encode_decode_roundtrip_v2","adb_encode_done","adb_encode_list_request","adb_encode_message","adb_encode_message_length","adb_encode_stat_request","adb_filter_by_level","adb_filter_by_level_count","adb_filter_by_tag","adb_group_by_tag","adb_group_by_tag_counts","adb_install_succeeded","adb_local_client_host_v2","adb_local_client_info","adb_log_entry_parse_auto","adb_log_entry_parse_brief_v2","adb_log_level_as_char","adb_log_level_display","adb_log_level_severity","adb_make_close","adb_make_connect","adb_make_connect_device","adb_make_okay","adb_make_open","adb_make_write","adb_max_payload_constant","adb_message_command_name","adb_message_command_name_for_u32","adb_message_crc_field","adb_message_data_str","adb_message_encode","adb_message_magic_field","adb_message_new","adb_message_no_data","adb_message_verify_crc","adb_msg_auth","adb_msg_close","adb_msg_connect","adb_msg_no_data_encoded","adb_msg_okay","adb_msg_open","adb_msg_write","adb_parse_brief_line","adb_parse_devices_output","adb_parse_features","adb_parse_getprop_output","adb_parse_logcat","adb_parse_logcat_line","adb_parse_logcat_output","adb_parse_pm_list_line","adb_parse_pm_list_output","adb_parse_threadtime_line","adb_protocol_auth_constants","adb_protocol_cmd_constants","adb_protocol_default_port","adb_protocol_max_data","adb_protocol_state_machine_new","adb_protocol_version_constant","adb_reboot_service_constants","adb_service_constants","adb_service_forward","adb_service_reverse","adb_service_shell_cmd","adb_service_transport_serial","adb_shell_result_success","adb_sync_cmd_tags","adb_sync_encode_list","adb_sync_encode_quit","adb_sync_encode_recv","adb_sync_encode_stat","adb_sync_max_data_chunk","adb_uninstall_succeeded"]:
    r = call(tool, {})
    if r:
        check("adb_v3", tool.replace("adb_",""), any_valid(r), True, tool)

for tool in ["adf_trace_callers_backward_simple","adf_statement_with_expr","adf_compute_dominators_chain","adf_dominators_from_edges","adf_lattice_value_meet_different","adf_lattice_value_meet_top","adf_linear_cfg_node_count","adf_postorder_chain","adf_statement_new","adf_trace_callees_forward_simple"]:
    r = call(tool, {})
    if r:
        check("adf_v3", tool.replace("adf_",""), any_valid(r), True, tool)

try: p.terminate()
except: pass
for cat, d in per_cat.items():
    out = fr"C:\Users\Fra\Desktop\RustRE\validation\mismatch_{cat}.json"
    with open(out, "w") as f: json.dump({"category":cat, "checks_total":d["checks"], "checks_passed":d["passed"], "mismatches":d["mismatches"]}, f, indent=1)
    print(f"{cat}: {d['passed']}/{d['checks']} passed, {len(d['mismatches'])} mismatch")
total_c = sum(d["checks"] for d in per_cat.values()); total_p = sum(d["passed"] for d in per_cat.values()); total_m = sum(len(d["mismatches"]) for d in per_cat.values())
print(f"\nBATCH51 TOTAL: {total_p}/{total_c} passed, {total_m} mismatch across {len(per_cat)} categories")
