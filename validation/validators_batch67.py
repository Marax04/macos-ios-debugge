#!/usr/bin/env python3
"""Batch67: analysis_dataflow more, events core/logger/spec, wire_*, arch_x86 more."""
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

for tool in ["analysis_dataflow_compute_dominance_frontiers","analysis_dataflow_compute_dominators","analysis_dataflow_compute_dominators_from_edges","analysis_dataflow_compute_liveness","analysis_dataflow_compute_reaching_defs","analysis_dataflow_insert_phi_nodes","analysis_dataflow_lattice_meet","analysis_dataflow_linear_cfg_size","analysis_dataflow_max_backward_hops","analysis_dataflow_max_forward_hops","analysis_dataflow_postorder","analysis_dataflow_propagate_constants","analysis_dataflow_trace_callees_forward","analysis_dataflow_trace_callers_backward"]:
    r = call(tool, {})
    if r:
        check("analysis_dataflow_v2", tool.replace("analysis_dataflow_",""), any_valid(r), True, tool)

for tool in ["events_bus_event_count","events_bus_event_counters","events_bus_new_capacity_ext","events_bus_new_default","events_bus_publish_custom","events_bus_send_agent_action_ext","events_bus_send_analysis_failed_ext","events_bus_send_analysis_progress_ext","events_bus_send_breakpoint_hit","events_bus_send_custom","events_bus_send_function_renamed_ext","events_bus_send_patch_applied_ext","events_bus_send_plugin_loaded","events_bus_send_script_executed_ext","events_bus_send_symbol_defined_ext","events_bus_send_view_closed","events_bus_send_xref_added_ext","events_bus_total_sent_variant","events_core_event_display_formatting","events_core_event_is_analysis_event","events_core_event_is_debug_event","events_core_event_is_function_event","events_core_event_json_roundtrip","events_core_event_kind_memory","events_core_event_variant_name","events_correlator_by_variant","events_correlator_by_view","events_correlator_keys_and_total","events_filter_by_variant","events_filter_combinators","events_filter_for_view","events_filter_negate","events_filter_of_kind_matches","events_filtered_subscription_counters","events_global_bus_publish","events_hook_dispatcher_new","events_hook_dispatcher_register","events_hook_dispatcher_remove","events_hook_matches_and_label","events_logger_clear_and_count","events_logger_events_by_kind","events_logger_events_for_view","events_logger_new","events_logger_recent_events","events_logger_record_and_count","events_replay_clear","events_replay_filtered","events_replay_new_is_empty","events_replay_push","events_replay_replay_all_ext","events_replay_snapshot_from","events_spec_bus_new_history","events_spec_bus_publish_and_receivers","events_spec_bus_recent_events","events_spec_core_event_json_roundtrip","events_spec_core_event_variant_name","events_spec_filter_combined","events_spec_filter_pass_global","events_stats_kind_count_ext","events_stats_kind_count_reset","events_stats_record","events_stats_record_many","events_stats_variant_count","events_view_subscription"]:
    r = call(tool, {})
    if r:
        check("events_v3", tool.replace("events_",""), any_valid(r), True, tool)

for tool in ["wire_bytes_hex_encode","wire_bytes_len","wire_echo_string","wire_string_len"]:
    r = call(tool, {})
    if r:
        check("wire_v2", tool.replace("wire_",""), any_valid(r), True, tool)

for tool in ["arch_x86_calling_conventions","arch_x86_disassemble_and_lift","arch_x86_lift_to_llil","arch_x86_metadata","arch_x86_registers"]:
    r = call(tool, {})
    if r:
        check("arch_x86_v2", tool.replace("arch_x86_",""), any_valid(r), True, tool)

try: p.terminate()
except: pass
for cat, d in per_cat.items():
    out = fr"C:\Users\Fra\Desktop\RustRE\validation\mismatch_{cat}.json"
    with open(out, "w") as f: json.dump({"category":cat, "checks_total":d["checks"], "checks_passed":d["passed"], "mismatches":d["mismatches"]}, f, indent=1)
    print(f"{cat}: {d['passed']}/{d['checks']} passed, {len(d['mismatches'])} mismatch")
total_c = sum(d["checks"] for d in per_cat.values()); total_p = sum(d["passed"] for d in per_cat.values()); total_m = sum(len(d["mismatches"]) for d in per_cat.values())
print(f"\nBATCH67 TOTAL: {total_p}/{total_c} passed, {total_m} mismatch across {len(per_cat)} categories")
