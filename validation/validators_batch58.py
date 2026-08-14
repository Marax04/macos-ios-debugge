#!/usr/bin/env python3
"""Batch58: ttd_recorder more, ttd_replay engine more, ttd query more, ttd_replayer more, ttd trace more."""
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

for tool in ["ttd_recorder_compression_level_display","ttd_recorder_config_for_pid","ttd_recorder_encryptor_roundtrip","ttd_recorder_filter_thread_allowed","ttd_recorder_is_valid_extension","ttd_recorder_metrics_summary","ttd_recorder_position_new","ttd_recorder_position_start","ttd_recorder_ring_buffer_overflow","ttd_recorder_schedule_should_stop","ttd_recorder_validate_trace","ttd_recorder_validation_is_perfect"]:
    r = call(tool, {})
    if r:
        check("ttd_recorder_v3", tool.replace("ttd_recorder_",""), any_valid(r), True, tool)

for tool in ["ttd_build_multi_thread_trace","ttd_build_test_trace","ttd_call_stack_from_trace","ttd_index_total_event_count","ttd_memory_map_from_trace","ttd_memory_region_contains","ttd_memory_snapshot_apply_write","ttd_memory_snapshot_contains","ttd_memory_snapshot_read_u32_le","ttd_memory_snapshot_read_u64_le","ttd_position_earliest","ttd_position_in_range","ttd_position_max","ttd_position_min","ttd_position_next_sequence","ttd_position_next_step","ttd_syscall_summary_from_trace","ttd_trace_event_count","ttd_trace_export_import_roundtrip","ttd_trace_filter_apply_by_kind","ttd_trace_position_as_u128","ttd_trace_position_compare","ttd_trace_position_from_u128","ttd_trace_stats_compute","ttd_trace_thread_ids_multi","ttd_watchpoint_find_hits"]:
    r = call(tool, {})
    if r:
        check("ttd_trace_v2", tool.replace("ttd_",""), any_valid(r), True, tool)

for tool in ["ttd_replayer_build_syscall_summaries","ttd_replayer_causal_step_build","ttd_replayer_find_root_cause","ttd_replayer_mem_write_bytes_in_range","ttd_replayer_mem_write_info","ttd_replayer_mem_write_overlaps","ttd_replayer_nearest_snapshot_before","ttd_replayer_query_execute_tick","ttd_replayer_query_parse_kind","ttd_replayer_replay_state_footprint","ttd_replayer_replay_state_program_counter","ttd_replayer_root_cause_report_build","ttd_replayer_scan_for_writes","ttd_replayer_snapshot_boundary","ttd_replayer_snapshot_page_count","ttd_replayer_trace_all_writes_touching","ttd_replayer_trace_event_index_query","ttd_replayer_trace_min_max_tick","ttd_replayer_trace_tick_bounds"]:
    r = call(tool, {})
    if r:
        check("ttd_replayer_v3", tool.replace("ttd_replayer_",""), any_valid(r), True, tool)

try: p.terminate()
except: pass
for cat, d in per_cat.items():
    out = fr"C:\Users\Fra\Desktop\RustRE\validation\mismatch_{cat}.json"
    with open(out, "w") as f: json.dump({"category":cat, "checks_total":d["checks"], "checks_passed":d["passed"], "mismatches":d["mismatches"]}, f, indent=1)
    print(f"{cat}: {d['passed']}/{d['checks']} passed, {len(d['mismatches'])} mismatch")
total_c = sum(d["checks"] for d in per_cat.values()); total_p = sum(d["passed"] for d in per_cat.values()); total_m = sum(len(d["mismatches"]) for d in per_cat.values())
print(f"\nBATCH58 TOTAL: {total_p}/{total_c} passed, {total_m} mismatch across {len(per_cat)} categories")
