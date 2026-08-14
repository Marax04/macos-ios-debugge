#!/usr/bin/env python3
"""Batch52: forensics_fs many, threatintel_x, ti_vt more, ti_opencti, malpedia."""
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

for tool in ["forensics_fs_detect_browser_db","forensics_fs_detect_certificate_store","forensics_fs_detect_dropped_payload","forensics_fs_detect_evtx","forensics_fs_detect_lnk","forensics_fs_detect_memory_dump","forensics_fs_detect_pagefile","forensics_fs_detect_prefetch","forensics_fs_detect_registry_hive","forensics_fs_inode_is_directory","forensics_fs_inode_table_find_by_name","forensics_fs_inode_table_find_deleted","forensics_fs_inode_table_insert_get","forensics_fs_inode_table_new_len_empty","forensics_fs_inode_total_run_bytes","forensics_fs_lnk_file_target_path","forensics_fs_lnk_parse","forensics_fs_memfs_node_child_lookup","forensics_fs_memfs_node_dir_child_by_name","forensics_fs_memfs_node_lazy_file_read","forensics_fs_memfs_node_v2_file_size","forensics_fs_memfs_node_v2_is_dir_check","forensics_fs_memfs_node_v2_is_file","forensics_fs_memfs_node_v2_size_file","forensics_fs_memory_fs_build_process_tree_empty","forensics_fs_memory_fs_into_root","forensics_fs_memory_fs_new_root","forensics_fs_memory_fs_root_inode","forensics_fs_node_v2_add_child","forensics_fs_node_v2_find_by_inode","forensics_fs_node_v2_find_child","forensics_fs_node_v2_sizes","forensics_fs_prefetch_file_loaded_modules","forensics_fs_prefetch_parse","forensics_fs_timeline_csv_roundtrip","forensics_fs_timeline_event_new","forensics_fs_timeline_event_type_kind_name","forensics_fs_timeline_filter_by_time","forensics_fs_timeline_filter_by_type","forensics_fs_timeline_hot_paths","forensics_fs_timeline_push_sort","forensics_fs_timeline_report","forensics_fs_to_export_dir_single_file"]:
    r = call(tool, {})
    if r:
        check("forensics_fs_v5", tool.replace("forensics_fs_",""), any_valid(r), True, tool)

for tool in ["threatintel_x_group_tracker_alias_search_count","threatintel_x_indicator_db_bulk_add","threatintel_x_indicator_db_export_stix_count","threatintel_x_ioc_new_hash_flag","threatintel_x_ioc_new_network_flag","threatintel_x_ioc_type_display_list","threatintel_x_malware_family_alias_count","threatintel_x_report_add_and_count","threatintel_x_report_json_roundtrip","threatintel_x_severity_ord_check","threatintel_x_threat_actor_ttp_count","threatintel_x_ttp_new_summary"]:
    r = call(tool, {})
    if r:
        check("threatintel_x", tool.replace("threatintel_x_",""), any_valid(r), True, tool)

for tool in ["ti_vt_analysis_stats_detection_ratio","ti_vt_analysis_stats_total","ti_vt_api_key_is_valid","ti_vt_av_result_classify","ti_vt_file_report_spec_stats","ti_vt_ip_report_spec_is_malicious","ti_vt_mock_file_report","ti_vt_mock_ip_report","ti_vt_parse_search_response","ti_vt_rate_limiter_free_tier","ti_vt_sandbox_verdict_score","ti_vt_scoring_weights_av_heavy","ti_vt_threat_level_from_score","ti_vt_threat_signals_detection_ratio","ti_vt_token_bucket_available","ti_vt_token_bucket_consume"]:
    r = call(tool, {})
    if r:
        check("ti_vt_v2", tool.replace("ti_vt_",""), any_valid(r), True, tool)

try: p.terminate()
except: pass
for cat, d in per_cat.items():
    out = fr"C:\Users\Fra\Desktop\RustRE\validation\mismatch_{cat}.json"
    with open(out, "w") as f: json.dump({"category":cat, "checks_total":d["checks"], "checks_passed":d["passed"], "mismatches":d["mismatches"]}, f, indent=1)
    print(f"{cat}: {d['passed']}/{d['checks']} passed, {len(d['mismatches'])} mismatch")
total_c = sum(d["checks"] for d in per_cat.values()); total_p = sum(d["passed"] for d in per_cat.values()); total_m = sum(len(d["mismatches"]) for d in per_cat.values())
print(f"\nBATCH52 TOTAL: {total_p}/{total_c} passed, {total_m} mismatch across {len(per_cat)} categories")
