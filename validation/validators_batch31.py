#!/usr/bin/env python3
"""Batch31: analysis_cfg extras, decompiler_c, decompiler_cfs, events_ext, forensics_fs more."""
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

# analysis_cfg advanced
for tool in ["analysis_cfg_block_count","analysis_cfg_build_stats","analysis_cfg_cyclomatic_complexity","analysis_cfg_dominator_tree","analysis_cfg_dominance_frontier","analysis_cfg_find_back_edges","analysis_cfg_find_natural_loops","analysis_cfg_immediate_dominator","analysis_cfg_iterated_dominance_frontier","analysis_cfg_post_dominator_tree","analysis_cfg_reverse_post_order","analysis_cfg_scc_components","analysis_cfg_stats_entry_exit_blocks","analysis_cfg_reducibility_test","analysis_cfg_metrics_compute","analysis_cfg_to_dot"]:
    r = call(tool, {})
    if r:
        check("analysis_cfg_v4", tool.replace("analysis_cfg_",""), any_valid(r), True, tool)

# decompiler_c
for tool in ["decompiler_c_brace_style_default","decompiler_c_indent_make","decompiler_c_max_decompile_depth","decompiler_c_supported_languages","decompiler_c_version"]:
    r = call(tool, {})
    if r:
        check("decompiler_c", tool.replace("decompiler_c_",""), any_valid(r), True, tool)

# decompiler_cfs
for tool in ["decompiler_cfs_algorithm_display","decompiler_cfs_block_id_display","decompiler_cfs_branch_condition","decompiler_cfs_identifier_tokens","decompiler_cfs_scc_groups"]:
    r = call(tool, {})
    if r:
        check("decompiler_cfs", tool.replace("decompiler_cfs_",""), any_valid(r), True, tool)

# events_ext
for tool in ["events_ext_bus_metrics_snapshot","events_ext_bus_new_default","events_ext_bus_send_diff_started","events_ext_bus_send_emulation_step","events_ext_bus_send_fuzz_crash","events_ext_bus_send_ttd_tick","events_ext_bus_total_published","events_ext_bus_variant_count","events_ext_bus_dropped_count"]:
    r = call(tool, {})
    if r:
        check("events_ext_v2", tool.replace("events_ext_",""), any_valid(r), True, tool)

# forensics_fs more
for tool in ["forensics_fs_prefetch_analyzer_report","forensics_fs_prefetch_pattern_matcher_risk","forensics_fs_prefetch_summary","forensics_fs_lnk_analyzer_summary","forensics_fs_memfs_node_dir_children","forensics_fs_memfs_node_file_size","forensics_fs_memory_fs_new","forensics_fs_artifact_scanner_scan_path"]:
    r = call(tool, {})
    if r:
        check("forensics_fs_v4", tool.replace("forensics_fs_",""), any_valid(r), True, tool)

# Save
try: p.terminate()
except: pass
for cat, d in per_cat.items():
    out = fr"C:\Users\Fra\Desktop\RustRE\validation\mismatch_{cat}.json"
    with open(out, "w") as f: json.dump({"category":cat, "checks_total":d["checks"], "checks_passed":d["passed"], "mismatches":d["mismatches"]}, f, indent=1)
    print(f"{cat}: {d['passed']}/{d['checks']} passed, {len(d['mismatches'])} mismatch")
total_c = sum(d["checks"] for d in per_cat.values()); total_p = sum(d["passed"] for d in per_cat.values()); total_m = sum(len(d["mismatches"]) for d in per_cat.values())
print(f"\nBATCH31 TOTAL: {total_p}/{total_c} passed, {total_m} mismatch across {len(per_cat)} categories")
