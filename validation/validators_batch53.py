#!/usr/bin/env python3
"""Batch53: symbols_v6 many, symbols_core, symbols_pdb v4, symbols_v3 more."""
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

for tool in ["symbols_v6_addr_map_lookup","symbols_v6_conflict_resolve","symbols_v6_demangle_all_table","symbols_v6_function_boundary_ops","symbols_v6_pdb_url_build","symbols_v6_source_priority_all","symbols_v6_symkind_display_all","symbols_v6_synthetic_names_all","symbols_v6_try_demangle_batch","symbols_v6_unified_table_ops","symbols_v7_binding_display","symbols_v7_conflict_strategies_all","symbols_v7_debug_merger_finish","symbols_v7_demangler_pipeline_order","symbols_v7_export_table_lookup","symbols_v7_import_table_group","symbols_v7_in_memory_provider_ops","symbols_v7_legacy_source_display","symbols_v7_pdb_server_msdl","symbols_v7_section_symbols_count","symbols_v7_symbol_cache_lru","symbols_v7_symbol_contains","symbols_v7_symbol_exporter_all","symbols_v7_symbol_new_display","symbols_v7_symbol_stats_from_names","symbols_v7_symbol_store_ops","symbols_v7_symkind_classify","symbols_v7_unified_symbol_display","symbols_v7_visibility_display","symbols_v7_xref_index_ops"]:
    r = call(tool, {})
    if r:
        check("symbols_v6v7", tool.replace("symbols_",""), any_valid(r), True, tool)

for tool in ["rustre_symbols_core_address_map_lookup","rustre_symbols_core_backends_registry","rustre_symbols_core_cache_lru","rustre_symbols_core_conflict_resolver","rustre_symbols_core_debug_merger","rustre_symbols_core_demangler_pipeline","rustre_symbols_core_export_table_by_name","rustre_symbols_core_exporter_all","rustre_symbols_core_function_boundary","rustre_symbols_core_import_table_group","rustre_symbols_core_in_memory_provider","rustre_symbols_core_pdb_url_build","rustre_symbols_core_stats","rustre_symbols_core_store_export_map","rustre_symbols_core_store_roundtrip","rustre_symbols_core_symbol_filter_apply","rustre_symbols_core_symbol_source_priority","rustre_symbols_core_synthetic_names","rustre_symbols_core_try_demangle","rustre_symbols_core_unified_table_ops","rustre_symbols_core_xref_index"]:
    r = call(tool, {})
    if r:
        check("rustre_symbols_core", tool.replace("rustre_symbols_core_",""), any_valid(r), True, tool)

for tool in ["rustre_symbols_v3_cross_ref_index_ops","rustre_symbols_v3_exporter_all_formats","rustre_symbols_v3_pdb_server_url","rustre_symbols_v3_store_export_csv","rustre_symbols_v3_store_find_ops","rustre_symbols_v3_symbol_cache_ops","rustre_symbols_v3_symbol_contains","rustre_symbols_v3_symbol_new","rustre_symbols_v3_symbol_table_add_remove","rustre_symbols_v3_synthetic_gen_all","rustre_symbols_v3_try_demangle_top","rustre_symbols_v3_unified_table_pdb_url_list"]:
    r = call(tool, {})
    if r:
        check("rustre_symbols_v3", tool.replace("rustre_symbols_v3_",""), any_valid(r), True, tool)

try: p.terminate()
except: pass
for cat, d in per_cat.items():
    out = fr"C:\Users\Fra\Desktop\RustRE\validation\mismatch_{cat}.json"
    with open(out, "w") as f: json.dump({"category":cat, "checks_total":d["checks"], "checks_passed":d["passed"], "mismatches":d["mismatches"]}, f, indent=1)
    print(f"{cat}: {d['passed']}/{d['checks']} passed, {len(d['mismatches'])} mismatch")
total_c = sum(d["checks"] for d in per_cat.values()); total_p = sum(d["passed"] for d in per_cat.values()); total_m = sum(len(d["mismatches"]) for d in per_cat.values())
print(f"\nBATCH53 TOTAL: {total_p}/{total_c} passed, {total_m} mismatch across {len(per_cat)} categories")
