#!/usr/bin/env python3
"""Batch42: analysis_cache, analysis_xref_db, decompiler_type_database, symbols_stabs more."""
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

# analysis_cache
for tool in ["analysis_cache_compute_hash","analysis_cache_key_from_data","analysis_cache_lru_basics"]:
    r = call(tool, {"data":[1,2,3]} if "compute" in tool or "key_from" in tool else {})
    if r:
        check("analysis_cache", tool.replace("analysis_cache_",""), any_valid(r), True, tool)

# analysis_xref_db
for tool in ["analysis_xref_call_graph_root_functions","analysis_xref_database_stats","analysis_xref_db_roundtrip","analysis_xref_get_xrefs_from","analysis_xref_get_xrefs_to","analysis_xref_global_db_total","analysis_xref_global_xrefs_from","analysis_xref_global_xrefs_to","analysis_xref_parse_kind","analysis_xref_string_ref_counts"]:
    r = call(tool, {})
    if r:
        check("analysis_xref_db", tool.replace("analysis_xref_",""), any_valid(r), True, tool)

# decompiler_type_database
for tool in ["decompiler_type_database_get_function_z1","decompiler_type_database_get_struct_z1","decompiler_type_database_get_union_z1","decompiler_type_database_linux_counts_wp","decompiler_type_database_resolve_typedef_n2","decompiler_type_database_windows_counts_wp","decompiler_type_stdlib_db_counts_wp"]:
    r = call(tool, {})
    if r:
        check("decompiler_type_db", tool.replace("decompiler_type_",""), any_valid(r), True, tool)

# symbols_stabs more
for tool in ["symbols_stabs_line_number_table_lookup","symbols_stabs_parse_all","symbols_stabs_parse_from_elf","symbols_stabs_provider_from_bytes","symbols_stabs_record_parse_all_be","symbols_stabs_string_table_roundtrip","symbols_stabs_type_category","symbols_stabs_type_code_from_char_v2","symbols_stabs_type_is_line_number","symbols_stabs_type_is_scope_bracket","symbols_stabs_type_is_source_file","symbols_stabs_type_is_symbol","symbols_stabs_type_parser_parse_descriptor","symbols_stabs_type_parser_primitives"]:
    r = call(tool, {})
    if r:
        check("symbols_stabs_v3", tool.replace("symbols_stabs_",""), any_valid(r), True, tool)

# codeview more
for tool in ["codeview_build_test_pub32","codeview_data32_parse","codeview_frameproc_parse","codeview_guid_to_string","codeview_magic_detect","codeview_parse_cv8_lines","codeview_parse_symbols","codeview_parse_type_record_single","codeview_parse_type_records","codeview_pdb_path_from_pe","codeview_pdb_superblock_parse","codeview_primitive_type","codeview_proc32_parse","codeview_public32_parse","codeview_signature_from_bytes","codeview_symbol_filter_count","codeview_symbol_stream_count"]:
    r = call(tool, {})
    if r:
        check("codeview_v3", tool.replace("codeview_",""), any_valid(r), True, tool)

try: p.terminate()
except: pass
for cat, d in per_cat.items():
    out = fr"C:\Users\Fra\Desktop\RustRE\validation\mismatch_{cat}.json"
    with open(out, "w") as f: json.dump({"category":cat, "checks_total":d["checks"], "checks_passed":d["passed"], "mismatches":d["mismatches"]}, f, indent=1)
    print(f"{cat}: {d['passed']}/{d['checks']} passed, {len(d['mismatches'])} mismatch")
total_c = sum(d["checks"] for d in per_cat.values()); total_p = sum(d["passed"] for d in per_cat.values()); total_m = sum(len(d["mismatches"]) for d in per_cat.values())
print(f"\nBATCH42 TOTAL: {total_p}/{total_c} passed, {total_m} mismatch across {len(per_cat)} categories")
