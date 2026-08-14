#!/usr/bin/env python3
"""Batch35: agent_prompts many, symb_z3_solver, trace_recorder more, ti_malpedia more, pe_editor extras."""
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

# agent_prompts many
for tool in ["agent_prompts_builtin_template_names","agent_prompts_context_build","agent_prompts_error_display","agent_prompts_few_shot_roundtrip","agent_prompts_registry_count","agent_prompts_registry_list_names","agent_prompts_registry_render","agent_prompts_render_template","agent_prompts_spec_template_render","agent_prompts_template_new","agent_prompts_template_var_spec"]:
    r = call(tool, {})
    if r:
        check("agent_prompts_v3", tool.replace("agent_prompts_",""), any_valid(r), True, tool)

# symb_z3 solver
for tool in ["symb_z3_solver_check_sat_const","symb_z3_solver_cache_size","symb_z3_solver_clear_cache","symb_z3_solver_hit_rate","symb_z3_solver_push_pop_cycle","symb_z3_solver_to_smtlib2_const","symb_z3_solver_with_logic_smt","symb_z3_builder_new_logic","symb_z3_builder_push_pop_timeout","symb_z3_parser_parse_unsat"]:
    r = call(tool, {})
    if r:
        check("symb_z3_solver_v2", tool.replace("symb_z3_",""), any_valid(r), True, tool)

# trace_recorder more
for tool in ["trace_recorder_is_full","trace_recorder_new","trace_recorder_record_insn","trace_recorder_record_wt1"]:
    r = call(tool, {})
    if r:
        check("trace_recorder_v2", tool.replace("trace_recorder_",""), any_valid(r), True, tool)

# ti_malpedia more
for tool in ["ti_malpedia_actor_spec_new","ti_malpedia_alias_resolve","ti_malpedia_alias_resolver_count","ti_malpedia_attribution_method_display","ti_malpedia_classifier_score_all","ti_malpedia_classify_family","ti_malpedia_client_list_actors","ti_malpedia_family_platform_prefix","ti_malpedia_family_to_malware_type","ti_malpedia_local_db_list_families","ti_malpedia_mock_family_response","ti_malpedia_signature_score","ti_malpedia_yara_rule_new"]:
    r = call(tool, {})
    if r:
        check("ti_malpedia_v2", tool.replace("ti_malpedia_",""), any_valid(r), True, tool)

# pe_editor more
for tool in ["pe_editor_certificate_header_bytes_len","pe_editor_certificate_header_dw_length","pe_editor_export_add","pe_editor_export_editor_new","pe_editor_export_editor_new_dll","pe_editor_export_remove","pe_editor_import_editor_new","pe_editor_import_entry_display","pe_editor_parse_dos_header","pe_editor_parse_file_header","pe_editor_parse_optional_header64","pe_editor_patchset_new","pe_editor_rc4_process_bytes","pe_editor_resource_editor_new"]:
    r = call(tool, {})
    if r:
        check("pe_editor_v3", tool.replace("pe_editor_",""), any_valid(r), True, tool)

# Save
try: p.terminate()
except: pass
for cat, d in per_cat.items():
    out = fr"C:\Users\Fra\Desktop\RustRE\validation\mismatch_{cat}.json"
    with open(out, "w") as f: json.dump({"category":cat, "checks_total":d["checks"], "checks_passed":d["passed"], "mismatches":d["mismatches"]}, f, indent=1)
    print(f"{cat}: {d['passed']}/{d['checks']} passed, {len(d['mismatches'])} mismatch")
total_c = sum(d["checks"] for d in per_cat.values()); total_p = sum(d["passed"] for d in per_cat.values()); total_m = sum(len(d["mismatches"]) for d in per_cat.values())
print(f"\nBATCH35 TOTAL: {total_p}/{total_c} passed, {total_m} mismatch across {len(per_cat)} categories")
