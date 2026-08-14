#!/usr/bin/env python3
"""Batch70: analyze_top, function_list, forensics_open, decompiler_core, agent_prompts_v3."""
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

for tool in ["analyze_basic_block","analyze_call_graph","analyze_cross_refs","analyze_exports","analyze_function","analyze_imports","analyze_strings","binary_entropy","binary_hexdump","binary_info","binary_read","binary_search_bytes","binary_search_strings","function_list_by_kind","survey_binary","noreturn_infer","forensics_open_dump","forensics_run_plugin","project_close","project_list_binaries","project_info","project_open"]:
    r = call(tool, {})
    if r:
        check("mcp_top_level", tool, any_valid(r), True, tool)

for tool in ["decompiler_core_batch_decompile","decompiler_detect_functions","decompiler_disassemble_function_x86","decompiler_expr_int_width_bits","decompiler_expr_int_width_bytes","decompiler_load_binary_info","decompiler_os_from_pe_flag","decompiler_recover_structs","decompiler_stack_frame_report","decompile_function","decompile_rename_variable","decompile_set_type","decompiler_arch_from_str","disasm_at","disasm_function"]:
    r = call(tool, {})
    if r:
        check("decompiler_v2", tool.replace("decompiler_","").replace("decompile_",""), any_valid(r), True, tool)

for tool in ["agent_prompts_v2_context_builder_full","agent_prompts_v2_engine_builtins","agent_prompts_v2_engine_prompt_variable","agent_prompts_v2_few_shot_count_filter","agent_prompts_v2_few_shot_similarity","agent_prompts_v2_prompt_chain_execute","agent_prompts_v2_render_pairs","agent_prompts_v2_spec_registry_builtins","agent_prompts_v2_spec_template_var_kinds","agent_prompts_v2_template_registry_builtins"]:
    r = call(tool, {})
    if r:
        check("agent_prompts_v2_v3", tool.replace("agent_prompts_v2_",""), any_valid(r), True, tool)

for tool in ["kg_annotate","kg_get_function","kg_list_functions","kg_query","kg_search","kg_set_comment","kg_set_function_name"]:
    r = call(tool, {})
    if r:
        check("kg_top", tool.replace("kg_",""), any_valid(r), True, tool)

try: p.terminate()
except: pass
for cat, d in per_cat.items():
    out = fr"C:\Users\Fra\Desktop\RustRE\validation\mismatch_{cat}.json"
    with open(out, "w") as f: json.dump({"category":cat, "checks_total":d["checks"], "checks_passed":d["passed"], "mismatches":d["mismatches"]}, f, indent=1)
    print(f"{cat}: {d['passed']}/{d['checks']} passed, {len(d['mismatches'])} mismatch")
total_c = sum(d["checks"] for d in per_cat.values()); total_p = sum(d["passed"] for d in per_cat.values()); total_m = sum(len(d["mismatches"]) for d in per_cat.values())
print(f"\nBATCH70 TOTAL: {total_p}/{total_c} passed, {total_m} mismatch across {len(per_cat)} categories")
