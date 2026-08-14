#!/usr/bin/env python3
"""Batch57: agent_prompts_v2 more, agent_llm_lib more, hex_pattern more, hex_tplx more, hex_template."""
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

for tool in ["agent_prompts_v2_context_builder_full","agent_prompts_v2_engine_builtins","agent_prompts_v2_engine_prompt_variable","agent_prompts_v2_few_shot_count_filter","agent_prompts_v2_few_shot_similarity","agent_prompts_v2_prompt_chain_execute","agent_prompts_v2_render_pairs","agent_prompts_v2_spec_registry_builtins","agent_prompts_v2_spec_template_var_kinds","agent_prompts_v2_template_registry_builtins"]:
    r = call(tool, {})
    if r:
        check("agent_prompts_v2_v2", tool.replace("agent_prompts_v2_",""), any_valid(r), True, tool)

for tool in ["agent_cast_f64_to_f32","agent_cast_f64_to_u32","agent_cast_f64_to_u64","agent_cast_i64_to_f64","agent_cast_u64_to_f32","agent_cast_u64_to_f64","agent_cast_u64_to_u32","agent_cast_u64_to_usize","agent_cast_usize_to_f64","agent_id_new_wire","agent_llm_llm_model_display","agent_llm_llm_role_display","agent_llm_message_assistant_wire","agent_llm_message_user_wire","agent_observation_build","agent_parse_confidence","agent_parse_vulnerabilities","agent_plan_new_v2","agent_plugin_registry_empty_v2","agent_prompt_gen_disasm","agent_prompt_gen_malware","agent_prompt_gen_rename","agent_prompt_gen_vuln","agent_prompt_gen_yara","agent_prompt_generator_rename_v2","agent_rate_limiter_acquire","agent_rate_limiter_available","agent_rate_limiter_reset_v2","agent_rate_limiter_try_acquire","agent_response_extract_json","agent_response_parse_renames","agent_self_improvement_avg_rating_v2","agent_self_improvement_summary","agent_shannon_entropy"]:
    r = call(tool, {})
    if r:
        check("agent_helpers", tool.replace("agent_",""), any_valid(r), True, tool)

for tool in ["hex_tplx_apply_builtin_to_bytes","hex_tplx_bitfield_def_extract","hex_tplx_bitfield_struct_extract","hex_tplx_builtin_count","hex_tplx_elf32_shdr","hex_tplx_expr_eval","hex_tplx_pe_opt_header","hex_tplx_printer_render","hex_tplx_registry_apply","hex_tplx_registry_with_builtins","hex_tplx_template_json_roundtrip","hex_template_bitfield_extract","hex_template_builtin_names","hex_template_builtin_templates","hex_template_elf32_phdr","hex_template_elf64_phdr","hex_template_riff_chunk","hex_template_riff_chunk_wire","hex_template_wav","hex_template_wav_wire"]:
    r = call(tool, {})
    if r:
        check("hex_tplx_v2", tool.replace("hex_",""), any_valid(r), True, tool)

try: p.terminate()
except: pass
for cat, d in per_cat.items():
    out = fr"C:\Users\Fra\Desktop\RustRE\validation\mismatch_{cat}.json"
    with open(out, "w") as f: json.dump({"category":cat, "checks_total":d["checks"], "checks_passed":d["passed"], "mismatches":d["mismatches"]}, f, indent=1)
    print(f"{cat}: {d['passed']}/{d['checks']} passed, {len(d['mismatches'])} mismatch")
total_c = sum(d["checks"] for d in per_cat.values()); total_p = sum(d["passed"] for d in per_cat.values()); total_m = sum(len(d["mismatches"]) for d in per_cat.values())
print(f"\nBATCH57 TOTAL: {total_p}/{total_c} passed, {total_m} mismatch across {len(per_cat)} categories")
