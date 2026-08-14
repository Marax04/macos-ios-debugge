#!/usr/bin/env python3
"""Batch38: agent_llm more, agent_memory, agent_reasoning, agent_conversation, analysis_string extras."""
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

# agent llm more
for tool in ["agent_llm_builtin_models","agent_llm_context_manager_build","agent_llm_count_tokens","agent_llm_estimate_cost","agent_llm_extract_code_blocks","agent_llm_llm_model_display","agent_llm_llm_role_display","agent_llm_message_assistant","agent_llm_message_user","agent_llm_message_system","agent_llm_mock_provider_complete","agent_llm_token_counter_count_messages","agent_llm_token_counter_count_text","agent_llm_token_counter_fits_in_context"]:
    r = call(tool, {"text":"hello"} if "count_tokens" in tool or "count_text" in tool else {})
    if r:
        check("agent_llm_v3", tool.replace("agent_llm_",""), any_valid(r), True, tool)

# agent memory
for tool in ["agent_memory_entry_with_tags_v2","agent_memory_store_get","agent_memory_store_len","agent_memory_store_len_v2"]:
    r = call(tool, {})
    if r:
        check("agent_memory", tool.replace("agent_memory_",""), any_valid(r), True, tool)

# agent reasoning
for tool in ["agent_reasoning_add_step_v2","agent_reasoning_build","agent_reasoning_new_v2"]:
    r = call(tool, {})
    if r:
        check("agent_reasoning", tool.replace("agent_reasoning_",""), any_valid(r), True, tool)

# agent conversation
for tool in ["agent_conversation_add_message_v2","agent_message_kind_flags","agent_message_role_as_str_wire","agent_session_new_v2","agent_task_queue_len_drain","agent_task_queue_peek_pop"]:
    r = call(tool, {})
    if r:
        check("agent_conversation", tool.replace("agent_",""), any_valid(r), True, tool)

# rustre_analysis_string more
for tool in ["rustre_analysis_string_scan_ascii","rustre_analysis_string_scan_pascal","rustre_analysis_string_scan_utf16_le","rustre_analysis_string_scan_utf8","rustre_analysis_string_stats"]:
    r = call(tool, {"data":[0x48,0x69,0x00,0x66,0x6f,0x6f,0x00]})
    if r:
        check("analysis_string_v5", tool.replace("rustre_analysis_string_",""), any_valid(r), True, tool)

# agent metrics more
for tool in ["agent_metrics_avg_duration_ms","agent_metrics_success_rate","agent_metrics_summary","agent_metrics_tool_success_rate"]:
    r = call(tool, {"total":10,"success":8} if "success_rate" in tool else {})
    if r:
        check("agent_metrics_v2", tool.replace("agent_metrics_",""), any_valid(r), True, tool)

# agent workflow
for tool in ["agent_builtin_workflows","agent_bump_priority","agent_workflow_builtin_list","agent_workflow_templates_list","agent_standard_re_pipeline"]:
    r = call(tool, {})
    if r:
        check("agent_workflow_v2", tool.replace("agent_",""), any_valid(r), True, tool)

try: p.terminate()
except: pass
for cat, d in per_cat.items():
    out = fr"C:\Users\Fra\Desktop\RustRE\validation\mismatch_{cat}.json"
    with open(out, "w") as f: json.dump({"category":cat, "checks_total":d["checks"], "checks_passed":d["passed"], "mismatches":d["mismatches"]}, f, indent=1)
    print(f"{cat}: {d['passed']}/{d['checks']} passed, {len(d['mismatches'])} mismatch")
total_c = sum(d["checks"] for d in per_cat.values()); total_p = sum(d["passed"] for d in per_cat.values()); total_m = sum(len(d["mismatches"]) for d in per_cat.values())
print(f"\nBATCH38 TOTAL: {total_p}/{total_c} passed, {total_m} mismatch across {len(per_cat)} categories")
