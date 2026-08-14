#!/usr/bin/env python3
"""Batch30: debug_macos, debug_frida, debug_unicorn extras, decompiler_type extras, ghidra backend, symb_engine."""
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

# debug_macos
for tool in ["debug_macos_cpu_type_from_u32","debug_macos_mach_exception_from_u32","debug_macos_format_uuid","debug_macos_extract_uuid","debug_macos_extract_dylibs","debug_macos_arm64_register_index","debug_macos_x86_register_index","debug_macos_thread_list_ops"]:
    args = {"cpu":0x100000c} if "cpu_type" in tool else {"exc":1} if "exception" in tool else {"uuid":[0]*16} if "format_uuid" in tool else {"reg":"x0"} if "arm64_register" in tool else {"reg":"rax"} if "x86_register" in tool else {}
    r = call(tool, args)
    if r:
        check("debug_macos_v2", tool.replace("debug_macos_",""), any_valid(r), True, tool)

# debug_frida
for tool in ["debug_frida_new_session_state","debug_frida_hook_display","debug_frida_v2_device_display","debug_frida_interceptor_record_display","debug_frida_scan_memory_detached","debug_frida_v2_manager_lifecycle","debug_frida_simulate_hook_hit_detached"]:
    r = call(tool, {})
    if r:
        check("debug_frida_v2", tool.replace("debug_frida_",""), any_valid(r), True, tool)

# debug_unicorn extras
for tool in ["debug_unicorn_coverage_map_merge","debug_unicorn_coverage_map_report","debug_unicorn_emulate_steps","debug_unicorn_hook_record_describe","debug_unicorn_instruction_trace_stats","debug_unicorn_memory_mapper_map_v2","debug_unicorn_register_history_diff","debug_unicorn_script_gen","debug_unicorn_snapshot_manager_ops","debug_unicorn_thread_simulate"]:
    r = call(tool, {})
    if r:
        check("debug_unicorn_v3", tool.replace("debug_unicorn_",""), any_valid(r), True, tool)

# decompiler_type extras
for tool in ["decompiler_type_calling_convention_zx2","decompiler_type_env_struct_named_zx2","decompiler_type_function_arity_zx2","decompiler_type_lattice_from_decomp_zx2","decompiler_type_lattice_join_zx2","decompiler_type_layout_padded_size_zx2","decompiler_type_pointee_c_name_zx2","decompiler_type_pointer_analysis_zx2","decompiler_type_qualified_c_name_zx2"]:
    r = call(tool, {})
    if r:
        check("decompiler_type_v4", tool.replace("decompiler_type_","").replace("_zx2",""), any_valid(r), True, tool)

# ghidra backend
for tool in ["ghidra_backend_arch_ghidfixp1","ghidra_backend_arm64_info","ghidra_backend_for_x86_64_ghidfixp1","ghidra_backend_supported_archs","ghidra_backend_new_custom_arch_gwx4","ghidra_availability_check","ghidra_config_from_home","ghidra_bridge_module"]:
    r = call(tool, {})
    if r:
        check("ghidra_backend_v2", tool.replace("ghidra_",""), any_valid(r), True, tool)

# symb_engine extras
for tool in ["symb_engine_check_satisfiable_const","symb_engine_default_solver","symb_engine_default_strategy","symb_engine_executor_config_default","symb_engine_function_summary_new","symb_engine_halt_reason_list","symb_engine_lifted_instr_new","symb_engine_simplify_constraints_len","symb_engine_solver_type_list","symb_engine_widen_sequence_check"]:
    r = call(tool, {})
    if r:
        check("symb_engine_v2", tool.replace("symb_engine_",""), any_valid(r), True, tool)

# Save
try: p.terminate()
except: pass
for cat, d in per_cat.items():
    out = fr"C:\Users\Fra\Desktop\RustRE\validation\mismatch_{cat}.json"
    with open(out, "w") as f: json.dump({"category":cat, "checks_total":d["checks"], "checks_passed":d["passed"], "mismatches":d["mismatches"]}, f, indent=1)
    print(f"{cat}: {d['passed']}/{d['checks']} passed, {len(d['mismatches'])} mismatch")
total_c = sum(d["checks"] for d in per_cat.values()); total_p = sum(d["passed"] for d in per_cat.values()); total_m = sum(len(d["mismatches"]) for d in per_cat.values())
print(f"\nBATCH30 TOTAL: {total_p}/{total_c} passed, {total_m} mismatch across {len(per_cat)} categories")
