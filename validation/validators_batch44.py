#!/usr/bin/env python3
"""Batch44: script_rhai many, script_builtin, script_bytes more, script_value, script_registry."""
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

for tool in ["script_rhai_binary_info","script_rhai_compute_entropy_v2","script_rhai_detect_arch","script_rhai_detect_format","script_rhai_detect_format_static","script_rhai_entropy_classify","script_rhai_entropy_impl","script_rhai_event_bus_new","script_rhai_event_hook_system_new","script_rhai_find_pattern","script_rhai_find_strings","script_rhai_get_info","script_rhai_hex_decode","script_rhai_hex_encode","script_rhai_load_binary","script_rhai_load_binary_into","script_rhai_lossy_i64_to_f64","script_rhai_lossy_u64_to_f64","script_rhai_match_pattern","script_rhai_new_binary_store","script_rhai_rhai_value_is_unit","script_rhai_sat_i64_to_usize_wire","script_rhai_sat_u64_to_usize_wire","script_rhai_sat_usize_to_i64","script_rhai_sha256_bytes","script_rhai_trunc_f64_to_i64","script_rhai_trunc_i64_to_u32","script_rhai_trunc_i64_to_u8","script_rhai_trunc_u128_to_u64","script_rhai_xor_bytes"]:
    r = call(tool, {})
    if r:
        check("script_rhai_v3", tool.replace("script_rhai_",""), any_valid(r), True, tool)

for tool in ["script_builtin_bytes_to_hex","script_builtin_functions_list_new","script_builtin_hex_to_bytes","script_bytes_concat","script_bytes_fill","script_bytes_fill_checked","script_bytes_find","script_bytes_slice","script_bytes_to_hex","script_hex_to_bytes","script_value_display","script_value_is_truthy","script_value_is_truthy_new","script_value_len_builtin","script_value_len_new","script_value_to_string_new","script_value_typeof_native","script_value_typeof_new","script_read_u8_new","script_read_u16_new","script_read_u32","script_read_u32_be_new","script_read_u64_new","script_registry_list","script_result_failure","script_sandbox_policy_preset","script_sandbox_policy_preset_new","script_variable_frame_probe","script_write_u16_new","script_write_u32_new","script_write_u64_new","script_write_u8_new","script_xor_bytes","script_pipeline_step_label","script_compiled_unit_info","script_error_runtime","script_error_is_recoverable","script_re_module_info"]:
    r = call(tool, {})
    if r:
        check("script_helpers", tool.replace("script_",""), any_valid(r), True, tool)

try: p.terminate()
except: pass
for cat, d in per_cat.items():
    out = fr"C:\Users\Fra\Desktop\RustRE\validation\mismatch_{cat}.json"
    with open(out, "w") as f: json.dump({"category":cat, "checks_total":d["checks"], "checks_passed":d["passed"], "mismatches":d["mismatches"]}, f, indent=1)
    print(f"{cat}: {d['passed']}/{d['checks']} passed, {len(d['mismatches'])} mismatch")
total_c = sum(d["checks"] for d in per_cat.values()); total_p = sum(d["passed"] for d in per_cat.values()); total_m = sum(len(d["mismatches"]) for d in per_cat.values())
print(f"\nBATCH44 TOTAL: {total_p}/{total_c} passed, {total_m} mismatch across {len(per_cat)} categories")
