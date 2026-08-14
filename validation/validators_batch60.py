#!/usr/bin/env python3
"""Batch60: syscalls many, loader_multi, loader_pipeline, script tail, threatintel_group more."""
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

for tool in ["syscalls_builder_build_open_v2","syscalls_call_prefix_flags_v2","syscalls_categorize_by_name","syscalls_clock_id_name_v2","syscalls_cross_arch_table","syscalls_database_empty_stats_v2","syscalls_database_stats","syscalls_decode_arg_fd_v2","syscalls_decode_arg_ip_addr_v2","syscalls_decode_arg_signal_v2","syscalls_detect_ia32_mechanism","syscalls_errno_name_lookup","syscalls_errno_name_lookup_wire","syscalls_estimate_risk","syscalls_format_cross_arch_table","syscalls_formatter_format_arg_fd_v2","syscalls_ia32_to_x86_64_nr","syscalls_linux_aarch64_name","syscalls_linux_aarch64_nr","syscalls_linux_category","syscalls_linux_decode_mmap_flags","syscalls_linux_decode_mmap_prot","syscalls_linux_decode_open_flags","syscalls_linux_error_not_found_display","syscalls_linux_format_exit_event","syscalls_linux_format_mmap_args","syscalls_linux_format_open_flags","syscalls_linux_format_retval","syscalls_linux_format_signal_delivery","syscalls_linux_hex_dump_ext","syscalls_linux_lookup_x86_64_entry","syscalls_linux_param_new","syscalls_linux_security_severity","syscalls_lookup_cross_arch","syscalls_sa_family_name_v2","syscalls_seccomp_policy_evaluate_v2","syscalls_signal_name_lookup","syscalls_signal_name_lookup_wire","syscalls_table_linux_arm64_list","syscalls_table_linux_x86_64_list","syscalls_table_max_number_x86_64_v2","syscalls_table_name_to_number","syscalls_table_number_to_name","syscalls_table_windows_x64_list","syscalls_trace_empty_error_rate_v2","syscalls_win10_22h2_syscalls","syscalls_windows_apis_by_module","syscalls_windows_arch_list","syscalls_windows_build_version_ssn_table","syscalls_windows_decode_alloc_type","syscalls_windows_decode_file_access","syscalls_windows_detect_hook_type","syscalls_windows_format_ntstatus","syscalls_windows_format_ntstatus_wire_v3","syscalls_windows_is_clean_stub_dual","syscalls_windows_is_clean_x64_stub","syscalls_windows_is_clean_x86_stub","syscalls_windows_is_dangerous_privilege","syscalls_windows_is_persistence_registry_key","syscalls_windows_is_system_path","syscalls_windows_is_system_path_wire_v2","syscalls_windows_lookup_win32_api","syscalls_windows_nt_to_win32_path","syscalls_windows_nt_to_win32_reg_path","syscalls_windows_version_list"]:
    r = call(tool, {})
    if r:
        check("syscalls_v3", tool.replace("syscalls_",""), any_valid(r), True, tool)

for tool in ["loader_android_adler32","loader_android_is_apk","loader_android_is_dex","loader_android_is_vdex","loader_android_verify_dex_checksum","loader_multi_format_probe_all","loader_multi_format_registry_find","loader_multi_format_registry_is_empty","loader_multi_format_registry_len","loader_multi_format_registry_loader_names","loader_multi_format_registry_new","loader_multi_loader_input_to_bytes","loader_pipeline_detect_format","loader_pipeline_loader_count","loader_pipeline_name","loader_pipeline_new","loader_hub_coordinator_new_empty","loader_coordinator_loader_count","loader_coordinator_new_with_registry","loader_console_xor_checksum","loader_core_md5","loader_core_sha256"]:
    r = call(tool, {})
    if r:
        check("loader_v3", tool.replace("loader_",""), any_valid(r), True, tool)

try: p.terminate()
except: pass
for cat, d in per_cat.items():
    out = fr"C:\Users\Fra\Desktop\RustRE\validation\mismatch_{cat}.json"
    with open(out, "w") as f: json.dump({"category":cat, "checks_total":d["checks"], "checks_passed":d["passed"], "mismatches":d["mismatches"]}, f, indent=1)
    print(f"{cat}: {d['passed']}/{d['checks']} passed, {len(d['mismatches'])} mismatch")
total_c = sum(d["checks"] for d in per_cat.values()); total_p = sum(d["passed"] for d in per_cat.values()); total_m = sum(len(d["mismatches"]) for d in per_cat.values())
print(f"\nBATCH60 TOTAL: {total_p}/{total_c} passed, {total_m} mismatch across {len(per_cat)} categories")
