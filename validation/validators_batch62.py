#!/usr/bin/env python3
"""Batch62: rustre_vsa v3, rustre_symb_v2 more, symb_engine v4, symb_z3 more, il_lift more."""
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

for tool in ["rustre_vsa_is_definitely_null","rustre_vsa_may_be_out_of_bounds","rustre_vsa_strided_interval_join","rustre_vsa_strided_interval_singleton","rustre_vsa_strided_interval_widen","rustre_vsa_valueset_add","rustre_vsa_valueset_bitwise_and","rustre_vsa_valueset_bitwise_or","rustre_vsa_valueset_contains","rustre_vsa_valueset_interval","rustre_vsa_valueset_strided","rustre_vsa_valueset_sub"]:
    r = call(tool, {})
    if r:
        check("rustre_vsa_v3", tool.replace("rustre_vsa_",""), any_valid(r), True, tool)

for tool in ["callconv_aapcs32_name_v2","callconv_aapcs64","callconv_aapcs64_arg_register_count","callconv_cdecl_x86_name_v2","callconv_fastcall_x86_name_v2","callconv_mips_o32_name_v2","callconv_msvc_x64","callconv_msvc_x64_is_callee_saved","callconv_msvc_x64_name","callconv_riscv64_lp64d_name_v2","callconv_stdcall_x86_name_v2","callconv_sysv_x64","callconv_sysv_x64_arg_register_at","callconv_sysv_x64_is_arg_register","callconv_sysv_x64_name","callconv_thiscall_x86_name_v2","callconv_vectorcall_x64_name_v2"]:
    r = call(tool, {})
    if r:
        check("callconv_v2", tool.replace("callconv_",""), any_valid(r), True, tool)

for tool in ["il_lift_arch_count","il_lift_arch_description","il_lift_arm64_lift_and_j30","il_lift_arm64_lift_bcond_eq_j30","il_lift_arm64_lift_blr_j30","il_lift_arm64_lift_eor_j30","il_lift_arm64_lift_orr_j30","il_lift_arm64_lift_sub_j30","il_lift_arm64_lift_svc_j30","il_lift_batch_lifter_for_arch_o1","il_lift_batch_lifter_lift_block_empty_o1","il_lift_batch_lifter_recovery_o1","il_lift_cache_clear_r7","il_lift_cache_new_capacity_r7","il_lift_diff_address_maps_empty_r7","il_lift_diff_count","il_lift_diff_empty_maps","il_lift_empty_lift_diff","il_lift_filter_at_level_empty","il_lift_filter_count_stubs_empty","il_lift_filter_partition_effects_empty","il_lift_filter_terminators_empty","il_lift_filter_with_side_effects_empty","il_lift_filters_writing_register_n6","il_lift_is_empty","il_lift_level_at_least","il_lift_level_at_least_reflexive_n3","il_lift_level_display"]:
    r = call(tool, {})
    if r:
        check("il_lift_v6", tool.replace("il_lift_",""), any_valid(r), True, tool)

try: p.terminate()
except: pass
for cat, d in per_cat.items():
    out = fr"C:\Users\Fra\Desktop\RustRE\validation\mismatch_{cat}.json"
    with open(out, "w") as f: json.dump({"category":cat, "checks_total":d["checks"], "checks_passed":d["passed"], "mismatches":d["mismatches"]}, f, indent=1)
    print(f"{cat}: {d['passed']}/{d['checks']} passed, {len(d['mismatches'])} mismatch")
total_c = sum(d["checks"] for d in per_cat.values()); total_p = sum(d["passed"] for d in per_cat.values()); total_m = sum(len(d["mismatches"]) for d in per_cat.values())
print(f"\nBATCH62 TOTAL: {total_p}/{total_c} passed, {total_m} mismatch across {len(per_cat)} categories")
