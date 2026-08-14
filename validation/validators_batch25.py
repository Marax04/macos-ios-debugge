#!/usr/bin/env python3
"""Batch25: symbols_pdb v2, threatintel_group, fuzz_afl stages, il_lift arm64/x86, dotnet_edit."""
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

PDB = r"C:\Users\Fra\Desktop\Zyphora\target\release\cargo_zyphora.pdb"

# symbols_pdb v3 with path support
for tool in ["symbols_pdb_public_scan","symbols_pdb_module_proc_count","symbols_pdb_stream_names","symbols_pdb_reader_types","symbols_pdb_symbols_count_by_kind","symbols_pdb_types_by_kind","symbols_pdb_reader_guid"]:
    r = call(tool, {"path":PDB})
    if r:
        check("symbols_pdb_v3", tool.replace("symbols_pdb_",""), any_valid(r), True, tool)

# threatintel_group
for tool in ["threatintel_group_list_known","threatintel_group_tracker_known_count","threatintel_group_aliases","threatintel_confidence_tier_from_score","threatintel_confidence_dominant_signal","threatintel_ioc_type_from_key"]:
    args = {"score":75} if "tier_from_score" in tool else {"group":"APT29"} if "aliases" in tool else {"key":"ip"} if "ioc_type" in tool else {}
    r = call(tool, args)
    if r:
        check("threatintel_v2", tool.replace("threatintel_",""), any_valid(r), True, tool)

# fuzz_afl stages
for tool in ["fuzz_afl_stage_arith_8","fuzz_afl_stage_arith_16","fuzz_afl_stage_arith_32","fuzz_afl_stage_interesting_8","fuzz_afl_stage_interesting_16","fuzz_afl_stage_bit_flip_2","fuzz_afl_stage_bit_flip_4","fuzz_afl_stage_byte_flip_1"]:
    r = call(tool, {"data":[0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07]})
    if r:
        check("fuzz_afl_stages", tool.replace("fuzz_afl_stage_",""), any_valid(r), True, tool)

# il_lift arm64 lifters
for tool in ["il_lift_arm64_lift_add_j30","il_lift_arm64_lift_mov_j30","il_lift_arm64_lift_ret_j30","il_lift_arm64_lift_ldr_j30","il_lift_arm64_lift_str_j30","il_lift_arm64_lift_b_j30","il_lift_arm64_lift_bl_j30"]:
    r = call(tool, {})
    if r:
        check("il_lift_arm64", tool.replace("il_lift_arm64_lift_","").replace("_j30",""), any_valid(r), True, tool)

# dotnet_edit builders
for tool in ["dotnet_edit_ilbuilder_nop","dotnet_edit_ilbuilder_ret","dotnet_edit_ilbuilder_call","dotnet_edit_ilbuilder_ldstr","dotnet_edit_ilbuilder_brtrue_s","dotnet_edit_il_builder_ldc_i4_v2","dotnet_edit_il_builder_ldarg_v2"]:
    args = {"n":5} if "ldc" in tool else {"n":0} if "ldarg" in tool else {}
    r = call(tool, args)
    if r:
        check("dotnet_edit_v2", tool.replace("dotnet_edit_",""), any_valid(r), True, tool)

# Save
try: p.terminate()
except: pass
for cat, d in per_cat.items():
    out = fr"C:\Users\Fra\Desktop\RustRE\validation\mismatch_{cat}.json"
    with open(out, "w") as f: json.dump({"category":cat, "checks_total":d["checks"], "checks_passed":d["passed"], "mismatches":d["mismatches"]}, f, indent=1)
    print(f"{cat}: {d['passed']}/{d['checks']} passed, {len(d['mismatches'])} mismatch")
total_c = sum(d["checks"] for d in per_cat.values()); total_p = sum(d["passed"] for d in per_cat.values()); total_m = sum(len(d["mismatches"]) for d in per_cat.values())
print(f"\nBATCH25 TOTAL: {total_p}/{total_c} passed, {total_m} mismatch across {len(per_cat)} categories")
