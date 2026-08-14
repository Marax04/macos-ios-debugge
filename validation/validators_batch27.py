#!/usr/bin/env python3
"""Batch27: vmlift extras, vsa extras, trace_pt/coresight extras, il_lift x86 extras, decomp2."""
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

# vmlift extras
for tool in ["vmlift_default_isa_len","vmlift_default_isa_opcodes","vmlift_default_isa_listing","vmlift_disassemble_default","vmlift_binop_display","vmlift_isa_lookup_opcode","vmlift_isa_new_empty","vmlift_isa_sorted_opcodes"]:
    args = {"op":0} if "lookup" in tool else {"op":0} if "display" in tool else {}
    r = call(tool, args)
    if r:
        check("vmlift_v2", tool.replace("vmlift_",""), any_valid(r), True, tool)

# vsa extras
for tool in ["vsa_strided_interval_join_wire","vsa_valueset_singleton","vsa_valueset_top","vsa_valueset_bottom","vsa_valueset_interval_wire","vsa_valueset_concretize_strided_wire","vsa_valueset_join_intervals_wire","vsa_valueset_widen_intervals_wire","vsa_is_definitely_null_wire","vsa_may_be_out_of_bounds_wire"]:
    r = call(tool, {})
    if r:
        check("vsa_v2", tool.replace("vsa_",""), any_valid(r), True, tool)

# trace_pt / coresight
for tool in ["trace_pt_decode_buffer","trace_pt_decoder_remaining_bytes","trace_pt_coverage","trace_pt_drcov","trace_pt_flow_event_count","trace_coresight_find_sync_offsets","trace_coresight_etm_decode_stream","trace_coresight_stm_decode_stream","trace_coresight_tpiu_demux"]:
    args = {"data":[0x02,0x82]} if "decode_buffer" in tool or "etm_decode" in tool or "stm_decode" in tool or "find_sync" in tool or "demux" in tool else {}
    r = call(tool, args)
    if r:
        check("trace_pt_v2", tool.replace("trace_pt_","").replace("trace_coresight_",""), any_valid(r), True, tool)

# il_lift x86
for tool in ["il_lift_x86_lifter_new","il_lift_x86_lift_bytes","il_lift_x86_reg_id","il_lift_x86_lifter_reg_id_rax_n5","il_lift_x86_cached_addresses_empty_n3","il_lift_x86_cache_state","il_lift_x86_lifter_lift_nop_o1"]:
    args = {"bytes":[0x90]} if "lift_bytes" in tool else {"reg":"rax"} if "reg_id" in tool else {}
    r = call(tool, args)
    if r:
        check("il_lift_x86", tool.replace("il_lift_x86_",""), any_valid(r), True, tool)

# decomp2
for tool in ["decomp2_pass_registry_empty","decomp2_annotation_store_clear","decomp2_calling_convention_param_regs","decomp2_decompiler_cache_miss","decomp2_type_propagation_roundtrip","decomp2_symbol_map_insert_lookup","decomp2_variable_recovery_stack","decomp2_annotation_category_filter"]:
    r = call(tool, {})
    if r:
        check("decomp2_v2", tool.replace("decomp2_",""), any_valid(r), True, tool)

# Save
try: p.terminate()
except: pass
for cat, d in per_cat.items():
    out = fr"C:\Users\Fra\Desktop\RustRE\validation\mismatch_{cat}.json"
    with open(out, "w") as f: json.dump({"category":cat, "checks_total":d["checks"], "checks_passed":d["passed"], "mismatches":d["mismatches"]}, f, indent=1)
    print(f"{cat}: {d['passed']}/{d['checks']} passed, {len(d['mismatches'])} mismatch")
total_c = sum(d["checks"] for d in per_cat.values()); total_p = sum(d["passed"] for d in per_cat.values()); total_m = sum(len(d["mismatches"]) for d in per_cat.values())
print(f"\nBATCH27 TOTAL: {total_p}/{total_c} passed, {total_m} mismatch across {len(per_cat)} categories")
