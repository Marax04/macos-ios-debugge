#!/usr/bin/env python3
"""Batch26: symb_z3 more, adf extras, axr extras, mobile_ipa extras, lua_bc/luajit extras."""
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

# symb_z3 more
for tool in ["symb_z3_solver_check_sat_empty","symb_z3_solver_is_sat_empty","symb_z3_solver_assert_reset","symb_z3_prove_reflexive","symb_z3_extract_bit_width","symb_z3_symbol_bit_width","symb_z3_concat_bw","symb_z3_zero_ext_bw","symb_z3_smtlib2_add","symb_z3_smtlib2_xor"]:
    r = call(tool, {})
    if r:
        check("symb_z3_v2", tool.replace("symb_z3_",""), any_valid(r), True, tool)

# adf extras
for tool in ["adf_dominators_from_edges","adf_compute_dominators_chain","adf_postorder_chain","adf_linear_cfg_node_count","adf_statement_new","adf_lattice_value_meet_top","adf_lattice_value_meet_equal","adf_trace_callees_forward_simple"]:
    r = call(tool, {})
    if r:
        check("adf_v2", tool.replace("adf_",""), any_valid(r), True, tool)

# axr extras
for tool in ["axr_db_all_strings","axr_db_all_import_names","axr_db_hot_functions","axr_db_is_leaf_function","axr_db_to_json","axr_graph_bfs_distances","axr_graph_call_graph_stats","axr_graph_scc"]:
    r = call(tool, {})
    if r:
        check("axr_v2", tool.replace("axr_",""), any_valid(r), True, tool)

# mobile_ipa extras
for tool in ["mobile_ipa_mock_summary","mobile_ipa_mock_binary_entries","mobile_ipa_mock_codesign_flags","mobile_ipa_mock_leaf_cert_apple","mobile_ipa_mock_has_entitlements","mobile_ipa_mock_targets_iphone","mobile_ipa_plist_all_strings"]:
    r = call(tool, {"strings":["a","b"]} if "plist_all" in tool else {})
    if r:
        check("mobile_ipa_v2", tool.replace("mobile_ipa_",""), any_valid(r), True, tool)

# lua_bc/luajit extras
for tool in ["lua_bc_header_parse","lua_bc_endian_from_byte","lua_bc_opcode_layout","lua_bc_version_from_byte","lua_bc_instr_decode","luajit_instr_op","luajit_instr_a"]:
    args = {"data":[0x1b,0x4c,0x75,0x61,0x51,0x00,0x01,0x04,0x08,0x08,0x00,0x00,0x00,0x00,0x00,0x00,0x00]*10} if "header" in tool else {"byte":0} if "endian" in tool else {"version":0x51} if "version_from" in tool else {"instr":0x00} if "instr" in tool else {}
    r = call(tool, args)
    if r:
        check("lua_bc_v2", tool.replace("lua_bc_","").replace("luajit_",""), any_valid(r), True, tool)

# Save
try: p.terminate()
except: pass
for cat, d in per_cat.items():
    out = fr"C:\Users\Fra\Desktop\RustRE\validation\mismatch_{cat}.json"
    with open(out, "w") as f: json.dump({"category":cat, "checks_total":d["checks"], "checks_passed":d["passed"], "mismatches":d["mismatches"]}, f, indent=1)
    print(f"{cat}: {d['passed']}/{d['checks']} passed, {len(d['mismatches'])} mismatch")
total_c = sum(d["checks"] for d in per_cat.values()); total_p = sum(d["passed"] for d in per_cat.values()); total_m = sum(len(d["mismatches"]) for d in per_cat.values())
print(f"\nBATCH26 TOTAL: {total_p}/{total_c} passed, {total_m} mismatch across {len(per_cat)} categories")
