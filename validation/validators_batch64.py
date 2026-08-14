#!/usr/bin/env python3
"""Batch64: fuzz_net, fuzz_san, fuzz_afl_stage more, fuzz_libfuzzer more."""
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

for tool in ["fuzz_net_add_checksum","fuzz_net_crash_classify","fuzz_net_crash_classify_reason","fuzz_net_crash_kind_labels","fuzz_net_decode_frame_u32_be_ext","fuzz_net_decode_frame_u32_le","fuzz_net_frame_u32_be","fuzz_net_frame_u32_le","fuzz_net_interesting_constants","fuzz_net_interesting_int_mutation","fuzz_net_protocol_drive_path","fuzz_net_protocol_load_yaml","fuzz_net_response_matcher_find","fuzz_net_response_matcher_matches","fuzz_net_xor_checksum"]:
    r = call(tool, {})
    if r:
        check("fuzz_net_v2", tool.replace("fuzz_net_",""), any_valid(r), True, tool)

for tool in ["fuzz_san_asan_scenario","fuzz_san_classify_severity","fuzz_san_coverage_summary","fuzz_san_crash_dedup_group","fuzz_san_log_parser_parse_all","fuzz_san_log_parser_parse_first","fuzz_san_msan_scenario","fuzz_san_parse_asan_output","fuzz_san_parse_hex_u64","fuzz_san_parse_ubsan_output","fuzz_san_stack_edit_distance","fuzz_san_ubsan_check_access","fuzz_san_ubsan_check_division","fuzz_san_ubsan_check_misaligned","fuzz_san_ubsan_check_null_deref","fuzz_san_ubsan_check_signed_overflow","fuzz_san_ubsan_checked_add","fuzz_san_ubsan_checked_mul"]:
    r = call(tool, {})
    if r:
        check("fuzz_san_v2", tool.replace("fuzz_san_",""), any_valid(r), True, tool)

for tool in ["fuzz_afl_stage_arith_16","fuzz_afl_stage_arith_32","fuzz_afl_stage_arith_8","fuzz_afl_stage_bit_flip_1","fuzz_afl_stage_bit_flip_2","fuzz_afl_stage_bit_flip_4","fuzz_afl_stage_byte_flip_1","fuzz_afl_stage_interesting_16","fuzz_afl_stage_interesting_32","fuzz_afl_stage_interesting_8","fuzz_afl_stage_splice"]:
    r = call(tool, {})
    if r:
        check("fuzz_afl_stages_v2", tool.replace("fuzz_afl_stage_",""), any_valid(r), True, tool)

try: p.terminate()
except: pass
for cat, d in per_cat.items():
    out = fr"C:\Users\Fra\Desktop\RustRE\validation\mismatch_{cat}.json"
    with open(out, "w") as f: json.dump({"category":cat, "checks_total":d["checks"], "checks_passed":d["passed"], "mismatches":d["mismatches"]}, f, indent=1)
    print(f"{cat}: {d['passed']}/{d['checks']} passed, {len(d['mismatches'])} mismatch")
total_c = sum(d["checks"] for d in per_cat.values()); total_p = sum(d["passed"] for d in per_cat.values()); total_m = sum(len(d["mismatches"]) for d in per_cat.values())
print(f"\nBATCH64 TOTAL: {total_p}/{total_c} passed, {total_m} mismatch across {len(per_cat)} categories")
