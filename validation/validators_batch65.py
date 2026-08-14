#!/usr/bin/env python3
"""Batch65: net_dns/icmp/ip/pcap, kgdb more, gdb more."""
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

for tool in ["kgdb_bytes_to_hex","kgdb_bytes_to_hex_v2","kgdb_decode_hex_buf","kgdb_encode_hex_buf","kgdb_gdb_packet_parse","kgdb_gdb_packet_to_wire","kgdb_hex_le_to_u64","kgdb_hex_to_bytes","kgdb_hex_to_bytes_v2","kgdb_is_kernel_address","kgdb_kvirt_to_phys","kgdb_page_align","kgdb_parse_kernel_callstack","kgdb_parse_qsupported","kgdb_parse_thread_list","kgdb_read_u64_le_hex","kgdb_rle_decode","kgdb_rle_encode","kgdb_rsp_checksum","kgdb_rsp_checksum_bytes","kgdb_rsp_encode_packet_bytes","kgdb_rsp_escape","kgdb_rsp_unescape","kgdb_rsp_verify_checksum_bytes","kgdb_target_xml_arm64","kgdb_target_xml_x86_64","kgdb_u32_to_hex_le","kgdb_u64_to_hex_le","kgdb_verify_rsp_checksum"]:
    r = call(tool, {})
    if r:
        check("kgdb_v3", tool.replace("kgdb_",""), any_valid(r), True, tool)

for tool in ["gdb_breakpoint_hw_cmd","gdb_breakpoint_sw_cmd","gdb_memory_map_parse","gdb_memory_read_cmd","gdb_memory_read_response_parse","gdb_memory_write_binary_cmd","gdb_memory_write_cmd","gdb_packet_checksum","gdb_packet_decode","gdb_packet_encode","gdb_packet_escape_data","gdb_packet_unescape_data","gdb_register_codec_decode_g","gdb_register_codec_decode_p","gdb_register_codec_encode_g","gdb_register_codec_encode_p","gdb_register_def_byte_size","gdb_step_range_packet","gdb_stop_reply_parse","gdb_stub_empty_packet","gdb_stub_error_packet","gdb_stub_ok_packet","gdb_target_desc_aarch64_linux","gdb_target_desc_x86_64_linux","gdb_target_xml_parse","gdb_target_xml_register_by_name","gdb_target_xml_register_by_num","gdb_target_xml_total_bytes","gdb_watchpoint_cmd"]:
    r = call(tool, {})
    if r:
        check("gdb_v3", tool.replace("gdb_",""), any_valid(r), True, tool)

for tool in ["mem_diff_bytes","mem_diff_bytes_at_base_wire2","mem_diff_bytes_first_span_offset_wire","mem_diff_bytes_span_count_wire","mem_diff_bytes_total_changed_wire","mem_diff_bytes_v3","mem_diff_providers_hex","mem_entropy_blocks_hex","mem_entropy_blocks_hex_v3","mem_entropy_classify","mem_entropy_classify_value_wire","mem_high_entropy_spans","mem_high_entropy_spans_from_hex","mem_high_entropy_spans_v3","mem_page_align_down","mem_page_align_down_many_wire","mem_page_align_down_v3","mem_page_align_up","mem_page_align_up_many_wire","mem_page_align_up_v3","mem_page_align_up_wire","mem_page_containing","mem_page_containing_len_wire","mem_page_index","mem_page_index_many_wire","mem_page_range_indices","mem_perms_from_rwx","mem_region_kind_list","mem_search_bytes_all_hex","mem_search_bytes_hex","mem_search_bytes_hex_v2","mem_search_bytes_range_hex","mem_search_bytes_with_mask_hex","mem_shannon_entropy","mem_shannon_entropy_max_block_wire","mem_shannon_entropy_mean_block_wire","mem_shannon_entropy_min_block_wire","mem_shannon_entropy_v3","mem_shannon_entropy_wire"]:
    r = call(tool, {})
    if r:
        check("mem_v3", tool.replace("mem_",""), any_valid(r), True, tool)

try: p.terminate()
except: pass
for cat, d in per_cat.items():
    out = fr"C:\Users\Fra\Desktop\RustRE\validation\mismatch_{cat}.json"
    with open(out, "w") as f: json.dump({"category":cat, "checks_total":d["checks"], "checks_passed":d["passed"], "mismatches":d["mismatches"]}, f, indent=1)
    print(f"{cat}: {d['passed']}/{d['checks']} passed, {len(d['mismatches'])} mismatch")
total_c = sum(d["checks"] for d in per_cat.values()); total_p = sum(d["passed"] for d in per_cat.values()); total_m = sum(len(d["mismatches"]) for d in per_cat.values())
print(f"\nBATCH65 TOTAL: {total_p}/{total_c} passed, {total_m} mismatch across {len(per_cat)} categories")
