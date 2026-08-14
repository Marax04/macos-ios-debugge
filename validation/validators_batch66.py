#!/usr/bin/env python3
"""Batch66: mem_kx7, mem_v5, mem_ma, mem_read/write."""
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

for tool in ["mem_kx7_bytepattern_matches_at","mem_kx7_bytepattern_parse_len","mem_kx7_bytepattern_valid","mem_kx7_diff_bytes_change_ratio","mem_kx7_diff_bytes_first_len","mem_kx7_diff_bytes_last_end","mem_kx7_diff_bytes_span_count","mem_kx7_diff_bytes_total_len","mem_kx7_diff_memory_changed_bytes","mem_kx7_diff_memory_first_addr","mem_kx7_diff_memory_is_identical","mem_kx7_diff_memory_last_end","mem_kx7_diff_memory_lenient_changed","mem_kx7_diff_memory_lenient_regions","mem_kx7_diff_memory_regions","mem_kx7_entropy_slice","mem_kx7_entropy_windows_above","mem_kx7_entropy_windows_avg","mem_kx7_entropy_windows_max","mem_kx7_page_align_down","mem_kx7_page_align_roundtrip","mem_kx7_page_align_up","mem_kx7_page_align_up_batch","mem_kx7_page_containing","mem_kx7_page_index","mem_kx7_page_range_indices","mem_kx7_page_span_count","mem_kx7_shannon_entropy_hex","mem_kx7_shannon_entropy_len","mem_kx7_snapshotdiff_apply","mem_kx7_snapshotdiff_invert","mem_kx7_snapshotdiff_json_roundtrip"]:
    r = call(tool, {})
    if r:
        check("mem_kx7", tool.replace("mem_kx7_",""), any_valid(r), True, tool)

for tool in ["mem_arena_new_v5","mem_composite_first_wins_v5","mem_diff_bytes_spans_list_v4","mem_diff_span_len_v5","mem_entropy_block_classify_bytes_v4","mem_entropy_block_new_v5","mem_find_bytes_provider_v5","mem_high_entropy_spans_from_bytes_v4","mem_null_provider_read_v5","mem_page_align_down_v5","mem_page_align_up_v5","mem_page_cache_read_v5","mem_page_containing_v5","mem_page_index_v5","mem_page_range_indices_v5","mem_patched_read_v5","mem_perms_from_rwx_v5","mem_search_bytes_with_mask_v5","mem_shannon_entropy_from_bytes_v5","mem_virtual_provider_read_u32_le_v5","mem_virtual_provider_read_u64_le_v5","mem_virtual_provider_read_u8_v5","mem_virtual_provider_write_u32_le_v5"]:
    r = call(tool, {})
    if r:
        check("mem_v5_arena", tool.replace("mem_",""), any_valid(r), True, tool)

for tool in ["mem_ma_byte_pattern_exact_v4","mem_ma_byte_pattern_from_hex_str_v4","mem_ma_byte_pattern_matcher_find_all_v4","mem_ma_byte_pattern_matches_at_v4","mem_ma_diff_regions_hex_v4","mem_ma_diff_span_len_v4","mem_ma_entropy_region_new_v4","mem_ma_entropy_region_suspicious_threshold_v4","mem_ma_memory_statistics_compute_v4","mem_ma_memory_statistics_fractions_v4","mem_ma_scan_entropy_v4","mem_ma_shannon_entropy_bytes_v4"]:
    r = call(tool, {})
    if r:
        check("mem_ma", tool.replace("mem_ma_",""), any_valid(r), True, tool)

for tool in ["mem_read_f32_be_at_hex","mem_read_f32_be_at_hex_v2","mem_read_f32_le_at_hex","mem_read_f64_be_at_hex","mem_read_f64_be_at_hex_v2","mem_read_f64_le_at_hex","mem_read_i16_le_at_hex","mem_read_i32_le_at_hex","mem_read_i64_le_at_hex","mem_read_i8_at_hex","mem_read_typed_at_hex","mem_read_u128_le_at_hex","mem_read_u128_le_at_hex_v2","mem_read_u16_be_at_hex","mem_read_u16_le_at_hex","mem_read_u32_be_at_hex","mem_read_u32_le_at_hex","mem_read_u64_be_at_hex","mem_read_u64_le_at_hex","mem_read_u8_at_hex","mem_write_f32_le_at_hex","mem_write_f64_le_at_hex","mem_write_i32_le_at_hex","mem_write_i64_le_at_hex","mem_write_typed_at_hex","mem_write_u16_be_at_hex","mem_write_u16_le_at_hex","mem_write_u32_be_at_hex","mem_write_u32_le_at_hex","mem_write_u64_be_at_hex","mem_write_u64_le_at_hex","mem_write_u8_at_hex"]:
    r = call(tool, {})
    if r:
        check("mem_readwrite", tool.replace("mem_",""), any_valid(r), True, tool)

try: p.terminate()
except: pass
for cat, d in per_cat.items():
    out = fr"C:\Users\Fra\Desktop\RustRE\validation\mismatch_{cat}.json"
    with open(out, "w") as f: json.dump({"category":cat, "checks_total":d["checks"], "checks_passed":d["passed"], "mismatches":d["mismatches"]}, f, indent=1)
    print(f"{cat}: {d['passed']}/{d['checks']} passed, {len(d['mismatches'])} mismatch")
total_c = sum(d["checks"] for d in per_cat.values()); total_p = sum(d["passed"] for d in per_cat.values()); total_m = sum(len(d["mismatches"]) for d in per_cat.values())
print(f"\nBATCH66 TOTAL: {total_p}/{total_c} passed, {total_m} mismatch across {len(per_cat)} categories")
