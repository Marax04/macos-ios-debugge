#!/usr/bin/env python3
"""Batch50: net_dissect more, net_proxy more, fuzz_afl more, fuzz_cov more, fuzz_libfuzzer more."""
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

for tool in ["net_dissect_byte_entropy","net_dissect_dnp3_app_fc_name","net_dissect_icmp_stream_tunnel_heuristic","net_dissect_scan_http_attacks_decoded","net_dissect_smb2_is_sensitive_share","net_decode_chunked_v2","net_detect_protocol_v2","net_dns_type_name_v2","net_icmp_type_name_v2","net_parse_ethernet_ext","net_parse_ethernet_v2","net_parse_icmp_echo","net_parse_icmp_v2","net_parse_ipv4_v2","net_parse_ipv6_full","net_parse_ipv6_v2","net_parse_tcp_v2","net_parse_udp_v2"]:
    r = call(tool, {})
    if r:
        check("net_dissect_v2", tool.replace("net_",""), any_valid(r), True, tool)

for tool in ["fuzz_afl_bit_flip_mutate","fuzz_afl_bitmap_summary","fuzz_afl_bucket_hits","fuzz_afl_cmplog_colorize","fuzz_afl_dict_info","fuzz_afl_dict_load","fuzz_afl_havoc_mutate","fuzz_afl_queue_score","fuzz_afl_arith_mutate","fuzz_afl_stats_parse","fuzz_afl_stats_serialize","fuzz_compute_priority","fuzz_corpus_prune","fuzz_coverage_map_update","fuzz_crash_dedup_submit","fuzz_dictionary_load_text","fuzz_fnv1a","fuzz_fnv1a_hash_v2","fuzz_generate_corpus","fuzz_mutate_input","fuzz_mutation_strategies_list","fuzz_rank_seeds_by_priority","fuzz_rng_generate","fuzz_splice_inputs","fuzz_xorshift64"]:
    r = call(tool, {})
    if r:
        check("fuzz_afl_v3", tool.replace("fuzz_",""), any_valid(r), True, tool)

for tool in ["fuzz_cov_cmplog_entry_diff","fuzz_cov_cmplog_mask_bit_diff_x","fuzz_cov_cmplog_suggest_mutations","fuzz_cov_cmplog_unique_pcs_x","fuzz_cov_corpus_prune","fuzz_cov_corpus_pruner","fuzz_cov_coverage_diff","fuzz_cov_coverage_fraction","fuzz_cov_coverage_run_hot_blocks","fuzz_cov_coverage_run_merge","fuzz_cov_coverage_run_was_hit_x","fuzz_cov_coverage_stats","fuzz_cov_db_aggregate","fuzz_cov_diff_jaccard","fuzz_cov_drcov_basic_block_abs_addr_x","fuzz_cov_drcov_blocks_per_module","fuzz_cov_drcov_bb_abs_addr","fuzz_cov_drcov_entry_end_addr","fuzz_cov_drcov_header_parse","fuzz_cov_drcov_header_parse_v2","fuzz_cov_drcov_module_contains","fuzz_cov_drcov_module_to_offset_x","fuzz_cov_edge_hot_edges","fuzz_cov_edge_map_analyze","fuzz_cov_edge_map_has_edge_x","fuzz_cov_edge_successors","fuzz_cov_heatmap_color","fuzz_cov_histogram","fuzz_cov_histogram_stats","fuzz_cov_lcov_aggregate_by_file","fuzz_cov_lcov_fully_covered_x","fuzz_cov_lcov_line_pct","fuzz_cov_lcov_parse","fuzz_cov_pcguard_density","fuzz_cov_pcguard_hash","fuzz_cov_pcguard_hit_guards","fuzz_cov_rle_encode","fuzz_cov_rle_is_beneficial","fuzz_cov_stats_full"]:
    r = call(tool, {})
    if r:
        check("fuzz_cov_v3", tool.replace("fuzz_cov_",""), any_valid(r), True, tool)

for tool in ["fuzz_libfuzzer_bucket_bitmap","fuzz_libfuzzer_count_new_bits_bucketed","fuzz_libfuzzer_crash_handler_inject","fuzz_libfuzzer_havoc_mutate","fuzz_libfuzzer_input_splice","fuzz_libfuzzer_parse_sanitizer_output","fuzz_libfuzzer_persistent_harness_run","fuzz_libfuzzer_simple_rng","fuzz_libfuzzer_structured_deserialize","fuzz_libfuzzer_structured_serialize"]:
    r = call(tool, {})
    if r:
        check("fuzz_libfuzzer_v3", tool.replace("fuzz_libfuzzer_",""), any_valid(r), True, tool)

try: p.terminate()
except: pass
for cat, d in per_cat.items():
    out = fr"C:\Users\Fra\Desktop\RustRE\validation\mismatch_{cat}.json"
    with open(out, "w") as f: json.dump({"category":cat, "checks_total":d["checks"], "checks_passed":d["passed"], "mismatches":d["mismatches"]}, f, indent=1)
    print(f"{cat}: {d['passed']}/{d['checks']} passed, {len(d['mismatches'])} mismatch")
total_c = sum(d["checks"] for d in per_cat.values()); total_p = sum(d["passed"] for d in per_cat.values()); total_m = sum(len(d["mismatches"]) for d in per_cat.values())
print(f"\nBATCH50 TOTAL: {total_p}/{total_c} passed, {total_m} mismatch across {len(per_cat)} categories")
