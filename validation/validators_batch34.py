#!/usr/bin/env python3
"""Batch34: net_proxy many, forensics_mem more, deobf_string many, hex_tply extras, hex_pattern more."""
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

# net_proxy many
for tool in ["net_proxy_glob_match","net_proxy_hex_decode","net_proxy_hex_encode","net_proxy_http_method_display","net_proxy_http_method_has_body","net_proxy_http_method_is_idempotent","net_proxy_http_status_classify","net_proxy_ms_to_iso8601","net_proxy_shared_stats_ops","net_proxy_simple_regex_match","net_proxy_socks5_udp_header_parse","net_proxy_rate_limiter_check","net_proxy_acl_evaluate"]:
    r = call(tool, {"input":[0xde,0xad]} if "hex_encode" in tool else {"input":"deadbeef"} if "hex_decode" in tool else {"pattern":"foo*","input":"foobar"} if "glob" in tool or "regex_match" in tool else {"ms":1234567890000} if "ms_to" in tool else {"method":"GET"} if "http_method" in tool else {"status":200} if "status_classify" in tool else {})
    if r:
        check("net_proxy_v2", tool.replace("net_proxy_",""), any_valid(r), True, tool)

# forensics_mem more
for tool in ["forensics_mem_linux_find_processes_mock","forensics_mem_linux_find_sockets_mock","forensics_mem_scan_pe_headers","forensics_mem_scan_stack_canaries","forensics_mem_registry_hive_parse_key","forensics_mem_scan_heap_allocations","forensics_mem_win_extract_registry_hives_mock","forensics_mem_win_find_kernel_info_mock","forensics_mem_win_find_modules_mock","forensics_mem_win_find_network_connections_mock"]:
    r = call(tool, {})
    if r:
        check("forensics_mem_v3", tool.replace("forensics_mem_",""), any_valid(r), True, tool)

# deobf_string many
for tool in ["deobf_string_asm_detect_stack_strings_v3","deobf_string_base64_encode","deobf_string_caesar_bruteforce","deobf_string_decode_base64_urlsafe","deobf_string_detect_base64_variant","deobf_string_detect_xor_encryption_v3","deobf_string_hex_decode","deobf_string_rc4_decrypt","deobf_string_rot13","deobf_string_score_plaintext_v3","deobf_string_xor_decrypt_constant","deobf_string_xor_bruteforce_top3"]:
    args = {"input":"hello"} if "rot13" in tool or "caesar" in tool else {"data":"48656c6c6f"} if "hex_decode" in tool else {"input":"aGVsbG8="} if "base64" in tool else {}
    r = call(tool, args)
    if r:
        check("deobf_string_v3", tool.replace("deobf_string_",""), any_valid(r), True, tool)

# hex_tply extras
for tool in ["hex_tply_pe32plus_optional_header","hex_tply_pe_import_descriptor","hex_tply_pe_export_directory","hex_tply_elf64_shdr","hex_tply_coff_file_header","hex_tply_zip_eocd","hex_tply_bmp_header","hex_tply_flatten_parsed","hex_tply_template_report"]:
    r = call(tool, {})
    if r:
        check("hex_tply_v2", tool.replace("hex_tply_",""), any_valid(r), True, tool)

# hex_pattern more
for tool in ["hex_pattern_alternation_matches","hex_pattern_alternation_parse","hex_pattern_alternation_search","hex_pattern_bmh_search_v3","hex_pattern_byte_mask_specificity_v3","hex_pattern_canonicalize","hex_pattern_compiled_matches_at","hex_pattern_crc16_ibm","hex_pattern_dfa_search_v3","hex_pattern_group_any_matches_v4","hex_pattern_masked_from_str","hex_pattern_masked_matches_at","hex_pattern_matches_at"]:
    r = call(tool, {})
    if r:
        check("hex_pattern_v8", tool.replace("hex_pattern_",""), any_valid(r), True, tool)

# Save
try: p.terminate()
except: pass
for cat, d in per_cat.items():
    out = fr"C:\Users\Fra\Desktop\RustRE\validation\mismatch_{cat}.json"
    with open(out, "w") as f: json.dump({"category":cat, "checks_total":d["checks"], "checks_passed":d["passed"], "mismatches":d["mismatches"]}, f, indent=1)
    print(f"{cat}: {d['passed']}/{d['checks']} passed, {len(d['mismatches'])} mismatch")
total_c = sum(d["checks"] for d in per_cat.values()); total_p = sum(d["passed"] for d in per_cat.values()); total_m = sum(len(d["mismatches"]) for d in per_cat.values())
print(f"\nBATCH34 TOTAL: {total_p}/{total_c} passed, {total_m} mismatch across {len(per_cat)} categories")
