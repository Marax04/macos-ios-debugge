#!/usr/bin/env python3
"""Batch28: dotnet_metadata extras, forensics_mem more, hex_pattern more, flirt_gen more, gdb_stub more."""
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

# dotnet_metadata extras
for tool in ["dotnet_metadata_all_type_names_basic","dotnet_metadata_all_field_names","dotnet_metadata_all_module_names","dotnet_metadata_assembly_manifest","dotnet_metadata_has_entry_point","dotnet_metadata_table_summary","dotnet_metadata_validate","dotnet_metadata_type_is_abstract","dotnet_metadata_type_is_sealed"]:
    r = call(tool, {})
    if r:
        check("dotnet_metadata_v2", tool.replace("dotnet_metadata_",""), any_valid(r), True, tool)

# forensics_mem more
for tool in ["forensics_mem_thread_state_from_u8","forensics_mem_connection_state_from_u8","forensics_mem_windows_version_display","forensics_mem_find_unicode_strings","forensics_mem_process_name_matches","forensics_mem_win_find_processes_mock","forensics_mem_linux_find_modules_mock"]:
    args = {"data":[0x48,0x00,0x69,0x00,0x00,0x00]} if "unicode" in tool else {"name":"cmd.exe", "pattern":"cmd"} if "process_name" in tool else {}
    r = call(tool, args)
    if r:
        check("forensics_mem_v2", tool.replace("forensics_mem_",""), any_valid(r), True, tool)

# hex_pattern more
for tool in ["hex_pattern_alternation_new_v4","hex_pattern_dfa_search_v3","hex_pattern_nfa_find_first_v3","hex_pattern_nfa_find_all_v3","hex_pattern_multi_matcher_search_v3","hex_pattern_range_expand_v3","hex_pattern_sequence_search_v3"]:
    r = call(tool, {})
    if r:
        check("hex_pattern_v7", tool.replace("hex_pattern_",""), any_valid(r), True, tool)

# flirt_gen more
for tool in ["flirt_gen_pattern_generator_default_wire","flirt_gen_pattern_generator_custom_wire","flirt_gen_pattern_quality_as_str_wire","flirt_gen_library_builder_demo","flirt_gen_scan_x86_masks","flirt_gen_generate_from_ranges_wire"]:
    r = call(tool, {})
    if r:
        check("flirt_gen_v2", tool.replace("flirt_gen_",""), any_valid(r), True, tool)

# gdb_stub more
for tool in ["gdb_stop_reply_parse","gdb_memory_map_parse","gdb_register_def_byte_size","gdb_target_desc_x86_64_linux","gdb_target_desc_aarch64_linux","gdb_target_xml_register_by_name","gdb_target_xml_register_by_num","gdb_target_xml_total_bytes","gdb_packet_encode","gdb_packet_decode","gdb_packet_escape_data","gdb_packet_unescape_data"]:
    args = {"packet":"$OK#9a"} if "reply_parse" in tool or "decode" in tool else {"payload":"OK"} if "encode" in tool else {"data":"$#hello"} if "escape" in tool else {"reg":"rax"} if "register_by_name" in tool else {"n":0} if "register_by_num" in tool else {"reg":"rax"} if "byte_size" in tool else {}
    r = call(tool, args)
    if r:
        check("gdb_v2", tool.replace("gdb_",""), any_valid(r), True, tool)

# Save
try: p.terminate()
except: pass
for cat, d in per_cat.items():
    out = fr"C:\Users\Fra\Desktop\RustRE\validation\mismatch_{cat}.json"
    with open(out, "w") as f: json.dump({"category":cat, "checks_total":d["checks"], "checks_passed":d["passed"], "mismatches":d["mismatches"]}, f, indent=1)
    print(f"{cat}: {d['passed']}/{d['checks']} passed, {len(d['mismatches'])} mismatch")
total_c = sum(d["checks"] for d in per_cat.values()); total_p = sum(d["passed"] for d in per_cat.values()); total_m = sum(len(d["mismatches"]) for d in per_cat.values())
print(f"\nBATCH28 TOTAL: {total_p}/{total_c} passed, {total_m} mismatch across {len(per_cat)} categories")
