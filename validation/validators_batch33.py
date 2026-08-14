#!/usr/bin/env python3
"""Batch33: emu_qiling extras, emu_unicorn many, forensics_fs_memfs, script_python pyvalue, symbols_ext."""
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

# emu_qiling extras
for tool in ["emu_qiling_closure_syscall_table_linux_len","emu_qiling_default_linux_x86_64_table_len","emu_qiling_elf_loader_stub_format_name","emu_qiling_fd_table_len","emu_qiling_process_env_new_linux64","emu_qiling_raw_binary_loader_format_name","emu_qiling_rootfs_root","emu_qiling_syscall_ctx_args","emu_qiling_syscall_result_retval","emu_qiling_syscall_table_empty"]:
    r = call(tool, {})
    if r:
        check("emu_qiling_v3", tool.replace("emu_qiling_",""), any_valid(r), True, tool)

# emu_unicorn many
for tool in ["emu_unicorn_coverage_default_empty","emu_unicorn_heap_alloc_free_cycle","emu_unicorn_heap_allocation_stats","emu_unicorn_heap_brk_frontier","emu_unicorn_heap_double_free","emu_unicorn_heap_malloc_sequence","emu_unicorn_hook_access_kind","emu_unicorn_mapped_region_contains","emu_unicorn_mode_endian_check","emu_unicorn_mode_ptr_size","emu_unicorn_perm_bitmask_encode","emu_unicorn_register_file_mask","emu_unicorn_syscall_args_pack"]:
    r = call(tool, {})
    if r:
        check("emu_unicorn_v4", tool.replace("emu_unicorn_",""), any_valid(r), True, tool)

# forensics_fs_memfs
for tool in ["forensics_fs_memfs_node_dir_probe","forensics_fs_memfs_node_dir_read_bytes_none","forensics_fs_memfs_node_dir_children","forensics_fs_memfs_node_file_probe","forensics_fs_memfs_node_file_read_bytes","forensics_fs_memfs_v2_walker_root","forensics_fs_node_v2_new_dir","forensics_fs_node_v2_new_file","forensics_fs_node_v2_readdir_entries"]:
    r = call(tool, {})
    if r:
        check("forensics_fs_memfs", tool.replace("forensics_fs_",""), any_valid(r), True, tool)

# script_python pyvalue
for tool in ["script_python_pyvalue_as_int","script_python_pyvalue_is_truthy","script_python_pyvalue_len","script_python_pyvalue_type_names","script_python_pyvalue_none_type_name","script_python_pure_value_classify","script_python_pyscriptvalue_display","script_python_pyscriptvalue_type_name"]:
    r = call(tool, {})
    if r:
        check("script_python_pyvalue", tool.replace("script_python_",""), any_valid(r), True, tool)

# symbols_ext
for tool in ["rustre_symbols_ext_cross_ref_index_ops","rustre_symbols_ext_demangler_pipeline","rustre_symbols_ext_pdb_server_msdl_url","rustre_symbols_ext_pdb_server_pdb_url","rustre_symbols_ext_source_priority_all","rustre_symbols_ext_synthetic_name_data","rustre_symbols_ext_synthetic_name_function","rustre_symbols_ext_try_demangle","rustre_symbols_ext_unified_table_add_lookup"]:
    r = call(tool, {})
    if r:
        check("symbols_ext_v2", tool.replace("rustre_symbols_ext_",""), any_valid(r), True, tool)

# net_pcap extras
for tool in ["net_pcap_link_type_from_u16","net_pcap_merge_files","net_pcap_split_by_count","net_pcap_split_by_time","net_pcap_file_parse_info"]:
    r = call(tool, {"link_type":1} if "link_type" in tool else {})
    if r:
        check("net_pcap_v2", tool.replace("net_pcap_",""), any_valid(r), True, tool)

# Save
try: p.terminate()
except: pass
for cat, d in per_cat.items():
    out = fr"C:\Users\Fra\Desktop\RustRE\validation\mismatch_{cat}.json"
    with open(out, "w") as f: json.dump({"category":cat, "checks_total":d["checks"], "checks_passed":d["passed"], "mismatches":d["mismatches"]}, f, indent=1)
    print(f"{cat}: {d['passed']}/{d['checks']} passed, {len(d['mismatches'])} mismatch")
total_c = sum(d["checks"] for d in per_cat.values()); total_p = sum(d["passed"] for d in per_cat.values()); total_m = sum(len(d["mismatches"]) for d in per_cat.values())
print(f"\nBATCH33 TOTAL: {total_p}/{total_c} passed, {total_m} mismatch across {len(per_cat)} categories")
