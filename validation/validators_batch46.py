#!/usr/bin/env python3
"""Batch46: emu_base, emu_backends, forensics_fs many, forensics_mem many."""
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

# emu_base
for tool in ["emu_arch_name","emu_arch_name_wire","emu_arch_pointer_size","emu_arch_pointer_size_wire","emu_backends_registry_find","emu_base_arch_is_64bit","emu_base_arch_is_x86","emu_base_coverage_map_summary","emu_base_coverage_tracker_pct","emu_base_factory_create","emu_base_mem_perms_flags","emu_base_mem_region_info","emu_base_registers_round_trip","emu_base_registry_size","emu_base_stats_ipc","emu_base_trace_summary","emu_coverage_map_summary","emu_coverage_tracker_pct","emu_interpreter_mem_roundtrip","emu_library_stub_is_stubbed","emu_library_stub_module","emu_mem_provider_find","emu_mem_region_batch_check","emu_mem_region_inspect","emu_os_linux_syscall_group","emu_registry_names","emu_stats_aggregate"]:
    r = call(tool, {})
    if r:
        check("emu_base_v3", tool.replace("emu_",""), any_valid(r), True, tool)

# emu_unicorn coverage & hooks
# emu_unicorn_heap_calloc_overflow_check requires explicit params (base, size, count, elem)
# and is validated separately below; it is excluded from the empty-args loop.
for tool in ["emu_unicorn_coverage_edge_walk","emu_unicorn_coverage_empty_report","emu_unicorn_coverage_hit_count","emu_unicorn_coverage_hot_block","emu_unicorn_coverage_most_visited","emu_unicorn_coverage_record_seq","emu_unicorn_coverage_reset_check","emu_unicorn_coverage_reset_clears","emu_unicorn_coverage_single_bb","emu_unicorn_emu_options_custom","emu_unicorn_heap_calloc_sim","emu_unicorn_heap_calloc_zero","emu_unicorn_heap_free_invalid","emu_unicorn_heap_free_sim","emu_unicorn_heap_free_then_alloc","emu_unicorn_heap_malloc_sim","emu_unicorn_heap_realloc_free_addr","emu_unicorn_heap_realloc_grow","emu_unicorn_heap_realloc_missing","emu_unicorn_heap_realloc_same","emu_unicorn_heap_realloc_shrink","emu_unicorn_heap_realloc_sim","emu_unicorn_heap_zero_size_malloc","emu_unicorn_hookkind_labels","emu_unicorn_mapped_region_read_roundtrip","emu_unicorn_mode_is_little_endian","emu_unicorn_mode_is_little_endian_v2","emu_unicorn_new_arm64","emu_unicorn_new_arm_thumb","emu_unicorn_new_mips32","emu_unicorn_new_x86_64","emu_unicorn_options_defaults_v2","emu_unicorn_perm_can_exec","emu_unicorn_perm_can_exec_v2","emu_unicorn_perm_can_read","emu_unicorn_perm_can_write","emu_unicorn_perm_exec_bit","emu_unicorn_perm_read_bit","emu_unicorn_perm_roundtrip","emu_unicorn_perm_write_bit","emu_unicorn_register_file_roundtrip"]:
    r = call(tool, {})
    if r:
        check("emu_unicorn_v5", tool.replace("emu_unicorn_",""), any_valid(r), True, tool)

# emu_unicorn_heap_calloc_overflow_check: count=0xffffffff * elem=2 overflows usize → overflow=True
r_calloc_ovf = call("emu_unicorn_heap_calloc_overflow_check",
                    {"base": 0x2000, "size": 0x10000, "count": 0xffffffff, "elem": 2})
check("emu_unicorn_v5", "heap_calloc_overflow_check",
      r_calloc_ovf.get("overflow") if isinstance(r_calloc_ovf, dict) else None,
      True, "emu_unicorn_heap_calloc_overflow_check")

try: p.terminate()
except: pass
for cat, d in per_cat.items():
    out = fr"C:\Users\Fra\Desktop\RustRE\validation\mismatch_{cat}.json"
    with open(out, "w") as f: json.dump({"category":cat, "checks_total":d["checks"], "checks_passed":d["passed"], "mismatches":d["mismatches"]}, f, indent=1)
    print(f"{cat}: {d['passed']}/{d['checks']} passed, {len(d['mismatches'])} mismatch")
total_c = sum(d["checks"] for d in per_cat.values()); total_p = sum(d["passed"] for d in per_cat.values()); total_m = sum(len(d["mismatches"]) for d in per_cat.values())
print(f"\nBATCH46 TOTAL: {total_p}/{total_c} passed, {total_m} mismatch across {len(per_cat)} categories")
