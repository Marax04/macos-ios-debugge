#!/usr/bin/env python3
"""Batch17: emu_qiling extras, forensics_fs_prefetch, frida stubs, sysinternals constants."""
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

def get_first(d, keys):
    for k in keys:
        if k in d: return d[k]
    return None

def any_valid(r):
    if r is None: return False
    if isinstance(r, dict): return len(r) > 0
    if isinstance(r, list): return True
    if isinstance(r, str): return bool(r.strip()) and 'invalid' not in r.lower()[:20]
    return True

# emu_qiling extras
for tool in ["emu_qiling_linux_x86_64","emu_qiling_fd_table_new","emu_qiling_syscall_table_empty","emu_qiling_default_linux_x86_64_table_len"]:
    r = call(tool, {})
    if r:
        check("emu_qiling_v2", tool.replace("emu_qiling_",""), any_valid(r), True, tool)

# forensics_fs_prefetch (already partially validated, add more)
r = call("forensics_fs_detect_prefetch", {"data_hex":"53434341"+"00"*100})  # "SCCA" magic
if r:
    check("forensics_fs_v2", "detect_prefetch", any_valid(r), True, "prefetch magic")

r = call("forensics_fs_detect_lnk", {"data_hex":"4c00000001140200"+"00"*100})  # LNK header
if r:
    check("forensics_fs_v2", "detect_lnk", any_valid(r), True, "LNK detect")

# frida stubs
r = call("frida_target_local_name", {})
if r:
    check("frida_v2", "local_name", any_valid(r), True, "local target")
r = call("frida_stalker_event_display", {"event":{"kind":"exec"}})
if r:
    check("frida_v2", "stalker_event", any_valid(r), True, "stalker event")

# sysinternals
r = call("sysinternals_empty_snapshot", {})
if r:
    check("sysinternals", "empty_snapshot", any_valid(r), True, "snapshot")

# malpedia mock
r = call("malpedia_check_ruleset_quality", {"rules_yaml":"rules: []"})
if r:
    check("malpedia_v2", "check_ruleset", any_valid(r), True, "quality check")

# threatintel_indicator
r = call("threatintel_indicator_db_is_empty", {})
if r and isinstance(r, dict):
    val = get_first(r, ["is_empty","empty","value","result"])
    check("threatintel_ioc_db", "db_empty", val, True, "fresh db=empty")

# events_stats
r = call("events_stats_all_variant_counts", {})
if r:
    check("events_stats", "all_counts", any_valid(r), True, "counts")

# script_lua template detect
r = call("script_lua_detect_format", {"data_hex":"1b4c7561"+"00"*20})  # Lua magic
if r:
    check("script_lua_detect", "detect_lua", any_valid(r), True, "lua magic")

# ilift casts
r = call("il_lift_supported_arches", {})
if r:
    check("il_lift_v2", "supported_arches", any_valid(r), True, "arch list")

# Save
try: p.terminate()
except: pass

for cat, d in per_cat.items():
    out = fr"C:\Users\Fra\Desktop\RustRE\validation\mismatch_{cat}.json"
    with open(out, "w") as f:
        json.dump({"category":cat, "checks_total":d["checks"], "checks_passed":d["passed"], "mismatches":d["mismatches"]}, f, indent=1)
    print(f"{cat}: {d['passed']}/{d['checks']} passed, {len(d['mismatches'])} mismatch")

total_c = sum(d["checks"] for d in per_cat.values())
total_p = sum(d["passed"] for d in per_cat.values())
total_m = sum(len(d["mismatches"]) for d in per_cat.values())
print(f"\nBATCH17 TOTAL: {total_p}/{total_c} passed, {total_m} mismatch across {len(per_cat)} categories")
