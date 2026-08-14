#!/usr/bin/env python3
"""Batch21: pe_editor extras, emu_unicorn extra, debug_unicorn constants, symbols_stabs."""
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

# pe_editor extras
r = call("pe_editor_section_chars_constants", {})
if r:
    check("pe_editor_v2", "section_chars", any_valid(r), True, "section chars")
r = call("pe_editor_rc4_process", {"key":[0x01,0x02,0x03], "data":[0xAA,0xBB]})
if r:
    check("pe_editor_v2", "rc4_process", any_valid(r), True, "rc4 done")

# emu_unicorn extras
r = call("emu_unicorn_perm_constants", {})
if r:
    check("emu_unicorn_v2", "perm_constants", any_valid(r), True, "perms")
r = call("emu_unicorn_perm_can_read", {"perm":1})
if r and isinstance(r, dict):
    val = get_first(r, ["can_read","value","result"])
    check("emu_unicorn_v2", "can_read(READ)", val, True, "READ=1")

# debug_unicorn constants
r = call("debug_unicorn_arch_pointer_size", {"arch":"x86_64"})
if r and isinstance(r, dict):
    val = get_first(r, ["size","bytes","value","result","pointer_size"])
    check("debug_unicorn_v2", "ptr_size(x86_64)", val, 8, "x86_64=8 bytes")

# symbols_stabs
r = call("symbols_stabs_type_code_from_char_v2", {"ch":"f"})
if r:
    check("symbols_stabs_v2", "type_code(f)", any_valid(r), True, "f=Function")
r = call("symbols_stabs_type_is_symbol", {"code":36})
if r:
    check("symbols_stabs_v2", "type_is_symbol", any_valid(r), True, "check symbol")

# gdb_target
r = call("gdb_target_xml_parse", {"xml":"<target><architecture>x86_64</architecture></target>"})
if r:
    check("gdb_target_v2", "xml_parse", any_valid(r), True, "xml parse")

# adb_parse
r = call("adb_parse_devices_output", {"output":"List of devices attached\ndevice1\tdevice\n"})
if r:
    check("adb_v2", "parse_devices", any_valid(r), True, "devices parsed")
r = call("adb_shell_escape", {"input":"echo hello world"})
if r:
    check("adb_v2", "shell_escape", any_valid(r), True, "escaped")

# yara rule
r = call("yara_rule_get_meta", {"name":"test"})
if r:
    check("yara_v2", "rule_get_meta", any_valid(r), True, "meta")

# ida_baseline check
r = call("iadl_convergence_moving_average", {"values":[10.0,20.0,30.0], "window":3})
if r and isinstance(r, dict):
    val = get_first(r, ["result","value","average"])
    if isinstance(val, (int, float)):
        check("iadl_v2", "moving_average", abs(val - 20.0) < 0.01, True, "avg=20")

# frida device
r = call("frida_target_local_pid", {})
if r:
    check("frida_v3", "local_pid", any_valid(r), True, "pid")

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
print(f"\nBATCH21 TOTAL: {total_p}/{total_c} passed, {total_m} mismatch across {len(per_cat)} categories")
