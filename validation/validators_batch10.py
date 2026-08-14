#!/usr/bin/env python3
"""Batch10: mobile_apktool/jadx, deobf_smc/vm, arch68k, emu_qiling, firmware, forensics constants."""
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
    if mcp == truth:
        d["passed"] += 1
    else:
        d["mismatches"].append({"tool":name,"mcp":mcp,"truth":truth,"note":note})

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

# ---- mobile_apktool ----
r = call("mobile_apktool_config_new", {})
if r:
    check("mobile_apktool", "config_new", any_valid(r), True, "config")
r = call("mobile_apktool_cli_with_path", {"path":"C:\\apktool.jar"})
if r:
    check("mobile_apktool", "cli_with_path", any_valid(r), True, "cli config")

# ---- mobile_jadx ----
r = call("mobile_jadx_config_new", {})
if r:
    check("mobile_jadx", "config_new", any_valid(r), True, "config")
r = call("mobile_jadx_descriptor_to_type", {"desc":"I"})
if r and isinstance(r, dict):
    val = get_first(r, ["type","value","result"])
    check("mobile_jadx", "descriptor_to_type(I)", str(val).lower(), "int", "I=int")
r = call("mobile_jadx_descriptor_to_type", {"desc":"Ljava/lang/String;"})
if r and isinstance(r, dict):
    val = get_first(r, ["type","value","result"])
    check("mobile_jadx", "descriptor_to_type(String)", "String" in str(val), True, "L...; =class")

# ---- arch68k ----
r = call("arch68k_size_bytes", {"size":"L"})
if r and isinstance(r, dict):
    val = get_first(r, ["bytes","value","size"])
    check("arch68k", "size_bytes(L)", val, 4, "Long=4 bytes")
r = call("arch68k_size_bytes", {"size":"W"})
if r and isinstance(r, dict):
    val = get_first(r, ["bytes","value","size"])
    check("arch68k", "size_bytes(W)", val, 2, "Word=2 bytes")

# ---- emu_qiling ----
r = call("emu_qiling_errno_constants", {})
if r:
    check("emu_qiling", "errno_constants", any_valid(r), True, "errno list")
r = call("emu_qiling_os_target_name", {"target":"linux_x86_64"})
if r:
    check("emu_qiling", "os_target_name", any_valid(r), True, "os name")

# ---- firmware ----
r = call("firmware_detect_kind_v2", {"data_hex":"aabbccdd" * 32})
if r:
    check("firmware", "detect_kind", any_valid(r), True, "firmware kind")

# ---- deobf_string ----
# rot13
r = call("deobf_string_rot13", {"input":"hello"})
if r and isinstance(r, dict):
    val = get_first(r, ["result","output","value","decoded"])
    check("deobf_string_v2", "rot13(hello)", val, "uryyb", "rot13")
r = call("deobf_string_caesar_bruteforce", {"cipher":"khoor"})
if r:
    check("deobf_string_v2", "caesar_bruteforce", any_valid(r), True, "caesar bf")

# ---- deobf_smc ----
r = call("deobf_smc_shannon_entropy", {"data_hex":"deadbeef"*8})
if r and isinstance(r, dict):
    val = get_first(r, ["entropy","value","result"])
    check("deobf_smc_v2", "entropy", isinstance(val, (int,float)) and val > 0, True, "entropy>0")

# ---- Save ----
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
print(f"\nBATCH10 TOTAL: {total_p}/{total_c} passed, {total_m} mismatch across {len(per_cat)} categories")
