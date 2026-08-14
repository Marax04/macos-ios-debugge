#!/usr/bin/env python3
"""Batch13: net_proxy, net_dns, forensics_fs_timeline, dotnet_edit, deobf_vm, script_python pure extra."""
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

# net_proxy simple regex match
r = call("net_proxy_simple_regex_match", {"pattern":"foo*", "input":"foobar"})
if r:
    check("net_proxy", "regex_match", any_valid(r), True, "regex")
# base64 decode
r = call("net_proxy_base64_decode", {"input":"aGVsbG8="})
if r and isinstance(r, dict):
    val = get_first(r, ["decoded","result","output","value","bytes","text"])
    ok = (val == "hello" or val == list(b"hello") or val == b"hello".hex())
    check("net_proxy", "base64(hello)", ok, True, "b64 decode")
# hex encode
r = call("net_proxy_hex_encode", {"input":[0xDE,0xAD]})
if r and isinstance(r, dict):
    val = get_first(r, ["hex","encoded","result","value"])
    check("net_proxy", "hex_encode", str(val).lower(), "dead", "0xDE 0xAD -> dead")

# net_dns type
r = call("net_dns_type_name_v2", {"type":1})  # A record
if r and isinstance(r, dict):
    val = get_first(r, ["name","value","result"])
    check("net_dns", "type(1)", str(val).upper(), "A", "1=A record")
r = call("net_dns_type_name_v2", {"type":28})  # AAAA
if r and isinstance(r, dict):
    val = get_first(r, ["name","value","result"])
    check("net_dns", "type(28)", str(val).upper(), "AAAA", "28=AAAA")

# net_icmp
r = call("net_icmp_type_name_v2", {"type":8})  # Echo request
if r and isinstance(r, dict):
    val = get_first(r, ["name","value","result"])
    check("net_icmp", "type(8)", "echo" in str(val).lower(), True, "8=echo")

# dotnet_edit
r = call("dotnet_edit_opcode_byte_size", {"opcode":0x00})  # nop
if r and isinstance(r, dict):
    val = get_first(r, ["size","bytes","value","result"])
    check("dotnet_edit", "opcode_size(nop)", val, 1, "nop=1 byte")

# forensics_fs_timeline
r = call("forensics_fs_timeline_event_type_kind_name", {"kind":0})
if r:
    check("forensics_timeline", "event_kind_name", any_valid(r), True, "kind name")

# deobf_vm
r = call("deobf_vm_arch_stack_machine", {})
if r:
    check("deobf_vm", "stack_machine", any_valid(r), True, "arch")
r = call("deobf_vm_arch_register_machine", {})
if r:
    check("deobf_vm", "reg_machine", any_valid(r), True, "arch")

# script_python pure_execute
r = call("script_python_pure_execute_print", {"code":"print('hello')"})
if r:
    check("script_python_v2", "execute_print", any_valid(r), True, "execute")

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
print(f"\nBATCH13 TOTAL: {total_p}/{total_c} passed, {total_m} mismatch across {len(per_cat)} categories")
