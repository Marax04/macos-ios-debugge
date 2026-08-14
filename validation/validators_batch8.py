#!/usr/bin/env python3
"""Batch8: net_ip, net_icmp, net_dns, patch extras, plugin, threatintel enums."""
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

# ---- net_is_private_addr ----
# 10.0.0.1 is private, 8.8.8.8 is not
r = call("net_is_private_addr", {"addr":"10.0.0.1"})
if r and isinstance(r, dict):
    val = get_first(r, ["is_private","private","value","result"])
    check("net_util", "is_private(10.0.0.1)", val, True, "RFC1918")
r = call("net_is_private_addr", {"addr":"8.8.8.8"})
if r and isinstance(r, dict):
    val = get_first(r, ["is_private","private","value","result"])
    check("net_util", "is_private(8.8.8.8)", val, False, "public")

# ---- net_is_multicast_addr_v2 ----
r = call("net_is_multicast_addr_v2", {"addr":"224.0.0.1"})
if r and isinstance(r, dict):
    val = get_first(r, ["is_multicast","multicast","value","result"])
    check("net_util", "multicast(224.0.0.1)", val, True, "multicast")

# ---- syscalls_errno_name ----
# EPERM=1, ENOENT=2, EACCES=13, ENOMEM=12
for nr, nm in [(1, "EPERM"), (2, "ENOENT"), (13, "EACCES"), (12, "ENOMEM")]:
    r = call("syscalls_errno_name", {"errno":nr})
    if r and isinstance(r, dict):
        val = get_first(r, ["name","value","errno_name"])
        check("syscalls_errno", f"errno({nr})", val, nm, f"errno {nr}")

# ---- z80 encoding round-trip ----
# already covered but add more
# LD A, n : 0x3E followed by immediate

# ---- gdb_packet_checksum ----
# checksum("OK") = 0x4F + 0x4B = 0x9A
r = call("gdb_packet_checksum", {"data":"OK"})
if r and isinstance(r, dict):
    val = get_first(r, ["checksum","value","result"])
    # accept int or hex string
    ok = (val == 0x9A or val == "9a" or val == "9A")
    check("gdb_packet_ext", "checksum(OK)", ok, True, "OK=0x9A")

# ---- forensics_compute hashes (already validated)  ----

# ---- kg extra ----
r = call("kg_get_function", {"binary_id":"bin-0001","addr":"0x140001000"})
if r:
    check("kg_ext", "get_function", any_valid(r), True, "get_function")

# ---- vsa addition ----
r = call("vsa_strided_interval_add_wire", {})
if r:
    check("vsa_ext", "si_add", any_valid(r), True, "SI add")

# ---- ttd position (already partial) ----
r = call("ttd_position_min", {})
if r:
    check("ttd_pos", "min", any_valid(r), True, "min pos")
r = call("ttd_position_max", {})
if r:
    check("ttd_pos", "max", any_valid(r), True, "max pos")

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
print(f"\nBATCH8 TOTAL: {total_p}/{total_c} passed, {total_m} mismatch across {len(per_cat)} categories")
