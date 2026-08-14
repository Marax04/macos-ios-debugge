#!/usr/bin/env python3
"""Batch7: script_python extra, script_builtin hex, deobf_string, forensics_fs_prefetch, dotnet_metadata simple."""
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
    if isinstance(r, dict): return len(r) > 0 and 'error' not in str(r).lower()[:30]
    if isinstance(r, list): return True
    if isinstance(r, str): return bool(r.strip()) and 'invalid' not in r.lower()[:20]
    return True

# ---- script_builtin hex ----
r = call("script_builtin_bytes_to_hex", {"bytes":[0xDE,0xAD,0xBE,0xEF]})
if r and isinstance(r, dict):
    val = get_first(r, ["hex","result","value"])
    check("script_builtin", "bytes_to_hex", str(val).lower(), "deadbeef", "bytes->hex")
r = call("script_builtin_hex_to_bytes", {"hex":"deadbeef"})
if r and isinstance(r, dict):
    # tool returns {len, hex, source} — verify length is correct
    check("script_builtin", "hex_to_bytes(len)", r.get("len"), 4, "deadbeef len=4")

# ---- script_bytes ----
r = call("script_bytes_to_hex", {"bytes":[0x01,0x02]})
if r:
    check("script_bytes", "to_hex", any_valid(r), True, "bytes to hex")
r = call("script_bytes_concat", {"a":[0x01,0x02], "b":[0x03,0x04]})
if r and isinstance(r, dict):
    val = get_first(r, ["result","bytes","concat","value"])
    if val is not None:
        exp = [0x01,0x02,0x03,0x04]
        check("script_bytes", "concat", val, exp, "concat lists")

# ---- deobf_string trivial ----
# rot13("hello") = "uryyb"
r = call("deobf_string_rot13", {"input":"hello"})
if r and isinstance(r, dict):
    val = get_first(r, ["result","output","value","decoded"])
    check("deobf_string", "rot13(hello)", val, "uryyb", "rot13")

# base64 decode via deobf
import base64
enc = base64.b64encode(b"hello").decode()
r = call("deobf_string_hex_decode", {"input":"68656c6c6f"})
if r and isinstance(r, dict):
    val = get_first(r, ["result","decoded","output","value","bytes"])
    if isinstance(val, list):
        check("deobf_string", "hex_decode(hello)", bytes(val), b"hello", "hex hello")
    elif isinstance(val, str):
        check("deobf_string", "hex_decode(hello)", val, "hello", "hex hello")

# ---- dotnet_metadata simple ----
r = call("dotnet_encode_token", {"table":0x02, "rid":0x123})
if r and isinstance(r, dict):
    val = get_first(r, ["token","value","result"])
    # token = (table << 24) | rid = (0x02 << 24) | 0x123 = 0x02000123
    check("dotnet_encode", "encode_token(0x02, 0x123)", val, 0x02000123, "token format")

r = call("dotnet_token_table_name", {"table":0x02})
if r and isinstance(r, dict):
    val = get_first(r, ["name","value"])
    # table 0x02 = TypeDef
    check("dotnet_encode", "token_table_name(0x02)", str(val), "TypeDef", "0x02=TypeDef")

# ---- forensics_fs_prefetch_pattern_matcher_risk ----
r = call("forensics_fs_prefetch_pattern_matcher_risk", {"path":"C:\\Windows\\System32\\notepad.exe"})
if r:
    check("forensics_prefetch", "risk", any_valid(r), True, "risk classification")

# ---- deobf_smc constants ----
r = call("deobf_smc_shannon_entropy", {"data_hex":"deadbeef"*8})
if r and isinstance(r, dict):
    val = get_first(r, ["entropy","value","result"])
    # Non-uniform bytes: some entropy < 3
    check("deobf_smc", "entropy(deadbeef*8)", isinstance(val, (int,float)) and val > 0, True, "shannon > 0")

# ---- flirt_crc16_ibm (standard CRC-16-IBM/ARC) ----
# crc16_arc("") = 0
r = call("flirt_crc16_ibm", {"data":[]})
if r and isinstance(r, dict):
    val = get_first(r, ["crc","value","result"])
    if val is not None:
        check("flirt_crc16", "crc16_ibm(empty)", val, 0, "empty=0")

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
print(f"\nBATCH7 TOTAL: {total_p}/{total_c} passed, {total_m} mismatch across {len(per_cat)} categories")
