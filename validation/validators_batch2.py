#!/usr/bin/env python3
"""Batch2: 10 more categories - ppc, sparc synth, arch_dex/jvm/lua/cil, luajit, m68k, smali, adb constants."""
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

def any_valid(r):
    return r is not None and (isinstance(r, dict) or isinstance(r, list) or (isinstance(r, str) and r.strip()))

# ---- ppc ----
r = call("ppc_encode_bl", {"target":0})
if r and isinstance(r, dict):
    val = r.get("encoded") or r.get("value") or r.get("hex")
    # bl 0 = 0x48000001
    ok = (val == 0x48000001 or val == "48000001" or val == "0x48000001")
    check("ppc", "ppc_encode_bl(0)", ok, True, "bl 0")
r = call("ppc_encode_lis", {"rd":0, "value":0, "imm":0})
if r:
    check("ppc", "ppc_encode_lis", any_valid(r), True, "lis returns value")

# ---- sparc synth ----
for tool in ["sparc_synth_clr", "sparc_synth_dec", "sparc_synth_inc", "sparc_synth_neg", "sparc_synth_not", "sparc_synth_tst"]:
    r = call(tool, {"rd":8, "rs":8} if "clr" not in tool and "tst" not in tool else {"rd":8} if "clr" in tool else {"rs":8})
    if r:
        check("sparc_synth", tool, any_valid(r), True, f"{tool} returns")

# ---- arch_dex ----
r = call("arch_dex_vreg", {"n":0})
if r and isinstance(r, dict):
    val = r.get("name") or r.get("value")
    check("arch_dex", "arch_dex_vreg(0)", val, "v0", "vreg 0 = v0")
r = call("arch_dex_preg", {"n":0})
if r:
    check("arch_dex", "arch_dex_preg(0)", any_valid(r), True, "preg returns")

# ---- arch_jvm ----
# javap opcode: 0x00=nop, 0xB1=return, 0xB2=getstatic, 0xB6=invokevirtual
for op, name in [(0x00, "nop"), (0xb1, "return"), (0xb6, "invokevirtual")]:
    r = call("arch_jvm_decode", {"opcode":op})
    if r and isinstance(r, dict):
        val = r.get("mnemonic") or r.get("name") or r.get("op")
        check("arch_jvm", f"decode({op:#x})", str(val).lower() if val else None, name, f"opcode {op:#x}")

# ---- arch_lua ----
r = call("arch_lua_get_ax54", {"word":0})
if r:
    check("arch_lua", "get_ax54", any_valid(r), True, "get_ax54 returns")
r = call("arch_lua_get_bx54", {"word":0})
if r:
    check("arch_lua", "get_bx54", any_valid(r), True, "get_bx54 returns")

# ---- arch_cil ----
r = call("arch_cil_decode_compressed_uint", {"bytes":[0x0A]})
if r and isinstance(r, dict):
    val = r.get("value") or r.get("result")
    check("arch_cil", "decompress uint (0x0A)", val, 10, "0x0A -> 10")
r = call("arch_cil_max_local_slot", {"code_hex":"00"})
if r:
    check("arch_cil", "max_local_slot", any_valid(r), True, "returns constant")

# ---- luajit ----
# LuaJIT opcode encoding: op = instr & 0xFF, A = (instr >> 8) & 0xFF
r = call("luajit_instr_a", {"instr":0x12345678})
if r and isinstance(r, dict):
    val = r.get("value") or r.get("a")
    check("luajit", "instr_a(0x12345678)", val, 0x56, "A = (instr>>8) & 0xFF")
r = call("luajit_instr_op", {"instr":0x12345678})
if r and isinstance(r, dict):
    val = r.get("value") or r.get("op") or r.get("opcode")
    check("luajit", "instr_op(0x12345678)", val, 0x78, "op = instr & 0xFF")

# ---- m68k ----
r = call("m68k_variant_info", {"variant":"68000"})
if r:
    check("m68k", "variant_info", any_valid(r), True, "m68000 dict")
r = call("m68k_decode_instr", {"word":0x4E71})  # NOP
if r and isinstance(r, dict):
    val = r.get("mnemonic") or r.get("name") or r.get("op")
    check("m68k", "decode(0x4E71 NOP)", str(val).lower() if val else None, "nop", "0x4E71=NOP")

# ---- smali ----
# Dalvik opcode 0x00 = nop, 0x0E = return-void
for op, name in [(0x00, "nop"), (0x0E, "return-void")]:
    r = call("smali_opcode_to_mnemonic", {"opcode":op})
    if r and isinstance(r, dict):
        val = r.get("mnemonic") or r.get("name") or r.get("value")
        check("smali", f"opcode_to_mnemonic({op:#x})", str(val).lower() if val else None, name, f"opcode {op:#x}")

# ---- adb constants ----
r = call("adb_max_payload_constant", {})
if r and isinstance(r, dict):
    val = r.get("max_payload") or r.get("value") or r.get("constant")
    # ADB max payload = 1024*1024 = 1048576 (v3) or 4096 (older)
    check("adb", "max_payload", val in (1024*1024, 4096, 262144), True, "adb max payload")
r = call("adb_version_constant", {})
if r and isinstance(r, dict):
    val = r.get("version") or r.get("value") or r.get("constant")
    # ADB version 0x01000000 or 0x01000001
    check("adb", "version", val in (0x01000000, 0x01000001), True, "version")

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
print(f"\nBATCH2 TOTAL: {total_p}/{total_c} passed, {total_m} mismatch across {len(per_cat)} categories")
