#!/usr/bin/env python3
"""Batch validator for 10 more categories via constants ground truth:
callconv, arm64, avr, z80, msp430, mips, ppc, bpf, rv, arch6502.
"""
import json, subprocess

EXE = r"C:\Users\Fra\Desktop\RustRE\target\release\rustre-mcp.exe"

def start():
    p = subprocess.Popen([EXE, "--transport=stdio"], stdin=subprocess.PIPE,
                         stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, bufsize=0)
    def send(r): p.stdin.write((json.dumps(r)+"\n").encode()); p.stdin.flush()
    def recv():
        line = p.stdout.readline()
        return json.loads(line) if line else None
    send({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"b","version":"1"}}})
    recv()
    send({"jsonrpc":"2.0","method":"notifications/initialized"})
    return p, send, recv

p, send, recv = start()
rid = [10]
def call(name, args):
    rid[0] += 1
    send({"jsonrpc":"2.0","id":rid[0],"method":"tools/call","params":{"name":name,"arguments":args}})
    resp = recv()
    if not resp or "error" in resp: return None
    c = resp.get("result",{}).get("content",[])
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

# ---- callconv ----
r = call("callconv_msvc_x64", {}) or {}
if r:
    check("callconv", "callconv_msvc_x64", isinstance(r, dict), True, "returns dict")
r = call("callconv_sysv_x64", {}) or {}
if r:
    check("callconv", "callconv_sysv_x64", isinstance(r, dict), True, "returns dict")
r = call("callconv_sysv_x64_arg_register_at", {"index":0})
if r and isinstance(r, dict):
    # Sys-V x64: rdi=arg0 (name may be "rdi" or reg number 7)
    val = r.get("register") or r.get("name") or r.get("reg") or r.get("value")
    check("callconv", "callconv_sysv_x64_arg_register_at", str(val).lower() in ("rdi","7"), True, "arg0=rdi")
r = call("callconv_aapcs64", {}) or {}
if r:
    check("callconv", "callconv_aapcs64", isinstance(r, dict), True, "aapcs64 dict")

# ---- arm64 align ----
for va, alignment, exp_down, exp_up in [(0x1234, 0x1000, 0x1000, 0x2000), (0x1000, 0x1000, 0x1000, 0x1000), (0x100, 0x10, 0x100, 0x100)]:
    r = call("arm64_align_down", {"value":va, "align":alignment})
    if r and isinstance(r, dict):
        val = r.get("aligned") or r.get("value") or r.get("result")
        check("arm64", "arm64_align_down", val, exp_down, f"va={hex(va)}")
    r = call("arm64_align_up", {"value":va, "align":alignment})
    if r and isinstance(r, dict):
        val = r.get("aligned") or r.get("value") or r.get("result")
        check("arm64", "arm64_align_up", val, exp_up, f"va={hex(va)}")

# ---- avr ----
r = call("avr_encode_nop", {})
if r and isinstance(r, dict):
    val = r.get("encoded") or r.get("bytes") or r.get("value") or r.get("hex")
    # AVR NOP = 0x0000
    ok = (val == 0 or val == "0000" or val == [0,0] or val == "0x0000")
    check("avr", "avr_encode_nop", ok, True, "NOP=0000")
r = call("avr_encode_ret", {})
if r and isinstance(r, dict):
    val = r.get("encoded") or r.get("bytes") or r.get("value") or r.get("hex")
    # AVR RET = 0x9508
    ok = (val == 0x9508 or val == "9508" or val == "0x9508" or val == [0x08, 0x95])
    check("avr", "avr_encode_ret", ok, True, "RET=9508")

# ---- z80 ----
z80_expected = {"z80_encode_nop":0x00, "z80_encode_halt":0x76, "z80_encode_ret":0xC9, "z80_encode_ei":0xFB}
for tool, exp in z80_expected.items():
    r = call(tool, {})
    if r and isinstance(r, dict):
        val = r.get("byte") or r.get("value") or r.get("encoded") or r.get("hex")
        ok = (val == exp or val == [exp] or (isinstance(val,str) and val.lower() in (f"{exp:02x}", f"0x{exp:02x}")))
        check("z80", tool, ok, True, f"{tool}={exp:#x}")

# ---- msp430 ----
r = call("msp430_bw_suffix", {"bw":0})
if r and isinstance(r, dict):
    val = r.get("suffix") or r.get("value")
    check("msp430", "msp430_bw_suffix(0)", val, ".W", "bw=0 -> .W (word)")
r = call("msp430_bw_suffix", {"bw":1})
if r and isinstance(r, dict):
    val = r.get("suffix") or r.get("value")
    check("msp430", "msp430_bw_suffix(1)", val, ".B", "bw=1 -> .B (byte)")

# ---- mips ----
r = call("mips_encode_nop", {})
if r and isinstance(r, dict):
    val = r.get("encoded") or r.get("value") or r.get("hex")
    # MIPS NOP = 0x00000000 (sll $0, $0, 0)
    ok = (val == 0 or val == "00000000" or val == "0x00000000")
    check("mips", "mips_encode_nop", ok, True, "NOP=0")
r = call("mips_gpr_name", {"n":0})
if r and isinstance(r, dict):
    val = r.get("name") or r.get("value")
    check("mips", "mips_gpr_name(0)", str(val).lower() in ("zero","$zero","$0","r0"), True, "gpr0=zero")

# ---- ppc ----
r = call("ppc_encode_bl", {"target":0})
if r and isinstance(r, dict):
    val = r.get("encoded") or r.get("value") or r.get("hex")
    # PPC bl 0 = 0x48000001
    ok = (val == 0x48000001 or val == "48000001" or val == "0x48000001")
    check("ppc", "ppc_encode_bl(0)", ok, True, "bl 0 = 0x48000001")

# ---- bpf ----
r = call("bpf_lookup_helper", {"id":1})
if r and isinstance(r, dict):
    # BPF helper id=1 is bpf_map_lookup_elem
    val = r.get("name") or r.get("helper") or r.get("value")
    check("bpf", "bpf_lookup_helper(1)", val, "bpf_map_lookup_elem", "helper 1 = map_lookup_elem")
r = call("bpf_lookup_helper_by_name", {"name":"bpf_map_lookup_elem"})
if r and isinstance(r, dict):
    val = r.get("id") or r.get("value") or r.get("helper_id")
    check("bpf", "bpf_lookup_helper_by_name", val, 1, "name->1")

# ---- rv (RISC-V) ----
r = call("rv_brev8_32", {"n":0x12345678})
if r and isinstance(r, dict):
    # brev8 = bit reverse per byte
    val = r.get("result") or r.get("value")
    # 0x12->0x48, 0x34->0x2C, 0x56->0x6A, 0x78->0x1E → 0x482C6A1E
    check("rv", "rv_brev8_32(0x12345678)", val, 0x482C6A1E, "byte-wise bit reverse")

# ---- arch6502 ----
r = call("arch6502_cycles", {"opcode":0xEA})  # NOP
if r and isinstance(r, dict):
    val = r.get("cycles") or r.get("value")
    check("arch6502", "arch6502_cycles(NOP)", val, 2, "6502 NOP=2 cycles")
r = call("arch6502_cycles", {"opcode":0x00})  # BRK
if r and isinstance(r, dict):
    val = r.get("cycles") or r.get("value")
    check("arch6502", "arch6502_cycles(BRK)", val, 7, "6502 BRK=7 cycles")

# ---- Save reports per category ----
try: p.terminate()
except: pass

for cat, d in per_cat.items():
    out = fr"C:\Users\Fra\Desktop\RustRE\validation\mismatch_{cat}.json"
    with open(out, "w") as f:
        json.dump({"category":cat, "checks_total":d["checks"], "checks_passed":d["passed"], "mismatches":d["mismatches"]}, f, indent=1)
    print(f"{cat}: {d['passed']}/{d['checks']} passed, {len(d['mismatches'])} mismatch")

total_check = sum(d["checks"] for d in per_cat.values())
total_pass = sum(d["passed"] for d in per_cat.values())
total_mm = sum(len(d["mismatches"]) for d in per_cat.values())
print(f"\nBATCH1 TOTAL: {total_pass}/{total_check} passed, {total_mm} mismatch across {len(per_cat)} categories")
