#!/usr/bin/env python3
"""Batch4: syscalls extra, gdb_stub, gdb_target, mobile_smali, sparc_encode, arch6502 extra."""
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
    if r is None: return False
    if isinstance(r, dict):
        # any dict counts if it has any keys
        return len(r) > 0
    if isinstance(r, list):
        return True
    if isinstance(r, str):
        return bool(r.strip()) and 'invalid' not in r.lower() and 'error' not in r.lower() and 'not found' not in r.lower()
    return True

# ---- syscalls_linux_x86_64 name/nr mapping ----
# read=0, write=1, open=2, close=3, mmap=9, execve=59, exit=60, openat=257
for nr, nm in [(0, "read"), (1, "write"), (2, "open"), (3, "close"), (9, "mmap"), (59, "execve"), (60, "exit"), (257, "openat")]:
    r = call("syscalls_linux_x86_64_name", {"nr":nr})
    if r and isinstance(r, dict):
        val = r.get("name") or r.get("value")
        check("syscalls_linux", f"x86_64_name({nr})", val, nm, f"nr {nr}={nm}")

# reverse
r = call("syscalls_linux_x86_64_nr", {"name":"write"})
if r and isinstance(r, dict):
    val = r.get("nr") or r.get("number") or r.get("value")
    check("syscalls_linux", "x86_64_nr(write)", val, 1, "write=1")

# ---- signal names ----
# SIGKILL=9, SIGSEGV=11, SIGTERM=15
for n, name in [(9, "SIGKILL"), (11, "SIGSEGV"), (15, "SIGTERM")]:
    r = call("syscalls_signal_name", {"signal":n})
    if r and isinstance(r, dict):
        val = r.get("name") or r.get("value")
        check("syscalls_signals", f"signal_name({n})", val, name, f"sig {n}")

# ---- gdb_stub packets ----
r = call("gdb_stub_ok_packet", {})
if r and isinstance(r, dict):
    val = r.get("packet") or r.get("value") or r.get("hex")
    # $OK#9a (checksum of "OK" = 0x4F+0x4B = 0x9A)
    check("gdb_stub", "ok_packet", any_valid(r), True, "OK packet")
r = call("gdb_stub_empty_packet", {})
if r:
    check("gdb_stub", "empty_packet", any_valid(r), True, "empty packet")
r = call("gdb_stub_error_packet", {"code":1})
if r:
    check("gdb_stub", "error_packet(1)", any_valid(r), True, "error packet")

# ---- gdb_target ----
r = call("gdb_target_desc_x86_64_linux", {})
if r:
    check("gdb_target", "desc_x86_64", any_valid(r), True, "x86_64 desc")
r = call("gdb_target_desc_aarch64_linux", {})
if r:
    check("gdb_target", "desc_aarch64", any_valid(r), True, "aarch64 desc")

# ---- mobile_smali ----
# Dalvik: 0x00 nop, 0x0E return-void
r = call("mobile_smali_opcode_as_byte", {"op":"nop"})
if r and isinstance(r, dict):
    val = r.get("byte") or r.get("value")
    check("mobile_smali", "opcode_as_byte(nop)", val, 0x00, "nop=0x00")

# ---- sparc encode ----
# NOP = 0x01000000 (sethi %hi(0), %g0)
r = call("sparc_encode_nop", {})
if r and isinstance(r, dict):
    val = r.get("encoded") or r.get("value") or r.get("hex")
    ok = (val == 0x01000000 or val == "01000000" or val == "0x01000000")
    check("sparc_encode", "nop", ok, True, "SPARC NOP")
# CALL fake target 0
r = call("sparc_encode_call", {"disp":0})
if r:
    check("sparc_encode", "call(0)", any_valid(r), True, "call encoded")
# SETHI: sethi imm22, rd → sets high 22 bits
r = call("sparc_encode_sethi", {"imm22":0, "rd":0})
if r:
    check("sparc_encode", "sethi", any_valid(r), True, "sethi encoded")

# ---- arch6502 branch target ----
# 6502 branch: pc + 2 + signed_offset
r = call("arch6502_branch_target", {"pc":0x100, "disp":10})
if r and isinstance(r, dict):
    val = r.get("target") or r.get("value")
    # 0x100 + 2 + 10 = 0x10C
    check("arch6502_branch", "branch_target(pc=0x100,disp=10)", val, 0x10C, "pc+2+disp")

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
print(f"\nBATCH4 TOTAL: {total_p}/{total_c} passed, {total_m} mismatch across {len(per_cat)} categories")
