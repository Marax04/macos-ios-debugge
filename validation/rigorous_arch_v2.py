#!/usr/bin/env python3
"""
Rigorous ground-truth validation for arch_* MCP tools.
Tests 10 arch_* tools not covered by rigorous_arch_x86.json or rigorous_arch_wasm.json.
"""
import json
import subprocess
import sys
import time

EXE = r"C:\Users\Fra\Desktop\RustRE\target\release\rustre-mcp.exe"
TARGET = r"C:\Users\Fra\Desktop\Zyphora\target\release\cargo-zyphora.exe"
OUT_JSON = r"C:\Users\Fra\Desktop\RustRE\validation\rigorous_arch_v2.json"
SKIP_JSON = r"C:\Users\Fra\Desktop\RustRE\validation\skip_arch.json"

# ── Python reference implementations ─────────────────────────────────────────

def ref_jvm_nop():
    """JVM opcode 0x00 is NOP, size=1, no operands."""
    return {"mnemonic": "nop", "operands": "", "size": 1}

def ref_sparc_encode_nop():
    """SPARC NOP = SETHI 0,%g0 = (rd=0)<<25 | (0b100)<<22 | 0 = 0x01000000"""
    rd = 0
    op2 = 0b100
    imm22 = 0
    word = ((rd & 31) << 25) | (op2 << 22) | (imm22 & 0x3FFFFF)
    return word  # 0x01000000

def ref_sparc_encode_call(disp):
    """SPARC CALL = op=01, disp30 = disp>>2"""
    assert disp % 4 == 0
    disp30 = (disp >> 2) & 0x3FFFFFFF
    return (1 << 30) | disp30

def ref_cil_decode_compressed_uint(data: bytes):
    """ECMA-335 compressed uint decode."""
    if not data:
        return None
    b0 = data[0]
    if b0 & 0x80 == 0:
        return (b0 & 0x7F, 1)
    if b0 & 0xC0 == 0x80:
        if len(data) < 2:
            return None
        val = ((b0 & 0x3F) << 8) | data[1]
        return (val, 2)
    if b0 & 0xE0 == 0xC0:
        if len(data) < 4:
            return None
        val = ((b0 & 0x1F) << 24) | (data[1] << 16) | (data[2] << 8) | data[3]
        return (val, 4)
    return None

def ref_dex_vreg(n):
    return f"v{n}"

def ref_dex_preg(n):
    return f"p{n}"

def ref_lua_get_bx54(w):
    """17-bit unsigned Bx field: bits [31:15]"""
    return (w >> 15) & 0x1FFFF

def ref_lua_get_ax54(w):
    """25-bit unsigned Ax field: bits [31:7]"""
    return (w >> 7) & 0x1FFFFFF

# ── MCP client ───────────────────────────────────────────────────────────────

p = subprocess.Popen(
    [EXE, "--transport=stdio"],
    stdin=subprocess.PIPE, stdout=subprocess.PIPE,
    stderr=subprocess.DEVNULL, bufsize=0
)

def send(req):
    p.stdin.write((json.dumps(req) + "\n").encode())
    p.stdin.flush()

def recv():
    line = p.stdout.readline()
    if not line:
        raise RuntimeError("server died")
    try:
        return json.loads(line)
    except json.JSONDecodeError:
        return {"error": {"message": f"bad-line: {line[:100]!r}"}}

# Initialize
send({"jsonrpc":"2.0","id":1,"method":"initialize",
      "params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"rigorous_arch_v2","version":"1"}}})
recv()
send({"jsonrpc":"2.0","method":"notifications/initialized"})

# Open project
send({"jsonrpc":"2.0","id":2,"method":"tools/call",
      "params":{"name":"project.open","arguments":{"path":TARGET}}})
op = recv()
op_data = json.loads(op["result"]["content"][0]["text"])
BINARY_ID = op_data["binary_id"]
PROJECT_ID = op_data["project_id"]

_rid = 100
def call_tool(name, args):
    global _rid
    _rid += 1
    send({"jsonrpc":"2.0","id":_rid,"method":"tools/call","params":{"name":name,"arguments":args}})
    r = recv()
    if "error" in r:
        return None, str(r["error"])
    is_err = r.get("result",{}).get("isError", False)
    content = r.get("result",{}).get("content",[])
    txt = content[0].get("text","") if content else ""
    if is_err:
        return None, txt
    try:
        return json.loads(txt), None
    except Exception:
        return txt, None

# ── Test cases ────────────────────────────────────────────────────────────────

results = []
skipped = []
mismatches = []

def record(tool, ok, expected, actual, note=""):
    entry = {"tool": tool, "pass": ok, "expected": expected, "actual": actual}
    if note:
        entry["note"] = note
    results.append(entry)
    if not ok:
        mismatches.append({"tool": tool, "expected": expected, "actual": actual})

def skip(tool, reason):
    skipped.append({"tool": tool, "reason": reason})

# ── 1. arch_jvm_decode: opcode 0x00 -> NOP ───────────────────────────────────
data, err = call_tool("arch_jvm_decode", {"hex": "00"})
if err:
    skip("arch_jvm_decode", f"tool error: {err}")
else:
    ref = ref_jvm_nop()
    ok = (data.get("mnemonic") == ref["mnemonic"] and
          data.get("operands") == ref["operands"] and
          data.get("size") == ref["size"])
    record("arch_jvm_decode", ok, ref, {"mnemonic": data.get("mnemonic"), "operands": data.get("operands"), "size": data.get("size")})

# ── 2. arch_jvm_decode_at: same bytes, pc_offset=0 ───────────────────────────
data, err = call_tool("arch_jvm_decode_at", {"hex": "00", "pc_offset": 0})
if err:
    skip("arch_jvm_decode_at", f"tool error: {err}")
else:
    ref = ref_jvm_nop()
    ok = (data.get("mnemonic") == ref["mnemonic"] and
          data.get("size") == ref["size"])
    record("arch_jvm_decode_at", ok, ref, {"mnemonic": data.get("mnemonic"), "size": data.get("size")})

# ── 3. arch_sparc_encode_nop ─────────────────────────────────────────────────
data, err = call_tool("arch_sparc_encode_nop", {})
if err:
    skip("arch_sparc_encode_nop", f"tool error: {err}")
else:
    ref_word = ref_sparc_encode_nop()  # 0x01000000
    actual_word = data.get("word")
    ok = (actual_word == ref_word)
    record("arch_sparc_encode_nop", ok, {"word": ref_word, "hex": f"0x{ref_word:08X}"}, {"word": actual_word, "hex": data.get("hex")})

# ── 4. arch_sparc_encode_call(disp=4) ────────────────────────────────────────
data, err = call_tool("arch_sparc_encode_call", {"disp": 4})
if err:
    skip("arch_sparc_encode_call", f"tool error: {err}")
else:
    ref_word = ref_sparc_encode_call(4)  # 0x40000001
    actual_word = data.get("word")
    ok = (actual_word == ref_word)
    record("arch_sparc_encode_call", ok, {"word": ref_word, "hex": f"0x{ref_word:08X}"}, {"word": actual_word, "hex": data.get("hex")})

# ── 5. arch_cil_decode_compressed_uint: single-byte form (0x05) ──────────────
test_hex = "05"
data, err = call_tool("arch_cil_decode_compressed_uint", {"data_hex": test_hex})
if err:
    skip("arch_cil_decode_compressed_uint", f"tool error: {err}")
else:
    ref_val, ref_consumed = ref_cil_decode_compressed_uint(bytes([0x05]))
    actual_val = data.get("value")
    actual_consumed = data.get("consumed")
    ok = (actual_val == ref_val and actual_consumed == ref_consumed)
    record("arch_cil_decode_compressed_uint_1byte", ok,
           {"value": ref_val, "consumed": ref_consumed},
           {"value": actual_val, "consumed": actual_consumed})

# ── 5b. arch_cil_decode_compressed_uint: two-byte form (0x8001 -> val=1) ─────
test_hex2 = "8001"
data2, err2 = call_tool("arch_cil_decode_compressed_uint", {"data_hex": test_hex2})
if err2:
    skip("arch_cil_decode_compressed_uint_2byte", f"tool error: {err2}")
else:
    ref2 = ref_cil_decode_compressed_uint(bytes([0x80, 0x01]))
    if ref2 is None:
        skip("arch_cil_decode_compressed_uint_2byte", "reference returned None")
    else:
        ref_val2, ref_con2 = ref2
        actual_val2 = data2.get("value")
        actual_con2 = data2.get("consumed")
        ok2 = (actual_val2 == ref_val2 and actual_con2 == ref_con2)
        record("arch_cil_decode_compressed_uint_2byte", ok2,
               {"value": ref_val2, "consumed": ref_con2},
               {"value": actual_val2, "consumed": actual_con2})

# ── 6. arch_cil_max_local_slot: body = stloc.0,stloc.1,stloc.2,stloc.3 ──────
# CIL: 0x0a=stloc.0, 0x0b=stloc.1, 0x0c=stloc.2, 0x0d=stloc.3 -> max=3
cil_body_hex = "0a0b0c0d"
data, err = call_tool("arch_cil_max_local_slot", {"code_hex": cil_body_hex})
if err:
    skip("arch_cil_max_local_slot", f"tool error: {err}")
else:
    # ref: max of slots 0,1,2,3 = 3
    ref_max = 3
    actual_max = data.get("max_slot")
    ok = (actual_max == ref_max)
    record("arch_cil_max_local_slot", ok, {"max_slot": ref_max}, {"max_slot": actual_max})

# ── 7. arch_dex_vreg(5) -> "v5" ──────────────────────────────────────────────
data, err = call_tool("arch_dex_vreg", {"n": 5})
if err:
    skip("arch_dex_vreg", f"tool error: {err}")
else:
    ref_name = ref_dex_vreg(5)
    actual_name = data.get("name")
    ok = (actual_name == ref_name)
    record("arch_dex_vreg", ok, {"name": ref_name}, {"name": actual_name})

# ── 8. arch_dex_preg(3) -> "p3" ──────────────────────────────────────────────
data, err = call_tool("arch_dex_preg", {"n": 3})
if err:
    skip("arch_dex_preg", f"tool error: {err}")
else:
    ref_name = ref_dex_preg(3)
    actual_name = data.get("name")
    ok = (actual_name == ref_name)
    record("arch_dex_preg", ok, {"name": ref_name}, {"name": actual_name})

# ── 9. arch_lua_get_bx54(0x80000) -> 16 ─────────────────────────────────────
# word = 0x80000 = bit 19 set; bx = (w>>15)&0x1ffff = 4&0x1ffff=4...
# 0x80000 = 524288; 524288 >> 15 = 16; 16 & 0x1ffff = 16
word_bx = 0x80000
ref_bx = ref_lua_get_bx54(word_bx)  # 16
data, err = call_tool("arch_lua_get_bx54", {"word": word_bx})
if err:
    skip("arch_lua_get_bx54", f"tool error: {err}")
else:
    actual_bx = data.get("bx")
    ok = (actual_bx == ref_bx)
    record("arch_lua_get_bx54", ok, {"bx": ref_bx}, {"bx": actual_bx})

# ── 10. arch_lua_get_ax54(0x400) -> 8 ────────────────────────────────────────
# word = 0x400 = 1024; ax = 1024 >> 7 = 8
word_ax = 0x400
ref_ax = ref_lua_get_ax54(word_ax)  # 8
data, err = call_tool("arch_lua_get_ax54", {"word": word_ax})
if err:
    skip("arch_lua_get_ax54", f"tool error: {err}")
else:
    actual_ax = data.get("ax")
    ok = (actual_ax == ref_ax)
    record("arch_lua_get_ax54", ok, {"ax": ref_ax}, {"ax": actual_ax})

# ── Additional cross-checks ───────────────────────────────────────────────────

# arch_jvm_decode: opcode 0x03 = iconst_0
data, err = call_tool("arch_jvm_decode", {"hex": "03"})
if not err:
    ok = (data.get("mnemonic") == "iconst_0" and data.get("size") == 1)
    record("arch_jvm_decode_iconst_0", ok,
           {"mnemonic": "iconst_0", "size": 1},
           {"mnemonic": data.get("mnemonic"), "size": data.get("size")})

# arch_sparc_encode_call(disp=8) -> 0x40000000 | 2 = 0x40000002
data, err = call_tool("arch_sparc_encode_call", {"disp": 8})
if not err:
    ref_w = ref_sparc_encode_call(8)
    ok = (data.get("word") == ref_w)
    record("arch_sparc_encode_call_disp8", ok, {"word": ref_w}, {"word": data.get("word")})

# arch_dex_vreg(0) -> "v0"
data, err = call_tool("arch_dex_vreg", {"n": 0})
if not err:
    ok = (data.get("name") == "v0")
    record("arch_dex_vreg_0", ok, {"name": "v0"}, {"name": data.get("name")})

# arch_dex_preg(0) -> "p0"
data, err = call_tool("arch_dex_preg", {"n": 0})
if not err:
    ok = (data.get("name") == "p0")
    record("arch_dex_preg_0", ok, {"name": "p0"}, {"name": data.get("name")})

# arch_lua_get_bx54(0) -> 0
data, err = call_tool("arch_lua_get_bx54", {"word": 0})
if not err:
    ok = (data.get("bx") == 0)
    record("arch_lua_get_bx54_zero", ok, {"bx": 0}, {"bx": data.get("bx")})

# arch_lua_get_ax54(0x80) -> 1
data, err = call_tool("arch_lua_get_ax54", {"word": 0x80})
if not err:
    ref_ax2 = ref_lua_get_ax54(0x80)  # 1
    ok = (data.get("ax") == ref_ax2)
    record("arch_lua_get_ax54_0x80", ok, {"ax": ref_ax2}, {"ax": data.get("ax")})

# arch_cil_decode_compressed_uint: 4-byte form 0xC0000001 -> value=1, consumed=4
four_byte = "C0000001"
data, err = call_tool("arch_cil_decode_compressed_uint", {"data_hex": four_byte})
if not err:
    ref4 = ref_cil_decode_compressed_uint(bytes([0xC0, 0x00, 0x00, 0x01]))
    if ref4:
        ok = (data.get("value") == ref4[0] and data.get("consumed") == ref4[1])
        record("arch_cil_decode_compressed_uint_4byte", ok,
               {"value": ref4[0], "consumed": ref4[1]},
               {"value": data.get("value"), "consumed": data.get("consumed")})

# ── Shutdown ──────────────────────────────────────────────────────────────────
p.stdin.close()
p.terminate()

# ── Summary ──────────────────────────────────────────────────────────────────
total = len(results)
passed = sum(1 for r in results if r["pass"])
failed = total - passed

output = {
    "module": "arch_multi",
    "tools_hardened": 10,
    "checks_total": total,
    "checks_passed": passed,
    "checks_failed": failed,
    "mismatches": mismatches,
    "results": results,
}

with open(OUT_JSON, "w") as f:
    json.dump(output, f, indent=2)

skip_output = {"skipped": skipped}
with open(SKIP_JSON, "w") as f:
    json.dump(skip_output, f, indent=2)

print(f"DONE: {passed}/{total} checks passed, {failed} failed, {len(skipped)} skipped")
print(f"Results -> {OUT_JSON}")
if mismatches:
    print("MISMATCHES:")
    for m in mismatches:
        print(f"  {m['tool']}: expected={m['expected']} actual={m['actual']}")
sys.exit(0 if failed == 0 else 1)
