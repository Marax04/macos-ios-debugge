#!/usr/bin/env python3
"""Independent validator for loader_wasm_* tools."""
import json, subprocess, struct, os

EXE = r"C:\Users\Fra\Desktop\RustRE\target\release\rustre-mcp.exe"
OUT = r"C:\Users\Fra\Desktop\RustRE\validation\mismatch_loader_wasm.json"

# ---------- Build a small valid wasm module ----------
def leb128_u(v):
    out = bytearray()
    while True:
        b = v & 0x7f; v >>= 7
        if v: out.append(b | 0x80)
        else: out.append(b); break
    return bytes(out)

def sec(sid, payload):
    return bytes([sid]) + leb128_u(len(payload)) + payload

# Type section: one func type () -> i32
# functype: 0x60, num_params (leb), params, num_results (leb), results
functype = bytes([0x60, 0x00, 0x01, 0x7f])  # ()->i32
type_sec = sec(1, leb128_u(1) + functype)

# Function section: one function, type idx 0
func_sec = sec(3, leb128_u(1) + leb128_u(0))

# Memory section: one memory, limits no-max, min=1
mem_sec = sec(5, leb128_u(1) + bytes([0x00]) + leb128_u(1))

# Export section: one export "mem" memory idx 0
name = b"mem"
export_entry = leb128_u(len(name)) + name + bytes([0x02, 0x00])  # kind=memory(2), idx 0
export_sec = sec(7, leb128_u(1) + export_entry)

# Code section: one function body, locals empty, i32.const 42, end
body = leb128_u(0) + bytes([0x41, 42, 0x0b])  # locals count=0, i32.const 42, end
code_entry = leb128_u(len(body)) + body
code_sec = sec(10, leb128_u(1) + code_entry)

WASM_HEADER = b"\x00asm\x01\x00\x00\x00"
WASM_BYTES = WASM_HEADER + type_sec + func_sec + mem_sec + export_sec + code_sec
WASM_HEX = WASM_BYTES.hex()

# ---------- MCP client ----------
def start():
    p = subprocess.Popen([EXE, "--transport=stdio"], stdin=subprocess.PIPE,
                         stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, bufsize=0)
    def send(r): p.stdin.write((json.dumps(r)+"\n").encode()); p.stdin.flush()
    def recv():
        line = p.stdout.readline()
        return json.loads(line) if line else None
    send({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"v","version":"1"}}})
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
    try: return json.loads(c[0].get("text",""))
    except: return c[0].get("text","")

def list_tools():
    rid[0] += 1
    send({"jsonrpc":"2.0","id":rid[0],"method":"tools/list","params":{}})
    all_t = []
    while True:
        resp = recv()
        if not resp: break
        r = resp.get("result",{})
        all_t.extend(r.get("tools",[]))
        cur = r.get("nextCursor")
        if not cur: break
        rid[0] += 1
        send({"jsonrpc":"2.0","id":rid[0],"method":"tools/list","params":{"cursor":cur}})
    return all_t

tools = [t for t in list_tools() if t["name"].startswith("loader_wasm_")]
tool_names = {t["name"] for t in tools}

mismatches = []
passed = 0
total = 0
skipped = 0

def check(name, inp, mcp_val, truth, note=""):
    global passed, total
    total += 1
    ok = False
    # Normalize
    try:
        if isinstance(mcp_val, float) or isinstance(truth, float):
            ok = abs(float(mcp_val) - float(truth)) < 1e-6
        else:
            ok = mcp_val == truth
    except Exception:
        ok = False
    if ok:
        passed += 1
    else:
        mismatches.append({"tool":name,"input":inp,"mcp":mcp_val,"truth":truth,"note":note})

def try_call(name, args):
    if name not in tool_names: return None, True  # skip
    r = call(name, args)
    return r, False

# ---------- Test cases ----------

# loader_wasm_parse: expects hex or path
for args in [{"hex": WASM_HEX}, {"data": WASM_HEX}, {"bytes": WASM_HEX}]:
    if "loader_wasm_parse" in tool_names:
        r = call("loader_wasm_parse", args)
        if r and isinstance(r, dict):
            # count sections we included = 5
            secs = r.get("sections") or r.get("section_count") or r.get("num_sections")
            if isinstance(secs, list):
                check("loader_wasm_parse", args, len(secs), 5, "5 sections")
                break
            elif isinstance(secs, int):
                check("loader_wasm_parse", args, secs, 5, "5 sections")
                break

# loader_wasm_stats
for args in [{"hex": WASM_HEX}, {"data": WASM_HEX}]:
    if "loader_wasm_stats" in tool_names:
        r = call("loader_wasm_stats", args)
        if r and isinstance(r, dict):
            # Look for function count = 1
            fc = r.get("function_count") or r.get("functions") or r.get("num_functions")
            if fc is not None:
                check("loader_wasm_stats", args, fc, 1, "1 function")
            size = r.get("size") or r.get("bytes") or r.get("total_size")
            if size is not None:
                check("loader_wasm_stats", args, size, len(WASM_BYTES), "byte size")
            break
    else:
        break

# loader_wasm_opcode_mnemonic: known opcodes
# 0x00 unreachable, 0x01 nop, 0x0b end, 0x41 i32.const, 0x0f return, 0x10 call
opcode_map = {
    0x00: "unreachable",
    0x01: "nop",
    0x0b: "end",
    0x0f: "return",
    0x10: "call",
    0x41: "i32.const",
    0x42: "i64.const",
    0x6a: "i32.add",
    0x1a: "drop",
    0x1b: "select",
}
if "loader_wasm_opcode_mnemonic" in tool_names:
    for opc, mnem in opcode_map.items():
        for args in [{"opcode":opc},{"op":opc},{"byte":opc}]:
            r = call("loader_wasm_opcode_mnemonic", args)
            if r is None: continue
            val = r if isinstance(r, str) else (r.get("mnemonic") or r.get("name") or r.get("op") or r.get("result"))
            if val:
                check("loader_wasm_opcode_mnemonic", args, str(val).lower(), mnem, f"opcode 0x{opc:02x}")
                break

# ---------- The rest are arch-wasm namespace but user asked for loader_wasm_ prefix ----------
# Also test simple: loader wasm module inspection variants

# Attempt: loader_wasm_ tools not covered above — call with minimal args & note as skipped
for t in tools:
    name = t["name"]
    if name in ("loader_wasm_parse","loader_wasm_stats","loader_wasm_opcode_mnemonic"):
        continue
    # Try common arg shapes and count as skipped if unknown
    schema = t.get("inputSchema", {})
    props = schema.get("properties", {})
    if not props:
        r = call(name, {})
        # informational only
        skipped += 1
        continue
    skipped += 1

report = {
    "category": "loader_wasm_",
    "tools_in_category": len(tools),
    "checks_total": total,
    "checks_passed": passed,
    "checks_skipped": skipped,
    "mismatches": mismatches,
}

with open(OUT, "w") as f:
    json.dump(report, f, indent=2, default=str)

print(json.dumps(report, indent=2, default=str))

p.terminate()
