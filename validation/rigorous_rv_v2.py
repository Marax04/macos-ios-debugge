#!/usr/bin/env python3
"""
Rigorous ground-truth validation for MCP tools prefixed with 'rv_'.
Computes expected outputs using inline Python reference implementations,
calls the MCP server via json-rpc-over-stdio (same pattern as exercise_v3.py),
and records pass/fail in rigorous_rv_v2.json.
"""
import json, subprocess, sys

EXE = r"C:\Users\Fra\Desktop\RustRE\target\release\rustre-mcp.exe"
TARGET = r"C:\Users\Fra\Desktop\Zyphora\target\release\cargo-zyphora.exe"
OUT_JSON = r"C:\Users\Fra\Desktop\RustRE\validation\rigorous_rv_v2.json"
SKIP_JSON = r"C:\Users\Fra\Desktop\RustRE\validation\skip_rv.json"

# ---------------------------------------------------------------------------
# Python reference implementations (inline, no shelling out)
# ---------------------------------------------------------------------------

def ref_rv_brev8_32(val: int) -> dict:
    """
    RISC-V brev8: bit-reverse each byte independently within a 32-bit word.
    Algorithm: extract each byte, reverse its 8 bits, reassemble as little-endian.
    """
    val = val & 0xFFFF_FFFF  # clamp to u32
    b0 = int('{:08b}'.format((val >> 0) & 0xFF)[::-1], 2)
    b1 = int('{:08b}'.format((val >> 8) & 0xFF)[::-1], 2)
    b2 = int('{:08b}'.format((val >> 16) & 0xFF)[::-1], 2)
    b3 = int('{:08b}'.format((val >> 24) & 0xFF)[::-1], 2)
    out = (b3 << 24) | (b2 << 16) | (b1 << 8) | b0
    return {"input": val, "output": out, "hex": f"{out:08X}"}

def ref_rv_c_classify(hw: int) -> dict:
    """
    Classify a 16-bit RISC-V compressed instruction by op quadrant (bits[1:0])
    and funct3 (bits[15:13]).
    """
    hw = hw & 0xFFFF
    op     = hw & 0x3
    funct3 = (hw >> 13) & 0x7
    table = {
        (0, 0): "c.addi4spn",
        (0, 1): "c.fld",
        (0, 2): "c.lw",
        (0, 3): "c.flw",
        (0, 5): "c.fsd",
        (0, 6): "c.sw",
        (0, 7): "c.fsw",
        (1, 0): "c.nop/c.addi",
        (1, 1): "c.jal",
        (1, 2): "c.li",
        (1, 3): "c.addi16sp/c.lui",
        (1, 4): "c.misc-alu",
        (1, 5): "c.j",
        (1, 6): "c.beqz",
        (1, 7): "c.bnez",
        (2, 0): "c.slli",
        (2, 1): "c.fldsp",
        (2, 2): "c.lwsp",
        (2, 3): "c.flwsp",
        (2, 4): "c.jr/c.mv/c.jalr/c.add",
        (2, 5): "c.fsdsp",
        (2, 6): "c.swsp",
        (2, 7): "c.fswsp",
    }
    cls = table.get((op, funct3), "c.unknown")
    return {"hw": hw, "class": cls}

# ---------------------------------------------------------------------------
# Test vectors — chosen to exercise boundary and interior cases
# ---------------------------------------------------------------------------

TEST_CASES = [
    # tool_name, args_to_send, ref_fn, args_to_ref
    ("rv_brev8_32", {"val": 0x00000000}, ref_rv_brev8_32, (0x00000000,)),
    ("rv_brev8_32", {"val": 0xFFFFFFFF}, ref_rv_brev8_32, (0xFFFFFFFF,)),
    ("rv_brev8_32", {"val": 0x01020304}, ref_rv_brev8_32, (0x01020304,)),
    ("rv_brev8_32", {"val": 0xDEADBEEF}, ref_rv_brev8_32, (0xDEADBEEF,)),
    ("rv_brev8_32", {"val": 0xA5A5A5A5}, ref_rv_brev8_32, (0xA5A5A5A5,)),
    # rv_c_classify test vectors: encode op=0,funct3=0 → c.addi4spn
    ("rv_c_classify", {"hw": 0x0000}, ref_rv_c_classify, (0x0000,)),  # op=0,f3=0 → c.addi4spn
    ("rv_c_classify", {"hw": 0x2000}, ref_rv_c_classify, (0x2000,)),  # op=0,f3=1 → c.fld
    ("rv_c_classify", {"hw": 0x4000}, ref_rv_c_classify, (0x4000,)),  # op=0,f3=2 → c.lw
    ("rv_c_classify", {"hw": 0x4001}, ref_rv_c_classify, (0x4001,)),  # op=1,f3=2 → c.li
    ("rv_c_classify", {"hw": 0x8004}, ref_rv_c_classify, (0x8004,)),  # op=0,f3=4 → c.unknown
    ("rv_c_classify", {"hw": 0xC802}, ref_rv_c_classify, (0xC802,)),  # op=2,f3=6 → c.swsp
    ("rv_c_classify", {"hw": 0xE002}, ref_rv_c_classify, (0xE002,)),  # op=2,f3=7 → c.fswsp
]

# ---------------------------------------------------------------------------
# MCP stdio helpers (same pattern as exercise_v3.py)
# ---------------------------------------------------------------------------

p = subprocess.Popen(
    [EXE, "--transport=stdio"],
    stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, bufsize=0
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

# Handshake
send({"jsonrpc":"2.0","id":1,"method":"initialize","params":{
    "protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"rigorous_rv","version":"1"}}})
recv()
send({"jsonrpc":"2.0","method":"notifications/initialized"})

# Open project (required by the server)
send({"jsonrpc":"2.0","id":2,"method":"tools/call","params":{
    "name":"project.open","arguments":{"path":TARGET}}})
recv()  # consume project.open result

# ---------------------------------------------------------------------------
# Run test cases
# ---------------------------------------------------------------------------

results = []
skips = []
rid = 100

for (tool, mcp_args, ref_fn, ref_args) in TEST_CASES:
    rid += 1
    send({"jsonrpc":"2.0","id":rid,"method":"tools/call","params":{"name":tool,"arguments":mcp_args}})
    resp = recv()

    expected = ref_fn(*ref_args)

    if "error" in resp:
        results.append({
            "tool": tool, "args": mcp_args,
            "status": "FAIL",
            "reason": f"JSONRPC_ERROR: {resp['error']}",
            "expected": expected, "actual": None
        })
        continue

    is_err = resp.get("result", {}).get("isError", False)
    content = resp.get("result", {}).get("content", [])
    txt = content[0].get("text", "") if content else ""

    if is_err:
        results.append({
            "tool": tool, "args": mcp_args,
            "status": "FAIL",
            "reason": f"TOOL_ERROR: {txt[:300]}",
            "expected": expected, "actual": None
        })
        continue

    try:
        actual = json.loads(txt)
    except Exception as e:
        results.append({
            "tool": tool, "args": mcp_args,
            "status": "FAIL",
            "reason": f"BAD_JSON: {e}",
            "expected": expected, "actual": txt[:300]
        })
        continue

    # Compare key fields
    mismatches = {}
    for k, v in expected.items():
        if k not in actual:
            mismatches[k] = {"expected": v, "actual": "<missing>"}
        elif actual[k] != v:
            mismatches[k] = {"expected": v, "actual": actual[k]}

    if mismatches:
        results.append({
            "tool": tool, "args": mcp_args,
            "status": "FAIL",
            "reason": "value mismatch",
            "expected": expected, "actual": actual,
            "mismatches": mismatches
        })
    else:
        results.append({
            "tool": tool, "args": mcp_args,
            "status": "PASS",
            "expected": expected, "actual": actual
        })

p.stdin.close()
p.terminate()

# ---------------------------------------------------------------------------
# Write outputs
# ---------------------------------------------------------------------------

with open(OUT_JSON, "w") as f:
    json.dump(results, f, indent=2)

with open(SKIP_JSON, "w") as f:
    json.dump(skips, f, indent=2)

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------

passed = sum(1 for r in results if r["status"] == "PASS")
failed = sum(1 for r in results if r["status"] == "FAIL")
print(f"rv_ tools: {passed} PASS, {failed} FAIL, {len(skips)} SKIP")
for r in results:
    mark = "OK" if r["status"] == "PASS" else "FAIL"
    print(f"  [{mark}] {r['tool']} {r['args']} -> {r.get('reason','')}")
