#!/usr/bin/env python3
"""
Rigorous ground-truth validation for ppc_* MCP tools.
Tools: ppc_encode_bl, ppc_encode_lis
"""
import json, subprocess, struct

EXE = r"C:\Users\Fra\Desktop\RustRE\target\release\rustre-mcp.exe"
TARGET = r"C:\Users\Fra\Desktop\Zyphora\target\release\cargo-zyphora.exe"

# ---- Python reference implementations ----

def ref_encode_bl(disp: int) -> int:
    """BL instruction: opcode=18, li=disp&0x03FFFFFC, lk=1"""
    li = disp & 0x03FF_FFFC
    return (18 << 26) | li | 1

def ref_encode_lis(rd: int, imm: int) -> int:
    """LIS rd,imm = ADDIS rd,r0,imm: opcode=15"""
    imm_u = imm & 0xFFFF
    return (15 << 26) | ((rd & 31) << 21) | imm_u

# ---- MCP subprocess helpers ----

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
    return json.loads(line)

# Initialize
send({"jsonrpc":"2.0","id":1,"method":"initialize","params":{
    "protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"ppc-rigorous","version":"1"}
}})
recv()
send({"jsonrpc":"2.0","method":"notifications/initialized"})

# Open project
send({"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"project.open","arguments":{"path":TARGET}}})
op = recv()
op_data = json.loads(op["result"]["content"][0]["text"])
BINARY_ID = op_data["binary_id"]

def call_tool(name, args, rid):
    send({"jsonrpc":"2.0","id":rid,"method":"tools/call","params":{"name":name,"arguments":args}})
    resp = recv()
    if "error" in resp:
        return None, f"JSONRPC_ERROR: {resp['error']}"
    result = resp.get("result", {})
    if result.get("isError"):
        content = result.get("content", [{}])
        return None, f"TOOL_ERROR: {content[0].get('text','')[:200]}"
    content = result.get("content", [{}])
    txt = content[0].get("text", "")
    try:
        return json.loads(txt), None
    except Exception:
        return txt, None

results = []
mismatches = []
rid = 100

# ---- Test cases for ppc_encode_bl ----
bl_cases = [
    {"disp": 4},
    {"disp": 8},
    {"disp": -4},
    {"disp": 1024},
    {"disp": -128},
    {"disp": 0x03FFFFC},   # max positive (nearly)
]

for case in bl_cases:
    rid += 1
    data, err = call_tool("ppc_encode_bl", case, rid)
    expected_enc = ref_encode_bl(case["disp"])
    expected_hex = f"{expected_enc:08X}"

    if err:
        results.append({"tool": "ppc_encode_bl", "input": case, "status": "FAIL", "reason": err})
        mismatches.append({"tool": "ppc_encode_bl", "input": case, "expected": expected_hex, "actual": err})
    elif data is None:
        results.append({"tool": "ppc_encode_bl", "input": case, "status": "FAIL", "reason": "no data"})
        mismatches.append({"tool": "ppc_encode_bl", "input": case, "expected": expected_hex, "actual": None})
    else:
        actual_enc = data.get("encoded")
        actual_hex = data.get("hex", "")
        if actual_enc == expected_enc and actual_hex == expected_hex:
            results.append({"tool": "ppc_encode_bl", "input": case, "status": "PASS",
                            "expected_hex": expected_hex, "actual_hex": actual_hex})
        else:
            results.append({"tool": "ppc_encode_bl", "input": case, "status": "FAIL",
                            "expected_hex": expected_hex, "actual_hex": actual_hex,
                            "expected_enc": expected_enc, "actual_enc": actual_enc})
            mismatches.append({"tool": "ppc_encode_bl", "input": case,
                               "expected": expected_hex, "actual": actual_hex})

# ---- Test cases for ppc_encode_lis ----
lis_cases = [
    {"rd": 3, "imm": 1},
    {"rd": 0, "imm": 0},
    {"rd": 31, "imm": -1},
    {"rd": 3, "imm": 32767},
    {"rd": 3, "imm": -32768},
    {"rd": 10, "imm": 0x1234},
]

for case in lis_cases:
    rid += 1
    data, err = call_tool("ppc_encode_lis", case, rid)
    expected_enc = ref_encode_lis(case["rd"], case["imm"])
    expected_hex = f"{expected_enc:08X}"

    if err:
        results.append({"tool": "ppc_encode_lis", "input": case, "status": "FAIL", "reason": err})
        mismatches.append({"tool": "ppc_encode_lis", "input": case, "expected": expected_hex, "actual": err})
    elif data is None:
        results.append({"tool": "ppc_encode_lis", "input": case, "status": "FAIL", "reason": "no data"})
        mismatches.append({"tool": "ppc_encode_lis", "input": case, "expected": expected_hex, "actual": None})
    else:
        actual_enc = data.get("encoded")
        actual_hex = data.get("hex", "")
        if actual_enc == expected_enc and actual_hex == expected_hex:
            results.append({"tool": "ppc_encode_lis", "input": case, "status": "PASS",
                            "expected_hex": expected_hex, "actual_hex": actual_hex})
        else:
            results.append({"tool": "ppc_encode_lis", "input": case, "status": "FAIL",
                            "expected_hex": expected_hex, "actual_hex": actual_hex,
                            "expected_enc": expected_enc, "actual_enc": actual_enc})
            mismatches.append({"tool": "ppc_encode_lis", "input": case,
                               "expected": expected_hex, "actual": actual_hex})

p.stdin.close()
p.terminate()

# Write results
with open(r"C:\Users\Fra\Desktop\RustRE\validation\rigorous_ppc_v2.json", "w") as f:
    json.dump(results, f, indent=2)

tools_passed = sum(1 for r in results if r["status"] == "PASS")
tools_failed = sum(1 for r in results if r["status"] == "FAIL")

# Summarize per tool
tool_names = list(dict.fromkeys(r["tool"] for r in results))
tool_pass = {t: all(r["status"] == "PASS" for r in results if r["tool"] == t) for t in tool_names}

print(json.dumps({
    "category": "ppc",
    "tools_hardened": len(tool_names),
    "tools_passed": sum(1 for v in tool_pass.values() if v),
    "tools_failed": sum(1 for v in tool_pass.values() if not v),
    "tools_skipped": 0,
    "mismatches": mismatches,
    "case_pass": tools_passed,
    "case_fail": tools_failed,
}, indent=2))
