#!/usr/bin/env python3
"""
Rigorous ground-truth validator for avr_* MCP tools.
AVR instruction encodings are fixed constants per the AVR ISA spec:
  NOP  = 0x0000  (all zero bits)
  RET  = 0x9508  (opcode 1001 0101 0000 1000)
"""
import json, subprocess, sys

EXE = r"C:\Users\Fra\Desktop\RustRE\target\release\rustre-mcp.exe"
TARGET = r"C:\Users\Fra\Desktop\Zyphora\target\release\cargo-zyphora.exe"
OUT_JSON = r"C:\Users\Fra\Desktop\RustRE\validation\rigorous_avr_v2.json"

# Ground truth from AVR ISA spec / rustre-arch-avr encode_nop/encode_ret constants
GROUND_TRUTH = {
    "avr_encode_nop": {"word": 0x0000, "hex": "0000"},
    "avr_encode_ret": {"word": 0x9508, "hex": "9508"},
}

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

# Handshake
send({"jsonrpc":"2.0","id":1,"method":"initialize",
      "params":{"protocolVersion":"2024-11-05","capabilities":{},
                "clientInfo":{"name":"rigorous_avr","version":"1"}}})
recv()
send({"jsonrpc":"2.0","method":"notifications/initialized"})

# Open project (required by server)
send({"jsonrpc":"2.0","id":2,"method":"tools/call",
      "params":{"name":"project.open","arguments":{"path":TARGET}}})
recv()

results = []
mismatches = []

for rid, (tool_name, expected) in enumerate(GROUND_TRUTH.items(), start=10):
    send({"jsonrpc":"2.0","id":rid,"method":"tools/call",
          "params":{"name":tool_name,"arguments":{}}})
    resp = recv()

    if "error" in resp:
        results.append({"tool": tool_name, "status": "JSONRPC_ERROR",
                        "detail": str(resp["error"])})
        mismatches.append({"tool": tool_name, "expected": expected,
                           "actual": f"JSONRPC_ERROR: {resp['error']}"})
        continue

    content = resp.get("result", {}).get("content", [])
    is_err = resp.get("result", {}).get("isError", False)
    txt = content[0].get("text", "") if content else ""

    if is_err:
        results.append({"tool": tool_name, "status": "TOOL_ERROR", "detail": txt})
        mismatches.append({"tool": tool_name, "expected": expected,
                           "actual": f"TOOL_ERROR: {txt}"})
        continue

    try:
        actual = json.loads(txt)
    except json.JSONDecodeError:
        results.append({"tool": tool_name, "status": "PARSE_ERROR", "detail": txt})
        mismatches.append({"tool": tool_name, "expected": expected, "actual": txt})
        continue

    # Ground-truth comparison (exact)
    word_ok = actual.get("word") == expected["word"]
    hex_ok  = actual.get("hex", "").upper() == expected["hex"].upper()

    if word_ok and hex_ok:
        results.append({"tool": tool_name, "status": "PASS",
                        "expected": expected, "actual": actual})
    else:
        results.append({"tool": tool_name, "status": "FAIL",
                        "expected": expected, "actual": actual})
        mismatches.append({"tool": tool_name,
                           "expected": expected,
                           "actual": actual})

p.stdin.close()
p.terminate()

with open(OUT_JSON, "w") as f:
    json.dump(results, f, indent=2)

passed  = sum(1 for r in results if r["status"] == "PASS")
failed  = sum(1 for r in results if r["status"] == "FAIL")
skipped = 0

summary = {
    "category": "avr",
    "tools_hardened": len(GROUND_TRUTH),
    "tools_passed": passed,
    "tools_failed": failed,
    "tools_skipped": skipped,
    "mismatches": mismatches,
}
print(json.dumps(summary, indent=2))

# Also write summary for the StructuredOutput
with open(r"C:\Users\Fra\Desktop\RustRE\validation\rigorous_avr_v2_summary.json", "w") as f:
    json.dump(summary, f, indent=2)
