#!/usr/bin/env python3
"""
Rigorous ground-truth validation for all z80_* MCP tools.
Reference: Z80 CPU User Manual opcodes (deterministic, no network).
  NOP  = 0x00
  HALT = 0x76
  RET  = 0xC9
  EI   = 0xFB
"""
import json, subprocess, sys

EXE = r"C:\Users\Fra\Desktop\RustRE\target\release\rustre-mcp.exe"
TARGET = r"C:\Users\Fra\Desktop\Zyphora\target\release\cargo-zyphora.exe"
OUT_PASS = r"C:\Users\Fra\Desktop\RustRE\validation\rigorous_z80_v2.json"
OUT_SKIP = r"C:\Users\Fra\Desktop\RustRE\validation\skip_z80.json"

# Ground-truth reference (Z80 opcode table — no external library needed)
GROUND_TRUTH = {
    "z80_encode_nop":  {"expected_bytes": [0x00], "expected_hex": "00"},
    "z80_encode_halt": {"expected_bytes": [0x76], "expected_hex": "76"},
    "z80_encode_ret":  {"expected_bytes": [0xC9], "expected_hex": "C9"},
    "z80_encode_ei":   {"expected_bytes": [0xFB], "expected_hex": "FB"},
}

p = subprocess.Popen(
    [EXE, "--transport=stdio"],
    stdin=subprocess.PIPE, stdout=subprocess.PIPE,
    stderr=subprocess.DEVNULL, bufsize=0,
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
                "clientInfo":{"name":"rigorous_z80","version":"1"}}})
recv()
send({"jsonrpc":"2.0","method":"notifications/initialized"})

# Open project (required by server)
send({"jsonrpc":"2.0","id":2,"method":"tools/call",
      "params":{"name":"project.open","arguments":{"path":TARGET}}})
recv()

results = []
mismatches = []
rid = 10

for tool_name, gt in GROUND_TRUTH.items():
    rid += 1
    send({"jsonrpc":"2.0","id":rid,"method":"tools/call",
          "params":{"name":tool_name,"arguments":{}}})
    resp = recv()

    if "error" in resp:
        entry = {"tool": tool_name, "status": "FAIL",
                 "reason": f"JSONRPC error: {resp['error']}",
                 "expected": gt, "actual": None}
        results.append(entry)
        mismatches.append({"tool": tool_name,
                            "expected": gt,
                            "actual": str(resp["error"])})
        continue

    is_err = resp.get("result", {}).get("isError", False)
    content = resp.get("result", {}).get("content", [])
    txt = content[0].get("text", "") if content else ""

    if is_err or not txt:
        entry = {"tool": tool_name, "status": "FAIL",
                 "reason": f"tool error: {txt[:200]}",
                 "expected": gt, "actual": None}
        results.append(entry)
        mismatches.append({"tool": tool_name, "expected": gt, "actual": txt})
        continue

    try:
        parsed = json.loads(txt)
    except json.JSONDecodeError as e:
        entry = {"tool": tool_name, "status": "FAIL",
                 "reason": f"JSON decode error: {e}",
                 "expected": gt, "actual": txt}
        results.append(entry)
        mismatches.append({"tool": tool_name, "expected": gt, "actual": txt})
        continue

    actual_bytes = parsed.get("bytes")
    actual_hex   = parsed.get("hex", "").upper()
    exp_bytes    = gt["expected_bytes"]
    exp_hex      = gt["expected_hex"].upper()

    if actual_bytes == exp_bytes and actual_hex == exp_hex:
        results.append({"tool": tool_name, "status": "PASS",
                        "actual_bytes": actual_bytes, "actual_hex": actual_hex})
    else:
        results.append({"tool": tool_name, "status": "FAIL",
                        "expected_bytes": exp_bytes, "expected_hex": exp_hex,
                        "actual_bytes": actual_bytes, "actual_hex": actual_hex})
        mismatches.append({"tool": tool_name,
                            "expected": gt,
                            "actual": {"bytes": actual_bytes, "hex": actual_hex}})

p.stdin.close()
p.terminate()

# Write outputs
with open(OUT_PASS, "w") as f:
    json.dump(results, f, indent=2)

skips = []  # all four tools are deterministic and independently verifiable
with open(OUT_SKIP, "w") as f:
    json.dump(skips, f, indent=2)

passed  = sum(1 for r in results if r["status"] == "PASS")
failed  = sum(1 for r in results if r["status"] == "FAIL")
skipped = len(skips)
total   = len(results)

print(f"tools_hardened={total} tools_passed={passed} tools_failed={failed} tools_skipped={skipped}")
print(f"mismatches={json.dumps(mismatches)}")
