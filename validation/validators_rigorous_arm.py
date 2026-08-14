#!/usr/bin/env python3
"""Rigorous ground-truth validator for arm_ MCP tools.

Tools covered:
  - arm_sreg_name  (VFP single-precision register name s0..s31)
  - arm_dreg_name  (VFP double-precision register name d0..d31)

Reference: the Rust arrays in crates/rustre-arch-arm/src/lib.rs are
VFP_SINGLE = ["s0".."s31"] and VFP_DOUBLE = ["d0".."d31"].  These are
simply f"s{n}" and f"d{n}" for n in 0..31, with wrap-around via (n & 0x1f).
"""
import json, subprocess, sys

EXE = r"C:\Users\Fra\Desktop\RustRE\target\release\rustre-mcp.exe"
TARGET = r"C:\Users\Fra\Desktop\Zyphora\target\release\cargo-zyphora.exe"
OUT_V2  = r"C:\Users\Fra\Desktop\RustRE\validation\rigorous_arm_v2.json"
SKIP_OUT = r"C:\Users\Fra\Desktop\RustRE\validation\skip_arm.json"

# ---------------------------------------------------------------------------
# MCP subprocess helpers (same pattern as exercise_v3.py)
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
send({"jsonrpc":"2.0","id":1,"method":"initialize",
      "params":{"protocolVersion":"2024-11-05","capabilities":{},
                "clientInfo":{"name":"rigorous_arm","version":"1"}}})
recv()
send({"jsonrpc":"2.0","method":"notifications/initialized"})

# Open project (required by server)
send({"jsonrpc":"2.0","id":2,"method":"tools/call",
      "params":{"name":"project.open","arguments":{"path":TARGET}}})
recv()  # ignore result

# ---------------------------------------------------------------------------
# Pure-Python reference implementations
# ---------------------------------------------------------------------------
VFP_SINGLE = [f"s{i}" for i in range(32)]
VFP_DOUBLE = [f"d{i}" for i in range(32)]

def ref_sreg(n: int) -> str:
    return VFP_SINGLE[n & 0x1F]

def ref_dreg(n: int) -> str:
    return VFP_DOUBLE[n & 0x1F]

# ---------------------------------------------------------------------------
# Call a tool and return the parsed JSON result (or None on error)
# ---------------------------------------------------------------------------
_rid = 100

def call_tool(name, args):
    global _rid
    _rid += 1
    send({"jsonrpc":"2.0","id":_rid,"method":"tools/call",
          "params":{"name":name,"arguments":args}})
    resp = recv()
    if "error" in resp:
        return None, str(resp["error"])
    content = resp.get("result",{}).get("content",[])
    txt = content[0].get("text","") if content else ""
    try:
        return json.loads(txt), None
    except Exception:
        return None, f"non-json: {txt[:120]}"

# ---------------------------------------------------------------------------
# Run checks
# ---------------------------------------------------------------------------
results_v2 = []
mismatches  = []
skipped     = []

def check(tool_name, args, expected_field, expected_value):
    actual, err = call_tool(tool_name, args)
    if err:
        results_v2.append({"tool": tool_name, "args": args, "status": "TOOL_ERROR", "detail": err})
        mismatches.append({"tool": tool_name, "expected": {expected_field: expected_value}, "actual": err})
        return
    got = actual.get(expected_field) if isinstance(actual, dict) else None
    if got == expected_value:
        results_v2.append({"tool": tool_name, "args": args, "status": "PASS",
                           "expected": expected_value, "actual": got})
    else:
        results_v2.append({"tool": tool_name, "args": args, "status": "FAIL",
                           "expected": expected_value, "actual": got})
        mismatches.append({"tool": tool_name,
                           "expected": {expected_field: expected_value},
                           "actual": {expected_field: got}})

# Test arm_sreg_name for all n in 0..31
for n in range(32):
    check("arm_sreg_name", {"n": n}, "name", ref_sreg(n))

# Test wrap-around: n=32 should give same as n=0
check("arm_sreg_name", {"n": 32}, "name", ref_sreg(32))

# Test arm_dreg_name for all n in 0..31
for n in range(32):
    check("arm_dreg_name", {"n": n}, "name", ref_dreg(n))

# Test wrap-around: n=33 -> d1
check("arm_dreg_name", {"n": 33}, "name", ref_dreg(33))

p.stdin.close()
p.terminate()

# ---------------------------------------------------------------------------
# Persist results
# ---------------------------------------------------------------------------
with open(OUT_V2, "w") as f:
    json.dump(results_v2, f, indent=2)

with open(SKIP_OUT, "w") as f:
    json.dump(skipped, f, indent=2)

total  = len(results_v2)
passed = sum(1 for r in results_v2 if r["status"] == "PASS")
failed = sum(1 for r in results_v2 if r["status"] in ("FAIL","TOOL_ERROR"))

print(f"TOTAL: {total}  PASS: {passed}  FAIL: {failed}  SKIP: {len(skipped)}")
if mismatches:
    print("MISMATCHES:")
    for m in mismatches:
        print(f"  {m['tool']}  expected={m['expected']}  actual={m['actual']}")

# Emit structured result for parent workflow
summary = {
    "category": "arm",
    "tools_hardened": 2,
    "tools_passed": passed // max(1, total // 2),  # will be overwritten below
    "tools_failed": 0,
    "tools_skipped": 0,
    "mismatches": mismatches,
}
# recount by tool
tools_seen = set()
tools_ok   = set()
tools_bad  = set()
for r in results_v2:
    t = r["tool"]
    tools_seen.add(t)
    if r["status"] == "PASS":
        tools_ok.add(t)
    else:
        tools_bad.add(t)

summary["tools_passed"]  = len(tools_ok - tools_bad)
summary["tools_failed"]  = len(tools_bad)
summary["tools_skipped"] = len(skipped)

print(json.dumps(summary))
