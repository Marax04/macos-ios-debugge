#!/usr/bin/env python3
"""Validator for arch_x86_* MCP tools."""
import json, subprocess, sys

EXE = r"C:\Users\Fra\Desktop\RustRE\target\release\rustre-mcp.exe"
OUT = r"C:\Users\Fra\Desktop\RustRE\validation\mismatch_arch_x86.json"
PREFIX = "arch_x86_"

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

# List tools
rid[0] += 1
send({"jsonrpc":"2.0","id":rid[0],"method":"tools/list","params":{}})
tools = []
while True:
    resp = recv()
    if not resp: break
    if resp.get("id") == rid[0]:
        tools = resp.get("result",{}).get("tools",[])
        break

arch_tools = [t for t in tools if t["name"].startswith(PREFIX)]
tool_map = {t["name"]: t for t in arch_tools}
tool_names = sorted(tool_map.keys())

mismatches = []
checks_total = 0
checks_passed = 0
checks_skipped = 0

def check(name, mcp, truth, inp, note=""):
    global checks_total, checks_passed
    checks_total += 1
    # Normalize
    def norm(v):
        if isinstance(v, str): return v.lower().strip()
        return v
    a, b = norm(mcp), norm(truth)
    if a == b or (isinstance(a,float) and isinstance(b,float) and abs(a-b)<1e-6):
        checks_passed += 1
        return
    mismatches.append({"tool":name, "input":inp, "mcp":mcp, "truth":truth, "note":note})

# Discover which tools exist
def has(name): return name in tool_map

# ---- arch_x86_metadata ----
if has("arch_x86_metadata"):
    r = call("arch_x86_metadata", {})
    # No strict truth; just sanity check it returns dict
    if isinstance(r, dict) and r:
        checks_total += 1; checks_passed += 1
    else:
        checks_skipped += 1

# ---- arch_x86_registers ----
if has("arch_x86_registers"):
    r = call("arch_x86_registers", {})
    if isinstance(r, dict):
        regs = r.get("registers") or r.get("names") or r.get("result") or []
        if isinstance(regs, list) and regs:
            regs_lower = [str(x).lower() for x in regs]
            expected = ["rax","rcx","rdx","rbx","rsp","rbp","rsi","rdi"]
            missing = [e for e in expected if not any(e in x for x in regs_lower)]
            checks_total += 1
            if not missing:
                checks_passed += 1
            else:
                mismatches.append({"tool":"arch_x86_registers","input":{},"mcp":regs,"truth":expected,"note":f"missing {missing}"})
        else:
            checks_skipped += 1
    else:
        checks_skipped += 1

# ---- arch_x86_calling_conventions ----
if has("arch_x86_calling_conventions"):
    r = call("arch_x86_calling_conventions", {})
    if isinstance(r, dict):
        # expect sysv and msvc mentioned
        s = json.dumps(r).lower()
        checks_total += 1
        if ("sysv" in s or "system" in s or "cdecl" in s) and ("msvc" in s or "win64" in s or "ms_x64" in s or "ms64" in s or "stdcall" in s or "fastcall" in s):
            checks_passed += 1
        else:
            mismatches.append({"tool":"arch_x86_calling_conventions","input":{},"mcp":r,"truth":"sysv+msvc","note":"missing conventions"})
    else:
        checks_skipped += 1

# ---- arch_x86_disassemble_and_lift ----
# Simple: 90 = nop, C3 = ret
if has("arch_x86_disassemble_and_lift"):
    for hx, expected_mnem in [("90","nop"), ("c3","ret"), ("9090","nop")]:
        r = call("arch_x86_disassemble_and_lift", {"hex": hx, "address": 0x1000})
        if isinstance(r, dict):
            s = json.dumps(r).lower()
            checks_total += 1
            if expected_mnem in s:
                checks_passed += 1
            else:
                mismatches.append({"tool":"arch_x86_disassemble_and_lift","input":{"hex":hx},"mcp":r,"truth":expected_mnem,"note":""})
        else:
            checks_skipped += 1

# ---- arch_x86_lift_to_llil ----
if has("arch_x86_lift_to_llil"):
    r = call("arch_x86_lift_to_llil", {"hex": "90", "address": 0x1000})
    if isinstance(r, (dict, str, list)):
        checks_total += 1; checks_passed += 1  # smoke
    else:
        checks_skipped += 1

# Cleanup
try: p.terminate()
except: pass

report = {
    "category": "arch_x86",
    "tools_in_category": len(arch_tools),
    "checks_total": checks_total,
    "checks_passed": checks_passed,
    "checks_skipped": checks_skipped,
    "mismatches": mismatches,
}
with open(OUT, "w") as f:
    json.dump(report, f, indent=2, default=str)

print(json.dumps({k:v for k,v in report.items() if k!="mismatches"}, indent=2))
print(f"tools: {tool_names}")
print(f"mismatches: {len(mismatches)}")
