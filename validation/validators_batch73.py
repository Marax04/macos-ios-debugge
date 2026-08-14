#!/usr/bin/env python3
"""Batch73: FULL COVERAGE - test EVERY single tool with empty args."""
import json, subprocess
from collections import defaultdict

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

# Get all tools
send({"jsonrpc":"2.0","id":100,"method":"tools/list","params":{}})
r=recv()
all_tools = r['result']['tools']
total = len(all_tools)

results = {"ok":0, "empty":0, "tool_error":0, "no_response":0, "total":total, "per_status":defaultdict(int)}
for t in all_tools:
    name = t['name']
    r = call(name, {})
    if r is None:
        results["no_response"] += 1
    elif isinstance(r, dict):
        if "error" in str(r).lower()[:60]:
            results["tool_error"] += 1
        elif len(r) == 0:
            results["empty"] += 1
        else:
            results["ok"] += 1
    elif isinstance(r, list):
        results["ok"] += 1
    elif isinstance(r, str):
        if r.strip() and 'invalid' not in r.lower()[:20]:
            if 'execution failed' in r.lower():
                results["tool_error"] += 1
            else:
                results["ok"] += 1
        else:
            results["empty"] += 1
    else:
        results["ok"] += 1

try: p.terminate()
except: pass

del results["per_status"]

# Save comprehensive
with open(r"C:\Users\Fra\Desktop\RustRE\validation\FULL_COVERAGE_REPORT.json", "w") as f:
    json.dump(results, f, indent=2)

print(f"FULL COVERAGE: {results['ok']} ok, {results['empty']} empty, {results['tool_error']} tool_error, {results['no_response']} no_response, total={results['total']}")
print(f"OK rate: {results['ok']/results['total']*100:.1f}%")
print(f"Non-crash rate: {(results['ok']+results['empty']+results['tool_error'])/results['total']*100:.1f}%")
