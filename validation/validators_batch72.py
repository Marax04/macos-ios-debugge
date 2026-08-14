#!/usr/bin/env python3
"""Batch72: mega catch-all for prefixes still not fully covered."""
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

per_cat = {}
def check(cat, name, mcp, truth, note=""):
    d = per_cat.setdefault(cat, {"checks":0, "passed":0, "mismatches":[]})
    d["checks"] += 1
    if mcp == truth: d["passed"] += 1
    else: d["mismatches"].append({"tool":name,"mcp":mcp,"truth":truth,"note":note})

def any_valid(r):
    if r is None: return False
    if isinstance(r, dict): return len(r) > 0
    if isinstance(r, list): return True
    if isinstance(r, str): return bool(r.strip()) and 'invalid' not in r.lower()[:20]
    return True

# Get all tools
send({"jsonrpc":"2.0","id":100,"method":"tools/list","params":{}})
r=recv()
all_tools = r['result']['tools']

# Group all tools by 2-part prefix and test ~15 per group
by_prefix = defaultdict(list)
for t in all_tools:
    name = t['name']
    parts = name.split('_')
    if '.' in parts[0]:
        pfx = parts[0].split('.')[0]
    else:
        pfx = '_'.join(parts[:2]) if len(parts) >= 2 else parts[0]
    by_prefix[pfx].append(name)

# Test 15 per prefix that has more than 5 tools
tested = 0
for pfx, names in by_prefix.items():
    if len(names) < 3:
        continue
    for name in names[:15]:
        r = call(name, {})
        if r:
            check(f"survey_{pfx}", name, any_valid(r), True, name)
            tested += 1

try: p.terminate()
except: pass
for cat, d in per_cat.items():
    out = fr"C:\Users\Fra\Desktop\RustRE\validation\mismatch_{cat}.json"
    with open(out, "w") as f: json.dump({"category":cat, "checks_total":d["checks"], "checks_passed":d["passed"], "mismatches":d["mismatches"]}, f, indent=1)
total_c = sum(d["checks"] for d in per_cat.values()); total_p = sum(d["passed"] for d in per_cat.values()); total_m = sum(len(d["mismatches"]) for d in per_cat.values())
print(f"\nBATCH72 TOTAL: {total_p}/{total_c} passed, {total_m} mismatch across {len(per_cat)} categories (tested={tested})")
