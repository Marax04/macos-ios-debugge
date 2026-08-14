#!/usr/bin/env python3
"""Validator for forensics_compute_* tools."""
import json, subprocess, hashlib, sys

EXE = r"C:\Users\Fra\Desktop\RustRE\target\release\rustre-mcp.exe"
OUT = r"C:\Users\Fra\Desktop\RustRE\validation\mismatch_forensics_compute.json"
PREFIX = "forensics_compute_"

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
    if not resp: return ("no_resp", None)
    if "error" in resp: return ("err", resp["error"])
    c = resp.get("result",{}).get("content",[])
    if not c: return ("empty", None)
    txt = c[0].get("text","")
    try: return ("ok", json.loads(txt))
    except: return ("ok", txt)

# List tools
rid[0] += 1
send({"jsonrpc":"2.0","id":rid[0],"method":"tools/list","params":{}})
listing = recv()
tools = [t for t in listing.get("result",{}).get("tools",[]) if t["name"].startswith(PREFIX)]
print(f"Found {len(tools)} tools with prefix {PREFIX}")
for t in tools:
    print(" -", t["name"])

mismatches = []
passed = 0
skipped = 0
checked = 0

HASH_MAP = {
    "forensics_compute_md5":    hashlib.md5,
    "forensics_compute_sha1":   hashlib.sha1,
    "forensics_compute_sha256": hashlib.sha256,
    "forensics_compute_sha512": hashlib.sha512,
}

# Multiple test inputs
INPUTS = [
    "hello world",
    "",
    "The quick brown fox jumps over the lazy dog",
    "a"*1000,
    "123456789",
]

for tool in tools:
    name = tool["name"]
    if name not in HASH_MAP:
        skipped += 1
        print(f"SKIP {name}: no ground truth mapping")
        continue
    hf = HASH_MAP[name]
    for data in INPUTS:
        truth = hf(data.encode("utf-8")).hexdigest()
        status, r = call(name, {"hex": data.encode("utf-8").hex()})
        checked += 1
        if status != "ok" or not isinstance(r, dict):
            mismatches.append({"tool":name, "input":data[:40], "mcp":str(r)[:200], "truth":truth,
                               "note":f"non-ok status={status}"})
            continue
        val = (r.get("digest") or r.get("hash") or r.get("hex") or
               r.get("md5") or r.get("sha1") or r.get("sha256") or r.get("sha512") or
               r.get("result") or r.get("value") or "")
        if isinstance(val, str):
            val = val.lower()
        if val == truth:
            passed += 1
        else:
            mismatches.append({"tool":name, "input":data[:40], "mcp":val, "truth":truth,
                               "note":"digest disagrees with hashlib"})

try: p.terminate()
except: pass

report = {
    "category": "forensics_compute",
    "tools_in_category": len(tools),
    "checks_total": checked,
    "checks_passed": passed,
    "checks_skipped": skipped,
    "mismatches": mismatches,
}
with open(OUT, "w") as f: json.dump(report, f, indent=2)
print(json.dumps({k:v for k,v in report.items() if k!="mismatches"}, indent=2))
print(f"Mismatches: {len(mismatches)}")
for m in mismatches[:10]:
    print(" ", m)
