#!/usr/bin/env python3
"""Re-run the 54 errors and capture the actual error message."""
import json, subprocess

EXE = r"C:\Users\Fra\Desktop\RustRE\target\release\rustre-mcp.exe"
TARGET = r"C:\Users\Fra\Desktop\Zyphora\target\release\cargo-zyphora.exe"
PDB = r"C:\Users\Fra\Desktop\Zyphora\target\release\cargo_zyphora.pdb"

with open(r"C:\Users\Fra\Desktop\RustRE\validation\mcp_outputs\R30_full_exercise.json") as f:
    results = json.load(f)
err_tools = [r["tool"] for r in results if "ERROR" in r["status"]]
print(f"Re-running {len(err_tools)} errored tools to capture messages")

def make_input(schema):
    props = (schema or {}).get("properties", {}) or {}
    req = (schema or {}).get("required", []) or []
    args = {}
    for name, spec in props.items():
        t = spec.get("type")
        if name in ("path","pe_path","binary_path"):
            args[name] = TARGET
        elif name == "pdb_path":
            args[name] = PDB
        elif name in ("address","addr","va"):
            args[name] = 5368771180
        elif name in ("hex","bytes","data"):
            args[name] = "deadbeef00112233"
        elif name in ("mangled","symbol"):
            args[name] = "_RNvNtCs6CKzx_3foo3bar4baz"
        elif name == "count":
            args[name] = 5
        elif name == "bits":
            args[name] = 64
        elif name == "expression":
            args[name] = "(x & y) + (x | y)"
        elif name in req:
            if t == "string": args[name] = ""
            elif t == "integer" or t == "number": args[name] = 0
            elif t == "boolean": args[name] = False
            elif t == "array": args[name] = []
            elif t == "object": args[name] = {}
    return args

p = subprocess.Popen([EXE, "--transport=stdio"], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, bufsize=0)
def send(req):
    p.stdin.write((json.dumps(req)+"\n").encode())
    p.stdin.flush()
def recv():
    line = p.stdout.readline()
    return json.loads(line) if line else None

send({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"d","version":"1"}}})
recv()
send({"jsonrpc":"2.0","method":"notifications/initialized"})
send({"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}})
tools = {t["name"]: t for t in recv()["result"]["tools"]}

errs = []
rid = 100
for name in err_tools:
    schema = tools[name].get("inputSchema", {})
    args = make_input(schema)
    rid += 1
    send({"jsonrpc":"2.0","id":rid,"method":"tools/call","params":{"name":name,"arguments":args}})
    resp = recv()
    msg = ""
    if "error" in resp:
        msg = json.dumps(resp["error"])
    else:
        content = resp.get("result",{}).get("content",[])
        if content:
            msg = content[0].get("text","")
    errs.append({"tool": name, "input": args, "message": msg[:400]})

p.stdin.close(); p.terminate()

with open(r"C:\Users\Fra\Desktop\RustRE\validation\mcp_outputs\R30_error_details.json","w") as f:
    json.dump(errs, f, indent=2)

# Categorize
cats = {"missing_required":[], "unknown_tool_or_bad_arg":[], "binary_id_required":[], "wrong_type":[], "other":[]}
for e in errs:
    m = e["message"].lower()
    if "missing" in m and ("field" in m or "required" in m):
        cats["missing_required"].append(e)
    elif "binary_id" in m or "no binary" in m or "binary not found" in m:
        cats["binary_id_required"].append(e)
    elif "invalid type" in m or "expected" in m and "but found" in m:
        cats["wrong_type"].append(e)
    elif "unknown" in m or "no such" in m:
        cats["unknown_tool_or_bad_arg"].append(e)
    else:
        cats["other"].append(e)

print("\nCategorization:")
for cat, items in cats.items():
    print(f"\n{cat}: {len(items)}")
    for it in items[:5]:
        print(f"  {it['tool']:<45} -> {it['message'][:120]}")
