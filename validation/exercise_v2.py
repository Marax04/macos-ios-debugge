#!/usr/bin/env python3
"""V2: open project first, get binary_id, use it for binary_id-requiring tools."""
import json, subprocess

EXE = r"C:\Users\Fra\Desktop\RustRE\target\release\rustre-mcp.exe"
TARGET = r"C:\Users\Fra\Desktop\Zyphora\target\release\cargo-zyphora.exe"
PDB = r"C:\Users\Fra\Desktop\Zyphora\target\release\cargo_zyphora.pdb"
OUT = r"C:\Users\Fra\Desktop\RustRE\validation\mcp_outputs\R30v2_full.json"

p = subprocess.Popen([EXE, "--transport=stdio"], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, bufsize=0)
def send(req):
    p.stdin.write((json.dumps(req)+"\n").encode())
    p.stdin.flush()
def recv():
    return json.loads(p.stdout.readline())

send({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"v2","version":"1"}}})
recv()
send({"jsonrpc":"2.0","method":"notifications/initialized"})
send({"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}})
tools = recv()["result"]["tools"]
print(f"Tools: {len(tools)}")

# Open project
send({"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"project.open","arguments":{"path":TARGET}}})
op_resp = recv()
op_txt = op_resp["result"]["content"][0]["text"]
op_data = json.loads(op_txt)
BINARY_ID = op_data.get("binary_id","bin-0001")
PROJECT_ID = op_data.get("project_id","proj-0001")
print(f"project.open OK: binary_id={BINARY_ID}, project_id={PROJECT_ID}")

def make_input(name, schema):
    props = (schema or {}).get("properties", {}) or {}
    req = (schema or {}).get("required", []) or []
    args = {}
    for pname, spec in props.items():
        t = spec.get("type")
        if pname == "binary_id":
            args[pname] = BINARY_ID
        elif pname == "project_id":
            args[pname] = PROJECT_ID
        elif pname in ("path","pe_path","binary_path"):
            args[pname] = TARGET
        elif pname == "pdb_path":
            args[pname] = PDB
        elif pname in ("address","addr","va","start","end"):
            args[pname] = 5368771180 if "end" not in pname else 5368771200
        elif pname in ("hex","bytes","data"):
            args[pname] = "deadbeef00112233"
        elif pname in ("mangled","symbol","name"):
            args[pname] = "_RNvNtCs6CKzx_3foo3bar4baz"
        elif pname == "count":
            args[pname] = 5
        elif pname == "bits":
            args[pname] = 64
        elif pname in ("size","length"):
            args[pname] = 16
        elif pname == "expression":
            args[pname] = "(x & y) + (x | y)"
        elif pname == "pattern":
            args[pname] = "deadbeef"
        elif pname == "query":
            args[pname] = "main"
        elif pname == "type_str":
            args[pname] = "int"
        elif pname == "var_name":
            args[pname] = "x"
        elif pname in req:
            if t == "string": args[pname] = ""
            elif t == "integer" or t == "number": args[pname] = 0
            elif t == "boolean": args[pname] = False
            elif t == "array": args[pname] = []
            elif t == "object": args[pname] = {}
    return args

results = []
rid = 100
for i, tool in enumerate(tools):
    name = tool["name"]
    schema = tool.get("inputSchema", {})
    args = make_input(name, schema)
    rid += 1
    send({"jsonrpc":"2.0","id":rid,"method":"tools/call","params":{"name":name,"arguments":args}})
    resp = recv()
    if "error" in resp:
        status, excerpt = "ERROR", str(resp["error"])[:300]
    else:
        is_err = resp.get("result",{}).get("isError", False)
        content = resp.get("result",{}).get("content",[])
        txt = content[0].get("text","") if content else ""
        if is_err:
            status = "TOOL_ERROR"
            excerpt = txt[:300]
        elif not txt or txt == "{}":
            status = "EMPTY"
            excerpt = ""
        else:
            try:
                parsed = json.loads(txt)
                status = "STUB" if (isinstance(parsed, dict) and parsed.get("stub")) else "OK"
            except:
                status = "OK_TEXT"
            excerpt = txt[:300]
    results.append({"tool":name,"status":status,"input":args,"output_excerpt":excerpt})

p.stdin.close(); p.terminate()

with open(OUT,"w") as f: json.dump(results, f, indent=2)

from collections import Counter
counts = Counter(r["status"] for r in results)
print(f"\nFINAL: {dict(counts)}")
print(f"\nStill in TOOL_ERROR:")
for r in results:
    if r["status"] == "TOOL_ERROR":
        print(f"  {r['tool']:<45} -> {r['output_excerpt'][:80]}")
