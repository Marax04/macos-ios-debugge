#!/usr/bin/env python3
"""V5: exercise 4000+ tools with server auto-restart on death, chunked."""
import json, subprocess, time
from collections import Counter

EXE = r"C:\Users\Fra\Desktop\RustRE\target\release\rustre-mcp.exe"
TARGET = r"C:\Users\Fra\Desktop\Zyphora\target\release\cargo-zyphora.exe"
PDB = r"C:\Users\Fra\Desktop\Zyphora\target\release\cargo_zyphora.pdb"
OUT = r"C:\Users\Fra\Desktop\RustRE\validation\mcp_outputs\R60_ALL.json"

BINARY_ID = "bin-0001"
PROJECT_ID = "proj-0001"

def start_server():
    p = subprocess.Popen([EXE, "--transport=stdio"], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, bufsize=0)
    def send(req):
        p.stdin.write((json.dumps(req)+"\n").encode())
        p.stdin.flush()
    def recv(timeout=15):
        line = p.stdout.readline()
        if not line:
            return None
        try:
            return json.loads(line)
        except json.JSONDecodeError:
            return {"error": {"message": f"bad-line: {line[:120]!r}"}}

    send({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"v5","version":"1"}}})
    recv()
    send({"jsonrpc":"2.0","method":"notifications/initialized"})
    send({"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"project.open","arguments":{"path":TARGET}}})
    op = recv()
    return p, send, recv

p, send, recv = start_server()

# Get list once
send({"jsonrpc":"2.0","id":3,"method":"tools/list","params":{}})
tools_list = recv()["result"]["tools"]
print(f"Total: {len(tools_list)}")

def make_input(name, schema):
    props = (schema or {}).get("properties", {}) or {}
    req = (schema or {}).get("required", []) or []
    args = {}
    for pname, spec in props.items():
        t = spec.get("type")
        if pname == "binary_id": args[pname] = BINARY_ID
        elif pname == "project_id": args[pname] = PROJECT_ID
        elif pname == "session_id": args[pname] = "dbg-0001"
        elif pname in ("path","pe_path","binary_path","exe_path","input","file","file_path"): args[pname] = TARGET
        elif pname == "pdb_path": args[pname] = PDB
        elif pname in ("address","addr","va","start","addr1","addr_1"): args[pname] = 5368771180
        elif pname in ("end","addr2","addr_2"): args[pname] = 5368771260
        elif pname in ("func_addr","function_address","function_addr","function"): args[pname] = 5368771180
        elif pname in ("hex","bytes","data","key_hex","bytes_hex","input_hex"):
            args[pname] = "deadbeef00112233" if t == "string" else [0xde, 0xad, 0xbe, 0xef]
        elif pname in ("mangled","symbol"): args[pname] = "_RNvNtCs6CKzx_3foo3bar4baz"
        elif pname == "name": args[pname] = "main"
        elif pname == "count": args[pname] = 5
        elif pname in ("bits","width"): args[pname] = 64
        elif pname in ("size","length","len","limit"):
            _size_enum = spec.get("enum", [])
            args[pname] = _size_enum[0] if _size_enum else 16
        elif pname == "offset": args[pname] = 0
        elif pname == "expression": args[pname] = "x + y"
        elif pname in ("pattern","pattern_hex"): args[pname] = "deadbeef"
        elif pname == "query": args[pname] = "SELECT * FROM functions LIMIT 5"
        elif pname == "type_str": args[pname] = "int"
        elif pname == "var_name": args[pname] = "x"
        elif pname in ("direction","dir"): args[pname] = "backward"
        elif pname == "addresses": args[pname] = [5368771180]
        elif pname in ("a","b","x","y"): args[pname] = 0
        elif pname == "rule": args[pname] = 'rule test { strings: $a = "test" condition: $a }'
        elif pname == "bp_id": args[pname] = "bp-0001"
        elif pname == "line": args[pname] = "test"
        elif pname == "text": args[pname] = "hello"
        elif pname == "arch": args[pname] = "x86_64"
        elif pname in req:
            _enum_vals = spec.get("enum", [])
            if _enum_vals: args[pname] = _enum_vals[0]
            elif t == "string": args[pname] = ""
            elif t in ("integer","number"): args[pname] = 0
            elif t == "boolean": args[pname] = False
            elif t == "array": args[pname] = []
            elif t == "object": args[pname] = {}
    return args

def call_tool(name, args, rid):
    global p, send, recv
    try:
        send({"jsonrpc":"2.0","id":rid,"method":"tools/call","params":{"name":name,"arguments":args}})
        return recv()
    except (OSError, BrokenPipeError):
        # Server died — restart
        try: p.terminate()
        except: pass
        p, send, recv = start_server()
        try:
            send({"jsonrpc":"2.0","id":rid,"method":"tools/call","params":{"name":name,"arguments":args}})
            return recv()
        except Exception as e:
            return {"error":{"message":f"restart-fail: {e}"}}

results = []
rid = 100
t0 = time.time()
restarts = 0

for i, tool in enumerate(tools_list):
    name = tool["name"]
    schema = tool.get("inputSchema", {})
    args = make_input(name, schema)
    rid += 1
    resp = call_tool(name, args, rid)

    if resp is None:
        # Server died silently, restart
        restarts += 1
        try: p.terminate()
        except: pass
        p, send, recv = start_server()
        status = "SERVER_DIED"
        excerpt = ""
    elif "error" in resp:
        status = "JSONRPC_ERROR"
        excerpt = str(resp["error"])[:200]
    else:
        is_err = resp.get("result",{}).get("isError", False)
        content = resp.get("result",{}).get("content",[])
        txt = content[0].get("text","") if content else ""
        if is_err:
            status = "TOOL_ERROR"
            excerpt = txt[:200]
        elif not txt or txt == "{}":
            status = "EMPTY"
            excerpt = ""
        else:
            try:
                parsed = json.loads(txt)
                if isinstance(parsed, dict) and parsed.get("stub") is True:
                    status = "STUB"
                else:
                    status = "OK"
            except Exception:
                status = "OK_TEXT"
            excerpt = txt[:200]

    results.append({"tool":name,"status":status,"input":args,"output_excerpt":excerpt})
    if (i+1) % 500 == 0:
        elapsed = time.time() - t0
        rate = (i+1) / elapsed
        by_s = Counter(r["status"] for r in results)
        print(f"{i+1}/{len(tools_list)} rate={rate:.1f}/s elapsed={elapsed:.1f}s restarts={restarts} {dict(by_s)}")

try: p.terminate()
except: pass

with open(OUT, "w") as f:
    json.dump(results, f, indent=1)

counts = Counter(r["status"] for r in results)
print(f"\nFINAL: {dict(counts)}")
print(f"Total: {len(results)} restarts: {restarts}")
