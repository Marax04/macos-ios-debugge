#!/usr/bin/env python3
"""Exercise all MCP tools on cargo-zyphora.exe and save outputs."""
import json, subprocess, sys, time

EXE = r"C:\Users\Fra\Desktop\RustRE\target\release\rustre-mcp.exe"
TARGET = r"C:\Users\Fra\Desktop\Zyphora\target\release\cargo-zyphora.exe"
PDB = r"C:\Users\Fra\Desktop\Zyphora\target\release\cargo_zyphora.pdb"
OUT = r"C:\Users\Fra\Desktop\RustRE\validation\mcp_outputs\R30_full_exercise.json"

# Test inputs by parameter name heuristic
def make_input(schema):
    """Best-effort input from JSON schema properties."""
    props = (schema or {}).get("properties", {}) or {}
    req = (schema or {}).get("required", []) or []
    args = {}
    for name, spec in props.items():
        t = spec.get("type")
        if name in ("path","pe_path","binary_path"):
            args[name] = TARGET
        elif name == "pdb_path" or (name == "path" and "pdb" in str(spec).lower()):
            args[name] = PDB
        elif name in ("address","addr","va"):
            args[name] = 5368771180  # 0x1400f206c
        elif name in ("hex","bytes","data"):
            args[name] = "deadbeef00112233"
        elif name == "mangled" or name == "symbol":
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


def main():
    p = subprocess.Popen([EXE, "--transport=stdio"], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, bufsize=0)

    def send(req):
        p.stdin.write((json.dumps(req)+"\n").encode())
        p.stdin.flush()

    def recv():
        line = p.stdout.readline()
        return json.loads(line) if line else None

    # Initialize
    send({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"ex","version":"1"}}})
    recv()
    send({"jsonrpc":"2.0","method":"notifications/initialized"})

    # Get tools
    send({"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}})
    list_resp = recv()
    tools = list_resp["result"]["tools"]
    print(f"Total tools: {len(tools)}", file=sys.stderr)

    results = []
    rid = 100
    for i, tool in enumerate(tools):
        name = tool["name"]
        schema = tool.get("inputSchema", {})
        args = make_input(schema)
        rid += 1
        send({"jsonrpc":"2.0","id":rid,"method":"tools/call","params":{"name":name,"arguments":args}})
        try:
            resp = recv()
        except Exception as e:
            resp = {"error":{"message":f"recv-fail: {e}"}}

        is_error = False
        excerpt = ""
        if resp is None:
            status = "NO_RESPONSE"
        elif "error" in resp:
            status = "ERROR"
            is_error = True
            excerpt = str(resp["error"])[:200]
        else:
            content = (resp.get("result") or {}).get("content", [])
            is_error = (resp.get("result") or {}).get("isError", False)
            if is_error:
                status = "TOOL_ERROR"
            elif not content:
                status = "EMPTY"
            else:
                txt = content[0].get("text","") if content else ""
                if not txt or txt == "{}":
                    status = "EMPTY"
                else:
                    # Try parse JSON output
                    try:
                        parsed = json.loads(txt)
                        if isinstance(parsed, dict) and parsed.get("stub") is True:
                            status = "STUB"
                        else:
                            status = "OK"
                    except:
                        status = "OK_TEXT"
                    excerpt = txt[:300]

        results.append({
            "tool": name,
            "status": status,
            "input_args": args,
            "output_excerpt": excerpt,
        })
        if i % 20 == 0:
            print(f"{i}/{len(tools)} {name}: {status}", file=sys.stderr)

    p.stdin.close()
    p.terminate()

    with open(OUT, "w") as f:
        json.dump(results, f, indent=2)

    by_status = {}
    for r in results:
        by_status[r["status"]] = by_status.get(r["status"], 0) + 1
    print(f"\nFINAL: {by_status}")
    print(f"Saved to {OUT}")

    return results


if __name__ == "__main__":
    main()
