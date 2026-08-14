#!/usr/bin/env python3
"""Dump current MCP tools list via stdio JSON-RPC."""
import json, subprocess, sys

EXE = r"C:\Users\Fra\Desktop\RustRE\target\release\rustre-mcp.exe"

p = subprocess.Popen([EXE, "--transport=stdio"], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
init = {"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"t","version":"1"}}}
notif = {"jsonrpc":"2.0","method":"notifications/initialized"}
list_req = {"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}

p.stdin.write((json.dumps(init)+"\n").encode())
p.stdin.flush()
init_resp = p.stdout.readline()

p.stdin.write((json.dumps(notif)+"\n").encode())
p.stdin.flush()

p.stdin.write((json.dumps(list_req)+"\n").encode())
p.stdin.flush()
list_resp = p.stdout.readline().decode()

p.stdin.close()
p.terminate()

data = json.loads(list_resp)
tools = [t["name"] for t in data["result"]["tools"]]
print(f"TOTAL_TOOLS: {len(tools)}")
with open(r"C:\Users\Fra\Desktop\RustRE\validation\tools_list.txt", "w") as f:
    for t in sorted(tools):
        f.write(t+"\n")
print("WROTE: validation/tools_list.txt")
