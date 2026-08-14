#!/usr/bin/env python3
"""Debug script to discover xref_ tool schemas."""

import subprocess
import json

MCP_BIN = r"C:\Users\Fra\Desktop\RustRE\target\release\rustre-mcp.exe"

def start():
    p = subprocess.Popen([MCP_BIN, "--transport=stdio"], stdin=subprocess.PIPE,
                         stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, bufsize=0)
    def send(r): p.stdin.write((json.dumps(r)+"\n").encode()); p.stdin.flush()
    def recv():
        line = p.stdout.readline()
        return json.loads(line) if line else None
    send({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"debug","version":"1"}}})
    recv()
    send({"jsonrpc":"2.0","method":"notifications/initialized"})
    return p, send, recv

p, send, recv = start()

# List tools
send({"jsonrpc":"2.0","id":2,"method":"tools/list"})
resp = recv()

tools = resp.get("result", {}).get("tools", [])
xref_tools = [t for t in tools if "analysis_xref_" in t.get("name", "")]

print(f"Found {len(xref_tools)} xref tools\n")

# Print first 10 tool schemas
for i, tool in enumerate(xref_tools[:10]):
    print(f"\n{'='*60}")
    print(f"Tool: {tool['name']}")
    print(f"Description: {tool.get('description', 'N/A')[:100]}")
    print(f"InputSchema:")
    schema = tool.get("inputSchema", {})
    print(json.dumps(schema, indent=2))

p.terminate()
