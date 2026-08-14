#!/usr/bin/env python3
"""Trace the project.open → binary.info bug."""
import json, subprocess

EXE = r"C:\Users\Fra\Desktop\RustRE\target\release\rustre-mcp.exe"
TARGET = r"C:\Users\Fra\Desktop\Zyphora\target\release\cargo-zyphora.exe"

p = subprocess.Popen([EXE, "--transport=stdio"], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, bufsize=0)
def send(req):
    p.stdin.write((json.dumps(req)+"\n").encode())
    p.stdin.flush()
def recv():
    return json.loads(p.stdout.readline())

send({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"x","version":"1"}}})
recv()
send({"jsonrpc":"2.0","method":"notifications/initialized"})

# Open
send({"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"project.open","arguments":{"path":TARGET}}})
r = recv()
txt = r["result"]["content"][0]["text"]
print(f"=== project.open response ===\n{txt}\n")

# Try with binary_id=bin-0001
send({"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"binary.info","arguments":{"binary_id":"bin-0001"}}})
r2 = recv()
print(f"=== binary.info(binary_id=bin-0001) ===\n{json.dumps(r2, indent=2)[:500]}\n")

# Try binary.info with path directly (no binary_id)
send({"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"binary.info","arguments":{"binary_id":"bin-0001","path":TARGET}}})
r3 = recv()
print(f"=== binary.info(binary_id=bin-0001, path) ===\n{json.dumps(r3, indent=2)[:500]}\n")

# Try project.list_binaries to see what's actually loaded
send({"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"project.list_binaries","arguments":{}}})
r4 = recv()
print(f"=== project.list_binaries ===\n{r4['result']['content'][0]['text'][:500]}\n")

p.stdin.close(); p.terminate()
