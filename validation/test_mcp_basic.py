#!/usr/bin/env python3
"""Quick test of MCP subprocess communication."""

import json
import subprocess
import sys

mcp_binary = r"C:\Users\Fra\Desktop\RustRE\target\release\rustre-mcp.exe"

print("[*] Starting MCP subprocess...")
proc = subprocess.Popen(
    [mcp_binary],
    stdin=subprocess.PIPE,
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE,
    text=True,
    bufsize=1
)

print("[*] Sending initialize request...")
msg = {
    "jsonrpc": "2.0",
    "id": 1,
    "method": "initialize",
    "params": {
        "protocolVersion": "2024-11-05",
        "capabilities": {},
        "clientInfo": {"name": "validator", "version": "1.0"}
    }
}

request = json.dumps(msg) + "\n"
proc.stdin.write(request)
proc.stdin.flush()

print("[*] Reading response...")
try:
    response_line = proc.stdout.readline()
    print(f"Got: {repr(response_line[:200])}")

    if response_line:
        resp = json.loads(response_line)
        print(f"Parsed: {resp.keys() if isinstance(resp, dict) else type(resp)}")
except Exception as e:
    print(f"Error: {e}")

proc.terminate()
