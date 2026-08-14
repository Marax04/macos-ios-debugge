#!/usr/bin/env python3
"""Test MCP tools/list call."""

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
    text=False,  # Binary mode
)

# Initialize
print("[*] Initializing...")
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
proc.stdin.write((json.dumps(msg) + "\n").encode('utf-8'))
proc.stdin.flush()
resp = proc.stdout.readline()
print(f"[*] Got init response")

# Send initialized
msg = {"jsonrpc": "2.0", "method": "notifications/initialized"}
proc.stdin.write((json.dumps(msg) + "\n").encode('utf-8'))
proc.stdin.flush()

# List tools
print("[*] Listing tools...")
msg = {"jsonrpc": "2.0", "id": 2, "method": "tools/list"}
proc.stdin.write((json.dumps(msg) + "\n").encode('utf-8'))
proc.stdin.flush()

print("[*] Reading tools response...")
response_line = proc.stdout.readline()
print(f"Got {len(response_line)} bytes")

resp = json.loads(response_line.decode('utf-8', errors='replace'))
if "result" in resp:
    tools = resp["result"].get("tools", [])
    print(f"[*] Total tools: {len(tools)}")

    # Find analysis_cfg_ tools
    cfg_tools = [t for t in tools if "analysis_cfg_" in t.get("name", "")]
    print(f"[*] analysis_cfg_ tools: {len(cfg_tools)}")

    for i, tool in enumerate(cfg_tools[:15]):
        print(f"  {i+1}. {tool.get('name')}")
        if i >= 14:
            break

proc.terminate()
