import json
import subprocess

BIN = r"C:\Users\Fra\Desktop\RustRE\target\release\rustre-mcp.exe"
p = subprocess.Popen(
    [BIN],
    stdin=subprocess.PIPE,
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE,
    bufsize=0
)

_id = 0
def send(m, par=None):
    global _id
    _id += 1
    msg = {"jsonrpc": "2.0", "id": _id, "method": m}
    if par is not None:
        msg["params"] = par
    p.stdin.write((json.dumps(msg) + "\n").encode())
    p.stdin.flush()
    return json.loads(p.stdout.readline().decode())

# Initialize
print("[+] Initializing...")
send("initialize", {
    "protocolVersion": "2024-11-05",
    "capabilities": {},
    "clientInfo": {"name": "debug", "version": "1"}
})

# Send notifications/initialized
p.stdin.write((json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized"}) + "\n").encode())
p.stdin.flush()

# List tools
print("[+] Listing tools...")
r = send("tools/list")
tools = [t["name"] for t in r.get("result", {}).get("tools", [])]
sandbox_tools = [t for t in tools if t.startswith("sandbox_report_")]
print(f"[+] Found {len(sandbox_tools)} sandbox_report_ tools")

# Test a few tools
test_tools = [
    ("sandbox_report_severity_parse_v5", {"s": "info"}),
    ("sandbox_report_severity_parse", {"severity": "info"}),
    ("sandbox_report_indicator_category_display_v5", {"category": "network"}),
]

for tool_name, args in test_tools:
    if tool_name in tools:
        print(f"\n[*] Testing {tool_name}...")
        result = send("tools/call", {"name": tool_name, "arguments": args})
        print(f"    Raw result: {json.dumps(result, indent=2)}")
    else:
        print(f"\n[-] Tool {tool_name} not found")

p.terminate()
p.wait()
