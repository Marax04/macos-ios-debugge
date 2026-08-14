#!/usr/bin/env python3
"""Classify each workspace crate by MCP coverage: NONE / PARTIAL / FULL."""
import os, json, re, subprocess

WS = r"C:\Users\Fra\Desktop\RustRE"
CRATES_DIR = os.path.join(WS, "crates")
EXE = os.path.join(WS, "target", "release", "rustre-mcp.exe")

# Internal crates that should NOT have MCP tools (infrastructure)
INTERNAL = {
    "rustre-core","rustre-project","rustre-knowledge","rustre-mcp","rustre-mcp-server",
    "rustre-mcp-tools","rustre-mcp-federation","rustre-bin","rustre-cli","rustre-daemon",
    "rustre-gui","rustre-plugin-api","rustre-plugin-host","rustre-plugin-loader",
    "rustre-graph","rustre-arch","rustre-arch-registry","rustre-il","rustre-il-llil",
    "rustre-il-mlil","rustre-il-hlil","rustre-hex","rustre-hex-view","rustre-debug",
}

# Get list of MCP tools
def get_tools():
    p = subprocess.Popen([EXE, "--transport=stdio"], stdin=subprocess.PIPE,
                         stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, bufsize=0)
    def send(o): p.stdin.write((json.dumps(o)+"\n").encode()); p.stdin.flush()
    def recv(): return json.loads(p.stdout.readline())
    send({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"c","version":"1"}}})
    recv()
    send({"jsonrpc":"2.0","method":"notifications/initialized"})
    send({"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}})
    r = recv()
    p.stdin.close(); p.terminate()
    return [t["name"] for t in r["result"]["tools"]]

tools = get_tools()
print(f"Total MCP tools: {len(tools)}")

# Count pub fn per crate
def count_pub_fn(crate):
    count = 0
    src = os.path.join(CRATES_DIR, crate, "src")
    if not os.path.exists(src):
        return 0
    for root, _, files in os.walk(src):
        for f in files:
            if f.endswith(".rs"):
                try:
                    with open(os.path.join(root, f), encoding="utf-8", errors="ignore") as fh:
                        content = fh.read()
                        # Match pub fn (not pub(crate))
                        count += len(re.findall(r"\bpub\s+(?:async\s+)?fn\b", content))
                except: pass
    return count

# For each crate, count matching tools
crates = sorted([d for d in os.listdir(CRATES_DIR) if d.startswith("rustre-")])

def tools_for_crate(crate):
    """Tools whose name matches the crate's purpose by prefix heuristic."""
    base = crate.replace("rustre-", "")
    parts = base.split("-")
    # Try variants: base_, parts[0]_, dotted forms
    prefixes = [base.replace("-","_")+"_", base.replace("-","_")+".", parts[0]+"_", parts[0]+"."]
    matched = []
    for t in tools:
        tl = t.lower()
        if any(tl.startswith(p) for p in prefixes):
            matched.append(t)
    return matched

result = {"FULL": [], "PARTIAL": [], "NONE": [], "INTERNAL": []}

for c in crates:
    if c in INTERNAL:
        result["INTERNAL"].append(c)
        continue
    fn_count = count_pub_fn(c)
    tool_matches = tools_for_crate(c)
    tc = len(tool_matches)
    # Heuristic:
    # FULL: tool_count >= max(1, fn_count // 5)  (at least 1 tool per 5 pub fn, or 1 if few fn)
    # PARTIAL: tool_count >= 1 but less than full target
    # NONE: 0 tools
    if tc == 0:
        result["NONE"].append((c, fn_count, []))
    elif tc >= max(1, fn_count // 5):
        result["FULL"].append((c, fn_count, tool_matches))
    else:
        result["PARTIAL"].append((c, fn_count, tool_matches))

print()
print(f"=== SUMMARY ===")
print(f"FULL (>= 1 tool per ~5 pub fn): {len(result['FULL'])} crate")
print(f"PARTIAL (has tools but coverage gap): {len(result['PARTIAL'])} crate")
print(f"NONE (no MCP wrapper at all): {len(result['NONE'])} crate")
print(f"INTERNAL (no tool needed - infrastructure): {len(result['INTERNAL'])} crate")
print(f"Total: {len(crates)}")

print(f"\n=== NONE list ({len(result['NONE'])}) ===")
for c, fn, _ in sorted(result["NONE"], key=lambda x: -x[1])[:50]:
    print(f"  {c:<40} pub_fn={fn}")
print(f"  ...")

print(f"\n=== PARTIAL ({len(result['PARTIAL'])}) ===")
for c, fn, tl in sorted(result["PARTIAL"], key=lambda x: -x[1])[:20]:
    print(f"  {c:<40} pub_fn={fn} tools={len(tl)}")

# Save full result
with open(os.path.join(WS, "validation", "R32_COVERAGE_BREAKDOWN.json"), "w") as f:
    json.dump({k: ([{"crate":c,"pub_fn":fn,"tools":t} for c,fn,t in v] if k!="INTERNAL" else v) for k,v in result.items()}, f, indent=2)
print(f"\nSaved: validation/R32_COVERAGE_BREAKDOWN.json")
