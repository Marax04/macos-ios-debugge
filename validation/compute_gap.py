#!/usr/bin/env python3
"""Compute crate→tool gap."""
import os, re, json

CRATES = r"C:\Users\Fra\Desktop\RustRE\crates"
TOOLS_FILE = r"C:\Users\Fra\Desktop\RustRE\validation\tools_list.txt"

INTERNAL = {
    "rustre-core","rustre-project","rustre-knowledge","rustre-mcp","rustre-mcp-server",
    "rustre-mcp-tools","rustre-mcp-federation","rustre-bin","rustre-cli","rustre-daemon",
    "rustre-gui","rustre-plugin-api","rustre-plugin-host","rustre-plugin-loader",
    "rustre-graph","rustre-arch","rustre-arch-registry","rustre-il","rustre-il-llil",
    "rustre-il-mlil","rustre-il-hlil","rustre-hex","rustre-hex-view","rustre-debug",
    "rustre-trace-coresight","rustre-symbols-stabs",
}

with open(TOOLS_FILE) as f:
    tools = [l.strip() for l in f if l.strip()]

crates = sorted([d for d in os.listdir(CRATES) if d.startswith("rustre-")])

def crate_prefix(c):
    """Derive expected tool prefix from crate name."""
    base = c.replace("rustre-", "")
    return base.replace("-", "_") + "_"

def has_tool(crate, tools):
    pref = crate_prefix(crate)
    # also accept short prefix
    short = pref.split("_")[0] + "_"
    for t in tools:
        if t.startswith(pref) or (pref.startswith(t.split("_")[0]+"_") and t.startswith(short) and crate.replace("rustre-","").split("-")[0] in t):
            return True
    return False

result = []
needs_wrap = []
covered = []
internal = []

for c in crates:
    if c in INTERNAL:
        internal.append(c)
        continue
    if has_tool(c, tools):
        covered.append(c)
    else:
        needs_wrap.append(c)

print(f"Total: {len(crates)} | Internal OK: {len(internal)} | Covered: {len(covered)} | NEEDS WRAP: {len(needs_wrap)}")

with open(r"C:\Users\Fra\Desktop\RustRE\validation\R28_GAP.json", "w") as f:
    json.dump({
        "total_crates": len(crates),
        "internal_ok": len(internal),
        "covered": len(covered),
        "needs_wrap": len(needs_wrap),
        "needs_wrap_list": needs_wrap,
        "covered_list": covered,
    }, f, indent=2)

print("Top 25 needs_wrap:")
for c in needs_wrap[:25]: print(" ", c)
