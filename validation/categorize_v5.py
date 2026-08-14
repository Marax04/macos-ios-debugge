#!/usr/bin/env python3
"""Categorize the 501 TOOL_ERROR and 9 SERVER_DIED."""
import json
from collections import Counter, defaultdict

with open(r"C:\Users\Fra\Desktop\RustRE\validation\mcp_outputs\R60_ALL.json") as f:
    results = json.load(f)

errs = [r for r in results if r["status"] in ("TOOL_ERROR","SERVER_DIED","JSONRPC_ERROR")]
print(f"Total errors: {len(errs)}")

cats = defaultdict(list)
for e in errs:
    msg = (e.get("output_excerpt") or "").lower()
    if e["status"] == "SERVER_DIED":
        cats["server_died"].append(e)
    elif "missing" in msg and ("field" in msg or "required" in msg or "'" in msg):
        cats["missing_field"].append(e)
    elif "invalid hex" in msg or "odd-length" in msg:
        cats["bad_hex_input"].append(e)
    elif "invalid params" in msg:
        cats["invalid_params"].append(e)
    elif "not found" in msg:
        cats["not_found"].append(e)
    elif "not a" in msg and ("mach-o" in msg or "elf" in msg or "pe" in msg or "wasm" in msg or "java" in msg or "dex" in msg):
        cats["wrong_file_type"].append(e)
    elif "unknown" in msg:
        cats["unknown"].append(e)
    elif "execution failed" in msg:
        cats["execution_failed"].append(e)
    else:
        cats["other"].append(e)

print()
for cat, items in sorted(cats.items(), key=lambda x: -len(x[1])):
    print(f"\n=== {cat}: {len(items)} ===")
    for it in items[:5]:
        print(f"  {it['tool']:<45} | {(it.get('output_excerpt') or '')[:90]}")

# Also print top 20 error tools by frequency of same error msg
msg_groups = defaultdict(list)
for e in errs:
    key = (e.get("output_excerpt") or "")[:60]
    msg_groups[key].append(e["tool"])
print(f"\n\n=== TOP 10 error patterns ===")
for msg, tools in sorted(msg_groups.items(), key=lambda x: -len(x[1]))[:10]:
    print(f"({len(tools)}x) {msg}")
    for t in tools[:3]:
        print(f"     -> {t}")
