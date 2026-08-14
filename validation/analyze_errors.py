#!/usr/bin/env python3
"""Categorize the 54 errors: real bug vs missing-input vs schema-mismatch."""
import json, re
from collections import Counter

with open(r"C:\Users\Fra\Desktop\RustRE\validation\mcp_outputs\R30_full_exercise.json") as f:
    results = json.load(f)

errs = [r for r in results if "ERROR" in r["status"]]
ok = [r for r in results if r["status"] == "OK"]
print(f"OK={len(ok)} ERROR={len(errs)} total={len(results)}")

categories = {
    "missing_field": [],   # input was missing required field
    "wrong_path_type": [],  # path needed different file (PDB instead of PE, etc)
    "schema_mismatch": [],  # param name addr vs address etc
    "real_bug": [],         # genuine bug
    "unknown": [],
}

for r in errs:
    excerpt = r["output_excerpt"].lower()
    name = r["tool"]
    if "missing" in excerpt or "required" in excerpt or "invalid params" in excerpt:
        categories["missing_field"].append(r)
    elif "not found" in excerpt and ("file" in excerpt or "path" in excerpt):
        categories["wrong_path_type"].append(r)
    elif "unknown field" in excerpt or "invalid" in excerpt and "param" in excerpt:
        categories["schema_mismatch"].append(r)
    elif "stub" in excerpt or "not implemented" in excerpt or "todo" in excerpt:
        categories["real_bug"].append(r)
    elif "panic" in excerpt:
        categories["real_bug"].append(r)
    else:
        categories["unknown"].append(r)

print()
for cat, items in categories.items():
    print(f"\n=== {cat}: {len(items)} ===")
    for it in items[:10]:
        print(f"  {it['tool']}: {it['output_excerpt'][:100]}")

# OK tools sample
print(f"\n=== OK sample (first 10) ===")
for r in ok[:10]:
    print(f"  {r['tool']}: {r['output_excerpt'][:100]}")
