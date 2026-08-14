#!/usr/bin/env python3
"""Deep dive on 508 TOOL_ERROR — classify actionable buckets."""
import json, re
from collections import Counter, defaultdict

with open(r"C:\Users\Fra\Desktop\RustRE\validation\mcp_outputs\R60_ALL.json") as f:
    data = json.load(f)

errs = [r for r in data if r["status"] == "TOOL_ERROR"]
print(f"TOOL_ERROR count: {len(errs)}")

# Categorize
buckets = defaultdict(list)
for e in errs:
    msg = (e.get("output_excerpt") or "").lower()
    name = e["tool"]
    if "missing '" in msg:
        # Extract missing field
        m = re.search(r"missing '(\w+)'", msg)
        field = m.group(1) if m else "unknown"
        buckets[f"missing_field_{field}"].append(name)
    elif "invalid hex" in msg or "odd-length" in msg or "invalid hex byte" in msg:
        buckets["bad_hex"].append(name)
    elif "not a mach-o" in msg or "not a fat" in msg or "not a wasm" in msg or "not a jar" in msg or "not a dex" in msg or "not a class" in msg or "not a jvm" in msg or "not supported bin" in msg:
        buckets["wrong_file_type"].append(name)
    elif "not loaded" in msg:
        buckets["binary_not_loaded"].append(name)
    elif "no function" in msg or "function not found" in msg:
        buckets["no_function_at_addr"].append(name)
    elif "empty" in msg:
        buckets["empty_input"].append(name)
    elif "unknown" in msg:
        buckets["unknown_kind"].append(name)
    elif "truncated" in msg or "too short" in msg or "insufficient" in msg:
        buckets["data_too_short"].append(name)
    elif "yara" in msg:
        buckets["yara_compile"].append(name)
    elif "sql" in msg or "select" in msg:
        buckets["sql_only_select"].append(name)
    elif "parse error" in msg:
        buckets["parse_error"].append(name)
    elif "invalid params" in msg:
        buckets["other_invalid_params"].append(name)
    elif "internal error" in msg:
        buckets["internal_error"].append(name)
    else:
        buckets["other"].append(name)

for cat, items in sorted(buckets.items(), key=lambda x: -len(x[1])):
    print(f"\n=== {cat}: {len(items)} ===")
    for t in items[:5]:
        print(f"  {t}")

print(f"\n\n=== Total categorized ===")
total = sum(len(v) for v in buckets.values())
print(f"Total: {total} (matches {len(errs)}: {total == len(errs)})")
