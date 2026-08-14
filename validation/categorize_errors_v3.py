#!/usr/bin/env python3
"""Categorize the 45 R30v3 errors precisely."""
import json
from collections import Counter, defaultdict

with open(r"C:\Users\Fra\Desktop\RustRE\validation\mcp_outputs\R30v3_full.json") as f:
    results = json.load(f)

errs = [r for r in results if r["status"] in ("TOOL_ERROR", "JSONRPC_ERROR")]
print(f"Total errors: {len(errs)}")

# Categorize
cats = defaultdict(list)
for e in errs:
    msg = (e.get("output_excerpt") or "").lower()
    name = e["tool"]
    if e["status"] == "JSONRPC_ERROR":
        cats["server_sync_error"].append(e)
    elif "missing 'binary_id'" in msg or "missing 'addr'" in msg or "missing 'address'" in msg or "missing 'query'" in msg or "missing 'a'" in msg or "missing 'function_address'" in msg:
        cats["missing_required_field"].append(e)
    elif "no function detected" in msg:
        cats["address_lookup_fail"].append(e)
    elif "binary  not loaded" in msg or "image  not loaded" in msg:
        cats["empty_binary_id_passed"].append(e)
    elif "yara compile error" in msg or "opaque expr node" in msg or "patch_asm: unsupported" in msg:
        cats["wrong_handler_dispatch"].append(e)  # CRITICAL BUG
    elif "invalid hex" in msg or "empty pattern" in msg or "supply either" in msg or "must be 'backward" in msg or "lift error" in msg or "pipeline error" in msg or "key:" in msg or "addresses' empty" in msg:
        cats["input_format_mismatch"].append(e)
    elif "not a mach-o" in msg or "not a fat" in msg:
        cats["wrong_file_type_for_tool"].append(e)
    elif "only select" in msg:
        cats["sql_validation"].append(e)
    elif "no debug session" in msg or "session  not found" in msg:
        cats["no_session"].append(e)
    elif "type_str and var_name" in msg:
        cats["legacy_stub_response"].append(e)
    else:
        cats["other"].append(e)

print()
for cat, items in cats.items():
    print(f"\n=== {cat}: {len(items)} ===")
    for it in items[:10]:
        print(f"  {it['tool']:<42} | {(it.get('output_excerpt') or '')[:90]}")
