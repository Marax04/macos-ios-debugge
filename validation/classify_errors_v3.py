#!/usr/bin/env python3
"""Classify the 45 errors in R30v3 by root cause for prioritized fixing."""
import json
from collections import defaultdict

with open(r"C:\Users\Fra\Desktop\RustRE\validation\mcp_outputs\R30v3_full.json") as f:
    results = json.load(f)

errs = [r for r in results if r["status"] in ("TOOL_ERROR","JSONRPC_ERROR")]
print(f"Total errors: {len(errs)}")

cats = defaultdict(list)
for r in errs:
    name = r["tool"]
    msg = r.get("output_excerpt", "")
    if r["status"] == "JSONRPC_ERROR":
        cats["A_stdio_desync"].append((name, msg))
    elif "opaque expr node must be an object" in msg or "YARA compile error" in msg or "kg.query" in msg.lower() or "patch_asm" in msg.lower():
        cats["B_state_leak_handler"].append((name, msg))
    elif "missing 'binary_id'" in msg or "binary_id required" in msg:
        cats["C_missing_binary_id"].append((name, msg))
    elif "missing 'address'" in msg or "missing 'addr'" in msg or "missing 'function_address'" in msg:
        cats["D_missing_address"].append((name, msg))
    elif "missing 'query'" in msg:
        cats["E_missing_query"].append((name, msg))
    elif "not found: no function" in msg:
        cats["F_no_function_at_addr"].append((name, msg))
    elif "invalid hex" in msg or "empty in" in msg:
        cats["G_invalid_hex"].append((name, msg))
    elif "addresses" in msg.lower() and "empty" in msg.lower():
        cats["H_empty_addresses"].append((name, msg))
    elif "direction" in msg.lower():
        cats["I_bad_direction"].append((name, msg))
    elif "missing 'a'" in msg or "missing 'b'" in msg:
        cats["J_missing_diff_args"].append((name, msg))
    elif "supply either" in msg.lower() or "key_hex" in msg:
        cats["K_xor_key"].append((name, msg))
    elif "not a Mach-O" in msg or "not a FAT" in msg:
        cats["L_wrong_file_type"].append((name, msg))
    elif "Unknown opcode" in msg or "bytecode" in msg:
        cats["M_input_format"].append((name, msg))
    elif "missing 'bp_id'" in msg:
        cats["N_missing_bp_id"].append((name, msg))
    else:
        cats["Z_other"].append((name, msg))

for cat, items in sorted(cats.items()):
    print(f"\n=== {cat}: {len(items)} ===")
    for name, msg in items:
        print(f"  {name:<45} {msg[:80]}")
