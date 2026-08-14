#!/usr/bin/env python3
"""Classify each TOOL_ERROR: is it a legitimate error handler or a real bug?
Real bug candidates:
  - "invalid params: missing 'X'" where X is REQUIRED by the schema but the smart
    exercise didn't know to send it -> smart exercise gap, not tool bug
  - Wrong hex-encoding requirement message: tool bug if it says "missing 'X'" for
    a field that IS in the schema.
  - "not a XXX" errors when the smart script sent PE bytes to non-PE parser:
    legitimate.
Output: mismatch buckets to validation/tool_errors_classified.json.
"""
import json, re
from collections import defaultdict, Counter

# Reads latest smart exercise output
LATEST = r"C:\Users\Fra\Desktop\RustRE\validation\mcp_outputs\R61_SMART.json"
OUT = r"C:\Users\Fra\Desktop\RustRE\validation\tool_errors_classified.json"

with open(LATEST) as f: data = json.load(f)

errs = [r for r in data if r["status"] == "TOOL_ERROR"]
print(f"TOOL_ERROR: {len(errs)}")

# Map: tool -> schema (loaded from a fresh dump)
buckets = defaultdict(list)
missing_field = re.compile(r"missing '(\w+)'", re.I)

for e in errs:
    name = e["tool"]
    msg = (e.get("output_excerpt") or "").lower()
    provided = set(e.get("input", {}).keys())

    m = missing_field.search(msg)
    if m:
        field = m.group(1)
        if field in provided:
            # BUG: field was sent but wrapper still says missing
            buckets["BUG_field_sent_but_missing"].append({"tool":name,"field":field,"input":e["input"],"msg":msg[:100]})
        else:
            # Smart script didn't know this field name -> gap
            buckets["OK_smart_did_not_know_field_"+field].append(name)
    elif "invalid hex" in msg or "odd-length" in msg or "invalid utf-8" in msg:
        buckets["OK_bad_encoding_from_smart"].append(name)
    elif re.search(r"not a (pe|mach-o|macho|fat|wasm|jar|dex|class|jvm|elf|dll|apk|dyld)", msg):
        buckets["OK_wrong_binary_type"].append(name)
    elif "not loaded" in msg or "no binary" in msg:
        buckets["OK_binary_not_loaded"].append(name)
    elif "no function" in msg or "function not found" in msg or "no data at" in msg:
        buckets["OK_no_data_at_address"].append(name)
    elif "empty" in msg and "not supported" not in msg:
        buckets["OK_empty_input"].append(name)
    elif "unknown" in msg or "unsupported" in msg:
        buckets["OK_unknown_variant"].append(name)
    elif "yara" in msg:
        buckets["OK_yara_compile"].append(name)
    elif "parse error" in msg or "invalid" in msg:
        buckets["OK_parse_error"].append(name)
    elif "internal error" in msg:
        # These are SUSPICIOUS — internal errors leaking through
        buckets["SUSPICIOUS_internal_error"].append({"tool":name,"msg":msg[:150],"input":e["input"]})
    else:
        buckets["UNCLASSIFIED"].append({"tool":name,"msg":msg[:150],"input":e["input"]})

report = {}
for cat, items in sorted(buckets.items(), key=lambda x: -len(x[1])):
    report[cat] = {"count": len(items), "samples": items[:8] if not cat.startswith("OK_") else items[:5]}
    print(f"{cat}: {len(items)}")

with open(OUT, "w") as f:
    json.dump(report, f, indent=1)
print(f"Report -> {OUT}")

# Highlight real problems
bug_count = sum(len(v) for k,v in buckets.items() if k.startswith("BUG_") or k.startswith("SUSPICIOUS_") or k == "UNCLASSIFIED")
print(f"\n=== POTENTIAL REAL BUGS: {bug_count} ===")
