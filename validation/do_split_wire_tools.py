#!/usr/bin/env python3
"""
Split wire_tools.rs into per-crate sub-modules under src/tools/.
Uses wire_tools_catalog.json to know which lines belong to which prefix.
"""

import json
import os
import re
import sys

# ── Paths ────────────────────────────────────────────────────────────────────
BASE = "C:/Users/Fra/Desktop/RustRE"
CATALOG_PATH = f"{BASE}/validation/wire_tools_catalog.json"
WIRE_TOOLS_PATH = f"{BASE}/crates/rustre-mcp-tools/src/wire_tools.rs"
LIB_RS_PATH = f"{BASE}/crates/rustre-mcp-tools/src/lib.rs"
TOOLS_DIR = f"{BASE}/crates/rustre-mcp-tools/src/tools"

# ── Step 1: Read catalog ─────────────────────────────────────────────────────
with open(CATALOG_PATH, encoding="utf-8") as f:
    catalog = json.load(f)

prefixes = catalog["prefixes"]  # dict: prefix -> {count, tools: [{name, snake, start_line, end_line}]}
total_tools = catalog["total_tools"]

# ── Step 2: Read wire_tools.rs ───────────────────────────────────────────────
print(f"Reading {WIRE_TOOLS_PATH} ...")
with open(WIRE_TOOLS_PATH, encoding="utf-8") as f:
    wire_lines = f.readlines()

orchestrator_lines_before = len(wire_lines)
print(f"  Lines: {orchestrator_lines_before}")

# ── Build set of catalog-covered line indices (0-based) ──────────────────────
covered_indices: set[int] = set()
for prefix, pdata in prefixes.items():
    for tool in pdata["tools"]:
        s = tool["start_line"] - 1  # convert to 0-based
        e = tool["end_line"] - 1
        for i in range(s, e + 1):
            covered_indices.add(i)

print(f"  Catalog-covered line count: {len(covered_indices)}")

# ── Find key line indices ─────────────────────────────────────────────────────
all_wire_handlers_idx = None
wire_into_server_idx = None

for i, line in enumerate(wire_lines):
    stripped = line.strip()
    if stripped.startswith("pub fn all_wire_handlers()") and all_wire_handlers_idx is None:
        all_wire_handlers_idx = i
    if stripped.startswith("pub fn wire_into_server(") and wire_into_server_idx is None:
        wire_into_server_idx = i

print(f"  all_wire_handlers at line {all_wire_handlers_idx + 1}")
print(f"  wire_into_server at line {wire_into_server_idx + 1}")

# ── Step 3: Create tools/ directory ─────────────────────────────────────────
os.makedirs(TOOLS_DIR, exist_ok=True)
print(f"  Created directory: {TOOLS_DIR}")

# ── Step 4: Write per-prefix .rs files ───────────────────────────────────────
sorted_prefixes = sorted(prefixes.keys())
files_created = 0
total_tools_moved = 0

for prefix in sorted_prefixes:
    pdata = prefixes[prefix]
    tools = pdata["tools"]
    if not tools:
        continue

    out_path = f"{TOOLS_DIR}/{prefix}.rs"

    lines_out = []
    lines_out.append(f"//! MCP wrappers for the rustre-{prefix} crate.\n")
    lines_out.append("//! Extracted from wire_tools.rs by workflow_split_wire_tools.\n")
    lines_out.append("\n")
    lines_out.append("use rustre_mcp_server::{ToolDefinition, ToolHandler};\n")
    lines_out.append("use serde_json::json;\n")
    lines_out.append("\n")

    for tool in tools:
        s = tool["start_line"] - 1  # 0-based
        e = tool["end_line"] - 1
        for li in range(s, e + 1):
            if li < len(wire_lines):
                lines_out.append(wire_lines[li])
        # Ensure trailing newline and blank separator
        if lines_out and not lines_out[-1].endswith("\n"):
            lines_out.append("\n")
        lines_out.append("\n")

    # handlers() function
    lines_out.append("pub fn handlers() -> Vec<(ToolDefinition, Box<dyn ToolHandler>)> {\n")
    lines_out.append("    vec![\n")
    for tool in tools:
        name = tool["name"]
        lines_out.append(f"        ({name}::definition(), Box::new({name})),\n")
    lines_out.append("    ]\n")
    lines_out.append("}\n")

    with open(out_path, "w", encoding="utf-8") as f:
        f.writelines(lines_out)

    files_created += 1
    total_tools_moved += len(tools)
    print(f"  Wrote {out_path}  ({len(tools)} tools)")

# ── Step 5: Write tools/mod.rs ───────────────────────────────────────────────
mod_rs_path = f"{TOOLS_DIR}/mod.rs"
mod_lines = []
mod_lines.append("//! MCP tool sub-modules, one per rustre-* crate.\n")
for prefix in sorted_prefixes:
    if prefixes[prefix]["tools"]:
        mod_lines.append(f"pub mod {prefix};\n")

with open(mod_rs_path, "w", encoding="utf-8") as f:
    f.writelines(mod_lines)

files_created += 1
print(f"  Wrote {mod_rs_path}")

# ── Step 6 & 7: Rewrite wire_tools.rs as slim orchestrator ───────────────────
#
# New wire_tools.rs contains:
#   1. New header
#   2. Non-catalog lines before all_wire_handlers (helpers, WireToolAdapter, etc.)
#      EXCEPT lines that are also in covered_indices
#   3. New all_wire_handlers() delegating to sub-module handlers()
#   4. Everything from wire_into_server through end-of-file (unchanged)
#

new_wire_lines = []

# Header
new_wire_lines.append("//! Cross-cutting MCP tool wrappers — orchestrator.\n")
new_wire_lines.append("//! The actual tools live under crate::tools::<prefix>.\n")
new_wire_lines.append("\n")
new_wire_lines.append("use rustre_mcp_server::{ToolDefinition, ToolHandler, RustReMcpServer};\n")
new_wire_lines.append("\n")

# Non-catalog helper lines that appear before all_wire_handlers
# (includes WireToolAdapter, wire_def_to_catalog, etc.)
# We skip covered_indices lines but keep everything else up to all_wire_handlers_idx
# Also skip the "// VSA_NEW_TOOLS_MARKER" type markers and blank-only sections
# Strategy: accumulate non-covered lines, collapsing runs of blank lines
preamble_lines = []
for i in range(6, all_wire_handlers_idx):
    if i in covered_indices:
        continue
    preamble_lines.append(wire_lines[i])

# Collapse multiple consecutive blank lines to single blank
collapsed = []
prev_blank = False
for ln in preamble_lines:
    is_blank = ln.strip() == ""
    if is_blank and prev_blank:
        continue
    collapsed.append(ln)
    prev_blank = is_blank

new_wire_lines.extend(collapsed)

# Ensure separation before all_wire_handlers
if new_wire_lines and new_wire_lines[-1].strip() != "":
    new_wire_lines.append("\n")

# New all_wire_handlers
new_wire_lines.append("pub fn all_wire_handlers() -> Vec<(ToolDefinition, Box<dyn ToolHandler>)> {\n")
new_wire_lines.append("    let mut all = Vec::new();\n")
for prefix in sorted_prefixes:
    if prefixes[prefix]["tools"]:
        new_wire_lines.append(f"    all.extend(crate::tools::{prefix}::handlers());\n")
new_wire_lines.append("    all\n")
new_wire_lines.append("}\n")
new_wire_lines.append("\n")

# Everything from wire_into_server to end of file
new_wire_lines.extend(wire_lines[wire_into_server_idx:])

with open(WIRE_TOOLS_PATH, "w", encoding="utf-8") as f:
    f.writelines(new_wire_lines)

orchestrator_lines_after = len(new_wire_lines)
print(f"  Rewrote {WIRE_TOOLS_PATH}")
print(f"  Orchestrator lines: {orchestrator_lines_before} -> {orchestrator_lines_after}")

# ── Step 8: Add pub mod tools; to lib.rs ─────────────────────────────────────
with open(LIB_RS_PATH, encoding="utf-8") as f:
    lib_content = f.read()

if "pub mod tools;" not in lib_content:
    # Insert after pub mod wire_tools; line
    new_lib = lib_content.replace(
        "pub mod wire_tools;\n",
        "pub mod wire_tools;\npub mod tools;\n"
    )
    if new_lib == lib_content:
        # fallback: append before end
        new_lib = lib_content.rstrip() + "\npub mod tools;\n"
    with open(LIB_RS_PATH, "w", encoding="utf-8") as f:
        f.write(new_lib)
    print(f"  Added 'pub mod tools;' to {LIB_RS_PATH}")
else:
    print(f"  'pub mod tools;' already present in {LIB_RS_PATH}")

# ── Summary ──────────────────────────────────────────────────────────────────
print("\n=== DONE ===")
print(f"files_created:           {files_created}")
print(f"total_tools_moved:       {total_tools_moved}")
print(f"orchestrator_lines_before: {orchestrator_lines_before}")
print(f"orchestrator_lines_after:  {orchestrator_lines_after}")
