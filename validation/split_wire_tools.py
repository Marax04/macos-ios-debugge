#!/usr/bin/env python3
"""
split_wire_tools.py
-------------------
Splits crates/rustre-mcp-tools/src/wire_tools.rs (~91k lines, ~3950 tools)
into per-crate module files under crates/rustre-mcp-tools/src/tools/.

Outputs:
  tools/<crate>.rs   — tool structs + handlers() fn
  tools/mod.rs       — pub mod declarations
  wire_tools.rs      — slim orchestrator (~500 lines)
"""

import re
import os
import shutil
from collections import defaultdict

# ── paths ─────────────────────────────────────────────────────────────────────
WIRE_RS   = r"C:\Users\Fra\Desktop\RustRE\crates\rustre-mcp-tools\src\wire_tools.rs"
TOOLS_DIR = r"C:\Users\Fra\Desktop\RustRE\crates\rustre-mcp-tools\src\tools"
BACKUP    = WIRE_RS + ".backup"

# ── 1. backup ─────────────────────────────────────────────────────────────────
print(f"[1] Backing up {WIRE_RS} …")
shutil.copy2(WIRE_RS, BACKUP)
print(f"    -> {BACKUP}")

# ── 2. read source ────────────────────────────────────────────────────────────
print("[2] Reading source …")
with open(WIRE_RS, encoding="utf-8", errors="replace") as f:
    src = f.read()

lines = src.splitlines(keepends=True)
total_lines = len(lines)
print(f"    {total_lines} lines, {len(src):,} bytes")

# ── 3. find every 'pub struct XxxTool' position ───────────────────────────────
# We look for lines that START a tool block: "pub struct <Name>Tool;"
# (may appear after blank/comment lines; not inside impl bodies)
STRUCT_RE = re.compile(r'^pub struct (\w+Tool);', re.MULTILINE)

struct_matches = list(STRUCT_RE.finditer(src))
print(f"[3] Found {len(struct_matches)} tool structs")

# ── 4. slice into per-tool blocks ─────────────────────────────────────────────
# Each block = from the 'pub struct' line up to (but not including) the next one.
blocks = []
for i, m in enumerate(struct_matches):
    name = m.group(1)
    start = m.start()
    end   = struct_matches[i + 1].start() if i + 1 < len(struct_matches) else len(src)
    body  = src[start:end]
    blocks.append((name, body))

# ── 5. group by crate ─────────────────────────────────────────────────────────
CRATE_RE = re.compile(r'\b(rustre_[a-z][a-z0-9_]*)\s*::', re.ASCII)

def infer_crate(body: str) -> str:
    hits = CRATE_RE.findall(body)
    # Skip rustre_mcp_server (it's the plumbing, not the domain crate)
    for h in hits:
        if h != "rustre_mcp_server" and h != "rustre_core":
            # Convert rustre_foo_bar → foo_bar  (underscores, no leading rustre_)
            return h[len("rustre_"):]
    # fallback: also check for rustre_core as a fallback group
    for h in hits:
        if h == "rustre_core":
            return "core"
    return "misc"

groups: dict[str, list[tuple[str, str]]] = defaultdict(list)
for name, body in blocks:
    crate = infer_crate(body)
    groups[crate].append((name, body))

print("[4] Distribution by crate:")
for crate, tools in sorted(groups.items(), key=lambda x: -len(x[1])):
    print(f"    {crate:40s} {len(tools):5d} tools")

# ── 6. find non-tool content: everything BEFORE the first tool struct ──────────
# This is the file header (comment banners, use statements, helper fns, etc.)
first_struct_pos = struct_matches[0].start() if struct_matches else len(src)
header = src[:first_struct_pos]

# ── 7. find non-tool content BETWEEN tools and all_wire_handlers ──────────────
# all_wire_handlers starts at a known position; we need everything after the
# last tool impl block up to EOF that is NOT a tool struct.
# Strategy: collect the positions of every tool block and every 'non-tool' line.
# We'll extract: helper functions, all_wire_handlers, wire_into_server, etc.
# These are all in the body AFTER the last tool block ends.

# Find start of all_wire_handlers
AWH_RE = re.compile(r'^pub fn all_wire_handlers\(\)', re.MULTILINE)
awh_match = AWH_RE.search(src)
if not awh_match:
    raise RuntimeError("Could not find all_wire_handlers()")

awh_start = awh_match.start()

# Everything from start-of-file to first tool struct: header
# Everything between last tool struct and all_wire_handlers: interstitial helpers
last_tool_end = struct_matches[-1].start() + len(blocks[-1][1]) if blocks else 0
interstitial = src[last_tool_end:awh_start]

# all_wire_handlers block + everything after it (wire_into_server, SurveyBinaryTool etc.)
tail = src[awh_start:]

# ── 8. create tools/ directory ────────────────────────────────────────────────
os.makedirs(TOOLS_DIR, exist_ok=True)

# ── 9. write per-crate .rs files ─────────────────────────────────────────────
# Use header's use/extern lines verbatim as a preamble so fully-qualified names
# that appear in some blocks continue to compile; also add the common imports.
COMMON_USES = """\
#[allow(unused_imports)]
use rustre_mcp_server::{ToolDefinition, ToolHandler, ToolResult, McpError};
#[allow(unused_imports)]
use serde_json::{json, Value};
#[allow(unused_imports)]
use async_trait::async_trait;

"""

crate_names_sorted = sorted(groups.keys())
file_sizes: dict[str, int] = {}

for crate, tools in groups.items():
    path = os.path.join(TOOLS_DIR, f"{crate}.rs")
    body_parts = [
        f"//! MCP wrappers for rustre-{crate}.\n",
        COMMON_USES,
    ]
    for _name, block in tools:
        body_parts.append(block.rstrip("\n") + "\n\n")

    # handlers() function
    handler_lines = ["pub fn handlers() -> Vec<(rustre_mcp_server::ToolDefinition, Box<dyn rustre_mcp_server::ToolHandler>)> {\n"]
    handler_lines.append("    vec![\n")
    for name, _ in tools:
        handler_lines.append(f"        ({name}::definition(), Box::new({name})),\n")
    handler_lines.append("    ]\n")
    handler_lines.append("}\n")
    body_parts.extend(handler_lines)

    content = "".join(body_parts)
    with open(path, "w", encoding="utf-8") as f:
        f.write(content)
    file_sizes[crate] = len(content)
    print(f"    wrote {path}  ({len(tools)} tools, {len(content):,} bytes)")

# ── 10. write tools/mod.rs ────────────────────────────────────────────────────
mod_rs_path = os.path.join(TOOLS_DIR, "mod.rs")
mod_lines = ["//! Auto-generated module index for split wire tool files.\n\n"]
for crate in crate_names_sorted:
    mod_lines.append(f"pub mod {crate};\n")
with open(mod_rs_path, "w", encoding="utf-8") as f:
    f.write("".join(mod_lines))
print(f"    wrote {mod_rs_path}")

# ── 11. rewrite wire_tools.rs as slim orchestrator ────────────────────────────
# Keep: file header (banners), helper fns (rs_sym_core_extra_handlers etc.),
#        wire_def_to_catalog, WireToolAdapter, wire_into_server
# Rewrite: all_wire_handlers to use tools::<crate>::handlers()
# Remove: every tool struct/impl block

# Find push_decompiler_type_extra_handlers call in all_wire_handlers
PUSH_DECOMPILER_RE = re.compile(r'push_decompiler_type_extra_handlers\(&mut out\);')
# Also preserve rs_sym_core_extra_handlers call

# Determine which 'extra helper' calls existed in the old all_wire_handlers body
AWH_BODY_END_RE = re.compile(r'^}\s*$', re.MULTILINE)
# Find closing brace of all_wire_handlers
# We'll find the function body from awh_start
# Simple approach: find the tail after "pub fn all_wire_handlers"
awh_line_end = tail.index('\n') + 1  # rest after first line
# Find end of function via balanced-brace counting
depth = 0
idx = 0
inside = False
awh_body_end = -1
for ci, ch in enumerate(tail):
    if ch == '{':
        depth += 1
        inside = True
    elif ch == '}':
        depth -= 1
        if inside and depth == 0:
            awh_body_end = ci + 1
            break

if awh_body_end < 0:
    raise RuntimeError("Could not find end of all_wire_handlers")

awh_full_text = tail[:awh_body_end]
after_awh = tail[awh_body_end:]

# Detect extra calls that must be preserved
extra_calls = []
if 'push_decompiler_type_extra_handlers' in awh_full_text:
    extra_calls.append('    push_decompiler_type_extra_handlers(&mut out);')
if 'rs_sym_core_extra_handlers' in awh_full_text:
    extra_calls.append('    for (d, h) in rs_sym_core_extra_handlers() { out.push((d, h)); }')

# Build new all_wire_handlers
new_awh_lines = [
    "pub fn all_wire_handlers() -> Vec<(ToolDefinition, Box<dyn ToolHandler>)> {\n",
    "    let mut out: Vec<(ToolDefinition, Box<dyn ToolHandler>)> = Vec::new();\n",
]
for crate in crate_names_sorted:
    new_awh_lines.append(f"    out.extend(tools::{crate}::handlers());\n")
for call in extra_calls:
    new_awh_lines.append(call + "\n")
new_awh_lines.append("    out\n")
new_awh_lines.append("}\n")

new_awh = "".join(new_awh_lines)

# Build slim wire_tools.rs
slim_parts = [
    header,
    "\n",
    "pub mod tools;\n",
    "\n",
    interstitial,
    "\n",
    new_awh,
    after_awh,
]
slim = "".join(slim_parts)

with open(WIRE_RS, "w", encoding="utf-8") as f:
    f.write(slim)

slim_size = len(slim)
print(f"\n[5] Rewrote {WIRE_RS}")
print(f"    New size: {slim_size:,} bytes ({slim.count(chr(10))} lines)")

# ── 12. stats ─────────────────────────────────────────────────────────────────
total_tools = sum(len(v) for v in groups.values())
largest_crate = max(file_sizes, key=file_sizes.get)
print("\n--- STATS -----------------------------------------------------------")
print(f"  Total tools found        : {total_tools}")
print(f"  Crates (modules)         : {len(groups)}")
print(f"  Largest module           : {largest_crate} ({file_sizes[largest_crate]:,} bytes)")
print(f"  New wire_tools.rs size   : {slim_size:,} bytes")
print("---------------------------------------------------------------------")
print("Done.")
