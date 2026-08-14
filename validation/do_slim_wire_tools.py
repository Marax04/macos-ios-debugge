#!/usr/bin/env python3
"""Mechanical extraction of items from wire_tools.rs into prefix modules."""

import json
import re
import sys
from pathlib import Path

WIRE_TOOLS = Path("C:/Users/Fra/Desktop/RustRE/crates/rustre-mcp-tools/src/wire_tools.rs")
TOOLS_DIR  = Path("C:/Users/Fra/Desktop/RustRE/crates/rustre-mcp-tools/src/tools")
MANIFEST   = Path("C:/Users/Fra/Desktop/RustRE/validation/wire_leftover.json")

manifest = json.loads(MANIFEST.read_text())
lines = WIRE_TOOLS.read_text(encoding="utf-8").splitlines(keepends=True)
total = len(lines)
print(f"wire_tools.rs loaded: {total} lines")

def find_block_end(lines, start_0):
    """
    Given 0-indexed start line (struct definition), find the 0-indexed last line
    of the complete block (struct + all impl blocks that belong to it).
    Returns exclusive end index.
    """
    # Scan forward consuming all contiguous impl blocks
    i = start_0
    n = len(lines)

    # First consume the struct definition line(s) — usually single line
    # Then consume any `impl XxxTool { ... }` or `#[async_trait]\nimpl ToolHandler ...`
    # We do brace counting for each top-level block

    def consume_braced_block(idx):
        """From idx, scan until brace depth returns to 0. Returns next idx after closing }."""
        depth = 0
        while idx < n:
            for ch in lines[idx]:
                if ch == '{':
                    depth += 1
                elif ch == '}':
                    depth -= 1
                    if depth == 0:
                        return idx + 1
            idx += 1
        return idx

    # The struct itself may be a one-liner (ends with ;) or multi-line with {}
    # First, consume the struct definition
    struct_line = lines[start_0]
    if '{' in struct_line and '}' in struct_line:
        # Single-line struct like: pub struct Foo; (no braces) or with inline impls
        # Count braces
        opens = struct_line.count('{')
        closes = struct_line.count('}')
        if opens == closes:
            i = start_0 + 1
        else:
            i = consume_braced_block(start_0)
    elif '{' in struct_line:
        i = consume_braced_block(start_0)
    else:
        # Unit struct: pub struct Foo;
        i = start_0 + 1

    # Now consume following impl blocks (including #[async_trait], #[allow(...)] attributes)
    while i < n:
        stripped = lines[i].strip()
        # Skip blank lines and attributes between blocks
        if stripped == '' or stripped.startswith('#[') or stripped == '#[async_trait]':
            # Peek ahead: is there an impl block soon?
            j = i + 1
            while j < n and (lines[j].strip() == '' or lines[j].strip().startswith('#[')):
                j += 1
            if j < n and lines[j].strip().startswith('impl '):
                i = j  # advance to the impl line
                continue
            else:
                break
        elif stripped.startswith('impl '):
            i = consume_braced_block(i)
        else:
            break

    return i


# Collect items to move, grouped by module
from collections import defaultdict
by_module = defaultdict(list)
for item in manifest['move_to_prefix_module']:
    by_module[item['module']].append(item)

# Process items: extract code blocks
removed_ranges = []  # list of (start_0, end_0_exclusive) to remove

module_appends = defaultdict(list)  # module path -> list of text chunks

for item in manifest['move_to_prefix_module']:
    name = item['item']
    start_1 = item['line_range'][0]
    start_0 = start_1 - 1

    # Include preceding doc-comment lines (/// or //)
    doc_start = start_0
    while doc_start > 0 and lines[doc_start - 1].strip().startswith('///'):
        doc_start -= 1

    end_0 = find_block_end(lines, start_0)

    block_lines = lines[doc_start:end_0]
    block_text = ''.join(block_lines)

    module_appends[item['module']].append((name, block_text))
    removed_ranges.append((doc_start, end_0))
    print(f"  {name}: lines {doc_start+1}–{end_0} ({end_0-doc_start} lines) -> {item['module']}")

# Write to target module files
items_moved = 0
for module_rel, items in module_appends.items():
    target = TOOLS_DIR / Path(module_rel).name
    existing = target.read_text(encoding="utf-8") if target.exists() else ""
    additions = "\n".join(text for _, text in items)
    if not existing.endswith("\n"):
        existing += "\n"
    target.write_text(existing + "\n" + additions, encoding="utf-8")
    items_moved += len(items)
    print(f"Appended {len(items)} items to {target}")

# Build misc.rs
misc_path = TOOLS_DIR / "misc.rs"
misc_content = '//! Miscellaneous MCP wire tools extracted from wire_tools.rs.\n'
misc_items = manifest.get('move_to_misc', [])
for item in misc_items:
    name = item['item']
    start_0 = item['line_range'][0] - 1
    doc_start = start_0
    while doc_start > 0 and lines[doc_start - 1].strip().startswith('///'):
        doc_start -= 1
    end_0 = find_block_end(lines, start_0)
    block_text = ''.join(lines[doc_start:end_0])
    misc_content += '\n' + block_text
    removed_ranges.append((doc_start, end_0))
misc_path.write_text(misc_content, encoding="utf-8")
misc_lines = misc_content.count('\n') + (1 if not misc_content.endswith('\n') else 0)
print(f"misc.rs written: {misc_lines} lines")

# Add pub mod misc; to mod.rs if not already present
mod_rs = TOOLS_DIR / "mod.rs"
mod_content = mod_rs.read_text(encoding="utf-8")
if 'pub mod misc;' not in mod_content:
    # Insert alphabetically near 'mem' section
    mod_content = mod_content.replace('pub mod mem;\n', 'pub mod mem;\npub mod misc;\n')
    if 'pub mod misc;' not in mod_content:
        mod_content += '\npub mod misc;\n'
    mod_rs.write_text(mod_content, encoding="utf-8")
    print("Added pub mod misc; to mod.rs")

# Remove extracted ranges from wire_tools.rs
# Merge overlapping/adjacent ranges and sort
removed_ranges.sort()
merged = []
for s, e in removed_ranges:
    if merged and s <= merged[-1][1]:
        merged[-1] = (merged[-1][0], max(merged[-1][1], e))
    else:
        merged.append([s, e])

# Build new wire_tools lines
remove_set = set()
for s, e in merged:
    for i in range(s, e):
        remove_set.add(i)

new_lines = [l for i, l in enumerate(lines) if i not in remove_set]
new_content = ''.join(new_lines)
WIRE_TOOLS.write_text(new_content, encoding="utf-8")
wire_lines_after = len(new_lines)
print(f"wire_tools.rs rewritten: {wire_lines_after} lines (removed {len(remove_set)} lines)")

result = {
    "misc_lines": misc_lines,
    "wire_tools_lines_after": wire_lines_after,
    "items_moved": items_moved,
    "notes": f"Moved {items_moved} items to prefix modules; misc.rs has {misc_lines} lines (no move_to_misc items)."
}
print(json.dumps(result))
