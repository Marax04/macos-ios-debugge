#!/usr/bin/env python3
"""Rimuove duplicati struct+impl da wire_tools.rs quando un tool è stato aggiunto due volte."""
import re, sys

WT = r"C:\Users\Fra\Desktop\RustRE\crates\rustre-mcp-tools\src\wire_tools.rs"

with open(WT, encoding='utf-8') as f:
    content = f.read()

# Find all struct defs with their names
pat = re.compile(r'^pub struct (\w+);', re.MULTILINE)
seen = {}
duplicates = []
for m in pat.finditer(content):
    name = m.group(1)
    pos = m.start()
    if name in seen:
        duplicates.append((name, pos, seen[name]))
    else:
        seen[name] = pos

print(f"Found {len(duplicates)} duplicate structs:")
for name, second_pos, first_pos in duplicates:
    print(f"  {name}  first@{first_pos} second@{second_pos}")

# For each duplicate, remove from second_pos backward until we find a delimiter
# and forward until we find the impl block end
if not duplicates:
    print("No duplicates.")
    sys.exit(0)

# Sort duplicates by position desc so removals don't shift earlier positions
duplicates.sort(key=lambda x: -x[1])

# For each duplicate: find the block (struct + impl blocks) and remove it
lines = content.split('\n')
# Rebuild content by identifying blocks to remove
# Find the line offset of each duplicate's second_pos
offset = 0
line_offsets = [0]
for l in lines:
    offset += len(l) + 1
    line_offsets.append(offset)

def pos_to_line(pos):
    lo, hi = 0, len(line_offsets)-1
    while lo < hi:
        mid = (lo+hi)//2
        if line_offsets[mid] <= pos < line_offsets[mid+1]:
            return mid
        elif line_offsets[mid] > pos:
            hi = mid
        else:
            lo = mid+1
    return lo

# Identify blocks to remove: from `pub struct DUP;` line to the end of the impl(s) for that struct
lines_to_remove = set()
for name, second_pos, first_pos in duplicates:
    start_line = pos_to_line(second_pos)
    # Find end: the impl block(s) end. Look for `impl ToolHandler for NAME {` and its matching }
    # Also look for `impl NAME {` for definition method
    end_line = start_line
    i = start_line
    braces = 0
    in_impl = False
    while i < len(lines):
        line = lines[i]
        if not in_impl:
            if re.match(rf'\s*(#\[.*\]\s*)?(pub struct {name};|impl (rustre_mcp_server::)?ToolHandler for {name}|impl {name})', line):
                in_impl = True
                braces = line.count('{') - line.count('}')
                if braces == 0 and 'pub struct' in line:
                    # struct decl has no braces, move on
                    end_line = i
                    i += 1
                    continue
            elif line.strip() == '':
                pass
            else:
                # different code, stop
                break
        else:
            braces += line.count('{') - line.count('}')
            if braces == 0:
                # end of block
                end_line = i
                in_impl = False
                # look ahead for another block for this name (next impl)
                j = i+1
                while j < len(lines) and lines[j].strip() == '':
                    j += 1
                if j < len(lines) and re.match(rf'\s*(#\[.*\]\s*)?(impl (rustre_mcp_server::)?ToolHandler for {name}|impl {name})', lines[j]):
                    i = j - 1
                else:
                    break
        i += 1
    for k in range(start_line, end_line + 1):
        lines_to_remove.add(k)
    print(f"Marking {end_line - start_line + 1} lines for removal for {name} (lines {start_line+1}-{end_line+1})")

new_lines = [l for i, l in enumerate(lines) if i not in lines_to_remove]
new_content = '\n'.join(new_lines)

# Also remove duplicate registrations in all_wire_handlers
# For each duplicate struct name, find all_wire_handlers body and remove second occurrence of registration
handlers_start = new_content.find('pub fn all_wire_handlers')
if handlers_start > 0:
    body_start = new_content.find('{', handlers_start)
    body_end = -1
    depth = 0
    for i in range(body_start, len(new_content)):
        if new_content[i] == '{': depth += 1
        elif new_content[i] == '}':
            depth -= 1
            if depth == 0:
                body_end = i
                break
    body = new_content[body_start:body_end]
    for name, _, _ in duplicates:
        # find all lines with this struct name in the body
        pattern = re.compile(rf'^\s*out\.push\(\({name}::definition\(\).*$', re.MULTILINE)
        matches = list(pattern.finditer(body))
        if len(matches) > 1:
            print(f"Removing {len(matches)-1} duplicate registrations for {name}")
            # Remove all but first
            for m in matches[1:][::-1]:
                body = body[:m.start()] + body[m.end():]
    new_content = new_content[:body_start] + body + new_content[body_end:]

with open(WT, 'w', encoding='utf-8') as f:
    f.write(new_content)
print(f"Wrote {WT}")
