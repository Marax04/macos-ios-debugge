#!/usr/bin/env python3
"""Remove duplicate impl ToolHandler blocks by struct name."""
import re

WT = r"C:\Users\Fra\Desktop\RustRE\crates\rustre-mcp-tools\src\wire_tools.rs"

with open(WT, encoding='utf-8') as f:
    content = f.read()

# Find all impl blocks and their struct names
# Pattern: matches optional #[async_trait] then impl ToolHandler for Name { ... }
impl_pat = re.compile(r'(#\[async_trait\]\s*)?impl(?:\s+rustre_mcp_server::)?\s+ToolHandler\s+for\s+(\w+)\s*\{', re.MULTILINE)

positions = []
for m in impl_pat.finditer(content):
    name = m.group(2)
    start = m.start()
    # Find matching closing brace
    brace_start = content.index('{', m.end() - 1)
    depth = 1
    i = brace_start + 1
    while i < len(content) and depth > 0:
        if content[i] == '{': depth += 1
        elif content[i] == '}': depth -= 1
        i += 1
    end = i
    positions.append((name, start, end))

seen = {}
duplicates = []
for name, start, end in positions:
    if name in seen:
        duplicates.append((name, start, end))
    else:
        seen[name] = (start, end)

print(f"Found {len(duplicates)} duplicate impl blocks")
if not duplicates:
    print("No dups.")
    import sys; sys.exit(0)

# Sort desc by start position
duplicates.sort(key=lambda x: -x[1])

# Also find any leftover "pub struct NAME;" for these names that appear AGAIN after first
struct_pat_name = lambda n: re.compile(rf'^pub struct {n};\s*\n', re.MULTILINE)

new_content = content
for name, start, end in duplicates:
    # Remove impl block
    # Include preceding blank line if present
    real_start = start
    while real_start > 0 and new_content[real_start-1] in ' \t':
        real_start -= 1
    if real_start > 0 and new_content[real_start-1] == '\n':
        # keep the newline
        pass
    # Also try to include leading struct decl if adjacent
    # Look backward up to 200 chars for "pub struct NAME;\n"
    look_start = max(0, real_start - 300)
    prefix = new_content[look_start:real_start]
    struct_re = re.compile(rf'pub struct {name};\s*\n')
    m2 = list(struct_re.finditer(prefix))
    if m2:
        last = m2[-1]
        # Check if very close (within 20 chars)
        if real_start - (look_start + last.end()) < 30:
            real_start = look_start + last.start()
    new_content = new_content[:real_start] + new_content[end:]
    print(f"Removed dup impl for {name}: {end-real_start} chars")

# Also remove duplicate registrations
handlers_start = new_content.find('pub fn all_wire_handlers')
if handlers_start > 0:
    body_start = new_content.find('{', handlers_start)
    depth = 0
    body_end = -1
    for i in range(body_start, len(new_content)):
        if new_content[i] == '{': depth += 1
        elif new_content[i] == '}':
            depth -= 1
            if depth == 0:
                body_end = i
                break
    body = new_content[body_start:body_end]
    for name in {n for n,_,_ in duplicates}:
        pattern = re.compile(rf'^\s*(\(|out\.push\(\(){name}::definition\(\).*$', re.MULTILINE)
        matches = list(pattern.finditer(body))
        if len(matches) > 1:
            for m in matches[1:][::-1]:
                body = body[:m.start()] + body[m.end():]
            print(f"Removed {len(matches)-1} dup regs for {name}")
    new_content = new_content[:body_start] + body + new_content[body_end:]

with open(WT, 'w', encoding='utf-8') as f:
    f.write(new_content)
print("Done")
