"""
Gate all impl/fn/macro blocks referencing disabled crates in wire_tools.rs and tools/emu.rs.
Pass 1: gate blocks that directly reference disabled crates.
Pass 2: gate blocks whose implementing type comes from a disabled/commented-out module.
Adds #[cfg(any())] before each affected item (preserving code, not deleting it).
Comments out handler entries in all_wire_handlers() for gated tools.

Disabled crates:
  rustre_decompiler_ghidra, rustre_debug_frida, rustre_symb_z3,
  rustre_emu_qiling, rustre_emu_unicorn
"""

import re
import os
import sys

DISABLED_CRATES = [
    'rustre_decompiler_ghidra',
    'rustre_debug_frida',
    'rustre_symb_z3',
    'rustre_emu_qiling',
    'rustre_emu_unicorn',
]
DISABLED_CRATE_RE = re.compile('|'.join(re.escape(d) for d in DISABLED_CRATES))

# Tool module files that are commented out in wire_tools.rs imports
DISABLED_MODULE_FILES = [
    'C:/Users/Fra/Desktop/RustRE/crates/rustre-mcp-tools/src/tools/emu_unicorn.rs',
    'C:/Users/Fra/Desktop/RustRE/crates/rustre-mcp-tools/src/tools/symb_z3.rs',
    'C:/Users/Fra/Desktop/RustRE/crates/rustre-mcp-tools/src/tools/frida.rs',
    'C:/Users/Fra/Desktop/RustRE/crates/rustre-mcp-tools/src/tools/ghidra.rs',
    'C:/Users/Fra/Desktop/RustRE/crates/rustre-mcp-tools/src/tools/ghidra_backend.rs',
    'C:/Users/Fra/Desktop/RustRE/crates/rustre-mcp-tools/src/tools/ghidra_pcode.rs',
]

CFG_TAG = '#[cfg(any())] // [DISABLED 2026-07-12]\n'
DISABLE_PREFIX = '// [DISABLED 2026-07-12] '


def collect_disabled_struct_names():
    """Collect pub struct names from disabled module files, plus
    any struct in emu.rs or wire_tools.rs already gated with #[cfg(any())]."""
    names = set()

    # From disabled module files
    for path in DISABLED_MODULE_FILES:
        if not os.path.exists(path):
            continue
        with open(path, 'r', encoding='utf-8') as f:
            for line in f:
                m = re.match(r'^\s*(?:#\[cfg\(any\(\)\)\]\s*)?pub\s+struct\s+(\w+)', line)
                if m:
                    names.add(m.group(1))

    # From emu.rs - structs already gated
    emu_path = 'C:/Users/Fra/Desktop/RustRE/crates/rustre-mcp-tools/src/tools/emu.rs'
    if os.path.exists(emu_path):
        prev_cfg = False
        with open(emu_path, 'r', encoding='utf-8') as f:
            for line in f:
                stripped = line.strip()
                if '#[cfg(any())]' in stripped:
                    prev_cfg = True
                    m = re.search(r'pub\s+struct\s+(\w+)', stripped)
                    if m:
                        names.add(m.group(1))
                        prev_cfg = False
                elif prev_cfg:
                    m = re.match(r'\s*pub\s+struct\s+(\w+)', line)
                    if m:
                        names.add(m.group(1))
                    prev_cfg = False
                else:
                    prev_cfg = False

    return names


def collect_block(lines, start):
    """Collect a brace-delimited block starting at lines[start].
    Returns (block_lines, next_index)."""
    block = [lines[start]]
    depth = lines[start].count('{') - lines[start].count('}')
    j = start + 1
    while depth > 0 and j < len(lines):
        block.append(lines[j])
        depth += lines[j].count('{') - lines[j].count('}')
        j += 1
    return block, j


def find_attr_start(result):
    """Look backwards in result for the start of an attribute/doc-comment block.
    Returns the index at which to insert #[cfg(any())]."""
    j = len(result) - 1
    while j >= 0:
        s = result[j].strip()
        if s.startswith('#[') or s.startswith('///') or s.startswith('//!'):
            j -= 1
        else:
            break
    return j + 1


def already_gated(result):
    """Return True if the immediately preceding non-empty line in result is #[cfg(any())]."""
    j = len(result) - 1
    while j >= 0 and result[j].strip() == '':
        j -= 1
    if j >= 0 and '#[cfg(any())]' in result[j]:
        return True
    # Also check via find_attr_start
    ins = find_attr_start(result)
    if ins > 0 and '#[cfg(any())]' in result[ins - 1]:
        return True
    # Check if any line in the attribute block contains cfg(any())
    for k in range(ins, len(result)):
        if '#[cfg(any())]' in result[k]:
            return True
    return False


def is_item_start(stripped):
    return (
        stripped.startswith('impl ')
        or stripped.startswith('pub fn ')
        or stripped.startswith('fn ')
        or stripped.startswith('pub(crate) fn ')
        or stripped.startswith('pub(super) fn ')
        or stripped.startswith('macro_rules!')
        or stripped.startswith('pub struct ')
        or stripped.startswith('struct ')
    )


def extract_impl_type(stripped):
    """Extract the type name from an impl line.
    'impl XxxTool {' -> 'XxxTool'
    'impl ToolHandler for XxxTool {' -> 'XxxTool'
    """
    m = re.match(r'impl\s+(?:\w+\s+for\s+)?(\w+)', stripped)
    if m:
        return m.group(1)
    return None


def process_file(path, disabled_types=None):
    """Process a Rust source file, gating items that reference disabled crates
    or implement disabled struct types.
    Returns (result_lines, gated_count, gated_type_names)."""
    with open(path, 'r', encoding='utf-8') as f:
        lines = f.readlines()

    if disabled_types is None:
        disabled_types = set()

    result = []
    gated_items = []
    gated_count = 0
    i = 0
    depth = 0

    while i < len(lines):
        line = lines[i]
        stripped = line.strip()

        # Single-line macro invocations: symb_z3_binop_eval_tool!(...);
        if depth == 0 and re.match(r'\w[\w_]*!\s*\(', stripped) and stripped.endswith(');'):
            if DISABLED_CRATE_RE.search(line) and not already_gated(result):
                ins = find_attr_start(result)
                result.insert(ins, CFG_TAG)
                gated_count += 1
            result.append(line)
            i += 1
            continue

        # Items with opening brace on same line
        if depth == 0 and is_item_start(stripped) and '{' in line:
            block, end_i = collect_block(lines, i)
            block_text = ''.join(block)
            needs_gate = False

            # Check 1: directly references disabled crates
            if DISABLED_CRATE_RE.search(block_text):
                needs_gate = True

            # Check 2: impl block for a disabled type
            if not needs_gate and stripped.startswith('impl '):
                impl_type = extract_impl_type(stripped)
                if impl_type and impl_type in disabled_types:
                    needs_gate = True

            if needs_gate and not already_gated(result):
                ins = find_attr_start(result)
                result.insert(ins, CFG_TAG)
                gated_count += 1
                m = re.match(r'(?:impl\s+(?:\w+\s+for\s+)?|pub(?:\(crate\))?\s+fn\s+|fn\s+|macro_rules!\s+)(\w+)', stripped)
                if m:
                    gated_items.append(m.group(1))

            result.extend(block)
            i = end_i
            continue

        depth += line.count('{') - line.count('}')
        if depth < 0:
            depth = 0
        result.append(line)
        i += 1

    return result, gated_count, gated_items


def comment_out_handlers(result, gated_items):
    """In registration functions (all_wire_handlers, etc.), comment out lines
    that call ::definition() on a gated tool."""
    if not gated_items:
        return result, 0

    pat = re.compile('(' + '|'.join(re.escape(n) for n in set(gated_items)) + r')::definition\b')

    new_result = []
    commented = 0
    for line in result:
        stripped = line.strip()
        if pat.search(line) and not stripped.startswith('//'):
            new_result.append(DISABLE_PREFIX + line)
            commented += 1
        else:
            new_result.append(line)
    return new_result, commented


def main():
    wire_path = 'C:/Users/Fra/Desktop/RustRE/crates/rustre-mcp-tools/src/wire_tools.rs'
    emu_path = 'C:/Users/Fra/Desktop/RustRE/crates/rustre-mcp-tools/src/tools/emu.rs'

    # Collect disabled struct names
    disabled_types = collect_disabled_struct_names()
    print(f'Collected {len(disabled_types)} disabled struct names')

    total_gated = 0
    all_gated_items = []

    for path in [wire_path, emu_path]:
        if not os.path.exists(path):
            print(f'SKIP (not found): {path}')
            continue
        print(f'Processing {path} ...')
        result, gated, gated_items = process_file(path, disabled_types)
        all_gated_items.extend(gated_items)
        total_gated += gated
        print(f'  -> gated {gated} new blocks')
        with open(path, 'w', encoding='utf-8') as f:
            f.writelines(result)

    # Comment out handler entries in wire_tools.rs
    if os.path.exists(wire_path):
        with open(wire_path, 'r', encoding='utf-8') as f:
            lines = f.readlines()
        lines, commented = comment_out_handlers(lines, all_gated_items)
        with open(wire_path, 'w', encoding='utf-8') as f:
            f.writelines(lines)
        print(f'  -> commented out {commented} handler entries in wire_tools.rs')
        total_gated_handlers = commented
    else:
        total_gated_handlers = 0

    print(f'\nTotal: {total_gated} blocks gated, {total_gated_handlers} handler entries commented')
    return total_gated, total_gated_handlers


if __name__ == '__main__':
    main()
