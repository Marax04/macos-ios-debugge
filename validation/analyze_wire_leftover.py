"""
analyze_wire_leftover.py
Analyze wire_tools.rs to categorize top-level items after Round 1 split.
Outputs wire_leftover.json.
"""
import re
import json
from pathlib import Path

SRC = Path("C:/Users/Fra/Desktop/RustRE/crates/rustre-mcp-tools/src/wire_tools.rs")

# Known prefix → module mapping
PREFIX_TO_MODULE = {
    "Analysis": "tools/analysis.rs",
    "Loader": "tools/loader.rs",
    "Flirt": "tools/flirt.rs",
    "Diff": "tools/diff.rs",
    "Decompiler": "tools/decompiler.rs",
    "Decomp": "tools/decomp.rs",
    "DecompReg": "tools/decomp.rs",
    "DecompI": "tools/decomp.rs",
    "Patch": "tools/patch.rs",
    "Triage": "tools/triage.rs",
    "Demangle": "tools/demangle.rs",
    "Deobf": "tools/deobf.rs",
    "Emu": "tools/emu.rs",
    "Script": "tools/script.rs",
    "Symb": "tools/symb.rs",
    "Fuzz": "tools/fuzz.rs",
    "Adb": "tools/adb.rs",
    "Arch": "tools/arch.rs",
    "Arch6502": "tools/arch.rs",
    "Avr": "tools/arch.rs",
    "Arm": "tools/arch.rs",
    "Msp430": "tools/arch.rs",
    "Mips": "tools/arch.rs",
    "Ppc": "tools/arch.rs",
    "Sparc": "tools/arch.rs",
    "Z80": "tools/arch.rs",
    "RvB": "tools/arch.rs",
    "RvC": "tools/arch.rs",
    "Luajit": "tools/arch.rs",
    "M68k": "tools/arch.rs",
    "IlLift": "tools/il_lift.rs",
    "IlPass": "tools/il_passes.rs",
    "Bpf": "tools/bpf.rs",
    "Hex": "tools/hex.rs",
    "Mem": "tools/mem.rs",
    "Events": "tools/events.rs",
    "Symbols": "tools/symbols.rs",
    "Symbol": "tools/symbols.rs",
    "Pe": "tools/pe.rs",
    "Ti": "tools/ti.rs",
    "Db": "tools/db.rs",
    "Sandbox": "tools/sandbox.rs",
    "Sys": "tools/sys.rs",
    "Win32": "tools/win32.rs",
    "Ttd": "tools/ttd.rs",
    "Ds": "tools/ds.rs",
    "Net": "tools/net.rs",
    "Icmp": "tools/icmp.rs",
    "Function": "tools/analysis.rs",
    "Noreturn": "tools/analysis.rs",
    "Recover": "tools/analysis.rs",
    "Stack": "tools/analysis.rs",
    "FlirtApply": "tools/flirt.rs",
    "Forensic": "tools/forensics.rs",
    "Cfg": "tools/cfg.rs",
    "Ssa": "tools/ssa.rs",
    "Rs": "tools/rs_sym.rs",
    "Decomp": "tools/decomp.rs",
}

ORCHESTRATOR_FNS = {"all_wire_handlers", "wire_into_server"}
KEEP_FN_PATTERNS = [
    r"_extra_handlers$",
    r"_wire_handlers$",
]
MISC_ITEMS = {"WireToolAdapter", "wire_def_to_catalog", "vmlift_parse_semantic_wl"}

lines = SRC.read_text(encoding="utf-8", errors="replace").splitlines()

keep_in_wire_tools = []
move_to_misc = []
move_to_prefix_module = []

# Parse top-level pub fn / fn / pub struct / impl / macro items
# We look for lines at column 0

def match_prefix(name):
    for prefix, module in sorted(PREFIX_TO_MODULE.items(), key=lambda x: -len(x[0])):
        if name.startswith(prefix):
            return prefix, module
    return None, None

# Collect structs defined at top level (col 0)
pub_struct_re = re.compile(r'^pub struct (\w+)')
pub_fn_re = re.compile(r'^pub (?:async )?fn (\w+)')
fn_re = re.compile(r'^(?:async )?fn (\w+)')
impl_re = re.compile(r'^impl (\w+)')

i = 0
while i < len(lines):
    line = lines[i]
    lineno = i + 1

    # pub struct
    m = pub_struct_re.match(line)
    if m:
        name = m.group(1)
        if name in MISC_ITEMS:
            move_to_misc.append({"name": name, "line_start": lineno, "type": "pub struct"})
        else:
            prefix, module = match_prefix(name)
            if prefix:
                move_to_prefix_module.append({"item": name, "prefix": prefix, "module": module, "line_range": [lineno, lineno]})
            else:
                move_to_misc.append({"name": name, "line_start": lineno, "type": "pub struct (unmatched)"})
        i += 1
        continue

    # pub fn / pub async fn
    m = pub_fn_re.match(line)
    if m:
        name = m.group(1)
        if name in ORCHESTRATOR_FNS:
            keep_in_wire_tools.append(name)
        elif any(re.search(p, name) for p in KEEP_FN_PATTERNS):
            keep_in_wire_tools.append(name)
        elif name in MISC_ITEMS:
            move_to_misc.append({"name": name, "line_start": lineno, "type": "pub fn"})
        else:
            prefix, module = match_prefix(name)
            if prefix:
                move_to_prefix_module.append({"item": name, "prefix": prefix, "module": module, "line_range": [lineno, lineno]})
            else:
                keep_in_wire_tools.append(name + " (unclassified pub fn)")
        i += 1
        continue

    i += 1

# Count impl XxxTool blocks (non-ToolHandler)
impl_tool_re = re.compile(r'^impl ([A-Z]\w+Tool)')
impl_th_re = re.compile(r'^impl ToolHandler for (\w+)')

impl_tool_count = 0
impl_th_count = 0
for line in lines:
    if impl_tool_re.match(line):
        impl_tool_count += 1
    if impl_th_re.match(line):
        impl_th_count += 1

result = {
    "keep_in_wire_tools": keep_in_wire_tools,
    "move_to_misc": move_to_misc,
    "move_to_prefix_module": move_to_prefix_module,
    "stats": {
        "total_lines": len(lines),
        "impl_tool_blocks": impl_tool_count,
        "impl_toolhandler_blocks": impl_th_count,
        "keep_count": len(keep_in_wire_tools),
        "misc_count": len(move_to_misc),
        "prefix_count": len(move_to_prefix_module),
    }
}

out = Path("C:/Users/Fra/Desktop/RustRE/validation/wire_leftover.json")
out.write_text(json.dumps(result, indent=2), encoding="utf-8")
print(f"Written {out}")
print(f"Stats: {result['stats']}")
