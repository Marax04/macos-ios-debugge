"""
do_phase2_disable.py
Disable 8 rustre-debug backend crates from the RustRE workspace.
Crates: rustre-debug-gdb, rustre-debug-kgdb, rustre-debug-linux,
        rustre-debug-macos, rustre-debug-registry, rustre-debug-unicorn,
        rustre-debug-windbg, rustre-debug-windows

Follows the same pattern already used for rustre-decompiler-ghidra,
rustre-debug-frida, rustre-symb-z3, rustre-emu-qiling, rustre-emu-unicorn.

Run from any directory — uses absolute paths throughout.
"""

import re
import sys
from pathlib import Path

ROOT = Path("C:/Users/Fra/Desktop/RustRE")

DISABLED_CRATES = [
    "rustre-debug-gdb",
    "rustre-debug-kgdb",
    "rustre-debug-linux",
    "rustre-debug-macos",
    "rustre-debug-registry",
    "rustre-debug-unicorn",
    "rustre-debug-windbg",
    "rustre-debug-windows",
]

# Rationale comments for each disabled crate lib.rs header
RATIONALE = {
    "rustre-debug-gdb":      "GDB remote-serial-protocol backend; replaced by rustre-debug internal modules.",
    "rustre-debug-kgdb":     "KGDB kernel-debug backend; replaced by rustre-debug internal modules.",
    "rustre-debug-linux":    "Linux ptrace/procfs backend; replaced by rustre-debug internal modules.",
    "rustre-debug-macos":    "macOS Mach-port task backend; replaced by rustre-debug internal modules.",
    "rustre-debug-registry": "Debug-backend registry aggregator; replaced by rustre-debug internal dispatch.",
    "rustre-debug-unicorn":  "Unicorn-CPU emulation debug shim; replaced by rustre-debug internal modules.",
    "rustre-debug-windbg":   "WinDbg/DbgEng COM wrapper; replaced by rustre-debug internal modules.",
    "rustre-debug-windows":  "Win32 debug-event loop backend; replaced by rustre-debug internal modules.",
}

DISABLE_DATE = "2026-07-12"

files_modified = 0
tools_gated = 0


def read(p: Path) -> str:
    return p.read_text(encoding="utf-8")


def write(p: Path, text: str):
    global files_modified
    p.write_text(text, encoding="utf-8")
    files_modified += 1


def comment_line(text: str, line_content: str, label: str) -> str:
    """Comment out an exact line in text, adding a DISABLED label."""
    # Match line_content exactly (strip trailing whitespace for robustness)
    pat = re.compile(r'^(' + re.escape(line_content.rstrip()) + r'.*)$', re.MULTILINE)
    replacement = f'# [DISABLED {DISABLE_DATE}] {label}\n    # \\1'
    new, n = pat.subn(replacement, text, count=1)
    if n == 0:
        print(f"  WARN: could not find line to comment: {line_content!r}", file=sys.stderr)
    return new


def comment_exact(text: str, exact: str, replacement: str) -> str:
    """Replace an exact string once."""
    if exact not in text:
        print(f"  WARN: exact string not found:\n  {exact!r}", file=sys.stderr)
        return text
    return text.replace(exact, replacement, 1)


# ─── 1. workspace Cargo.toml ─────────────────────────────────────────────────
print("[1] Patching workspace Cargo.toml …")
wct = ROOT / "Cargo.toml"
txt = read(wct)
for crate in DISABLED_CRATES:
    member_line = f'    "crates/{crate}",'
    if member_line in txt and f'# "crates/{crate}"' not in txt:
        txt = txt.replace(
            member_line,
            f'    # [DISABLED {DISABLE_DATE}] {crate} — {RATIONALE[crate]}\n'
            f'    # "{crate.replace("rustre-", "crates/rustre-")}",',
        )
        # fix the path — the replace above produces a wrong path
        # let's do it cleanly
        txt = txt.replace(
            f'    # "{crate.replace("rustre-", "crates/rustre-")}",',
            f'    # "crates/{crate}",',
        )
        print(f"  commented out member: {crate}")
write(wct, txt)

# ─── 2. rustre-mcp-tools/Cargo.toml ─────────────────────────────────────────
print("[2] Patching mcp-tools/Cargo.toml …")
mct = ROOT / "crates/rustre-mcp-tools/Cargo.toml"
txt = read(mct)
for crate in DISABLED_CRATES:
    dep_line = f'{crate} = {{ path = "../{crate}" }}'
    if dep_line in txt:
        txt = txt.replace(
            dep_line,
            f'# [DISABLED {DISABLE_DATE}] {crate} — see workspace Cargo.toml.\n# {dep_line}',
        )
        print(f"  commented out dep: {crate}")
    else:
        print(f"  (no dep line for {crate} — skipping)")
write(mct, txt)

# ─── 3. tools/mod.rs ─────────────────────────────────────────────────────────
print("[3] Patching tools/mod.rs …")
mod_rs = ROOT / "crates/rustre-mcp-tools/src/tools/mod.rs"
txt = read(mod_rs)

# Maps: crate → mod name(s) to disable
MODS_TO_DISABLE = {
    "rustre-debug-gdb":     ["gdb"],
    "rustre-debug-kgdb":    ["kgdb"],
    "rustre-debug-linux":   [],        # lives inside debug.rs, no separate mod
    "rustre-debug-macos":   ["debug_macos"],
    "rustre-debug-registry": [],       # no separate mod
    "rustre-debug-unicorn": ["debug_unicorn"],
    "rustre-debug-windbg":  ["debug_windbg"],
    "rustre-debug-windows": ["debug_windows"],
}
for crate, mods in MODS_TO_DISABLE.items():
    for m in mods:
        pub_mod = f'pub mod {m};'
        if pub_mod in txt and f'// pub mod {m};' not in txt:
            txt = txt.replace(
                pub_mod,
                f'// [DISABLED {DISABLE_DATE}] {crate} dep disabled.\n// {pub_mod}',
            )
            print(f"  commented out: pub mod {m};")
write(mod_rs, txt)

# ─── 4 + 5. wire_tools.rs — use statements, all.extend, and #[cfg(any())] ───
print("[4+5+6] Patching wire_tools.rs …")
wt = ROOT / "crates/rustre-mcp-tools/src/wire_tools.rs"
txt = read(wt)

# --- 4a. Comment out use statements ---
use_stmts = [
    ("use crate::tools::debug_macos::*;",   "rustre-debug-macos disabled"),
    ("use crate::tools::debug_unicorn::*;", "rustre-debug-unicorn disabled"),
    ("use crate::tools::debug_windbg::*;",  "rustre-debug-windbg disabled"),
    ("use crate::tools::debug_windows::*;", "rustre-debug-windows disabled"),
    ("use crate::tools::gdb::*;",            "rustre-debug-gdb disabled"),
    ("use crate::tools::kgdb::*;",           "rustre-debug-kgdb disabled"),
]
for stmt, label in use_stmts:
    if stmt in txt and f'// [DISABLED' not in txt[max(0, txt.index(stmt)-60):txt.index(stmt)]:
        txt = txt.replace(stmt, f'// [DISABLED {DISABLE_DATE}] {label}\n// {stmt}')
        print(f"  commented out use: {stmt}")

# --- 4b. Comment out all.extend calls ---
extend_stmts = [
    "all.extend(crate::tools::debug_macos::handlers());",
    "all.extend(crate::tools::debug_unicorn::handlers());",
    "all.extend(crate::tools::debug_windbg::handlers());",
    "all.extend(crate::tools::debug_windows::handlers());",
    "all.extend(crate::tools::gdb::handlers());",
    "all.extend(crate::tools::kgdb::handlers());",
]
for stmt in extend_stmts:
    if stmt in txt:
        txt = txt.replace(stmt, f'// [DISABLED {DISABLE_DATE}] {stmt}')
        print(f"  commented out extend: {stmt}")

# --- 6. Gate impl blocks in wire_tools.rs ---
# Strategy: add  #[cfg(any())]  before each impl block that references a disabled crate.
# We gate BOTH the definition impl and the ToolHandler impl.

def gate_impl(text: str, marker: str, label: str) -> tuple[str, int]:
    """Add #[cfg(any())] before `marker` (which is the start of an impl block or doc comment).
    Returns (new_text, count_gated).
    """
    gate = f'#[cfg(any())] // DISABLED {DISABLE_DATE} — {label}\n'
    if marker in text:
        # Only gate if not already gated
        idx = text.index(marker)
        before = text[max(0, idx-60):idx]
        if '#[cfg(any())]' not in before:
            text = text[:idx] + gate + text[idx:]
            return text, 1
    else:
        print(f"  WARN: gate marker not found: {marker!r}", file=sys.stderr)
    return text, 0

# Pairs (section_comment_or_impl_start, crate_label)
# We gate the section marker comment (or the impl start if no section comment)
# then each individual impl + ToolHandler impl block.

GATES = [
    # rustre-debug-unicorn
    ("/// Wrapper: decode `MemRegion` permission bits (read/write/execute) via\n/// `rustre_debug_unicorn::MemRegion` helper methods.",
     "rustre-debug-unicorn disabled"),
    ("#[async_trait]\nimpl ToolHandler for DebugUnicornMemRegionPermsTool {",
     "rustre-debug-unicorn disabled"),
    ("/// Wrapper: report the pointer size (bytes) for a `v2::UnicornArch` variant.",
     "rustre-debug-unicorn disabled"),
    ("#[async_trait]\nimpl ToolHandler for DebugUnicornArchPointerSizeTool {",
     "rustre-debug-unicorn disabled"),
    # rustre-debug-kgdb
    ("impl KgdbBytesToHexTool {\n    #[must_use]",
     "rustre-debug-kgdb disabled"),
    ("#[async_trait]\nimpl ToolHandler for KgdbBytesToHexTool {",
     "rustre-debug-kgdb disabled"),
    ("impl KgdbHexToBytesTool {\n    #[must_use]",
     "rustre-debug-kgdb disabled"),
    ("#[async_trait]\nimpl ToolHandler for KgdbHexToBytesTool {",
     "rustre-debug-kgdb disabled"),
    # rustre-debug-windows
    ("// --- rustre-debug-windows wrappers ---",
     "rustre-debug-windows disabled"),
    ("impl DebugWindowsIsCommittedTool {\n    #[must_use]",
     "rustre-debug-windows disabled"),
    ("#[async_trait]\nimpl ToolHandler for DebugWindowsIsCommittedTool {",
     "rustre-debug-windows disabled"),
    ("impl DebugWindowsExceptionNameTool {\n    #[must_use]",
     "rustre-debug-windows disabled"),
    ("#[async_trait]\nimpl ToolHandler for DebugWindowsExceptionNameTool {",
     "rustre-debug-windows disabled"),
    # rustre-debug-macos  (uses non-ASCII dashes in the marker)
    ("impl DebugMacosBreakpointManagerBuildTool {\n    #[must_use]",
     "rustre-debug-macos disabled"),
    ("#[async_trait]\nimpl ToolHandler for DebugMacosBreakpointManagerBuildTool {",
     "rustre-debug-macos disabled"),
    ("impl DebugMacosProcessDescribeTool {\n    #[must_use]",
     "rustre-debug-macos disabled"),
    ("#[async_trait]\nimpl ToolHandler for DebugMacosProcessDescribeTool {",
     "rustre-debug-macos disabled"),
    # rustre-debug-gdb
    ("// --- rustre-debug-gdb wrappers",
     "rustre-debug-gdb disabled"),
    ("impl GdbPacketChecksumTool {\n    #[must_use]",
     "rustre-debug-gdb disabled"),
    ("#[async_trait]\nimpl ToolHandler for GdbPacketChecksumTool {",
     "rustre-debug-gdb disabled"),
    ("impl GdbPacketEncodeTool {\n    #[must_use]",
     "rustre-debug-gdb disabled"),
    ("#[async_trait]\nimpl ToolHandler for GdbPacketEncodeTool {",
     "rustre-debug-gdb disabled"),
    # rustre-debug-windbg
    ("/// Report the display string for the `WinDbg` `NoDebuggee` execution status.",
     "rustre-debug-windbg disabled"),
    ("#[async_trait]\nimpl ToolHandler for DebugWindbgExecutionStatusNoDebuggeeTool {",
     "rustre-debug-windbg disabled"),
    ("impl DebugWindbgDefaultModuleCountTool {\n    #[must_use]",
     "rustre-debug-windbg disabled"),
    ("#[async_trait]\nimpl ToolHandler for DebugWindbgDefaultModuleCountTool {",
     "rustre-debug-windbg disabled"),
    # rustre-debug-linux (inline in wire_tools.rs)
    ("impl DebugLinuxProcMapsParseLineTool {\n    #[must_use]",
     "rustre-debug-linux disabled"),
    ("#[async_trait]\nimpl ToolHandler for DebugLinuxProcMapsParseLineTool {",
     "rustre-debug-linux disabled"),
    ("impl DebugLinuxProcMapsParseCountTool {\n    #[must_use]",
     "rustre-debug-linux disabled"),
    ("#[async_trait]\nimpl ToolHandler for DebugLinuxProcMapsParseCountTool {",
     "rustre-debug-linux disabled"),
]

for marker, label in GATES:
    txt, n = gate_impl(txt, marker, label)
    if n:
        tools_gated += n
        print(f"  gated: {marker[:60]!r}…")

write(wt, txt)

# ─── Gate debug.rs — DebugLinuxProcMapsParseLineTool / DebugLinuxProcMapsParseCountTool ─
print("[6b] Patching tools/debug.rs …")
dbg = ROOT / "crates/rustre-mcp-tools/src/tools/debug.rs"
txt = read(dbg)

# Gate the struct definitions
for struct_name in ["DebugLinuxProcMapsParseLineTool", "DebugLinuxProcMapsParseCountTool"]:
    marker = f'pub struct {struct_name};'
    gate = f'#[cfg(any())] // DISABLED {DISABLE_DATE} — rustre-debug-linux disabled\n'
    if marker in txt and '#[cfg(any())]' not in txt[max(0, txt.index(marker)-60):txt.index(marker)]:
        idx = txt.index(marker)
        txt = txt[:idx] + gate + txt[idx:]
        tools_gated += 1
        print(f"  gated struct: {struct_name}")

# Comment out handlers() entries for these structs
for struct_name in ["DebugLinuxProcMapsParseLineTool", "DebugLinuxProcMapsParseCountTool"]:
    entry = f'({struct_name}::definition(), Box::new({struct_name})),'
    if entry in txt:
        txt = txt.replace(entry, f'// [DISABLED {DISABLE_DATE}] ({struct_name}::definition(), Box::new({struct_name})),')
        print(f"  commented out handlers() entry: {struct_name}")

write(dbg, txt)

# ─── 7. Add MODULE DISABLED header to each disabled crate's lib.rs ───────────
print("[7] Adding MODULE DISABLED headers to disabled crate lib.rs files …")
HEADER_TMPL = '''\
//! # MODULE DISABLED {date}
//!
//! This crate has been temporarily removed from the RustRE workspace build.
//! Rationale: {rationale}
//!
//! User preference: custom debugger only (rustre-debug); these 8 platform
//! backends will be replaced by rustre-debug internal modules.
//! To re-enable: restore the member line in the workspace Cargo.toml and
//! remove this header.

'''

for crate in DISABLED_CRATES:
    lib_rs = ROOT / f"crates/{crate}/src/lib.rs"
    if not lib_rs.exists():
        print(f"  WARN: {lib_rs} does not exist — skipping", file=sys.stderr)
        continue
    txt = read(lib_rs)
    if "MODULE DISABLED" in txt:
        print(f"  (already has header: {crate})")
        continue
    header = HEADER_TMPL.format(date=DISABLE_DATE, rationale=RATIONALE[crate])
    txt = header + txt
    write(lib_rs, txt)
    print(f"  added header: {crate}/src/lib.rs")

# ─── Summary ──────────────────────────────────────────────────────────────────
print(f"\nDone. files_modified={files_modified}, tools_gated={tools_gated}")
print(f"DISABLED_CRATES={len(DISABLED_CRATES)}")
