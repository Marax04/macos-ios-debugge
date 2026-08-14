#!/usr/bin/env python3
"""Validator for rustre-mem crate based on validation/reports/rustre-mem.md.

Stdlib-only. Verifies that the report's claimed Cargo metadata, modules, and
public re-exports actually exist in the crate sources.
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

CRATE_NAME = "rustre-mem"
ROOT = Path(__file__).resolve().parents[2]
CRATE_DIR = ROOT / "crates" / CRATE_NAME
CARGO_TOML = CRATE_DIR / "Cargo.toml"
LIB_RS = CRATE_DIR / "src" / "lib.rs"
SRC_DIR = CRATE_DIR / "src"


def read(p: Path) -> str:
    try:
        return p.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def check_cargo(errs: list[str]) -> None:
    txt = read(CARGO_TOML)
    if not txt:
        errs.append("Cargo.toml missing")
        return
    if not re.search(r'name\s*=\s*"rustre-mem"', txt):
        errs.append("Cargo.toml: name != rustre-mem")
    if not re.search(r'version\s*=\s*"0\.1\.0"', txt):
        errs.append("Cargo.toml: version != 0.1.0")
    if not re.search(r'edition\s*=\s*"2024"', txt):
        errs.append("Cargo.toml: edition != 2024")
    for dep in ("rustre-core", "async-trait", "bitflags",
                "parking_lot", "thiserror", "serde", "serde_json"):
        if dep not in txt:
            errs.append(f"Cargo.toml: missing dep '{dep}'")
    if "windows-sys" not in txt:
        errs.append("Cargo.toml: missing windows-sys target dep")


def check_modules(errs: list[str]) -> None:
    lib = read(LIB_RS)
    if not lib:
        errs.append("src/lib.rs missing")
        return
    modules = [
        "access_log", "arena", "cache", "cache_layer", "composite_memory",
        "composite_provider", "cow", "diff", "emulated_memory", "entropy",
        "fault", "file_memory", "helpers", "memory_access_log",
        "memory_analysis", "memory_diff", "memory_layout_analyzer",
        "memory_provider", "null_memory", "patched_memory", "patched_provider",
        "permissions_model", "phys", "process_memory", "provider", "region",
        "search", "snapshot", "snapshot_diff", "sparse", "trace_memory",
        "trace_provider", "virtual_memory", "vmmap",
    ]
    for m in modules:
        if not re.search(rf'pub\s+mod\s+{re.escape(m)}\b', lib):
            errs.append(f"lib.rs: missing `pub mod {m}`")


def check_reexports(errs: list[str]) -> None:
    lib = read(LIB_RS)
    if not lib:
        return
    # representative symbols from the report
    symbols = [
        "MemoryProvider", "MemError", "MemoryRegion", "RegionSource",
        "SnapshotId", "ProviderMemoryStats", "ReadOnlyWrapper",
        "VirtualMemoryProvider", "NullMemoryProvider", "FileMemoryProvider",
        "CompositeMemoryProvider", "CowMemoryProvider",
        "PatchedMemoryProvider", "EmulatedMemoryProvider",
        "ProcessMemoryProvider", "TraceMemoryProvider",
        "SparseMemoryProvider", "LoggingMemoryProvider",
        "FaultingMemoryProvider", "PageCache", "MemoryArena",
        "FlatPhysMemory", "PhysicalMemory", "ExtendedPerms",
        "MemorySearcher", "SnapshotStore", "MemorySnapshot",
        "shannon_entropy", "diff_memory", "diff_providers",
    ]
    for s in symbols:
        # accept `pub use ... ::S` or `pub use ... ::{...S...}`
        if not re.search(rf'\b{re.escape(s)}\b', lib):
            errs.append(f"lib.rs: symbol '{s}' not referenced")


def check_helpers(errs: list[str]) -> None:
    helpers = read(SRC_DIR / "helpers.rs")
    if not helpers:
        errs.append("src/helpers.rs missing")
        return
    for fn in ("read_u8_at", "read_u16_le_at", "read_u32_le_at",
               "read_u64_le_at", "write_u8_at", "write_u32_le_at",
               "search_bytes_with_mask"):
        if fn not in helpers:
            errs.append(f"helpers.rs: missing fn '{fn}'")


def main() -> int:
    errs: list[str] = []
    if not CRATE_DIR.is_dir():
        errs.append(f"crate dir missing: {CRATE_DIR}")
        print(json.dumps({"crate": CRATE_NAME, "saved": False,
                          "errors": errs}))
        return 1
    check_cargo(errs)
    check_modules(errs)
    check_reexports(errs)
    check_helpers(errs)

    saved = len(errs) == 0
    out = {"crate": CRATE_NAME, "saved": saved}
    if errs:
        out["errors"] = errs
    print(json.dumps(out, indent=2))
    return 0 if saved else 1


if __name__ == "__main__":
    sys.exit(main())
