"""Independent validator for rustre-emu-unicorn crate.

Validates the report claims using only Python stdlib by inspecting the source tree.
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

CRATE = "rustre-emu-unicorn"
CRATE_ROOT = Path(r"C:\Users\Fra\Desktop\RustRE\crates\rustre-emu-unicorn")
SRC = CRATE_ROOT / "src"
CARGO = CRATE_ROOT / "Cargo.toml"

EXPECTED_FILE_COUNTS = {
    "arch_backends.rs": 1,
    "arch_register_maps.rs": 48,
    "coverage_hooks.rs": 29,
    "hook_manager.rs": 19,
    "instruction_trace.rs": 23,
    "lib.rs": 93,
    "memory_model.rs": 45,
    "os_hooks.rs": 15,
    "snapshot_manager.rs": 30,
    "unicorn_arch_support.rs": 21,
    "unicorn_bindings.rs": 40,
    "unicorn_context_manager.rs": 26,
    "unicorn_coverage.rs": 48,
    "unicorn_filesystem_emu.rs": 24,
    "unicorn_hooks.rs": 28,
    "unicorn_os_emulator.rs": 12,
    "unicorn_os_hooks.rs": 38,
    "unicorn_snapshot.rs": 33,
    "unicorn_syscall_linux.rs": 8,
}

EXPECTED_MODULES = [
    "arch_backends", "arch_register_maps", "coverage_hooks", "hook_manager",
    "instruction_trace", "memory_model", "os_hooks", "snapshot_manager",
    "unicorn_arch_support", "unicorn_bindings", "unicorn_context_manager",
    "unicorn_coverage", "unicorn_filesystem_emu", "unicorn_hooks",
    "unicorn_os_emulator", "unicorn_os_hooks", "unicorn_snapshot",
    "unicorn_syscall_linux",
]

EXPECTED_DEPS = ["rustre-emu", "thiserror", "serde", "serde_json", "parking_lot"]

PUB_FN_RE = re.compile(r"^\s*pub(?:\s*\([^)]*\))?\s+(?:async\s+|const\s+|unsafe\s+|extern\s+(?:\"[^\"]*\"\s+)?)*fn\b", re.MULTILINE)


def count_pub_fns(path: Path) -> int:
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except FileNotFoundError:
        return -1
    return len(PUB_FN_RE.findall(text))


def main() -> int:
    mismatches = 0
    findings = []

    if not CRATE_ROOT.exists():
        print(json.dumps({"crate": CRATE, "error": "crate root missing"}))
        return 1

    # Check Cargo.toml deps
    cargo_text = CARGO.read_text(encoding="utf-8", errors="replace") if CARGO.exists() else ""
    for dep in EXPECTED_DEPS:
        if dep not in cargo_text:
            mismatches += 1
            findings.append(f"missing dep: {dep}")

    # Check native feature presence and unicorn-engine commented
    if "native" not in cargo_text:
        mismatches += 1
        findings.append("native feature not declared")
    # unicorn-engine line should be commented out
    ue_lines = [ln for ln in cargo_text.splitlines() if "unicorn-engine" in ln]
    if ue_lines and not all(ln.strip().startswith("#") for ln in ue_lines):
        # report claims it's commented out; if uncommented this is a mismatch
        mismatches += 1
        findings.append("unicorn-engine dep appears uncommented")

    # Check expected modules exist
    for mod in EXPECTED_MODULES:
        if not (SRC / f"{mod}.rs").exists():
            mismatches += 1
            findings.append(f"missing module file: {mod}.rs")

    # Check pub fn counts per file (tolerate small drift +/- 2)
    total_actual = 0
    for fname, expected in EXPECTED_FILE_COUNTS.items():
        p = SRC / fname
        actual = count_pub_fns(p)
        if actual < 0:
            mismatches += 1
            findings.append(f"{fname}: file missing")
            continue
        total_actual += actual
        if abs(actual - expected) > 2:
            mismatches += 1
            findings.append(f"{fname}: expected ~{expected} pub fn, got {actual}")

    # Total around 641 (tolerate +/- 10)
    if abs(total_actual - 641) > 10:
        mismatches += 1
        findings.append(f"total pub fn ~641 expected, got {total_actual}")

    # Check Arch enum variants in lib.rs
    lib_text = (SRC / "lib.rs").read_text(encoding="utf-8", errors="replace")
    arch_variants = ["X86", "Arm", "Arm64", "Mips", "Sparc", "RiscV", "M68K", "Ppc", "S390X"]
    arch_match = re.search(r"enum\s+Arch\s*\{([^}]+)\}", lib_text)
    if not arch_match:
        mismatches += 1
        findings.append("enum Arch not found")
    else:
        body = arch_match.group(1)
        for v in arch_variants:
            if not re.search(rf"\b{v}\b", body):
                mismatches += 1
                findings.append(f"Arch variant missing: {v}")

    if not re.search(r"enum\s+Mode\b", lib_text):
        mismatches += 1
        findings.append("enum Mode not found")

    result = {
        "crate": CRATE,
        "mismatches": mismatches,
        "total_pub_fn": total_actual,
        "findings": findings[:30],
    }
    print(json.dumps(result, indent=2))
    return 0 if mismatches == 0 else 2


if __name__ == "__main__":
    sys.exit(main())
