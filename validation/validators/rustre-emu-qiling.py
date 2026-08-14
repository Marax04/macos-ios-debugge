#!/usr/bin/env python3
"""Independent validator for rustre-emu-qiling crate.

Validates the actual source against the report claims using only stdlib.
Counts pub fn in impl blocks per module, free pub fn, modules declared, etc.
"""
from __future__ import annotations
import json
import re
import sys
from pathlib import Path

CRATE = "rustre-emu-qiling"
ROOT = Path(__file__).resolve().parents[2]
CRATE_DIR = ROOT / "crates" / CRATE
SRC = CRATE_DIR / "src"
REPORT = ROOT / "validation" / "reports" / f"{CRATE}.md"


def read(p: Path) -> str:
    try:
        return p.read_text(encoding="utf-8", errors="replace")
    except FileNotFoundError:
        return ""


def strip_comments(s: str) -> str:
    # remove line comments
    s = re.sub(r"//[^\n]*", "", s)
    # remove block comments (non-nested approximation)
    s = re.sub(r"/\*.*?\*/", "", s, flags=re.DOTALL)
    return s


def find_impl_blocks(src: str) -> list[str]:
    """Return list of impl-block bodies (text between matching braces)."""
    blocks = []
    i = 0
    n = len(src)
    while i < n:
        m = re.search(r"\bimpl\b", src[i:])
        if not m:
            break
        start = i + m.start()
        # find opening brace
        brace = src.find("{", start)
        if brace < 0:
            break
        depth = 1
        j = brace + 1
        while j < n and depth > 0:
            c = src[j]
            if c == "{":
                depth += 1
            elif c == "}":
                depth -= 1
            j += 1
        blocks.append(src[brace + 1 : j - 1])
        i = j
    return blocks


def count_pub_fn_in_impls(src: str) -> int:
    src = strip_comments(src)
    total = 0
    for body in find_impl_blocks(src):
        total += len(re.findall(r"\bpub\s+(?:async\s+)?(?:unsafe\s+)?(?:const\s+)?fn\b", body))
    return total


def count_free_pub_fn(src: str) -> int:
    """pub fn outside impl blocks."""
    src = strip_comments(src)
    # Mask impl blocks
    masked = list(src)
    i = 0
    n = len(src)
    while i < n:
        m = re.search(r"\bimpl\b", src[i:])
        if not m:
            break
        start = i + m.start()
        brace = src.find("{", start)
        if brace < 0:
            break
        depth = 1
        j = brace + 1
        while j < n and depth > 0:
            if src[j] == "{":
                depth += 1
            elif src[j] == "}":
                depth -= 1
            j += 1
        for k in range(start, j):
            masked[k] = " "
        i = j
    outside = "".join(masked)
    return len(re.findall(r"\bpub\s+(?:async\s+)?(?:unsafe\s+)?(?:const\s+)?fn\b", outside))


# Per-report expectations
EXPECTED_METHODS = {
    "lib.rs": 145,
    "qiling_windows": 39,
    "qiling_memory": 46,
    "qiling_hook_manager": 17,
    "qiling_coverage": 24,
    "qiling_backend": 26,
    "qiling_analysis": 51,
    "qiling_posix": 9,
    "qiling_result_parser": 7,
    "qiling_script_gen": 15,
    "rootfs_manager": 26,
    "fs_manager": 39,
    "os_syscall_emu": 11,
    "os_posix_emulation": 29,
    "anti_evasion": 22,
}
EXPECTED_FREE_FNS = 5
EXPECTED_MODULES = [
    "os_syscall_emu", "os_posix_emulation", "qiling_analysis", "qiling_backend",
    "qiling_memory", "qiling_coverage", "qiling_result_parser", "qiling_script_gen",
    "qiling_hook_manager", "qiling_posix", "qiling_windows", "rootfs_manager",
    "fs_manager", "anti_evasion",
]
EXPECTED_FREE_FUNCS = [
    "default_linux_x86_64_table", "linux_x86_64", "shellcode_runner",
    "make_hook", "standard_bypasses",
]


def main() -> int:
    mismatches: list[dict] = []

    if not SRC.exists():
        print(json.dumps({"crate": CRATE, "error": f"missing src: {SRC}"}))
        return 1

    # Per-module method counts
    actual_methods = {}
    for mod, expected in EXPECTED_METHODS.items():
        fname = mod if mod.endswith(".rs") else f"{mod}.rs"
        path = SRC / fname
        src = read(path)
        if not src:
            mismatches.append({"kind": "missing_file", "module": mod, "expected": expected})
            actual_methods[mod] = 0
            continue
        n = count_pub_fn_in_impls(src)
        actual_methods[mod] = n
        if n != expected:
            mismatches.append({
                "kind": "method_count",
                "module": mod,
                "expected": expected,
                "actual": n,
            })

    # Free pub fn count (only counts top-level, not impl methods)
    free_total = 0
    for rs in SRC.rglob("*.rs"):
        free_total += count_free_pub_fn(read(rs))
    if free_total != EXPECTED_FREE_FNS:
        # Soft mismatch - note but informational because "free pub fn" definition can vary
        mismatches.append({
            "kind": "free_fn_count",
            "expected": EXPECTED_FREE_FNS,
            "actual": free_total,
        })

    # Module declarations in lib.rs
    lib = read(SRC / "lib.rs")
    declared = set(re.findall(r"\bpub\s+mod\s+(\w+)", lib))
    for m in EXPECTED_MODULES:
        if m not in declared:
            mismatches.append({"kind": "module_not_declared", "module": m})

    # Expected free functions exist somewhere
    all_src = "\n".join(read(p) for p in SRC.rglob("*.rs"))
    for fn in EXPECTED_FREE_FUNCS:
        if not re.search(rf"\bpub\s+(?:async\s+)?(?:unsafe\s+)?fn\s+{re.escape(fn)}\b", all_src):
            mismatches.append({"kind": "free_fn_missing", "fn": fn})

    # Tests files
    tests_dir = CRATE_DIR / "tests"
    for t in ("blitz.rs", "blitz2.rs"):
        if not (tests_dir / t).exists():
            mismatches.append({"kind": "missing_test", "file": t})

    result = {
        "crate": CRATE,
        "mismatches_count": len(mismatches),
        "mismatches": mismatches,
        "actual_methods": actual_methods,
        "free_fn_total": free_total,
    }
    print(json.dumps(result, indent=2))
    return 0 if not mismatches else 2


if __name__ == "__main__":
    sys.exit(main())
