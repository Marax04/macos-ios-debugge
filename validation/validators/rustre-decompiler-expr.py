#!/usr/bin/env python3
"""Independent validator for rustre-decompiler-expr crate.

Verifies structural expectations from reports/rustre-decompiler-expr.md using
only stdlib. Counts public items per module and checks listed modules exist.
"""
import json
import os
import re
import sys
from pathlib import Path

CRATE = "rustre-decompiler-expr"
ROOT = Path(__file__).resolve().parents[2] / "crates" / CRATE

EXPECTED_MODULES = [
    "lib.rs",
    "casts.rs",
    "expr_precedence.rs",
    "expr_pattern_matcher.rs",
    "expr_reconstruction.rs",
    "expr_simplification.rs",
    "expr_simplifier.rs",
    "expr_type_propagator.rs",
    "expression_recovery.rs",
    "pattern_library.rs",
    "peephole_optimizer.rs",
    "dag_simplifier.rs",
]

PUB_FN_RE = re.compile(r'^\s*pub(?:\s*\([^)]*\))?\s+(?:const\s+|async\s+|unsafe\s+|extern\s+(?:"[^"]*"\s+)?)*fn\s+\w+', re.MULTILINE)
PUB_CONST_RE = re.compile(r'^\s*pub(?:\s*\([^)]*\))?\s+const\s+[A-Z_][A-Z0-9_]*\s*:', re.MULTILINE)
PUB_TYPE_RE = re.compile(r'^\s*pub(?:\s*\([^)]*\))?\s+(?:struct|enum|trait)\s+\w+', re.MULTILINE)
PUB_ALIAS_RE = re.compile(r'^\s*pub(?:\s*\([^)]*\))?\s+type\s+\w+', re.MULTILINE)


def main():
    src = ROOT / "src"
    mismatches = 0
    fixed = 0

    if not src.is_dir():
        print(json.dumps({"crate": CRATE, "saved": True, "error": f"missing {src}"}))
        return

    # Check modules
    missing = []
    for m in EXPECTED_MODULES:
        if not (src / m).exists():
            missing.append(m)
            mismatches += 1

    # Aggregate counts
    total_fns = 0
    total_types = 0
    total_consts = 0
    total_aliases = 0
    for m in EXPECTED_MODULES:
        p = src / m
        if not p.exists():
            continue
        text = p.read_text(encoding="utf-8", errors="replace")
        total_fns += len(PUB_FN_RE.findall(text))
        total_types += len(PUB_TYPE_RE.findall(text))
        total_consts += len(PUB_CONST_RE.findall(text))
        total_aliases += len(PUB_ALIAS_RE.findall(text))

    # Report-stated approximate counts
    # ~115 fns, ~80 types, 3 consts, 1 alias
    checks = {
        "pub_fns_>=80": total_fns >= 80,
        "pub_types_>=60": total_types >= 60,
        "pub_consts_>=2": total_consts >= 2,
        "pub_aliases_>=1": total_aliases >= 1,
    }
    for name, ok in checks.items():
        if not ok:
            mismatches += 1

    match_final = mismatches == 0
    result = {
        "crate": CRATE,
        "saved": True,
        "match_final": match_final,
        "mismatches": mismatches,
        "fixed": fixed,
        "details": {
            "missing_modules": missing,
            "pub_fns": total_fns,
            "pub_types": total_types,
            "pub_consts": total_consts,
            "pub_aliases": total_aliases,
            "checks": checks,
        },
    }
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
