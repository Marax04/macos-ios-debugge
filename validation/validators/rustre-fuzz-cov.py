#!/usr/bin/env python3
"""Independent validator for rustre-fuzz-cov crate.

Checks the crate against the spec in reports/rustre-fuzz-cov.md using only
the Python stdlib. Walks the crate source tree and validates:
  - Cargo.toml package name + required deps
  - Presence of 19 documented modules
  - Selected public structs/enums/functions surface
  - Lint configuration (unsafe_code allow, unused_must_use deny)

Output: JSON { "crate": "rustre-fuzz-cov", "saved": <bool> } on stdout.
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

CRATE = "rustre-fuzz-cov"

REPO_ROOT = Path(r"C:\Users\Fra\Desktop\RustRE")
CRATE_DIR_CANDIDATES = [
    REPO_ROOT / "crates" / CRATE,
    REPO_ROOT / CRATE,
]

REQUIRED_MODULES = [
    "casts",
    "block_coverage_tracker",
    "coverage_diff",
    "coverage_diff_reporter",
    "edge_coverage",
    "edge_coverage_tracker",
    "coverage_feedback",
    "coverage_guide",
    "coverage_minimizer",
    "coverage_persistence",
    "coverage_statistics",
    "coverage_map_merger",
    "lcov_export",
    "pt_integration",
    "qemu_tcg_cov",
    "sancov_instrumentation",
    "source_coverage_tracker",
    "source_coverage_mapper",
]

REQUIRED_DEPS = ["thiserror", "serde", "serde_json", "serde_bytes", "rayon"]

REQUIRED_TYPES = [
    ("enum", "CovError"),
    ("struct", "DrcovModule"),
    ("struct", "DrcovEntry"),
    ("struct", "DrcovFile"),
    ("struct", "DrcovHeader"),
    ("struct", "DrcovBasicBlock"),
    ("struct", "DrcovModuleV2"),
    ("struct", "DrcovFileV2"),
    ("struct", "CoverageRun"),
    ("struct", "CoverageDiff"),
    ("struct", "CoverageStats"),
    ("struct", "CoverageDatabase"),
    ("struct", "LcovRecord"),
    ("struct", "LcovParser"),
    ("struct", "PcGuardBitmap"),
    ("struct", "EdgeCoverageMap"),
    ("struct", "CmplogEntry"),
    ("struct", "CmplogMap"),
    ("struct", "CorpusPruner"),
    ("struct", "CoverageHistogram"),
]


def find_crate_dir() -> Path | None:
    for c in CRATE_DIR_CANDIDATES:
        if (c / "Cargo.toml").is_file():
            return c
    return None


def read(p: Path) -> str:
    try:
        return p.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def gather_src(crate_dir: Path) -> str:
    src = crate_dir / "src"
    if not src.is_dir():
        return ""
    out = []
    for f in src.rglob("*.rs"):
        out.append(read(f))
    return "\n".join(out)


def validate(crate_dir: Path) -> dict:
    findings = {
        "fixed": 0,
        "mismatches": 0,
        "details": [],
    }

    def mismatch(msg: str) -> None:
        findings["mismatches"] += 1
        findings["details"].append({"level": "mismatch", "msg": msg})

    def ok(msg: str) -> None:
        findings["fixed"] += 1
        findings["details"].append({"level": "ok", "msg": msg})

    cargo = read(crate_dir / "Cargo.toml")
    if re.search(r'^\s*name\s*=\s*"rustre-fuzz-cov"\s*$', cargo, re.M):
        ok("Cargo.toml package name")
    else:
        mismatch("Cargo.toml: package name 'rustre-fuzz-cov' not found")

    for dep in REQUIRED_DEPS:
        if re.search(rf'(?m)^\s*{re.escape(dep)}\s*=', cargo) or re.search(
            rf'\[dependencies\.{re.escape(dep)}\]', cargo
        ):
            ok(f"dep:{dep}")
        else:
            mismatch(f"Cargo.toml: missing dependency '{dep}'")

    # Lints
    lints_text = cargo
    lints_toml = crate_dir.parent.parent / "Cargo.toml"
    workspace_cargo = read(lints_toml) if lints_toml.is_file() else ""
    combined_lints = lints_text + "\n" + workspace_cargo
    if re.search(r'unsafe_code\s*=\s*"allow"', combined_lints):
        ok("lint: unsafe_code allow")
    else:
        mismatch("lints: unsafe_code = \"allow\" not declared in crate Cargo.toml")
    if re.search(r'unused_must_use\s*=\s*"deny"', combined_lints):
        ok("lint: unused_must_use deny")
    else:
        mismatch("lints: unused_must_use = \"deny\" not declared")

    # Modules
    src_dir = crate_dir / "src"
    lib_rs = read(src_dir / "lib.rs")
    for m in REQUIRED_MODULES:
        candidate_file = src_dir / f"{m}.rs"
        candidate_mod = src_dir / m / "mod.rs"
        declared = re.search(rf'(?m)^\s*(?:pub\s+)?mod\s+{re.escape(m)}\s*;', lib_rs) is not None
        if candidate_file.is_file() or candidate_mod.is_file() or declared:
            ok(f"module:{m}")
        else:
            mismatch(f"missing module '{m}' (no src/{m}.rs and not declared in lib.rs)")

    all_src = gather_src(crate_dir)

    # Type surface
    for kind, name in REQUIRED_TYPES:
        pat = rf'(?m)^\s*(?:pub(?:\([^)]*\))?\s+)?{kind}\s+{re.escape(name)}\b'
        if re.search(pat, all_src):
            ok(f"{kind}:{name}")
        else:
            mismatch(f"missing {kind} '{name}'")

    # Selected critical fn signatures
    fn_checks = [
        r'fn\s+parse\s*\(\s*[^)]*&\s*\[\s*u8\s*\]',  # DRcov parse
        r'fn\s+serialize\s*\(\s*&\s*self\s*\)\s*->\s*Vec\s*<\s*u8\s*>',  # DRcov serialize
        r'fn\s+jaccard\b',
        r'fn\s+prune\b',
        r'fn\s+suggest_mutations\b',
        r'fn\s+record_hit\b',
        r'fn\s+hot_edges\b',
    ]
    for pat in fn_checks:
        if re.search(pat, all_src):
            ok(f"fn:{pat[:30]}")
        else:
            mismatch(f"missing fn pattern '{pat}'")

    # CovError variants
    if re.search(r'enum\s+CovError\b[^{]*\{([^}]*)\}', all_src, re.S):
        body = re.search(r'enum\s+CovError\b[^{]*\{([^}]*)\}', all_src, re.S).group(1)
        for variant in ["Parse", "Io", "UnsupportedVersion", "Overflow", "EmptyInput"]:
            if re.search(rf'\b{variant}\b', body):
                ok(f"CovError::{variant}")
            else:
                mismatch(f"CovError missing variant '{variant}'")
    else:
        mismatch("CovError enum body not found")

    return findings


def main() -> int:
    crate_dir = find_crate_dir()
    saved = False
    result: dict = {"crate": CRATE}

    if crate_dir is None:
        result["error"] = "crate directory not found"
        result["saved"] = False
        print(json.dumps(result))
        return 1

    findings = validate(crate_dir)

    out_dir = REPO_ROOT / "validation" / "out"
    try:
        out_dir.mkdir(parents=True, exist_ok=True)
        out_file = out_dir / f"{CRATE}.json"
        out_file.write_text(
            json.dumps(
                {
                    "crate": CRATE,
                    "crate_dir": str(crate_dir),
                    "fixed": findings["fixed"],
                    "mismatches": findings["mismatches"],
                    "details": findings["details"],
                },
                indent=2,
            ),
            encoding="utf-8",
        )
        saved = True
    except OSError as e:
        result["error"] = f"write failed: {e}"

    result["saved"] = saved
    result["fixed"] = findings["fixed"]
    result["mismatches"] = findings["mismatches"]
    print(json.dumps(result))
    return 0


if __name__ == "__main__":
    sys.exit(main())
