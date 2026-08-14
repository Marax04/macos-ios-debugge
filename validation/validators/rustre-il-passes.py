#!/usr/bin/env python3
"""Independent validator for rustre-il-passes crate."""
import json
import os
import re
import sys
from pathlib import Path

CRATE = "rustre-il-passes"
ROOT = Path(r"C:\Users\Fra\Desktop\RustRE")
CRATE_DIR = ROOT / "crates" / CRATE

EXPECTED_MODULES = {
    "constant_propagation",
    "interprocedural_passes",
    "loop_analysis",
    "memory_access_patterns",
    "optimization_pipeline",
    "pass_dependency_graph",
    "pass_metrics",
    "switch_detection",
    "type_recovery_pass",
}

EXPECTED_DEPS = {"rustre-il", "rustre-core", "rustre-il-llil", "serde"}

EXPECTED_TR_CONSTS = {
    "SYSV_ARGS",
    "MS_X64_ARGS",
    "CALLEE_SAVED_SYSV",
    "CALLER_SAVED_SYSV",
    "DEFAULT_CONFIDENCE",
    "MAX_CONSTRAINTS_PER_VAR",
    "MIN_POINTER_EVIDENCE",
    "MIN_FLOAT_EVIDENCE",
}

EXPECTED_TR_ITEMS = {
    "TypeConstraintBuilder",
    "TypeConstraintCollector",
    "TypeSolver",
    "AnnotationMerger",
    "TypeExporter",
    "PropagatedType",
    "TypeConstraint",
    "TypeStatistics",
}

EXPECTED_PASS_STATS_FIELDS = {
    "instrs_visited",
    "instrs_modified",
    "instrs_removed",
    "const_folded",
    "exprs_simplified",
    "dead_removed",
}


def read(p):
    try:
        return p.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return ""


def validate():
    findings = []

    # Cargo.toml checks
    cargo = read(CRATE_DIR / "Cargo.toml")
    if not cargo:
        findings.append("Cargo.toml missing")
    else:
        if 'name = "rustre-il-passes"' not in cargo:
            findings.append("package name mismatch")
        if 'version = "0.1.0"' not in cargo:
            findings.append("version not 0.1.0")
        if 'edition = "2024"' not in cargo:
            findings.append("edition not 2024")
        for dep in EXPECTED_DEPS:
            if dep not in cargo:
                findings.append(f"missing dep: {dep}")

    # Modules
    src = CRATE_DIR / "src"
    existing_files = {p.stem for p in src.glob("*.rs")} if src.exists() else set()
    missing_mods = EXPECTED_MODULES - existing_files
    for m in missing_mods:
        findings.append(f"missing module file: {m}.rs")

    # lib.rs checks
    lib = read(src / "lib.rs")
    if not lib:
        findings.append("lib.rs missing")
    else:
        # PassStats fields
        m = re.search(r"struct\s+PassStats\s*\{([^}]*)\}", lib, re.DOTALL)
        if not m:
            findings.append("PassStats struct not found")
        else:
            body = m.group(1)
            for f in EXPECTED_PASS_STATS_FIELDS:
                if f not in body:
                    findings.append(f"PassStats missing field: {f}")
        if "struct PassContext" not in lib:
            findings.append("PassContext struct not found")
        else:
            ctx = re.search(r"struct\s+PassContext\s*\{([^}]*)\}", lib, re.DOTALL)
            if ctx:
                cb = ctx.group(1)
                for f in ("changed", "stats", "warnings"):
                    if f not in cb:
                        findings.append(f"PassContext missing field: {f}")
        # re-exports
        for sym in ("LlilFunction", "LlilCfg", "LlilExpr", "LlilInstruction",
                    "LlilRegister", "Size", "Address"):
            if sym not in lib:
                findings.append(f"missing re-export: {sym}")

    # type_recovery_pass.rs
    tr = read(src / "type_recovery_pass.rs")
    if not tr:
        findings.append("type_recovery_pass.rs missing")
    else:
        for c in EXPECTED_TR_CONSTS:
            if c not in tr:
                findings.append(f"type_recovery missing const/sym: {c}")
        for it in EXPECTED_TR_ITEMS:
            if it not in tr:
                findings.append(f"type_recovery missing item: {it}")
        # confidence threshold value
        if not re.search(r"DEFAULT_CONFIDENCE[^;]*0\.75", tr):
            findings.append("DEFAULT_CONFIDENCE != 0.75")
        if not re.search(r"MAX_CONSTRAINTS_PER_VAR[^;]*1024", tr):
            findings.append("MAX_CONSTRAINTS_PER_VAR != 1024")

    # Count pub fn at lib root (non-recursive scan of lib.rs only, excluding test modules best-effort)
    if lib:
        # strip #[cfg(test)] modules naively
        stripped = re.sub(r"#\[cfg\(test\)\]\s*mod\s+\w+\s*\{(?:[^{}]|\{[^{}]*\})*\}",
                          "", lib, flags=re.DOTALL)
        pub_fns = len(re.findall(r"\bpub\s+fn\s+", stripped))
        # Report expects ~32 pub fn at lib root
        if pub_fns < 16:
            findings.append(f"lib.rs pub fn count low: {pub_fns}")

    # Total pub fn across crate
    total_pub_fn = 0
    if src.exists():
        for rs in src.glob("*.rs"):
            txt = read(rs)
            total_pub_fn += len(re.findall(r"\bpub\s+fn\s+", txt))
    if total_pub_fn < 100:
        findings.append(f"total pub fn count low: {total_pub_fn}")

    # Test attributes
    if src.exists():
        has_tests = False
        for rs in src.glob("*.rs"):
            if "#[cfg(test)]" in read(rs) or "#[test]" in read(rs):
                has_tests = True
                break
        if not has_tests:
            findings.append("no #[cfg(test)] or #[test] found in any source file")

    return findings


def main():
    findings = validate()
    out_dir = ROOT / "validation" / "output"
    out_dir.mkdir(parents=True, exist_ok=True)
    result = {
        "crate": CRATE,
        "saved": True,
        "mismatches": len(findings),
        "findings": findings,
    }
    out_file = out_dir / f"{CRATE}.json"
    try:
        out_file.write_text(json.dumps(result, indent=2), encoding="utf-8")
    except Exception as e:
        result["saved"] = False
        result["error"] = str(e)
    print(json.dumps({"crate": CRATE, "saved": result["saved"],
                      "mismatches": result["mismatches"]}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
