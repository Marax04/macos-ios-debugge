#!/usr/bin/env python3
"""Validator for rustre-mobile-dyld crate against report claims."""
import json
import os
import re
import sys
from pathlib import Path

CRATE = "rustre-mobile-dyld"
ROOT = Path(__file__).resolve().parents[2]
CRATE_DIR = ROOT / "crates" / CRATE


def find_crate_dir():
    if CRATE_DIR.is_dir():
        return CRATE_DIR
    for base in (ROOT / "crates", ROOT):
        if base.is_dir():
            for p in base.rglob("Cargo.toml"):
                try:
                    txt = p.read_text(encoding="utf-8", errors="ignore")
                except Exception:
                    continue
                if re.search(r'^\s*name\s*=\s*"%s"' % re.escape(CRATE), txt, re.M):
                    return p.parent
    return None


def read(p):
    try:
        return p.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return ""


def main():
    cdir = find_crate_dir()
    results = {"crate": CRATE, "checks": [], "missing": [], "found": []}

    if cdir is None:
        results["error"] = "crate directory not found"
        out = ROOT / "validation" / "results" / f"{CRATE}.json"
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(results, indent=2), encoding="utf-8")
        print(json.dumps({"crate": CRATE, "saved": True}))
        return

    cargo = read(cdir / "Cargo.toml")
    # Cargo.toml claims
    for dep in ["anyhow", "thiserror", "serde", "serde_json", "goblin", "bitflags"]:
        ok = re.search(r'(?m)^\s*%s\s*=' % re.escape(dep), cargo) is not None
        results["checks"].append({"k": f"dep:{dep}", "ok": ok})

    ok_ed = 'edition = "2024"' in cargo
    results["checks"].append({"k": "edition_2024", "ok": ok_ed})

    # Gather all source content
    src_dir = cdir / "src"
    all_src = ""
    files = list(src_dir.rglob("*.rs")) if src_dir.is_dir() else []
    for f in files:
        all_src += "\n" + read(f)

    # Module presence (file or mod declaration)
    modules = [
        "cache_header", "dyld_cache_analysis", "dyld_cache_parser", "dyld_exports_trie",
        "dyld_fixups", "images", "mappings", "objc_selector_db", "shared_cache_extractor",
        "slide_info", "subcaches", "dyld_cache_image_extractor", "dyld_fixup_chains",
        "dyld_shared_cache_analyzer", "dyld_bind_info_parser", "dyld_rebase_info_parser",
        "dyld_symbol_table", "objc_optimizer",
    ]
    file_names = {f.stem for f in files}
    for m in modules:
        ok = m in file_names or re.search(r'\bmod\s+%s\b' % re.escape(m), all_src) is not None
        results["checks"].append({"k": f"mod:{m}", "ok": ok})

    # Types
    types = [
        "DyldError", "DyldHeader", "DyldMapping", "DyldImage", "DyldSymbol",
        "ExtractReport", "SlideFixup", "DyldCache", "DyldCacheHeader",
    ]
    for t in types:
        ok = re.search(r'\b(struct|enum)\s+%s\b' % re.escape(t), all_src) is not None
        results["checks"].append({"k": f"type:{t}", "ok": ok})

    # Methods/functions (loose match: fn NAME)
    fns = [
        "parse", "uuid_string", "is_arm64", "platform_name", "is_simulator",
        "is_executable", "is_writable", "is_readable", "end_address", "contains_va",
        "va_to_file_offset", "prot_string", "filename", "is_system_framework",
        "is_swift_overlay", "is_weak", "is_objc", "is_swift", "new", "apply",
        "find_image", "find_images_containing", "find_symbols_for_image", "find_symbol",
        "image_count", "symbol_count", "read_at_va", "extract_image_data",
        "extract_image", "extract_all", "mock", "magic_str",
    ]
    for fn in fns:
        ok = re.search(r'\bfn\s+%s\b' % re.escape(fn), all_src) is not None
        results["checks"].append({"k": f"fn:{fn}", "ok": ok})

    # MIN_SIZE constant
    ok_min = re.search(r'MIN_SIZE\s*:\s*usize\s*=\s*72', all_src) is not None
    results["checks"].append({"k": "const:MIN_SIZE=72", "ok": ok_min})

    # Tests
    test_count = len(re.findall(r'#\[test\]', all_src))
    results["checks"].append({"k": "tests>=25", "ok": test_count >= 25, "count": test_count})

    # Summary
    mismatches = [c for c in results["checks"] if not c["ok"]]
    results["mismatches"] = len(mismatches)
    results["total"] = len(results["checks"])

    out = ROOT / "validation" / "results" / f"{CRATE}.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(results, indent=2), encoding="utf-8")
    print(json.dumps({"crate": CRATE, "saved": True}))


if __name__ == "__main__":
    main()
