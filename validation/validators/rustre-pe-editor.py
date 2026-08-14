#!/usr/bin/env python3
"""Independent validator for rustre-pe-editor against its report."""
import json
import os
import re
import sys

CRATE = "rustre-pe-editor"
REPORT = os.path.join(os.path.dirname(__file__), "..", "reports", f"{CRATE}.md")
CRATE_DIR = os.path.join(os.path.dirname(__file__), "..", "..", "crates", CRATE)


def read(path):
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            return f.read()
    except OSError:
        return ""


def walk_rs(root):
    out = {}
    for dp, _, fns in os.walk(root):
        for fn in fns:
            if fn.endswith(".rs"):
                p = os.path.join(dp, fn)
                out[p] = read(p)
    return out


def main():
    saved = False
    if not os.path.isdir(CRATE_DIR):
        print(json.dumps({"crate": CRATE, "saved": saved}))
        return

    cargo = read(os.path.join(CRATE_DIR, "Cargo.toml"))
    src = os.path.join(CRATE_DIR, "src")
    files = walk_rs(src)
    blob = "\n".join(files.values())

    checks = []

    # Cargo.toml
    checks.append(('name = "rustre-pe-editor"' in cargo, "name"))
    checks.append(('edition = "2024"' in cargo, "edition2024"))
    for dep in ["rustre-pe-tools", "thiserror", "serde", "parking_lot"]:
        checks.append((dep in cargo, f"dep:{dep}"))

    # Modules
    mods = ["certificate_editor", "import_editor", "overlay_editor",
            "pe_patcher", "pe_import_editor", "pe_resource_editor",
            "pe_section_editor", "pe_surgeon", "resource_editor", "section_editor",
            "pe_header_editor", "pe_certificate_table", "pe_debug_directory"]
    libfile = read(os.path.join(src, "lib.rs"))
    for m in mods:
        checks.append((re.search(rf"\bmod\s+{m}\b|\bpub\s+mod\s+{m}\b", libfile) is not None, f"mod:{m}"))

    # Types and key fns
    for sym in ["EditError", "Patch", "PatchSet", "SectionEdit", "SectionEditor",
                "ImportEntry", "ImportEditor", "ExportEdit", "ExportEditor",
                "ResourceType", "ResourceEntry", "ResourceEditor",
                "CertificateHeader", "PeSigningScaffold", "HeaderField", "PeEditor", "Rc4"]:
        checks.append((re.search(rf"\b(struct|enum)\s+{sym}\b", blob) is not None, f"type:{sym}"))

    for fn in ["xor_section", "nop_range", "int3_range", "patch_entry_point",
               "zero_checksum", "apply_patch", "apply_patchset"]:
        checks.append((re.search(rf"\bfn\s+{fn}\b", blob) is not None, f"fn:{fn}"))

    total = len(checks)
    passed = sum(1 for ok, _ in checks if ok)
    missing = [n for ok, n in checks if not ok]

    saved = passed >= int(total * 0.7)
    result = {"crate": CRATE, "saved": saved, "passed": passed, "total": total, "missing": missing}
    print(json.dumps(result))


if __name__ == "__main__":
    main()
