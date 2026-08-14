#!/usr/bin/env python3
"""Independent validator for rustre-decompiler-ghidra crate."""
import json
import os
import re
import sys
from pathlib import Path

CRATE = "rustre-decompiler-ghidra"
ROOT = Path(r"C:\Users\Fra\Desktop\RustRE\crates") / CRATE
SRC = ROOT / "src"

EXPECTED_MODULES = [
    "lib.rs", "ast_printer.rs", "ghidra_ast.rs", "ghidra_bridge.rs",
    "ghidra_client.rs", "ghidra_headless.rs", "ghidra_pcode.rs",
    "ghidra_type_recovery.rs", "ghidra_types.rs", "ghidra_types_db.rs",
    "pcode_analysis.rs", "pcode_importer.rs", "pcode_interpreter.rs",
    "pcode_lifter.rs", "decompiler_ir_bridge.rs", "result_merger.rs",
]

EXPECTED_SYMBOLS = [
    "enum GhidraDecompError",
    "enum PCodeOp",
    "enum PCodeVarnode",
    "struct PCodeInstr",
    "struct PCodeTranslator",
    "struct PCodeLifter",
    "struct GhidraBackend",
    "struct GhidraServerConfig",
    "struct GhidraServer",
    "struct GhidraProject",
    "struct GhidraScript",
    "struct GhidraDecompileRequest",
    "struct GhidraDecompileResponse",
    "struct GhidraRpcClient",
    "struct GhidraMemoryMap",
    "struct GhidraSegment",
    "struct GhidraSymbolImporter",
    "struct GhidraTypeImporter",
    "struct GhidraXmlParser",
    "struct GhidraDataTypeDb",
    "struct GhidraDataType",
]


def main():
    mismatches = 0
    if not SRC.exists():
        print(json.dumps({"crate": CRATE, "saved": True, "error": "src missing"}))
        return

    # check modules
    for m in EXPECTED_MODULES:
        if not (SRC / m).exists():
            mismatches += 1

    # read all rust source
    all_src = ""
    for p in SRC.rglob("*.rs"):
        try:
            all_src += p.read_text(encoding="utf-8", errors="ignore") + "\n"
        except Exception:
            pass

    # check expected symbols
    for sym in EXPECTED_SYMBOLS:
        # pub <kind> <Name>
        kind, name = sym.split(" ", 1)
        pattern = rf"pub\s+{kind}\s+{name}\b"
        if not re.search(pattern, all_src):
            mismatches += 1

    # check pub fn count ~463 (allow tolerance)
    pub_fn_count = len(re.findall(r"^\s*pub\s+(?:async\s+)?fn\s+", all_src, re.MULTILINE))
    # expected ~463; tolerate +/-50%
    if pub_fn_count < 200:
        mismatches += 1

    # check Cargo.toml deps
    cargo = ROOT / "Cargo.toml"
    if cargo.exists():
        text = cargo.read_text(encoding="utf-8", errors="ignore")
        for dep in ["rustre-core", "rustre-decompiler", "anyhow", "thiserror", "serde", "serde_json", "tokio"]:
            if dep not in text:
                mismatches += 1
    else:
        mismatches += 1

    result = {
        "crate": CRATE,
        "saved": True,
        "fixed": 0,
        "mismatches": mismatches,
        "match_final": mismatches == 0,
    }
    print(json.dumps(result))


if __name__ == "__main__":
    main()
