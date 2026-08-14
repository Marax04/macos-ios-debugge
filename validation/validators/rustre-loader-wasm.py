#!/usr/bin/env python3
"""Validator for rustre-loader-wasm crate against report spec."""
import json
import os
import re
import sys
from pathlib import Path

CRATE = "rustre-loader-wasm"
ROOT = Path(r"C:\Users\Fra\Desktop\RustRE")
CRATE_DIR = ROOT / "crates" / CRATE


def read_all_src():
    texts = {}
    if not CRATE_DIR.exists():
        return texts
    for p in CRATE_DIR.rglob("*.rs"):
        try:
            texts[str(p)] = p.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            pass
    return texts


def read_cargo():
    cargo = CRATE_DIR / "Cargo.toml"
    if cargo.exists():
        return cargo.read_text(encoding="utf-8", errors="ignore")
    return ""


def main():
    report = {"crate": CRATE, "saved": False, "checks": [], "errors": []}

    if not CRATE_DIR.exists():
        report["errors"].append(f"crate dir not found: {CRATE_DIR}")
        emit(report)
        return

    cargo = read_cargo()
    srcs = read_all_src()
    blob = "\n".join(srcs.values())

    def check(name, cond, detail=""):
        report["checks"].append({"name": name, "ok": bool(cond), "detail": detail})

    # Cargo checks
    check("cargo.name", re.search(r'name\s*=\s*"rustre-loader-wasm"', cargo))
    check("cargo.edition_2024", re.search(r'edition\s*=\s*"2024"', cargo))
    for dep in ["rustre-core", "tokio", "async-trait", "thiserror", "serde", "anyhow"]:
        check(f"dep.{dep}", dep in cargo)
    check("dev-dep.serde_json", "serde_json" in cargo)

    # Constants
    check("WASM_MAGIC", "WASM_MAGIC" in blob and "0x6D" in blob.upper() or "0x6d" in blob)
    check("WASM_VERSION", re.search(r"WASM_VERSION\s*[:=]", blob))
    check("MAX_SECTION_SIZE", "MAX_SECTION_SIZE" in blob)

    # Errors
    for v in ["InvalidMagic", "UnsupportedVersion", "InvalidSection", "Leb128Error",
              "UnexpectedEof", "InvalidUtf8", "SectionTooLarge"]:
        check(f"WasmError.{v}", v in blob)

    # Leb128Decoder
    check("Leb128Decoder", "Leb128Decoder" in blob)
    for m in ["read_u32", "read_i32", "read_u64", "read_i64", "read_u8",
              "read_bytes", "read_name", "remaining", "is_done"]:
        check(f"leb128.{m}", m in blob)

    # Types
    for t in ["WasmValType", "WasmFuncType", "WasmLimits", "WasmTableType",
              "WasmGlobalType", "WasmImportDesc", "WasmImport", "WasmExportDesc",
              "WasmExport", "WasmLocal", "WasmFunction", "WasmGlobal",
              "WasmDataSegment", "WasmCustomSection", "WasmNameSection",
              "WasmModule", "WasmParser", "WasmStats", "WasmLoader",
              "WasmOpcode", "WasmArch"]:
        check(f"type.{t}", t in blob)

    # WasmValType variants
    for v in ["I32", "I64", "F32", "F64", "V128", "FuncRef", "ExternRef"]:
        check(f"valtype.{v}", v in blob)

    # WasmModule methods
    for m in ["function_type", "exported_function", "exported_function_names",
              "function_name", "imports_from", "memory_pages_min",
              "has_start_function"]:
        check(f"module.{m}", m in blob)

    # WasmParser
    check("WasmParser::parse", re.search(r"impl\s+WasmParser", blob) and "parse" in blob)

    # WasmLoader / Loader trait
    check("impl Loader", re.search(r"impl\s+.*Loader\s+for\s+WasmLoader", blob))
    for m in ["can_load", "find_nested"]:
        check(f"loader.{m}", m in blob)

    # WasmStats fields
    for f in ["function_count", "import_count", "export_count", "data_size",
              "code_size", "global_count", "memory_count", "table_count",
              "custom_section_count", "has_name_section", "has_dwarf",
              "most_complex_function"]:
        check(f"stats.{f}", f in blob)

    # Modules
    for mod in ["wasm_analyzer", "wasm_binary_parser", "wasm_component_model",
                "wasm_disassembler", "wasm_module_loader", "wasm_name_section",
                "wasm_optimization_hints", "wasm_security", "wasm_disasm",
                "wasm_validator", "wasm_section_parser", "wasm_type_decoder",
                "wasm_import_export"]:
        check(f"mod.{mod}", f"mod {mod}" in blob or (CRATE_DIR / "src" / f"{mod}.rs").exists())

    emit(report)


def emit(report):
    mism = sum(1 for c in report["checks"] if not c["ok"])
    report["mismatches"] = mism
    out_dir = ROOT / "validation" / "out"
    out_dir.mkdir(parents=True, exist_ok=True)
    out_file = out_dir / f"{CRATE}.json"
    try:
        out_file.write_text(json.dumps(report, indent=2), encoding="utf-8")
        report["saved"] = True
    except Exception as e:
        report["errors"].append(f"save failed: {e}")
    print(json.dumps({"crate": CRATE, "saved": report["saved"],
                      "mismatches": mism}))


if __name__ == "__main__":
    main()
