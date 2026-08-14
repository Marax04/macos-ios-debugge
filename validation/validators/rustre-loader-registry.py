#!/usr/bin/env python3
"""Validator for rustre-loader-registry crate (stdlib only)."""
import json
import os
import re
import sys

CRATE = "rustre-loader-registry"
ROOT = os.path.join("C:\\Users\\Fra\\Desktop\\RustRE", "crates", CRATE)

EXPECTED_ADAPTERS = [
    ("AndroidLoaderAdapter", "android"),
    ("ConsoleLoaderAdapter", "console"),
    ("DotnetLoaderAdapter", "dotnet"),
    ("ElfLoaderAdapter", "elf-full"),
    ("FirmwareLoaderAdapter", "firmware"),
    ("JavaLoaderAdapter", "java-full"),
    ("LuaLoaderAdapter", "lua-full"),
    ("LuaJitLoaderAdapter", "luajit"),
    ("MachoLoaderAdapter", "macho-full"),
    ("OleLoaderAdapter", "ole"),
    ("PdfLoaderAdapter", "pdf"),
    ("PeLoaderAdapter", "pe-full"),
    ("WasmLoaderAdapter", "wasm-full"),
]

EXPECTED_SUBCRATES = [
    "rustre-loader-android", "rustre-loader-console", "rustre-loader-dotnet",
    "rustre-loader-elf", "rustre-loader-firmware", "rustre-loader-java",
    "rustre-loader-lua", "rustre-loader-luajit", "rustre-loader-macho",
    "rustre-loader-ole", "rustre-loader-pdf", "rustre-loader-pe",
    "rustre-loader-wasm",
]

EXPECTED_FNS = ["register_all_subcrate_loaders", "default_full_registry"]


def read(p):
    try:
        with open(p, "r", encoding="utf-8", errors="replace") as f:
            return f.read()
    except OSError:
        return None


def main():
    mismatches = []

    cargo = read(os.path.join(ROOT, "Cargo.toml"))
    if cargo is None:
        mismatches.append("Cargo.toml missing")
    else:
        if 'name = "rustre-loader-registry"' not in cargo:
            mismatches.append("Cargo name")
        if 'edition = "2024"' not in cargo:
            mismatches.append("edition not 2024")
        if "rustre-loader" not in cargo:
            mismatches.append("dep rustre-loader missing")
        if "anyhow" not in cargo:
            mismatches.append("dep anyhow missing")
        for sc in EXPECTED_SUBCRATES:
            if sc not in cargo:
                mismatches.append(f"dep {sc} missing")

    # source: try lib.rs
    src = None
    for cand in ["src/lib.rs", "src/main.rs"]:
        s = read(os.path.join(ROOT, cand))
        if s:
            src = s
            break
    if src is None:
        mismatches.append("source file missing")
        src = ""

    for adapter, tag in EXPECTED_ADAPTERS:
        if adapter not in src:
            mismatches.append(f"adapter {adapter} missing")
        if f'"{tag}"' not in src:
            mismatches.append(f"tag {tag} missing")

    for fn in EXPECTED_FNS:
        if f"fn {fn}" not in src:
            mismatches.append(f"fn {fn} missing")

    if "MultiFormatLoader" not in src:
        mismatches.append("MultiFormatLoader trait not referenced")
    if "MultiFormatRegistry" not in src:
        mismatches.append("MultiFormatRegistry not referenced")
    if "RichLoadResult" not in src:
        mismatches.append("RichLoadResult not referenced")

    # probe functions
    probes = ["probe_android", "probe_console", "probe_dotnet", "probe_elf",
              "probe_firmware", "probe_java", "probe_lua", "probe_luajit",
              "probe_macho", "probe_ole", "probe_pdf", "probe_pe", "probe_wasm"]
    for p in probes:
        if p not in src:
            mismatches.append(f"{p} missing")

    out_dir = os.path.join("C:\\Users\\Fra\\Desktop\\RustRE", "validation", "results")
    os.makedirs(out_dir, exist_ok=True)
    out_path = os.path.join(out_dir, f"{CRATE}.json")
    result = {"crate": CRATE, "mismatches": mismatches, "ok": len(mismatches) == 0}
    saved = False
    try:
        with open(out_path, "w", encoding="utf-8") as f:
            json.dump(result, f, indent=2)
        saved = True
    except OSError as e:
        print(f"save failed: {e}", file=sys.stderr)

    print(json.dumps({"crate": CRATE, "saved": saved, "mismatches": len(mismatches)}))


if __name__ == "__main__":
    main()
