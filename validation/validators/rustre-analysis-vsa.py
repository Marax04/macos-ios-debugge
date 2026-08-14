#!/usr/bin/env python3
"""Independent validator for rustre-analysis-vsa.

Reads the markdown report and emits a JSON summary of the public surface
documented for the crate. Pure stdlib, no Rust import, no MCP calls.
"""
import json
import re
import sys
from pathlib import Path

REPORT = Path(r"C:\Users\Fra\Desktop\RustRE\validation\reports\rustre-analysis-vsa.md")
OUT_DIR = Path(r"C:\Users\Fra\Desktop\RustRE\validation\out")
OUT_FILE = OUT_DIR / "rustre-analysis-vsa.json"

CRATE = "rustre-analysis-vsa"


def parse_modules(text: str):
    """Extract `module` - description entries from the 'Moduli pubblici' section."""
    m = re.search(r"## Moduli pubblici\s*\n(.*?)\n## ", text, re.S)
    if not m:
        return []
    block = m.group(1)
    mods = []
    for line in block.splitlines():
        line = line.strip()
        if not line.startswith("- "):
            continue
        # `name` - description
        mm = re.match(r"- `([^`]+)`\s*-\s*(.*)", line)
        if mm:
            name = mm.group(1)
            desc = mm.group(2)
            # extract backtick'd items in desc as exported symbols
            symbols = re.findall(r"`([^`]+)`", desc)
            mods.append({"name": name, "description": desc, "symbols": symbols})
    return mods


def parse_key_symbols(text: str):
    """Collect every backtick'd token inside the 'Tipi/funzioni pubbliche chiave' section."""
    m = re.search(r"## Tipi/funzioni pubbliche chiave[^\n]*\n(.*?)\n## ", text, re.S)
    if not m:
        return []
    block = m.group(1)
    syms = []
    seen = set()
    for tok in re.findall(r"`([^`]+)`", block):
        if tok not in seen:
            seen.add(tok)
            syms.append(tok)
    return syms


def build_functions(modules, key_symbols):
    """Synthesize a 'functions' list: one entry per module + a synthetic 'lib_root' entry."""
    funcs = []
    for mod in modules:
        funcs.append({
            "module": mod["name"],
            "description": mod["description"],
            "symbol_count": len(mod["symbols"]),
            "symbols": mod["symbols"],
        })
    funcs.append({
        "module": "lib_root",
        "description": "Top-level public surface from lib.rs (types, traits, consumer APIs).",
        "symbol_count": len(key_symbols),
        "symbols": key_symbols,
    })
    return funcs


def main():
    if not REPORT.exists():
        print(f"ERROR: report not found: {REPORT}", file=sys.stderr)
        result = {"crate": CRATE, "saved": False, "functions": []}
        print(json.dumps(result, indent=2))
        return 1

    text = REPORT.read_text(encoding="utf-8")
    modules = parse_modules(text)
    key_symbols = parse_key_symbols(text)
    functions = build_functions(modules, key_symbols)

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    saved = False
    try:
        OUT_FILE.write_text(
            json.dumps({"crate": CRATE, "functions": functions}, indent=2),
            encoding="utf-8",
        )
        saved = True
    except OSError as e:
        print(f"WARN: could not save {OUT_FILE}: {e}", file=sys.stderr)

    result = {"crate": CRATE, "saved": saved, "functions": functions}
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
