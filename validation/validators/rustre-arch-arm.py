#!/usr/bin/env python3
"""Independent validator for rustre-arch-arm based on its report."""
import json
import re
import sys
from pathlib import Path

CRATE = "rustre-arch-arm"
REPORT = Path(__file__).resolve().parent.parent / "reports" / f"{CRATE}.md"


def parse_functions(md_text: str):
    """Extract function signatures listed under '## Funzioni pubbliche'."""
    funcs = []
    in_section = False
    current_module = None
    for line in md_text.splitlines():
        if line.startswith("## "):
            in_section = line.strip().startswith("## Funzioni pubbliche")
            current_module = None
            continue
        if not in_section:
            continue
        if line.startswith("### "):
            current_module = line[4:].strip().strip("`")
            continue
        m = re.match(r"\s*-\s+`([^`]+)`", line)
        if m:
            sig = m.group(1)
            # Pull a name token (identifier, possibly ::-qualified)
            name_match = re.match(r"([A-Za-z_][A-Za-z0-9_:]*)", sig)
            name = name_match.group(1) if name_match else sig
            funcs.append({
                "module": current_module,
                "name": name,
                "signature": sig,
            })
    return funcs


def main():
    if not REPORT.exists():
        print(json.dumps({"crate": CRATE, "saved": False,
                          "error": f"report not found: {REPORT}"}))
        return 1
    text = REPORT.read_text(encoding="utf-8")
    functions = parse_functions(text)

    out_dir = Path(__file__).resolve().parent.parent / "out"
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / f"{CRATE}.json"
    payload = {"crate": CRATE, "saved": True, "functions": functions}
    out_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    print(json.dumps(payload))
    return 0


if __name__ == "__main__":
    sys.exit(main())
