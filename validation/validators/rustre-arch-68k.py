"""Independent validator for rustre-arch-68k.

Reads the analysis report and extracts the documented public function
signatures. Pure stdlib, no Rust crate import, no MCP calls.
"""
import json
import re
from pathlib import Path

CRATE = "rustre-arch-68k"
REPORT = Path(__file__).resolve().parent.parent / "reports" / f"{CRATE}.md"
OUT = Path(__file__).resolve().parent.parent / "validators_out" / f"{CRATE}.json"


def extract_functions(text: str) -> list[str]:
    # Match `fn name(...)` occurrences inside backticks in the report.
    pattern = re.compile(r"`fn\s+([A-Za-z_][A-Za-z0-9_]*)\s*[(<]")
    seen = []
    for m in pattern.finditer(text):
        name = m.group(1)
        if name not in seen:
            seen.append(name)
    return seen


def main() -> dict:
    text = REPORT.read_text(encoding="utf-8")
    functions = extract_functions(text)
    result = {
        "crate": CRATE,
        "saved": False,
        "functions": functions,
    }
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(result, indent=2), encoding="utf-8")
    result["saved"] = True
    return result


if __name__ == "__main__":
    res = main()
    print(json.dumps(res, indent=2))
