#!/usr/bin/env python3
"""Independent validator for rustre-il crate.

Parses the crate sources with stdlib regex only and compares the public surface
to the spec recorded in reports/rustre-il.md. Emits a JSON summary with the
mismatch count so the orchestrator can score the implementation.
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

CRATE = "rustre-il"
ROOT = Path(__file__).resolve().parents[2]
CRATE_DIR = ROOT / "crates" / CRATE
CARGO_TOML = CRATE_DIR / "Cargo.toml"
LIB_RS = CRATE_DIR / "src" / "lib.rs"

EXPECTED_TIERS = [
    ("Lift", "lift"),
    ("Llil", "llil"),
    ("Mlil", "mlil"),
    ("Hlil", "hlil"),
]
EXPECTED_ERROR_VARIANTS = {"Unsupported", "TierMismatch", "Invalid"}
EXPECTED_DEPS = {"serde", "thiserror"}


def read(p: Path) -> str:
    try:
        return p.read_text(encoding="utf-8")
    except OSError:
        return ""


def check_cargo(text: str, mismatches: list[str]) -> None:
    if not text:
        mismatches.append("Cargo.toml: missing or unreadable")
        return
    if not re.search(r'^\s*name\s*=\s*"rustre-il"\s*$', text, re.M):
        mismatches.append("Cargo.toml: name != rustre-il")
    if not re.search(r'^\s*edition\s*=\s*"2024"', text, re.M):
        mismatches.append("Cargo.toml: edition != 2024")
    if not re.search(r'^\s*version\s*=\s*"0\.1\.0"', text, re.M):
        mismatches.append("Cargo.toml: version != 0.1.0")
    for dep in EXPECTED_DEPS:
        if not re.search(rf'^\s*{re.escape(dep)}\s*=', text, re.M):
            mismatches.append(f"Cargo.toml: missing dependency {dep}")


def check_lib(text: str, mismatches: list[str]) -> None:
    if not text:
        mismatches.append("src/lib.rs: missing or unreadable")
        return

    if "forbid(unsafe_code)" not in text:
        mismatches.append("lib.rs: missing #![forbid(unsafe_code)]")

    # IlTier enum
    tier_match = re.search(
        r"pub\s+enum\s+IlTier\s*\{([^}]*)\}", text, re.S
    )
    if not tier_match:
        mismatches.append("lib.rs: pub enum IlTier not found")
    else:
        body = tier_match.group(1)
        for variant, _ in EXPECTED_TIERS:
            if not re.search(rf"\b{variant}\b", body):
                mismatches.append(f"IlTier: missing variant {variant}")
        # derives
        derives_block = text[max(0, tier_match.start() - 300):tier_match.start()]
        for d in ("Debug", "Clone", "Copy", "PartialEq", "Eq", "Hash",
                  "Serialize", "Deserialize"):
            if d not in derives_block:
                mismatches.append(f"IlTier: missing derive {d}")

    # tag()
    tag_match = re.search(
        r"pub\s+const\s+fn\s+tag\s*\(\s*self\s*\)\s*->\s*&'static\s+str\s*\{([^}]*)\}",
        text, re.S
    )
    if not tag_match:
        mismatches.append("IlTier::tag: signature not found")
    else:
        body = tag_match.group(1)
        for variant, tag in EXPECTED_TIERS:
            if not re.search(rf'{variant}\s*=>\s*"{tag}"', body):
                mismatches.append(f"tag(): {variant} => \"{tag}\" missing")

    # next()
    next_match = re.search(
        r"pub\s+const\s+fn\s+next\s*\(\s*self\s*\)\s*->\s*Option<\s*Self\s*>\s*\{([^}]*)\}",
        text, re.S
    )
    if not next_match:
        mismatches.append("IlTier::next: signature not found")
    else:
        body = next_match.group(1)
        chain = [
            ("Lift", "Llil"),
            ("Llil", "Mlil"),
            ("Mlil", "Hlil"),
        ]
        for src, dst in chain:
            if not re.search(rf"{src}\s*=>\s*Some\s*\(\s*(?:Self::|IlTier::)?{dst}", body):
                mismatches.append(f"next(): {src} -> Some({dst}) missing")
        if not re.search(r"Hlil\s*=>\s*None", body):
            mismatches.append("next(): Hlil -> None missing")

    # IlError
    err_match = re.search(r"pub\s+enum\s+IlError\s*\{([^}]*)\}", text, re.S)
    if not err_match:
        mismatches.append("lib.rs: pub enum IlError not found")
    else:
        body = err_match.group(1)
        for v in EXPECTED_ERROR_VARIANTS:
            if not re.search(rf"\b{v}\b", body):
                mismatches.append(f"IlError: missing variant {v}")
        # error messages
        if 'unsupported operation' not in text:
            mismatches.append("IlError::Unsupported: message missing")
        if 'tier mismatch' not in text:
            mismatches.append("IlError::TierMismatch: message missing")
        if 'invalid IL' not in text:
            mismatches.append("IlError::Invalid: message missing")
        # thiserror derive
        derives_block = text[max(0, err_match.start() - 300):err_match.start()]
        if "Error" not in derives_block or "thiserror" not in text:
            mismatches.append("IlError: missing thiserror Error derive")


def main() -> int:
    mismatches: list[str] = []
    check_cargo(read(CARGO_TOML), mismatches)
    check_lib(read(LIB_RS), mismatches)

    out_dir = ROOT / "validation" / "results"
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / f"{CRATE}.json"
    result = {
        "crate": CRATE,
        "mismatches": len(mismatches),
        "details": mismatches,
    }
    out_path.write_text(json.dumps(result, indent=2), encoding="utf-8")
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
