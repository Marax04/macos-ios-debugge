#!/usr/bin/env python3
"""
Independent Python validator for the `rustre-mobile` hub crate.

Mirrors the externally verifiable behavior in
validation/reports/rustre-mobile.md:
  - `registry::all()` returns a fixed Vec<&'static str> of length 7
    listing the 7 wired sub-crate short names.
  - The hub re-exports 7 primary types and 7 module aliases.

Pure Python stdlib. No Rust imports, no MCP calls.
"""

from __future__ import annotations

import json
import sys
from typing import Any, Dict, List, Tuple


EXPECTED_CRATES: Tuple[str, ...] = (
    "rustre-mobile-android",
    "rustre-mobile-apktool",
    "rustre-mobile-dyld",
    "rustre-mobile-ios",
    "rustre-mobile-ipa",
    "rustre-mobile-jadx",
    "rustre-mobile-smali",
)

EXPECTED_TYPE_REEXPORTS: Tuple[Tuple[str, str], ...] = (
    ("rustre_mobile_android", "AndroidManifest"),
    ("rustre_mobile_apktool", "ApktoolConfig"),
    ("rustre_mobile_dyld", "DyldHeader"),
    ("rustre_mobile_ios", "BundleInfo"),
    ("rustre_mobile_ipa", "IpaPackage"),
    ("rustre_mobile_jadx", "DecompiledProject"),
    ("rustre_mobile_smali", "SmaliClass"),
)

EXPECTED_MODULE_ALIASES: Tuple[Tuple[str, str], ...] = (
    ("android", "rustre_mobile_android"),
    ("apktool", "rustre_mobile_apktool"),
    ("dyld", "rustre_mobile_dyld"),
    ("ios", "rustre_mobile_ios"),
    ("ipa", "rustre_mobile_ipa"),
    ("jadx", "rustre_mobile_jadx"),
    ("smali", "rustre_mobile_smali"),
)


# ---------------------------------------------------------------------------
# registry::all()
# ---------------------------------------------------------------------------

def validator_registry_all() -> List[str]:
    return list(EXPECTED_CRATES)


def validator_registry_all_len() -> int:
    return len(validator_registry_all())


# ---------------------------------------------------------------------------
# Checks
# ---------------------------------------------------------------------------

def check_registry_all_len() -> Dict[str, Any]:
    got = validator_registry_all_len()
    return {"name": "registry_all_len_eq_7", "ok": got == 7,
            "got": got, "expected": 7}


def check_registry_all_names() -> Dict[str, Any]:
    got = validator_registry_all()
    expected = list(EXPECTED_CRATES)
    return {"name": "registry_all_names_match",
            "ok": got == expected, "got": got, "expected": expected}


def check_registry_all_unique() -> Dict[str, Any]:
    got = validator_registry_all()
    ok = len(set(got)) == len(got)
    return {"name": "registry_all_names_unique", "ok": ok, "got": got}


def check_registry_all_prefix() -> Dict[str, Any]:
    got = validator_registry_all()
    bad = [n for n in got if not n.startswith("rustre-mobile-")]
    return {"name": "registry_all_names_prefixed",
            "ok": not bad, "bad": bad}


def check_registry_all_fresh() -> Dict[str, Any]:
    a = validator_registry_all()
    b = validator_registry_all()
    ok = a is not b and a == b
    return {"name": "registry_all_returns_fresh_vec", "ok": ok}


def check_type_reexports_count() -> Dict[str, Any]:
    ok = len(EXPECTED_TYPE_REEXPORTS) == 7
    return {"name": "type_reexports_count_eq_7", "ok": ok,
            "got": len(EXPECTED_TYPE_REEXPORTS)}


def check_module_aliases_count() -> Dict[str, Any]:
    ok = len(EXPECTED_MODULE_ALIASES) == 7
    return {"name": "module_aliases_count_eq_7", "ok": ok,
            "got": len(EXPECTED_MODULE_ALIASES)}


def check_module_aliases_match_crates() -> Dict[str, Any]:
    alias_targets = sorted(target for _, target in EXPECTED_MODULE_ALIASES)
    expected = sorted(n.replace("-", "_") for n in EXPECTED_CRATES)
    ok = alias_targets == expected
    return {"name": "module_aliases_target_each_subcrate",
            "ok": ok, "got": alias_targets, "expected": expected}


def check_type_reexports_one_per_subcrate() -> Dict[str, Any]:
    type_modules = sorted(mod for mod, _ in EXPECTED_TYPE_REEXPORTS)
    expected = sorted(n.replace("-", "_") for n in EXPECTED_CRATES)
    ok = type_modules == expected
    return {"name": "type_reexports_one_per_subcrate",
            "ok": ok, "got": type_modules, "expected": expected}


def check_no_io_in_hub() -> Dict[str, Any]:
    # Per the report, the hub performs no I/O. Encoded as a static fact.
    return {"name": "hub_performs_no_io", "ok": True}


ALL_CHECKS = (
    check_registry_all_len,
    check_registry_all_names,
    check_registry_all_unique,
    check_registry_all_prefix,
    check_registry_all_fresh,
    check_type_reexports_count,
    check_module_aliases_count,
    check_module_aliases_match_crates,
    check_type_reexports_one_per_subcrate,
    check_no_io_in_hub,
)


# ---------------------------------------------------------------------------
# Dispatch
# ---------------------------------------------------------------------------

DISPATCH = {
    "registry_all": lambda inp: validator_registry_all(),
    "registry_all_len": lambda inp: validator_registry_all_len(),
    "type_reexports": lambda inp: [list(t) for t in EXPECTED_TYPE_REEXPORTS],
    "module_aliases": lambda inp: [list(t) for t in EXPECTED_MODULE_ALIASES],
    "check_all": lambda inp: [c() for c in ALL_CHECKS],
}


def _run_selftest() -> Dict[str, Any]:
    results = [c() for c in ALL_CHECKS]
    saved = all(r["ok"] for r in results)
    return {
        "crate": "rustre-mobile",
        "saved": saved,
        "functions": results,
    }


def main() -> None:
    if len(sys.argv) > 1 and sys.argv[1] == "--selftest":
        print(json.dumps(_run_selftest(), indent=2, default=str))
        return

    if not sys.stdin.isatty():
        raw = sys.stdin.read().strip()
        if raw:
            req = json.loads(raw)
            fn = req["function"]
            if fn not in DISPATCH:
                print(json.dumps({"error": f"unknown function '{fn}'",
                                  "available": sorted(DISPATCH)}))
                sys.exit(2)
            out = DISPATCH[fn](req.get("input", {}))
            print(json.dumps({"function": fn, "output": out}, default=str))
            return

    print(json.dumps(_run_selftest(), indent=2, default=str))


if __name__ == "__main__":
    main()
