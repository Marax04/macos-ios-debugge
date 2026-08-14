#!/usr/bin/env python3
"""
Independent Python validator for the `rustre-arch-registry` crate.

Mirrors the externally verifiable behavior described in
validation/reports/rustre-arch-registry.md:
  - `all()` builds a fresh Vec of 19 concrete backends.
  - `register_all()` inserts each into a process-wide registry,
    overwriting prior entries (idempotent).

No imports of the Rust crate, no MCP calls. Pure Python stdlib.
"""

from __future__ import annotations

import json
import sys
from typing import Any, Dict, List, Tuple


# Expected 19 backend architecture names, per the report.
EXPECTED_ARCHES: Tuple[str, ...] = (
    "6502", "68k", "arm", "arm64", "avr", "bpf", "cil", "dex", "jvm",
    "lua", "luajit", "mips", "msp430", "ppc", "riscv", "sparc", "wasm",
    "x86", "z80",
)


class FakeArch:
    """Stand-in for `dyn Architecture` — only `name()` matters for the registry."""

    def __init__(self, name: str) -> None:
        self._name = name

    def name(self) -> str:
        return self._name

    def __repr__(self) -> str:  # pragma: no cover - debug aid
        return f"FakeArch({self._name!r})"


# ---------------------------------------------------------------------------
# `all()` — fresh vector, one entry per backend
# ---------------------------------------------------------------------------

def validator_all() -> List[FakeArch]:
    return [FakeArch(name) for name in EXPECTED_ARCHES]


def validator_all_names() -> List[str]:
    return [a.name() for a in validator_all()]


def validator_all_len() -> int:
    return len(validator_all())


# ---------------------------------------------------------------------------
# `register_all()` — populates a process-wide registry
# ---------------------------------------------------------------------------

# Simulated global_registry — process-wide dict mapping name -> arch.
_REGISTRY: Dict[str, FakeArch] = {}


def _reset_registry() -> None:
    _REGISTRY.clear()


def validator_register_all_builtins_placeholders() -> None:
    """Pre-populate registry with placeholders, like `rustre_arch::register_all_builtins`."""
    for name in EXPECTED_ARCHES:
        _REGISTRY[name] = FakeArch(f"placeholder:{name}")


def validator_register_all() -> None:
    """For each arch in `all()`, insert (overwrite) into `_REGISTRY`."""
    for arch in validator_all():
        _REGISTRY[arch.name()] = arch


def validator_registry_get(name: str) -> str | None:
    a = _REGISTRY.get(name)
    return None if a is None else a.name()


def validator_registry_snapshot() -> Dict[str, str]:
    return {k: v.name() for k, v in _REGISTRY.items()}


# ---------------------------------------------------------------------------
# Composite checks
# ---------------------------------------------------------------------------

def check_all_len() -> Dict[str, Any]:
    got = validator_all_len()
    return {"name": "all_len_eq_19", "ok": got == 19, "got": got, "expected": 19}


def check_all_names_set() -> Dict[str, Any]:
    got = sorted(validator_all_names())
    expected = sorted(EXPECTED_ARCHES)
    return {
        "name": "all_names_match_expected_set",
        "ok": got == expected,
        "got": got,
        "expected": expected,
    }


def check_all_returns_fresh_vector() -> Dict[str, Any]:
    a = validator_all()
    b = validator_all()
    # Same names, but different list objects and different element objects.
    ok = (
        a is not b
        and [x.name() for x in a] == [x.name() for x in b]
        and all(x is not y for x, y in zip(a, b))
    )
    return {"name": "all_returns_fresh_vector", "ok": ok}


def check_register_all_overwrites_placeholders() -> Dict[str, Any]:
    _reset_registry()
    validator_register_all_builtins_placeholders()
    pre = {k: v.name() for k, v in _REGISTRY.items()}
    validator_register_all()
    post = {k: v.name() for k, v in _REGISTRY.items()}
    overwritten = all(
        pre[name].startswith("placeholder:") and post[name] == name
        for name in EXPECTED_ARCHES
    )
    return {
        "name": "register_all_overwrites_placeholders",
        "ok": overwritten,
        "pre_sample": pre.get("x86"),
        "post_sample": post.get("x86"),
    }


def check_register_all_idempotent() -> Dict[str, Any]:
    _reset_registry()
    validator_register_all()
    snap1 = validator_registry_snapshot()
    validator_register_all()
    snap2 = validator_registry_snapshot()
    ok = snap1 == snap2 and len(snap2) == 19
    return {
        "name": "register_all_idempotent",
        "ok": ok,
        "len_after_first": len(snap1),
        "len_after_second": len(snap2),
    }


def check_registry_get_each_name() -> Dict[str, Any]:
    _reset_registry()
    validator_register_all()
    missing = [n for n in EXPECTED_ARCHES if validator_registry_get(n) != n]
    return {
        "name": "registry_get_each_expected_name",
        "ok": not missing,
        "missing": missing,
    }


ALL_CHECKS = (
    check_all_len,
    check_all_names_set,
    check_all_returns_fresh_vector,
    check_register_all_overwrites_placeholders,
    check_register_all_idempotent,
    check_registry_get_each_name,
)


# ---------------------------------------------------------------------------
# Dispatch (for stdin JSON mode, parity with sibling validators)
# ---------------------------------------------------------------------------

DISPATCH = {
    "all_len": lambda inp: validator_all_len(),
    "all_names": lambda inp: validator_all_names(),
    "register_all_and_snapshot": lambda inp: (
        _reset_registry() or validator_register_all() or validator_registry_snapshot()
    ),
    "registry_get": lambda inp: validator_registry_get(inp["name"]),
    "check_all": lambda inp: [c() for c in ALL_CHECKS],
}


def _run_selftest() -> Dict[str, Any]:
    results = [c() for c in ALL_CHECKS]
    saved = all(r["ok"] for r in results)
    return {
        "crate": "rustre-arch-registry",
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
