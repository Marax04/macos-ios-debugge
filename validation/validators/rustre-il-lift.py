#!/usr/bin/env python3
"""Standalone validator for rustre-il-lift crate.

Reimplements pure/structural reference logic in Python stdlib so that the
Rust crate output can be compared against an independent oracle.

Covers:
  - hit_rate / success_rate arithmetic
  - LiftCache map invariants
  - AddressMap insert/get/contains/range
  - diff_address_maps set arithmetic
  - LifterRegistry::with_defaults().arch_names() expected membership
  - IrExpr::node_count recursive count
  - LiftFilter::terminators filter
  - Structural shape table for x86 lifted opcode sequences (golden)
"""
from __future__ import annotations

import json
import sys
from typing import Any, Dict, List, Optional, Tuple


# ---------------------------------------------------------------------------
# Rate helpers
# ---------------------------------------------------------------------------
def validator_hit_rate(inp: Dict[str, int]) -> float:
    hits = int(inp.get("hits", 0))
    misses = int(inp.get("misses", 0))
    total = hits + misses
    return (hits / total) if total > 0 else 0.0


def validator_success_rate(inp: Dict[str, int]) -> float:
    successful = int(inp.get("successful", 0))
    total = int(inp.get("total", 0))
    return (successful / total) if total > 0 else 0.0


# ---------------------------------------------------------------------------
# LiftCache reference (bounded dict keyed by VA)
# ---------------------------------------------------------------------------
def validator_lift_cache(inp: Dict[str, Any]) -> Dict[str, Any]:
    """Replay an op log against a bounded cache.

    Input:
      { "max_entries": int, "ops": [ {"op":"insert","addr":N,"instr":...},
                                     {"op":"get","addr":N},
                                     {"op":"clear"} ] }
    Output: { "len", "hits", "misses", "hit_rate", "contents": {addr: instr} }
    """
    max_entries = int(inp.get("max_entries", 1024))
    store: Dict[int, Any] = {}
    hits = 0
    misses = 0
    for op in inp.get("ops", []):
        kind = op["op"]
        if kind == "insert":
            addr = int(op["addr"])
            if addr not in store and len(store) >= max_entries:
                # bounded: drop arbitrary (first inserted) entry
                first = next(iter(store))
                store.pop(first)
            store[addr] = op.get("instr")
        elif kind == "get":
            addr = int(op["addr"])
            if addr in store:
                hits += 1
            else:
                misses += 1
        elif kind == "clear":
            store.clear()
    total = hits + misses
    return {
        "len": len(store),
        "hits": hits,
        "misses": misses,
        "hit_rate": (hits / total) if total > 0 else 0.0,
        "contents": {str(k): v for k, v in store.items()},
    }


# ---------------------------------------------------------------------------
# AddressMap reference
# ---------------------------------------------------------------------------
def validator_address_map(inp: Dict[str, Any]) -> Dict[str, Any]:
    """Input: { "inserts": [[addr, instr], ...], "queries": {...} }
    Returns sorted addresses, range result, contains result."""
    entries: Dict[int, Any] = {}
    for addr, instr in inp.get("inserts", []):
        entries[int(addr)] = instr
    addresses = sorted(entries.keys())
    out: Dict[str, Any] = {"addresses": addresses, "len": len(addresses)}

    q = inp.get("queries", {})
    if "contains" in q:
        out["contains"] = [int(a) in entries for a in q["contains"]]
    if "get" in q:
        out["get"] = [entries.get(int(a)) for a in q["get"]]
    if "range" in q:
        start = int(q["range"][0])
        end = int(q["range"][1])
        out["range"] = [a for a in addresses if start <= a < end]
    return out


# ---------------------------------------------------------------------------
# diff_address_maps reference
# ---------------------------------------------------------------------------
def validator_diff_address_maps(inp: Dict[str, Any]) -> Dict[str, List[int]]:
    left = {int(k): v for k, v in inp.get("left", {}).items()}
    right = {int(k): v for k, v in inp.get("right", {}).items()}
    lk = set(left.keys())
    rk = set(right.keys())
    added = sorted(rk - lk)
    removed = sorted(lk - rk)
    changed = sorted(a for a in (lk & rk) if left[a] != right[a])
    return {"added": added, "removed": removed, "changed": changed}


# ---------------------------------------------------------------------------
# LifterRegistry::with_defaults().arch_names() expected set
# ---------------------------------------------------------------------------
EXPECTED_ARCHES = [
    "x86", "x86_64", "arm", "aarch64", "mips", "mips64",
    "riscv", "ppc", "sparc", "m68k", "avr", "z80",
    "bpf", "wasm", "cil", "dex",
]


def validator_arch_names(inp: Dict[str, Any]) -> Dict[str, Any]:
    actual = set(inp.get("actual", []))
    expected = set(EXPECTED_ARCHES)
    return {
        "missing": sorted(expected - actual),
        "extra": sorted(actual - expected),
        "ok": expected.issubset(actual),
    }


# ---------------------------------------------------------------------------
# IrExpr::node_count reference (recursive on JSON-shaped tree)
# ---------------------------------------------------------------------------
def validator_node_count(expr: Any) -> int:
    """Each node counts as 1; recurse into list/dict child fields."""
    if expr is None:
        return 0
    if isinstance(expr, dict):
        n = 1
        for v in expr.values():
            if isinstance(v, (dict, list)):
                n += validator_node_count(v)
        return n
    if isinstance(expr, list):
        return sum(validator_node_count(c) for c in expr)
    return 0


def validator_registers_used(expr: Any) -> List[str]:
    regs: List[str] = []

    def walk(e: Any) -> None:
        if isinstance(e, dict):
            if e.get("kind") == "Reg" and "name" in e:
                regs.append(e["name"])
            for v in e.values():
                walk(v)
        elif isinstance(e, list):
            for c in e:
                walk(c)

    walk(expr)
    # dedup preserving order
    seen = set()
    out = []
    for r in regs:
        if r not in seen:
            seen.add(r)
            out.append(r)
    return out


# ---------------------------------------------------------------------------
# LiftFilter helpers
# ---------------------------------------------------------------------------
TERMINATOR_KINDS = {"ret", "jmp", "jcc", "call", "syscall", "branch"}


def validator_filter_terminators(instrs: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    return [i for i in instrs if (i.get("kind") in TERMINATOR_KINDS) or i.get("is_terminator")]


def validator_filter_with_side_effects(instrs: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    return [i for i in instrs if i.get("has_side_effects") or i.get("written_registers") or i.get("mem_write")]


def validator_filter_writing_register(instrs: List[Dict[str, Any]], reg: str) -> List[Dict[str, Any]]:
    return [i for i in instrs if reg in (i.get("written_registers") or [])]


# ---------------------------------------------------------------------------
# x86 lift shape golden table (structural ground truth)
# ---------------------------------------------------------------------------
# Maps mnemonic -> expected structural invariants on the LlilOp sequence.
X86_SHAPE = {
    "nop":      {"min_ops": 0, "max_ops": 1, "must_have": [],                  "must_not_have": ["mem_load", "mem_store", "branch"]},
    "mov":      {"min_ops": 1, "max_ops": 4, "must_have": ["reg_write"],       "must_not_have": ["branch"]},
    "xor_self": {"min_ops": 1, "max_ops": 6, "must_have": ["reg_write"],       "must_not_have": ["mem_load", "mem_store", "branch"], "fold_to_const_zero": True},
    "push":     {"min_ops": 2, "max_ops": 4, "must_have": ["reg_write", "mem_store"], "must_not_have": []},
    "pop":      {"min_ops": 2, "max_ops": 4, "must_have": ["reg_write", "mem_load"],  "must_not_have": []},
    "call":     {"min_ops": 2, "max_ops": 6, "must_have": ["mem_store", "branch"],    "must_not_have": []},
    "ret":      {"min_ops": 1, "max_ops": 4, "must_have": ["branch"],          "must_not_have": []},
    "jmp":      {"min_ops": 1, "max_ops": 2, "must_have": ["branch"],          "must_not_have": ["mem_load", "mem_store"]},
    "lea":      {"min_ops": 1, "max_ops": 3, "must_have": ["reg_write"],       "must_not_have": ["mem_load"]},
    "cmp":      {"min_ops": 1, "max_ops": 6, "must_have": ["flag_write"],      "must_not_have": ["reg_write"]},
    "test":     {"min_ops": 1, "max_ops": 6, "must_have": ["flag_write"],      "must_not_have": ["reg_write"]},
}


def _classify_op(op: Any) -> str:
    if isinstance(op, str):
        s = op.lower()
    elif isinstance(op, dict):
        s = (op.get("kind") or op.get("op") or "").lower()
    else:
        return "unknown"
    if "branch" in s or s in ("jmp", "jcc", "ret", "call"):
        return "branch"
    if "store" in s or s == "mem_store":
        return "mem_store"
    if "load" in s or s == "mem_load":
        return "mem_load"
    if "flag" in s:
        return "flag_write"
    if "reg" in s or "assign" in s or "mov" in s:
        return "reg_write"
    return s


def validator_x86_shape(inp: Dict[str, Any]) -> Dict[str, Any]:
    """Input: { "mnemonic": "...", "ops": [...] }
    Returns pass/fail + which invariants failed."""
    mnem = inp.get("mnemonic", "")
    ops = inp.get("ops", [])
    rules = X86_SHAPE.get(mnem)
    if rules is None:
        return {"ok": False, "reason": f"unknown mnemonic: {mnem}"}

    classes = [_classify_op(o) for o in ops]
    issues = []

    if len(ops) < rules["min_ops"]:
        issues.append(f"too few ops: {len(ops)} < {rules['min_ops']}")
    if len(ops) > rules["max_ops"]:
        issues.append(f"too many ops: {len(ops)} > {rules['max_ops']}")
    for needed in rules["must_have"]:
        if needed not in classes:
            issues.append(f"missing class: {needed}")
    for forbidden in rules["must_not_have"]:
        if forbidden in classes:
            issues.append(f"forbidden class present: {forbidden}")

    return {"ok": len(issues) == 0, "issues": issues, "classes": classes}


# ---------------------------------------------------------------------------
# LiftVerifier reference: deep equality of two LiftedInstr dicts
# ---------------------------------------------------------------------------
def validator_verify(inp: Dict[str, Any]) -> Dict[str, Any]:
    a = inp.get("a")
    b = inp.get("b")
    return {"equivalent": a == b}


def validator_verify_batch(inp: Dict[str, Any]) -> Dict[str, Any]:
    pairs = inp.get("pairs", [])
    results = [a == b for a, b in pairs]
    return {
        "all_equivalent": all(results),
        "results": results,
        "mismatch_indices": [i for i, r in enumerate(results) if not r],
    }


# ---------------------------------------------------------------------------
# Dispatch
# ---------------------------------------------------------------------------
DISPATCH = {
    "hit_rate": validator_hit_rate,
    "success_rate": validator_success_rate,
    "lift_cache": validator_lift_cache,
    "address_map": validator_address_map,
    "diff_address_maps": validator_diff_address_maps,
    "arch_names": validator_arch_names,
    "node_count": validator_node_count,
    "registers_used": validator_registers_used,
    "filter_terminators": validator_filter_terminators,
    "filter_with_side_effects": validator_filter_with_side_effects,
    "filter_writing_register": lambda inp: validator_filter_writing_register(inp["instrs"], inp["reg"]),
    "x86_shape": validator_x86_shape,
    "verify": validator_verify,
    "verify_batch": validator_verify_batch,
}


def main() -> int:
    raw = sys.stdin.read().strip()
    if not raw:
        # Self-test with fixed inputs
        out = {
            "hit_rate_0_0": validator_hit_rate({"hits": 0, "misses": 0}),
            "hit_rate_3_1": validator_hit_rate({"hits": 3, "misses": 1}),
            "success_rate_7_10": validator_success_rate({"successful": 7, "total": 10}),
            "arch_names_full": validator_arch_names({"actual": EXPECTED_ARCHES}),
            "arch_names_missing": validator_arch_names({"actual": ["x86", "x86_64"]}),
            "diff_simple": validator_diff_address_maps({
                "left":  {"16": "a", "32": "b"},
                "right": {"32": "b", "48": "c"},
            }),
            "node_count_leaf": validator_node_count({"kind": "Const", "value": 7}),
            "node_count_tree": validator_node_count({
                "kind": "BinOp", "op": "Add",
                "lhs": {"kind": "Reg", "name": "rax"},
                "rhs": {"kind": "Const", "value": 1},
            }),
            "shape_ret": validator_x86_shape({"mnemonic": "ret", "ops": ["branch"]}),
            "shape_lea_bad": validator_x86_shape({"mnemonic": "lea", "ops": ["mem_load", "reg_write"]}),
            "shape_push_ok": validator_x86_shape({"mnemonic": "push", "ops": ["reg_write", "mem_store"]}),
            "verify_eq": validator_verify({"a": {"x": 1}, "b": {"x": 1}}),
            "verify_ne": validator_verify({"a": {"x": 1}, "b": {"x": 2}}),
        }
        print(json.dumps(out, indent=2))
        return 0

    payload = json.loads(raw)
    fn = payload.get("function")
    inp = payload.get("input", {})
    if fn not in DISPATCH:
        print(json.dumps({"error": f"unknown function: {fn}",
                          "available": sorted(DISPATCH.keys())}))
        return 2
    result = DISPATCH[fn](inp)
    print(json.dumps({"function": fn, "output": result}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
