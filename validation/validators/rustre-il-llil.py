#!/usr/bin/env python3
"""
Independent Python validator for the rustre-il-llil crate.

Implements oracles for selected LLIL-level operations using only the Python
stdlib. No imports of the Rust crate; no MCP calls. Each validator_<name>
function mirrors the semantic contract of one piece of the crate so its
output can be diff'd against the Rust implementation in cross-checks.

Usage:
  - JSON over stdin:  {"function": "name", "input": {...}}  ->  {"output": ...}
  - or:               python rustre-il-llil.py --self-test
"""
from __future__ import annotations

import json
import sys
from typing import Any, Dict, List, Tuple


# ---------------------------------------------------------------------------
# Size helpers (LLIL Size is byte-width: 1,2,4,8,16)
# ---------------------------------------------------------------------------

def _mask(size_bytes: int) -> int:
    return (1 << (size_bytes * 8)) - 1


def _sign_bit(size_bytes: int) -> int:
    return 1 << (size_bytes * 8 - 1)


def _to_signed(v: int, size_bytes: int) -> int:
    v &= _mask(size_bytes)
    if v & _sign_bit(size_bytes):
        v -= 1 << (size_bytes * 8)
    return v


# ---------------------------------------------------------------------------
# Expression builders -- structural JSON oracle
# Each builder returns a canonical dict that mirrors the LlilExpr shape.
# ---------------------------------------------------------------------------

def validator_llil_reg(inp: Dict[str, Any]) -> Dict[str, Any]:
    return {"op": "Reg", "size": inp["size"], "name": inp["name"]}


def validator_llil_load(inp: Dict[str, Any]) -> Dict[str, Any]:
    return {"op": "Load", "size": inp["size"], "addr": inp["addr"]}


def _binop(op: str, inp: Dict[str, Any]) -> Dict[str, Any]:
    return {"op": op, "size": inp["size"], "lhs": inp["lhs"], "rhs": inp["rhs"]}


def validator_llil_add(inp): return _binop("Add", inp)
def validator_llil_sub(inp): return _binop("Sub", inp)
def validator_llil_and(inp): return _binop("And", inp)
def validator_llil_or(inp):  return _binop("Or",  inp)
def validator_llil_xor(inp): return _binop("Xor", inp)
def validator_llil_shl(inp): return _binop("Shl", inp)
def validator_llil_shr(inp): return _binop("Shr", inp)


def validator_llil_cmp_eq(inp): return {"op": "CmpEq", "size": 1, "lhs": inp["lhs"], "rhs": inp["rhs"]}
def validator_llil_cmp_ne(inp): return {"op": "CmpNe", "size": 1, "lhs": inp["lhs"], "rhs": inp["rhs"]}
def validator_llil_cmp_slt(inp): return {"op": "CmpSlt", "size": 1, "lhs": inp["lhs"], "rhs": inp["rhs"]}


def validator_llil_zx(inp): return {"op": "Zx", "from": inp["from"], "to": inp["to"], "expr": inp["expr"]}
def validator_llil_sx(inp): return {"op": "Sx", "from": inp["from"], "to": inp["to"], "expr": inp["expr"]}


def validator_llil_flag(inp): return {"op": "Flag", "name": inp["name"]}


# ---------------------------------------------------------------------------
# Concrete-interpreter oracle: evaluate an LLIL-like expression tree against
# a register-file mapping. Mirrors what LlilConcreteInterpreter must produce.
# ---------------------------------------------------------------------------

def _eval(expr: Dict[str, Any], regs: Dict[str, int]) -> int:
    op = expr["op"]
    if op == "Const":
        return expr["value"] & _mask(expr["size"])
    if op == "Reg":
        return regs.get(expr["name"], 0) & _mask(expr["size"])
    if op in ("Add", "Sub", "And", "Or", "Xor", "Shl", "Shr"):
        l = _eval(expr["lhs"], regs)
        r = _eval(expr["rhs"], regs)
        sz = expr["size"]
        m = _mask(sz)
        if op == "Add": return (l + r) & m
        if op == "Sub": return (l - r) & m
        if op == "And": return (l & r) & m
        if op == "Or":  return (l | r) & m
        if op == "Xor": return (l ^ r) & m
        if op == "Shl": return (l << (r & (sz * 8 - 1))) & m
        if op == "Shr": return (l >> (r & (sz * 8 - 1))) & m
    if op == "CmpEq": return int(_eval(expr["lhs"], regs) == _eval(expr["rhs"], regs))
    if op == "CmpNe": return int(_eval(expr["lhs"], regs) != _eval(expr["rhs"], regs))
    if op == "CmpSlt":
        l = _to_signed(_eval(expr["lhs"], regs), expr.get("opsize", 4))
        r = _to_signed(_eval(expr["rhs"], regs), expr.get("opsize", 4))
        return int(l < r)
    if op == "Zx":
        return _eval(expr["expr"], regs) & _mask(expr["from"])
    if op == "Sx":
        v = _eval(expr["expr"], regs) & _mask(expr["from"])
        return _to_signed(v, expr["from"]) & _mask(expr["to"])
    raise ValueError(f"unknown op {op}")


def validator_LlilConcreteInterpreter_eval(inp: Dict[str, Any]) -> Dict[str, Any]:
    """Evaluate one expression against a register map; mirror semantics."""
    return {"value": _eval(inp["expr"], inp.get("regs", {}))}


def validator_LlilConcreteInterpreter_run(inp: Dict[str, Any]) -> Dict[str, Any]:
    """
    Run a straight-line program: list of {"dst": regname, "expr": <expr>}.
    Returns final register file.
    """
    regs: Dict[str, int] = dict(inp.get("regs", {}))
    for instr in inp["program"]:
        regs[instr["dst"]] = _eval(instr["expr"], regs)
    return {"regs": regs}


# ---------------------------------------------------------------------------
# Constant folding oracle (LlilConstantFolder)
# Folds Const op Const => Const for ALU binops.
# ---------------------------------------------------------------------------

def validator_LlilConstantFolder(inp: Dict[str, Any]) -> Dict[str, Any]:
    def fold(e):
        if not isinstance(e, dict):
            return e
        e = {k: (fold(v) if isinstance(v, dict) else v) for k, v in e.items()}
        op = e.get("op")
        if op in ("Add", "Sub", "And", "Or", "Xor", "Shl", "Shr"):
            l, r = e.get("lhs"), e.get("rhs")
            if isinstance(l, dict) and isinstance(r, dict) and l.get("op") == "Const" and r.get("op") == "Const":
                v = _eval(e, {})
                return {"op": "Const", "size": e["size"], "value": v}
        return e
    return {"expr": fold(inp["expr"])}


# ---------------------------------------------------------------------------
# Liveness analysis oracle (backward dataflow on a tiny CFG)
# Input:
#   blocks: [{id, defs:[reg], uses:[reg], succs:[block_id]}]
# Output:
#   per-block {live_in:[...], live_out:[...]}
# ---------------------------------------------------------------------------

def validator_liveness_analysis(inp: Dict[str, Any]) -> Dict[str, Any]:
    blocks = {b["id"]: b for b in inp["blocks"]}
    live_in: Dict[Any, set] = {bid: set() for bid in blocks}
    live_out: Dict[Any, set] = {bid: set() for bid in blocks}
    changed = True
    while changed:
        changed = False
        for bid, b in blocks.items():
            new_out = set()
            for s in b.get("succs", []):
                new_out |= live_in[s]
            new_in = set(b.get("uses", [])) | (new_out - set(b.get("defs", [])))
            if new_in != live_in[bid] or new_out != live_out[bid]:
                live_in[bid] = new_in
                live_out[bid] = new_out
                changed = True
    return {
        "blocks": {
            str(bid): {"live_in": sorted(live_in[bid]), "live_out": sorted(live_out[bid])}
            for bid in blocks
        }
    }


# ---------------------------------------------------------------------------
# SSA invariant checker oracle for build_ssa output
# Input: ssa_instrs: [{dst:"r1.2", uses:["r0.1",...]}]
# Output: {single_def: bool, def_count_per_name: {...}}
# ---------------------------------------------------------------------------

def validator_build_ssa_invariants(inp: Dict[str, Any]) -> Dict[str, Any]:
    counts: Dict[str, int] = {}
    for ins in inp["ssa_instrs"]:
        dst = ins.get("dst")
        if dst is not None:
            counts[dst] = counts.get(dst, 0) + 1
    single_def = all(v == 1 for v in counts.values())
    multi = [n for n, c in counts.items() if c > 1]
    return {"single_def": single_def, "violating": multi, "def_count_per_name": counts}


# ---------------------------------------------------------------------------
# DOT oracle: build expected DOT for a CFG.
# Input: {name, nodes:[id], edges:[[a,b]]}
# Output: dot string + edge/node counts.
# ---------------------------------------------------------------------------

def validator_function_to_dot(inp: Dict[str, Any]) -> Dict[str, Any]:
    name = inp.get("name", "f")
    nodes = inp["nodes"]
    edges = inp["edges"]
    lines = [f"digraph {name} {{"]
    for n in nodes:
        lines.append(f'  "{n}";')
    for a, b in edges:
        lines.append(f'  "{a}" -> "{b}";')
    lines.append("}")
    return {"dot": "\n".join(lines), "node_count": len(nodes), "edge_count": len(edges)}


# ---------------------------------------------------------------------------
# JSON round-trip oracle for function_to_json / llil_snapshot_from_json
# ---------------------------------------------------------------------------

def validator_function_to_json_roundtrip(inp: Dict[str, Any]) -> Dict[str, Any]:
    s = json.dumps(inp["snapshot"], sort_keys=True)
    back = json.loads(s)
    return {"roundtrip_equal": back == inp["snapshot"], "json": s}


# ---------------------------------------------------------------------------
# Dispatcher
# ---------------------------------------------------------------------------

VALIDATORS = {
    name[len("validator_"):]: fn
    for name, fn in globals().items()
    if name.startswith("validator_") and callable(fn)
}


def _self_test() -> int:
    failures = 0

    def check(label, got, want):
        nonlocal failures
        ok = got == want
        print(f"[{'OK' if ok else 'FAIL'}] {label}")
        if not ok:
            print(f"   got : {got}")
            print(f"   want: {want}")
            failures += 1

    # builders
    check("llil_reg", validator_llil_reg({"name": "rax", "size": 8}),
          {"op": "Reg", "size": 8, "name": "rax"})
    check("llil_add struct", validator_llil_add({"size": 4, "lhs": {"op": "Const", "size": 4, "value": 2},
                                                 "rhs": {"op": "Const", "size": 4, "value": 3}})["op"], "Add")

    # interpreter: (2 + 3) ^ 1 = 4
    prog = {
        "regs": {},
        "program": [
            {"dst": "r1", "expr": {"op": "Add", "size": 4,
                                    "lhs": {"op": "Const", "size": 4, "value": 2},
                                    "rhs": {"op": "Const", "size": 4, "value": 3}}},
            {"dst": "r2", "expr": {"op": "Xor", "size": 4,
                                    "lhs": {"op": "Reg", "size": 4, "name": "r1"},
                                    "rhs": {"op": "Const", "size": 4, "value": 1}}},
        ],
    }
    check("interpreter (2+3)^1", validator_LlilConcreteInterpreter_run(prog)["regs"]["r2"], 4)

    # constant folding: 2+3 -> 5
    folded = validator_LlilConstantFolder({"expr": {"op": "Add", "size": 4,
                                                     "lhs": {"op": "Const", "size": 4, "value": 2},
                                                     "rhs": {"op": "Const", "size": 4, "value": 3}}})
    check("const fold 2+3", folded["expr"], {"op": "Const", "size": 4, "value": 5})

    # liveness on: B0(def r1, use=[]) -> B1(use r1, def r2) -> B2(use r2)
    liv = validator_liveness_analysis({"blocks": [
        {"id": 0, "defs": ["r1"], "uses": [], "succs": [1]},
        {"id": 1, "defs": ["r2"], "uses": ["r1"], "succs": [2]},
        {"id": 2, "defs": [], "uses": ["r2"], "succs": []},
    ]})
    check("liveness B0 live_in", liv["blocks"]["0"]["live_in"], [])
    check("liveness B1 live_in", liv["blocks"]["1"]["live_in"], ["r1"])
    check("liveness B2 live_in", liv["blocks"]["2"]["live_in"], ["r2"])

    # SSA invariants
    inv = validator_build_ssa_invariants({"ssa_instrs": [
        {"dst": "r1.1", "uses": []},
        {"dst": "r1.2", "uses": ["r1.1"]},
        {"dst": "r2.1", "uses": ["r1.2"]},
    ]})
    check("ssa single_def true", inv["single_def"], True)

    # DOT counts
    dot = validator_function_to_dot({"name": "f", "nodes": [0, 1, 2], "edges": [[0, 1], [1, 2]]})
    check("dot counts", (dot["node_count"], dot["edge_count"]), (3, 2))

    # JSON round-trip
    rt = validator_function_to_json_roundtrip({"snapshot": {"name": "f", "blocks": [{"id": 0}]}})
    check("json roundtrip", rt["roundtrip_equal"], True)

    print(f"\n{len(VALIDATORS)} validators registered, {failures} failures")
    return 0 if failures == 0 else 1


def main() -> int:
    if "--self-test" in sys.argv:
        return _self_test()
    if "--list" in sys.argv:
        print(json.dumps(sorted(VALIDATORS.keys()), indent=2))
        return 0
    raw = sys.stdin.read().strip()
    if not raw:
        return _self_test()
    req = json.loads(raw)
    fn_name = req["function"]
    if fn_name not in VALIDATORS:
        print(json.dumps({"error": f"unknown function {fn_name}",
                          "available": sorted(VALIDATORS.keys())}))
        return 2
    out = VALIDATORS[fn_name](req.get("input", {}))
    print(json.dumps({"output": out}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
