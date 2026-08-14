#!/usr/bin/env python3
"""
Standalone validator for rustre-il-mlil crate.

Reimplements (in Python stdlib + optional networkx) the semantic ground-truths
of the MLIL crate: constant folding, idempotency of optimization passes
(modelled abstractly), dominators, liveness, reaching defs, JSON round-trip,
counting oracles.

The validator does NOT import the Rust crate nor call any MCP tool. It exposes
`validator_<name>(input) -> output` functions plus a `main()` that runs a fixed
test battery and emits a JSON report on stdout. It can also be driven from
stdin: `{"function": "<name>", "input": {...}}` -> `{"output": ...}`.
"""

from __future__ import annotations

import json
import sys
import subprocess
import hashlib
from collections import defaultdict, deque
from typing import Any, Dict, List, Tuple, Set, Optional


# ---------------------------------------------------------------------------
# Optional deps (networkx for dominators reference). Install on demand.
# ---------------------------------------------------------------------------
def _ensure(pkg: str, import_name: Optional[str] = None):
    name = import_name or pkg
    try:
        return __import__(name)
    except ImportError:
        subprocess.check_call(
            [sys.executable, "-m", "pip", "install", "--quiet", pkg]
        )
        return __import__(name)


# =============================================================================
# 1. fold_mlil_expr — pure constant folding oracle
# =============================================================================
# Expressions are encoded as nested lists:
#   ["Const", value, size_bits]
#   ["Var",   name]
#   ["Add"|"Sub"|"Mul"|"Shl"|"Shr"|"And"|"Or"|"Xor", lhs, rhs, size_bits]
#   ["Neg"|"Not", expr, size_bits]

_BINOPS = {
    "Add": lambda a, b: a + b,
    "Sub": lambda a, b: a - b,
    "Mul": lambda a, b: a * b,
    "Shl": lambda a, b: a << (b & 63),
    "Shr": lambda a, b: (a & ((1 << 64) - 1)) >> (b & 63),
    "And": lambda a, b: a & b,
    "Or":  lambda a, b: a | b,
    "Xor": lambda a, b: a ^ b,
}


def _mask(v: int, size_bits: int) -> int:
    m = (1 << size_bits) - 1
    return v & m


def validator_fold_mlil_expr(expr: list) -> Tuple[list, int]:
    """Returns (folded_expr, change_count). Mirrors the Rust `fold_mlil_expr`."""
    if not isinstance(expr, list) or not expr:
        return expr, 0
    op = expr[0]
    if op == "Const" or op == "Var":
        return expr, 0
    if op in _BINOPS:
        _, lhs, rhs, size = expr
        lhs_f, c1 = validator_fold_mlil_expr(lhs)
        rhs_f, c2 = validator_fold_mlil_expr(rhs)
        changes = c1 + c2
        if lhs_f[0] == "Const" and rhs_f[0] == "Const":
            val = _mask(_BINOPS[op](lhs_f[1], rhs_f[1]), size)
            return ["Const", val, size], changes + 1
        return [op, lhs_f, rhs_f, size], changes
    if op in ("Neg", "Not"):
        _, inner, size = expr
        inner_f, c = validator_fold_mlil_expr(inner)
        if inner_f[0] == "Const":
            val = -inner_f[1] if op == "Neg" else ~inner_f[1]
            return ["Const", _mask(val, size), size], c + 1
        return [op, inner_f, size], c
    return expr, 0


# =============================================================================
# 2. Idempotency oracle (abstract MlilFunction)
# =============================================================================
# A function is a dict:
#   {"blocks": {bid: {"instrs": [...], "succs": [bid,...]}},
#    "entry": bid}
# Each instr: {"op": "Store"|"Load"|"Copy"|"Phi"|"Call"|"BinOp"|"Return",
#              "def": ssa_var_or_None, "uses": [ssa_var,...],
#              "addr": int_or_None, "extra": {...}}

def _run_pass_once(func: dict, pass_name: str) -> Tuple[dict, int]:
    """Apply one optimization pass, return (new_func, change_count)."""
    import copy
    f = copy.deepcopy(func)
    changes = 0

    if pass_name == "eliminate_dead_stores":
        all_uses: Set = set()
        for b in f["blocks"].values():
            for ins in b["instrs"]:
                for u in ins.get("uses", []):
                    all_uses.add(u)
        for b in f["blocks"].values():
            keep = []
            for ins in b["instrs"]:
                if ins["op"] == "Store" and ins.get("def") is not None \
                        and ins["def"] not in all_uses:
                    changes += 1
                    continue
                keep.append(ins)
            b["instrs"] = keep

    elif pass_name == "propagate_copies":
        copies: Dict = {}
        for b in f["blocks"].values():
            for ins in b["instrs"]:
                if ins["op"] == "Copy" and ins.get("def") and ins.get("uses"):
                    copies[ins["def"]] = ins["uses"][0]
        # transitive
        changed = True
        while changed:
            changed = False
            for k, v in list(copies.items()):
                if v in copies and copies[v] != v:
                    copies[k] = copies[v]
                    changed = True
        for b in f["blocks"].values():
            for ins in b["instrs"]:
                new_uses = []
                for u in ins.get("uses", []):
                    nu = copies.get(u, u)
                    if nu != u:
                        changes += 1
                    new_uses.append(nu)
                ins["uses"] = new_uses

    elif pass_name == "eliminate_trivial_phis":
        for b in f["blocks"].values():
            keep = []
            for ins in b["instrs"]:
                if ins["op"] == "Phi":
                    distinct = set(ins.get("uses", []))
                    distinct.discard(ins.get("def"))
                    if len(distinct) <= 1:
                        changes += 1
                        continue
                keep.append(ins)
            b["instrs"] = keep

    elif pass_name == "algebraic_simplify":
        for b in f["blocks"].values():
            for ins in b["instrs"]:
                if ins["op"] == "BinOp":
                    e = ins.get("extra", {})
                    kind = e.get("kind")
                    lhs = e.get("lhs")
                    rhs = e.get("rhs")
                    # x+0 = x, x*1 = x, x&x = x, x^x = 0
                    if kind == "Add" and rhs == ["Const", 0, 64]:
                        ins["op"] = "Copy"
                        ins["uses"] = [lhs] if isinstance(lhs, str) else []
                        ins["extra"] = {}
                        changes += 1
                    elif kind == "Mul" and rhs == ["Const", 1, 64]:
                        ins["op"] = "Copy"
                        ins["uses"] = [lhs] if isinstance(lhs, str) else []
                        ins["extra"] = {}
                        changes += 1

    elif pass_name == "strength_reduce":
        for b in f["blocks"].values():
            for ins in b["instrs"]:
                if ins["op"] == "BinOp":
                    e = ins.get("extra", {})
                    if e.get("kind") == "Mul":
                        rhs = e.get("rhs")
                        if isinstance(rhs, list) and rhs[0] == "Const":
                            v = rhs[1]
                            if v > 0 and (v & (v - 1)) == 0:  # power of two
                                k = v.bit_length() - 1
                                e["kind"] = "Shl"
                                e["rhs"] = ["Const", k, rhs[2]]
                                changes += 1

    elif pass_name == "eliminate_redundant_loads":
        for b in f["blocks"].values():
            seen_addr: Dict[int, Any] = {}
            keep = []
            for ins in b["instrs"]:
                if ins["op"] == "Store":
                    seen_addr.clear()
                if ins["op"] == "Load" and ins.get("addr") is not None:
                    if ins["addr"] in seen_addr:
                        changes += 1
                        continue
                    seen_addr[ins["addr"]] = ins.get("def")
                keep.append(ins)
            b["instrs"] = keep

    elif pass_name == "global_value_numbering":
        value_num: Dict[Tuple, int] = {}
        var_to_num: Dict[str, int] = {}
        next_n = [0]

        def num_for(key):
            if key not in value_num:
                value_num[key] = next_n[0]
                next_n[0] += 1
            return value_num[key]

        for b in f["blocks"].values():
            for ins in b["instrs"]:
                if ins["op"] == "BinOp" and ins.get("def"):
                    e = ins.get("extra", {})
                    key = (e.get("kind"), str(e.get("lhs")), str(e.get("rhs")))
                    n = num_for(key)
                    if ins["def"] in var_to_num and var_to_num[ins["def"]] == n:
                        # already numbered → counted as redundancy
                        pass
                    else:
                        if any(v == n for v in var_to_num.values()):
                            changes += 1
                        var_to_num[ins["def"]] = n

    return f, changes


def validator_idempotency(func: dict, pass_name: str) -> Dict[str, int]:
    """Run pass twice; second run must report 0 changes."""
    f1, c1 = _run_pass_once(func, pass_name)
    f2, c2 = _run_pass_once(f1, pass_name)
    return {
        "first_changes": c1,
        "second_changes": c2,
        "idempotent": c2 == 0,
    }


# =============================================================================
# 3. compute_dominators — Cooper-Harvey-Kennedy reference
# =============================================================================
def validator_compute_dominators(cfg: Dict[str, Any]) -> Dict[str, Optional[str]]:
    """cfg = {'entry': id, 'succs': {id: [id,...]}}. Returns id -> idom."""
    entry = cfg["entry"]
    succs: Dict[str, List[str]] = {str(k): [str(x) for x in v]
                                   for k, v in cfg["succs"].items()}
    nodes = set(succs.keys()) | {str(entry)}
    for vs in succs.values():
        nodes.update(vs)
    nodes = list(nodes)

    preds: Dict[str, List[str]] = {n: [] for n in nodes}
    for s, vs in succs.items():
        for d in vs:
            preds[d].append(s)

    # Reverse-postorder
    order: List[str] = []
    visited: Set[str] = set()

    def dfs(n: str):
        if n in visited:
            return
        visited.add(n)
        for s in succs.get(n, []):
            dfs(s)
        order.append(n)

    dfs(str(entry))
    rpo = list(reversed(order))
    rpo_index = {n: i for i, n in enumerate(rpo)}

    idom: Dict[str, Optional[str]] = {n: None for n in nodes}
    idom[str(entry)] = str(entry)

    def intersect(b1: str, b2: str) -> str:
        while b1 != b2:
            while rpo_index.get(b1, 1 << 30) > rpo_index.get(b2, 1 << 30):
                b1 = idom[b1]  # type: ignore
            while rpo_index.get(b2, 1 << 30) > rpo_index.get(b1, 1 << 30):
                b2 = idom[b2]  # type: ignore
        return b1

    changed = True
    while changed:
        changed = False
        for n in rpo:
            if n == str(entry):
                continue
            processed_preds = [p for p in preds[n] if idom.get(p) is not None]
            if not processed_preds:
                continue
            new_idom = processed_preds[0]
            for p in processed_preds[1:]:
                new_idom = intersect(p, new_idom)
            if idom[n] != new_idom:
                idom[n] = new_idom
                changed = True

    # entry has no idom (None) by convention
    idom[str(entry)] = None
    return idom


# =============================================================================
# 4. compute_liveness — textbook backward fixpoint
# =============================================================================
def validator_compute_liveness(func: dict) -> Dict[str, Dict[str, List[str]]]:
    """
    func = {'blocks': {bid: {'instrs': [...], 'succs': [bid,...]}}}
    Returns {bid: {'live_in': [...], 'live_out': [...]}}.
    Each instr contributes 'def' (str|None) and 'uses' (list[str]).
    """
    blocks = func["blocks"]
    use: Dict[str, Set[str]] = {}
    defs: Dict[str, Set[str]] = {}
    for bid, b in blocks.items():
        u, d = set(), set()
        for ins in b["instrs"]:
            for x in ins.get("uses", []):
                if x not in d:
                    u.add(x)
            if ins.get("def"):
                d.add(ins["def"])
        use[bid] = u
        defs[bid] = d

    live_in: Dict[str, Set[str]] = {bid: set() for bid in blocks}
    live_out: Dict[str, Set[str]] = {bid: set() for bid in blocks}

    changed = True
    while changed:
        changed = False
        for bid, b in blocks.items():
            new_out = set()
            for s in b.get("succs", []):
                new_out |= live_in.get(s, set())
            new_in = use[bid] | (new_out - defs[bid])
            if new_in != live_in[bid] or new_out != live_out[bid]:
                live_in[bid] = new_in
                live_out[bid] = new_out
                changed = True

    return {
        bid: {
            "live_in": sorted(live_in[bid]),
            "live_out": sorted(live_out[bid]),
        }
        for bid in blocks
    }


# =============================================================================
# 5. compute_reaching_defs — textbook forward fixpoint
# =============================================================================
def validator_compute_reaching_defs(func: dict) -> Dict[str, Dict[str, List[str]]]:
    blocks = func["blocks"]
    # gen[B] = set of defs in B (use index "bid:i"); kill[B] = defs of same var elsewhere
    var_defs: Dict[str, Set[str]] = defaultdict(set)
    gen: Dict[str, Set[str]] = {}
    instr_var: Dict[str, str] = {}
    for bid, b in blocks.items():
        g = set()
        for i, ins in enumerate(b["instrs"]):
            if ins.get("def"):
                key = f"{bid}:{i}"
                g.add(key)
                instr_var[key] = ins["def"]
                var_defs[ins["def"]].add(key)
        gen[bid] = g

    kill: Dict[str, Set[str]] = {}
    for bid, g in gen.items():
        k = set()
        for d in g:
            v = instr_var[d]
            k |= (var_defs[v] - {d})
        kill[bid] = k

    preds: Dict[str, List[str]] = {bid: [] for bid in blocks}
    for bid, b in blocks.items():
        for s in b.get("succs", []):
            preds.setdefault(s, []).append(bid)

    rin: Dict[str, Set[str]] = {bid: set() for bid in blocks}
    rout: Dict[str, Set[str]] = {bid: set() for bid in blocks}

    changed = True
    while changed:
        changed = False
        for bid in blocks:
            new_in = set()
            for p in preds.get(bid, []):
                new_in |= rout.get(p, set())
            new_out = gen[bid] | (new_in - kill[bid])
            if new_in != rin[bid] or new_out != rout[bid]:
                rin[bid] = new_in
                rout[bid] = new_out
                changed = True

    return {
        bid: {"in": sorted(rin[bid]), "out": sorted(rout[bid])}
        for bid in blocks
    }


# =============================================================================
# 6. JSON round-trip
# =============================================================================
def validator_mlil_function_to_json_roundtrip(func: dict) -> Dict[str, Any]:
    s = json.dumps(func, sort_keys=True)
    back = json.loads(s)
    s2 = json.dumps(back, sort_keys=True)
    return {
        "roundtrip_equal": s == s2,
        "hash": hashlib.sha256(s.encode()).hexdigest(),
    }


# =============================================================================
# 7. Counting oracles
# =============================================================================
def _walk_consts(expr) -> List[int]:
    out = []
    if isinstance(expr, list) and expr:
        if expr[0] == "Const":
            out.append(expr[1])
        else:
            for sub in expr[1:]:
                if isinstance(sub, list):
                    out.extend(_walk_consts(sub))
    return out


def validator_collect_constants(func: dict) -> List[int]:
    out: List[int] = []
    for b in func["blocks"].values():
        for ins in b["instrs"]:
            extra = ins.get("extra", {})
            for v in extra.values():
                if isinstance(v, list):
                    out.extend(_walk_consts(v))
                elif isinstance(v, int):
                    out.append(v)
    return out


def validator_collect_call_sites(func: dict) -> int:
    n = 0
    for b in func["blocks"].values():
        for ins in b["instrs"]:
            if ins["op"] == "Call":
                n += 1
    return n


def validator_compute_stats(func: dict) -> Dict[str, int]:
    n_instr = 0
    n_phi = 0
    for b in func["blocks"].values():
        n_instr += len(b["instrs"])
        for ins in b["instrs"]:
            if ins["op"] == "Phi":
                n_phi += 1
    return {
        "block_count": len(func["blocks"]),
        "instr_count": n_instr,
        "phi_count": n_phi,
    }


# =============================================================================
# 8. effects_to_mlil — abstract monotonicity check
# =============================================================================
def validator_effects_to_mlil(effects: List[dict]) -> List[dict]:
    """Translate a flat effect list to a flat MLIL instr list, deterministic."""
    out = []
    for e in effects:
        kind = e.get("kind")
        if kind in ("SetVar", "Store", "Call", "Branch", "Return"):
            out.append({
                "op": "Store" if kind == "Store" else
                      "Call" if kind == "Call" else
                      "Return" if kind == "Return" else
                      "BinOp" if kind == "SetVar" else "Branch",
                "def": e.get("dst"),
                "uses": e.get("uses", []),
                "addr": e.get("addr"),
                "extra": e.get("extra", {}),
            })
    return out


# =============================================================================
# 9. DOT validity check (optional — uses pydot if available)
# =============================================================================
def validator_mlil_function_to_dot_check(dot_text: str, expected_nodes: int) -> Dict[str, Any]:
    try:
        pydot = _ensure("pydot")
        graphs = pydot.graph_from_dot_data(dot_text)
        if not graphs:
            return {"parseable": False, "node_count": 0,
                    "expected": expected_nodes, "match": False}
        g = graphs[0]
        n = len(g.get_nodes())
        return {
            "parseable": True,
            "node_count": n,
            "expected": expected_nodes,
            "match": n == expected_nodes,
        }
    except Exception as ex:
        return {"parseable": False, "error": str(ex)}


# =============================================================================
# Dispatcher (stdin JSON) + main test battery
# =============================================================================
FUNCTIONS = {
    "fold_mlil_expr": validator_fold_mlil_expr,
    "idempotency": lambda inp: validator_idempotency(inp["func"], inp["pass"]),
    "compute_dominators": validator_compute_dominators,
    "compute_liveness": validator_compute_liveness,
    "compute_reaching_defs": validator_compute_reaching_defs,
    "json_roundtrip": validator_mlil_function_to_json_roundtrip,
    "collect_constants": validator_collect_constants,
    "collect_call_sites": validator_collect_call_sites,
    "compute_stats": validator_compute_stats,
    "effects_to_mlil": validator_effects_to_mlil,
    "dot_check": lambda inp: validator_mlil_function_to_dot_check(
        inp["dot"], inp["expected_nodes"]),
}


def _self_test() -> Dict[str, Any]:
    results = {}

    # fold
    e = ["Add", ["Const", 2, 32], ["Const", 3, 32], 32]
    folded, n = validator_fold_mlil_expr(e)
    results["fold_mlil_expr"] = {
        "ok": folded == ["Const", 5, 32] and n == 1
    }

    # idempotency for each pass
    sample = {
        "entry": "B0",
        "blocks": {
            "B0": {
                "instrs": [
                    {"op": "Copy", "def": "v1", "uses": ["v0"]},
                    {"op": "BinOp", "def": "v2", "uses": ["v1"],
                     "extra": {"kind": "Mul", "lhs": "v1",
                               "rhs": ["Const", 8, 64]}},
                    {"op": "BinOp", "def": "v3", "uses": ["v2"],
                     "extra": {"kind": "Add", "lhs": "v2",
                               "rhs": ["Const", 0, 64]}},
                    {"op": "Store", "def": "s1", "uses": [], "addr": 0x100},
                    {"op": "Load",  "def": "l1", "uses": [], "addr": 0x100},
                    {"op": "Load",  "def": "l2", "uses": [], "addr": 0x100},
                    {"op": "Phi",   "def": "p1", "uses": ["v3", "v3"]},
                    {"op": "Call",  "def": "r1", "uses": ["v3"]},
                    {"op": "Return", "def": None, "uses": ["r1"]},
                ],
                "succs": [],
            }
        },
    }
    for p in [
        "eliminate_dead_stores", "propagate_copies", "eliminate_trivial_phis",
        "algebraic_simplify", "strength_reduce", "eliminate_redundant_loads",
        "global_value_numbering",
    ]:
        results[f"idempotency_{p}"] = validator_idempotency(sample, p)

    # dominators (diamond)
    cfg = {
        "entry": "A",
        "succs": {"A": ["B", "C"], "B": ["D"], "C": ["D"], "D": []},
    }
    idom = validator_compute_dominators(cfg)
    results["compute_dominators"] = {
        "idom": idom,
        "ok": idom["B"] == "A" and idom["C"] == "A" and idom["D"] == "A"
              and idom["A"] is None,
    }

    # liveness on tiny graph
    lf = {
        "blocks": {
            "B0": {"instrs": [{"op": "Copy", "def": "x", "uses": []}],
                   "succs": ["B1"]},
            "B1": {"instrs": [{"op": "Return", "def": None, "uses": ["x"]}],
                   "succs": []},
        }
    }
    results["compute_liveness"] = validator_compute_liveness(lf)

    # reaching defs
    results["compute_reaching_defs"] = validator_compute_reaching_defs(lf)

    # json roundtrip
    results["json_roundtrip"] = validator_mlil_function_to_json_roundtrip(sample)

    # counts
    results["collect_constants"] = validator_collect_constants(sample)
    results["collect_call_sites"] = validator_collect_call_sites(sample)
    results["compute_stats"] = validator_compute_stats(sample)

    # effects_to_mlil monotonic
    ef = [{"kind": "SetVar", "dst": "v0"},
          {"kind": "Store", "addr": 0x10},
          {"kind": "Return"}]
    out1 = validator_effects_to_mlil(ef)
    out2 = validator_effects_to_mlil(ef + [{"kind": "Call", "dst": "r"}])
    results["effects_to_mlil_monotonic"] = {
        "ok": len(out2) >= len(out1),
        "n1": len(out1), "n2": len(out2),
    }

    return results


def main():
    # stdin JSON dispatch
    if not sys.stdin.isatty():
        try:
            payload = json.loads(sys.stdin.read() or "{}")
        except json.JSONDecodeError:
            payload = {}
        if payload.get("function"):
            fn = FUNCTIONS[payload["function"]]
            out = fn(payload.get("input"))
            print(json.dumps({"output": out}, default=str))
            return

    # otherwise: self-test
    report = {
        "crate": "rustre-il-mlil",
        "results": _self_test(),
    }
    print(json.dumps(report, default=str, indent=2))


if __name__ == "__main__":
    main()
