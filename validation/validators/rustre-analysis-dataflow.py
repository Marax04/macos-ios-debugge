#!/usr/bin/env python3
"""
Independent Python validator for rustre-analysis-dataflow.

Reimplements (in pure Python) the testable functions of the crate so we
can cross-check the Rust outputs. No Rust import, no MCP calls.

Covered:
  - compute_liveness
  - compute_reaching_defs
  - propagate_constants (with LatticeValue meet)
  - compute_dominators / compute_dominators_from_edges
  - compute_dominance_frontiers
  - postorder
  - trace_callers_backward / trace_callees_forward
  - LatticeValue.meet (truth table)
  - WorklistAlgorithm + LiveVariableAnalysis / ReachingDefinitions
  - ChainBuilder.build (def-use chains validity check)

Usage:
  echo '{"fn":"compute_liveness","input":{...}}' | python rustre-analysis-dataflow.py
  python rustre-analysis-dataflow.py        # runs main() self-test
"""
from __future__ import annotations
import json
import sys
import subprocess
from collections import defaultdict, deque
from typing import Any

# ---------- optional deps ----------
def _ensure(pkg: str, import_name: str | None = None):
    name = import_name or pkg
    try:
        return __import__(name)
    except ImportError:
        subprocess.check_call([sys.executable, "-m", "pip", "install", "--quiet", pkg])
        return __import__(name)

nx = _ensure("networkx")

# ============================================================
# LatticeValue
# ============================================================
# Representation: ("Top",) | ("Const", int) | ("Bottom",)
TOP = ("Top",)
BOTTOM = ("Bottom",)
def CONST(v): return ("Const", int(v))

def lattice_meet(a, b):
    """Constant-propagation lattice meet.
       Top is identity; Bottom is absorbing; Const meet Const = same or Bottom."""
    if a == TOP: return b
    if b == TOP: return a
    if a == BOTTOM or b == BOTTOM: return BOTTOM
    # both Const
    if a[1] == b[1]: return a
    return BOTTOM

def validator_lattice_meet_table():
    """Exhaustive truth table for small set of values."""
    vals = [TOP, BOTTOM, CONST(1), CONST(2)]
    out = {}
    for a in vals:
        for b in vals:
            out[f"{a}|{b}"] = lattice_meet(a, b)
    return out

# ============================================================
# compute_liveness  (backward, may)
#   in = (out - def) U use
#   out = U over successors of in[s]
# Input nodes: list of (bb_id, succs, gen(use), kill(def))
# ============================================================
def validator_compute_liveness(nodes):
    nodes = [(n[0], list(n[1]), set(n[2]), set(n[3])) for n in nodes]
    ids = [n[0] for n in nodes]
    by_id = {n[0]: n for n in nodes}
    live_in = {i: set() for i in ids}
    live_out = {i: set() for i in ids}
    changed = True
    iters = 0
    while changed and iters < 10000:
        changed = False
        iters += 1
        for bb, succs, use, dfn in nodes:
            new_out = set()
            for s in succs:
                if s in live_in:
                    new_out |= live_in[s]
            new_in = (new_out - dfn) | use
            if new_in != live_in[bb] or new_out != live_out[bb]:
                live_in[bb] = new_in
                live_out[bb] = new_out
                changed = True
    return {bb: {"live_in": sorted(live_in[bb]), "live_out": sorted(live_out[bb])} for bb in ids}

# ============================================================
# compute_reaching_defs  (forward, may)
#   Each node has gen (defs created) and kill (defs killed).
#   out = gen U (in - kill); in = union over preds of out
# Definitions identified by strings (e.g. "x@bb1").
# ============================================================
def validator_compute_reaching_defs(nodes):
    nodes = [(n[0], list(n[1]), set(n[2]), set(n[3])) for n in nodes]
    ids = [n[0] for n in nodes]
    succs = {n[0]: n[1] for n in nodes}
    gen = {n[0]: n[2] for n in nodes}
    kill = {n[0]: n[3] for n in nodes}
    preds = defaultdict(list)
    for bb, ss in succs.items():
        for s in ss:
            preds[s].append(bb)
    rd_in = {i: set() for i in ids}
    rd_out = {i: set() for i in ids}
    changed = True
    iters = 0
    while changed and iters < 10000:
        changed = False
        iters += 1
        for bb in ids:
            new_in = set()
            for p in preds[bb]:
                new_in |= rd_out[p]
            new_out = gen[bb] | (new_in - kill[bb])
            if new_in != rd_in[bb] or new_out != rd_out[bb]:
                rd_in[bb] = new_in
                rd_out[bb] = new_out
                changed = True
    return {bb: {"rd_in": sorted(rd_in[bb]), "rd_out": sorted(rd_out[bb])} for bb in ids}

# ============================================================
# propagate_constants
#   assignments: list of [var, value_int_or_null]  (null => Bottom)
#   uses: list of var names; if a use has no assignment => Bottom
# ============================================================
def validator_propagate_constants(assignments, uses):
    table: dict[str, Any] = {}
    for var, val in assignments:
        v = CONST(val) if val is not None else BOTTOM
        if var in table:
            table[var] = lattice_meet(table[var], v)
        else:
            table[var] = v
    for u in uses:
        if u not in table:
            table[u] = BOTTOM
    return {k: list(v) for k, v in table.items()}

# ============================================================
# Dominators via networkx
# ============================================================
def _build_digraph(n, successors, entry):
    g = nx.DiGraph()
    g.add_nodes_from(range(n))
    for u, ss in enumerate(successors):
        for v in ss:
            g.add_edge(u, v)
    return g

def validator_compute_dominators(n, successors, entry):
    g = _build_digraph(n, successors, entry)
    idom = nx.immediate_dominators(g, entry)
    # by convention idom[entry] = entry; nodes unreachable -> entry as sentinel
    out = []
    for i in range(n):
        out.append(idom.get(i, entry))
    return out

def validator_compute_dominators_from_edges(n, edges, entry):
    successors = [[] for _ in range(n)]
    for u, v in edges:
        successors[u].append(v)
    return validator_compute_dominators(n, successors, entry)

def validator_compute_dominance_frontiers(n, successors, entry):
    g = _build_digraph(n, successors, entry)
    df = nx.dominance_frontiers(g, entry)
    return {i: sorted(df.get(i, set())) for i in range(n)}

def validator_postorder(n, successors, entry):
    g = _build_digraph(n, successors, entry)
    return list(nx.dfs_postorder_nodes(g, source=entry))

# ============================================================
# Call-graph slicers
# edges: list of [caller, callee]
# ============================================================
def validator_trace_callers_backward(addr, hops, edges):
    # reverse direction
    g = nx.DiGraph()
    for c, ce in edges:
        g.add_edge(ce, c)  # reversed
    if addr not in g:
        return [addr]
    visited = {addr}
    frontier = deque([(addr, 0)])
    while frontier:
        node, d = frontier.popleft()
        if d >= hops: continue
        for nb in g.successors(node):
            if nb not in visited:
                visited.add(nb)
                frontier.append((nb, d + 1))
    return sorted(visited)

def validator_trace_callees_forward(addr, hops, edges):
    g = nx.DiGraph()
    for c, ce in edges:
        g.add_edge(c, ce)
    if addr not in g:
        return [addr]
    visited = {addr}
    frontier = deque([(addr, 0)])
    while frontier:
        node, d = frontier.popleft()
        if d >= hops: continue
        for nb in g.successors(node):
            if nb not in visited:
                visited.add(nb)
                frontier.append((nb, d + 1))
    return sorted(visited)

# ============================================================
# WorklistAlgorithm — generic, with two analyses
# ============================================================
def _worklist(direction, transfer, join, boundary, init, nodes, succs, preds):
    """direction: 'forward' | 'backward'."""
    in_facts = {n: set(init) for n in nodes}
    out_facts = {n: set(init) for n in nodes}
    # boundary
    if direction == "forward":
        for n in nodes:
            if not preds[n]:
                in_facts[n] = set(boundary)
    else:
        for n in nodes:
            if not succs[n]:
                out_facts[n] = set(boundary)

    work = deque(nodes)
    iters = 0
    in_q = set(nodes)
    while work and iters < 10000:
        iters += 1
        n = work.popleft(); in_q.discard(n)
        if direction == "forward":
            merged = set()
            ps = preds[n]
            if ps:
                merged = set(out_facts[ps[0]])
                for p in ps[1:]:
                    merged = join(merged, out_facts[p])
            else:
                merged = set(boundary)
            in_facts[n] = merged
            new_out = transfer(n, merged)
            if new_out != out_facts[n]:
                out_facts[n] = new_out
                for s in succs[n]:
                    if s not in in_q:
                        work.append(s); in_q.add(s)
        else:
            merged = set()
            ss = succs[n]
            if ss:
                merged = set(in_facts[ss[0]])
                for s in ss[1:]:
                    merged = join(merged, in_facts[s])
            else:
                merged = set(boundary)
            out_facts[n] = merged
            new_in = transfer(n, merged)
            if new_in != in_facts[n]:
                in_facts[n] = new_in
                for p in preds[n]:
                    if p not in in_q:
                        work.append(p); in_q.add(p)
    return in_facts, out_facts, iters

def validator_worklist_live(nodes):
    """nodes: list of (id, succs, use, def_)."""
    ids = [n[0] for n in nodes]
    succs = {n[0]: list(n[1]) for n in nodes}
    preds = defaultdict(list)
    for i, ss in succs.items():
        for s in ss:
            preds[s].append(i)
    preds = {i: preds[i] for i in ids}
    use = {n[0]: set(n[2]) for n in nodes}
    dfn = {n[0]: set(n[3]) for n in nodes}

    def transfer(n, out_set):
        return (out_set - dfn[n]) | use[n]
    join = lambda a, b: a | b
    in_f, out_f, iters = _worklist("backward", transfer, join, set(), set(), ids, succs, preds)
    return {
        "in_facts": {i: sorted(in_f[i]) for i in ids},
        "out_facts": {i: sorted(out_f[i]) for i in ids},
        "iterations": iters,
    }

def validator_worklist_reaching(nodes):
    """nodes: list of (id, succs, gen, kill)."""
    ids = [n[0] for n in nodes]
    succs = {n[0]: list(n[1]) for n in nodes}
    preds = defaultdict(list)
    for i, ss in succs.items():
        for s in ss:
            preds[s].append(i)
    preds = {i: preds[i] for i in ids}
    gen = {n[0]: set(n[2]) for n in nodes}
    kill = {n[0]: set(n[3]) for n in nodes}

    def transfer(n, in_set):
        return gen[n] | (in_set - kill[n])
    join = lambda a, b: a | b
    in_f, out_f, iters = _worklist("forward", transfer, join, set(), set(), ids, succs, preds)
    return {
        "in_facts": {i: sorted(in_f[i]) for i in ids},
        "out_facts": {i: sorted(out_f[i]) for i in ids},
        "iterations": iters,
    }

# ============================================================
# ChainBuilder validity — given RD result + uses, every produced
# (def_site, use_site) edge must have a def-clear path.
# Input: cfg succs, defs_per_node {bb: [(var,def_id)]}, uses_per_node {bb: [var]}
# Output: list of [def_id, use_bb, var]  for chains that are valid.
# ============================================================
def validator_build_du_chains(succs, defs_per_node, uses_per_node):
    # nodes
    ids = list(succs.keys())
    # build kill sets per node (defs of same var)
    var_to_defs = defaultdict(set)
    for bb, ds in defs_per_node.items():
        for var, d_id in ds:
            var_to_defs[var].add(d_id)
    gen = {bb: {d for _, d in ds} for bb, ds in defs_per_node.items()}
    kill = {bb: set() for bb in ids}
    for bb, ds in defs_per_node.items():
        local_vars = {v for v, _ in ds}
        for v in local_vars:
            kill[bb] |= var_to_defs[v] - gen[bb]

    rd_in = {i: set() for i in ids}
    rd_out = {i: set() for i in ids}
    preds = defaultdict(list)
    for bb, ss in succs.items():
        for s in ss:
            preds[s].append(bb)
    changed = True
    iters = 0
    while changed and iters < 10000:
        changed = False; iters += 1
        for bb in ids:
            new_in = set()
            for p in preds[bb]:
                new_in |= rd_out[p]
            new_out = gen.get(bb, set()) | (new_in - kill.get(bb, set()))
            if new_in != rd_in[bb] or new_out != rd_out[bb]:
                rd_in[bb] = new_in; rd_out[bb] = new_out; changed = True

    # def_id -> (def_bb, var)
    def_meta = {}
    for bb, ds in defs_per_node.items():
        for var, d_id in ds:
            def_meta[d_id] = (bb, var)

    chains = []
    for bb, uses in uses_per_node.items():
        for var in uses:
            for d_id in rd_in[bb]:
                if def_meta[d_id][1] == var:
                    chains.append([d_id, bb, var])
    return sorted(chains)

# ============================================================
# Dispatcher
# ============================================================
DISPATCH = {
    "lattice_meet_table": lambda i: validator_lattice_meet_table(),
    "compute_liveness": lambda i: validator_compute_liveness(i["nodes"]),
    "compute_reaching_defs": lambda i: validator_compute_reaching_defs(i["nodes"]),
    "propagate_constants": lambda i: validator_propagate_constants(i["assignments"], i["uses"]),
    "compute_dominators": lambda i: validator_compute_dominators(i["n"], i["successors"], i["entry"]),
    "compute_dominators_from_edges": lambda i: validator_compute_dominators_from_edges(i["n"], i["edges"], i["entry"]),
    "compute_dominance_frontiers": lambda i: validator_compute_dominance_frontiers(i["n"], i["successors"], i["entry"]),
    "postorder": lambda i: validator_postorder(i["n"], i["successors"], i["entry"]),
    "trace_callers_backward": lambda i: validator_trace_callers_backward(i["addr"], i["hops"], i["edges"]),
    "trace_callees_forward": lambda i: validator_trace_callees_forward(i["addr"], i["hops"], i["edges"]),
    "worklist_live": lambda i: validator_worklist_live(i["nodes"]),
    "worklist_reaching": lambda i: validator_worklist_reaching(i["nodes"]),
    "build_du_chains": lambda i: validator_build_du_chains(i["succs"], i["defs_per_node"], i["uses_per_node"]),
}

def main():
    if not sys.stdin.isatty():
        try:
            payload = json.load(sys.stdin)
        except Exception:
            payload = None
        if payload and "fn" in payload:
            fn = payload["fn"]
            if fn not in DISPATCH:
                print(json.dumps({"error": f"unknown fn {fn}", "available": list(DISPATCH)}))
                return
            res = DISPATCH[fn](payload.get("input", {}))
            print(json.dumps({"fn": fn, "output": res}, default=str))
            return

    # ---- self-test ----
    # Tiny CFG:  0 -> 1 -> 2 (linear)
    # node 0: def x;  node 1: use x, def y;  node 2: use y
    liveness_nodes = [
        (0, [1], [],     ["x"]),
        (1, [2], ["x"],  ["y"]),
        (2, [],  ["y"],  []),
    ]
    live = validator_compute_liveness(liveness_nodes)

    rd_nodes = [
        (0, [1], ["x@0"],         set()),
        (1, [2], ["y@1"],         set()),
        (2, [],  set(),           set()),
    ]
    rd = validator_compute_reaching_defs(rd_nodes)

    cp = validator_propagate_constants([["x", 1], ["x", 1], ["y", 2], ["z", None]], ["x","y","z","w"])

    # Diamond CFG for dominators:  0 -> {1,2} -> 3
    succs = [[1, 2], [3], [3], []]
    dom = validator_compute_dominators(4, succs, 0)
    df = validator_compute_dominance_frontiers(4, succs, 0)
    po = validator_postorder(4, succs, 0)

    callers = validator_trace_callers_backward(10, 2, [[20,10],[30,20],[40,30]])
    callees = validator_trace_callees_forward(10, 2, [[10,20],[20,30],[30,40]])

    lm = validator_lattice_meet_table()
    wl_live = validator_worklist_live(liveness_nodes)
    wl_rd   = validator_worklist_reaching([(n[0], n[1], list(n[2]), list(n[3])) for n in rd_nodes])

    du = validator_build_du_chains(
        succs={0:[1], 1:[2], 2:[]},
        defs_per_node={0:[["x","d0"]], 1:[["x","d1"]], 2:[]},
        uses_per_node={0:[], 1:[], 2:["x"]},
    )

    print(json.dumps({
        "self_test": {
            "liveness": live,
            "reaching_defs": rd,
            "const_prop": cp,
            "dominators": dom,
            "dominance_frontiers": df,
            "postorder": po,
            "callers_backward": callers,
            "callees_forward": callees,
            "lattice_meet_table_size": len(lm),
            "worklist_live_iters": wl_live["iterations"],
            "worklist_rd_iters": wl_rd["iterations"],
            "du_chains": du,
        }
    }, indent=2, default=str))

if __name__ == "__main__":
    main()
