#!/usr/bin/env python3
"""
Independent Python validator for rustre-decompiler-cfs.

Reimplements observable behavior of the crate's public API in pure Python
(no Rust bindings, no MCP calls) so its outputs can be cross-checked.

Covered functions (validator_<name>):
  - validator_block_id_display
  - validator_basic_block_new / with_stmts / with_successors
  - validator_structured_flatten
  - validator_structured_goto_count
  - validator_structured_node_count
  - validator_cfs_algorithm_display
  - validator_region_block_ids
  - validator_region_is_loop
  - validator_region_depth
  - validator_dom_tree_dominance_path
  - validator_dom_tree_dominates
  - validator_post_dom_tree_post_dominates
  - validator_scc_groups
  - validator_structure_cfg  (mirrors ControlFlowStructurer::structure
                              loop/goto-count semantics for canonical CFGs)

Usage:
  echo '{"fn":"scc_groups","input":{"edges":[[0,1],[1,0]]}}' | python rustre-decompiler-cfs.py
  python rustre-decompiler-cfs.py   # runs main() self-tests
"""

import json
import subprocess
import sys


# --------------------------------------------------------------------------- #
# Lazy networkx import (optional dep; used for SCC + idom ground truth).
# --------------------------------------------------------------------------- #
def _ensure(pkg, mod=None):
    mod = mod or pkg
    try:
        return __import__(mod)
    except ImportError:
        subprocess.check_call([sys.executable, "-m", "pip", "install",
                               "--quiet", pkg])
        return __import__(mod)


def _nx():
    return _ensure("networkx")


# --------------------------------------------------------------------------- #
# BlockId / BasicBlock
# --------------------------------------------------------------------------- #
def validator_block_id_display(n: int) -> str:
    return f"bb{int(n)}"


def validator_basic_block_new(bid: int) -> dict:
    return {"id": int(bid), "stmts": [], "successors": []}


def validator_basic_block_with_stmts(bid: int, stmts: list) -> dict:
    return {"id": int(bid), "stmts": list(stmts), "successors": []}


def validator_basic_block_with_successors(bid: int, succs: list) -> dict:
    return {"id": int(bid), "stmts": [], "successors": [int(s) for s in succs]}


# --------------------------------------------------------------------------- #
# StructuredNode helpers
# Node JSON shape (Serde tagged enum, matching crate `#[serde]` defaults):
#   {"BasicBlock": {...}} | {"Sequence": [..]} |
#   {"If": {cond, then}} | {"IfElse": {cond, then, else_}} |
#   {"Loop": {kind, body, cond}} | {"Switch": {disc, cases}} |
#   {"Goto": <BlockId>} | {"Break": null} | {"Continue": null} |
#   {"Return": <opt str>}
# We accept any tagging by inspecting the single key.
# --------------------------------------------------------------------------- #
def _tag(node):
    if not isinstance(node, dict) or len(node) != 1:
        return None, None
    k = next(iter(node))
    return k, node[k]


def _children(node):
    tag, payload = _tag(node)
    if tag is None:
        return []
    if tag == "Sequence":
        return list(payload)
    if tag == "If":
        return [payload["then"]]
    if tag == "IfElse":
        # accept "else" or "else_"
        e = payload.get("else_", payload.get("else"))
        return [payload["then"], e]
    if tag == "Loop":
        return [payload["body"]]
    if tag == "Switch":
        return [c["body"] for c in payload["cases"]]
    return []


def validator_structured_flatten(node):
    """Idempotent collapse of singleton Sequences."""
    tag, payload = _tag(node)
    if tag is None:
        return node
    if tag == "Sequence":
        flat = [validator_structured_flatten(c) for c in payload]
        if len(flat) == 1:
            return flat[0]
        return {"Sequence": flat}
    if tag == "If":
        return {"If": {"cond": payload["cond"],
                       "then": validator_structured_flatten(payload["then"])}}
    if tag == "IfElse":
        e_key = "else_" if "else_" in payload else "else"
        return {"IfElse": {"cond": payload["cond"],
                           "then": validator_structured_flatten(payload["then"]),
                           e_key: validator_structured_flatten(payload[e_key])}}
    if tag == "Loop":
        out = dict(payload)
        out["body"] = validator_structured_flatten(payload["body"])
        return {"Loop": out}
    if tag == "Switch":
        cases = [{"value": c.get("value"),
                  "body": validator_structured_flatten(c["body"])}
                 for c in payload["cases"]]
        return {"Switch": {"disc": payload["disc"], "cases": cases}}
    return node


def validator_structured_goto_count(node) -> int:
    tag, _ = _tag(node)
    if tag is None:
        return 0
    if tag == "Goto":
        return 1
    return sum(validator_structured_goto_count(c) for c in _children(node))


def validator_structured_node_count(node) -> int:
    tag, _ = _tag(node)
    if tag is None:
        return 0
    return 1 + sum(validator_structured_node_count(c) for c in _children(node))


# --------------------------------------------------------------------------- #
# CfsAlgorithm::Display
# --------------------------------------------------------------------------- #
def validator_cfs_algorithm_display(variant: str) -> str:
    m = {"Dream": "DREAM", "Phoenix": "Phoenix",
         "Sailr": "SAILR", "Structural": "Structural"}
    if variant not in m:
        raise ValueError(f"unknown CfsAlgorithm variant: {variant}")
    return m[variant]


# --------------------------------------------------------------------------- #
# Region helpers (operate on JSON-ish dict mirroring crate's enum)
# Shape: {"Sequence": [Region,..]} | {"IfThen":{cond,then}} |
#        {"IfThenElse":{cond,then,else}} | {"While":{...}} |
#        {"DoWhile":{...}} | {"For":{...}} | {"Switch":{cases}} |
#        {"SelfLoop": <BlockId>} | {"Block": <BlockId>}
# --------------------------------------------------------------------------- #
_LOOP_TAGS = {"While", "DoWhile", "For", "SelfLoop"}


def _region_subregions(region):
    tag, payload = _tag(region)
    if tag is None:
        return []
    if tag == "Sequence":
        return list(payload)
    if tag == "IfThen":
        return [payload["then"]]
    if tag == "IfThenElse":
        e = payload.get("else_", payload.get("else"))
        return [payload["then"], e]
    if tag in ("While", "DoWhile", "For"):
        return [payload["body"]]
    if tag == "Switch":
        return [c["body"] for c in payload["cases"]]
    return []


def validator_region_block_ids(region) -> list:
    tag, payload = _tag(region)
    if tag is None:
        return []
    if tag == "Block":
        return [int(payload)]
    if tag == "SelfLoop":
        return [int(payload)]
    out = []
    for sub in _region_subregions(region):
        out.extend(validator_region_block_ids(sub))
    return out


def validator_region_is_loop(region) -> bool:
    tag, _ = _tag(region)
    return tag in _LOOP_TAGS


def validator_region_depth(region) -> int:
    tag, _ = _tag(region)
    if tag is None or tag in ("Block",):
        return 0
    subs = _region_subregions(region)
    if not subs:
        return 1 if tag != "Block" else 0
    return 1 + max(validator_region_depth(s) for s in subs)


# --------------------------------------------------------------------------- #
# DomTree / PostDomTree (input: idom dict {node: idom_of_node})
# --------------------------------------------------------------------------- #
def validator_dom_tree_dominance_path(idom: dict, b) -> list:
    path = [b]
    seen = {b}
    cur = b
    while True:
        nxt = idom.get(cur)
        if nxt is None or nxt == cur or nxt in seen:
            break
        path.append(nxt)
        seen.add(nxt)
        cur = nxt
    return path


def validator_dom_tree_dominates(idom: dict, a, b) -> bool:
    return a in validator_dom_tree_dominance_path(idom, b)


def validator_post_dom_tree_post_dominates(ipost: dict, a, b) -> bool:
    return a in validator_dom_tree_dominance_path(ipost, b)


# --------------------------------------------------------------------------- #
# Tarjan SCC vs networkx
# --------------------------------------------------------------------------- #
def validator_scc_groups(edges: list, nodes: list = None) -> list:
    nx = _nx()
    g = nx.DiGraph()
    if nodes:
        g.add_nodes_from(nodes)
    g.add_edges_from(edges)
    sccs = [sorted(list(c)) for c in nx.strongly_connected_components(g)]
    sccs.sort()
    return sccs


# --------------------------------------------------------------------------- #
# ControlFlowStructurer::structure — observable outcome model
#
# We can't replicate DREAM exactly, but for canonical fixtures the
# observable contract is:
#   * empty CFG          -> {"err":"EmptyCfg"}
#   * unknown entry      -> {"err":"EntryNotFound"}
#   * otherwise          -> {"loop_count": <#back-edges via DFS from entry>,
#                            "reducible":  <bool: all loops reducible>}
# Reducibility check: a back-edge (u->v) is reducible iff v dominates u.
# For reducible CFGs the crate's goto_count must be 0.
# --------------------------------------------------------------------------- #
def _dfs_back_edges(adj: dict, entry):
    color = {n: 0 for n in adj}        # 0=white,1=gray,2=black
    back = []
    stack = [(entry, iter(adj.get(entry, [])))]
    color[entry] = 1
    while stack:
        node, it = stack[-1]
        nxt = next(it, None)
        if nxt is None:
            color[node] = 2
            stack.pop()
            continue
        c = color.get(nxt, 0)
        if c == 0:
            color[nxt] = 1
            stack.append((nxt, iter(adj.get(nxt, []))))
        elif c == 1:
            back.append((node, nxt))
    return back


def _immediate_dominators(adj: dict, entry):
    nx = _nx()
    g = nx.DiGraph()
    for u, vs in adj.items():
        g.add_node(u)
        for v in vs:
            g.add_edge(u, v)
    if entry not in g:
        return {}
    return nx.immediate_dominators(g, entry)


def validator_structure_cfg(blocks: list, entry) -> dict:
    """blocks: [{"id":int,"successors":[int,...]}, ...]"""
    if not blocks:
        return {"err": "EmptyCfg"}
    ids = {b["id"] for b in blocks}
    if entry not in ids:
        return {"err": "EntryNotFound"}
    adj = {b["id"]: list(b.get("successors", [])) for b in blocks}
    back = _dfs_back_edges(adj, entry)
    idom = _immediate_dominators(adj, entry)

    def dominates(a, b):
        cur = b
        seen = set()
        while cur is not None and cur not in seen:
            if cur == a:
                return True
            seen.add(cur)
            nxt = idom.get(cur)
            if nxt == cur:
                return cur == a
            cur = nxt
        return False

    reducible = all(dominates(v, u) for (u, v) in back)
    return {
        "loop_count": len(back),
        "reducible": reducible,
        "expected_goto_count_zero": reducible,
    }


# --------------------------------------------------------------------------- #
# Dispatcher / self-test
# --------------------------------------------------------------------------- #
_DISPATCH = {
    "block_id_display": lambda i: validator_block_id_display(i["n"]),
    "basic_block_new": lambda i: validator_basic_block_new(i["id"]),
    "basic_block_with_stmts":
        lambda i: validator_basic_block_with_stmts(i["id"], i["stmts"]),
    "basic_block_with_successors":
        lambda i: validator_basic_block_with_successors(i["id"], i["successors"]),
    "structured_flatten": lambda i: validator_structured_flatten(i["node"]),
    "structured_goto_count":
        lambda i: validator_structured_goto_count(i["node"]),
    "structured_node_count":
        lambda i: validator_structured_node_count(i["node"]),
    "cfs_algorithm_display":
        lambda i: validator_cfs_algorithm_display(i["variant"]),
    "region_block_ids": lambda i: validator_region_block_ids(i["region"]),
    "region_is_loop": lambda i: validator_region_is_loop(i["region"]),
    "region_depth": lambda i: validator_region_depth(i["region"]),
    "dom_tree_dominance_path":
        lambda i: validator_dom_tree_dominance_path(i["idom"], i["b"]),
    "dom_tree_dominates":
        lambda i: validator_dom_tree_dominates(i["idom"], i["a"], i["b"]),
    "post_dom_tree_post_dominates":
        lambda i: validator_post_dom_tree_post_dominates(
            i["ipost"], i["a"], i["b"]),
    "scc_groups":
        lambda i: validator_scc_groups(i["edges"], i.get("nodes")),
    "structure_cfg":
        lambda i: validator_structure_cfg(i["blocks"], i["entry"]),
}


def _self_test():
    results = {}
    # 1. BlockId display
    results["block_id_display"] = validator_block_id_display(7) == "bb7"
    # 2. flatten idempotence
    n = {"Sequence": [{"Sequence": [{"Goto": 3}]}]}
    once = validator_structured_flatten(n)
    twice = validator_structured_flatten(once)
    results["flatten_collapse"] = once == {"Goto": 3}
    results["flatten_idempotent"] = once == twice
    # 3. goto/node count
    tree = {"Sequence": [{"Goto": 1}, {"If": {"cond": "x", "then": {"Goto": 2}}}]}
    results["goto_count"] = validator_structured_goto_count(tree) == 2
    results["node_count"] = validator_structured_node_count(tree) == 4
    # 4. CfsAlgorithm display
    results["alg_dream"] = validator_cfs_algorithm_display("Dream") == "DREAM"
    results["alg_sailr"] = validator_cfs_algorithm_display("Sailr") == "SAILR"
    # 5. Region
    reg = {"Sequence": [{"Block": 0}, {"While": {"body": {"Block": 1}}}]}
    results["region_blocks"] = validator_region_block_ids(reg) == [0, 1]
    results["region_is_loop_outer"] = validator_region_is_loop(reg) is False
    results["region_is_loop_inner"] = validator_region_is_loop(
        {"While": {"body": {"Block": 1}}}) is True
    # 6. DomTree
    idom = {0: 0, 1: 0, 2: 1, 3: 1}
    results["dom_path"] = validator_dom_tree_dominance_path(idom, 3) == [3, 1, 0]
    results["dom_dominates"] = validator_dom_tree_dominates(idom, 0, 3) is True
    results["dom_not"] = validator_dom_tree_dominates(idom, 2, 3) is False
    # 7. SCC
    sccs = validator_scc_groups([[0, 1], [1, 0], [1, 2]], nodes=[0, 1, 2])
    results["scc"] = sorted(map(tuple, sccs)) == [(0, 1), (2,)]
    # 8. structure_cfg fixtures
    results["empty"] = validator_structure_cfg([], 0) == {"err": "EmptyCfg"}
    results["missing"] = validator_structure_cfg(
        [{"id": 0, "successors": []}], 99) == {"err": "EntryNotFound"}
    linear = [{"id": i, "successors": [i + 1]} for i in range(3)] + \
             [{"id": 3, "successors": []}]
    r = validator_structure_cfg(linear, 0)
    results["linear"] = r["loop_count"] == 0 and r["reducible"] is True
    while_cfg = [{"id": 0, "successors": [1]},
                 {"id": 1, "successors": [1, 2]},
                 {"id": 2, "successors": []}]
    r = validator_structure_cfg(while_cfg, 0)
    results["while"] = r["loop_count"] == 1 and r["reducible"] is True

    ok = all(results.values())
    print(json.dumps({"self_test_ok": ok, "results": results}, indent=2))
    return 0 if ok else 1


def main():
    data = sys.stdin.read().strip() if not sys.stdin.isatty() else ""
    if not data:
        return _self_test()
    req = json.loads(data)
    fn = req["fn"]
    if fn not in _DISPATCH:
        print(json.dumps({"error": f"unknown fn: {fn}"}))
        return 2
    out = _DISPATCH[fn](req.get("input", {}))
    print(json.dumps({"fn": fn, "output": out}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
