"""Independent validator for rustre-analysis-cfg.

Implements ground-truth CFG analysis in pure Python (stdlib + optional networkx)
for cross-checking the Rust crate's behavior. No imports of the Rust crate, no
MCP calls. Each validator_<name>(input) -> output mirrors a public function.

Input format for each validator_*:
    cfg = {
        "entry": <node id>,
        "blocks": [<node id>, ...],
        "edges": [[from, to, "kind"], ...]   # kind optional
    }
"""
from __future__ import annotations

import json
import struct
import subprocess
import sys
from collections import defaultdict, deque
from typing import Any, Dict, List, Optional, Set, Tuple


def _ensure(pkg: str, mod: Optional[str] = None) -> None:
    mod = mod or pkg
    try:
        __import__(mod)
    except ImportError:
        subprocess.check_call(
            [sys.executable, "-m", "pip", "install", "--quiet", pkg]
        )


# ---------- Graph helpers ----------

def _succ(cfg) -> Dict[Any, List[Any]]:
    s = defaultdict(list)
    for e in cfg["edges"]:
        s[e[0]].append(e[1])
    for b in cfg["blocks"]:
        s.setdefault(b, [])
    return s


def _pred(cfg) -> Dict[Any, List[Any]]:
    p = defaultdict(list)
    for e in cfg["edges"]:
        p[e[1]].append(e[0])
    for b in cfg["blocks"]:
        p.setdefault(b, [])
    return p


def _post_order(cfg) -> List[Any]:
    succ = _succ(cfg)
    seen, out = set(), []

    def dfs(n):
        if n in seen:
            return
        seen.add(n)
        for s in succ[n]:
            dfs(s)
        out.append(n)

    dfs(cfg["entry"])
    return out


def validator_reverse_post_order(cfg) -> List[Any]:
    po = _post_order(cfg)
    return list(reversed(po))


def validator_post_order(cfg) -> List[Any]:
    return _post_order(cfg)


def validator_reachable_from(cfg, start=None) -> List[Any]:
    succ = _succ(cfg)
    start = start if start is not None else cfg["entry"]
    seen, stk = set(), [start]
    while stk:
        n = stk.pop()
        if n in seen:
            continue
        seen.add(n)
        stk.extend(succ[n])
    return sorted(seen, key=lambda x: str(x))


# ---------- Dominators (Cooper-Harvey-Kennedy) ----------

def validator_dominator_tree(cfg) -> Dict[str, Any]:
    """Returns {idom: {node: idom_or_None}, children, frontiers}."""
    entry = cfg["entry"]
    pred = _pred(cfg)
    rpo = validator_reverse_post_order(cfg)
    rpo_index = {n: i for i, n in enumerate(rpo)}

    idom: Dict[Any, Optional[Any]] = {n: None for n in rpo}
    idom[entry] = entry

    def intersect(b1, b2):
        f1, f2 = b1, b2
        while f1 != f2:
            while rpo_index[f1] > rpo_index[f2]:
                f1 = idom[f1]
            while rpo_index[f2] > rpo_index[f1]:
                f2 = idom[f2]
        return f1

    changed = True
    while changed:
        changed = False
        for b in rpo:
            if b == entry:
                continue
            processed_preds = [p for p in pred[b] if idom.get(p) is not None]
            if not processed_preds:
                continue
            new_idom = processed_preds[0]
            for p in processed_preds[1:]:
                new_idom = intersect(p, new_idom)
            if idom[b] != new_idom:
                idom[b] = new_idom
                changed = True

    # normalize entry's idom to None
    idom_out = {n: (None if n == entry or idom[n] == n and n == entry else idom[n]) for n in rpo}
    idom_out[entry] = None

    children: Dict[Any, List[Any]] = defaultdict(list)
    for n, d in idom_out.items():
        if d is not None:
            children[d].append(n)

    # Dominance frontiers
    frontiers: Dict[Any, Set[Any]] = defaultdict(set)
    for b in rpo:
        if len(pred[b]) >= 2:
            for p in pred[b]:
                runner = p
                while runner is not None and runner != idom_out[b] and runner != b:
                    frontiers[runner].add(b)
                    runner = idom_out[runner]

    return {
        "idom": {str(k): (None if v is None else str(v)) for k, v in idom_out.items()},
        "children": {str(k): [str(x) for x in v] for k, v in children.items()},
        "frontiers": {str(k): sorted(str(x) for x in v) for k, v in frontiers.items()},
    }


def _idom_map(cfg) -> Dict[Any, Optional[Any]]:
    dt = validator_dominator_tree(cfg)
    return {k: v for k, v in dt["idom"].items()}


def validator_dominates(cfg, a, b) -> bool:
    idom = _idom_map(cfg)
    a, b = str(a), str(b)
    cur = b
    while cur is not None:
        if cur == a:
            return True
        cur = idom.get(cur)
    return False


# ---------- Post-dominators (reverse CFG with virtual exit) ----------

def validator_post_dominator_tree(cfg) -> Dict[str, Any]:
    succ = _succ(cfg)
    exits = [b for b in cfg["blocks"] if not succ[b]]
    virtual_exit = "__EXIT__"
    rev_cfg = {
        "entry": virtual_exit,
        "blocks": cfg["blocks"] + [virtual_exit],
        "edges": [[e[1], e[0]] for e in cfg["edges"]] + [[virtual_exit, x] for x in exits],
    }
    return validator_dominator_tree(rev_cfg)


def validator_post_dominates(cfg, a, b) -> bool:
    pdt = validator_post_dominator_tree(cfg)
    idom = pdt["idom"]
    a, b = str(a), str(b)
    cur = b
    while cur is not None:
        if cur == a:
            return True
        cur = idom.get(cur)
    return False


# ---------- Back edges, natural loops, reducibility ----------

def validator_find_back_edges(cfg) -> List[List[Any]]:
    out = []
    for e in cfg["edges"]:
        src, dst = e[0], e[1]
        if validator_dominates(cfg, dst, src):
            out.append([src, dst])
    return out


def validator_is_reducible(cfg) -> bool:
    # Reducible iff every retreating edge (target in dfs ancestor chain) is a back-edge
    # i.e. all retreating edges have their target dominating source.
    succ = _succ(cfg)
    color = {n: 0 for n in cfg["blocks"]}  # 0=white,1=gray,2=black
    retreating = []

    def dfs(n):
        color[n] = 1
        for s in succ[n]:
            if color[s] == 1:
                retreating.append((n, s))
            elif color[s] == 0:
                dfs(s)
        color[n] = 2

    dfs(cfg["entry"])
    for src, dst in retreating:
        if not validator_dominates(cfg, dst, src):
            return False
    return True


def validator_find_natural_loops(cfg) -> List[Dict[str, Any]]:
    back = validator_find_back_edges(cfg)
    pred = _pred(cfg)
    loops = []
    for src, header in back:
        body = {header, src}
        stack = [src]
        while stack:
            n = stack.pop()
            for p in pred[n]:
                if p not in body:
                    body.add(p)
                    stack.append(p)
        succ = _succ(cfg)
        exits = sorted({s for b in body for s in succ[b] if s not in body}, key=str)
        loops.append({
            "header": str(header),
            "back_edge_src": str(src),
            "body": sorted(str(x) for x in body),
            "exits": [str(x) for x in exits],
        })
    # mark innermost
    bodies = [set(l["body"]) for l in loops]
    for i, l in enumerate(loops):
        bi = bodies[i]
        l["is_innermost"] = not any(i != j and bodies[j] < bi for j in range(len(loops)))
    return loops


# ---------- Cyclomatic complexity ----------

def validator_cyclomatic_complexity(cfg) -> int:
    # McCabe: E - N + 2P (P = connected components reachable from entry => 1)
    n = len(cfg["blocks"])
    e = len(cfg["edges"])
    return e - n + 2


# ---------- CfgStats ----------

def validator_cfg_stats(cfg) -> Dict[str, Any]:
    succ = _succ(cfg)
    pred = _pred(cfg)
    loops = validator_find_natural_loops(cfg)
    # loop depth: count nesting
    bodies = [set(l["body"]) for l in loops]
    max_depth = 0
    for b in cfg["blocks"]:
        depth = sum(1 for body in bodies if str(b) in body)
        if depth > max_depth:
            max_depth = depth
    return {
        "node_count": len(cfg["blocks"]),
        "block_count": len(cfg["blocks"]),
        "edge_count": len(cfg["edges"]),
        "loop_count": len(loops),
        "max_loop_depth": max_depth,
        "cyclomatic_complexity": validator_cyclomatic_complexity(cfg),
        "entry_blocks": [str(b) for b in cfg["blocks"] if not pred[b]],
        "exit_blocks": [str(b) for b in cfg["blocks"] if not succ[b]],
    }


def validator_is_complex(cfg) -> bool:
    return validator_cyclomatic_complexity(cfg) > 10


# ---------- DOT serialization ----------

def validator_cfg_to_dot(cfg) -> str:
    lines = ["digraph cfg {"]
    for b in cfg["blocks"]:
        lines.append(f'  "{b}" [label="{b}"];')
    for e in cfg["edges"]:
        kind = e[2] if len(e) > 2 else "Unconditional"
        lines.append(f'  "{e[0]}" -> "{e[1]}" [label="{kind}"];')
    lines.append("}")
    return "\n".join(lines)


# ---------- to_petgraph (node/edge counts) ----------

def validator_to_petgraph_counts(cfg) -> Dict[str, int]:
    return {"node_count": len(cfg["blocks"]), "edge_count": len(cfg["edges"])}


# ---------- Lengauer-Tarjan (independent impl, must agree with CHK) ----------

def validator_compute_lt(cfg) -> Dict[str, Optional[str]]:
    """Independent Lengauer-Tarjan; output must match validator_dominator_tree.idom."""
    entry = cfg["entry"]
    succ = _succ(cfg)
    pred = _pred(cfg)

    parent: Dict[Any, Any] = {}
    semi: Dict[Any, int] = {}
    vertex: List[Any] = []
    dfnum: Dict[Any, int] = {}
    ancestor: Dict[Any, Optional[Any]] = {}
    best: Dict[Any, Any] = {}
    idom: Dict[Any, Optional[Any]] = {}
    samedom: Dict[Any, Optional[Any]] = {}
    bucket: Dict[Any, Set[Any]] = defaultdict(set)

    # iterative DFS
    n = 0
    stack = [(entry, None, iter(succ[entry]))]
    parent[entry] = None
    semi[entry] = n
    dfnum[entry] = n
    vertex.append(entry)
    ancestor[entry] = None
    best[entry] = entry
    n += 1

    visiting = {entry}
    # simulate recursive
    work = [(entry, iter(succ[entry]))]
    while work:
        node, it = work[-1]
        try:
            child = next(it)
            if child not in visiting:
                visiting.add(child)
                parent[child] = node
                semi[child] = n
                dfnum[child] = n
                vertex.append(child)
                ancestor[child] = None
                best[child] = child
                n += 1
                work.append((child, iter(succ[child])))
        except StopIteration:
            work.pop()

    def eval_(v):
        if ancestor[v] is None:
            return v
        # path compression
        path = []
        u = v
        while ancestor[u] is not None:
            path.append(u)
            u = ancestor[u]
        # u is root
        for x in reversed(path):
            a = ancestor[x]
            if a is not None and semi[best[a]] < semi[best[x]]:
                best[x] = best[a]
            if ancestor[a] is not None:
                ancestor[x] = ancestor[a]
        return best[v]

    for i in range(len(vertex) - 1, 0, -1):
        w = vertex[i]
        p = parent[w]
        for v in pred[w]:
            if v not in dfnum:
                continue
            u = eval_(v)
            if semi[u] < semi[w]:
                semi[w] = semi[u]
        bucket[vertex[semi[w]]].add(w)
        ancestor[w] = p
        best[w] = w
        for v in list(bucket[p]):
            bucket[p].discard(v)
            u = eval_(v)
            if semi[u] < semi[v]:
                samedom[v] = u
            else:
                idom[v] = p

    for i in range(1, len(vertex)):
        w = vertex[i]
        if samedom.get(w) is not None:
            idom[w] = idom[samedom[w]]

    idom[entry] = None
    # only include reachable nodes
    return {str(w): (None if idom.get(w) is None else str(idom[w])) for w in vertex}


# ---------- Jump table decoders ----------

def validator_decode_absolute_table(data: bytes, base_offset: int, count: int, entry_size: int) -> List[int]:
    fmt = {4: "<I", 8: "<Q"}[entry_size]
    out = []
    for i in range(count):
        off = base_offset + i * entry_size
        out.append(struct.unpack_from(fmt, data, off)[0])
    return out


def validator_decode_relative_table(data: bytes, base_offset: int, base_addr: int, count: int, entry_size: int) -> List[int]:
    sfmt = {4: "<i", 8: "<q"}[entry_size]
    out = []
    for i in range(count):
        off = base_offset + i * entry_size
        rel = struct.unpack_from(sfmt, data, off)[0]
        out.append(base_addr + rel)
    return out


# ---------- try_analyze_cfg semantics ----------

def validator_try_analyze_cfg(instrs: List[Any]) -> Dict[str, Any]:
    if not instrs:
        return {"error": "EmptyCfg"}
    # Synthetic: 1 block per "leader". Caller normally pre-builds CFG; here we
    # only validate the empty-input contract.
    return {"ok": True, "block_count": 1, "edge_count": 0}


# ---------- Dispatcher ----------

VALIDATORS = {
    "reverse_post_order": validator_reverse_post_order,
    "post_order": validator_post_order,
    "reachable_from": validator_reachable_from,
    "dominator_tree": validator_dominator_tree,
    "dominates": validator_dominates,
    "post_dominator_tree": validator_post_dominator_tree,
    "post_dominates": validator_post_dominates,
    "find_back_edges": validator_find_back_edges,
    "is_reducible": validator_is_reducible,
    "find_natural_loops": validator_find_natural_loops,
    "cyclomatic_complexity": validator_cyclomatic_complexity,
    "cfg_stats": validator_cfg_stats,
    "is_complex": validator_is_complex,
    "cfg_to_dot": validator_cfg_to_dot,
    "to_petgraph_counts": validator_to_petgraph_counts,
    "compute_lt": validator_compute_lt,
    "decode_absolute_table": validator_decode_absolute_table,
    "decode_relative_table": validator_decode_relative_table,
    "try_analyze_cfg": validator_try_analyze_cfg,
}


def main():
    # Diamond CFG: A -> B,C ; B,C -> D
    diamond = {
        "entry": "A",
        "blocks": ["A", "B", "C", "D"],
        "edges": [["A", "B", "True"], ["A", "C", "False"], ["B", "D", "Unconditional"], ["C", "D", "Unconditional"]],
    }
    # while loop: A -> B ; B -> C,D ; C -> B
    loop = {
        "entry": "A",
        "blocks": ["A", "B", "C", "D"],
        "edges": [["A", "B"], ["B", "C", "True"], ["B", "D", "False"], ["C", "B"]],
    }

    if not sys.stdin.isatty():
        try:
            payload = json.load(sys.stdin)
            fn = VALIDATORS[payload["function"]]
            args = payload.get("args", [])
            kwargs = payload.get("kwargs", {})
            result = fn(*args, **kwargs)
            print(json.dumps({"ok": True, "result": result}, default=str))
            return
        except Exception as e:
            print(json.dumps({"ok": False, "error": str(e)}))
            return

    # Fixed self-test
    report = {
        "diamond_stats": validator_cfg_stats(diamond),
        "diamond_dom": validator_dominator_tree(diamond),
        "diamond_lt": validator_compute_lt(diamond),
        "diamond_reducible": validator_is_reducible(diamond),
        "loop_stats": validator_cfg_stats(loop),
        "loop_back_edges": validator_find_back_edges(loop),
        "loop_natural_loops": validator_find_natural_loops(loop),
        "loop_cyclomatic": validator_cyclomatic_complexity(loop),
        "abs_table_roundtrip": validator_decode_absolute_table(
            struct.pack("<III", 0x1000, 0x2000, 0x3000), 0, 3, 4
        ),
        "empty_try": validator_try_analyze_cfg([]),
    }
    # sanity: CHK and LT must agree
    chk = report["diamond_dom"]["idom"]
    lt = report["diamond_lt"]
    report["chk_lt_agree"] = chk == lt
    print(json.dumps(report, indent=2, default=str))


if __name__ == "__main__":
    main()
