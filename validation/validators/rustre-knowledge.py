#!/usr/bin/env python3
"""
Standalone validator for the rustre-knowledge crate.

Reimplements the semantic ground-truth of the crate's pure Python-modelable
functions: KnowledgeGraph primitives, JSON import/export round-trip, merge
semantics, snapshot query helpers, and event-log replay.

No imports of the Rust crate. No MCP calls. Pure stdlib.
"""

import json
import sys
from copy import deepcopy


# ---------------------------------------------------------------------------
# KnowledgeGraph primitives
# ---------------------------------------------------------------------------

def _new_graph():
    return {"nodes": {}, "edges": []}


def validator_add_node(state):
    """input: { graph, node:{id,label,kind,metadata?} }"""
    g = state.get("graph") or _new_graph()
    node = state["node"]
    g["nodes"][node["id"]] = node
    return g


def validator_add_edge(state):
    """input: { graph, edge:{from,to,relation,weight?} }"""
    g = state.get("graph") or _new_graph()
    g["edges"].append(state["edge"])
    return g


def validator_node_count(graph):
    return len(graph.get("nodes", {}))


def validator_edge_count(graph):
    return len(graph.get("edges", []))


def validator_outgoing(state):
    """input: { graph, id } -> list of edges with from == id"""
    g = state["graph"]
    nid = state["id"]
    return [e for e in g["edges"] if e["from"] == nid]


def validator_incoming(state):
    g = state["graph"]
    nid = state["id"]
    return [e for e in g["edges"] if e["to"] == nid]


# ---------------------------------------------------------------------------
# Importer / Exporter
# ---------------------------------------------------------------------------

def validator_export_to_json(graph):
    """Serialize graph to canonical JSON string."""
    return json.dumps(
        {"nodes": list(graph["nodes"].values()), "edges": graph["edges"]},
        sort_keys=True,
    )


def validator_import_from_json(s):
    """Parse JSON string, return graph dict + counts."""
    data = json.loads(s)
    nodes = {}
    for n in data.get("nodes", []):
        nodes[n["id"]] = n
    edges = list(data.get("edges", []))
    return {
        "graph": {"nodes": nodes, "edges": edges},
        "nodes_imported": len(nodes),
        "edges_imported": len(edges),
    }


def validator_minimal_graph_json(state):
    """input: { nodes:[(id,label,kind),...], edges:[(from,to,relation),...] }"""
    nodes = [
        {"id": n[0], "label": n[1], "kind": n[2], "metadata": {}}
        for n in state.get("nodes", [])
    ]
    edges = [
        {"from": e[0], "to": e[1], "relation": e[2], "weight": 1.0}
        for e in state.get("edges", [])
    ]
    return json.dumps({"nodes": nodes, "edges": edges}, sort_keys=True)


def validator_filter_import(state):
    """input: { json, node_kinds?, relations? }"""
    data = json.loads(state["json"])
    kinds = set(state.get("node_kinds") or [])
    rels = set(state.get("relations") or [])
    nodes = data.get("nodes", [])
    edges = data.get("edges", [])
    if kinds:
        nodes = [n for n in nodes if n["kind"] in kinds]
    keep_ids = {n["id"] for n in nodes} if kinds else None
    if rels:
        edges = [e for e in edges if e["relation"] in rels]
    if keep_ids is not None:
        edges = [e for e in edges if e["from"] in keep_ids and e["to"] in keep_ids]
    return {
        "nodes_imported": len(nodes),
        "edges_imported": len(edges),
    }


# ---------------------------------------------------------------------------
# Merger
# ---------------------------------------------------------------------------

def validator_merge_graphs(state):
    """input: { left, right, strategy? (right_wins|left_wins) }"""
    left = state["left"]
    right = state["right"]
    strategy = state.get("strategy", "right_wins")

    merged_nodes = dict(left["nodes"])
    left_wins = 0
    right_wins = 0
    conflicts = 0
    for nid, n in right["nodes"].items():
        if nid in merged_nodes:
            conflicts += 1
            if strategy == "right_wins":
                merged_nodes[nid] = n
                right_wins += 1
            else:
                left_wins += 1
        else:
            merged_nodes[nid] = n

    merged_edges = list(left["edges"]) + list(right["edges"])

    return {
        "graph": {"nodes": merged_nodes, "edges": merged_edges},
        "node_count": len(merged_nodes),
        "edge_count": len(merged_edges),
        "conflicts": conflicts,
        "left_wins_count": left_wins,
        "right_wins_count": right_wins,
    }


def validator_merge_many(state):
    """input: { graphs:[...], strategy? }"""
    graphs = state["graphs"]
    strategy = state.get("strategy", "right_wins")
    if not graphs:
        return {"graph": _new_graph(), "node_count": 0, "edge_count": 0}
    acc = deepcopy(graphs[0])
    total_conflicts = 0
    for g in graphs[1:]:
        r = validator_merge_graphs({"left": acc, "right": g, "strategy": strategy})
        acc = r["graph"]
        total_conflicts += r["conflicts"]
    return {
        "graph": acc,
        "node_count": len(acc["nodes"]),
        "edge_count": len(acc["edges"]),
        "conflicts": total_conflicts,
    }


# ---------------------------------------------------------------------------
# Snapshot query helpers
# ---------------------------------------------------------------------------

def _snap(snapshot):
    s = snapshot or {}
    return {
        "symbols": s.get("symbols", []),
        "functions": s.get("functions", []),
        "types": s.get("types", []),
        "comments": s.get("comments", []),
        "xrefs": s.get("xrefs", []),
        "patches": s.get("patches", []),
        "bookmarks": s.get("bookmarks", []),
        "traces": s.get("traces", []),
        "tags": s.get("tags", []),
    }


def validator_find_symbol_by_addr(state):
    snap = _snap(state["snapshot"])
    addr = state["addr"]
    for s in snap["symbols"]:
        if s.get("address") == addr:
            return s
    return None


def validator_find_symbol_by_name(state):
    snap = _snap(state["snapshot"])
    name = state["name"]
    for s in snap["symbols"]:
        if s.get("name") == name:
            return s
    return None


def validator_symbols_in_range(state):
    snap = _snap(state["snapshot"])
    lo, hi = state["lo"], state["hi"]
    return [s for s in snap["symbols"] if lo <= s.get("address", -1) < hi]


def validator_find_function_by_entry(state):
    snap = _snap(state["snapshot"])
    entry = state["entry"]
    for f in snap["functions"]:
        if f.get("entry") == entry:
            return f
    return None


def validator_function_containing(state):
    snap = _snap(state["snapshot"])
    addr = state["addr"]
    for f in snap["functions"]:
        if f.get("entry", 0) <= addr < f.get("end", 0):
            return f
    return None


def validator_functions_in_range(state):
    snap = _snap(state["snapshot"])
    lo, hi = state["lo"], state["hi"]
    return [
        f for f in snap["functions"]
        if f.get("entry", 0) < hi and f.get("end", 0) > lo
    ]


def validator_find_type_by_name(state):
    snap = _snap(state["snapshot"])
    name = state["name"]
    for t in snap["types"]:
        if t.get("name") == name:
            return t
    return None


def validator_comments_at(state):
    snap = _snap(state["snapshot"])
    addr = state["addr"]
    return [c for c in snap["comments"] if c.get("address") == addr]


def validator_comments_at_scope(state):
    snap = _snap(state["snapshot"])
    addr = state["addr"]
    scope = state["scope"]
    return [
        c for c in snap["comments"]
        if c.get("address") == addr and c.get("scope") == scope
    ]


def validator_xrefs_to(state):
    snap = _snap(state["snapshot"])
    addr = state["addr"]
    return [x for x in snap["xrefs"] if x.get("to") == addr]


def validator_xrefs_from(state):
    snap = _snap(state["snapshot"])
    addr = state["addr"]
    return [x for x in snap["xrefs"] if x.get("from") == addr]


def validator_xrefs_of_kind(state):
    snap = _snap(state["snapshot"])
    kind = state["kind"]
    return [x for x in snap["xrefs"] if x.get("kind") == kind]


def validator_patches_at(state):
    snap = _snap(state["snapshot"])
    addr = state["addr"]
    return [p for p in snap["patches"] if p.get("address") == addr]


def validator_applied_patches(snapshot):
    snap = _snap(snapshot)
    return [p for p in snap["patches"] if p.get("applied") is True]


def validator_bookmarks_at(state):
    snap = _snap(state["snapshot"])
    addr = state["addr"]
    return [b for b in snap["bookmarks"] if b.get("address") == addr]


def validator_traces_in_window(state):
    snap = _snap(state["snapshot"])
    lo, hi = state["lo"], state["hi"]
    return [t for t in snap["traces"] if lo <= t.get("timestamp", -1) < hi]


def validator_traces_at(state):
    snap = _snap(state["snapshot"])
    addr = state["addr"]
    return [t for t in snap["traces"] if t.get("address") == addr]


def validator_tags_for(state):
    snap = _snap(state["snapshot"])
    eid = state["entity_id"]
    return [t for t in snap["tags"] if t.get("entity_id") == eid]


def validator_tags_with_key(state):
    snap = _snap(state["snapshot"])
    key = state["key"]
    return [t for t in snap["tags"] if t.get("key") == key]


def validator_count(state):
    snap = _snap(state["snapshot"])
    kind = state["kind"]
    mapping = {
        "Symbol": "symbols", "Function": "functions", "TypeDef": "types",
        "Comment": "comments", "Xref": "xrefs", "Patch": "patches",
        "Bookmark": "bookmarks", "Trace": "traces", "Tag": "tags",
    }
    return len(snap.get(mapping.get(kind, ""), []))


# ---------------------------------------------------------------------------
# Event log replay
# ---------------------------------------------------------------------------

def _apply_event(snap, ev):
    payload = ev.get("payload", {})
    op = payload.get("op")  # "upsert" | "remove"
    kind = payload.get("kind")
    entity = payload.get("entity")
    mapping = {
        "Symbol": ("symbols", "id"), "Function": ("functions", "id"),
        "TypeDef": ("types", "id"), "Comment": ("comments", "id"),
        "Xref": ("xrefs", "id"), "Patch": ("patches", "id"),
        "Bookmark": ("bookmarks", "id"), "Trace": ("traces", "id"),
        "Tag": ("tags", "id"),
    }
    if kind not in mapping:
        return snap
    bucket, key = mapping[kind]
    lst = snap.setdefault(bucket, [])
    if op == "upsert":
        for i, e in enumerate(lst):
            if e.get(key) == entity.get(key):
                lst[i] = entity
                return snap
        lst.append(entity)
    elif op == "remove":
        snap[bucket] = [e for e in lst if e.get(key) != entity.get(key)]
    return snap


def validator_replay(state):
    """input: { events: [ {seq,author,payload}, ... ], up_to? }"""
    events = sorted(state["events"], key=lambda e: e.get("seq", 0))
    up_to = state.get("up_to")
    snap = _snap({})
    for ev in events:
        if up_to is not None and ev.get("seq", 0) > up_to:
            break
        _apply_event(snap, ev)
    return snap


# ---------------------------------------------------------------------------
# Self-test main
# ---------------------------------------------------------------------------

def main():
    if not sys.stdin.isatty():
        data = sys.stdin.read().strip()
        if data:
            req = json.loads(data)
            fn = globals().get(f"validator_{req['function']}")
            if not fn:
                print(json.dumps({"error": f"unknown function {req['function']}"}))
                return
            print(json.dumps({"result": fn(req.get("input"))}, default=str))
            return

    # Built-in self-test
    results = {}

    # Graph primitives
    g = _new_graph()
    g = validator_add_node({"graph": g, "node": {"id": "a", "label": "A", "kind": "fn"}})
    g = validator_add_node({"graph": g, "node": {"id": "b", "label": "B", "kind": "fn"}})
    g = validator_add_edge({"graph": g, "edge": {"from": "a", "to": "b", "relation": "calls"}})
    g = validator_add_edge({"graph": g, "edge": {"from": "a", "to": "b", "relation": "refs"}})
    results["node_count"] = validator_node_count(g)
    results["edge_count"] = validator_edge_count(g)
    results["outgoing_a"] = len(validator_outgoing({"graph": g, "id": "a"}))
    results["incoming_b"] = len(validator_incoming({"graph": g, "id": "b"}))

    # Round-trip
    j = validator_export_to_json(g)
    imp = validator_import_from_json(j)
    results["roundtrip_nodes"] = imp["nodes_imported"]
    results["roundtrip_edges"] = imp["edges_imported"]

    # Merge
    g2 = _new_graph()
    g2 = validator_add_node({"graph": g2, "node": {"id": "b", "label": "B2", "kind": "fn"}})
    g2 = validator_add_node({"graph": g2, "node": {"id": "c", "label": "C", "kind": "fn"}})
    m = validator_merge_graphs({"left": g, "right": g2, "strategy": "right_wins"})
    results["merge_node_count"] = m["node_count"]
    results["merge_conflicts"] = m["conflicts"]
    results["merge_right_wins"] = m["right_wins_count"]

    # Snapshot queries
    snap = {
        "symbols": [{"id": 1, "name": "main", "address": 0x1000}],
        "functions": [{"id": 1, "entry": 0x1000, "end": 0x1100}],
        "xrefs": [{"id": 1, "from": 0x1020, "to": 0x1100, "kind": "Call"}],
    }
    results["find_sym_addr"] = validator_find_symbol_by_addr({"snapshot": snap, "addr": 0x1000}) is not None
    results["fn_containing"] = validator_function_containing({"snapshot": snap, "addr": 0x1050}) is not None
    results["count_symbols"] = validator_count({"snapshot": snap, "kind": "Symbol"})

    # Replay
    events = [
        {"seq": 1, "author": "t", "payload": {"op": "upsert", "kind": "Symbol",
                                              "entity": {"id": 1, "name": "a", "address": 0x10}}},
        {"seq": 2, "author": "t", "payload": {"op": "upsert", "kind": "Symbol",
                                              "entity": {"id": 2, "name": "b", "address": 0x20}}},
        {"seq": 3, "author": "t", "payload": {"op": "remove", "kind": "Symbol",
                                              "entity": {"id": 1}}},
    ]
    rs = validator_replay({"events": events})
    results["replay_symbol_count"] = len(rs["symbols"])

    print(json.dumps(results, indent=2))


if __name__ == "__main__":
    main()
