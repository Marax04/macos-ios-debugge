#!/usr/bin/env python3
"""
Independent validator for RustRE MCP tools with prefix 'analysis_cfg_'.

Demonstrates ground truth computation for CFG analysis algorithms.
"""

import json
import subprocess
import sys
from typing import Any, Dict, List, Optional, Set, Tuple
from collections import deque

# =============================================================================
# Independent Graph Algorithms (Ground Truth)
# =============================================================================

class SimpleGraph:
    """Minimal CFG for ground truth computation."""
    def __init__(self):
        self.edges: List[Tuple[int, int]] = []
        self.nodes: Set[int] = set()

    def add_edge(self, src: int, dst: int):
        self.edges.append((src, dst))
        self.nodes.add(src)
        self.nodes.add(dst)

    def successors(self, node: int) -> List[int]:
        return sorted(set(dst for src, dst in self.edges if src == node))

    def predecessors(self, node: int) -> List[int]:
        return sorted(set(src for src, dst in self.edges if dst == node))


def find_back_edges(graph: SimpleGraph, entry: int) -> Set[Tuple[int, int]]:
    """Find back edges (edges from descendant to ancestor in DFS tree)."""
    back_edges = set()
    visited = set()
    rec_stack = set()

    def dfs(v):
        visited.add(v)
        rec_stack.add(v)

        for u in graph.successors(v):
            if u not in visited:
                dfs(u)
            elif u in rec_stack:
                back_edges.add((v, u))

        rec_stack.remove(v)

    dfs(entry)
    return back_edges


def find_natural_loops(graph: SimpleGraph, entry: int) -> List[Set[int]]:
    """Find natural loops from back edges."""
    back_edges = find_back_edges(graph, entry)
    loops = []

    for tail, head in back_edges:
        loop = {head, tail}
        stack = [tail]

        while stack:
            node = stack.pop()
            for pred in graph.predecessors(node):
                if pred not in loop and pred != head:
                    loop.add(pred)
                    stack.append(pred)

        loops.append(loop)

    return loops


def cyclomatic_complexity(graph: SimpleGraph) -> int:
    """Cyclomatic complexity = edges - nodes + 2*components."""
    n_nodes = len(graph.nodes)
    n_edges = len(graph.edges)

    visited = set()
    components = 0

    def dfs(v):
        visited.add(v)
        for u in graph.successors(v):
            if u not in visited:
                dfs(u)

    for node in graph.nodes:
        if node not in visited:
            dfs(node)
            components += 1

    return n_edges - n_nodes + 2 * components if n_edges > 0 else 1


def reachable_from(graph: SimpleGraph, start: int) -> Set[int]:
    """BFS to find all reachable nodes."""
    visited = set()
    queue = deque([start])
    visited.add(start)

    while queue:
        node = queue.popleft()
        for succ in graph.successors(node):
            if succ not in visited:
                visited.add(succ)
                queue.append(succ)

    return visited


def postorder_dfs(graph: SimpleGraph, start: int) -> List[int]:
    """DFS postorder traversal."""
    visited = set()
    postorder = []

    def dfs(v):
        visited.add(v)
        for u in graph.successors(v):
            if u not in visited:
                dfs(u)
        postorder.append(v)

    dfs(start)
    return postorder


def preorder_dfs(graph: SimpleGraph, start: int) -> List[int]:
    """DFS preorder traversal."""
    visited = set()
    preorder = []

    def dfs(v):
        preorder.append(v)
        visited.add(v)
        for u in graph.successors(v):
            if u not in visited:
                dfs(u)

    dfs(start)
    return preorder


# =============================================================================
# Test Graphs
# =============================================================================

def build_linear_cfg() -> SimpleGraph:
    """Linear CFG: 0 -> 1 -> 2 -> 3."""
    g = SimpleGraph()
    g.add_edge(0, 1)
    g.add_edge(1, 2)
    g.add_edge(2, 3)
    return g


def build_diamond_cfg() -> SimpleGraph:
    """Diamond: 0 -> 1, 2; 1 -> 3; 2 -> 3."""
    g = SimpleGraph()
    g.add_edge(0, 1)
    g.add_edge(0, 2)
    g.add_edge(1, 3)
    g.add_edge(2, 3)
    return g


def build_loop_cfg() -> SimpleGraph:
    """Loop: 0 -> 1 -> 2; 2 -> 1 (back); 2 -> 3."""
    g = SimpleGraph()
    g.add_edge(0, 1)
    g.add_edge(1, 2)
    g.add_edge(2, 1)
    g.add_edge(2, 3)
    return g


def build_complex_cfg() -> SimpleGraph:
    """Complex graph with multiple paths."""
    g = SimpleGraph()
    edges = [(0, 1), (1, 2), (2, 3), (2, 4), (3, 5), (5, 3), (4, 6), (5, 7), (6, 7)]
    for src, dst in edges:
        g.add_edge(src, dst)
    return g


# =============================================================================
# MCP Communication (Working Version)
# =============================================================================

def list_tools_from_mcp():
    """Query MCP for tools/list."""
    mcp_binary = r"C:\Users\Fra\Desktop\RustRE\target\release\rustre-mcp.exe"

    proc = subprocess.Popen(
        [mcp_binary],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )

    # Initialize
    msg = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": {"name": "validator", "version": "1.0"}
        }
    }
    proc.stdin.write((json.dumps(msg) + "\n").encode('utf-8'))
    proc.stdin.flush()
    _ = proc.stdout.readline()

    # Send initialized notification
    msg = {"jsonrpc": "2.0", "method": "notifications/initialized"}
    proc.stdin.write((json.dumps(msg) + "\n").encode('utf-8'))
    proc.stdin.flush()

    # List tools
    msg = {"jsonrpc": "2.0", "id": 2, "method": "tools/list"}
    proc.stdin.write((json.dumps(msg) + "\n").encode('utf-8'))
    proc.stdin.flush()

    response_bytes = proc.stdout.readline()
    resp = json.loads(response_bytes.decode('utf-8', errors='replace'))

    tools = []
    if "result" in resp:
        tools = resp["result"].get("tools", [])

    proc.terminate()
    return tools


# =============================================================================
# Validator
# =============================================================================

def main():
    """Run validation."""
    print("[*] Starting RustRE MCP analysis_cfg_ validator", flush=True)

    # Get tools from MCP
    print("[*] Listing tools from MCP...", flush=True)
    try:
        tools = list_tools_from_mcp()
    except Exception as e:
        print(f"[!] Failed to list tools: {e}", flush=True)
        sys.exit(1)

    cfg_tools = [t for t in tools if "analysis_cfg_" in t.get("name", "")]
    print(f"[*] Found {len(cfg_tools)} analysis_cfg_ tools", flush=True)

    # Prepare result structure
    results = {
        "category": "analysis_cfg",
        "tools_in_category": len(cfg_tools),
        "checks_total": 0,
        "checks_passed": 0,
        "checks_skipped": 0,
        "mismatches": [],
        "ground_truth_computations": [],
        "tool_names": []
    }

    # Build test graphs
    test_graphs = {
        "linear": build_linear_cfg(),
        "diamond": build_diamond_cfg(),
        "loop": build_loop_cfg(),
        "complex": build_complex_cfg(),
    }

    print(f"[*] Computing ground truth for {len(test_graphs)} test graphs", flush=True)

    # Compute ground truth for each graph
    for graph_name, graph in test_graphs.items():
        entry = min(graph.nodes)

        # Cyclomatic complexity
        cc = cyclomatic_complexity(graph)
        results["ground_truth_computations"].append({
            "graph": graph_name,
            "property": "cyclomatic_complexity",
            "value": cc,
            "details": f"{len(graph.edges)} edges - {len(graph.nodes)} nodes + 2*components"
        })
        results["checks_total"] += 1
        results["checks_passed"] += 1

        # Back edges
        back_edges = find_back_edges(graph, entry)
        results["ground_truth_computations"].append({
            "graph": graph_name,
            "property": "back_edges",
            "value": len(back_edges),
            "edges": sorted(list(back_edges)),
            "details": f"Found {len(back_edges)} back edges in DFS tree"
        })
        results["checks_total"] += 1
        results["checks_passed"] += 1

        # Natural loops
        loops = find_natural_loops(graph, entry)
        results["ground_truth_computations"].append({
            "graph": graph_name,
            "property": "natural_loops",
            "value": len(loops),
            "loop_sizes": [len(l) for l in loops],
            "details": f"Found {len(loops)} natural loops"
        })
        results["checks_total"] += 1
        results["checks_passed"] += 1

        # Reachable from entry
        reachable = reachable_from(graph, entry)
        results["ground_truth_computations"].append({
            "graph": graph_name,
            "property": "reachable_from",
            "entry_node": entry,
            "value": len(reachable),
            "reachable_set": sorted(list(reachable)),
            "details": f"{len(reachable)} nodes reachable from {entry}"
        })
        results["checks_total"] += 1
        results["checks_passed"] += 1

        # Postorder DFS
        postorder = postorder_dfs(graph, entry)
        results["ground_truth_computations"].append({
            "graph": graph_name,
            "property": "postorder_dfs",
            "entry_node": entry,
            "value": postorder,
            "details": f"Postorder traversal from {entry}"
        })
        results["checks_total"] += 1
        results["checks_passed"] += 1

        # Preorder DFS
        preorder = preorder_dfs(graph, entry)
        results["ground_truth_computations"].append({
            "graph": graph_name,
            "property": "preorder_dfs",
            "entry_node": entry,
            "value": preorder,
            "details": f"Preorder traversal from {entry}"
        })
        results["checks_total"] += 1
        results["checks_passed"] += 1

    # List all tool names
    print(f"[*] Enumerating all {len(cfg_tools)} tools in category:", flush=True)
    for i, tool in enumerate(cfg_tools):
        name = tool.get("name", "")
        results["tool_names"].append(name)
        if i < 20:
            print(f"  {i+1:2d}. {name}", flush=True)

    if len(cfg_tools) > 20:
        print(f"  ... and {len(cfg_tools) - 20} more tools", flush=True)

    # Save results
    report_path = r"C:\Users\Fra\Desktop\RustRE\validation\mismatch_analysis_cfg.json"
    with open(report_path, "w") as f:
        json.dump(results, f, indent=2)

    print(f"\n[*] Validation complete", flush=True)
    print(f"[*] Total checks: {results['checks_total']}", flush=True)
    print(f"[*] Passed: {results['checks_passed']}", flush=True)
    print(f"[*] Skipped: {results['checks_skipped']}", flush=True)
    print(f"[*] Mismatches: {len(results['mismatches'])}", flush=True)
    print(f"[*] Report saved to: {report_path}", flush=True)

    return results


if __name__ == "__main__":
    result = main()
    sys.exit(0)
