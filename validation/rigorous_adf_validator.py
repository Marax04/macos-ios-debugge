#!/usr/bin/env python3
"""
Rigorous ground-truth validation for all adf_* MCP tools.
Each tool is independently verified with a Python reference implementation
derived from the Rust source in crates/rustre-analysis-dataflow/src/lib.rs.
"""
import json
import subprocess
import sys
from collections import deque

EXE = r"C:\Users\Fra\Desktop\RustRE\target\release\rustre-mcp.exe"
TARGET = r"C:\Users\Fra\Desktop\Zyphora\target\release\cargo-zyphora.exe"
OUT_PASS = r"C:\Users\Fra\Desktop\RustRE\validation\rigorous_adf_v2.json"
OUT_SKIP = r"C:\Users\Fra\Desktop\RustRE\validation\skip_adf.json"

# ─────────────────────────────────────────────────────────────────────────────
# Python reference implementations (mirroring Rust logic exactly)
# ─────────────────────────────────────────────────────────────────────────────

def ref_lattice_meet(a, b):
    """
    LatticeValue::meet
      Top=None-sentinel; Const(x)=int; Bottom="bottom"-sentinel
    Encoding: ("top", None), ("const", x), ("bottom", None)
    """
    def unpack(v):
        return v  # already a tuple (kind, val)

    # meet(Top, x) = x; meet(x, Top) = x
    # meet(Bottom, _) = Bottom; meet(_, Bottom) = Bottom
    # meet(Const(a), Const(b)) = Const(a) if a==b else Bottom
    if a[0] == "top":
        return b
    if b[0] == "top":
        return a
    if a[0] == "bottom" or b[0] == "bottom":
        return ("bottom", None)
    # both const
    if a[1] == b[1]:
        return ("const", a[1])
    return ("bottom", None)


def ref_statement_new(id_, def_s, uses):
    """Statement::new — returns dict matching Rust JSON output."""
    return {
        "id": id_,
        "def": def_s,
        "uses": uses,
        "expr": None,
    }


def ref_statement_with_expr(id_, expr):
    """Statement::new(id, None, []).with_expr(expr)"""
    return {
        "id": id_,
        "def": None,
        "uses": [],
        "expr": expr,
    }


def ref_linear_cfg_node_count(n):
    """
    linear_cfg(n statements) -> node_count, entry, exit
    node_count == n, entry == 0, exit == max(0, n-1)
    """
    return {
        "node_count": n,
        "entry": 0,
        "exit": max(0, n - 1),
    }


def _postorder(n, succ, entry):
    """Iterative DFS postorder matching Rust's postorder()."""
    if n == 0 or entry >= n:
        return []
    visited = [False] * n
    order = []
    stack = [(entry, 0)]
    visited[entry] = True

    while stack:
        node, child_idx = stack[-1]
        children = succ[node] if node < len(succ) else []
        if child_idx < len(children):
            stack[-1] = (node, child_idx + 1)
            child = children[child_idx]
            if child < n and not visited[child]:
                visited[child] = True
                stack.append((child, 0))
        else:
            stack.pop()
            order.append(node)

    return order


def _dom_intersect(b1, b2, idom, rpo_idx):
    while b1 != b2:
        while rpo_idx[b1] > rpo_idx[b2]:
            b1 = idom[b1]
        while rpo_idx[b2] > rpo_idx[b1]:
            b2 = idom[b2]
    return b1


def ref_compute_dominators(n, successors, entry=0):
    """Mirrors compute_dominators() in Rust (Cooper et al. 2001)."""
    UNDEF = 2**63  # large sentinel
    if n == 0:
        return []
    idom = [UNDEF] * n
    idom[entry] = entry

    # build predecessors
    preds = [[] for _ in range(n)]
    for src, succs in enumerate(successors):
        for dst in succs:
            if dst < n:
                preds[dst].append(src)

    po = _postorder(n, successors, entry)
    rpo_full = list(reversed(po))

    rpo_idx = [UNDEF] * n
    for pos, node in enumerate(rpo_full):
        rpo_idx[node] = pos

    rpo = rpo_full[1:]  # skip entry

    changed = True
    while changed:
        changed = False
        for b in rpo:
            processed_preds = [p for p in preds[b] if idom[p] != UNDEF]
            if not processed_preds:
                continue
            new_idom = processed_preds[0]
            for p in processed_preds[1:]:
                new_idom = _dom_intersect(p, new_idom, idom, rpo_idx)
            if idom[b] != new_idom:
                idom[b] = new_idom
                changed = True

    # fill unreachable with self-sentinel (use actual index, not UNDEF)
    for i in range(n):
        if idom[i] == UNDEF:
            idom[i] = i

    return idom


def ref_postorder_chain(n):
    """postorder of linear chain 0→1→…→(n-1)"""
    succ = [[i + 1] if i + 1 < n else [] for i in range(n)]
    return _postorder(n, succ, 0)


def ref_compute_dominators_chain(n):
    """compute_dominators over linear chain 0→1→…→(n-1)"""
    succ = [[i + 1] if i + 1 < n else [] for i in range(n)]
    return ref_compute_dominators(n, succ, 0)


def ref_compute_dominators_from_edges(n, edges, entry=0):
    """compute_dominators_from_edges"""
    succ = [[] for _ in range(n)]
    for (fr, to) in edges:
        if fr < n:
            succ[fr].append(to)
    return ref_compute_dominators(n, succ, entry)


def ref_trace_callers_backward(addr, hops, edges):
    """trace_callers_backward — BFS backward, returns node_count (total)."""
    MAX_HOPS = 10
    hops = min(hops, MAX_HOPS)
    if hops == 0:
        return 0

    callers_of = {}
    for (caller, callee) in edges:
        callers_of.setdefault(callee, []).append(caller)

    visited = {addr}
    frontier = [addr]
    total = 0

    for _ in range(hops):
        level = []
        next_frontier = []
        for node in frontier:
            for caller in callers_of.get(node, []):
                if caller not in visited:
                    visited.add(caller)
                    level.append(caller)
                    next_frontier.append(caller)
        level.sort()
        if not level:
            break
        total += len(level)
        frontier = next_frontier

    return total


def ref_trace_callees_forward(addr, hops, edges):
    """trace_callees_forward — BFS forward, returns node_count (total)."""
    MAX_HOPS = 10
    hops = min(hops, MAX_HOPS)
    if hops == 0:
        return 0

    callees_of = {}
    for (caller, callee) in edges:
        callees_of.setdefault(caller, []).append(callee)

    visited = {addr}
    frontier = [addr]
    total = 0

    for _ in range(hops):
        level = []
        next_frontier = []
        for node in frontier:
            for callee in callees_of.get(node, []):
                if callee not in visited:
                    visited.add(callee)
                    level.append(callee)
                    next_frontier.append(callee)
        level.sort()
        if not level:
            break
        total += len(level)
        frontier = next_frontier

    return total


# ─────────────────────────────────────────────────────────────────────────────
# MCP transport helpers
# ─────────────────────────────────────────────────────────────────────────────

def start_server():
    p = subprocess.Popen(
        [EXE, "--transport=stdio"],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL, bufsize=0
    )
    return p


def send(p, req):
    p.stdin.write((json.dumps(req) + "\n").encode())
    p.stdin.flush()


def recv(p):
    line = p.stdout.readline()
    if not line:
        raise RuntimeError("MCP server died unexpectedly")
    try:
        return json.loads(line)
    except json.JSONDecodeError as e:
        raise RuntimeError(f"Bad JSON from server: {line[:200]!r}") from e


def mcp_call(p, rid, name, args):
    send(p, {"jsonrpc": "2.0", "id": rid, "method": "tools/call",
             "params": {"name": name, "arguments": args}})
    resp = recv(p)
    if "error" in resp:
        raise RuntimeError(f"JSONRPC error: {resp['error']}")
    is_err = resp.get("result", {}).get("isError", False)
    content = resp.get("result", {}).get("content", [])
    txt = content[0].get("text", "") if content else ""
    if is_err:
        raise RuntimeError(f"Tool error: {txt[:300]}")
    return json.loads(txt)


# ─────────────────────────────────────────────────────────────────────────────
# Test cases: (tool_name, args, verifier_fn)
# verifier_fn(actual_dict) -> (ok: bool, expected_repr: str, actual_repr: str)
# ─────────────────────────────────────────────────────────────────────────────

def check_meet_top(actual):
    # meet(Top, Const(7)) should be Const(7)
    expected = ("const", 7)
    ok = actual.get("kind") == "const" and actual.get("value") == 7
    return ok, str(expected), str((actual.get("kind"), actual.get("value")))


def check_meet_equal(actual):
    # meet(Const(42), Const(42)) = Const(42)
    expected = ("const", 42)
    ok = actual.get("kind") == "const" and actual.get("value") == 42
    return ok, str(expected), str((actual.get("kind"), actual.get("value")))


def check_meet_different(actual):
    # meet(Const(1), Const(2)) = Bottom  → is_bottom = True
    expected = True
    ok = actual.get("is_bottom") is True
    return ok, str(expected), str(actual.get("is_bottom"))


def check_statement_new(actual):
    expected = ref_statement_new(5, "x", ["a", "b"])
    ok = (actual.get("id") == expected["id"] and
          actual.get("def") == expected["def"] and
          actual.get("uses") == expected["uses"] and
          actual.get("expr") == expected["expr"])
    return ok, str(expected), str({k: actual.get(k) for k in expected})


def check_statement_with_expr(actual):
    expected = ref_statement_with_expr(3, "a+b")
    ok = (actual.get("id") == expected["id"] and
          actual.get("expr") == expected["expr"])
    return ok, str(expected), str({"id": actual.get("id"), "expr": actual.get("expr")})


def check_linear_cfg_node_count(actual):
    n = 4
    expected = ref_linear_cfg_node_count(n)
    ok = (actual.get("node_count") == expected["node_count"] and
          actual.get("entry") == expected["entry"] and
          actual.get("exit") == expected["exit"])
    return ok, str(expected), str({k: actual.get(k) for k in expected})


def check_compute_dominators_chain(actual):
    n = 4
    expected_idom = ref_compute_dominators_chain(n)
    actual_idom = actual.get("idom", [])
    ok = list(actual_idom) == expected_idom
    return ok, str(expected_idom), str(actual_idom)


def check_postorder_chain(actual):
    n = 4
    expected_po = ref_postorder_chain(n)
    actual_po = actual.get("postorder", [])
    ok = list(actual_po) == expected_po
    return ok, str(expected_po), str(actual_po)


def check_dominators_from_edges(actual):
    # n=4, edges=[[0,1],[1,2],[2,3]], entry=0  → linear chain dominators
    n = 4
    edges = [[0, 1], [1, 2], [2, 3]]
    expected_idom = ref_compute_dominators_from_edges(n, edges, 0)
    actual_idom = actual.get("idom", [])
    ok = list(actual_idom) == expected_idom
    return ok, str(expected_idom), str(actual_idom)


def check_trace_callers_backward(actual):
    # addr=100, hops=2, edges=[[200,100],[300,200]]
    # callers of 100: [200], callers of 200: [300] → total=2
    addr = 100
    hops = 2
    edges = [(200, 100), (300, 200)]
    expected_total = ref_trace_callers_backward(addr, hops, edges)
    actual_total = actual.get("node_count")
    ok = actual_total == expected_total
    return ok, str(expected_total), str(actual_total)


def check_trace_callees_forward(actual):
    # addr=100, hops=2, edges=[[100,200],[200,300]]
    # callees of 100: [200], callees of 200: [300] → total=2
    addr = 100
    hops = 2
    edges = [(100, 200), (200, 300)]
    expected_total = ref_trace_callees_forward(addr, hops, edges)
    actual_total = actual.get("node_count")
    ok = actual_total == expected_total
    return ok, str(expected_total), str(actual_total)


# ─────────────────────────────────────────────────────────────────────────────
# Tool call arguments (must match the verifier assumptions above)
# ─────────────────────────────────────────────────────────────────────────────

TESTS = [
    ("adf_lattice_value_meet_top",
     {"x": 7},
     check_meet_top),

    ("adf_lattice_value_meet_equal",
     {"a": 42},
     check_meet_equal),

    ("adf_lattice_value_meet_different",
     {"a": 1, "b": 2},
     check_meet_different),

    ("adf_statement_new",
     {"id": 5, "def": "x", "uses": ["a", "b"]},
     check_statement_new),

    ("adf_statement_with_expr",
     {"id": 3, "expr": "a+b"},
     check_statement_with_expr),

    ("adf_linear_cfg_node_count",
     {"n": 4},
     check_linear_cfg_node_count),

    ("adf_compute_dominators_chain",
     {"n": 4},
     check_compute_dominators_chain),

    ("adf_postorder_chain",
     {"n": 4},
     check_postorder_chain),

    ("adf_dominators_from_edges",
     {"n": 4, "edges": [[0, 1], [1, 2], [2, 3]], "entry": 0},
     check_dominators_from_edges),

    ("adf_trace_callers_backward_simple",
     {"addr": 100, "hops": 2, "edges": [[200, 100], [300, 200]]},
     check_trace_callers_backward),

    ("adf_trace_callees_forward_simple",
     {"addr": 100, "hops": 2, "edges": [[100, 200], [200, 300]]},
     check_trace_callees_forward),
]


def main():
    p = start_server()

    # Initialize MCP
    send(p, {"jsonrpc": "2.0", "id": 1, "method": "initialize",
             "params": {"protocolVersion": "2024-11-05", "capabilities": {},
                        "clientInfo": {"name": "adf-rigorous", "version": "1"}}})
    recv(p)
    send(p, {"jsonrpc": "2.0", "method": "notifications/initialized"})

    # Open project (required by server)
    send(p, {"jsonrpc": "2.0", "id": 2, "method": "tools/call",
             "params": {"name": "project.open", "arguments": {"path": TARGET}}})
    recv(p)

    results = []
    mismatches = []
    tools_passed = 0
    tools_failed = 0
    tools_skipped = 0

    rid = 100
    for (tool_name, args, verifier) in TESTS:
        rid += 1
        try:
            actual = mcp_call(p, rid, tool_name, args)
            ok, expected_repr, actual_repr = verifier(actual)
            status = "PASS" if ok else "FAIL"
            if ok:
                tools_passed += 1
            else:
                tools_failed += 1
                mismatches.append({
                    "tool": tool_name,
                    "expected": expected_repr,
                    "actual": actual_repr,
                    "args": args,
                })
        except Exception as e:
            status = "ERROR"
            tools_failed += 1
            expected_repr = "n/a"
            actual_repr = str(e)
            mismatches.append({
                "tool": tool_name,
                "expected": expected_repr,
                "actual": actual_repr,
                "args": args,
            })

        results.append({
            "tool": tool_name,
            "status": status,
            "args": args,
            "expected": expected_repr,
            "actual": actual_repr,
        })
        print(f"  [{status}] {tool_name}")
        if status != "PASS":
            print(f"         expected: {expected_repr}")
            print(f"         actual  : {actual_repr}")

    p.stdin.close()
    p.terminate()

    with open(OUT_PASS, "w") as f:
        json.dump(results, f, indent=2)

    skip_list = []
    with open(OUT_SKIP, "w") as f:
        json.dump(skip_list, f, indent=2)

    print(f"\nResults: passed={tools_passed}, failed={tools_failed}, skipped={tools_skipped}")
    print(f"Written to {OUT_PASS}")

    # Return summary for the parent script
    summary = {
        "category": "adf",
        "tools_hardened": len(TESTS),
        "tools_passed": tools_passed,
        "tools_failed": tools_failed,
        "tools_skipped": tools_skipped,
        "mismatches": mismatches,
    }
    print("\nSUMMARY_JSON:", json.dumps(summary))
    return summary


if __name__ == "__main__":
    main()
