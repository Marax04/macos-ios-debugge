#!/usr/bin/env python3
"""
Rigorous ground-truth validation for all MCP tools prefixed with axr_.
Each tool is exercised with a known, deterministic input; expected output is
computed independently in Python and compared byte-for-byte / value-for-value
against the Rust implementation via JSON-RPC-over-stdio.
"""
import json
import subprocess
import collections
import sys
import os

# ---------------------------------------------------------------------------
# MCP server I/O helpers (identical pattern to exercise_v3.py)
# ---------------------------------------------------------------------------

EXE = r"C:\Users\Fra\Desktop\RustRE\target\release\rustre-mcp.exe"
TARGET = r"C:\Users\Fra\Desktop\Zyphora\target\release\cargo-zyphora.exe"

p = subprocess.Popen(
    [EXE, "--transport=stdio"],
    stdin=subprocess.PIPE,
    stdout=subprocess.PIPE,
    stderr=subprocess.DEVNULL,
    bufsize=0,
)

def send(req):
    p.stdin.write((json.dumps(req) + "\n").encode())
    p.stdin.flush()

def recv():
    line = p.stdout.readline()
    if not line:
        raise RuntimeError("server died")
    try:
        return json.loads(line)
    except json.JSONDecodeError:
        return {"error": {"message": f"bad-line: {line[:100]!r}"}}

# Handshake
send({"jsonrpc": "2.0", "id": 1, "method": "initialize",
      "params": {"protocolVersion": "2024-11-05", "capabilities": {},
                 "clientInfo": {"name": "axr_rigorous", "version": "1"}}})
recv()
send({"jsonrpc": "2.0", "method": "notifications/initialized"})

# Open project (required by the server to initialise binary_id etc.)
send({"jsonrpc": "2.0", "id": 2, "method": "tools/call",
      "params": {"name": "project.open", "arguments": {"path": TARGET}}})
recv()  # discard result; we don't need binary_id for axr_ tools

_rid = 100

def call_tool(name, arguments):
    global _rid
    _rid += 1
    send({"jsonrpc": "2.0", "id": _rid, "method": "tools/call",
          "params": {"name": name, "arguments": arguments}})
    resp = recv()
    if "error" in resp:
        return None, f"JSONRPC_ERROR: {resp['error']}"
    content = resp.get("result", {}).get("content", [])
    is_err = resp.get("result", {}).get("isError", False)
    text = content[0].get("text", "") if content else ""
    if is_err:
        return None, f"TOOL_ERROR: {text}"
    try:
        return json.loads(text), None
    except Exception as e:
        return None, f"JSON_PARSE_ERROR: {e}: {text[:200]}"

# ---------------------------------------------------------------------------
# Test fixture — deterministic call graph with known topology
#
#   0x100 -> 0x200   (call)
#   0x100 -> 0x300   (call)
#   0x200 -> 0x300   (call)
#   0x400 -> 0x200   (call)
#
# Derived facts:
#   callers_of(0x200)       = {0x100, 0x400}
#   callees_of(0x100)       = {0x200, 0x300}
#   hot_functions(3) sorted = [(0x200, 2), (0x300, 2)]  [tie → addr asc]
#   is_leaf(0x300)          = True   (no outgoing calls)
#   is_leaf(0x100)          = False
#   call_graph nodes        = {0x100, 0x200, 0x300, 0x400}  → 4
#   call_graph edges        = 4  (each unique from/to pair)
#   reachable_from(0x100)   = {0x100, 0x200, 0x300}
#   bfs_distances(0x100)    = {0x100:0, 0x200:1, 0x300:1}
#   SCC (acyclic graph)     = 4 singleton SCCs
#   topo_sort               = valid ordering where 0x300 is last
#
# ---------------------------------------------------------------------------

CALLS = [
    {"from": 0x100, "to": 0x200},
    {"from": 0x100, "to": 0x300},
    {"from": 0x200, "to": 0x300},
    {"from": 0x400, "to": 0x200},
]

# Cyclic fixture for topo_sort=null test
CYCLIC_CALLS = [
    {"from": 0xA00, "to": 0xB00},
    {"from": 0xB00, "to": 0xA00},
]

IMPORTS = [
    {"from": 0x1000, "to": 0x2000, "name": "kernel32.dll!CreateFile"},
    {"from": 0x1001, "to": 0x2001, "name": "ntdll.dll!NtQuerySystemInformation"},
]

STRINGS = [
    {"from": 0x3000, "to": 0x4000, "content": "Hello, world!"},
    {"from": 0x3001, "to": 0x4001, "content": "error: invalid argument"},
]

# ---------------------------------------------------------------------------
# Python reference implementations
# ---------------------------------------------------------------------------

def py_callers_of(addr, calls):
    return sorted({c["from"] for c in calls if c["to"] == addr})

def py_callees_of(addr, calls):
    return sorted({c["to"] for c in calls if c["from"] == addr})

def py_hot_functions(top_n, calls):
    counts = collections.Counter(c["to"] for c in calls)
    items = sorted(counts.items(), key=lambda x: (-x[1], x[0]))[:top_n]
    return items  # list of (addr, count)

def py_is_leaf(addr, calls):
    return not any(c["from"] == addr for c in calls)

def py_all_import_names(imports):
    return sorted(i["name"] for i in imports)

def py_all_strings(strings):
    return sorted(s["content"] for s in strings)

def py_call_graph_stats(calls):
    nodes = set()
    edges = set()
    for c in calls:
        nodes.add(c["from"])
        nodes.add(c["to"])
        edges.add((c["from"], c["to"]))
    return len(nodes), len(edges)

def py_reachable_from(start, calls):
    adj = collections.defaultdict(set)
    for c in calls:
        adj[c["from"]].add(c["to"])
    visited = set()
    queue = collections.deque([start])
    visited.add(start)
    while queue:
        cur = queue.popleft()
        for nxt in adj[cur]:
            if nxt not in visited:
                visited.add(nxt)
                queue.append(nxt)
    return visited

def py_bfs_distances(start, calls):
    adj = collections.defaultdict(set)
    for c in calls:
        adj[c["from"]].add(c["to"])
    dist = {start: 0}
    queue = collections.deque([(start, 0)])
    while queue:
        cur, d = queue.popleft()
        for nxt in adj[cur]:
            if nxt not in dist:
                dist[nxt] = d + 1
                queue.append((nxt, d + 1))
    return dist

def py_scc_count(calls):
    """Compute number of SCCs using Kosaraju's algorithm."""
    nodes = set()
    adj = collections.defaultdict(list)
    radj = collections.defaultdict(list)
    for c in calls:
        nodes.add(c["from"])
        nodes.add(c["to"])
        adj[c["from"]].append(c["to"])
        radj[c["to"]].append(c["from"])
    # Pass 1: finish order
    visited = set()
    order = []
    def dfs1(v):
        stack = [(v, iter(adj[v]))]
        visited.add(v)
        while stack:
            node, it = stack[-1]
            try:
                nxt = next(it)
                if nxt not in visited:
                    visited.add(nxt)
                    stack.append((nxt, iter(adj[nxt])))
            except StopIteration:
                order.append(node)
                stack.pop()
    for n in nodes:
        if n not in visited:
            dfs1(n)
    # Pass 2: reverse graph in finish order
    visited2 = set()
    count = 0
    def dfs2(v):
        stack = [v]
        visited2.add(v)
        while stack:
            node = stack.pop()
            for nxt in radj[node]:
                if nxt not in visited2:
                    visited2.add(nxt)
                    stack.append(nxt)
    for v in reversed(order):
        if v not in visited2:
            dfs2(v)
            count += 1
    return count

def py_is_valid_topo_order(order, calls):
    """Return True if `order` is a valid topological ordering for `calls`."""
    pos = {addr: i for i, addr in enumerate(order)}
    for c in calls:
        if c["from"] not in pos or c["to"] not in pos:
            return False
        if pos[c["from"]] >= pos[c["to"]]:
            return False
    return True

# ---------------------------------------------------------------------------
# Run checks
# ---------------------------------------------------------------------------

results = []
mismatches = []

def check(tool_name, args, verify_fn, description):
    """Call the MCP tool, then verify with verify_fn(actual_parsed) -> (ok, detail)."""
    actual, err = call_tool(tool_name, args)
    if err:
        results.append({"tool": tool_name, "status": "TOOL_ERROR", "detail": err})
        mismatches.append({"tool": tool_name, "expected": description, "actual": err})
        return
    ok, detail = verify_fn(actual)
    if ok:
        results.append({"tool": tool_name, "status": "PASS", "detail": detail})
    else:
        results.append({"tool": tool_name, "status": "FAIL", "detail": detail})
        mismatches.append({"tool": tool_name, "expected": description, "actual": detail})

# 1. axr_db_callers_of
expected_callers = py_callers_of(0x200, CALLS)
def verify_callers(actual):
    got = sorted(actual.get("callers", []))
    ok = got == expected_callers
    return ok, f"got={got} expected={expected_callers}"
check("axr_db_callers_of",
      {"addr": 0x200, "calls": CALLS},
      verify_callers,
      f"sorted callers == {expected_callers}")

# 2. axr_db_callees_of
expected_callees = py_callees_of(0x100, CALLS)
def verify_callees(actual):
    got = sorted(actual.get("callees", []))
    ok = got == expected_callees
    return ok, f"got={got} expected={expected_callees}"
check("axr_db_callees_of",
      {"addr": 0x100, "calls": CALLS},
      verify_callees,
      f"sorted callees == {expected_callees}")

# 3. axr_db_hot_functions
expected_hot = py_hot_functions(3, CALLS)  # [(0x200,2), (0x300,2)]
def verify_hot(actual):
    hot = actual.get("hot", [])
    # hot is [[addr, count], ...]
    # Sort same way Rust does: count desc, addr asc
    got = sorted(([addr, cnt] for addr, cnt in (h for h in hot)),
                 key=lambda x: (-x[1], x[0]))
    exp = [[addr, cnt] for addr, cnt in expected_hot]
    ok = got == exp
    return ok, f"got={got} expected={exp}"
check("axr_db_hot_functions",
      {"top_n": 3, "calls": CALLS},
      verify_hot,
      f"hot functions sorted == {expected_hot}")

# 4. axr_db_is_leaf_function — 0x300 is a leaf
def verify_leaf_true(actual):
    got = actual.get("leaf")
    return got is True, f"got={got} expected=True"
check("axr_db_is_leaf_function",
      {"addr": 0x300, "calls": CALLS},
      verify_leaf_true,
      "is_leaf(0x300) == True")

# 5. axr_db_is_leaf_function — 0x100 is NOT a leaf
def verify_leaf_false(actual):
    got = actual.get("leaf")
    return got is False, f"got={got} expected=False"
check("axr_db_is_leaf_function",
      {"addr": 0x100, "calls": CALLS},
      verify_leaf_false,
      "is_leaf(0x100) == False")

# 6. axr_db_all_import_names
expected_imports = py_all_import_names(IMPORTS)
def verify_imports(actual):
    got = sorted(actual.get("imports", []))
    ok = got == expected_imports
    return ok, f"got={got} expected={expected_imports}"
check("axr_db_all_import_names",
      {"imports": IMPORTS},
      verify_imports,
      f"import names == {expected_imports}")

# 7. axr_db_all_strings
expected_strings = py_all_strings(STRINGS)
def verify_strings(actual):
    got = sorted(actual.get("strings", []))
    ok = got == expected_strings
    return ok, f"got={got} expected={expected_strings}"
check("axr_db_all_strings",
      {"strings": STRINGS},
      verify_strings,
      f"string contents == {expected_strings}")

# 8. axr_db_to_json
def verify_to_json(actual):
    ok_flag = actual.get("ok") is True
    bytes_gt0 = isinstance(actual.get("bytes"), int) and actual["bytes"] > 0
    ok = ok_flag and bytes_gt0
    return ok, f"ok={actual.get('ok')} bytes={actual.get('bytes')}"
check("axr_db_to_json",
      {"calls": CALLS},
      verify_to_json,
      "ok=true and bytes>0")

# 9. axr_graph_call_graph_stats
exp_nodes, exp_edges = py_call_graph_stats(CALLS)
def verify_cg_stats(actual):
    got_nodes = actual.get("nodes")
    got_edges = actual.get("edges")
    ok = got_nodes == exp_nodes and got_edges == exp_edges
    return ok, f"got=({got_nodes},{got_edges}) expected=({exp_nodes},{exp_edges})"
check("axr_graph_call_graph_stats",
      {"calls": CALLS},
      verify_cg_stats,
      f"nodes={exp_nodes} edges={exp_edges}")

# 10. axr_graph_reachable_from (start=0x100)
exp_reach = py_reachable_from(0x100, CALLS)
def verify_reach(actual):
    got_set = set(actual.get("reachable", []))
    got_count = actual.get("count")
    ok = got_set == exp_reach and got_count == len(exp_reach)
    return ok, f"got={sorted(got_set)} count={got_count} expected={sorted(exp_reach)}"
check("axr_graph_reachable_from",
      {"start": 0x100, "calls": CALLS},
      verify_reach,
      f"reachable from 0x100 == {sorted(exp_reach)}")

# 11. axr_graph_bfs_distances (start=0x100)
exp_dists = py_bfs_distances(0x100, CALLS)
def verify_bfs(actual):
    raw = actual.get("distances", [])
    # raw is [[addr, dist], ...]
    got_dict = {item[0]: item[1] for item in raw}
    ok = got_dict == exp_dists
    return ok, f"got={dict(sorted(got_dict.items()))} expected={dict(sorted(exp_dists.items()))}"
check("axr_graph_bfs_distances",
      {"start": 0x100, "calls": CALLS},
      verify_bfs,
      f"bfs distances from 0x100 == {exp_dists}")

# 12. axr_graph_scc (acyclic graph → all singletons)
exp_scc_count = py_scc_count(CALLS)
def verify_scc(actual):
    count = actual.get("count")
    sccs = actual.get("sccs", [])
    sizes = sorted(len(s) for s in sccs)
    # Each SCC should be a singleton (all-1 list of length 4)
    all_singleton = all(len(s) == 1 for s in sccs)
    # All addresses appear exactly once
    all_addrs = sorted(v for s in sccs for v in s)
    exp_addrs = sorted({c["from"] for c in CALLS} | {c["to"] for c in CALLS})
    ok = count == exp_scc_count and all_singleton and all_addrs == exp_addrs
    return ok, (f"count={count} expected={exp_scc_count} "
                f"all_singleton={all_singleton} addrs={all_addrs} expected_addrs={exp_addrs}")
check("axr_graph_scc",
      {"calls": CALLS},
      verify_scc,
      f"scc count={exp_scc_count} all singletons")

# 13. axr_graph_scc (cyclic graph → one SCC of size 2)
exp_cyc_count = py_scc_count(CYCLIC_CALLS)
def verify_scc_cyclic(actual):
    count = actual.get("count")
    sccs = actual.get("sccs", [])
    # Should have one SCC of size 2 (the cycle A<->B)
    size2_sccs = [s for s in sccs if len(s) == 2]
    ok = count == exp_cyc_count and len(size2_sccs) == 1
    return ok, f"count={count} expected={exp_cyc_count} size2_sccs={size2_sccs}"
check("axr_graph_scc",
      {"calls": CYCLIC_CALLS},
      verify_scc_cyclic,
      f"cyclic scc count={exp_cyc_count}")

# 14. axr_graph_topological_sort (acyclic → valid order)
def verify_topo_acyclic(actual):
    order = actual.get("order")
    if order is None:
        return False, "order is None but graph is acyclic"
    ok = py_is_valid_topo_order(order, CALLS)
    return ok, f"order={order} is_valid={ok}"
check("axr_graph_topological_sort",
      {"calls": CALLS},
      verify_topo_acyclic,
      "topological order is valid for acyclic graph")

# 15. axr_graph_topological_sort (cyclic → None)
def verify_topo_cyclic(actual):
    order = actual.get("order")
    ok = order is None
    return ok, f"order={order} (expected null/None for cyclic graph)"
check("axr_graph_topological_sort",
      {"calls": CYCLIC_CALLS},
      verify_topo_cyclic,
      "topological sort returns null for cyclic graph")

# ---------------------------------------------------------------------------
# Wrap up
# ---------------------------------------------------------------------------

p.stdin.close()
p.terminate()

passed = sum(1 for r in results if r["status"] == "PASS")
failed = sum(1 for r in results if r["status"] == "FAIL")
errored = sum(1 for r in results if r["status"] == "TOOL_ERROR")
total = len(results)

print(f"\n=== rigorous_axr_v2 results ===")
for r in results:
    symbol = "OK" if r["status"] == "PASS" else "FAIL"
    print(f"  [{symbol}] {r['tool']:<40} {r['detail']}")

print(f"\nSummary: {passed}/{total} passed, {failed} failed, {errored} errors")

# Write rigorous_axr_v2.json
out_path = os.path.join(os.path.dirname(__file__), "rigorous_axr_v2.json")
with open(out_path, "w") as f:
    json.dump({
        "summary": {
            "total": total,
            "passed": passed,
            "failed": failed,
            "tool_errors": errored,
            "skipped": 0,
        },
        "results": results,
        "mismatches": mismatches,
    }, f, indent=2)
print(f"Written: {out_path}")
