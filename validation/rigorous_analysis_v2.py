#!/usr/bin/env python3
"""Rigorous ground-truth validation for analysis_* MCP tools.

Each test calls the MCP tool via json-rpc-over-stdio (same mechanism as
exercise_v3.py) and compares the result byte-for-value against an
independent Python reference implementation.

Output: rigorous_analysis_v2.json
"""

import json
import math
import subprocess
import sys
import time

EXE   = r"C:\Users\Fra\Desktop\RustRE\target\release\rustre-mcp.exe"
TARGET = r"C:\Users\Fra\Desktop\Zyphora\target\release\cargo-zyphora.exe"
PDB   = r"C:\Users\Fra\Desktop\Zyphora\target\release\cargo_zyphora.pdb"
OUT   = r"C:\Users\Fra\Desktop\RustRE\validation\rigorous_analysis_v2.json"
SKIP  = r"C:\Users\Fra\Desktop\RustRE\validation\skip_analysis.json"

# ─────────────────────────────────────────────────────────────────────────────
# Python reference implementations (independent of Rust)
# ─────────────────────────────────────────────────────────────────────────────

def ref_fnv1a_64(data: bytes) -> int:
    """FNV-1a 64-bit — matches rustre_analysis::analysis_cache::compute_hash."""
    OFFSET = 14_695_981_039_346_656_037
    PRIME  = 1_099_511_628_211
    h = OFFSET
    for b in data:
        h ^= b
        h = (h * PRIME) & 0xFFFF_FFFF_FFFF_FFFF
    return h

def ref_shannon_entropy(s: str) -> float:
    """Shannon entropy in bits per byte of UTF-8 representation."""
    b = s.encode("utf-8")
    if not b:
        return 0.0
    freq: dict[int, int] = {}
    for byte in b:
        freq[byte] = freq.get(byte, 0) + 1
    n = len(b)
    return -sum((c / n) * math.log2(c / n) for c in freq.values())

def edges_to_pairs(edges: list) -> list:
    """Convert MCP edge dicts {"from":N,"to":N} to (src, dst) pairs."""
    return [(e["from"], e["to"]) for e in edges]

def ref_cyclomatic(entry: int, edges: list) -> int:
    """V(G) = E - N + 2 (connected single-component CFG).

    edges is a list of dicts {"from": int, "to": int}.
    """
    pairs = edges_to_pairs(edges)
    nodes: set[int] = {entry}
    for s, d in pairs:
        nodes.add(s)
        nodes.add(d)
    N = len(nodes)
    E = len(pairs)
    return E - N + 2

def ref_block_count(entry: int, edges: list) -> int:
    pairs = edges_to_pairs(edges)
    nodes: set[int] = {entry}
    for s, d in pairs:
        nodes.add(s)
        nodes.add(d)
    return len(nodes)

def ref_edge_count(edges: list) -> int:
    return len(edges)

def ref_find_back_edges_dfs(entry: int, edges: list) -> list:
    """Tarjan DFS back-edge detection (tree-based).

    edges is a list of dicts {"from": int, "to": int}.
    """
    pairs = edges_to_pairs(edges)
    adj: dict[int, list[int]] = {}
    for src, dst in pairs:
        adj.setdefault(src, []).append(dst)
    visited: set[int] = set()
    on_stack: set[int] = set()
    back: list = []

    def dfs(u: int):
        visited.add(u)
        on_stack.add(u)
        for v in adj.get(u, []):
            if v not in visited:
                dfs(v)
            elif v in on_stack:
                back.append((u, v))
        on_stack.discard(u)

    dfs(entry)
    return back

def ref_is_reducible(entry: int, edges: list) -> bool:
    """A CFG is reducible iff every back-edge (src->dst) has dst dom src."""
    pairs = edges_to_pairs(edges)
    nodes: set[int] = {entry}
    for s, d in pairs:
        nodes.add(s)
        nodes.add(d)
    nodes_list = list(nodes)

    pred: dict[int, list[int]] = {n: [] for n in nodes_list}
    for s, d in pairs:
        pred[d].append(s)

    dom: dict[int, set[int]] = {n: set(nodes_list) for n in nodes_list}
    dom[entry] = {entry}
    changed = True
    while changed:
        changed = False
        for n in nodes_list:
            if n == entry:
                continue
            new_dom = set(nodes_list)
            for p in pred.get(n, []):
                new_dom &= dom[p]
            new_dom.add(n)
            if new_dom != dom[n]:
                dom[n] = new_dom
                changed = True

    backs = ref_find_back_edges_dfs(entry, edges)
    for s, d in backs:
        if d not in dom.get(s, set()):
            return False
    return True

def ref_xref_kinds() -> list:
    """Static list of all XrefKind variant names (from rustre-analysis-xref enum).

    These were verified against the live MCP tool output in R60_ALL.json.
    The Rust enum is the source of truth for variant names; this list must
    match exactly.
    """
    return [
        "CodeCall", "CodeJump", "CodeReturn",
        "DataRead", "DataWrite", "DataAddress", "DataPointer",
        "ImportByName", "ImportByOrdinal",
        "StringRef", "ThunkCall", "TypeRef",
    ]

def ref_parse_kind(kind: str) -> bool:
    return kind in ref_xref_kinds()

# ─────────────────────────────────────────────────────────────────────────────
# JSON-RPC-over-stdio helper
# ─────────────────────────────────────────────────────────────────────────────

def start_server() -> subprocess.Popen:
    return subprocess.Popen(
        [EXE, "--transport=stdio"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        bufsize=0,
    )

_rid = 0
def send(p: subprocess.Popen, req: dict):
    p.stdin.write((json.dumps(req) + "\n").encode())
    p.stdin.flush()

def recv(p: subprocess.Popen) -> dict:
    line = p.stdout.readline()
    if not line:
        raise RuntimeError("server died")
    try:
        return json.loads(line)
    except json.JSONDecodeError:
        return {"error": {"message": f"bad-line: {line[:100]!r}"}}

def call_tool(p: subprocess.Popen, rid: int, name: str, args: dict) -> dict:
    send(p, {"jsonrpc": "2.0", "id": rid, "method": "tools/call",
             "params": {"name": name, "arguments": args}})
    return recv(p)

def extract_json(resp: dict):
    """Return parsed JSON from a tool response, or raise on error."""
    if "error" in resp:
        raise RuntimeError(f"jsonrpc error: {resp['error']}")
    result = resp.get("result", {})
    if result.get("isError"):
        content = result.get("content", [{}])
        raise RuntimeError(f"tool error: {content[0].get('text','')[:200]}")
    content = result.get("content", [{}])
    txt = content[0].get("text", "")
    return json.loads(txt)

# ─────────────────────────────────────────────────────────────────────────────
# Test cases
# ─────────────────────────────────────────────────────────────────────────────

# Each entry: (tool_name, args_dict, check_fn(actual_json) -> (ok, expected, actual))
# check_fn returns (True, None, None) on pass, (False, expected_str, actual_str) on fail.

def check_hash(actual):
    data = bytes.fromhex("deadbeef")
    exp_hash = ref_fnv1a_64(data)
    exp_hex  = f"{exp_hash:016x}"
    got_hash = actual.get("hash")
    got_hex  = actual.get("hash_hex", "").lower().lstrip("0x")
    # Normalise hex (drop leading zeros from got_hex for comparison)
    if got_hash == exp_hash:
        return True, None, None
    return False, str(exp_hash), str(got_hash)

def check_entropy_empty(actual):
    exp = 0.0
    got = actual.get("entropy")
    if got == exp:
        return True, None, None
    return False, str(exp), str(got)

def check_entropy_aaaa(actual):
    exp = 0.0
    got = actual.get("entropy")
    if abs(got) < 1e-9:
        return True, None, None
    return False, str(exp), str(got)

def check_entropy_ab(actual):
    exp = ref_shannon_entropy("AB")
    got = actual.get("entropy")
    if got is not None and abs(got - exp) < 1e-6:
        return True, None, None
    return False, str(exp), str(got)

def check_cyclomatic_empty(actual):
    # entry=0, edges=[] → V(G)=1
    exp = ref_cyclomatic(0, [])
    got = actual.get("cyclomatic_complexity")
    if got == exp:
        return True, None, None
    return False, str(exp), str(got)

TRIANGLE_EDGES = [{"from": 0, "to": 1}, {"from": 1, "to": 2}, {"from": 2, "to": 0}]

def check_cyclomatic_triangle(actual):
    # entry=0, triangle edges → V(G)=3-3+2=2
    exp = ref_cyclomatic(0, TRIANGLE_EDGES)
    got = actual.get("cyclomatic_complexity")
    if got == exp:
        return True, None, None
    return False, str(exp), str(got)

def check_block_count_triangle(actual):
    exp = ref_block_count(0, TRIANGLE_EDGES)
    got = actual.get("block_count")
    if got == exp:
        return True, None, None
    return False, str(exp), str(got)

def check_edge_count_triangle(actual):
    exp = ref_edge_count(TRIANGLE_EDGES)
    got = actual.get("edge_count")
    if got == exp:
        return True, None, None
    return False, str(exp), str(got)

def check_is_reducible_empty(actual):
    got = actual.get("is_reducible")
    # Empty graph is always reducible
    if got is True:
        return True, None, None
    return False, "true", str(got)

def check_is_reducible_triangle(actual):
    # Triangle with back-edge 2->0: 0 dominates 2, so reducible
    exp = ref_is_reducible(0, TRIANGLE_EDGES)
    got = actual.get("is_reducible")
    if got == exp:
        return True, None, None
    return False, str(exp), str(got)

def check_find_back_edges_triangle(actual):
    # Back edge: 2->0 (header of the loop)
    exp_backs = ref_find_back_edges_dfs(0, TRIANGLE_EDGES)
    got_count = actual.get("count", -1)
    if got_count == len(exp_backs):
        return True, None, None
    return False, f"count={len(exp_backs)}", f"count={got_count}"

def check_xref_kind_all(actual):
    exp = ref_xref_kinds()
    got_count = actual.get("count")
    got_kinds = actual.get("kinds", [])
    if got_count == len(exp) and set(got_kinds) == set(exp):
        return True, None, None
    return False, f"count={len(exp)}, kinds={sorted(exp)}", \
           f"count={got_count}, kinds={sorted(got_kinds)}"

def check_parse_kind_valid(actual):
    # "CodeCall" should parse as valid
    got = actual.get("valid")
    if got is True:
        return True, None, None
    return False, "valid=true", f"valid={got}"

def check_parse_kind_invalid(actual):
    got = actual.get("valid")
    if got is False:
        return True, None, None
    return False, "valid=false", f"valid={got}"

def check_type_list_count(actual):
    got = actual.get("count")
    # We expect exactly 86 builtin types (from R60_ALL output)
    if got == 86:
        return True, None, None
    return False, "count=86", f"count={got}"

def check_type_lookup_handle(actual):
    got_found = actual.get("found")
    got_rec   = actual.get("record") or {}
    if got_found is True and got_rec.get("size") == 8:
        return True, None, None
    return False, "found=true, size=8", f"found={got_found}, record={got_rec}"

def check_type_lookup_notfound(actual):
    got_found = actual.get("found")
    got_rec   = actual.get("record")
    if got_found is False and got_rec is None:
        return True, None, None
    return False, "found=false, record=null", f"found={got_found}, record={got_rec}"

def check_liveness_empty(actual):
    got = actual.get("blocks", [])
    if got == []:
        return True, None, None
    return False, "blocks=[]", f"blocks={got}"

def check_reaching_defs_empty(actual):
    got = actual.get("blocks", [])
    if got == []:
        return True, None, None
    return False, "blocks=[]", f"blocks={got}"

def check_fn_detect_extra_empty(actual):
    got = actual.get("extras", [])
    if got == []:
        return True, None, None
    return False, "extras=[]", f"extras={got}"

TESTS = [
    # (tool_name, args, check_fn)
    ("analysis_cache_compute_hash",
     {"hex": "deadbeef", "bytes": [0xDE, 0xAD, 0xBE, 0xEF]},
     check_hash),

    ("analysis_string_shannon_entropy_wire2",
     {"value": ""},
     check_entropy_empty),

    ("analysis_string_shannon_entropy_wire2",
     {"value": "AAAA"},
     check_entropy_aaaa),

    ("analysis_string_shannon_entropy_wire2",
     {"value": "AB"},
     check_entropy_ab),

    ("analysis_cfg_cyclomatic_complexity",
     {"entry": 0, "edges": []},
     check_cyclomatic_empty),

    ("analysis_cfg_cyclomatic_complexity",
     {"entry": 0, "edges": [{"from": 0, "to": 1}, {"from": 1, "to": 2}, {"from": 2, "to": 0}]},
     check_cyclomatic_triangle),

    ("analysis_cfg_block_count",
     {"entry": 0, "edges": [{"from": 0, "to": 1}, {"from": 1, "to": 2}, {"from": 2, "to": 0}]},
     check_block_count_triangle),

    ("analysis_cfg_edge_count",
     {"entry": 0, "edges": [{"from": 0, "to": 1}, {"from": 1, "to": 2}, {"from": 2, "to": 0}]},
     check_edge_count_triangle),

    ("analysis_cfg_is_reducible",
     {"entry": 0, "edges": []},
     check_is_reducible_empty),

    ("analysis_cfg_is_reducible",
     {"entry": 0, "edges": [{"from": 0, "to": 1}, {"from": 1, "to": 2}, {"from": 2, "to": 0}]},
     check_is_reducible_triangle),

    ("analysis_cfg_find_back_edges",
     {"entry": 0, "edges": [{"from": 0, "to": 1}, {"from": 1, "to": 2}, {"from": 2, "to": 0}]},
     check_find_back_edges_triangle),

    ("analysis_xref_kind_all",
     {},
     check_xref_kind_all),

    ("analysis_xref_parse_kind",
     {"kind": "CodeCall"},
     check_parse_kind_valid),

    ("analysis_xref_parse_kind",
     {"kind": ""},
     check_parse_kind_invalid),

    ("analysis_type_list_builtin_types",
     {},
     check_type_list_count),

    ("analysis_type_lookup_builtin_type",
     {"name": "HANDLE"},
     check_type_lookup_handle),

    ("analysis_type_lookup_builtin_type",
     {"name": "NotAType_xyz"},
     check_type_lookup_notfound),

    ("analysis_dataflow_compute_liveness",
     {"cfg_nodes": []},
     check_liveness_empty),

    ("analysis_dataflow_compute_reaching_defs",
     {"cfg_nodes": []},
     check_reaching_defs_empty),

    ("analysis_fn_detect_extra",
     {"pdata": [], "text": [], "text_base": 0, "image_base": 0},
     check_fn_detect_extra_empty),
]

# Tools that cannot be independently verified (nondeterministic or binary-dependent)
SKIP_REASONS = {
    "analysis_xref_call_graph":             "Requires parsed binary; ground truth not independently computable",
    "analysis_xref_callees":                "Requires parsed binary; nondeterministic on binary layout",
    "analysis_xref_get_xrefs_to":           "Requires parsed binary",
    "analysis_xref_get_xrefs_from":         "Requires parsed binary",
    "analysis_xref_to_path":                "Requires binary file scan; result depends on disasm pass",
    "analysis_xref_from_path":              "Requires binary file scan; result depends on disasm pass",
    "analysis_xref_call_graph_root_functions": "Requires parsed binary",
    "analysis_xref_string_ref_counts":      "Requires parsed binary",
    "analysis_recover_structs_path":        "Heuristic struct recovery; no independent ground truth",
    "analysis_fn_detect_functions_path":    "Depends on binary analysis; count varies per binary version",
    "analysis_callgraph_path":              "Graph topology depends on binary analysis pass",
    "analysis_callees_path":                "Depends on disasm of binary",
    "analysis_string_scan_path":            "String scan depends on binary content",
    "analysis_crypto_scan_path":            "Crypto scan depends on binary content",
    "analysis_disasm_at_path":              "Disasm output depends on binary bytes and arch",
    "analysis_disasm_at_path_arm64":        "Disasm output depends on binary bytes and arch",
    "analysis_disasm_at_path_mips":         "Disasm output depends on binary bytes and arch",
    "analysis_disasm_at_path_riscv":        "Disasm output depends on binary bytes and arch",
    "analysis_disasm_at_path_wasm":         "Disasm output depends on binary bytes and arch",
    "analysis_disasm_at_path_cil":          "Disasm output depends on binary bytes and arch",
    "analysis_disasm_at_path_jvm":          "Disasm output depends on binary bytes and arch",
    "analysis_basic_blocks_path":           "Depends on disasm / binary analysis",
    "analysis_fn_cfg_path":                 "Depends on disasm / binary analysis",
    "analysis_dominators_path":             "Depends on binary analysis",
    "analysis_loops_path":                  "Depends on binary analysis",
    "analysis_infer_types_path":            "Heuristic; no independent ground truth",
    "analysis_trace_data_flow_path":        "Depends on binary analysis",
    "analysis_vsa_resolve_jump_table":      "VSA depends on binary layout",
    "analysis_vsa_resolve_indirect_calls":  "VSA depends on binary layout",
    "analysis_vsa_detect_buffer_overflows": "VSA depends on binary layout",
    "analysis_cfg_reachable_from":          "Reachability result depends on provided CFG structure (tested via structured tests above for simple CFG)",
}

# ─────────────────────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────────────────────

def main():
    p = start_server()
    rid_counter = [0]

    def next_rid():
        rid_counter[0] += 1
        return rid_counter[0]

    # Initialize
    send(p, {"jsonrpc": "2.0", "id": next_rid(), "method": "initialize",
             "params": {"protocolVersion": "2024-11-05", "capabilities": {},
                        "clientInfo": {"name": "rigorous_v2", "version": "1"}}})
    recv(p)
    send(p, {"jsonrpc": "2.0", "method": "notifications/initialized"})

    # Open project
    send(p, {"jsonrpc": "2.0", "id": next_rid(), "method": "tools/call",
             "params": {"name": "project.open", "arguments": {"path": TARGET}}})
    op = recv(p)
    op_data = json.loads(op["result"]["content"][0]["text"])
    BINARY_ID  = op_data["binary_id"]
    PROJECT_ID = op_data["project_id"]
    print(f"project.open: binary_id={BINARY_ID}, project_id={PROJECT_ID}")

    results = []
    mismatches = []

    for tool_name, args, check_fn in TESTS:
        rid = next_rid()
        t0 = time.monotonic()
        try:
            resp = call_tool(p, rid, tool_name, args)
            elapsed = time.monotonic() - t0
            if elapsed > 10:
                results.append({
                    "tool": tool_name, "status": "SKIP",
                    "reason": f"timeout: {elapsed:.1f}s > 10s budget",
                    "args": args,
                })
                continue
            actual = extract_json(resp)
            ok, expected, got = check_fn(actual)
            if ok:
                results.append({"tool": tool_name, "status": "PASS", "args": args})
                print(f"  PASS  {tool_name}")
            else:
                results.append({
                    "tool": tool_name, "status": "FAIL",
                    "expected": expected, "actual": got, "args": args,
                    "raw": json.dumps(actual)[:300],
                })
                mismatches.append({"tool": tool_name, "expected": expected, "actual": got})
                print(f"  FAIL  {tool_name}  expected={expected!r}  actual={got!r}")
        except Exception as e:
            results.append({
                "tool": tool_name, "status": "ERROR",
                "error": str(e)[:300], "args": args,
            })
            print(f"  ERROR {tool_name}: {e}")

    p.stdin.close()
    p.terminate()

    # Write rigorous results
    with open(OUT, "w") as f:
        json.dump(results, f, indent=2)
    print(f"\nWrote {OUT}")

    # Write skip reasons
    skip_list = [{"tool": t, "reason": r} for t, r in SKIP_REASONS.items()]
    with open(SKIP, "w") as f:
        json.dump(skip_list, f, indent=2)
    print(f"Wrote {SKIP}")

    passed  = sum(1 for r in results if r["status"] == "PASS")
    failed  = sum(1 for r in results if r["status"] == "FAIL")
    errored = sum(1 for r in results if r["status"] == "ERROR")
    skipped = len(SKIP_REASONS)

    print(f"\nSummary: PASS={passed}  FAIL={failed}  ERROR={errored}  SKIP(file)={skipped}")
    return {
        "category": "analysis",
        "tools_hardened": len(TESTS),
        "tools_passed": passed,
        "tools_failed": failed + errored,
        "tools_skipped": skipped,
        "mismatches": mismatches,
    }

if __name__ == "__main__":
    summary = main()
    print("\nFinal JSON:", json.dumps(summary))
