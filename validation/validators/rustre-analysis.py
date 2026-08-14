#!/usr/bin/env python3
"""
Standalone validator for the rustre-analysis crate.

Reimplements the deterministic, externally-testable functions in pure Python
(stdlib only) so results can be cross-checked against the Rust crate.

Usage:
    echo '{"fn":"scan_prologues","base":0,"bytes_hex":"554889E5..."}' | python rustre-analysis.py
    python rustre-analysis.py            # runs the built-in self-test main()
"""

import hashlib
import json
import re
import struct
import sys
from collections import defaultdict, deque
from typing import Any


# ---------------------------------------------------------------------------
# Track A — byte-scanner oracles
# ---------------------------------------------------------------------------

_PROLOGUE_PATTERNS = [
    (re.compile(rb"\x55\x48\x89\xE5"), 80, 4, "push_rbp_mov_rbp_rsp"),
    (re.compile(rb"\x55\x48\x8B\xEC"), 80, 4, "push_rbp_mov_rbp_rsp_alt"),
    (re.compile(rb"\x48\x83\xEC"),     70, 3, "sub_rsp_imm8"),
]

_MAX_RESULTS = 1_048_576


def validator_scan_prologues(base: int, data: bytes) -> list[dict]:
    """Mirror of FunctionBoundaryAnalysis::scan_prologues.

    Linear sweep: at each i, test the three signatures in order; on match emit
    {start, end=start, confidence, method} and advance i by the pattern length;
    otherwise advance by 1. Cap at _MAX_RESULTS.
    """
    out: list[dict] = []
    i = 0
    n = len(data)
    while i < n and len(out) < _MAX_RESULTS:
        matched = False
        for pat, conf, plen, method in _PROLOGUE_PATTERNS:
            if pat.match(data, i):
                out.append({
                    "start": (base + i) & 0xFFFFFFFFFFFFFFFF,
                    "end":   (base + i) & 0xFFFFFFFFFFFFFFFF,
                    "confidence": conf,
                    "method": method,
                })
                i += plen
                matched = True
                break
        if not matched:
            i += 1
    return out


def validator_scan_call_targets(base: int, data: bytes) -> list[int]:
    """Mirror of FunctionBoundaryAnalysis::scan_call_targets.

    For every i where data[i] == 0xE8 and i+5 <= len(data), compute
    target = base + i + 5 + sign_extend(i32_le(data[i+1:i+5])) mod 2^64.
    Returns sorted, deduplicated u64 list. Cap at _MAX_RESULTS.
    """
    targets: set[int] = set()
    n = len(data)
    i = 0
    while i < n and len(targets) < _MAX_RESULTS:
        if data[i] == 0xE8 and i + 5 <= n:
            rel = struct.unpack("<i", data[i + 1:i + 5])[0]
            t = (base + i + 5 + rel) & 0xFFFFFFFFFFFFFFFF
            targets.add(t)
        i += 1
    return sorted(targets)


def validator_sweep(base: int, data: bytes) -> list[dict]:
    """Mirror of LinearSweepAnalyzer::sweep — composes the two scans above.

    Confidence is bumped to 90 if a call target lands on a prologue's start,
    else the prologue's own confidence is kept (semantics per report).
    """
    prologues = validator_scan_prologues(base, data)
    targets = set(validator_scan_call_targets(base, data))
    out = []
    for p in prologues:
        conf = 90 if p["start"] in targets else p["confidence"]
        out.append({**p, "confidence": conf})
    return out


# ---------------------------------------------------------------------------
# Track B — algorithmic / data-structural items
# ---------------------------------------------------------------------------

def validator_compute_hash(data: bytes) -> int:
    """Stable 64-bit hash for cache-keying. Deterministic; algorithm pinned
    here to BLAKE2b-64 — value-equality with Rust isn't asserted, only
    determinism + collision-resistance properties.
    """
    h = hashlib.blake2b(data, digest_size=8).digest()
    return int.from_bytes(h, "little", signed=False)


def validator_schedule(passes: list[dict]) -> dict:
    """Mirror of PassScheduler::schedule — Kahn's topological sort.

    Input: list of {name: str, dependencies: [str, ...]}.
    Output: {"ok": True, "order": [...]} or {"ok": False, "error": "cycle"}.
    """
    deps: dict[str, set[str]] = {p["name"]: set(p.get("dependencies", [])) for p in passes}
    rev: dict[str, set[str]] = defaultdict(set)
    for n, ds in deps.items():
        for d in ds:
            rev[d].add(n)
    indeg = {n: len(ds) for n, ds in deps.items()}
    q = deque(sorted(n for n, d in indeg.items() if d == 0))
    order: list[str] = []
    while q:
        n = q.popleft()
        order.append(n)
        for m in sorted(rev.get(n, ())):
            indeg[m] -= 1
            if indeg[m] == 0:
                q.append(m)
    if len(order) != len(deps):
        return {"ok": False, "error": "cycle"}
    return {"ok": True, "order": order}


def validator_schedule_groups(passes: list[dict]) -> dict:
    """Mirror of PassScheduler::schedule_groups — Kahn grouped by level."""
    deps: dict[str, set[str]] = {p["name"]: set(p.get("dependencies", [])) for p in passes}
    rev: dict[str, set[str]] = defaultdict(set)
    for n, ds in deps.items():
        for d in ds:
            rev[d].add(n)
    indeg = {n: len(ds) for n, ds in deps.items()}
    groups: list[list[str]] = []
    remaining = set(deps)
    while remaining:
        ready = sorted(n for n in remaining if indeg[n] == 0)
        if not ready:
            return {"ok": False, "error": "cycle"}
        groups.append(ready)
        for n in ready:
            remaining.discard(n)
            for m in rev.get(n, ()):
                indeg[m] -= 1
    return {"ok": True, "groups": groups}


# CrossReferenceDb mirror -----------------------------------------------------

class CrossReferenceDb:
    """Multimap with sorted-dedup target lists per (from, to) bucket."""

    def __init__(self) -> None:
        self._to: dict[int, set[int]] = defaultdict(set)      # xrefs_to[dst] = {srcs}
        self._from: dict[int, set[int]] = defaultdict(set)    # xrefs_from[src] = {dsts}
        self._calls: dict[int, set[int]] = defaultdict(set)   # calls[src] = {dsts}
        self._count = 0

    def add(self, src: int, dst: int, kind: str = "ref") -> None:
        self._to[dst].add(src)
        self._from[src].add(dst)
        if kind == "call":
            self._calls[src].add(dst)
        self._count += 1

    def xrefs_to(self, dst: int) -> list[int]:    return sorted(self._to.get(dst, ()))
    def xrefs_from(self, src: int) -> list[int]:  return sorted(self._from.get(src, ()))
    def calls(self, src: int) -> list[int]:       return sorted(self._calls.get(src, ()))
    def call_targets(self) -> list[int]:
        out: set[int] = set()
        for s in self._calls.values():
            out |= s
        return sorted(out)
    def count(self) -> int:                       return self._count


def validator_xref_roundtrip(adds: list[dict]) -> dict:
    """Replay adds, return summary used by property tests."""
    db = CrossReferenceDb()
    for a in adds:
        db.add(int(a["src"]), int(a["dst"]), a.get("kind", "ref"))
    srcs = sorted({int(a["src"]) for a in adds})
    dsts = sorted({int(a["dst"]) for a in adds})
    return {
        "count": db.count(),
        "xrefs_to":   {str(d): db.xrefs_to(d) for d in dsts},
        "xrefs_from": {str(s): db.xrefs_from(s) for s in srcs},
        "calls":      {str(s): db.calls(s) for s in srcs},
        "call_targets": db.call_targets(),
    }


# Call-graph (de)serialization round-trip ------------------------------------

def validator_serialize_call_graph(graph: dict) -> str:
    """Canonical JSON serialization of {nodes:[int], edges:[[u,v], ...]}."""
    nodes = sorted({int(n) for n in graph.get("nodes", [])})
    edges = sorted({(int(u), int(v)) for u, v in graph.get("edges", [])})
    return json.dumps({"nodes": nodes, "edges": [list(e) for e in edges]},
                      separators=(",", ":"), sort_keys=True)


def validator_deserialize_call_graph(blob: str) -> dict:
    g = json.loads(blob)
    return {"nodes": list(g["nodes"]),
            "edges": [tuple(e) for e in g["edges"]]}


# AnalysisStats mirror -------------------------------------------------------

def validator_analysis_stats(records: list[dict]) -> dict:
    """Each record: {pass: str, duration_ms: float, ok: bool}."""
    ok = [r for r in records if r["ok"]]
    err = [r for r in records if not r["ok"]]
    durations = [float(r["duration_ms"]) for r in ok]
    avg = sum(durations) / len(durations) if durations else 0.0
    slowest = max(ok, key=lambda r: r["duration_ms"])["pass"] if ok else None
    return {
        "ok_count":   len(ok),
        "err_count":  len(err),
        "avg_duration_ms": avg,
        "slowest_pass":    slowest,
    }


# AnalysisReport::build ------------------------------------------------------

def validator_report_build(functions: list, strings: list) -> dict:
    return {
        "total_functions": len(functions),
        "total_strings":   len(strings),
        "summary": f"{len(functions)} fn / {len(strings)} str",
    }


# ---------------------------------------------------------------------------
# Dispatcher / CLI
# ---------------------------------------------------------------------------

_DISPATCH = {
    "scan_prologues":       lambda r: validator_scan_prologues(int(r["base"]), bytes.fromhex(r["bytes_hex"])),
    "scan_call_targets":    lambda r: validator_scan_call_targets(int(r["base"]), bytes.fromhex(r["bytes_hex"])),
    "sweep":                lambda r: validator_sweep(int(r["base"]), bytes.fromhex(r["bytes_hex"])),
    "compute_hash":         lambda r: validator_compute_hash(bytes.fromhex(r["bytes_hex"])),
    "schedule":             lambda r: validator_schedule(r["passes"]),
    "schedule_groups":      lambda r: validator_schedule_groups(r["passes"]),
    "xref_roundtrip":       lambda r: validator_xref_roundtrip(r["adds"]),
    "serialize_call_graph": lambda r: validator_serialize_call_graph(r["graph"]),
    "deserialize_call_graph": lambda r: validator_deserialize_call_graph(r["blob"]),
    "analysis_stats":       lambda r: validator_analysis_stats(r["records"]),
    "report_build":         lambda r: validator_report_build(r["functions"], r["strings"]),
}


def _run_request(req: dict) -> Any:
    fn = req.get("fn")
    if fn not in _DISPATCH:
        return {"error": f"unknown fn '{fn}'", "available": sorted(_DISPATCH)}
    return _DISPATCH[fn](req)


def main() -> None:
    # If stdin has data, treat it as a JSON request.
    if not sys.stdin.isatty():
        raw = sys.stdin.read().strip()
        if raw:
            try:
                req = json.loads(raw)
            except json.JSONDecodeError as e:
                json.dump({"error": f"bad json: {e}"}, sys.stdout)
                return
            json.dump(_run_request(req), sys.stdout, default=list)
            return

    # Otherwise, run built-in self-tests.
    results: dict[str, Any] = {}

    # 1) Prologue scan: place a 55 48 89 E5 at offset 0, a sub_rsp at 8.
    buf = bytes.fromhex("554889E5" + "90909090" + "4883EC20" + "90")
    p = validator_scan_prologues(0x1000, buf)
    results["scan_prologues"] = p
    assert p[0]["start"] == 0x1000 and p[0]["confidence"] == 80
    assert p[1]["start"] == 0x1008 and p[1]["confidence"] == 70

    # 2) Call targets: E8 00 00 00 00 at offset 0 → target = base + 5.
    buf2 = bytes.fromhex("E800000000" + "E8FBFFFFFF")  # second call: rel=-5 → base+5
    t = validator_scan_call_targets(0x2000, buf2)
    results["scan_call_targets"] = t
    assert 0x2005 in t

    # 3) Sweep: prologue at offset 0 that is *also* a call target → confidence 90.
    buf3 = bytes.fromhex("554889E5" + "E8F7FFFFFF")  # rel=-9 → target = 5+9-9? compute
    # call at i=4: target = base + 4 + 5 + (-9) = base. So base must equal prologue start.
    s = validator_sweep(0x3000, buf3)
    results["sweep"] = s
    assert s[0]["confidence"] == 90

    # 4) compute_hash determinism.
    h1 = validator_compute_hash(b"hello"); h2 = validator_compute_hash(b"hello")
    h3 = validator_compute_hash(b"world")
    assert h1 == h2 and h1 != h3
    results["compute_hash"] = {"hello": h1, "world": h3}

    # 5) schedule + groups.
    passes = [
        {"name": "c", "dependencies": ["a", "b"]},
        {"name": "a", "dependencies": []},
        {"name": "b", "dependencies": ["a"]},
    ]
    sched = validator_schedule(passes)
    grp   = validator_schedule_groups(passes)
    assert sched["ok"] and sched["order"].index("a") < sched["order"].index("c")
    assert grp["ok"] and grp["groups"][0] == ["a"]
    results["schedule"] = sched
    results["schedule_groups"] = grp
    cycle = validator_schedule([{"name": "x", "dependencies": ["y"]},
                                {"name": "y", "dependencies": ["x"]}])
    assert not cycle["ok"]
    results["schedule_cycle"] = cycle

    # 6) xref roundtrip.
    xr = validator_xref_roundtrip([
        {"src": 0x100, "dst": 0x200, "kind": "call"},
        {"src": 0x100, "dst": 0x200, "kind": "call"},  # dup
        {"src": 0x108, "dst": 0x200, "kind": "ref"},
    ])
    assert xr["count"] == 3
    assert xr["xrefs_to"]["512"] == [0x100, 0x108]
    assert xr["calls"]["256"] == [0x200]
    results["xref_roundtrip"] = xr

    # 7) call-graph roundtrip.
    g = {"nodes": [3, 1, 2], "edges": [[1, 2], [2, 3]]}
    blob = validator_serialize_call_graph(g)
    g2 = validator_deserialize_call_graph(blob)
    assert g2["nodes"] == [1, 2, 3]
    results["call_graph_roundtrip"] = {"blob": blob, "decoded": g2}

    # 8) analysis_stats.
    st = validator_analysis_stats([
        {"pass": "p1", "duration_ms": 10.0, "ok": True},
        {"pass": "p2", "duration_ms": 30.0, "ok": True},
        {"pass": "p3", "duration_ms": 5.0,  "ok": False},
    ])
    assert st["slowest_pass"] == "p2" and st["err_count"] == 1
    results["analysis_stats"] = st

    # 9) report_build.
    rb = validator_report_build([1, 2, 3], ["a", "b"])
    assert rb["total_functions"] == 3 and rb["total_strings"] == 2
    results["report_build"] = rb

    print(json.dumps({"self_test": "ok", "results": results}, indent=2, default=list))


if __name__ == "__main__":
    main()
