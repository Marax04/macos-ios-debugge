"""
Independent Python validator for the `rustre-analysis-xref` crate.

Re-implements the deterministic, testable behaviors of the crate using
only Python stdlib + (optionally) networkx, pefile. No Rust import, no MCP.

Each validator_<name>(input) -> output mirrors a public surface of the crate
described in validation/reports/rustre-analysis-xref.md.

Usage:
  - As a module: import and call validator_* functions.
  - As a script with JSON via stdin:  echo {"fn":"x86_call_target","input":{...}} | python rustre-analysis-xref.py
  - As a script with no stdin: runs main() with fixed inputs and prints a self-test JSON report.
"""

from __future__ import annotations

import json
import os
import struct
import subprocess
import sys
from collections import Counter, defaultdict, deque
from typing import Any, Dict, Iterable, List, Optional, Tuple


# ---------------------------------------------------------------------------
# Optional deps (auto-install on demand)
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


# ---------------------------------------------------------------------------
# XrefKind — mirror of the Rust enum
# ---------------------------------------------------------------------------
XREF_KINDS = [
    "CodeCall", "CodeJump", "CodeReturn",
    "DataRead", "DataWrite", "DataAddress", "DataPointer",
    "ImportByName", "ImportByOrdinal",
    "StringRef", "TypeRef", "ThunkCall",
]

_CODE_KINDS = {"CodeCall", "CodeJump", "CodeReturn", "ThunkCall"}
_DATA_KINDS = {"DataRead", "DataWrite", "DataAddress", "DataPointer"}
_IMPORT_KINDS = {"ImportByName", "ImportByOrdinal"}


def validator_xrefkind_is_code(kind: str) -> bool:
    return kind in _CODE_KINDS


def validator_xrefkind_is_data(kind: str) -> bool:
    return kind in _DATA_KINDS


def validator_xrefkind_is_import(kind: str) -> bool:
    return kind in _IMPORT_KINDS


def validator_xrefkind_all() -> List[str]:
    return list(XREF_KINDS)


def validator_xrefkind_partition() -> Dict[str, bool]:
    """Sanity: every kind is in at most one category; partitions match docs."""
    ok = True
    for k in XREF_KINDS:
        flags = (
            validator_xrefkind_is_code(k),
            validator_xrefkind_is_data(k),
            validator_xrefkind_is_import(k),
        )
        # At most one True (StringRef/TypeRef belong to none, that's allowed)
        if sum(flags) > 1:
            ok = False
    return {"partition_ok": ok}


# ---------------------------------------------------------------------------
# Xref / Display
# ---------------------------------------------------------------------------
def validator_xref_display(xref: Dict[str, Any]) -> str:
    """Mirrors the `Display` impl: '0xFROM -> 0xTO [kind] "tag"' (tag optional)."""
    from_addr = int(xref["from"])
    to_addr = int(xref["to"])
    kind = xref["kind"]
    tag = xref.get("tag")
    base = f"0x{from_addr:X} -> 0x{to_addr:X} [{kind}]"
    if tag:
        base += f' "{tag}"'
    return base


# ---------------------------------------------------------------------------
# XrefFilter — pure predicate AND
# ---------------------------------------------------------------------------
def validator_xreffilter_matches(flt: Dict[str, Any], xref: Dict[str, Any]) -> bool:
    if "with_kinds" in flt and flt["with_kinds"] is not None:
        if xref["kind"] not in set(flt["with_kinds"]):
            return False
    if "from_range" in flt and flt["from_range"] is not None:
        lo, hi = flt["from_range"]
        if not (lo <= xref["from"] < hi):
            return False
    if "to_range" in flt and flt["to_range"] is not None:
        lo, hi = flt["to_range"]
        if not (lo <= xref["to"] < hi):
            return False
    if flt.get("with_tag_required") and not xref.get("tag"):
        return False
    if flt.get("tag_contains"):
        if not xref.get("tag") or flt["tag_contains"] not in xref["tag"]:
            return False
    if "min_from" in flt and flt["min_from"] is not None:
        if xref["from"] < flt["min_from"]:
            return False
    if "max_to" in flt and flt["max_to"] is not None:
        if xref["to"] > flt["max_to"]:
            return False
    return True


# ---------------------------------------------------------------------------
# XrefDatabase — minimal Python replica
# ---------------------------------------------------------------------------
class PyXrefDatabase:
    def __init__(self):
        self.records: List[Dict[str, Any]] = []

    def add(self, x: Dict[str, Any]) -> None:
        rec = {
            "from": int(x["from"]),
            "to": int(x["to"]),
            "kind": x["kind"],
            "instr_size": int(x.get("instr_size", 0)),
            "tag": x.get("tag"),
        }
        self.records.append(rec)

    def xrefs_from(self, addr: int) -> List[Dict[str, Any]]:
        return [r for r in self.records if r["from"] == addr]

    def xrefs_to(self, addr: int) -> List[Dict[str, Any]]:
        return [r for r in self.records if r["to"] == addr]

    def callers_of(self, addr: int) -> List[int]:
        return sorted({r["from"] for r in self.records
                       if r["to"] == addr and r["kind"] in ("CodeCall", "ThunkCall")})

    def callees_of(self, addr: int) -> List[int]:
        return sorted({r["to"] for r in self.records
                       if r["from"] == addr and r["kind"] in ("CodeCall", "ThunkCall")})

    def callee_count(self, addr: int) -> int:
        return len(self.callees_of(addr))

    def caller_count(self, addr: int) -> int:
        return len(self.callers_of(addr))

    def is_leaf_function(self, addr: int) -> bool:
        return self.callee_count(addr) == 0

    def hot_functions(self, top_n: int) -> List[Tuple[int, int]]:
        c = Counter()
        for r in self.records:
            if r["kind"] in ("CodeCall", "ThunkCall"):
                c[r["to"]] += 1
        return c.most_common(top_n)

    def total_count(self) -> int:
        return len(self.records)

    def is_empty(self) -> bool:
        return not self.records

    def to_json(self) -> str:
        return json.dumps({"records": self.records}, sort_keys=True)

    @classmethod
    def from_json(cls, s: str) -> "PyXrefDatabase":
        db = cls()
        obj = json.loads(s)
        for r in obj.get("records", []):
            db.add(r)
        return db


def validator_db_insert_and_query(xrefs: List[Dict[str, Any]]) -> Dict[str, Any]:
    """For every added xref, must appear in both xrefs_from(from) and xrefs_to(to)."""
    db = PyXrefDatabase()
    for x in xrefs:
        db.add(x)
    ok = True
    for x in xrefs:
        if not any(r["to"] == x["to"] and r["kind"] == x["kind"]
                   for r in db.xrefs_from(int(x["from"]))):
            ok = False
        if not any(r["from"] == x["from"] and r["kind"] == x["kind"]
                   for r in db.xrefs_to(int(x["to"]))):
            ok = False
    return {"symmetric": ok, "total": db.total_count()}


def validator_db_json_roundtrip(xrefs: List[Dict[str, Any]]) -> Dict[str, Any]:
    db = PyXrefDatabase()
    for x in xrefs:
        db.add(x)
    s = db.to_json()
    db2 = PyXrefDatabase.from_json(s)
    a = sorted(json.dumps(r, sort_keys=True) for r in db.records)
    b = sorted(json.dumps(r, sort_keys=True) for r in db2.records)
    return {"equal": a == b, "n": len(a)}


def validator_db_hot_functions(
    xrefs: List[Dict[str, Any]], top_n: int
) -> List[List[int]]:
    db = PyXrefDatabase()
    for x in xrefs:
        db.add(x)
    return [[addr, cnt] for addr, cnt in db.hot_functions(top_n)]


def validator_db_counts(
    xrefs: List[Dict[str, Any]], addr: int
) -> Dict[str, Any]:
    db = PyXrefDatabase()
    for x in xrefs:
        db.add(x)
    return {
        "callee_count": db.callee_count(addr),
        "caller_count": db.caller_count(addr),
        "is_leaf": db.is_leaf_function(addr),
    }


# ---------------------------------------------------------------------------
# XrefGraph — implemented with networkx so we can cross-check the Rust crate
# ---------------------------------------------------------------------------
def _build_graph(edges: List[Tuple[int, int]]):
    nx = _ensure("networkx")
    g = nx.DiGraph()
    for u, v in edges:
        g.add_edge(u, v)
    return g, nx


def validator_graph_reachable_from(
    edges: List[List[int]], src: int
) -> List[int]:
    g, nx = _build_graph([tuple(e) for e in edges])
    if src not in g:
        return []
    return sorted(nx.descendants(g, src) | {src})


def validator_graph_is_reachable(
    edges: List[List[int]], src: int, dst: int
) -> bool:
    g, nx = _build_graph([tuple(e) for e in edges])
    if src not in g or dst not in g:
        return src == dst
    return nx.has_path(g, src, dst)


def validator_graph_bfs_distances(
    edges: List[List[int]], src: int
) -> Dict[str, int]:
    g, nx = _build_graph([tuple(e) for e in edges])
    if src not in g:
        return {}
    dist = nx.single_source_shortest_path_length(g, src)
    return {str(k): int(v) for k, v in dist.items()}


def validator_graph_topological_sort(
    edges: List[List[int]]
) -> Optional[List[int]]:
    g, nx = _build_graph([tuple(e) for e in edges])
    if not nx.is_directed_acyclic_graph(g):
        return None
    return list(nx.topological_sort(g))


def validator_graph_sccs(edges: List[List[int]]) -> List[List[int]]:
    g, nx = _build_graph([tuple(e) for e in edges])
    return [sorted(c) for c in nx.strongly_connected_components(g)]


# ---------------------------------------------------------------------------
# X86XrefScanner — minimal Python decoder for E8 / E9 rel32 + RIP-rel LEA
# ---------------------------------------------------------------------------
def _rel32_target(base: int, offset: int, instr_len: int, disp_bytes: bytes) -> int:
    disp = struct.unpack("<i", disp_bytes)[0]
    return (base + offset + instr_len + disp) & 0xFFFFFFFFFFFFFFFF


def validator_x86_scan_code(
    base: int,
    code: bytes | str,
    function_entries: Optional[List[int]] = None,
) -> List[Dict[str, Any]]:
    """Minimal scanner: emit CodeCall (E8), CodeJump/ThunkCall (E9),
    and DataAddress for RIP-relative LEA `48 8D 05 disp32`."""
    if isinstance(code, str):
        # accept hex string for convenience
        code = bytes.fromhex(code.replace(" ", ""))
    entries = set(function_entries or [])
    out: List[Dict[str, Any]] = []
    i = 0
    n = len(code)
    while i < n:
        b = code[i]
        if b == 0xE8 and i + 5 <= n:
            tgt = _rel32_target(base, i, 5, code[i + 1:i + 5])
            out.append({"from": base + i, "to": tgt, "kind": "CodeCall",
                        "instr_size": 5, "tag": None})
            i += 5
            continue
        if b == 0xE9 and i + 5 <= n:
            tgt = _rel32_target(base, i, 5, code[i + 1:i + 5])
            from_addr = base + i
            kind = "ThunkCall" if from_addr in entries else "CodeJump"
            out.append({"from": from_addr, "to": tgt, "kind": kind,
                        "instr_size": 5, "tag": None})
            i += 5
            continue
        # RIP-rel LEA: 48 8D 05 disp32  (REX.W + LEA r/m, [rip+disp32], modrm=05)
        if (
            i + 7 <= n
            and code[i] == 0x48
            and code[i + 1] == 0x8D
            and code[i + 2] == 0x05
        ):
            tgt = _rel32_target(base, i, 7, code[i + 3:i + 7])
            out.append({"from": base + i, "to": tgt, "kind": "DataAddress",
                        "instr_size": 7, "tag": None})
            i += 7
            continue
        i += 1
    return out


# ---------------------------------------------------------------------------
# PE-level: xref_index_from_path / from_bytes
# ---------------------------------------------------------------------------
def _pe_text_section(path_or_bytes) -> Optional[Tuple[int, bytes]]:
    pefile = _ensure("pefile")
    if isinstance(path_or_bytes, (bytes, bytearray)):
        try:
            pe = pefile.PE(data=bytes(path_or_bytes), fast_load=True)
        except pefile.PEFormatError:
            return None
    else:
        try:
            pe = pefile.PE(path_or_bytes, fast_load=True)
        except pefile.PEFormatError:
            return None
    image_base = pe.OPTIONAL_HEADER.ImageBase
    # Prefer .text, else first executable section.
    chosen = None
    for sec in pe.sections:
        name = sec.Name.rstrip(b"\x00").decode("ascii", "replace")
        if name == ".text":
            chosen = sec
            break
    if chosen is None:
        IMAGE_SCN_MEM_EXECUTE = 0x20000000
        for sec in pe.sections:
            if sec.Characteristics & IMAGE_SCN_MEM_EXECUTE:
                chosen = sec
                break
    if chosen is None:
        return None
    va = image_base + chosen.VirtualAddress
    data = chosen.get_data()
    return va, data


def validator_xref_index_from_path(path: str) -> Dict[str, Any]:
    if not os.path.isfile(path):
        return {"error": "io::Error", "exists": False, "total": 0}
    sec = _pe_text_section(path)
    if sec is None:
        return {"total": 0, "is_pe": False}
    base, data = sec
    refs = validator_x86_scan_code(base, data)
    return {"total": len(refs), "is_pe": True, "base": base, "len": len(data)}


def validator_xref_index_from_bytes(data_hex: str) -> Dict[str, Any]:
    data = bytes.fromhex(data_hex)
    sec = _pe_text_section(data)
    if sec is None:
        return {"total": 0, "is_pe": False}
    base, txt = sec
    refs = validator_x86_scan_code(base, txt)
    return {"total": len(refs), "is_pe": True}


# ---------------------------------------------------------------------------
# Dispatcher / self-test
# ---------------------------------------------------------------------------
DISPATCH = {
    "xrefkind_is_code": lambda i: validator_xrefkind_is_code(i["kind"]),
    "xrefkind_is_data": lambda i: validator_xrefkind_is_data(i["kind"]),
    "xrefkind_is_import": lambda i: validator_xrefkind_is_import(i["kind"]),
    "xrefkind_all": lambda i: validator_xrefkind_all(),
    "xrefkind_partition": lambda i: validator_xrefkind_partition(),
    "xref_display": lambda i: validator_xref_display(i),
    "xreffilter_matches": lambda i: validator_xreffilter_matches(i["filter"], i["xref"]),
    "db_insert_and_query": lambda i: validator_db_insert_and_query(i["xrefs"]),
    "db_json_roundtrip": lambda i: validator_db_json_roundtrip(i["xrefs"]),
    "db_hot_functions": lambda i: validator_db_hot_functions(i["xrefs"], i["top_n"]),
    "db_counts": lambda i: validator_db_counts(i["xrefs"], i["addr"]),
    "graph_reachable_from": lambda i: validator_graph_reachable_from(i["edges"], i["src"]),
    "graph_is_reachable": lambda i: validator_graph_is_reachable(i["edges"], i["src"], i["dst"]),
    "graph_bfs_distances": lambda i: validator_graph_bfs_distances(i["edges"], i["src"]),
    "graph_topological_sort": lambda i: validator_graph_topological_sort(i["edges"]),
    "graph_sccs": lambda i: validator_graph_sccs(i["edges"]),
    "x86_scan_code": lambda i: validator_x86_scan_code(
        i["base"], i["code"], i.get("function_entries")),
    "xref_index_from_path": lambda i: validator_xref_index_from_path(i["path"]),
    "xref_index_from_bytes": lambda i: validator_xref_index_from_bytes(i["data_hex"]),
}


def main() -> None:
    # If stdin has JSON, dispatch; else run self-tests.
    if not sys.stdin.isatty():
        try:
            req = json.load(sys.stdin)
        except json.JSONDecodeError:
            req = None
        if isinstance(req, dict) and "fn" in req:
            fn = req["fn"]
            inp = req.get("input", {})
            if fn not in DISPATCH:
                print(json.dumps({"error": f"unknown fn: {fn}"}))
                return
            out = DISPATCH[fn](inp)
            print(json.dumps({"fn": fn, "output": out}, default=str))
            return

    # Self-tests with fixed inputs.
    report: Dict[str, Any] = {}
    report["partition"] = validator_xrefkind_partition()
    report["display"] = validator_xref_display(
        {"from": 0x1000, "to": 0x2000, "kind": "CodeCall", "tag": "main"}
    )
    # E8 disp32 = +0x10 from base=0x401000 at offset 0 -> 0x401015
    code = bytes.fromhex("E810000000")
    report["scan_E8"] = validator_x86_scan_code(0x401000, code)
    # E9 at function entry -> ThunkCall
    code2 = bytes.fromhex("E900000000")
    report["scan_E9_thunk"] = validator_x86_scan_code(
        0x401000, code2, function_entries=[0x401000]
    )
    # RIP-rel LEA 48 8D 05 10 00 00 00 at 0x401000 -> 0x401017
    code3 = bytes.fromhex("488D0510000000")
    report["scan_lea"] = validator_x86_scan_code(0x401000, code3)
    # Graph tests
    report["topo_dag"] = validator_graph_topological_sort(
        [[1, 2], [2, 3], [1, 3]]
    )
    report["topo_cycle"] = validator_graph_topological_sort(
        [[1, 2], [2, 3], [3, 1]]
    )
    report["sccs"] = validator_graph_sccs([[1, 2], [2, 3], [3, 1], [4, 5]])
    report["bfs"] = validator_graph_bfs_distances(
        [[1, 2], [2, 3], [1, 4]], 1
    )
    # DB tests
    sample = [
        {"from": 0x1000, "to": 0x2000, "kind": "CodeCall"},
        {"from": 0x1010, "to": 0x2000, "kind": "CodeCall"},
        {"from": 0x1020, "to": 0x3000, "kind": "CodeJump"},
        {"from": 0x1030, "to": 0x2000, "kind": "ThunkCall"},
    ]
    report["symmetry"] = validator_db_insert_and_query(sample)
    report["roundtrip"] = validator_db_json_roundtrip(sample)
    report["hot"] = validator_db_hot_functions(sample, 2)
    report["counts"] = validator_db_counts(sample, 0x2000)
    # Non-PE bytes
    report["non_pe"] = validator_xref_index_from_bytes("00010203")
    print(json.dumps(report, indent=2, default=str))


if __name__ == "__main__":
    main()
