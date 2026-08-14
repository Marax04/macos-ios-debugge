#!/usr/bin/env python3
"""
Rigorous validator for module 'symbols_v6'.

Calls 10 MCP tools and compares outputs against independently-computed
Python truth values derived from reading the Rust source in
crates/rustre-symbols/src/lib.rs.

Saves report to validation/rigorous_symbols_v6.json.
"""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

EXE = r"C:\Users\Fra\Desktop\RustRE\target\release\rustre-mcp.exe"
REPORT = r"C:\Users\Fra\Desktop\RustRE\validation\rigorous_symbols_v6.json"

# ---------------------------------------------------------------------------
# MCP session helpers
# ---------------------------------------------------------------------------

def start_session():
    p = subprocess.Popen(
        [EXE, "--transport=stdio"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        bufsize=0,
    )
    _send(p, {"jsonrpc": "2.0", "id": 1, "method": "initialize",
               "params": {"protocolVersion": "2024-11-05",
                          "capabilities": {}, "clientInfo": {"name": "rigorous_v6", "version": "1"}}})
    _recv(p)
    _send(p, {"jsonrpc": "2.0", "method": "notifications/initialized"})
    return p


def _send(p, req):
    p.stdin.write((json.dumps(req) + "\n").encode())
    p.stdin.flush()


def _recv(p):
    line = p.stdout.readline()
    if not line:
        raise RuntimeError("MCP server died")
    return json.loads(line)


_rid = 10

def call_tool(p, name, args):
    global _rid
    _rid += 1
    _send(p, {"jsonrpc": "2.0", "id": _rid, "method": "tools/call",
               "params": {"name": name, "arguments": args}})
    resp = _recv(p)
    if "error" in resp:
        raise RuntimeError(f"tool error: {resp['error']}")
    text = resp["result"]["content"][0]["text"]
    return json.loads(text)


# ---------------------------------------------------------------------------
# Independent Python truth implementations
# ---------------------------------------------------------------------------

# 1. SymKind Display strings (uses Debug format in Rust, i.e. variant name)
EXPECTED_SYMKIND_DISPLAY = [
    "Function", "Data", "Label", "Section", "File",
    "Type", "Namespace", "TLS", "IFunc", "Common", "Unknown",
]

# 2. SymbolSource::priority() — from Rust match arms
SYMBOL_SOURCE_ORDER = ["Pdb", "Dwarf", "CodeView", "Stabs", "Flirt", "Manual",
                        "Inferred", "Import", "Export", "Elf", "Pe", "Ai"]
SYMBOL_SOURCE_PRIORITY = {
    "Pdb": 90, "Dwarf": 90, "CodeView": 90,
    "Stabs": 80, "Flirt": 70, "Manual": 100,
    "Inferred": 30, "Import": 60, "Export": 60,
    "Elf": 55, "Pe": 55, "Ai": 50,
}

def expected_source_priorities():
    return [[s, SYMBOL_SOURCE_PRIORITY[s]] for s in SYMBOL_SOURCE_ORDER]

# 3. SyntheticSymbolGen — uppercase hex format
def synth_names(addr: int):
    h = f"{addr:X}"
    return {
        "function": f"sub_{h}",
        "data":     f"byte_{h}",
        "label":    f"loc_{h}",
        "dword":    f"dword_{h}",
        "qword":    f"qword_{h}",
    }

# 4. FunctionBoundary — half-open [start, end)
def fb_size(start, end):       return max(0, end - start)          # saturating_sub
def fb_contains(start, end, addr): return start <= addr < end
def fb_overlaps(s1, e1, s2, e2):
    return s1 < e1 and s2 < e2 and s1 < e2 and s2 < e1
def fb_display(name, start, end): return f"{name} [{hex(start)}..{hex(end)})"

# 5. PdbSymbolServer::pdb_url
# Rust format: "{base}\{pdb}\{guid_no_dashes}{age:X}/{pdb}"
def pdb_url(base, pdb_name, guid, age):
    # Rust format: "{}/{}/{}{:X}/{}" — all forward slashes
    guid_clean = guid.replace("-", "")
    return f"{base}/{pdb_name}/{guid_clean}{age:X}/{pdb_name}"

# 6. AddressToSymbolMap — sorted vec, binary search
def addr_map_names(addrs):
    return {a: f"f_{a:x}" for a in addrs}

def addr_map_exact(addrs, probe):
    names = addr_map_names(addrs)
    return names.get(probe)

def addr_map_floor(addrs, probe):
    sorted_addrs = sorted(addrs)
    # largest addr <= probe
    result = None
    for a in sorted_addrs:
        if a <= probe:
            result = a
    return addr_map_names(addrs).get(result) if result is not None else None

# 7. SymbolConflictResolver::KeepFirst
# Filter symbols: keep first encountered per address
def conflict_keep_first(names, addr):
    seen = set()
    kept = []
    for name in names:
        if addr not in seen:
            seen.add(addr)
            kept.append(name)
    return kept

# 8. UnifiedSymbolTable: nearest_below(probe) = largest addr <= probe
def nearest_below(entries, probe):
    # entries: list of (name, addr) sorted by addr
    result = None
    for name, addr in sorted(entries, key=lambda x: x[1]):
        if addr <= probe:
            result = name
    return result

def lookup_name_count(entries, name_q):
    return sum(1 for n, _ in entries if n == name_q)

# 9. try_demangle heuristic (mirrors Rust implementation)
def try_demangle_itanium(name: str):
    if not (name.startswith("_Z") or name.startswith("__Z")):
        return None
    if name.startswith("__Z"):
        s = name[3:]
    else:
        s = name[2:]
    if not s:
        return None
    if s.startswith("N"):
        inner_raw = s[1:]  # strip 'N'
        if inner_raw.endswith("E"):
            inner = inner_raw[:-1]
        else:
            inner = s  # unwrap_or(s) — original s before strip_prefix
        parts = decode_itanium_parts(inner)
        if not parts:
            return None
        return "::".join(parts)
    parts = decode_itanium_parts(s)
    if not parts:
        return None
    return "::".join(parts)


def decode_itanium_parts(s: str):
    parts = []
    while s:
        if not s[0].isdigit():
            break
        len_end = 0
        while len_end < len(s) and s[len_end].isdigit():
            len_end += 1
        try:
            length = int(s[:len_end])
        except ValueError:
            break
        s = s[len_end:]
        if length > len(s):
            break
        parts.append(s[:length])
        s = s[length:]
    return parts


def try_demangle_rust(name: str):
    if name.startswith("_R"):
        return f"<rust>{name}"
    return None


def try_demangle_msvc(name: str):
    if not name.startswith("?"):
        return None
    inner = name[1:]
    base = inner.split("@@")[0]
    result = base.replace("@", "::")
    return result if result else None


def try_demangle(name: str):
    return (try_demangle_itanium(name)
            or try_demangle_rust(name)
            or try_demangle_msvc(name))

# 10. demangle_all_table: same as try_demangle per entry, but only sets
#     demangled_name when not already set.
def demangle_all_result(names):
    out = []
    for name in names:
        d = try_demangle(name)
        out.append([name, d])
    return out


# ---------------------------------------------------------------------------
# Test runner
# ---------------------------------------------------------------------------

def check(tool, field, got, expected, mismatches, notes_list, *, exact=True):
    if exact:
        ok = got == expected
    else:
        ok = got == expected  # alias; caller can relax
    if ok:
        return True
    mismatches.append({
        "tool": tool,
        "field": field,
        "expected": expected,
        "got": got,
    })
    notes_list.append(f"MISMATCH {tool}:{field}: expected={expected!r} got={got!r}")
    return False


def run():
    mismatches = []
    notes = []
    checks_passed = 0
    checks_failed = 0

    p = start_session()
    try:
        results = _run_checks(p, mismatches, notes)
        checks_passed, checks_failed = results
    finally:
        p.stdin.close()
        p.wait(timeout=5)

    tools_hardened = 10
    report = {
        "module": "symbols_v6",
        "tools_hardened": tools_hardened,
        "checks_passed": checks_passed,
        "checks_failed": checks_failed,
        "mismatches": mismatches,
        "notes": notes,
    }
    Path(REPORT).write_text(json.dumps(report, indent=2))
    print(f"Report saved to {REPORT}")
    print(f"checks_passed={checks_passed} checks_failed={checks_failed} mismatches={len(mismatches)}")
    for n in notes:
        print(n)
    return report


def _run_checks(p, mismatches, notes):
    passed = 0
    failed = 0

    def ok():
        nonlocal passed
        passed += 1

    def fail(tool, field, got, expected):
        nonlocal failed
        failed += 1
        check(tool, field, got, expected, mismatches, notes)

    def chk(tool, field, got, expected):
        if got == expected:
            ok()
        else:
            fail(tool, field, got, expected)

    # ── 1. symbols_v6_symkind_display_all ────────────────────────────────────
    r1 = call_tool(p, "symbols_v6_symkind_display_all", {})
    chk("symkind_display_all", "kinds", r1.get("kinds"), EXPECTED_SYMKIND_DISPLAY)

    # ── 2. symbols_v6_source_priority_all ────────────────────────────────────
    r2 = call_tool(p, "symbols_v6_source_priority_all", {})
    expected_prio = expected_source_priorities()
    chk("source_priority_all", "priorities", r2.get("priorities"), expected_prio)

    # ── 3. symbols_v6_synthetic_names_all ────────────────────────────────────
    ADDR = 0x1000
    r3 = call_tool(p, "symbols_v6_synthetic_names_all", {"addr": ADDR})
    exp3 = synth_names(ADDR)
    for field in ("function", "data", "label", "dword", "qword"):
        chk("synthetic_names_all", field, r3.get(field), exp3[field])

    # ── 4. symbols_v6_function_boundary_ops ──────────────────────────────────
    S, E, PR, OS, OE = 0x1000, 0x1100, 0x1050, 0x10F0, 0x1200
    r4 = call_tool(p, "symbols_v6_function_boundary_ops",
                   {"start": S, "end": E, "probe": PR, "o_start": OS, "o_end": OE})
    chk("function_boundary_ops", "size_a",         r4.get("size_a"),         fb_size(S, E))
    chk("function_boundary_ops", "contains_probe", r4.get("contains_probe"), fb_contains(S, E, PR))
    chk("function_boundary_ops", "overlaps_ab",    r4.get("overlaps_ab"),    fb_overlaps(S, E, OS, OE))
    chk("function_boundary_ops", "display_a",      r4.get("display_a"),      fb_display("a", S, E))

    # ── 5. symbols_v6_pdb_url_build ──────────────────────────────────────────
    PDB_NAME = "ntdll.pdb"
    GUID     = "AABBCCDD-1122-3344-5566-778899AABBCC"
    AGE      = 1
    MSDL     = "https://msdl.microsoft.com/download/symbols"
    r5 = call_tool(p, "symbols_v6_pdb_url_build",
                   {"pdb": PDB_NAME, "guid": GUID, "age": AGE})
    exp_url = pdb_url(MSDL, PDB_NAME, GUID, AGE)
    chk("pdb_url_build", "url", r5.get("url"), exp_url)

    # ── 6. symbols_v6_addr_map_lookup ────────────────────────────────────────
    ADDRS = [0x1000, 0x2000, 0x3000]
    PROBE = 0x2000
    r6 = call_tool(p, "symbols_v6_addr_map_lookup", {"addrs": ADDRS, "probe": PROBE})
    chk("addr_map_lookup", "len",   r6.get("len"),   len(ADDRS))
    chk("addr_map_lookup", "exact", r6.get("exact"), addr_map_exact(ADDRS, PROBE))
    chk("addr_map_lookup", "floor", r6.get("floor"), addr_map_floor(ADDRS, PROBE))

    # ── 7. symbols_v6_conflict_resolve ───────────────────────────────────────
    NAMES_CR = ["alpha", "beta", "gamma"]
    ADDR_CR  = 0x1000
    r7 = call_tool(p, "symbols_v6_conflict_resolve",
                   {"names": NAMES_CR, "addr": ADDR_CR})
    exp_kept = conflict_keep_first(NAMES_CR, ADDR_CR)
    chk("conflict_resolve", "kept",  r7.get("kept"),  exp_kept)
    chk("conflict_resolve", "count", r7.get("count"), len(exp_kept))

    # ── 8. symbols_v6_unified_table_ops ──────────────────────────────────────
    ENTRIES = [{"name": "foo", "addr": 0x1000}, {"name": "bar", "addr": 0x2000}]
    PROBE8  = 0x1500
    NAME_Q  = "foo"
    r8 = call_tool(p, "symbols_v6_unified_table_ops",
                   {"entries": ENTRIES, "probe": PROBE8, "name_q": NAME_Q})
    py_entries = [(e["name"], e["addr"]) for e in ENTRIES]
    chk("unified_table_ops", "len",           r8.get("len"),           len(ENTRIES))
    chk("unified_table_ops", "nearest_below", r8.get("nearest_below"), nearest_below(py_entries, PROBE8))
    chk("unified_table_ops", "by_name_count", r8.get("by_name_count"), lookup_name_count(py_entries, NAME_Q))

    # ── 9. symbols_v6_try_demangle_batch ─────────────────────────────────────
    BATCH = ["_Z3foo", "plain", "_Rtest", "?abc@@YAXXZ"]
    r9 = call_tool(p, "symbols_v6_try_demangle_batch", {"names": BATCH})
    results9 = r9.get("results", [])
    expected9 = [[n, try_demangle(n)] for n in BATCH]
    chk("try_demangle_batch", "results", results9, expected9)
    chk("try_demangle_batch", "count",   r9.get("count"), len(BATCH))

    # ── 10. symbols_v6_demangle_all_table ────────────────────────────────────
    NAMES_D = ["_Z3foo", "plain"]
    r10 = call_tool(p, "symbols_v6_demangle_all_table", {"names": NAMES_D})
    exp10 = demangle_all_result(NAMES_D)
    chk("demangle_all_table", "results", r10.get("results"), exp10)
    chk("demangle_all_table", "len",     r10.get("len"),     len(NAMES_D))

    return passed, failed


if __name__ == "__main__":
    report = run()
    sys.exit(0 if report["checks_failed"] == 0 else 1)
