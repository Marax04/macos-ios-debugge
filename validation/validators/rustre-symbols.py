#!/usr/bin/env python3
"""
Standalone validator for the `rustre-symbols` crate.

Pure-Python (stdlib only) re-implementations of the principal pure helpers
exposed by the crate, per validation/reports/rustre-symbols.md (spec §7):

  - SymbolSource.priority() ordering
  - SymbolFilter::apply (address range / kinds / name_prefix / sources /
                        section_index / max)
  - AddressToSymbolMap (sorted vector + binary search for exact / floor)
  - SymbolStats::from_symbols (kind counters)
  - ExportTable / ImportTable grouping
  - SectionSymbols::in_section
  - SymbolConflictResolver (PreferDebug / PreferExport / KeepFirst /
                            KeepLast / KeepAll)
  - SymbolExporter (to_json / to_csv / to_idc / to_map)
  - SymbolCache (bounded FIFO LRU semantics: capacity, insert, get, clear)
  - SymbolStore-ish unique-by-address+name dedup helpers
  - UnifiedSymbol::end_address, FunctionBoundary::{size,contains,overlaps}

These validators take plain dict symbols of the shape:
  {"name": str, "address": int, "size": int, "kind": str,
   "source": str, "section_index": Optional[int],
   "ordinal": Optional[int], "module": Optional[str],
   "is_external": bool}

JSON-on-stdin protocol:
  echo {"fn":"filter_apply","args":{...}} | python rustre-symbols.py

Self-test:
  python rustre-symbols.py
"""
from __future__ import annotations

import bisect
import csv
import io
import json
import sys
from typing import Any, Dict, Iterable, List, Optional


# ---------------------------------------------------------------------------
# Taxonomy
# ---------------------------------------------------------------------------

# SymbolKind (spec §7)
SYMBOL_KINDS = {
    "Function", "Variable", "Label", "Thunk",
    "Import", "Export", "Section", "Module", "Namespace",
}

# Legacy SymKind
LEGACY_KINDS = {
    "Function", "Data", "Label", "Section", "File", "Type",
    "Namespace", "TLS", "IFunc", "Common", "Unknown",
}

# SymbolSource.priority(): higher = more authoritative for resolution
# (Debug formats outrank PE/ELF tables, which outrank inferred/AI.)
_SOURCE_PRIORITY = {
    "Pdb": 90,
    "Dwarf": 90,
    "CodeView": 80,
    "Stabs": 70,
    "Flirt": 60,
    "Manual": 100,
    "Export": 50,
    "Import": 50,
    "Pe": 40,
    "Elf": 40,
    "Inferred": 20,
    "Ai": 10,
}


def validator_source_priority(source: str) -> int:
    return _SOURCE_PRIORITY.get(source, 0)


# ---------------------------------------------------------------------------
# Symbol helpers
# ---------------------------------------------------------------------------

def _addr(sym: Dict[str, Any]) -> int:
    return int(sym.get("address", 0))


def _size(sym: Dict[str, Any]) -> int:
    return int(sym.get("size", 0))


def validator_end_address(sym: Dict[str, Any]) -> int:
    """UnifiedSymbol::end_address / Symbol::end_address."""
    return _addr(sym) + _size(sym)


def validator_contains(sym: Dict[str, Any], addr: int) -> bool:
    a = _addr(sym)
    return a <= addr < a + _size(sym)


def validator_display_name(sym: Dict[str, Any]) -> str:
    return sym.get("demangled_name") or sym.get("name") or ""


# ---------------------------------------------------------------------------
# FunctionBoundary
# ---------------------------------------------------------------------------

def validator_fb_size(fb: Dict[str, Any]) -> int:
    return int(fb["end"]) - int(fb["start"])


def validator_fb_contains(fb: Dict[str, Any], addr: int) -> bool:
    return int(fb["start"]) <= addr < int(fb["end"])


def validator_fb_overlaps(a: Dict[str, Any], b: Dict[str, Any]) -> bool:
    return int(a["start"]) < int(b["end"]) and int(b["start"]) < int(a["end"])


# ---------------------------------------------------------------------------
# SymbolFilter::apply
# ---------------------------------------------------------------------------

def validator_filter_apply(symbols: List[Dict[str, Any]],
                           filter_: Dict[str, Any]) -> List[Dict[str, Any]]:
    amin = filter_.get("address_min")
    amax = filter_.get("address_max")
    kinds = filter_.get("kinds")
    name_prefix = filter_.get("name_prefix")
    sources = filter_.get("sources")
    section_index = filter_.get("section_index")
    max_n = filter_.get("max")

    out: List[Dict[str, Any]] = []
    for s in symbols:
        a = _addr(s)
        if amin is not None and a < int(amin):
            continue
        if amax is not None and a > int(amax):
            continue
        if kinds and s.get("kind") not in set(kinds):
            continue
        if sources and s.get("source") not in set(sources):
            continue
        if section_index is not None \
                and s.get("section_index") != int(section_index):
            continue
        if name_prefix and not (s.get("name") or "").startswith(name_prefix):
            continue
        out.append(s)
        if max_n is not None and len(out) >= int(max_n):
            break
    return out


# ---------------------------------------------------------------------------
# AddressToSymbolMap
# ---------------------------------------------------------------------------

class AddressToSymbolMap:
    def __init__(self) -> None:
        self._items: List[tuple] = []  # (addr, symbol)
        self._sorted = True

    @classmethod
    def from_symbols(cls, syms: Iterable[Dict[str, Any]]) -> "AddressToSymbolMap":
        m = cls()
        for s in syms:
            m.insert(s)
        m.sort()
        return m

    def insert(self, sym: Dict[str, Any]) -> None:
        self._items.append((_addr(sym), sym))
        self._sorted = False

    def sort(self) -> None:
        self._items.sort(key=lambda kv: kv[0])
        self._sorted = True

    def lookup_exact(self, addr: int) -> Optional[Dict[str, Any]]:
        if not self._sorted:
            self.sort()
        keys = [k for k, _ in self._items]
        i = bisect.bisect_left(keys, addr)
        if i < len(keys) and keys[i] == addr:
            return self._items[i][1]
        return None

    def lookup_floor(self, addr: int) -> Optional[Dict[str, Any]]:
        if not self._sorted:
            self.sort()
        keys = [k for k, _ in self._items]
        i = bisect.bisect_right(keys, addr) - 1
        if i >= 0:
            return self._items[i][1]
        return None

    def __len__(self) -> int:
        return len(self._items)


def validator_lookup_exact(symbols, addr):
    return AddressToSymbolMap.from_symbols(symbols).lookup_exact(int(addr))


def validator_lookup_floor(symbols, addr):
    return AddressToSymbolMap.from_symbols(symbols).lookup_floor(int(addr))


# ---------------------------------------------------------------------------
# SymbolStats
# ---------------------------------------------------------------------------

def validator_stats_from_symbols(symbols: List[Dict[str, Any]]) -> Dict[str, int]:
    stats = dict(functions=0, data=0, labels=0, sections=0, files=0,
                 types=0, tls=0, ifunc=0, common=0, unknown=0, total=0)
    for s in symbols:
        k = s.get("kind", "Unknown")
        stats["total"] += 1
        if k == "Function":
            stats["functions"] += 1
        elif k in ("Data", "Variable"):
            stats["data"] += 1
        elif k == "Label":
            stats["labels"] += 1
        elif k == "Section":
            stats["sections"] += 1
        elif k == "File":
            stats["files"] += 1
        elif k == "Type":
            stats["types"] += 1
        elif k == "TLS":
            stats["tls"] += 1
        elif k == "IFunc":
            stats["ifunc"] += 1
        elif k == "Common":
            stats["common"] += 1
        else:
            stats["unknown"] += 1
    return stats


# ---------------------------------------------------------------------------
# ExportTable / ImportTable / SectionSymbols
# ---------------------------------------------------------------------------

def validator_export_table(symbols):
    exports = [s for s in symbols
               if s.get("kind") == "Export" or s.get("source") == "Export"]
    by_ord = {s["ordinal"]: s for s in exports if s.get("ordinal") is not None}
    by_name = {s.get("name"): s for s in exports if s.get("name")}
    return {
        "exports": exports,
        "by_ordinal": by_ord,
        "by_name": by_name,
        "len": len(exports),
        "is_empty": not exports,
    }


def validator_import_table(symbols):
    imports = [s for s in symbols
               if s.get("kind") == "Import" or s.get("source") == "Import"]
    by_name = {s.get("name"): s for s in imports if s.get("name")}
    grouped: Dict[str, List[Dict[str, Any]]] = {}
    for s in imports:
        m = s.get("module") or ""
        grouped.setdefault(m, []).append(s)
    return {
        "imports": imports,
        "by_name": by_name,
        "grouped_by_module": grouped,
        "len": len(imports),
        "is_empty": not imports,
    }


def validator_in_section(symbols, section_index: int):
    return [s for s in symbols
            if s.get("section_index") == int(section_index)]


# ---------------------------------------------------------------------------
# SymbolConflictResolver
# ---------------------------------------------------------------------------

def _dbg_score(src: str) -> int:
    return 1 if src in ("Pdb", "Dwarf", "CodeView", "Stabs") else 0


def _exp_score(src: str) -> int:
    return 1 if src in ("Export", "Import") else 0


def validator_resolve_conflicts(symbols: List[Dict[str, Any]],
                                strategy: str) -> List[Dict[str, Any]]:
    """Group symbols by address; resolve per strategy.
    PreferDebug   -> pick highest debug-format priority, ties by source priority
    PreferExport  -> pick Export/Import first, else fallback to priority
    KeepFirst     -> first seen per address
    KeepLast      -> last seen per address
    KeepAll       -> identity (preserve order)
    """
    if strategy == "KeepAll":
        return list(symbols)
    groups: Dict[int, List[Dict[str, Any]]] = {}
    order: List[int] = []
    for s in symbols:
        a = _addr(s)
        if a not in groups:
            order.append(a)
            groups[a] = []
        groups[a].append(s)
    out: List[Dict[str, Any]] = []
    for a in order:
        g = groups[a]
        if len(g) == 1:
            out.append(g[0])
            continue
        if strategy == "KeepFirst":
            out.append(g[0])
        elif strategy == "KeepLast":
            out.append(g[-1])
        elif strategy == "PreferDebug":
            out.append(max(g, key=lambda s: (
                _dbg_score(s.get("source", "")),
                validator_source_priority(s.get("source", "")),
            )))
        elif strategy == "PreferExport":
            out.append(max(g, key=lambda s: (
                _exp_score(s.get("source", "")),
                validator_source_priority(s.get("source", "")),
            )))
        else:
            raise ValueError(f"unknown strategy {strategy!r}")
    return out


# ---------------------------------------------------------------------------
# SymbolExporter
# ---------------------------------------------------------------------------

def validator_to_json(symbols) -> str:
    return json.dumps(symbols, sort_keys=True)


def validator_to_csv(symbols) -> str:
    buf = io.StringIO()
    w = csv.writer(buf, lineterminator="\n")
    w.writerow(["address", "size", "name", "kind", "source"])
    for s in symbols:
        w.writerow([
            _addr(s), _size(s),
            s.get("name", ""), s.get("kind", ""), s.get("source", ""),
        ])
    return buf.getvalue()


def validator_to_idc(symbols) -> str:
    lines = ["#include <idc.idc>", "static main() {"]
    for s in symbols:
        name = (s.get("name") or "").replace('"', '\\"')
        lines.append(f'    set_name(0x{_addr(s):X}, "{name}", SN_CHECK);')
    lines.append("}")
    return "\n".join(lines) + "\n"


def validator_to_map(symbols) -> str:
    out = []
    for s in symbols:
        out.append(f"{_addr(s):016X} {s.get('name','')}")
    return "\n".join(out) + ("\n" if out else "")


# ---------------------------------------------------------------------------
# SymbolCache (bounded LRU)
# ---------------------------------------------------------------------------

class SymbolCache:
    def __init__(self, capacity: int) -> None:
        self.capacity = max(0, int(capacity))
        self._data: Dict[str, Any] = {}
        self._order: List[str] = []

    def insert(self, key: str, value: Any) -> None:
        if self.capacity == 0:
            return
        if key in self._data:
            self._order.remove(key)
        elif len(self._data) >= self.capacity:
            evict = self._order.pop(0)
            self._data.pop(evict, None)
        self._data[key] = value
        self._order.append(key)

    def get(self, key: str) -> Optional[Any]:
        if key not in self._data:
            return None
        self._order.remove(key)
        self._order.append(key)
        return self._data[key]

    def clear(self) -> None:
        self._data.clear()
        self._order.clear()

    def __len__(self) -> int:
        return len(self._data)


def validator_cache_simulate(capacity: int,
                             ops: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Drive a SymbolCache with a list of {op:'insert'|'get'|'clear', ...}."""
    c = SymbolCache(capacity)
    trace: List[Any] = []
    for op in ops:
        kind = op.get("op")
        if kind == "insert":
            c.insert(op["key"], op.get("value"))
            trace.append(None)
        elif kind == "get":
            trace.append(c.get(op["key"]))
        elif kind == "clear":
            c.clear()
            trace.append(None)
    return {"len": len(c), "order": list(c._order), "trace": trace}


# ---------------------------------------------------------------------------
# Backends registry (mirror of `backends::registry`)
# ---------------------------------------------------------------------------

_BACKENDS = [
    {"crate_name": "rustre-symbols-codeview",
     "format": "CodeView", "provider_type": "CodeViewProvider"},
    {"crate_name": "rustre-symbols-dwarf",
     "format": "Dwarf", "provider_type": "DwarfProvider"},
    {"crate_name": "rustre-symbols-pdb",
     "format": "Pdb", "provider_type": "PdbProvider"},
    {"crate_name": "rustre-symbols-stabs",
     "format": "Stabs", "provider_type": "StabsProvider"},
]


def validator_backend_registry():
    return list(_BACKENDS)


# ---------------------------------------------------------------------------
# Dispatcher
# ---------------------------------------------------------------------------

FUNCS = {
    "source_priority":      lambda a: validator_source_priority(a["source"]),
    "end_address":          lambda a: validator_end_address(a["sym"]),
    "contains":             lambda a: validator_contains(a["sym"], a["addr"]),
    "display_name":         lambda a: validator_display_name(a["sym"]),
    "fb_size":              lambda a: validator_fb_size(a["fb"]),
    "fb_contains":          lambda a: validator_fb_contains(a["fb"], a["addr"]),
    "fb_overlaps":          lambda a: validator_fb_overlaps(a["a"], a["b"]),
    "filter_apply":         lambda a: validator_filter_apply(a["symbols"], a["filter"]),
    "lookup_exact":         lambda a: validator_lookup_exact(a["symbols"], a["addr"]),
    "lookup_floor":         lambda a: validator_lookup_floor(a["symbols"], a["addr"]),
    "stats_from_symbols":   lambda a: validator_stats_from_symbols(a["symbols"]),
    "export_table":         lambda a: validator_export_table(a["symbols"]),
    "import_table":         lambda a: validator_import_table(a["symbols"]),
    "in_section":           lambda a: validator_in_section(a["symbols"], a["section_index"]),
    "resolve_conflicts":    lambda a: validator_resolve_conflicts(a["symbols"], a["strategy"]),
    "to_json":              lambda a: validator_to_json(a["symbols"]),
    "to_csv":               lambda a: validator_to_csv(a["symbols"]),
    "to_idc":               lambda a: validator_to_idc(a["symbols"]),
    "to_map":               lambda a: validator_to_map(a["symbols"]),
    "cache_simulate":       lambda a: validator_cache_simulate(a["capacity"], a["ops"]),
    "backend_registry":     lambda a: validator_backend_registry(),
}


def _self_test() -> Dict[str, Any]:
    syms = [
        {"name": "main",      "address": 0x1000, "size": 0x40,
         "kind": "Function", "source": "Pdb", "section_index": 1},
        {"name": "main",      "address": 0x1000, "size": 0x40,
         "kind": "Function", "source": "Export", "section_index": 1,
         "ordinal": 1},
        {"name": "g_table",   "address": 0x2000, "size": 0x100,
         "kind": "Variable", "source": "Dwarf", "section_index": 2},
        {"name": "CreateFileW", "address": 0x3000, "size": 0,
         "kind": "Import", "source": "Import",
         "module": "KERNEL32.dll"},
    ]
    out = {
        "priorities": {s: validator_source_priority(s)
                       for s in ("Pdb", "Dwarf", "Pe", "Ai", "Manual")},
        "stats": validator_stats_from_symbols(syms),
        "filter_main": validator_filter_apply(
            syms, {"kinds": ["Function"], "name_prefix": "m"}),
        "exact_1000": validator_lookup_exact(syms, 0x1000),
        "floor_1010": validator_lookup_floor(syms, 0x1010),
        "imports": validator_import_table(syms),
        "exports": validator_export_table(syms),
        "in_section_1": [s["name"] for s in validator_in_section(syms, 1)],
        "resolve_prefer_debug": [s["source"] for s in
            validator_resolve_conflicts(syms, "PreferDebug")],
        "resolve_prefer_export": [s["source"] for s in
            validator_resolve_conflicts(syms, "PreferExport")],
        "resolve_keep_first": [s["source"] for s in
            validator_resolve_conflicts(syms, "KeepFirst")],
        "resolve_keep_last": [s["source"] for s in
            validator_resolve_conflicts(syms, "KeepLast")],
        "csv": validator_to_csv(syms),
        "map_head": validator_to_map(syms).splitlines()[:2],
        "idc_head": validator_to_idc(syms).splitlines()[:3],
        "cache": validator_cache_simulate(2, [
            {"op": "insert", "key": "a", "value": 1},
            {"op": "insert", "key": "b", "value": 2},
            {"op": "get",    "key": "a"},
            {"op": "insert", "key": "c", "value": 3},  # evict "b"
            {"op": "get",    "key": "b"},
            {"op": "get",    "key": "c"},
        ]),
        "fb": {
            "size": validator_fb_size({"start": 0x100, "end": 0x180}),
            "contains": validator_fb_contains(
                {"start": 0x100, "end": 0x180}, 0x120),
            "overlaps": validator_fb_overlaps(
                {"start": 0x100, "end": 0x180},
                {"start": 0x150, "end": 0x200}),
        },
        "backends": validator_backend_registry(),
    }
    return out


def main() -> None:
    if not sys.stdin.isatty():
        try:
            req = json.load(sys.stdin)
        except Exception:
            req = None
        if req:
            fn = req.get("fn")
            args = req.get("args", {})
            try:
                out = FUNCS[fn](args)
                json.dump({"ok": True, "result": out},
                          sys.stdout, default=str)
            except Exception as e:
                json.dump({"ok": False, "error": str(e)}, sys.stdout)
            return
    print(json.dumps(_self_test(), indent=2, default=str))


if __name__ == "__main__":
    main()
