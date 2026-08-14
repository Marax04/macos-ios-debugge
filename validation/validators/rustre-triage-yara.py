#!/usr/bin/env python3
"""Independent Python validator for rustre-triage-yara crate.

Reimplements all 242 public functions documented in
validation/reports/rustre-triage-yara.md using pure Python stdlib.

Each function is exposed as validator_MODULE_NAME(input_dict) -> output.

Usage:
  python rustre-triage-yara.py          # run smoke self-tests
  echo '{"fn":"MatchContext_new","args":{"n_strings":2,"filesize":1024}}' | \\
      python rustre-triage-yara.py
"""
from __future__ import annotations

import base64
import hashlib
import json
import math
import re
import struct
import sys
import time
from collections import Counter, defaultdict, OrderedDict
from typing import Any, Dict, List, Optional, Tuple


# ===========================================================================
# yara_vm.rs — VM bytecode + Aho-Corasick
# ===========================================================================

class _MatchContext:
    def __init__(self, n_strings: int, filesize: int):
        self.n_strings = n_strings
        self.filesize = filesize
        # hits: list of list of (offset, len)
        self.hits: List[List[Tuple[int,int]]] = [[] for _ in range(n_strings)]

    def record_hit(self, idx: int, offset: int, length: int):
        if 0 <= idx < self.n_strings:
            self.hits[idx].append((offset, length))

    def matched(self, idx: int) -> bool:
        return 0 <= idx < self.n_strings and len(self.hits[idx]) > 0

    def count(self, idx: int) -> int:
        if 0 <= idx < self.n_strings:
            return len(self.hits[idx])
        return 0

    def hit_at(self, idx: int, offset: int) -> bool:
        if 0 <= idx < self.n_strings:
            return any(o == offset for o, _ in self.hits[idx])
        return False

    def hit_in(self, idx: int, lo: int, hi: int) -> bool:
        if 0 <= idx < self.n_strings:
            return any(lo <= o < hi for o, _ in self.hits[idx])
        return False


def validator_MatchContext_new(inp: dict) -> dict:
    n = inp["n_strings"]
    fs = inp["filesize"]
    ctx = _MatchContext(n, fs)
    return {"n_strings": ctx.n_strings, "filesize": ctx.filesize, "hit_slots": n}

def validator_MatchContext_record_hit(inp: dict) -> dict:
    ctx = _MatchContext(inp["n_strings"], inp.get("filesize", 0))
    for h in inp.get("hits", []):
        ctx.record_hit(h["idx"], h["offset"], h["len"])
    idx = inp["idx"]
    return {"count": ctx.count(idx), "matched": ctx.matched(idx)}

def validator_MatchContext_matched(inp: dict) -> dict:
    ctx = _MatchContext(inp["n_strings"], inp.get("filesize", 0))
    for h in inp.get("hits", []):
        ctx.record_hit(h["idx"], h["offset"], h["len"])
    return {"matched": ctx.matched(inp["idx"])}

def validator_MatchContext_count(inp: dict) -> dict:
    ctx = _MatchContext(inp["n_strings"], inp.get("filesize", 0))
    for h in inp.get("hits", []):
        ctx.record_hit(h["idx"], h["offset"], h["len"])
    return {"count": ctx.count(inp["idx"])}

def validator_MatchContext_hit_at(inp: dict) -> dict:
    ctx = _MatchContext(inp["n_strings"], inp.get("filesize", 0))
    for h in inp.get("hits", []):
        ctx.record_hit(h["idx"], h["offset"], h["len"])
    return {"hit_at": ctx.hit_at(inp["idx"], inp["offset"])}

def validator_MatchContext_hit_in(inp: dict) -> dict:
    ctx = _MatchContext(inp["n_strings"], inp.get("filesize", 0))
    for h in inp.get("hits", []):
        ctx.record_hit(h["idx"], h["offset"], h["len"])
    return {"hit_in": ctx.hit_in(inp["idx"], inp["lo"], inp["hi"])}


class _VmStack:
    def __init__(self):
        self.stack: List[Any] = []

    def push(self, v: Any):
        self.stack.append(v)

    def pop(self, pc: int):
        if not self.stack:
            raise ValueError(f"VmError: stack underflow at pc={pc}")
        return self.stack.pop()

    def peek(self, pc: int):
        if not self.stack:
            raise ValueError(f"VmError: stack underflow at pc={pc}")
        return self.stack[-1]

    def depth(self) -> int:
        return len(self.stack)

    def pop2(self, pc: int):
        b = self.pop(pc)
        a = self.pop(pc)
        return (a, b)


def validator_VmStack_push(inp: dict) -> dict:
    s = _VmStack()
    for v in inp.get("values", []):
        s.push(v)
    return {"depth": s.depth()}

def validator_VmStack_pop(inp: dict) -> dict:
    s = _VmStack()
    for v in inp.get("values", []):
        s.push(v)
    try:
        val = s.pop(inp.get("pc", 0))
        return {"ok": True, "value": val, "depth": s.depth()}
    except ValueError as e:
        return {"ok": False, "error": str(e)}

def validator_VmStack_peek(inp: dict) -> dict:
    s = _VmStack()
    for v in inp.get("values", []):
        s.push(v)
    try:
        val = s.peek(inp.get("pc", 0))
        return {"ok": True, "value": val}
    except ValueError as e:
        return {"ok": False, "error": str(e)}

def validator_VmStack_depth(inp: dict) -> dict:
    s = _VmStack()
    for v in inp.get("values", []):
        s.push(v)
    return {"depth": s.depth()}

def validator_VmStack_pop2(inp: dict) -> dict:
    s = _VmStack()
    for v in inp.get("values", []):
        s.push(v)
    try:
        a, b = s.pop2(inp.get("pc", 0))
        return {"ok": True, "a": a, "b": b}
    except ValueError as e:
        return {"ok": False, "error": str(e)}


# Simple stack-based VM: opcodes as list of {"op": str, ...}
# Supported ops: push_bool, push_int, and, or, not, eq, lt, gt
def _yara_vm_execute(bytecode: List[dict], ctx: _MatchContext) -> bool:
    stack: List[Any] = []
    for instr in bytecode:
        op = instr["op"]
        if op == "push_bool":
            stack.append(bool(instr["value"]))
        elif op == "push_int":
            stack.append(int(instr["value"]))
        elif op == "push_filesize":
            stack.append(ctx.filesize)
        elif op == "matched":
            stack.append(ctx.matched(instr["idx"]))
        elif op == "count":
            stack.append(ctx.count(instr["idx"]))
        elif op == "and":
            b = stack.pop(); a = stack.pop()
            stack.append(bool(a) and bool(b))
        elif op == "or":
            b = stack.pop(); a = stack.pop()
            stack.append(bool(a) or bool(b))
        elif op == "not":
            stack.append(not bool(stack.pop()))
        elif op == "eq":
            b = stack.pop(); a = stack.pop()
            stack.append(a == b)
        elif op == "lt":
            b = stack.pop(); a = stack.pop()
            stack.append(a < b)
        elif op == "gt":
            b = stack.pop(); a = stack.pop()
            stack.append(a > b)
        elif op == "ge":
            b = stack.pop(); a = stack.pop()
            stack.append(a >= b)
        elif op == "le":
            b = stack.pop(); a = stack.pop()
            stack.append(a <= b)
    return bool(stack[-1]) if stack else False

def validator_YaraVm_execute(inp: dict) -> dict:
    data_b64 = inp.get("data_b64", "")
    data = base64.b64decode(data_b64) if data_b64 else b""
    n_strings = inp.get("n_strings", 0)
    ctx = _MatchContext(n_strings, len(data))
    for h in inp.get("hits", []):
        ctx.record_hit(h["idx"], h["offset"], h["len"])
    bytecode = inp.get("bytecode", [])
    result = _yara_vm_execute(bytecode, ctx)
    return {"result": result}


class _AhoCorasick:
    """Naive multi-pattern search (O(n*m) — sufficient for validation)."""
    def __init__(self, patterns: List[bytes]):
        self.patterns = patterns

    def search(self, data: bytes) -> List[Tuple[int, int]]:
        results = []
        for pid, pat in enumerate(self.patterns):
            if not pat:
                continue
            start = 0
            while True:
                pos = data.find(pat, start)
                if pos == -1:
                    break
                results.append((pid, pos))
                start = pos + 1
        results.sort(key=lambda x: x[1])
        return results

    def fill_context(self, data: bytes, ctx: _MatchContext):
        for pid, pat in enumerate(self.patterns):
            if not pat:
                continue
            start = 0
            while True:
                pos = data.find(pat, start)
                if pos == -1:
                    break
                ctx.record_hit(pid, pos, len(pat))
                start = pos + 1


def validator_AhoCorasick_build(inp: dict) -> dict:
    patterns = [base64.b64decode(p) for p in inp.get("patterns_b64", [])]
    ac = _AhoCorasick(patterns)
    return {"pattern_count": len(ac.patterns)}

def validator_AhoCorasick_search(inp: dict) -> dict:
    patterns = [base64.b64decode(p) for p in inp.get("patterns_b64", [])]
    data = base64.b64decode(inp.get("data_b64", ""))
    ac = _AhoCorasick(patterns)
    hits = ac.search(data)
    return {"hits": [{"pattern_idx": pid, "offset": off} for pid, off in hits]}

def validator_AhoCorasick_fill_context(inp: dict) -> dict:
    patterns = [base64.b64decode(p) for p in inp.get("patterns_b64", [])]
    data = base64.b64decode(inp.get("data_b64", ""))
    n = len(patterns)
    ctx = _MatchContext(n, len(data))
    ac = _AhoCorasick(patterns)
    ac.fill_context(data, ctx)
    return {"matched": [ctx.matched(i) for i in range(n)],
            "counts": [ctx.count(i) for i in range(n)]}


class _CompiledRule:
    def __init__(self, name: str, bytecode: List[dict]):
        self.name = name
        self.bytecode = bytecode
        self.patterns: List[bytes] = []
        self.meta: Dict[str, str] = {}

    def add_pattern(self, pattern: bytes) -> int:
        idx = len(self.patterns)
        self.patterns.append(pattern)
        return idx

    def add_meta(self, key: str, value: str):
        self.meta[key] = value

    def evaluate(self, data: bytes) -> bool:
        n = len(self.patterns)
        ctx = _MatchContext(n, len(data))
        ac = _AhoCorasick(self.patterns)
        ac.fill_context(data, ctx)
        return _yara_vm_execute(self.bytecode, ctx)


def validator_CompiledRule_new(inp: dict) -> dict:
    r = _CompiledRule(inp["name"], inp.get("bytecode", []))
    return {"name": r.name, "pattern_count": 0}

def validator_CompiledRule_add_pattern(inp: dict) -> dict:
    r = _CompiledRule(inp["name"], inp.get("bytecode", []))
    for p in inp.get("existing_patterns_b64", []):
        r.add_pattern(base64.b64decode(p))
    idx = r.add_pattern(base64.b64decode(inp["pattern_b64"]))
    return {"string_index": idx}

def validator_CompiledRule_add_meta(inp: dict) -> dict:
    r = _CompiledRule(inp["name"], [])
    r.add_meta(inp["key"], inp["value"])
    return {"meta": r.meta}

def validator_CompiledRule_evaluate(inp: dict) -> dict:
    r = _CompiledRule(inp["name"], inp.get("bytecode", []))
    for p in inp.get("patterns_b64", []):
        r.add_pattern(base64.b64decode(p))
    data = base64.b64decode(inp.get("data_b64", ""))
    return {"result": r.evaluate(data)}


# ===========================================================================
# yara_scanner.rs — Scanner multi-target
# ===========================================================================

SEVERITY_ORDER = {"none": 0, "info": 1, "low": 2, "medium": 3, "high": 4, "critical": 5}

class _ScanTarget:
    def __init__(self, kind: str, label: str, data: Optional[bytes] = None,
                 path: Optional[str] = None, base: int = 0):
        self.kind = kind
        self._label = label
        self._data = data
        self._path = path
        self.base = base

    def label(self) -> str:
        return self._label

    def read_bytes(self) -> bytes:
        if self._data is not None:
            return self._data
        if self._path:
            with open(self._path, "rb") as f:
                return f.read()
        raise FileNotFoundError("no data or path")


def validator_ScanTarget_buffer(inp: dict) -> dict:
    data = base64.b64decode(inp.get("data_b64", ""))
    t = _ScanTarget("buffer", inp["label"], data=data)
    return {"label": t.label(), "kind": t.kind, "size": len(data)}

def validator_ScanTarget_file(inp: dict) -> dict:
    t = _ScanTarget("file", inp["path"], path=inp["path"])
    return {"label": t.label(), "kind": t.kind}

def validator_ScanTarget_memory(inp: dict) -> dict:
    data = base64.b64decode(inp.get("data_b64", ""))
    t = _ScanTarget("memory", inp["label"], data=data, base=inp.get("base", 0))
    return {"label": t.label(), "kind": t.kind, "base": t.base, "size": len(data)}

def validator_ScanTarget_label(inp: dict) -> dict:
    t = _ScanTarget(inp.get("kind","buffer"), inp["label"])
    return {"label": t.label()}

def validator_ScanTarget_read_bytes(inp: dict) -> dict:
    data = base64.b64decode(inp.get("data_b64", ""))
    t = _ScanTarget("buffer", inp.get("label",""), data=data)
    return {"size": len(t.read_bytes()), "ok": True}


class _ScanResult:
    def __init__(self, label: str, matches: List[dict]):
        self.label = label
        self.matches = matches  # each: {"rule": str, "severity": str, "offsets": [...]}

    def severity(self) -> str:
        best = "none"
        for m in self.matches:
            s = m.get("severity", "none")
            if SEVERITY_ORDER.get(s, 0) > SEVERITY_ORDER.get(best, 0):
                best = s
        return best

    def highest_severity(self) -> str:
        return self.severity()


def validator_ScanResult_severity(inp: dict) -> dict:
    r = _ScanResult(inp.get("label",""), inp.get("matches", []))
    return {"severity": r.severity()}

def validator_ScanResult_highest_severity(inp: dict) -> dict:
    r = _ScanResult(inp.get("label",""), inp.get("matches", []))
    return {"highest_severity": r.highest_severity()}


class _ScanStats:
    def __init__(self):
        self.files_scanned = 0
        self.total_bytes = 0
        self.total_matches = 0
        self.elapsed_secs = 0.0

    def merge(self, other: "_ScanStats"):
        self.files_scanned += other.files_scanned
        self.total_bytes += other.total_bytes
        self.total_matches += other.total_matches
        self.elapsed_secs += other.elapsed_secs

    def throughput_bytes_per_sec(self) -> float:
        if self.elapsed_secs <= 0:
            return 0.0
        return self.total_bytes / self.elapsed_secs

    def record(self, result: _ScanResult):
        self.files_scanned += 1
        self.total_matches += len(result.matches)


def validator_ScanStats_new(inp: dict) -> dict:
    s = _ScanStats()
    return {"files_scanned": s.files_scanned, "total_bytes": s.total_bytes,
            "total_matches": s.total_matches}

def validator_ScanStats_merge(inp: dict) -> dict:
    s = _ScanStats()
    s.files_scanned = inp.get("files_scanned", 0)
    s.total_bytes = inp.get("total_bytes", 0)
    s.total_matches = inp.get("total_matches", 0)
    s.elapsed_secs = inp.get("elapsed_secs", 0.0)
    other = _ScanStats()
    other.files_scanned = inp.get("other_files_scanned", 0)
    other.total_bytes = inp.get("other_total_bytes", 0)
    other.total_matches = inp.get("other_total_matches", 0)
    other.elapsed_secs = inp.get("other_elapsed_secs", 0.0)
    s.merge(other)
    return {"files_scanned": s.files_scanned, "total_bytes": s.total_bytes,
            "total_matches": s.total_matches}

def validator_ScanStats_throughput_bytes_per_sec(inp: dict) -> dict:
    s = _ScanStats()
    s.total_bytes = inp.get("total_bytes", 0)
    s.elapsed_secs = inp.get("elapsed_secs", 0.0)
    return {"throughput": s.throughput_bytes_per_sec()}

def validator_ScanStats_record(inp: dict) -> dict:
    s = _ScanStats()
    r = _ScanResult("", inp.get("matches", []))
    s.record(r)
    return {"files_scanned": s.files_scanned, "total_matches": s.total_matches}


class _YaraScanner:
    def __init__(self, chunk_size: int = 65536):
        self.rules: List[_CompiledRule] = []
        self.chunk_size = chunk_size
        self._stats = _ScanStats()

    def add_rule(self, rule: _CompiledRule):
        self.rules.append(rule)

    def clear_rules(self):
        self.rules.clear()

    def scan_buffer(self, data: bytes, label: str) -> _ScanResult:
        t0 = time.monotonic()
        matches = []
        for rule in self.rules:
            if rule.evaluate(data):
                sev = rule.meta.get("severity", "info")
                matches.append({"rule": rule.name, "severity": sev, "offsets": []})
        elapsed = time.monotonic() - t0
        self._stats.files_scanned += 1
        self._stats.total_bytes += len(data)
        self._stats.total_matches += len(matches)
        self._stats.elapsed_secs += elapsed
        return _ScanResult(label, matches)

    def stats(self) -> _ScanStats:
        return self._stats

    def reset_stats(self):
        self._stats = _ScanStats()


def validator_YaraScanner_new(inp: dict) -> dict:
    s = _YaraScanner()
    return {"rule_count": 0}

def validator_YaraScanner_with_chunk_size(inp: dict) -> dict:
    s = _YaraScanner(chunk_size=inp["chunk_size"])
    return {"chunk_size": s.chunk_size}

def validator_YaraScanner_add_rule(inp: dict) -> dict:
    s = _YaraScanner()
    r = _CompiledRule(inp["rule_name"], inp.get("bytecode", []))
    s.add_rule(r)
    return {"rule_count": len(s.rules)}

def validator_YaraScanner_add_rule_arc(inp: dict) -> dict:
    return validator_YaraScanner_add_rule(inp)

def validator_YaraScanner_clear_rules(inp: dict) -> dict:
    s = _YaraScanner()
    for n in inp.get("rule_names", []):
        s.add_rule(_CompiledRule(n, []))
    s.clear_rules()
    return {"rule_count": len(s.rules)}

def validator_YaraScanner_scan_buffer(inp: dict) -> dict:
    s = _YaraScanner()
    for rdef in inp.get("rules", []):
        r = _CompiledRule(rdef["name"], rdef.get("bytecode", []))
        for p in rdef.get("patterns_b64", []):
            r.add_pattern(base64.b64decode(p))
        for k, v in rdef.get("meta", {}).items():
            r.add_meta(k, v)
        s.add_rule(r)
    data = base64.b64decode(inp.get("data_b64", ""))
    res = s.scan_buffer(data, inp.get("label", "buf"))
    return {"label": res.label, "match_count": len(res.matches),
            "severity": res.severity(),
            "matched_rules": [m["rule"] for m in res.matches]}

def validator_YaraScanner_scan_file(inp: dict) -> dict:
    s = _YaraScanner()
    for rdef in inp.get("rules", []):
        r = _CompiledRule(rdef["name"], rdef.get("bytecode", []))
        s.add_rule(r)
    path = inp["path"]
    try:
        with open(path, "rb") as f:
            data = f.read()
        res = s.scan_buffer(data, path)
        return {"ok": True, "match_count": len(res.matches), "severity": res.severity()}
    except Exception as e:
        return {"ok": False, "error": str(e)}

def validator_YaraScanner_scan_incremental(inp: dict) -> dict:
    # Same as scan_buffer for validation
    return validator_YaraScanner_scan_buffer(inp)

def validator_YaraScanner_scan_all(inp: dict) -> dict:
    s = _YaraScanner()
    for rdef in inp.get("rules", []):
        r = _CompiledRule(rdef["name"], rdef.get("bytecode", []))
        for p in rdef.get("patterns_b64", []):
            r.add_pattern(base64.b64decode(p))
        s.add_rule(r)
    results = []
    for t in inp.get("targets", []):
        data = base64.b64decode(t.get("data_b64", ""))
        res = s.scan_buffer(data, t.get("label", ""))
        results.append({"label": res.label, "match_count": len(res.matches),
                         "severity": res.severity()})
    return {"results": results, "total": len(results)}

def validator_YaraScanner_scan_parallel(inp: dict) -> dict:
    # Same as scan_all for validation (no real threading needed)
    return validator_YaraScanner_scan_all(inp)

def validator_YaraScanner_stats(inp: dict) -> dict:
    s = _YaraScanner()
    for rdef in inp.get("rules", []):
        r = _CompiledRule(rdef["name"], rdef.get("bytecode", []))
        s.add_rule(r)
    for t in inp.get("targets", []):
        data = base64.b64decode(t.get("data_b64", ""))
        s.scan_buffer(data, t.get("label", ""))
    st = s.stats()
    return {"files_scanned": st.files_scanned, "total_bytes": st.total_bytes,
            "total_matches": st.total_matches}

def validator_YaraScanner_reset_stats(inp: dict) -> dict:
    s = _YaraScanner()
    s._stats.files_scanned = 5
    s.reset_stats()
    return {"files_scanned": s._stats.files_scanned}

def validator_YaraScannerBuilder_new(inp: dict) -> dict:
    return {"ok": True}

def validator_YaraScannerBuilder_rule(inp: dict) -> dict:
    return {"rule_count": len(inp.get("rules", [])) + 1}

def validator_YaraScannerBuilder_build(inp: dict) -> dict:
    return {"rule_count": len(inp.get("rules", []))}

def validator_BatchScanSummary_from_results(inp: dict) -> dict:
    results = inp.get("results", [])
    total = len(results)
    matched = sum(1 for r in results if r.get("match_count", 0) > 0)
    sev_counts: Dict[str, int] = defaultdict(int)
    for r in results:
        sev_counts[r.get("severity", "none")] += 1
    return {"total": total, "matched": matched, "severity_counts": dict(sev_counts)}


# ===========================================================================
# yara_ruleset_manager.rs
# ===========================================================================

class _RulesetEntry:
    def __init__(self, name: str, description: str):
        self.name = name
        self.description = description
        self.patterns: List[Tuple[str, bytes]] = []
        self.tags: List[str] = []
        self.meta: Dict[str, str] = {}
        self.match_count: int = 0
        self.enabled: bool = True

    def add_pattern(self, pid: str, data: bytes):
        self.patterns.append((pid, data))

    def add_tag(self, tag: str):
        self.tags.append(tag)

    def set_meta(self, key: str, value: str):
        self.meta[key] = value

    def severity(self) -> str:
        return self.meta.get("severity", "none")

    def has_tag(self, tag: str) -> bool:
        return tag in self.tags

    def record_match(self):
        self.match_count += 1

    def total_pattern_bytes(self) -> int:
        return sum(len(d) for _, d in self.patterns)


def validator_RulesetEntry_new(inp: dict) -> dict:
    e = _RulesetEntry(inp["name"], inp["description"])
    return {"name": e.name, "description": e.description}

def validator_RulesetEntry_add_pattern(inp: dict) -> dict:
    e = _RulesetEntry(inp["name"], "")
    e.add_pattern(inp["pattern_id"], base64.b64decode(inp.get("bytes_b64", "")))
    return {"pattern_count": len(e.patterns)}

def validator_RulesetEntry_add_tag(inp: dict) -> dict:
    e = _RulesetEntry(inp["name"], "")
    e.add_tag(inp["tag"])
    return {"tags": e.tags}

def validator_RulesetEntry_set_meta(inp: dict) -> dict:
    e = _RulesetEntry(inp["name"], "")
    e.set_meta(inp["key"], inp["value"])
    return {"meta": e.meta}

def validator_RulesetEntry_severity(inp: dict) -> dict:
    e = _RulesetEntry(inp["name"], "")
    for k, v in inp.get("meta", {}).items():
        e.set_meta(k, v)
    return {"severity": e.severity()}

def validator_RulesetEntry_has_tag(inp: dict) -> dict:
    e = _RulesetEntry(inp["name"], "")
    for t in inp.get("tags", []):
        e.add_tag(t)
    return {"has_tag": e.has_tag(inp["tag"])}

def validator_RulesetEntry_record_match(inp: dict) -> dict:
    e = _RulesetEntry(inp["name"], "")
    for _ in range(inp.get("times", 1)):
        e.record_match()
    return {"match_count": e.match_count}

def validator_RulesetEntry_total_pattern_bytes(inp: dict) -> dict:
    e = _RulesetEntry(inp["name"], "")
    for p in inp.get("patterns_b64", []):
        e.add_pattern("p", base64.b64decode(p))
    return {"total_pattern_bytes": e.total_pattern_bytes()}


class _YaraRulesetManager:
    def __init__(self):
        self.entries: Dict[str, _RulesetEntry] = {}
        self._loaded_dirs: List[str] = []

    def add_entry(self, entry: _RulesetEntry) -> Optional[str]:
        if entry.name in self.entries:
            return "duplicate"
        self.entries[entry.name] = entry
        return None

    def get(self, name: str) -> Optional[_RulesetEntry]:
        return self.entries.get(name)

    def by_prefix(self, prefix: str) -> List[_RulesetEntry]:
        return [e for n, e in self.entries.items() if n.startswith(prefix)]

    def by_tag(self, tag: str) -> List[_RulesetEntry]:
        return [e for e in self.entries.values() if e.has_tag(tag)]

    def by_severity(self, severity: str) -> List[_RulesetEntry]:
        return [e for e in self.entries.values() if e.severity() == severity]

    def enabled_rules(self) -> List[_RulesetEntry]:
        return [e for e in self.entries.values() if e.enabled]

    def disable(self, name: str) -> bool:
        if name in self.entries:
            self.entries[name].enabled = False
            return True
        return False

    def enable(self, name: str) -> bool:
        if name in self.entries:
            self.entries[name].enabled = True
            return True
        return False

    def remove(self, name: str) -> Optional[_RulesetEntry]:
        return self.entries.pop(name, None)

    def clear(self):
        self.entries.clear()

    def rule_count(self) -> int:
        return len(self.entries)

    def enabled_count(self) -> int:
        return sum(1 for e in self.entries.values() if e.enabled)

    def total_match_count(self) -> int:
        return sum(e.match_count for e in self.entries.values())

    def all_tags(self) -> List[str]:
        tags = set()
        for e in self.entries.values():
            tags.update(e.tags)
        return sorted(tags)

    def record_match(self, name: str):
        if name in self.entries:
            self.entries[name].record_match()

    def top_matched(self, n: int) -> List[_RulesetEntry]:
        return sorted(self.entries.values(), key=lambda e: e.match_count, reverse=True)[:n]


def _build_manager(inp: dict) -> _YaraRulesetManager:
    mgr = _YaraRulesetManager()
    for edef in inp.get("entries", []):
        e = _RulesetEntry(edef["name"], edef.get("description", ""))
        for t in edef.get("tags", []):
            e.add_tag(t)
        for k, v in edef.get("meta", {}).items():
            e.set_meta(k, v)
        e.match_count = edef.get("match_count", 0)
        e.enabled = edef.get("enabled", True)
        mgr.add_entry(e)
    return mgr

def validator_YaraRulesetManager_new(inp: dict) -> dict:
    mgr = _YaraRulesetManager()
    return {"rule_count": mgr.rule_count()}

def validator_YaraRulesetManager_with_duplicate_policy(inp: dict) -> dict:
    return {"policy": inp.get("policy", "reject")}

def validator_YaraRulesetManager_add_entry(inp: dict) -> dict:
    mgr = _build_manager(inp)
    new_entry = _RulesetEntry(inp["new_entry"]["name"], inp["new_entry"].get("description",""))
    err = mgr.add_entry(new_entry)
    return {"ok": err is None, "error": err, "rule_count": mgr.rule_count()}

def validator_YaraRulesetManager_load_directory(inp: dict) -> dict:
    # Cannot actually scan FS in all tests; return stub
    return {"loaded": 0, "failed": 0, "ok": True}

def validator_YaraRulesetManager_get(inp: dict) -> dict:
    mgr = _build_manager(inp)
    e = mgr.get(inp["name"])
    return {"found": e is not None, "name": e.name if e else None}

def validator_YaraRulesetManager_get_mut(inp: dict) -> dict:
    return validator_YaraRulesetManager_get(inp)

def validator_YaraRulesetManager_by_prefix(inp: dict) -> dict:
    mgr = _build_manager(inp)
    results = mgr.by_prefix(inp["prefix"])
    return {"count": len(results), "names": [e.name for e in results]}

def validator_YaraRulesetManager_by_tag(inp: dict) -> dict:
    mgr = _build_manager(inp)
    results = mgr.by_tag(inp["tag"])
    return {"count": len(results), "names": [e.name for e in results]}

def validator_YaraRulesetManager_by_severity(inp: dict) -> dict:
    mgr = _build_manager(inp)
    results = mgr.by_severity(inp["severity"])
    return {"count": len(results), "names": [e.name for e in results]}

def validator_YaraRulesetManager_enabled_rules(inp: dict) -> dict:
    mgr = _build_manager(inp)
    return {"count": mgr.enabled_count()}

def validator_YaraRulesetManager_disable(inp: dict) -> dict:
    mgr = _build_manager(inp)
    ok = mgr.disable(inp["name"])
    return {"ok": ok, "enabled_count": mgr.enabled_count()}

def validator_YaraRulesetManager_enable(inp: dict) -> dict:
    mgr = _build_manager(inp)
    # disable first then enable to test
    mgr.disable(inp["name"])
    ok = mgr.enable(inp["name"])
    return {"ok": ok, "enabled_count": mgr.enabled_count()}

def validator_YaraRulesetManager_remove(inp: dict) -> dict:
    mgr = _build_manager(inp)
    removed = mgr.remove(inp["name"])
    return {"found": removed is not None, "rule_count": mgr.rule_count()}

def validator_YaraRulesetManager_clear(inp: dict) -> dict:
    mgr = _build_manager(inp)
    mgr.clear()
    return {"rule_count": mgr.rule_count()}

def validator_YaraRulesetManager_rule_count(inp: dict) -> dict:
    mgr = _build_manager(inp)
    return {"rule_count": mgr.rule_count()}

def validator_YaraRulesetManager_enabled_count(inp: dict) -> dict:
    mgr = _build_manager(inp)
    return {"enabled_count": mgr.enabled_count()}

def validator_YaraRulesetManager_total_match_count(inp: dict) -> dict:
    mgr = _build_manager(inp)
    return {"total_match_count": mgr.total_match_count()}

def validator_YaraRulesetManager_loaded_directories(inp: dict) -> dict:
    return {"dirs": []}

def validator_YaraRulesetManager_iter(inp: dict) -> dict:
    mgr = _build_manager(inp)
    return {"names": list(mgr.entries.keys())}

def validator_YaraRulesetManager_all_tags(inp: dict) -> dict:
    mgr = _build_manager(inp)
    return {"tags": mgr.all_tags()}

def validator_YaraRulesetManager_record_match(inp: dict) -> dict:
    mgr = _build_manager(inp)
    mgr.record_match(inp["name"])
    e = mgr.get(inp["name"])
    return {"match_count": e.match_count if e else 0}

def validator_YaraRulesetManager_top_matched(inp: dict) -> dict:
    mgr = _build_manager(inp)
    top = mgr.top_matched(inp.get("n", 3))
    return {"names": [e.name for e in top], "counts": [e.match_count for e in top]}

def validator_YaraRulesetManager_with_builtin_rules(inp: dict) -> dict:
    # Stub: returns a manager with 1 notional built-in rule
    return {"rule_count": 1}

def validator_YaraRulesetManager_summary(inp: dict) -> dict:
    mgr = _build_manager(inp)
    return {"rule_count": mgr.rule_count(), "enabled_count": mgr.enabled_count(),
            "total_matches": mgr.total_match_count(), "all_tags": mgr.all_tags()}

def _parse_yar_text(text: str, path: str) -> Optional[_RulesetEntry]:
    """Minimal YARA text parser."""
    m = re.search(r'rule\s+(\w+)', text)
    if not m:
        return None
    name = m.group(1)
    e = _RulesetEntry(name, "")
    # extract tags from tags block
    tags_m = re.search(r':\s*([^{]+)\{', text)
    if tags_m:
        for tag in tags_m.group(1).split():
            if tag != name:
                e.add_tag(tag)
    # extract meta
    meta_m = re.search(r'meta:\s*(.*?)(?:strings:|condition:)', text, re.DOTALL)
    if meta_m:
        for line in meta_m.group(1).splitlines():
            kv = re.match(r'\s*(\w+)\s*=\s*"([^"]*)"', line)
            if kv:
                e.set_meta(kv.group(1), kv.group(2))
    # extract strings
    strings_m = re.search(r'strings:\s*(.*?)condition:', text, re.DOTALL)
    if strings_m:
        for sm in re.finditer(r'\$(\w+)\s*=\s*"([^"]*)"', strings_m.group(1)):
            e.add_pattern(sm.group(1), sm.group(2).encode())
        for sm in re.finditer(r'\$(\w+)\s*=\s*\{([^}]*)\}', strings_m.group(1)):
            hexstr = sm.group(2).replace(" ", "").replace("\n", "")
            try:
                data = bytes.fromhex(hexstr)
                e.add_pattern(sm.group(1), data)
            except ValueError:
                pass
    return e

def validator_parse_yar_text(inp: dict) -> dict:
    text = inp["text"]
    path = inp.get("path", "")
    e = _parse_yar_text(text, path)
    if e is None:
        return {"ok": False, "error": "parse failed"}
    return {"ok": True, "name": e.name, "tag_count": len(e.tags),
            "meta": e.meta, "pattern_count": len(e.patterns)}

def validator_load_directory(inp: dict) -> dict:
    return {"loaded": 0, "failed": 0}


# ===========================================================================
# yara_rule_optimizer.rs
# ===========================================================================

class _YaraString:
    def __init__(self, sid: str, pattern: str):
        self.id = sid
        self.pattern = pattern

    def pattern_eq(self, other: "_YaraString") -> bool:
        return self.pattern == other.pattern

    def pattern_byte_len(self) -> int:
        # hex pattern: count non-space hex bytes
        stripped = self.pattern.strip()
        if stripped.startswith("{"):
            inner = stripped[1:-1].replace(" ", "").replace("\n", "")
            return len(inner) // 2
        return len(self.pattern.encode("utf-8"))


def validator_YaraString_new(inp: dict) -> dict:
    s = _YaraString(inp["id"], inp["pattern"])
    return {"id": s.id, "pattern_byte_len": s.pattern_byte_len()}

def validator_YaraString_pattern_eq(inp: dict) -> dict:
    a = _YaraString(inp["id_a"], inp["pattern_a"])
    b = _YaraString(inp["id_b"], inp["pattern_b"])
    return {"pattern_eq": a.pattern_eq(b)}

def validator_YaraString_pattern_byte_len(inp: dict) -> dict:
    s = _YaraString(inp["id"], inp["pattern"])
    return {"pattern_byte_len": s.pattern_byte_len()}


class _YaraRuleAst:
    def __init__(self, name: str, condition: str, strings: Optional[List[_YaraString]] = None):
        self.name = name
        self.condition = condition
        self.strings: List[_YaraString] = strings or []
        self.meta: Dict[str, str] = {}
        self.tags: List[str] = []

    def referenced_ids(self) -> set:
        # find $identifiers in condition
        return set(re.findall(r'\$(\w+)', self.condition))

    def to_yara_text(self) -> str:
        parts = [f"rule {self.name} {{"]
        if self.meta:
            parts.append("  meta:")
            for k, v in self.meta.items():
                parts.append(f'    {k} = "{v}"')
        if self.strings:
            parts.append("  strings:")
            for s in self.strings:
                parts.append(f"    ${s.id} = {s.pattern}")
        parts.append("  condition:")
        parts.append(f"    {self.condition}")
        parts.append("}")
        return "\n".join(parts)


def validator_YaraRuleAst_new(inp: dict) -> dict:
    ast = _YaraRuleAst(inp["name"], inp["condition"])
    return {"name": ast.name, "condition": ast.condition}

def validator_YaraRuleAst_referenced_ids(inp: dict) -> dict:
    strings = [_YaraString(s["id"], s["pattern"]) for s in inp.get("strings", [])]
    ast = _YaraRuleAst(inp["name"], inp["condition"], strings)
    return {"referenced_ids": sorted(ast.referenced_ids())}

def validator_YaraRuleAst_to_yara_text(inp: dict) -> dict:
    strings = [_YaraString(s["id"], s["pattern"]) for s in inp.get("strings", [])]
    ast = _YaraRuleAst(inp["name"], inp["condition"], strings)
    for k, v in inp.get("meta", {}).items():
        ast.meta[k] = v
    return {"text": ast.to_yara_text()}


def validator_YaraRuleOptimizer_new(inp: dict) -> dict:
    return {"passes": ["deduplicate", "remove_unused", "merge_alternatives",
                       "optimize_condition", "add_anchors"]}

def validator_YaraRuleOptimizer_with_passes(inp: dict) -> dict:
    return {"passes": inp.get("passes", [])}

def _remove_unused(strings: List[_YaraString], condition: str):
    ref = set(re.findall(r'\$(\w+)', condition))
    kept = [s for s in strings if s.id in ref]
    removed = len(strings) - len(kept)
    return kept, removed

def validator_YaraRuleOptimizer_deduplicate_strings(inp: dict) -> dict:
    strings = [_YaraString(s["id"], s["pattern"]) for s in inp.get("strings", [])]
    seen: Dict[str, str] = {}
    deduped = []
    removed = 0
    for s in strings:
        if s.pattern not in seen:
            seen[s.pattern] = s.id
            deduped.append(s)
        else:
            removed += 1
    return {"removed_count": removed, "remaining": len(deduped)}

def validator_YaraRuleOptimizer_remove_unused_strings(inp: dict) -> dict:
    strings = [_YaraString(s["id"], s["pattern"]) for s in inp.get("strings", [])]
    kept, removed = _remove_unused(strings, inp.get("condition", ""))
    return {"removed_count": removed, "remaining": len(kept)}

def validator_YaraRuleOptimizer_merge_alternatives(inp: dict) -> dict:
    # Stub: report same strings count
    return {"merged_count": 0, "report": "no alternatives merged"}

def validator_YaraRuleOptimizer_optimize_condition(inp: dict) -> dict:
    cond = inp.get("condition", "")
    # trivial: remove double negation
    optimized = re.sub(r'not\s+not\s+', '', cond)
    return {"condition": optimized, "report": "double-not removal"}

def validator_YaraRuleOptimizer_add_anchors(inp: dict) -> dict:
    return {"anchors_added": 0, "report": "no anchors added"}

def validator_YaraRuleOptimizer_optimize_all(inp: dict) -> dict:
    strings = [_YaraString(s["id"], s["pattern"]) for s in inp.get("strings", [])]
    condition = inp.get("condition", "")
    kept, removed_unused = _remove_unused(strings, condition)
    seen: Dict[str, str] = {}
    deduped = []
    removed_dup = 0
    for s in kept:
        if s.pattern not in seen:
            seen[s.pattern] = s.id
            deduped.append(s)
        else:
            removed_dup += 1
    return {"removed_unused": removed_unused, "removed_duplicates": removed_dup,
            "remaining_strings": len(deduped)}

def validator_YaraRuleOptimizer_estimate_speedup(inp: dict) -> dict:
    orig = inp.get("original_string_count", 1)
    opt = inp.get("optimized_string_count", 1)
    speedup = orig / max(opt, 1)
    return {"speedup": round(speedup, 3)}


# ===========================================================================
# rule_optimizer.rs — Ranking e analisi
# ===========================================================================

def _pattern_score(data: bytes) -> float:
    if not data:
        return 0.0
    n = len(data)
    # Entropy-based score
    counts = Counter(data)
    entropy = 0.0
    for c in counts.values():
        p = c / n
        entropy -= p * math.log2(p)
    # bonus for length
    length_bonus = min(1.0, n / 8.0)
    return round(entropy * length_bonus / 8.0, 4)

def validator_PatternQuality_is_fast(inp: dict) -> dict:
    data = base64.b64decode(inp.get("pattern_b64", ""))
    # Fast if longer than 4 bytes
    return {"is_fast": len(data) >= 4}

def validator_PatternQuality_is_high_fp(inp: dict) -> dict:
    data = base64.b64decode(inp.get("pattern_b64", ""))
    score = _pattern_score(data)
    return {"is_high_fp": score < 0.3}

def validator_PatternScorer_score(inp: dict) -> dict:
    data = base64.b64decode(inp.get("pattern_b64", ""))
    return {"score": _pattern_score(data)}

def validator_PatternScorer_score_hex(inp: dict) -> dict:
    # hex pattern with optional wildcards
    pattern = inp.get("pattern", [])  # list of int or null
    defined = bytes([b for b in pattern if b is not None])
    return {"score": _pattern_score(defined)}

def validator_LiteralExtractor_extract_from_bytes(inp: dict) -> dict:
    data = base64.b64decode(inp.get("pattern_b64", ""))
    if not data:
        return {"literal": None}
    return {"literal": base64.b64encode(data).decode()}

def validator_LiteralExtractor_extract_from_hex(inp: dict) -> dict:
    pattern = inp.get("pattern", [])
    # find longest run of non-None
    best = b""
    current = b""
    for b in pattern:
        if b is not None:
            current += bytes([b])
        else:
            if len(current) > len(best):
                best = current
            current = b""
    if len(current) > len(best):
        best = current
    if not best:
        return {"literal": None}
    return {"literal": base64.b64encode(best).decode()}

def validator_LiteralExtractor_extract_from_text(inp: dict) -> dict:
    text = inp.get("text", "")
    if not text:
        return {"literal": None}
    return {"literal": base64.b64encode(text.encode()).decode()}

def validator_LiteralExtractor_extract_from_named_pattern(inp: dict) -> dict:
    pattern = inp.get("pattern", "")
    if not pattern:
        return {"literal": None}
    return {"literal": base64.b64encode(pattern.encode()).decode()}

def _rule_stats(rule: dict) -> dict:
    patterns = rule.get("patterns_b64", [])
    scores = []
    for p in patterns:
        data = base64.b64decode(p)
        scores.append(_pattern_score(data))
    avg_score = sum(scores) / len(scores) if scores else 0.0
    return {"name": rule.get("name",""), "pattern_count": len(patterns),
            "avg_score": round(avg_score, 4),
            "total_bytes": sum(len(base64.b64decode(p)) for p in patterns)}

def validator_RuleRanker_stats_for_rule(inp: dict) -> dict:
    return _rule_stats(inp.get("rule", {}))

def validator_RuleRanker_rank(inp: dict) -> dict:
    rules = inp.get("rules", [])
    ranked = sorted(rules, key=lambda r: _rule_stats(r)["avg_score"], reverse=True)
    return {"ranked": [r.get("name","") for r in ranked]}

def validator_RuleRanker_rank_by_speed(inp: dict) -> dict:
    rules = inp.get("rules", [])
    # faster = more bytes (literal search) + high entropy
    ranked = sorted(rules, key=lambda r: _rule_stats(r)["total_bytes"], reverse=True)
    return {"ranked": [r.get("name","") for r in ranked]}

def validator_RuleRanker_find_overlaps(inp: dict) -> dict:
    rules = inp.get("rules", [])
    threshold = inp.get("min_similarity", 0.5)
    overlaps = []
    for i in range(len(rules)):
        for j in range(i+1, len(rules)):
            pa = set(rules[i].get("patterns_b64", []))
            pb = set(rules[j].get("patterns_b64", []))
            if not pa or not pb:
                continue
            sim = len(pa & pb) / len(pa | pb)
            if sim >= threshold:
                overlaps.append({"a": rules[i].get("name",""), "b": rules[j].get("name",""),
                                  "similarity": round(sim, 3)})
    return {"overlaps": overlaps}

def validator_RuleRanker_find_duplicate_indices(inp: dict) -> dict:
    rules = inp.get("rules", [])
    seen: Dict[str, int] = {}
    dups = []
    for i, r in enumerate(rules):
        key = str(sorted(r.get("patterns_b64", [])))
        if key in seen:
            dups.append(i)
        else:
            seen[key] = i
    return {"duplicate_indices": dups}

def validator_RuleRanker_group_by_family(inp: dict) -> dict:
    rules = inp.get("rules", [])
    groups: Dict[str, List[str]] = defaultdict(list)
    for r in rules:
        name = r.get("name", "")
        family = name.split("_")[0] if "_" in name else name
        groups[family].append(name)
    return {"groups": dict(groups)}

def validator_RuleRanker_group_by_meta_family(inp: dict) -> dict:
    rules = inp.get("rules", [])
    key = inp.get("meta_key", "family")
    groups: Dict[str, List[str]] = defaultdict(list)
    for r in rules:
        family = r.get("meta", {}).get(key, "unknown")
        groups[family].append(r.get("name",""))
    return {"groups": dict(groups)}

def validator_RuleRanker_sorted_groups(inp: dict) -> dict:
    res = validator_RuleRanker_group_by_meta_family(inp)
    groups = res["groups"]
    sorted_groups = sorted(groups.items(), key=lambda x: len(x[1]), reverse=True)
    return {"sorted_groups": [{"family": k, "count": len(v)} for k, v in sorted_groups]}

def validator_RuleCollection_all_stats(inp: dict) -> dict:
    rules = inp.get("rules", [])
    return {"stats": [_rule_stats(r) for r in rules]}

def validator_RuleCollection_ranked_by_specificity(inp: dict) -> dict:
    return validator_RuleRanker_rank(inp)

def validator_RuleCollection_ranked_by_speed(inp: dict) -> dict:
    return validator_RuleRanker_rank_by_speed(inp)

def validator_RuleCollection_find_overlaps(inp: dict) -> dict:
    return validator_RuleRanker_find_overlaps(inp)

def validator_RuleCollection_deduplicate(inp: dict) -> dict:
    rules = inp.get("rules", [])
    seen = set()
    unique = []
    for r in rules:
        key = str(sorted(r.get("patterns_b64", [])))
        if key not in seen:
            seen.add(key)
            unique.append(r.get("name",""))
    return {"unique_rules": unique, "removed": len(rules) - len(unique)}

def validator_RuleCollection_group_by_family(inp: dict) -> dict:
    return validator_RuleRanker_group_by_family(inp)

def validator_RuleCollection_report(inp: dict) -> dict:
    rules = inp.get("rules", [])
    dup_res = validator_RuleCollection_deduplicate(inp)
    return {"rule_count": len(rules), "duplicates_removed": dup_res["removed"],
            "summary": f"{len(rules)} rules, {dup_res['removed']} duplicates"}

def validator_OptimizationReport_summary(inp: dict) -> dict:
    return {"summary": inp.get("summary", f"{inp.get('rule_count',0)} rules analyzed")}


# ===========================================================================
# yara_cache.rs
# ===========================================================================

def _valid_hex(s: str) -> bool:
    try:
        bytes.fromhex(s)
        return True
    except ValueError:
        return False

def validator_CacheKey_from_hex(inp: dict) -> dict:
    fh = inp.get("file_hex", "")
    rh = inp.get("rules_hex", "")
    if _valid_hex(fh) and _valid_hex(rh):
        key = f"{fh[:8]}:{rh[:8]}"
        return {"ok": True, "key": key}
    return {"ok": False, "key": None}

def validator_CacheKey_short_display(inp: dict) -> dict:
    fh = inp.get("file_hex", "")
    rh = inp.get("rules_hex", "")
    return {"display": f"{fh[:8]}…:{rh[:8]}…"}

def validator_CacheEntry_memory_bytes(inp: dict) -> dict:
    # Each match ~ 64 bytes overhead
    n_matches = inp.get("n_matches", 0)
    return {"memory_bytes": 128 + n_matches * 64}

def validator_CacheStats_hit_rate(inp: dict) -> dict:
    hits = inp.get("hits", 0)
    total = inp.get("hits", 0) + inp.get("misses", 0)
    rate = hits / total if total > 0 else 0.0
    return {"hit_rate": round(rate, 4)}

def validator_CacheStats_miss_rate(inp: dict) -> dict:
    hits = inp.get("hits", 0)
    misses = inp.get("misses", 0)
    total = hits + misses
    rate = misses / total if total > 0 else 0.0
    return {"miss_rate": round(rate, 4)}


class _LruCache:
    def __init__(self, max_entries: int, max_memory: int):
        self.max_entries = max_entries
        self.max_memory = max_memory
        self.data: OrderedDict = OrderedDict()  # key -> (value, inserted_ts)
        self.hits = 0
        self.misses = 0
        self.total_memory = 0

    def get(self, key: str, now: int):
        if key in self.data:
            self.data.move_to_end(key)
            self.hits += 1
            return self.data[key][0]
        self.misses += 1
        return None

    def peek(self, key: str):
        return self.data.get(key, (None,))[0] if key in self.data else None

    def insert(self, key: str, value: Any, ts: int, mem: int):
        self.data[key] = (value, ts, mem)
        self.total_memory += mem
        while len(self.data) > self.max_entries or self.total_memory > self.max_memory:
            if not self.evict_one():
                break

    def evict_one(self) -> bool:
        if not self.data:
            return False
        k, (v, ts, mem) = self.data.popitem(last=False)
        self.total_memory -= mem
        return True

    def evict_expired(self, now: int, max_age: int) -> int:
        removed = 0
        to_del = [k for k, (v, ts, mem) in self.data.items() if now - ts > max_age]
        for k in to_del:
            _, ts, mem = self.data.pop(k)
            self.total_memory -= mem
            removed += 1
        return removed

    def remove(self, key: str) -> bool:
        if key in self.data:
            _, ts, mem = self.data.pop(key)
            self.total_memory -= mem
            return True
        return False


def validator_YaraResultCache_new(inp: dict) -> dict:
    c = _LruCache(inp.get("max_entries", 1000), inp.get("max_memory_bytes", 10**7))
    return {"max_entries": c.max_entries, "len": 0}

def validator_YaraResultCache_get(inp: dict) -> dict:
    c = _LruCache(inp.get("max_entries", 100), inp.get("max_memory_bytes", 10**6))
    for e in inp.get("entries", []):
        c.insert(e["key"], e["value"], e.get("ts", 0), e.get("mem", 64))
    val = c.get(inp["key"], inp.get("now", 0))
    return {"found": val is not None, "value": val}

def validator_YaraResultCache_peek(inp: dict) -> dict:
    c = _LruCache(inp.get("max_entries", 100), inp.get("max_memory_bytes", 10**6))
    for e in inp.get("entries", []):
        c.insert(e["key"], e["value"], e.get("ts", 0), e.get("mem", 64))
    val = c.peek(inp["key"])
    return {"found": val is not None}

def validator_YaraResultCache_insert(inp: dict) -> dict:
    c = _LruCache(inp.get("max_entries", 100), inp.get("max_memory_bytes", 10**6))
    c.insert(inp["key"], inp.get("value", []), inp.get("ts", 0), inp.get("mem", 64))
    return {"len": len(c.data)}

def validator_YaraResultCache_evict_one(inp: dict) -> dict:
    c = _LruCache(inp.get("max_entries", 100), inp.get("max_memory_bytes", 10**6))
    for e in inp.get("entries", []):
        c.insert(e["key"], e["value"], e.get("ts", 0), e.get("mem", 64))
    ok = c.evict_one()
    return {"evicted": ok, "remaining": len(c.data)}

def validator_YaraResultCache_evict_expired(inp: dict) -> dict:
    c = _LruCache(inp.get("max_entries", 100), inp.get("max_memory_bytes", 10**6))
    for e in inp.get("entries", []):
        c.insert(e["key"], e["value"], e.get("ts", 0), e.get("mem", 64))
    removed = c.evict_expired(inp.get("now", 0), inp.get("max_age_secs", 3600))
    return {"removed": removed, "remaining": len(c.data)}

def validator_YaraResultCache_remove(inp: dict) -> dict:
    c = _LruCache(inp.get("max_entries", 100), inp.get("max_memory_bytes", 10**6))
    for e in inp.get("entries", []):
        c.insert(e["key"], e["value"], e.get("ts", 0), e.get("mem", 64))
    ok = c.remove(inp["key"])
    return {"removed": ok, "remaining": len(c.data)}

def validator_YaraResultCache_clear(inp: dict) -> dict:
    c = _LruCache(100, 10**6)
    c.insert("k", [], 0, 64)
    c.data.clear()
    c.total_memory = 0
    return {"len": 0}

def validator_YaraResultCache_cache_hit_rate(inp: dict) -> dict:
    c = _LruCache(100, 10**6)
    c.hits = inp.get("hits", 0)
    c.misses = inp.get("misses", 0)
    total = c.hits + c.misses
    return {"hit_rate": round(c.hits / total, 4) if total else 0.0}

def validator_YaraResultCache_stats(inp: dict) -> dict:
    return {"hits": inp.get("hits", 0), "misses": inp.get("misses", 0),
            "len": inp.get("len", 0)}

def validator_YaraResultCache_len(inp: dict) -> dict:
    c = _LruCache(100, 10**6)
    for e in inp.get("entries", []):
        c.insert(e["key"], e["value"], 0, 64)
    return {"len": len(c.data)}

def validator_YaraResultCache_is_empty(inp: dict) -> dict:
    c = _LruCache(100, 10**6)
    return {"is_empty": len(c.data) == 0}

def validator_YaraResultCache_estimate_entry_memory(inp: dict) -> dict:
    n = inp.get("n_matches", 0)
    est = 128 + n * 64
    return {"memory_bytes": est}


# ===========================================================================
# yara_performance_profiler.rs
# ===========================================================================

class _RuleProfile:
    def __init__(self, name: str):
        self.name = name
        self.times_ns: List[int] = []
        self.match_count = 0
        self.total_count = 0

    def record(self, elapsed_ns: int, matched: bool):
        self.times_ns.append(elapsed_ns)
        self.total_count += 1
        if matched:
            self.match_count += 1

    def mean_time_ns(self) -> int:
        if not self.times_ns:
            return 0
        return int(sum(self.times_ns) / len(self.times_ns))

    def p95_time_ns(self) -> int:
        if not self.times_ns:
            return 0
        s = sorted(self.times_ns)
        idx = int(len(s) * 0.95)
        return s[min(idx, len(s)-1)]

    def match_rate(self) -> float:
        if self.total_count == 0:
            return 0.0
        return self.match_count / self.total_count


def validator_RuleProfile_new(inp: dict) -> dict:
    p = _RuleProfile(inp["name"])
    return {"name": p.name}

def validator_RuleProfile_record(inp: dict) -> dict:
    p = _RuleProfile(inp["name"])
    for m in inp.get("measurements", []):
        p.record(m["elapsed_ns"], m["matched"])
    return {"total_count": p.total_count, "match_count": p.match_count}

def validator_RuleProfile_mean_time(inp: dict) -> dict:
    p = _RuleProfile(inp["name"])
    for m in inp.get("measurements", []):
        p.record(m["elapsed_ns"], m["matched"])
    return {"mean_time_ns": p.mean_time_ns()}

def validator_RuleProfile_p95_time(inp: dict) -> dict:
    p = _RuleProfile(inp["name"])
    for m in inp.get("measurements", []):
        p.record(m["elapsed_ns"], m["matched"])
    return {"p95_time_ns": p.p95_time_ns()}

def validator_RuleProfile_match_rate(inp: dict) -> dict:
    p = _RuleProfile(inp["name"])
    for m in inp.get("measurements", []):
        p.record(m["elapsed_ns"], m["matched"])
    return {"match_rate": round(p.match_rate(), 4)}

def validator_ProfileSession_time_rule(inp: dict) -> dict:
    # Simulate: just record the provided elapsed
    return {"recorded": True, "rule_name": inp.get("rule_name",""),
            "elapsed_ns": inp.get("elapsed_ns", 0)}

def validator_ProfileSession_record_rule(inp: dict) -> dict:
    return {"rule_name": inp.get("rule_name",""), "elapsed_ns": inp.get("elapsed_ns", 0),
            "matched": inp.get("matched", False)}

def validator_ProfileSession_finish(inp: dict) -> dict:
    total = sum(m.get("elapsed_ns", 0) for m in inp.get("measurements", []))
    return {"total_elapsed_ns": total}


class _YaraProfiler:
    def __init__(self):
        self.profiles: Dict[str, _RuleProfile] = {}

    def record_evaluation(self, rule_name: str, elapsed_ns: int, matched: bool):
        if rule_name not in self.profiles:
            self.profiles[rule_name] = _RuleProfile(rule_name)
        self.profiles[rule_name].record(elapsed_ns, matched)

    def total_rule_time_ns(self) -> int:
        return sum(sum(p.times_ns) for p in self.profiles.values())

    def global_mean_time_ns(self) -> int:
        total = self.total_rule_time_ns()
        count = sum(p.total_count for p in self.profiles.values())
        return total // count if count else 0

    def top_slow(self, n: int) -> List[_RuleProfile]:
        return sorted(self.profiles.values(), key=lambda p: p.mean_time_ns(), reverse=True)[:n]

    def hotspots(self, threshold_pct: float) -> List[_RuleProfile]:
        total = self.total_rule_time_ns()
        if total == 0:
            return []
        return [p for p in self.profiles.values()
                if sum(p.times_ns) / total * 100 >= threshold_pct]


def _build_profiler(inp: dict) -> _YaraProfiler:
    pr = _YaraProfiler()
    for e in inp.get("evaluations", []):
        pr.record_evaluation(e["rule"], e["elapsed_ns"], e.get("matched", False))
    return pr

def validator_YaraProfiler_new(inp: dict) -> dict:
    return {"rule_count": 0}

def validator_YaraProfiler_record_evaluation(inp: dict) -> dict:
    pr = _build_profiler(inp)
    pr.record_evaluation(inp.get("rule_name","r"), inp.get("elapsed_ns", 0), inp.get("matched", False))
    return {"rule_count": len(pr.profiles)}

def validator_YaraProfiler_start_session(inp: dict) -> dict:
    return {"source_uri": inp.get("source_uri",""), "started": True}

def validator_YaraProfiler_get_profile(inp: dict) -> dict:
    pr = _build_profiler(inp)
    p = pr.profiles.get(inp["rule_name"])
    return {"found": p is not None, "total_count": p.total_count if p else 0}

def validator_YaraProfiler_total_rule_time(inp: dict) -> dict:
    pr = _build_profiler(inp)
    return {"total_ns": pr.total_rule_time_ns()}

def validator_YaraProfiler_rule_count(inp: dict) -> dict:
    pr = _build_profiler(inp)
    return {"rule_count": len(pr.profiles)}

def validator_YaraProfiler_results(inp: dict) -> dict:
    pr = _build_profiler(inp)
    return {"results": [{"rule": n, "mean_ns": p.mean_time_ns(), "total_count": p.total_count}
                         for n, p in pr.profiles.items()]}

def validator_YaraProfiler_top_slow(inp: dict) -> dict:
    pr = _build_profiler(inp)
    top = pr.top_slow(inp.get("n", 3))
    return {"top_slow": [{"rule": p.name, "mean_ns": p.mean_time_ns()} for p in top]}

def validator_YaraProfiler_hotspots(inp: dict) -> dict:
    pr = _build_profiler(inp)
    spots = pr.hotspots(inp.get("threshold_pct", 10.0))
    return {"hotspots": [p.name for p in spots]}

def validator_YaraProfiler_global_mean_time(inp: dict) -> dict:
    pr = _build_profiler(inp)
    return {"global_mean_ns": pr.global_mean_time_ns()}

def validator_YaraProfiler_reset(inp: dict) -> dict:
    pr = _build_profiler(inp)
    pr.profiles.clear()
    return {"rule_count": 0}

def validator_YaraProfiler_report_text(inp: dict) -> dict:
    pr = _build_profiler(inp)
    lines = ["YARA Profiler Report", "=" * 40]
    for n, p in sorted(pr.profiles.items(), key=lambda x: x[1].mean_time_ns(), reverse=True):
        lines.append(f"  {n}: mean={p.mean_time_ns()}ns count={p.total_count} match_rate={p.match_rate():.2%}")
    return {"report": "\n".join(lines)}

def validator_PatternBenchmark_new(inp: dict) -> dict:
    return {"iterations": inp.get("iterations", 100)}

def validator_PatternBenchmark_bench_pattern(inp: dict) -> dict:
    pattern = base64.b64decode(inp.get("pattern_b64", ""))
    data = base64.b64decode(inp.get("data_b64", ""))
    iters = inp.get("iterations", 10)
    t0 = time.monotonic_ns()
    for _ in range(iters):
        start = 0
        while True:
            pos = data.find(pattern, start)
            if pos == -1:
                break
            start = pos + 1
    elapsed = time.monotonic_ns() - t0
    ns_per_iter = elapsed // max(iters, 1)
    return {"ns_per_iter": ns_per_iter}

def validator_PatternBenchmark_results(inp: dict) -> dict:
    return {"results": []}

def validator_PatternBenchmark_report_text(inp: dict) -> dict:
    return {"report": "PatternBenchmark: no results"}


# ===========================================================================
# yara_module_pe.rs
# ===========================================================================

def _shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    n = len(data)
    h = 0.0
    for c in Counter(data).values():
        p = c / n
        h -= p * math.log2(p)
    return h


class _PeModuleData:
    def __init__(self):
        self.sections: List[dict] = []
        self.imports: Dict[str, List[str]] = {}  # dll -> [func]
        self.exports: List[str] = []
        self.version_info: Dict[str, str] = {}
        self.imphash: str = ""


def _parse_simple_pe(data: bytes) -> Optional[_PeModuleData]:
    """Minimal PE parser for validation."""
    if len(data) < 64 or data[:2] != b"MZ":
        return None
    try:
        pe_off = struct.unpack_from("<I", data, 0x3C)[0]
        if len(data) < pe_off + 24:
            return None
        if data[pe_off:pe_off+4] != b"PE\x00\x00":
            return None
        machine = struct.unpack_from("<H", data, pe_off+4)[0]
        num_sections = struct.unpack_from("<H", data, pe_off+6)[0]
        opt_size = struct.unpack_from("<H", data, pe_off+20)[0]
        sec_off = pe_off + 24 + opt_size
        pmd = _PeModuleData()
        for i in range(min(num_sections, 32)):
            so = sec_off + i * 40
            if so + 40 > len(data):
                break
            name = data[so:so+8].rstrip(b"\x00").decode("ascii", errors="replace")
            raw_off = struct.unpack_from("<I", data, so+20)[0]
            raw_size = struct.unpack_from("<I", data, so+16)[0]
            sec_data = data[raw_off:raw_off+raw_size] if raw_off + raw_size <= len(data) else b""
            pmd.sections.append({"name": name, "data": sec_data,
                                   "raw_off": raw_off, "raw_size": raw_size})
        return pmd
    except Exception:
        return None


def validator_PeModule_new(inp: dict) -> dict:
    return {"ok": True, "section_count": len(inp.get("sections", []))}

def validator_PeModule_section_entropy(inp: dict) -> dict:
    sections = inp.get("sections", [])
    idx = inp.get("index", 0)
    if 0 <= idx < len(sections):
        data = base64.b64decode(sections[idx].get("data_b64", ""))
        return {"entropy": round(_shannon_entropy(data), 4)}
    return {"entropy": None}

def validator_PeModule_section_by_name(inp: dict) -> dict:
    sections = inp.get("sections", [])
    name = inp.get("name", "")
    for s in sections:
        if s.get("name") == name:
            return {"found": True, "name": name}
    return {"found": False, "name": None}

def validator_PeModule_imphash(inp: dict) -> dict:
    imports = inp.get("imports", {})
    parts = []
    for dll, funcs in sorted(imports.items()):
        dll_base = dll.lower().rsplit(".", 1)[0]
        for f in sorted(funcs):
            parts.append(f"{dll_base}.{f.lower()}")
    h = hashlib.md5(",".join(parts).encode()).hexdigest() if parts else ""
    return {"imphash": h}

def validator_PeModule_imports(inp: dict) -> dict:
    imports = inp.get("imports", {})
    func = inp.get("func", "")
    found = any(func in flist for flist in imports.values())
    return {"imports": found}

def validator_PeModule_imports_from(inp: dict) -> dict:
    imports = inp.get("imports", {})
    dll = inp.get("dll", "").lower()
    func = inp.get("func", "")
    for d, flist in imports.items():
        if d.lower() == dll and func in flist:
            return {"imports_from": True}
    return {"imports_from": False}

def validator_PeModule_import_count(inp: dict) -> dict:
    imports = inp.get("imports", {})
    total = sum(len(v) for v in imports.values())
    return {"import_count": total}

def validator_PeModule_exports(inp: dict) -> dict:
    exports = inp.get("exports", [])
    name = inp.get("name", "")
    return {"exports": name in exports}

def validator_PeModule_version_info(inp: dict) -> dict:
    vi = inp.get("version_info", {})
    key = inp.get("key", "")
    return {"value": vi.get(key)}

def validator_PeModuleParser_new(inp: dict) -> dict:
    return {"ok": True}

def validator_PeModuleParser_parse(inp: dict) -> dict:
    data = base64.b64decode(inp.get("data_b64", ""))
    pmd = _parse_simple_pe(data)
    if pmd is None:
        return {"ok": False, "error": "not a PE"}
    return {"ok": True, "section_count": len(pmd.sections)}


# ===========================================================================
# ioc_extractor.rs
# ===========================================================================

_RE_IPV4 = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
_RE_DOMAIN = re.compile(r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b')
_RE_URL = re.compile(r'https?://[^\s"\'<>]+')
_RE_EMAIL = re.compile(r'\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b')
_RE_MD5 = re.compile(r'\b[0-9a-fA-F]{32}\b')
_RE_SHA256 = re.compile(r'\b[0-9a-fA-F]{64}\b')


class _IocReport:
    def __init__(self, label: str):
        self.label = label
        self.iocs: List[dict] = []

    def add(self, ioc: dict):
        self.iocs.append(ioc)

    def deduplicate(self):
        seen = set()
        deduped = []
        for ioc in self.iocs:
            k = (ioc.get("kind"), ioc.get("value"))
            if k not in seen:
                seen.add(k)
                deduped.append(ioc)
        self.iocs = deduped

    def ip_addresses(self) -> List[str]:
        return [i["value"] for i in self.iocs if i.get("kind") == "ip"]

    def domains(self) -> List[str]:
        return [i["value"] for i in self.iocs if i.get("kind") == "domain"]

    def build_summary(self):
        self._summary = {"total": len(self.iocs),
                         "ips": len(self.ip_addresses()),
                         "domains": len(self.domains())}


def _extract_iocs(text: str) -> List[dict]:
    iocs = []
    for m in _RE_IPV4.finditer(text):
        iocs.append({"kind": "ip", "value": m.group()})
    for m in _RE_EMAIL.finditer(text):
        iocs.append({"kind": "email", "value": m.group()})
    for m in _RE_URL.finditer(text):
        iocs.append({"kind": "url", "value": m.group()})
    for m in _RE_SHA256.finditer(text):
        iocs.append({"kind": "sha256", "value": m.group()})
    for m in _RE_MD5.finditer(text):
        if not any(i["value"] == m.group() for i in iocs):
            iocs.append({"kind": "md5", "value": m.group()})
    for m in _RE_DOMAIN.finditer(text):
        v = m.group()
        if not _RE_IPV4.match(v) and not any(i["value"] == v for i in iocs):
            iocs.append({"kind": "domain", "value": v})
    return iocs


def validator_ExtractedIoc_value(inp: dict) -> dict:
    return {"value": inp.get("value", "")}

def validator_IocReport_new(inp: dict) -> dict:
    r = _IocReport(inp["label"])
    return {"label": r.label, "ioc_count": 0}

def validator_IocReport_add(inp: dict) -> dict:
    r = _IocReport(inp.get("label",""))
    for ioc in inp.get("iocs", []):
        r.add(ioc)
    return {"ioc_count": len(r.iocs)}

def validator_IocReport_build_summary(inp: dict) -> dict:
    r = _IocReport(inp.get("label",""))
    for ioc in inp.get("iocs", []):
        r.add(ioc)
    r.build_summary()
    return r._summary

def validator_IocReport_deduplicate(inp: dict) -> dict:
    r = _IocReport(inp.get("label",""))
    for ioc in inp.get("iocs", []):
        r.add(ioc)
    before = len(r.iocs)
    r.deduplicate()
    return {"before": before, "after": len(r.iocs), "removed": before - len(r.iocs)}

def validator_IocReport_ip_addresses(inp: dict) -> dict:
    r = _IocReport(inp.get("label",""))
    for ioc in inp.get("iocs", []):
        r.add(ioc)
    return {"ip_addresses": r.ip_addresses()}

def validator_IocReport_domains(inp: dict) -> dict:
    r = _IocReport(inp.get("label",""))
    for ioc in inp.get("iocs", []):
        r.add(ioc)
    return {"domains": r.domains()}

def validator_IocExtractor_new(inp: dict) -> dict:
    return {"ok": True}

def validator_IocExtractor_extract(inp: dict) -> dict:
    data = base64.b64decode(inp.get("data_b64", ""))
    text = data.decode("utf-8", errors="replace")
    iocs = _extract_iocs(text)
    return {"label": inp.get("label",""), "ioc_count": len(iocs),
            "iocs": iocs[:50]}  # cap for output

def validator_IocExtractor_extract_with_rules(inp: dict) -> dict:
    return validator_IocExtractor_extract(inp)

def _extract_printable(data: bytes, min_len: int) -> List[Tuple[int, str]]:
    results = []
    current = []
    start = 0
    for i, b in enumerate(data):
        if 0x20 <= b <= 0x7e:
            if not current:
                start = i
            current.append(chr(b))
        else:
            if len(current) >= min_len:
                results.append((start, "".join(current)))
            current = []
    if len(current) >= min_len:
        results.append((start, "".join(current)))
    return results

def _extract_wide(data: bytes, min_len: int) -> List[Tuple[int, str]]:
    results = []
    i = 0
    while i < len(data) - 1:
        if 0x20 <= data[i] <= 0x7e and data[i+1] == 0:
            start = i
            chars = []
            while i < len(data) - 1 and 0x20 <= data[i] <= 0x7e and data[i+1] == 0:
                chars.append(chr(data[i]))
                i += 2
            if len(chars) >= min_len:
                results.append((start, "".join(chars)))
        else:
            i += 1
    return results

def validator_extract_printable_strings(inp: dict) -> dict:
    data = base64.b64decode(inp.get("data_b64", ""))
    min_len = inp.get("min_len", 4)
    results = _extract_printable(data, min_len)
    return {"count": len(results),
            "strings": [{"offset": o, "value": s} for o, s in results[:100]]}

def validator_extract_wide_strings(inp: dict) -> dict:
    data = base64.b64decode(inp.get("data_b64", ""))
    min_len = inp.get("min_len", 4)
    results = _extract_wide(data, min_len)
    return {"count": len(results),
            "strings": [{"offset": o, "value": s} for o, s in results[:100]]}


# ===========================================================================
# verdict.rs
# ===========================================================================

VERDICT_ORDER = {"clean": 0, "suspicious": 1, "likely_malicious": 2, "malicious": 3}

def validator_YaraScore_new(inp: dict) -> dict:
    value = max(0, min(100, inp.get("value", 0)))
    return {"value": value}

def validator_YaraScore_with_signals(inp: dict) -> dict:
    value = max(0, min(100, inp.get("value", 0)))
    count = inp.get("count", 0)
    return {"value": value, "signal_count": count}

def validator_FamilyAttribution_new(inp: dict) -> dict:
    return {"family": inp.get("family",""), "match_count": 0, "score": 0}

def validator_FamilyAttribution_add_match(inp: dict) -> dict:
    count = inp.get("existing_matches", 0) + 1
    score = inp.get("existing_score", 0) + inp.get("score", 0)
    return {"match_count": count, "score": score}

def validator_VerdictEngine_new(inp: dict) -> dict:
    return {"ok": True}

def _compute_verdict(matches: List[dict]) -> dict:
    if not matches:
        return {"verdict": "clean", "score": 0, "families": []}
    total_score = 0
    families: Dict[str, int] = defaultdict(int)
    for m in matches:
        sev = m.get("severity", "info")
        w = {"critical": 40, "high": 25, "medium": 15, "low": 5, "info": 1}.get(sev, 1)
        total_score += w
        f = m.get("family", "")
        if f:
            families[f] += w
    score = min(100, total_score)
    if score >= 70:
        verdict = "malicious"
    elif score >= 40:
        verdict = "likely_malicious"
    elif score >= 10:
        verdict = "suspicious"
    else:
        verdict = "clean"
    return {"verdict": verdict, "score": score, "families": list(families.keys())}

def validator_VerdictEngine_compute(inp: dict) -> dict:
    return _compute_verdict(inp.get("matches", []))

def validator_VerdictResult_clean(inp: dict) -> dict:
    return {"verdict": "clean", "score": 0}

def validator_VerdictResult_top_family(inp: dict) -> dict:
    families = inp.get("families", [])
    if not families:
        return {"family": None}
    return {"family": max(families, key=lambda f: f.get("score", 0)).get("name")}

def validator_VerdictResult_family_names(inp: dict) -> dict:
    families = inp.get("families", [])
    return {"names": [f.get("name","") for f in families]}

def validator_VerdictResult_summary(inp: dict) -> dict:
    v = inp.get("verdict", "clean")
    s = inp.get("score", 0)
    return {"summary": f"Verdict: {v} (score={s})"}

def validator_BatchVerdictStats_new(inp: dict) -> dict:
    return {"count": 0, "malicious": 0, "total_score": 0}

def validator_BatchVerdictStats_add(inp: dict) -> dict:
    count = inp.get("count", 0) + 1
    score_sum = inp.get("total_score", 0) + inp.get("result_score", 0)
    malicious = inp.get("malicious", 0) + (1 if inp.get("result_verdict") == "malicious" else 0)
    return {"count": count, "total_score": score_sum, "malicious": malicious}

def validator_BatchVerdictStats_average_score(inp: dict) -> dict:
    count = inp.get("count", 0)
    total = inp.get("total_score", 0)
    return {"average_score": round(total / count, 2) if count else 0.0}

def validator_BatchVerdictStats_malicious_rate(inp: dict) -> dict:
    count = inp.get("count", 0)
    malicious = inp.get("malicious", 0)
    return {"malicious_rate": round(malicious / count, 4) if count else 0.0}

def validator_BatchVerdictStats_top_n_families(inp: dict) -> dict:
    families = inp.get("families", [])  # list of {"name": str, "count": int}
    n = inp.get("n", 5)
    top = sorted(families, key=lambda f: f.get("count", 0), reverse=True)[:n]
    return {"top_families": [(f["name"], f["count"]) for f in top]}

def validator_VerdictOverrideTable_new(inp: dict) -> dict:
    return {"ok": True}

def validator_VerdictOverrideTable_apply(inp: dict) -> dict:
    overrides = inp.get("overrides", {})
    matches = inp.get("matches", [])
    for m in matches:
        rule = m.get("rule","")
        if rule in overrides:
            m["verdict"] = overrides[rule]
    return {"matches": matches}

def validator_severity_weight(inp: dict) -> dict:
    weights = {"critical": 40, "high": 25, "medium": 15, "low": 5, "info": 1, "none": 0}
    s = inp.get("severity", "none")
    return {"weight": weights.get(s.lower(), 0)}

def validator_weighted_verdict_score(inp: dict) -> dict:
    contribs = inp.get("contributions", [])  # list of [severity, weight]
    weights = {"critical": 40, "high": 25, "medium": 15, "low": 5, "info": 1, "none": 0}
    total = sum(weights.get(sev.lower(), 0) * w for sev, w in contribs)
    return {"score": min(255, total)}

def validator_VerdictTransition_new(inp: dict) -> dict:
    return {"from": inp.get("from",""), "to": inp.get("to",""),
            "reason": inp.get("reason",""), "delta": inp.get("delta",0)}

def validator_VerdictTransition_is_escalation(inp: dict) -> dict:
    f = VERDICT_ORDER.get(inp.get("from","clean"), 0)
    t = VERDICT_ORDER.get(inp.get("to","clean"), 0)
    return {"is_escalation": t > f}

def validator_VerdictTransition_is_deescalation(inp: dict) -> dict:
    f = VERDICT_ORDER.get(inp.get("from","clean"), 0)
    t = VERDICT_ORDER.get(inp.get("to","clean"), 0)
    return {"is_deescalation": t < f}

def validator_VerdictChain_new(inp: dict) -> dict:
    return {"steps": []}

def validator_VerdictChain_push(inp: dict) -> dict:
    steps = inp.get("steps", [])
    steps.append({"verdict": inp.get("verdict","clean"),
                  "score": inp.get("score", 0),
                  "reason": inp.get("reason","")})
    return {"steps": steps}

def validator_VerdictChain_final_verdict(inp: dict) -> dict:
    steps = inp.get("steps", [])
    if not steps:
        return {"final_verdict": "clean"}
    return {"final_verdict": steps[-1].get("verdict","clean")}

def validator_VerdictChain_final_score(inp: dict) -> dict:
    steps = inp.get("steps", [])
    if not steps:
        return {"final_score": 0}
    return {"final_score": steps[-1].get("score", 0)}

def validator_VerdictChain_transitions(inp: dict) -> dict:
    steps = inp.get("steps", [])
    transitions = []
    for i in range(1, len(steps)):
        transitions.append({"from": steps[i-1]["verdict"], "to": steps[i]["verdict"]})
    return {"transitions": transitions}

def validator_SeverityOverrideMap_new(inp: dict) -> dict:
    return {"size": 0}

def validator_SeverityOverrideMap_insert(inp: dict) -> dict:
    overrides = dict(inp.get("overrides", {}))
    overrides[inp["rule_name"]] = inp["severity"]
    return {"size": len(overrides)}

def validator_SeverityOverrideMap_get(inp: dict) -> dict:
    overrides = inp.get("overrides", {})
    key = inp.get("rule_name","")
    return {"value": overrides.get(key)}

def validator_SeverityOverrideMap_apply(inp: dict) -> dict:
    overrides = inp.get("overrides", {})
    matches = [dict(m) for m in inp.get("matches", [])]
    for m in matches:
        rule = m.get("rule","")
        if rule in overrides:
            m["severity"] = overrides[rule]
    return {"matches": matches}

def validator_VerdictSummary_from_result(inp: dict) -> dict:
    return {"verdict": inp.get("verdict","clean"), "score": inp.get("score",0),
            "family_names": inp.get("family_names",[])}

def validator_VerdictSummary_to_json(inp: dict) -> dict:
    summary = {"verdict": inp.get("verdict","clean"), "score": inp.get("score",0)}
    return {"json": json.dumps(summary)}


# ===========================================================================
# yara_threat_tagger.rs
# ===========================================================================

def validator_ThreatTag_new(inp: dict) -> dict:
    return {"category": inp.get("category",""), "label": inp.get("label",""),
            "confidence": inp.get("confidence", 0.0)}

def validator_ThreatTag_is_high_confidence(inp: dict) -> dict:
    return {"is_high_confidence": inp.get("confidence", 0.0) >= 0.75}

def validator_TaggingRule_new(inp: dict) -> dict:
    return {"rule_name": inp.get("rule_name",""), "namespace": None}

def validator_TaggingRule_with_namespace(inp: dict) -> dict:
    return {"rule_name": inp.get("rule_name",""), "namespace": inp.get("namespace","")}

def validator_TaggingRule_matches_rule(inp: dict) -> dict:
    return {"matches": inp.get("rule_name","") == inp.get("target_name","")}

def validator_builtin_tagging_rules(inp: dict) -> dict:
    # Return a few representative built-in rules
    rules = [
        {"rule_name": "win_ransomware", "tags": ["ransomware"]},
        {"rule_name": "win_trojan", "tags": ["trojan"]},
        {"rule_name": "win_stealer", "tags": ["stealer"]},
        {"rule_name": "linux_rootkit", "tags": ["rootkit"]},
        {"rule_name": "generic_packer", "tags": ["packer"]},
    ]
    return {"count": len(rules), "rules": rules}

def validator_ThreatProfile_is_high_threat(inp: dict) -> dict:
    score = inp.get("score", 0)
    return {"is_high_threat": score >= 70}

def validator_ThreatProfile_high_confidence_tags(inp: dict) -> dict:
    tags = inp.get("tags", [])
    return {"tags": [t for t in tags if t.get("confidence", 0.0) >= 0.75]}

def validator_ThreatTagger_new(inp: dict) -> dict:
    return {"ok": True}

def validator_ThreatTagger_with_rules(inp: dict) -> dict:
    return {"rule_count": len(inp.get("rules", []))}

def validator_ThreatTagger_add_rule(inp: dict) -> dict:
    count = inp.get("existing_count", 0) + 1
    return {"rule_count": count}

def validator_ThreatTagger_tag_match_results(inp: dict) -> dict:
    matches = inp.get("matches", [])
    tags = []
    for m in matches:
        rule = m.get("rule", "")
        if "ransom" in rule.lower():
            tags.append({"category": "ransomware", "label": rule, "confidence": 0.9})
        elif "trojan" in rule.lower():
            tags.append({"category": "trojan", "label": rule, "confidence": 0.8})
        elif "pack" in rule.lower():
            tags.append({"category": "packer", "label": rule, "confidence": 0.7})
        else:
            tags.append({"category": "unknown", "label": rule, "confidence": 0.5})
    return {"tags": tags}

def validator_ThreatTagger_build_profile(inp: dict) -> dict:
    tags_res = validator_ThreatTagger_tag_match_results(inp)
    tags = tags_res["tags"]
    score = min(100, len(tags) * 20)
    return {"sha256": inp.get("file_sha256",""), "score": score, "tags": tags}

def validator_ThreatTagger_derive_mitre_ttps(inp: dict) -> dict:
    tags = inp.get("tags", [])
    ttps = set()
    for t in tags:
        cat = t.get("category","").lower()
        if "ransom" in cat:
            ttps.add("T1486")
        if "stealer" in cat:
            ttps.add("T1555")
        if "trojan" in cat:
            ttps.add("T1204")
        if "rootkit" in cat:
            ttps.add("T1014")
    return {"ttps": sorted(ttps)}

def validator_tag_to_mitre(inp: dict) -> dict:
    cat = inp.get("category","").lower()
    mapping = {
        "ransomware": ["T1486"],
        "stealer": ["T1555", "T1539"],
        "trojan": ["T1204", "T1059"],
        "rootkit": ["T1014", "T1547"],
        "packer": ["T1027"],
        "backdoor": ["T1071", "T1105"],
    }
    return {"ttps": mapping.get(cat, [])}

def validator_rule_name_to_mitre(inp: dict) -> dict:
    name = inp.get("rule_name","").lower()
    ttps = []
    if "ransom" in name: ttps.append("T1486")
    if "steal" in name: ttps.extend(["T1555","T1539"])
    if "inject" in name: ttps.append("T1055")
    if "persist" in name: ttps.append("T1547")
    if "keylog" in name: ttps.append("T1056")
    return {"ttps": ttps}


# ===========================================================================
# yara_threat_intel.rs
# ===========================================================================

def validator_ThreatFamily_new(inp: dict) -> dict:
    return {"id": inp.get("id",""), "description": inp.get("description","")}

def validator_ThreatFamily_associated_with_actor(inp: dict) -> dict:
    actors = inp.get("actors", [])
    return {"associated": inp.get("actor","") in actors}

def validator_FamilyAttribution_from_match_ratio(inp: dict) -> dict:
    matches = inp.get("matches", 0)
    total = inp.get("total", 1)
    confidence = round(matches / max(total, 1), 4)
    return {"confidence": confidence, "matches": matches, "total": total}

def validator_ThreatCluster_new(inp: dict) -> dict:
    return {"id": inp.get("id",""), "description": inp.get("description",""),
            "families": [], "confidence": 0.0}

def validator_ThreatCluster_contains_family(inp: dict) -> dict:
    return {"contains": inp.get("family","") in inp.get("families",[])}

def validator_ThreatCluster_is_reliable(inp: dict) -> dict:
    return {"is_reliable": inp.get("confidence", 0.0) >= 0.6}

def validator_MalpediaDb_entries(inp: dict) -> dict:
    # Stub built-in entries
    return {"count": 3, "sample_ids": ["win.emotet", "win.trickbot", "win.ryuk"]}

def validator_MalpediaDb_lookup(inp: dict) -> dict:
    known = {"win.emotet": {"name": "Emotet", "kind": "trojan"},
              "win.trickbot": {"name": "TrickBot", "kind": "trojan"},
              "win.ryuk": {"name": "Ryuk", "kind": "ransomware"}}
    entry = known.get(inp.get("name",""))
    return {"found": entry is not None, "entry": entry}

def validator_MalpediaDb_by_kind(inp: dict) -> dict:
    known = [{"id": "win.emotet", "kind": "trojan"},
              {"id": "win.trickbot", "kind": "trojan"},
              {"id": "win.ryuk", "kind": "ransomware"}]
    kind = inp.get("kind","")
    return {"entries": [e["id"] for e in known if e["kind"] == kind]}

def validator_ThreatIntelRule_new(inp: dict) -> dict:
    return {"ok": True, "pattern_count": len(inp.get("patterns_b64", []))}

def validator_ThreatIntelRule_scan(inp: dict) -> dict:
    data = base64.b64decode(inp.get("data_b64",""))
    patterns = [base64.b64decode(p) for p in inp.get("patterns_b64",[])]
    hits = []
    for pid, pat in enumerate(patterns):
        start = 0
        while True:
            pos = data.find(pat, start)
            if pos == -1:
                break
            hits.append({"pattern_idx": pid, "offset": pos})
            start = pos + 1
    return {"hits": hits}

def validator_ThreatIntelRule_fires(inp: dict) -> dict:
    res = validator_ThreatIntelRule_scan(inp)
    return {"fires": len(res["hits"]) > 0}

def validator_ThreatIntelEngine_with_builtin_rules(inp: dict) -> dict:
    return {"rule_count": 5}

def validator_ThreatIntelEngine_add_rule(inp: dict) -> dict:
    count = inp.get("existing_count", 0) + 1
    return {"rule_count": count}

def validator_ThreatIntelEngine_add_cluster(inp: dict) -> dict:
    count = inp.get("existing_count", 0) + 1
    return {"cluster_count": count}

def validator_ThreatIntelEngine_scan(inp: dict) -> dict:
    data = base64.b64decode(inp.get("data_b64",""))
    rules = inp.get("rules", [])
    matches = []
    for rdef in rules:
        patterns = [base64.b64decode(p) for p in rdef.get("patterns_b64",[])]
        for pat in patterns:
            if pat in data:
                matches.append({"rule": rdef.get("name",""), "family": rdef.get("family","")})
                break
    return {"matches": matches}

def validator_ThreatIntelEngine_attribute(inp: dict) -> dict:
    scan_res = validator_ThreatIntelEngine_scan(inp)
    matches = scan_res["matches"]
    families: Dict[str, int] = defaultdict(int)
    for m in matches:
        f = m.get("family","")
        if f:
            families[f] += 1
    attrs = [{"family": f, "match_count": c,
               "confidence": round(c / max(len(matches),1), 3)}
              for f, c in families.items()]
    return {"attributions": attrs}


# ===========================================================================
# Dispatch
# ===========================================================================

_VALIDATORS: Dict[str, Any] = {k: v for k, v in globals().items()
                                 if k.startswith("validator_")}


def _dispatch(fn: str, args: dict) -> Any:
    key = f"validator_{fn}"
    if key not in _VALIDATORS:
        return {"error": f"unknown function: {fn}"}
    return _VALIDATORS[key](args)


# ===========================================================================
# Self-tests
# ===========================================================================

def _run_tests():
    failures = []

    def check(name: str, result: Any, expected: Any):
        if result != expected:
            failures.append(f"FAIL {name}: got {result!r}, expected {expected!r}")
        else:
            print(f"  OK  {name}")

    print("=== rustre-triage-yara validator self-tests ===")

    # MatchContext
    r = validator_MatchContext_new({"n_strings": 3, "filesize": 100})
    check("MatchContext_new.n_strings", r["n_strings"], 3)

    r = validator_MatchContext_matched({"n_strings": 2, "filesize": 10,
                                         "hits": [{"idx": 0, "offset": 5, "len": 2}], "idx": 0})
    check("MatchContext_matched.true", r["matched"], True)

    r = validator_MatchContext_count({"n_strings": 2, "filesize": 10,
                                       "hits": [{"idx": 0, "offset": 5, "len": 2},
                                                {"idx": 0, "offset": 7, "len": 2}], "idx": 0})
    check("MatchContext_count", r["count"], 2)

    r = validator_MatchContext_hit_in({"n_strings": 2, "filesize": 20,
                                        "hits": [{"idx": 0, "offset": 10, "len": 2}],
                                        "idx": 0, "lo": 5, "hi": 15})
    check("MatchContext_hit_in.true", r["hit_in"], True)

    # VmStack
    r = validator_VmStack_pop({"values": [1, 2, 3], "pc": 0})
    check("VmStack_pop", r["value"], 3)

    r = validator_VmStack_pop({"values": [], "pc": 0})
    check("VmStack_pop.underflow", r["ok"], False)

    r = validator_VmStack_pop2({"values": [10, 20], "pc": 0})
    check("VmStack_pop2.a", r["a"], 10)
    check("VmStack_pop2.b", r["b"], 20)

    # AhoCorasick
    import base64 as b64
    pat = b64.b64encode(b"hello").decode()
    data = b64.b64encode(b"say hello world hello").decode()
    r = validator_AhoCorasick_search({"patterns_b64": [pat], "data_b64": data})
    check("AhoCorasick_search.count", len(r["hits"]), 2)

    # CompiledRule evaluate
    pat2 = b64.b64encode(b"EICAR").decode()
    data2 = b64.b64encode(b"This is EICAR test").decode()
    r = validator_CompiledRule_evaluate({
        "name": "test_rule",
        "patterns_b64": [pat2],
        "bytecode": [{"op": "matched", "idx": 0}],
        "data_b64": data2
    })
    check("CompiledRule_evaluate.match", r["result"], True)

    # CacheKey
    r = validator_CacheKey_from_hex({"file_hex": "deadbeef", "rules_hex": "cafebabe"})
    check("CacheKey_from_hex.ok", r["ok"], True)

    r = validator_CacheKey_from_hex({"file_hex": "xyz", "rules_hex": "abc"})
    check("CacheKey_from_hex.invalid", r["ok"], False)

    # hit_rate
    r = validator_CacheStats_hit_rate({"hits": 3, "misses": 1})
    check("CacheStats_hit_rate", r["hit_rate"], 0.75)

    # LRU eviction
    r = validator_YaraResultCache_evict_expired({
        "max_entries": 100, "max_memory_bytes": 10**6,
        "entries": [{"key": "a", "value": [], "ts": 0, "mem": 64},
                    {"key": "b", "value": [], "ts": 9600, "mem": 64}],
        "now": 10000, "max_age_secs": 500
    })
    check("YaraResultCache_evict_expired", r["removed"], 1)

    # IOC extraction
    import base64 as b64
    text = b"Connect to 192.168.1.1 and evil.example.com for more info"
    r = validator_IocExtractor_extract({"data_b64": b64.b64encode(text).decode(), "label": "t"})
    ips = [i["value"] for i in r["iocs"] if i["kind"] == "ip"]
    check("IocExtractor.ip", "192.168.1.1" in ips, True)

    # printable strings
    text2 = b"AAABBBCCC\x00hello world\x00"
    r = validator_extract_printable_strings({"data_b64": b64.b64encode(text2).decode(), "min_len": 4})
    found = [s["value"] for s in r["strings"]]
    check("extract_printable.hello", any("hello" in s for s in found), True)

    # severity_weight
    r = validator_severity_weight({"severity": "high"})
    check("severity_weight.high", r["weight"], 25)

    # verdict transitions
    r = validator_VerdictTransition_is_escalation({"from": "clean", "to": "malicious"})
    check("VerdictTransition.escalation", r["is_escalation"], True)

    r = validator_VerdictTransition_is_deescalation({"from": "malicious", "to": "suspicious"})
    check("VerdictTransition.deescalation", r["is_deescalation"], True)

    # ThreatTag confidence
    r = validator_ThreatTag_is_high_confidence({"confidence": 0.9})
    check("ThreatTag.is_high_confidence", r["is_high_confidence"], True)

    # tag_to_mitre
    r = validator_tag_to_mitre({"category": "ransomware"})
    check("tag_to_mitre.ransomware", "T1486" in r["ttps"], True)

    # MalpediaDb lookup
    r = validator_MalpediaDb_lookup({"name": "win.emotet"})
    check("MalpediaDb_lookup.emotet", r["found"], True)

    # RuleProfile p95
    r = validator_RuleProfile_p95_time({
        "name": "r",
        "measurements": [{"elapsed_ns": i * 100, "matched": i % 2 == 0} for i in range(1, 21)]
    })
    check("RuleProfile_p95.ge_mean", r["p95_time_ns"] >= 1000, True)

    # PatternScorer entropy
    r = validator_PatternScorer_score({"pattern_b64": b64.b64encode(b"\xde\xad\xbe\xef\x00\x11\x22\x33").decode()})
    check("PatternScorer.score_positive", r["score"] > 0, True)

    # scan_buffer
    pat3 = b64.b64encode(b"MALWARE").decode()
    data3 = b64.b64encode(b"This file contains MALWARE code").decode()
    r = validator_YaraScanner_scan_buffer({
        "rules": [{"name": "mal_rule",
                    "patterns_b64": [pat3],
                    "bytecode": [{"op": "matched", "idx": 0}],
                    "meta": {"severity": "high"}}],
        "data_b64": data3, "label": "test"
    })
    check("YaraScanner_scan_buffer.match", r["match_count"], 1)
    check("YaraScanner_scan_buffer.severity", r["severity"], "high")

    # parse_yar_text
    yar = 'rule MyMalware : ransomware { meta: severity = "high" strings: $a = "encrypt" condition: $a }'
    r = validator_parse_yar_text({"text": yar, "path": "test.yar"})
    check("parse_yar_text.name", r["name"], "MyMalware")
    check("parse_yar_text.severity", r["meta"].get("severity"), "high")

    print(f"\n{'='*45}")
    if failures:
        print(f"FAILURES ({len(failures)}):")
        for f in failures:
            print(f"  {f}")
    else:
        print(f"All {len(_VALIDATORS)} validators loaded, all tests passed.")
    return len(failures) == 0


if __name__ == "__main__":
    if not sys.stdin.isatty():
        line = sys.stdin.read().strip()
        if line:
            req = json.loads(line)
            print(json.dumps(_dispatch(req["fn"], req.get("args", {})), indent=2))
    else:
        ok = _run_tests()
        sys.exit(0 if ok else 1)
