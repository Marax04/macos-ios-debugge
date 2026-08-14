"""Independent validator for rustre-ttd-query crate.

Reimplements pure-logic primitives described in
validation/reports/rustre-ttd-query.md using only Python stdlib, and
emits expected results that can be compared against the crate's
actual behavior.

The crate provides a rich query engine over Time-Travel Debugging
(TTD) traces: composable filters, a typed DSL, indexing, aggregation,
and multi-format export. We model the pure-functional pieces here:

  - TimeRange (pos-range with inclusive contains)
  - EventKind / TraceEvent (synthetic in-memory events)
  - QueryFilter / QueryLogic matching (legacy filter tree)
  - EventPattern matching (subset of the 18 variants)
  - QueryIndex::build (by_address / calls_from / calls_to / syscalls /
    by_thread)
  - Aggregations: event_histogram_by_kind, event_histogram_by_thread,
    most_accessed_addresses, most_called_functions, analyze_call_frequency
  - CSV / DOT / JSON timeline export shape
"""

import json
import io
import csv
from collections import defaultdict
from typing import Optional


# ---------- EventKind / TraceEvent ----------
# Kinds modeled as plain strings; the real crate uses a Rust enum.
KIND_MEM_READ = "MemoryRead"
KIND_MEM_WRITE = "MemoryWrite"
KIND_CALL = "Call"
KIND_RETURN = "Return"
KIND_SYSCALL = "Syscall"
KIND_EXCEPTION = "Exception"
KIND_THREAD_CREATE = "ThreadCreate"
KIND_THREAD_EXIT = "ThreadExit"
KIND_BREAKPOINT = "Breakpoint"


def mk_event(pos, kind, thread=1, **fields):
    ev = {"position": pos, "kind": kind, "thread": thread}
    ev.update(fields)
    return ev


# ---------- TimeRange ----------
def time_range_new(start, end):
    return {"start": start, "end": end}


def time_range_contains(rng, pos):
    # Inclusive on both ends, matching the typical Rust range helper.
    return rng["start"] <= pos <= rng["end"]


# ---------- QueryFilter matching ----------
def filter_matches(flt, ev):
    t = flt["type"]
    k = ev["kind"]
    if t == "MemoryRead":
        return k == KIND_MEM_READ and ev.get("addr") == flt["addr"]
    if t == "MemoryWrite":
        return k == KIND_MEM_WRITE and ev.get("addr") == flt["addr"]
    if t == "Thread":
        return ev.get("thread") == flt["tid"]
    if t == "CallTo":
        return k == KIND_CALL and ev.get("to") == flt["addr"]
    if t == "CallFrom":
        return k == KIND_CALL and ev.get("from") == flt["addr"]
    if t == "SyscallNumber":
        return k == KIND_SYSCALL and ev.get("nr") == flt["nr"]
    if t == "InTimeRange":
        return time_range_contains(flt["range"], ev["position"])
    if t == "ExceptionCode":
        return k == KIND_EXCEPTION and ev.get("code") == flt["code"]
    if t == "ThreadCreate":
        return k == KIND_THREAD_CREATE
    if t == "ThreadExit":
        return k == KIND_THREAD_EXIT
    raise ValueError(f"unknown filter type {t}")


def logic_matches(logic, ev):
    op = logic["op"]
    if op == "Single":
        return filter_matches(logic["filter"], ev)
    if op == "And":
        return all(logic_matches(c, ev) for c in logic["children"])
    if op == "Or":
        return any(logic_matches(c, ev) for c in logic["children"])
    if op == "Not":
        return not logic_matches(logic["child"], ev)
    raise ValueError(f"unknown logic op {op}")


# ---------- EventPattern subset ----------
def pattern_matches(pat, ev):
    n = pat["name"]
    k = ev["kind"]
    if n == "AnyMemRead":
        return k == KIND_MEM_READ
    if n == "AnyMemWrite":
        return k == KIND_MEM_WRITE
    if n == "AnyCall":
        return k == KIND_CALL
    if n == "AnyReturn":
        return k == KIND_RETURN
    if n == "AnySyscall":
        return k == KIND_SYSCALL
    if n == "AnyException":
        return k == KIND_EXCEPTION
    if n == "MemReadAt":
        return k == KIND_MEM_READ and ev.get("addr") == pat["addr"]
    if n == "MemWriteAt":
        return k == KIND_MEM_WRITE and ev.get("addr") == pat["addr"]
    if n == "CallTo":
        return k == KIND_CALL and ev.get("to") == pat["addr"]
    if n == "CallFrom":
        return k == KIND_CALL and ev.get("from") == pat["addr"]
    if n == "SyscallNr":
        return k == KIND_SYSCALL and ev.get("nr") == pat["nr"]
    if n == "ThreadId":
        return ev.get("thread") == pat["tid"]
    if n == "InPositionRange":
        return pat["start"] <= ev["position"] <= pat["end"]
    if n == "Breakpoint":
        return k == KIND_BREAKPOINT
    raise ValueError(f"unknown pattern {n}")


# ---------- QueryIndex ----------
def build_index(events):
    by_address = defaultdict(list)
    calls_from = defaultdict(list)
    calls_to = defaultdict(list)
    syscalls = defaultdict(list)
    by_thread = defaultdict(list)
    for ev in events:
        pos = ev["position"]
        by_thread[ev["thread"]].append(pos)
        k = ev["kind"]
        if k in (KIND_MEM_READ, KIND_MEM_WRITE):
            by_address[ev["addr"]].append(pos)
        elif k == KIND_CALL:
            if "from" in ev:
                calls_from[ev["from"]].append(pos)
            if "to" in ev:
                calls_to[ev["to"]].append(pos)
        elif k == KIND_SYSCALL:
            syscalls[ev["nr"]].append(pos)
    return {
        "by_address": dict(by_address),
        "calls_from": dict(calls_from),
        "calls_to": dict(calls_to),
        "syscalls": dict(syscalls),
        "by_thread": dict(by_thread),
    }


def calls_to_address(idx, addr):
    return idx["calls_to"].get(addr, [])


def calls_from_address(idx, addr):
    return idx["calls_from"].get(addr, [])


def syscalls_for_nr(idx, nr):
    return idx["syscalls"].get(nr, [])


def accesses_to_address(idx, addr):
    return idx["by_address"].get(addr, [])


def events_for_thread(idx, tid):
    return idx["by_thread"].get(tid, [])


# ---------- Aggregations ----------
def event_histogram_by_kind(events):
    h = defaultdict(int)
    for ev in events:
        h[ev["kind"]] += 1
    return dict(h)


def event_histogram_by_thread(events):
    h = defaultdict(int)
    for ev in events:
        h[ev["thread"]] += 1
    return dict(h)


def event_histogram_over_time(events, bucket):
    if bucket <= 0:
        raise ValueError("bucket must be > 0")
    h = defaultdict(int)
    for ev in events:
        b = (ev["position"] // bucket) * bucket
        h[b] += 1
    return sorted(h.items())


def most_accessed_addresses(events, n):
    counts = defaultdict(int)
    for ev in events:
        if ev["kind"] in (KIND_MEM_READ, KIND_MEM_WRITE):
            counts[ev["addr"]] += 1
    items = sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))
    return items[:n]


def most_called_functions(events, n):
    counts = defaultdict(int)
    for ev in events:
        if ev["kind"] == KIND_CALL and "to" in ev:
            counts[ev["to"]] += 1
    items = sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))
    return items[:n]


def analyze_call_frequency(events):
    # Same as most_called_functions but unbounded, sorted desc.
    return most_called_functions(events, n=len(events))


def summarize_syscalls(events):
    out = {}
    for ev in events:
        if ev["kind"] == KIND_SYSCALL:
            nr = ev["nr"]
            s = out.setdefault(nr, {"count": 0, "first": ev["position"], "last": ev["position"]})
            s["count"] += 1
            if ev["position"] < s["first"]:
                s["first"] = ev["position"]
            if ev["position"] > s["last"]:
                s["last"] = ev["position"]
    return out


def find_recursive_calls(events):
    # A simple recursive-call detector: a CallTo(addr) whose target equals
    # an ancestor still on the call stack. We track a stack of "to" addrs.
    stack = []
    chains = []
    for ev in events:
        if ev["kind"] == KIND_CALL and "to" in ev:
            target = ev["to"]
            if target in stack:
                depth = len(stack) - stack.index(target)
                chains.append({"address": target, "depth": depth, "position": ev["position"]})
            stack.append(target)
        elif ev["kind"] == KIND_RETURN and stack:
            stack.pop()
    return chains


def compute_code_coverage(events, ranges):
    # Coverage = fraction of (start,end) ranges that have at least one
    # call landing inside [start, end].
    hit = 0
    for (s, e) in ranges:
        for ev in events:
            if ev["kind"] == KIND_CALL and "to" in ev and s <= ev["to"] <= e:
                hit += 1
                break
    total = len(ranges)
    return {
        "total_ranges": total,
        "hit_ranges": hit,
        "coverage_ratio": (hit / total) if total else 0.0,
    }


# ---------- Exports ----------
def export_to_csv(events, flt=None):
    buf = io.StringIO()
    w = csv.writer(buf, lineterminator="\n")
    w.writerow(["position", "kind", "thread", "addr", "from", "to", "nr", "code"])
    for ev in events:
        if flt is not None and not filter_matches(flt, ev):
            continue
        w.writerow([
            ev["position"], ev["kind"], ev["thread"],
            ev.get("addr", ""), ev.get("from", ""),
            ev.get("to", ""), ev.get("nr", ""), ev.get("code", ""),
        ])
    return buf.getvalue()


def export_call_graph_dot(events):
    edges = defaultdict(int)
    for ev in events:
        if ev["kind"] == KIND_CALL and "from" in ev and "to" in ev:
            edges[(ev["from"], ev["to"])] += 1
    lines = ["digraph CallGraph {"]
    for (f, t), c in sorted(edges.items()):
        lines.append(f'  "{f:#x}" -> "{t:#x}" [label="{c}"];')
    lines.append("}")
    return "\n".join(lines) + "\n"


def export_timeline_json(events, flt=None):
    out = []
    for ev in events:
        if flt is not None and not filter_matches(flt, ev):
            continue
        out.append({"position": ev["position"], "kind": ev["kind"], "thread": ev["thread"]})
    return json.dumps({"events": out}, separators=(",", ":"))


# ---------- Sample dataset & validators ----------
def sample_events():
    return [
        mk_event(0, KIND_THREAD_CREATE, thread=1),
        mk_event(1, KIND_CALL, thread=1, **{"from": 0x1000, "to": 0x2000}),
        mk_event(2, KIND_MEM_READ, thread=1, addr=0x4000),
        mk_event(3, KIND_MEM_WRITE, thread=1, addr=0x4000),
        mk_event(4, KIND_CALL, thread=1, **{"from": 0x2000, "to": 0x3000}),
        mk_event(5, KIND_SYSCALL, thread=1, nr=60),
        mk_event(6, KIND_RETURN, thread=1),
        mk_event(7, KIND_CALL, thread=1, **{"from": 0x2000, "to": 0x2000}),  # recursive
        mk_event(8, KIND_RETURN, thread=1),
        mk_event(9, KIND_RETURN, thread=1),
        mk_event(10, KIND_MEM_READ, thread=2, addr=0x5000),
        mk_event(11, KIND_EXCEPTION, thread=2, code=0xC0000005),
        mk_event(12, KIND_THREAD_EXIT, thread=2),
    ]


def fn_time_range():
    r = time_range_new(10, 20)
    return {
        "range": r,
        "contains_10": time_range_contains(r, 10),
        "contains_15": time_range_contains(r, 15),
        "contains_20": time_range_contains(r, 20),
        "contains_21": time_range_contains(r, 21),
    }


def fn_filter_matches():
    evs = sample_events()
    f_call_to = {"type": "CallTo", "addr": 0x2000}
    f_mem_w = {"type": "MemoryWrite", "addr": 0x4000}
    f_sys = {"type": "SyscallNumber", "nr": 60}
    f_thread = {"type": "Thread", "tid": 2}
    return {
        "call_to_0x2000": [ev["position"] for ev in evs if filter_matches(f_call_to, ev)],
        "mem_w_0x4000": [ev["position"] for ev in evs if filter_matches(f_mem_w, ev)],
        "syscall_60": [ev["position"] for ev in evs if filter_matches(f_sys, ev)],
        "thread_2": [ev["position"] for ev in evs if filter_matches(f_thread, ev)],
    }


def fn_logic_matches():
    evs = sample_events()
    logic = {
        "op": "And",
        "children": [
            {"op": "Single", "filter": {"type": "InTimeRange",
                                         "range": time_range_new(0, 5)}},
            {"op": "Or", "children": [
                {"op": "Single", "filter": {"type": "MemoryRead", "addr": 0x4000}},
                {"op": "Single", "filter": {"type": "CallTo", "addr": 0x3000}},
            ]},
        ],
    }
    return [ev["position"] for ev in evs if logic_matches(logic, ev)]


def fn_pattern_matches():
    evs = sample_events()
    return {
        "AnyCall": [ev["position"] for ev in evs if pattern_matches({"name": "AnyCall"}, ev)],
        "AnyMemRead": [ev["position"] for ev in evs if pattern_matches({"name": "AnyMemRead"}, ev)],
        "SyscallNr_60": [ev["position"] for ev in evs
                          if pattern_matches({"name": "SyscallNr", "nr": 60}, ev)],
        "InPositionRange_2_5": [ev["position"] for ev in evs
                                  if pattern_matches({"name": "InPositionRange",
                                                       "start": 2, "end": 5}, ev)],
        "AnyException": [ev["position"] for ev in evs
                           if pattern_matches({"name": "AnyException"}, ev)],
    }


def fn_index_build():
    evs = sample_events()
    idx = build_index(evs)
    return {
        "calls_to_0x2000": calls_to_address(idx, 0x2000),
        "calls_from_0x2000": calls_from_address(idx, 0x2000),
        "syscalls_60": syscalls_for_nr(idx, 60),
        "accesses_0x4000": accesses_to_address(idx, 0x4000),
        "events_thread_1_count": len(events_for_thread(idx, 1)),
        "events_thread_2_count": len(events_for_thread(idx, 2)),
        "by_address_keys_sorted": sorted(idx["by_address"].keys()),
    }


def fn_aggregations():
    evs = sample_events()
    return {
        "hist_by_kind": event_histogram_by_kind(evs),
        "hist_by_thread": event_histogram_by_thread(evs),
        "hist_over_time_bucket5": event_histogram_over_time(evs, 5),
        "most_accessed_top2": most_accessed_addresses(evs, 2),
        "most_called_top2": most_called_functions(evs, 2),
        "call_frequency": analyze_call_frequency(evs),
        "syscalls_summary": summarize_syscalls(evs),
    }


def fn_recursive_calls():
    return find_recursive_calls(sample_events())


def fn_code_coverage():
    return compute_code_coverage(
        sample_events(),
        [(0x2000, 0x2FFF), (0x3000, 0x3FFF), (0x9000, 0x9FFF)],
    )


def fn_exports():
    evs = sample_events()
    csv_out = export_to_csv(evs, {"type": "Thread", "tid": 2})
    dot_out = export_call_graph_dot(evs)
    json_out = export_timeline_json(evs, {"type": "InTimeRange",
                                            "range": time_range_new(0, 3)})
    return {
        "csv_thread_2_lines": csv_out.strip().splitlines(),
        "dot": dot_out.strip().splitlines(),
        "json_in_range_0_3": json.loads(json_out),
    }


FUNCTIONS = [
    ("time_range", fn_time_range),
    ("filter_matches", fn_filter_matches),
    ("logic_matches", fn_logic_matches),
    ("pattern_matches", fn_pattern_matches),
    ("index_build", fn_index_build),
    ("aggregations", fn_aggregations),
    ("recursive_calls", fn_recursive_calls),
    ("code_coverage", fn_code_coverage),
    ("exports", fn_exports),
]


def main():
    results = []
    for name, fn in FUNCTIONS:
        try:
            results.append({"name": name, "ok": True, "result": fn()})
        except Exception as e:
            results.append({"name": name, "ok": False, "error": str(e)})
    out = {"crate": "rustre-ttd-query", "saved": True, "functions": results}
    print(json.dumps(out, indent=2, default=str))


if __name__ == "__main__":
    main()
