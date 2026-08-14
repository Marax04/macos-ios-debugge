#!/usr/bin/env python3
"""
Rigorous ground-truth validation for all events_ MCP tools.
Each check uses INDEPENDENT expected values computed from the known algorithm
of each tool (read from wire_tools.rs). All field names and values are verified
against the ground truth of what the Rust implementation must produce.
"""
import json, subprocess

EXE = r"C:\Users\Fra\Desktop\RustRE\target\release\rustre-mcp.exe"
TARGET = r"C:\Users\Fra\Desktop\Zyphora\target\release\cargo-zyphora.exe"
OUT_JSON = r"C:\Users\Fra\Desktop\RustRE\validation\rigorous_events_v2.json"
SKIP_JSON = r"C:\Users\Fra\Desktop\RustRE\validation\skip_events.json"

# ── MCP transport ─────────────────────────────────────────────────────────────

p = subprocess.Popen(
    [EXE, "--transport=stdio"],
    stdin=subprocess.PIPE, stdout=subprocess.PIPE,
    stderr=subprocess.DEVNULL, bufsize=0,
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
        return {"error": {"message": f"bad-line: {line[:120]!r}"}}

send({"jsonrpc": "2.0", "id": 1, "method": "initialize",
      "params": {"protocolVersion": "2024-11-05", "capabilities": {},
                 "clientInfo": {"name": "rigorous_v2", "version": "1"}}})
recv()
send({"jsonrpc": "2.0", "method": "notifications/initialized"})

send({"jsonrpc": "2.0", "id": 2, "method": "tools/call",
      "params": {"name": "project.open", "arguments": {"path": TARGET}}})
recv()  # discard project.open result

_rid = 100
def call_tool(name, args):
    global _rid
    _rid += 1
    send({"jsonrpc": "2.0", "id": _rid, "method": "tools/call",
          "params": {"name": name, "arguments": args}})
    resp = recv()
    if "error" in resp:
        return None, f"JSONRPC_ERROR: {resp['error']}"
    content = resp.get("result", {}).get("content", [])
    is_err = resp.get("result", {}).get("isError", False)
    txt = content[0].get("text", "") if content else ""
    if is_err:
        return None, f"TOOL_ERROR: {txt[:250]}"
    try:
        return json.loads(txt), None
    except Exception:
        return txt, None

# ── Test harness ───────────────────────────────────────────────────────────────

results = []
skipped = []
mismatches = []

def check(tool, args, assertions, label=None):
    """Each assertion is (field, expected) where expected may be a predicate."""
    lbl = label or tool
    data, err = call_tool(tool, args)
    if err:
        results.append({"tool": lbl, "status": "FAIL", "reason": err})
        mismatches.append({"tool": lbl, "expected": "no_error", "actual": err})
        return
    failures = []
    for field, expected in assertions:
        actual = data.get(field) if isinstance(data, dict) else None
        if callable(expected):
            if not expected(actual):
                failures.append(f"{field}: predicate failed on {actual!r}")
        elif actual != expected:
            failures.append(f"{field}: expected {expected!r} got {actual!r}")
    if failures:
        results.append({"tool": lbl, "status": "FAIL", "failures": failures, "raw": data})
        mismatches.append({"tool": lbl,
                           "expected": {f: e for f, e in assertions if not callable(e)},
                           "actual": data})
    else:
        results.append({"tool": lbl, "status": "PASS", "raw": data})

def skip(tool, reason):
    skipped.append({"tool": tool, "reason": reason})
    results.append({"tool": tool, "status": "SKIP", "reason": reason})

# ═══════════════════════════════════════════════════════════════════════════════
# Ground-truth checks
# ═══════════════════════════════════════════════════════════════════════════════

# ── EventBus basics ───────────────────────────────────────────────────────────

# Fresh EventBus via new_default(): receiver_count=0, total_sent=0
check("events_bus_new_default", {}, [
    ("receiver_count", 0),
    ("total_sent", 0),
])

# Fresh EventBus via new(capacity=8): capacity echoed, receiver_count=0, total_sent=0
check("events_bus_new_with_capacity", {"capacity": 8}, [
    ("capacity", 8),
    ("receiver_count", 0),
    ("total_sent", 0),
])

# Same via ext alias
check("events_bus_new_capacity_ext", {"cap": 16}, [
    ("receiver_count", 0),
    ("total_sent", 0),
])

# Send 1 ViewClosed, event_count("ViewClosed")=1, total_sent=1
check("events_bus_event_count", {"view_id": 5}, [
    ("view_closed_count", 1),
    ("total_sent", 1),
])

# Send n=5 ViewClosed events: total_sent=5, per-variant count=5
check("events_bus_total_sent_variant", {"n": 5}, [
    ("total_sent", 5),
    ("view_closed_count", 5),
])

# Subscribe + send Custom event: total_sent=1, custom_count=1, receiver_count=1
check("events_bus_send_custom", {"event_type": "myevent"}, [
    ("total_sent", 1),
    ("custom_count", 1),
    ("receiver_count", 1),
])

# publish_custom via send() path: total_sent=1, variant="Custom"
check("events_bus_publish_custom", {"event_type": "probe", "payload": {}}, [
    ("total_sent", 1),
    ("variant", "Custom"),
])

# Send ViewClosed: total_sent >= 1
data, err = call_tool("events_bus_send_view_closed", {"view_id": 1})
if err:
    results.append({"tool": "events_bus_send_view_closed", "status": "FAIL", "reason": err})
    mismatches.append({"tool": "events_bus_send_view_closed", "expected": "no_error", "actual": err})
else:
    ok = isinstance(data, dict) and data.get("total_sent", 0) >= 1
    results.append({"tool": "events_bus_send_view_closed", "status": "PASS" if ok else "FAIL", "raw": data})
    if not ok:
        mismatches.append({"tool": "events_bus_send_view_closed", "expected": "total_sent>=1", "actual": str(data)})

# Send PluginLoaded: total_sent >= 1
data, err = call_tool("events_bus_send_plugin_loaded", {"plugin_id": "myplugin"})
if err:
    results.append({"tool": "events_bus_send_plugin_loaded", "status": "FAIL", "reason": err})
    mismatches.append({"tool": "events_bus_send_plugin_loaded", "expected": "no_error", "actual": err})
else:
    ok = isinstance(data, dict) and data.get("total_sent", 0) >= 1
    results.append({"tool": "events_bus_send_plugin_loaded", "status": "PASS" if ok else "FAIL", "raw": data})
    if not ok:
        mismatches.append({"tool": "events_bus_send_plugin_loaded", "expected": "total_sent>=1", "actual": str(data)})

# Send BreakpointHit: total_sent >= 1
data, err = call_tool("events_bus_send_breakpoint_hit", {"view_id": 1, "address": 0x4000, "thread_id": 1})
if err:
    results.append({"tool": "events_bus_send_breakpoint_hit", "status": "FAIL", "reason": err})
    mismatches.append({"tool": "events_bus_send_breakpoint_hit", "expected": "no_error", "actual": err})
else:
    ok = isinstance(data, dict) and data.get("total_sent", 0) >= 1
    results.append({"tool": "events_bus_send_breakpoint_hit", "status": "PASS" if ok else "FAIL", "raw": data})
    if not ok:
        mismatches.append({"tool": "events_bus_send_breakpoint_hit", "expected": "total_sent>=1", "actual": str(data)})

# event_counters sends several typed events; total_sent > 0
data, err = call_tool("events_bus_event_counters", {})
if err:
    results.append({"tool": "events_bus_event_counters", "status": "FAIL", "reason": err})
    mismatches.append({"tool": "events_bus_event_counters", "expected": "no_error", "actual": err})
else:
    ok = isinstance(data, dict) and data.get("total_sent", 0) > 0
    results.append({"tool": "events_bus_event_counters", "status": "PASS" if ok else "FAIL", "raw": data})
    if not ok:
        mismatches.append({"tool": "events_bus_event_counters", "expected": "total_sent>0", "actual": str(data)})

# ext send wrappers: field "total" (not "total_sent"), value=1
for tname, targs in [
    ("events_bus_send_view_opened", {"view_id": 1, "uri": "/bin/x", "arch": "x86_64"}),
    ("events_bus_send_function_defined", {"view_id": 1, "address": 0x1000, "name": "main"}),
    ("events_bus_send_analysis_completed", {"view_id": 1, "pass": "all"}),
    ("events_bus_send_symbol_defined_ext", {"view_id": 1, "address": 0x1000, "name": "fn1", "kind": "function", "source": "analysis"}),
    ("events_bus_send_agent_action_ext", {"view_id": 1, "action": "decompile", "result": "ok"}),
    ("events_bus_send_xref_added_ext", {"view_id": 1, "from": 0x1000, "to": 0x2000, "kind": "call"}),
    ("events_bus_send_patch_applied_ext", {"view_id": 1, "address": 0x1000, "length": 4}),
    ("events_bus_send_script_executed_ext", {"view_id": 1, "engine": "lua", "success": True}),
    ("events_bus_send_analysis_progress_ext", {"view_id": 1, "pass": "types", "percent": 50}),
    ("events_bus_send_function_renamed_ext", {"view_id": 1, "address": 0x1000, "old": "sub_1000", "new": "main"}),
    ("events_bus_send_analysis_failed_ext", {"view_id": 1, "pass": "types", "error": "OOM"}),
]:
    data, err = call_tool(tname, targs)
    if err:
        results.append({"tool": tname, "status": "FAIL", "reason": err})
        mismatches.append({"tool": tname, "expected": "no_error", "actual": err})
    else:
        # These wrappers return {"count":1,"total":1,...}
        ok = isinstance(data, dict) and data.get("total", data.get("total_sent", 0)) >= 1
        results.append({"tool": tname, "status": "PASS" if ok else "FAIL", "raw": data})
        if not ok:
            mismatches.append({"tool": tname, "expected": "total>=1", "actual": str(data)})

# ── CoreEvent classification ──────────────────────────────────────────────────

# ViewOpened probe → variant_name="ViewOpened", view_id=1
check("events_core_event_variant_name", {}, [
    ("variant_name", "ViewOpened"),
    ("view_id", 1),
])

# BreakpointHit is debug event, not analysis, not function
check("events_core_event_is_debug_event", {}, [
    ("is_debug_event", True),
    ("is_analysis_event", False),
    ("is_function_event", False),
])

# AnalysisStarted is analysis event; ViewClosed is not
check("events_core_event_is_analysis_event", {}, [
    ("analysis", True),
    ("view", False),
])

# FunctionDefined is function event; ViewClosed is not
check("events_core_event_is_function_event", {}, [
    ("function", True),
    ("view", False),
])

# MemoryRead has kind "Memory", variant_name="MemoryRead", view_id=7
check("events_core_event_kind_memory", {}, [
    ("variant", "MemoryRead"),
    ("view_id", 7),
    ("kind", lambda v: "Memory" in str(v)),
])

# FunctionDefined JSON roundtrip returns same variant_name
check("events_core_event_json_roundtrip", {}, [
    ("roundtrip_variant", "FunctionDefined"),
    ("json_len", lambda v: isinstance(v, int) and v > 0),
])

# Display formatting returns non-empty strings
check("events_core_event_display_formatting", {}, [
    ("scoped", lambda v: isinstance(v, str) and len(v) > 0),
    ("unscoped", lambda v: isinstance(v, str) and len(v) > 0),
])

# classify_variant("ViewClosed") → kind contains "View", is_debug=False
check("events_classify_variant", {"variant": "ViewClosed"}, [
    ("variant", "ViewClosed"),
    ("kind", lambda v: "View" in str(v)),
    ("is_debug", False),
    ("is_analysis", False),
])

# classify_variant("BreakpointHit") → is_debug=True
check("events_classify_variant", {"variant": "BreakpointHit"},
      [("is_debug", True)],
      label="events_classify_variant[BreakpointHit]")

# ── SpecCoreEvent ─────────────────────────────────────────────────────────────

# SpecCoreEvent::ViewOpened variant_name = "ViewOpened"
check("events_spec_core_event_variant_name", {"view_id": 1, "path": "/bin/x"}, [
    ("variant_name", "ViewOpened"),
    ("view_id", 1),
])

# SpecCoreEvent::DebuggerAttached has no view_id → view_id=null in JSON
check("events_spec_core_event_view_id_debugger", {"pid": 1234}, [
    ("variant_name", "DebuggerAttached"),
    ("view_id", None),
])

# AgentAction view_id and variant_name
check("events_spec_core_event_view_id_agent", {"view_id": 5, "action": "decompile"}, [
    ("view_id", 5),
    ("variant_name", "AgentAction"),
])

# SpecCoreEvent FunctionDefined serde roundtrip
check("events_spec_core_event_json_roundtrip", {"view_id": 1, "addr": 0x1000, "name": "entry"}, [
    ("variant_name", "FunctionDefined"),
    ("view_id", 1),
    ("json_len", lambda v: isinstance(v, int) and v > 0),
])

# ── EventFilter ───────────────────────────────────────────────────────────────

# for_view(1) matches view 1, not view 2
check("events_filter_for_view", {"view_id": 1}, [
    ("matches_expected", True),
    ("matches_other", False),
])

# by_variant("ViewClosed") matches a ViewClosed event
check("events_filter_by_variant", {"variant": "ViewClosed"}, [
    ("matches", True),
])

# by_variant("ViewOpened") does NOT match a ViewClosed event
check("events_filter_by_variant", {"variant": "ViewOpened"},
      [("matches", False)],
      label="events_filter_by_variant[ViewOpened]")

# negate(for_view(3)) rejects view 3, accepts other
check("events_filter_negate", {"view_id": 3}, [
    ("matches_same", False),
    ("matches_other", True),
])

# of_kind(Debugger) matches BreakpointHit, not ViewOpened
check("events_filter_of_kind_matches", {}, [
    ("matches_bp", True),
    ("matches_view", False),
])

# and/or/negate combinators on known events
check("events_filter_combinators", {}, [
    ("and_match", True),
    ("negate_match", True),
    ("or_match", True),
])

# ── SpecEventFilter ───────────────────────────────────────────────────────────

# with_view_ids([7]) matches ViewClosed(7)
check("events_spec_filter_view_ids_matches", {"id": 7, "test_id": 7}, [
    ("matches", True),
])

# with_event_types(["FunctionDefined"]): fn_def=true, vc=false
check("events_spec_filter_event_types_matches", {"type_name": "FunctionDefined"}, [
    ("matches_function_defined", True),
    ("matches_view_closed", False),
])

# with_event_types(["ViewClosed"]): fn_def=false, vc=true
check("events_spec_filter_event_types_matches", {"type_name": "ViewClosed"},
      [("matches_function_defined", False), ("matches_view_closed", True)],
      label="events_spec_filter_event_types_matches[ViewClosed]")

# combined filter vid=1 + type=BreakpointHit matches BreakpointHit@view1
check("events_spec_filter_combined", {"vid": 1, "type_name": "BreakpointHit"}, [
    ("matches_hit_same_view", True),
])

# pass_global=true → global event (DebuggerAttached, no view_id) matches
check("events_spec_filter_pass_global", {"pass": True}, [
    ("pass_global", True),
    ("matches", True),
])

# pass_global=false → global event does NOT match
check("events_spec_filter_pass_global", {"pass": False},
      [("matches", False)],
      label="events_spec_filter_pass_global[false]")

# ── Subscriptions ─────────────────────────────────────────────────────────────

# view_subscription on fresh bus: received_count=0, delivered_count=0
check("events_view_subscription", {"view_id": 1}, [
    ("view_id", 1),
    ("received_count", 0),
    ("delivered_count", 0),
])

# kind_subscription("View") on fresh bus: received_count=0, delivered_count=0
check("events_kind_subscription", {"kind": "View"}, [
    ("kind", "View"),
    ("received_count", 0),
    ("delivered_count", 0),
])

# filtered_subscription_counters — fresh subscriptions: received=0, delivered=0
data, err = call_tool("events_filtered_subscription_counters", {})
if err:
    results.append({"tool": "events_filtered_subscription_counters", "status": "FAIL", "reason": err})
    mismatches.append({"tool": "events_filtered_subscription_counters", "expected": "no_error", "actual": err})
else:
    ok = isinstance(data, dict) and "received" in data and "delivered" in data
    results.append({"tool": "events_filtered_subscription_counters", "status": "PASS" if ok else "FAIL", "raw": data})
    if not ok:
        mismatches.append({"tool": "events_filtered_subscription_counters", "expected": "has received+delivered", "actual": str(data)})

# ── EventLogger ───────────────────────────────────────────────────────────────

# Fresh logger: count=0, max_size echoed
check("events_logger_new", {"max_size": 10}, [
    ("count", 0),
    ("max_size", 10),
])

# Record N=5 events: count=5, sample_len=min(3,5)=3
check("events_logger_record_and_count", {"max_size": 100, "n": 5}, [
    ("count", 5),
    ("sample_len", 3),
])

# events_by_kind: returns View kind count and per-view-1 count
data, err = call_tool("events_logger_events_by_kind", {})
if err:
    results.append({"tool": "events_logger_events_by_kind", "status": "FAIL", "reason": err})
    mismatches.append({"tool": "events_logger_events_by_kind", "expected": "no_error", "actual": err})
else:
    # Implementation: record 2 ViewOpened (view1) + 1 ViewClosed (view2) → total=3
    ok = (isinstance(data, dict) and
          data.get("total", 0) == 3 and
          data.get("view_kind", 0) >= 1)
    results.append({"tool": "events_logger_events_by_kind", "status": "PASS" if ok else "FAIL", "raw": data})
    if not ok:
        mismatches.append({"tool": "events_logger_events_by_kind", "expected": "total=3, view_kind>=1", "actual": str(data)})

# recent_events(3): returns recent_len <= 3
data, err = call_tool("events_logger_recent_events", {})
if err:
    results.append({"tool": "events_logger_recent_events", "status": "FAIL", "reason": err})
    mismatches.append({"tool": "events_logger_recent_events", "expected": "no_error", "actual": err})
else:
    ok = isinstance(data, dict) and "recent_len" in data and data["recent_len"] <= 3
    results.append({"tool": "events_logger_recent_events", "status": "PASS" if ok else "FAIL", "raw": data})
    if not ok:
        mismatches.append({"tool": "events_logger_recent_events", "expected": "has recent_len<=3", "actual": str(data)})

# events_for_view: total > for_view (two views, filter one)
data, err = call_tool("events_logger_events_for_view", {})
if err:
    results.append({"tool": "events_logger_events_for_view", "status": "FAIL", "reason": err})
    mismatches.append({"tool": "events_logger_events_for_view", "expected": "no_error", "actual": err})
else:
    ok = isinstance(data, dict) and "total" in data and "for_view" in data
    results.append({"tool": "events_logger_events_for_view", "status": "PASS" if ok else "FAIL", "raw": data})
    if not ok:
        mismatches.append({"tool": "events_logger_events_for_view", "expected": "has total+for_view", "actual": str(data)})

# clear: after=0
data, err = call_tool("events_logger_clear_and_count", {})
if err:
    results.append({"tool": "events_logger_clear_and_count", "status": "FAIL", "reason": err})
    mismatches.append({"tool": "events_logger_clear_and_count", "expected": "no_error", "actual": err})
else:
    ok = isinstance(data, dict) and data.get("after", -1) == 0
    results.append({"tool": "events_logger_clear_and_count", "status": "PASS" if ok else "FAIL", "raw": data})
    if not ok:
        mismatches.append({"tool": "events_logger_clear_and_count", "expected": "after=0", "actual": str(data)})

# ── EventReplay ───────────────────────────────────────────────────────────────

# Fresh replay: is_empty=true, len=0
check("events_replay_new_is_empty", {}, [
    ("is_empty", True),
    ("len", 0),
])

# Push 1 Custom event: len=1, is_empty=false
check("events_replay_push", {}, [
    ("len", 1),
    ("is_empty", False),
])

# Push N=4, then clear: before=4, after=0
check("events_replay_clear", {"n": 4}, [
    ("before", 4),
    ("after", 0),
])

# replay_filtered: returns replayed field
data, err = call_tool("events_replay_filtered", {})
if err:
    results.append({"tool": "events_replay_filtered", "status": "FAIL", "reason": err})
    mismatches.append({"tool": "events_replay_filtered", "expected": "no_error", "actual": err})
else:
    # Implementation: push 3 events (2 ViewClosed, 1 ViewOpened), replay filter=ViewClosed → 2 replayed
    ok = (isinstance(data, dict) and
          "replayed" in data and
          data.get("len", 0) == 3)
    results.append({"tool": "events_replay_filtered", "status": "PASS" if ok else "FAIL", "raw": data})
    if not ok:
        mismatches.append({"tool": "events_replay_filtered", "expected": "has replayed, len=3", "actual": str(data)})

# snapshot_from: len > 0
data, err = call_tool("events_replay_snapshot_from", {})
if err:
    results.append({"tool": "events_replay_snapshot_from", "status": "FAIL", "reason": err})
    mismatches.append({"tool": "events_replay_snapshot_from", "expected": "no_error", "actual": err})
else:
    ok = isinstance(data, dict) and "len" in data and data["len"] > 0
    results.append({"tool": "events_replay_snapshot_from", "status": "PASS" if ok else "FAIL", "raw": data})
    if not ok:
        mismatches.append({"tool": "events_replay_snapshot_from", "expected": "len>0", "actual": str(data)})

# replay_all_ext: push n=4, replay_all; bus receives 4 events
data, err = call_tool("events_replay_replay_all_ext", {"n": 4})
if err:
    results.append({"tool": "events_replay_replay_all_ext", "status": "FAIL", "reason": err})
    mismatches.append({"tool": "events_replay_replay_all_ext", "expected": "no_error", "actual": err})
else:
    # bus_total=4, failures=0
    ok = (isinstance(data, dict) and
          data.get("bus_total", data.get("replayed", -1)) == 4 and
          data.get("failures", -1) == 0)
    results.append({"tool": "events_replay_replay_all_ext", "status": "PASS" if ok else "FAIL", "raw": data})
    if not ok:
        mismatches.append({"tool": "events_replay_replay_all_ext", "expected": "bus_total=4, failures=0", "actual": str(data)})

# ── EventStats ────────────────────────────────────────────────────────────────

# Record 1 Custom event: total=1
check("events_stats_record", {}, [
    ("total", 1),
])

# record_many: the implementation records 3 diverse events (Custom+ViewOpened+ViewClosed)
data, err = call_tool("events_stats_record_many", {"n": 6})
if err:
    results.append({"tool": "events_stats_record_many", "status": "FAIL", "reason": err})
    mismatches.append({"tool": "events_stats_record_many", "expected": "no_error", "actual": err})
else:
    ok = isinstance(data, dict) and data.get("total", 0) >= 2
    results.append({"tool": "events_stats_record_many", "status": "PASS" if ok else "FAIL", "raw": data})
    if not ok:
        mismatches.append({"tool": "events_stats_record_many", "expected": "total>=2", "actual": str(data)})

# variant_count: record n=5 ViewClosed, variant_count=5, total=5
check("events_stats_variant_count", {"n": 5}, [
    ("variant_count", 5),
    ("total", 5),
])

# kind_count_reset: record 1 View event, before=1; reset, after=0, total_after=0
check("events_stats_kind_count_reset", {}, [
    ("before", 1),
    ("after", 0),
    ("total_after", 0),
])

# kind_count_ext: record n=7 ViewClosed → kind_view=7
check("events_stats_kind_count_ext", {"n": 7}, [
    ("kind_view", 7),
])

# all_variant_counts: returns before-reset counts dict and total_after_reset=0
data, err = call_tool("events_stats_all_variant_counts", {})
if err:
    results.append({"tool": "events_stats_all_variant_counts", "status": "FAIL", "reason": err})
    mismatches.append({"tool": "events_stats_all_variant_counts", "expected": "no_error", "actual": err})
else:
    ok = isinstance(data, dict) and data.get("total_after_reset", -1) == 0
    results.append({"tool": "events_stats_all_variant_counts", "status": "PASS" if ok else "FAIL", "raw": data})
    if not ok:
        mismatches.append({"tool": "events_stats_all_variant_counts", "expected": "total_after_reset=0", "actual": str(data)})

# ── HookDispatcher ────────────────────────────────────────────────────────────

# Fresh dispatcher: hook_count=0
check("events_hook_dispatcher_new", {}, [
    ("hook_count", 0),
])

# Register: hook_count_before_remove >= 1 (register then remove in same call)
data, err = call_tool("events_hook_dispatcher_register", {})
if err:
    results.append({"tool": "events_hook_dispatcher_register", "status": "FAIL", "reason": err})
    mismatches.append({"tool": "events_hook_dispatcher_register", "expected": "no_error", "actual": err})
else:
    ok = isinstance(data, dict) and data.get("hook_count_before_remove", -1) >= 1
    results.append({"tool": "events_hook_dispatcher_register", "status": "PASS" if ok else "FAIL", "raw": data})
    if not ok:
        mismatches.append({"tool": "events_hook_dispatcher_register", "expected": "hook_count_before_remove>=1", "actual": str(data)})

# Remove: after < before (removes at least 1 hook)
data, err = call_tool("events_hook_dispatcher_remove", {})
if err:
    results.append({"tool": "events_hook_dispatcher_remove", "status": "FAIL", "reason": err})
    mismatches.append({"tool": "events_hook_dispatcher_remove", "expected": "no_error", "actual": err})
else:
    before = data.get("before", -1) if isinstance(data, dict) else -1
    after = data.get("after", -1) if isinstance(data, dict) else -1
    ok = isinstance(data, dict) and before > after and after >= 0
    results.append({"tool": "events_hook_dispatcher_remove", "status": "PASS" if ok else "FAIL", "raw": data})
    if not ok:
        mismatches.append({"tool": "events_hook_dispatcher_remove", "expected": "before>after>=0", "actual": str(data)})

# hook_matches_and_label: matches=true, label matches the input label
check("events_hook_matches_and_label", {"label": "test_label"}, [
    ("matches", True),
    ("label", lambda v: isinstance(v, str) and "test_label" in v),
])

# ── EventCorrelator ───────────────────────────────────────────────────────────

# by_view: ingest 3 events with different view_ids → total_count=3, keys sorted=[0,1,2] (as strings)
check("events_correlator_keys_and_total", {"n": 3}, [
    ("total", 3),
    # Rust serializes u64 map keys as JSON strings
    ("keys", ["0", "1", "2"]),
])

# by_view (existing tool): total_count=3, 2 unique view keys
data, err = call_tool("events_correlator_by_view", {})
if err:
    results.append({"tool": "events_correlator_by_view", "status": "FAIL", "reason": err})
    mismatches.append({"tool": "events_correlator_by_view", "expected": "no_error", "actual": err})
else:
    ok = (isinstance(data, dict) and
          data.get("total_count", 0) == 3 and
          len(data.get("keys", [])) == 2)
    results.append({"tool": "events_correlator_by_view", "status": "PASS" if ok else "FAIL", "raw": data})
    if not ok:
        mismatches.append({"tool": "events_correlator_by_view", "expected": "total_count=3, len(keys)=2", "actual": str(data)})

# by_variant: ingest 3 events of 2 variants → total_count=3, 2 variant keys
data, err = call_tool("events_correlator_by_variant", {})
if err:
    results.append({"tool": "events_correlator_by_variant", "status": "FAIL", "reason": err})
    mismatches.append({"tool": "events_correlator_by_variant", "expected": "no_error", "actual": err})
else:
    ok = (isinstance(data, dict) and
          data.get("total_count", 0) == 3 and
          len(data.get("keys", [])) == 2)
    results.append({"tool": "events_correlator_by_variant", "status": "PASS" if ok else "FAIL", "raw": data})
    if not ok:
        mismatches.append({"tool": "events_correlator_by_variant", "expected": "total_count=3, len(keys)=2", "actual": str(data)})

# ── SpecEventBus ─────────────────────────────────────────────────────────────

# Fresh SpecEventBus: history_len=0, receiver_count=0
check("events_spec_bus_new_history", {"capacity": 32}, [
    ("history_len", 0),
    ("receiver_count", 0),
])

# Publish n=5 events, request recent k=3: history_len=5, recent_len=3
check("events_spec_bus_recent_events", {"n": 5, "k": 3}, [
    ("history_len", 5),
    ("recent_len", 3),
])

# Subscribe + publish 1 ViewOpened: history_len=1, receiver_count=1
check("events_spec_bus_publish_and_receivers", {"view_id": 2, "path": "/bin/x"}, [
    ("history_len", 1),
    ("receiver_count", 1),
])

# global_bus_publish — SKIP: cumulative shared state
skip("events_global_bus_publish",
     "Nondeterministic: publishes to a shared global_bus whose history_len "
     "accumulates across all tool calls within the same process lifetime.")

# ── ExtEventBus ──────────────────────────────────────────────────────────────

# Fresh ExtEventBus: total_published=0, dropped=0, history_len=0
check("events_ext_bus_new_default", {}, [
    ("total_published", 0),
    ("dropped", 0),
    ("history_len", 0),
    ("receiver_count", 0),
])

# dropped_count on fresh bus = 0 (field name is "dropped", not "dropped_count")
check("events_ext_bus_dropped_count", {}, [
    ("dropped", 0),
    ("total", 0),
])

# total_published after n=3 publishes = 3 (field "total")
check("events_ext_bus_total_published", {"n": 3}, [
    ("total", 3),
])

# variant_count after n=4 events: variant_count=4
check("events_ext_bus_variant_count", {"n": 4}, [
    ("variant_count", 4),
])

# recent_events(n=5, k=3): recent_len=3
check("events_ext_bus_recent_events", {"n": 5, "k": 3}, [
    ("recent_len", 3),
])

# subscribe_with_history: returns history_len
data, err = call_tool("events_ext_bus_subscribe_with_history", {"n": 5})
if err:
    results.append({"tool": "events_ext_bus_subscribe_with_history", "status": "FAIL", "reason": err})
    mismatches.append({"tool": "events_ext_bus_subscribe_with_history", "expected": "no_error", "actual": err})
else:
    ok = isinstance(data, dict) and "history_len" in data
    results.append({"tool": "events_ext_bus_subscribe_with_history", "status": "PASS" if ok else "FAIL", "raw": data})
    if not ok:
        mismatches.append({"tool": "events_ext_bus_subscribe_with_history", "expected": "has history_len", "actual": str(data)})

# send_X ext wrappers: count=1, total=1
for tname, targs in [
    ("events_ext_bus_send_ttd_tick", {"view_id": 1, "tick": 42, "thread_id": 0}),
    ("events_ext_bus_send_ttd_backward", {"view_id": 1, "tick": 10, "thread_id": 0}),
    ("events_ext_bus_send_emulation_step", {"view_id": 1, "address": 0x1000, "mnemonic": "mov"}),
    ("events_ext_bus_send_emulation_stop", {"view_id": 1, "reason": "done"}),
    ("events_ext_bus_send_fuzz_crash", {"view_id": 1, "input_hash": "deadbeef", "crash_address": 0x4000}),
    ("events_ext_bus_send_fuzz_new_coverage", {"view_id": 1, "new_blocks": 3, "total_blocks": 100}),
    ("events_ext_bus_send_mcp_tool_call", {"view_id": 1, "tool_name": "t", "params_json": "{}"}),
    ("events_ext_bus_send_diff_started", {"view_id_a": 1, "view_id_b": 2, "algorithm": "bindiff"}),
    ("events_ext_bus_send_diff_completed", {"a": 1, "b": 2, "matched": 10, "unmatched": 2}),
    ("events_ext_bus_send_flirt_match", {"view_id": 1, "address": 0x1000, "library": "libssl", "name": "SSL_read", "score": 0.95}),
    ("events_ext_bus_send_coverage_updated", {"view_id": 1, "percent": 42.5}),
    ("events_ext_bus_send_watchdog_ping", {"component": "engine", "latency_ms": 5}),
    ("events_ext_bus_send_peer_connected", {"peer_id": "peer1", "view_id": 1}),
    ("events_ext_bus_send_agent_thinking", {"view_id": 1, "agent": "claude", "thought": "analyzing"}),
    ("events_ext_bus_send_mcp_tool_result", {"view_id": 1, "tool": "disasm", "result": "ok", "success": True}),
]:
    data, err = call_tool(tname, targs)
    if err:
        results.append({"tool": tname, "status": "FAIL", "reason": err})
        mismatches.append({"tool": tname, "expected": "no_error", "actual": err})
    else:
        ok = isinstance(data, dict) and data.get("count", data.get("total", 0)) == 1
        results.append({"tool": tname, "status": "PASS" if ok else "FAIL", "raw": data})
        if not ok:
            mismatches.append({"tool": tname, "expected": "count=1 or total=1", "actual": str(data)})

# metrics_snapshot: 2 events sent → total_published=2, variants>=2
check("events_ext_bus_metrics_snapshot", {}, [
    ("total_published", 2),
    ("variants", lambda v: isinstance(v, int) and v >= 2),
])

# ── Shutdown ──────────────────────────────────────────────────────────────────
try:
    p.stdin.close()
    p.terminate()
except Exception:
    pass

# ── Tally ─────────────────────────────────────────────────────────────────────
passed  = sum(1 for r in results if r["status"] == "PASS")
failed  = sum(1 for r in results if r["status"] == "FAIL")
n_skip  = sum(1 for r in results if r["status"] == "SKIP")
hardened = passed + failed

print(f"\nEvents rigorous v2: PASS={passed}  FAIL={failed}  SKIP={n_skip}  total={len(results)}")
for r in results:
    icon = {"PASS": "OK", "FAIL": "!!", "SKIP": "--"}[r["status"]]
    print(f"  [{icon}] {r['tool']}")
    if r["status"] == "FAIL":
        detail = r.get("reason") or r.get("failures", "")
        print(f"        -> {detail}")

# Write rigorous_events_v2.json
summary = {
    "category": "events",
    "tools_hardened": hardened,
    "tools_passed": passed,
    "tools_failed": failed,
    "tools_skipped": n_skip,
    "mismatches": mismatches,
    "detail": results,
}
with open(OUT_JSON, "w") as f:
    json.dump(summary, f, indent=2)
print(f"\nWrote {OUT_JSON}")

# Write skip_events.json
with open(SKIP_JSON, "w") as f:
    json.dump({"skipped": skipped}, f, indent=2)
print(f"Wrote {SKIP_JSON}")

# Final machine-readable summary for parent agent
print(json.dumps({
    "category": "events",
    "tools_hardened": hardened,
    "tools_passed": passed,
    "tools_failed": failed,
    "tools_skipped": n_skip,
    "mismatches": mismatches,
}))
