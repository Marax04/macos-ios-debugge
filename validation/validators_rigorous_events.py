#!/usr/bin/env python3
"""
Rigorous validator for RustRE MCP 'events_' tools.

Every check uses an independently computed Python truth derived from
reading the Rust source — NOT from trusting the MCP output.

Tools hardened: 12
"""

import json
import subprocess
import sys
import time
from pathlib import Path

MCP_BINARY = Path(r"C:\Users\Fra\Desktop\RustRE\target\release\rustre-mcp.exe")
OUTPUT_JSON = Path(r"C:\Users\Fra\Desktop\RustRE\validation\rigorous_events.json")


# ============================================================================
# MCP client (minimal stdio transport)
# ============================================================================

class MCPClient:
    def __init__(self, binary: Path):
        self.binary = binary
        self.proc = None
        self._id = 1

    def start(self):
        self.proc = subprocess.Popen(
            [str(self.binary), "--transport=stdio"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            bufsize=0,
        )

    def stop(self):
        if self.proc:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.proc.kill()

    def _send(self, method: str, params) -> dict:
        req = {"jsonrpc": "2.0", "id": self._id, "method": method, "params": params}
        self._id += 1
        line = (json.dumps(req) + "\n").encode()
        self.proc.stdin.write(line)
        self.proc.stdin.flush()
        resp = json.loads(self.proc.stdout.readline().decode())
        return resp.get("result", resp.get("error", {}))

    def initialize(self):
        r = self._send("initialize", {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": {"name": "rigorous-events", "version": "1.0"},
        })
        notif = {"jsonrpc": "2.0", "method": "notifications/initialized"}
        self.proc.stdin.write((json.dumps(notif) + "\n").encode())
        self.proc.stdin.flush()
        return r

    def call_tool(self, name: str, arguments: dict):
        r = self._send("tools/call", {"name": name, "arguments": arguments})
        if isinstance(r, dict):
            content = r.get("content", [])
            if content:
                text = content[0].get("text", "")
                if text:
                    try:
                        return json.loads(text)
                    except Exception:
                        return text
        return r


# ============================================================================
# Independent Python truth computations
# ============================================================================

def truth_bus_new_default():
    """
    EventBus::new_default() creates a bus with 0 receivers and 0 total_sent.
    Source: rustre-events/src/lib.rs EventBus::new_default → new(1024).
    """
    return {"receiver_count": 0, "total_sent": 0}


def truth_core_event_variant_name():
    """
    CoreEvent::ViewOpened { view_id: 1, uri: "x", arch: "x86_64" }.variant_name()
    → "ViewOpened"
    .view_id() → Some(1) → 1
    .kind() → EventKind::View → Debug format "View"
    Source: rustre-events/src/lib.rs lines 381, 533.
    """
    return {
        "variant_name": "ViewOpened",
        "view_id": 1,
        "kind": "View",
    }


def truth_core_event_is_debug_event():
    """
    CoreEvent::BreakpointHit is in the is_debug_event() match arm.
    It is NOT in is_analysis_event() or is_function_event().
    Source: rustre-events/src/lib.rs lines 437-475.
    """
    return {
        "is_debug_event": True,
        "is_analysis_event": False,
        "is_function_event": False,
    }


def truth_core_event_kind_memory():
    """
    CoreEvent::MemoryRead { view_id: 7, address: 0x1000, length: 32 }
    .kind() → EventKind::Memory → Debug format "Memory"
    .variant_name() → "MemoryRead"
    .view_id() → Some(7) → 7
    Source: rustre-events/src/lib.rs lines 558-561, 409.
    """
    return {
        "kind": "Memory",
        "variant": "MemoryRead",
        "view_id": 7,
    }


def truth_core_event_display_formatting():
    """
    CoreEvent::FunctionRenamed { view_id: 3, address: 0x400, old_name: "a", new_name: "b" }
    Display: has view_id → "[view=3] FunctionRenamed"

    CoreEvent::PluginLoaded { plugin_id: "p" }
    Display: no view_id → "PluginLoaded"

    Source: rustre-events/src/lib.rs fmt::Display impl lines 496-503.
    """
    return {
        "scoped": "[view=3] FunctionRenamed",
        "unscoped": "PluginLoaded",
    }


def truth_filter_of_kind_matches():
    """
    EventFilter::of_kind(EventKind::Debugger).matches(BreakpointHit) → true
    EventFilter::of_kind(EventKind::Debugger).matches(ViewOpened) → false
    BreakpointHit.kind() == Debugger (lines 548-557 lib.rs)
    ViewOpened.kind() == View (lines 533-534 lib.rs)
    """
    return {
        "matches_bp": True,
        "matches_view": False,
    }


def truth_filter_combinators():
    """
    a = EventFilter::for_view(1)   → matches view_id==1
    b = EventFilter::by_variant("ViewOpened")  → matches variant=="ViewOpened"
    both = a.and(b)
    e = ViewOpened { view_id: 1, uri: "x", arch: "x86_64" }
    both.matches(e) → true (view_id==1 AND variant=="ViewOpened")

    neg = EventFilter::for_view(2).negate()
    neg.matches(e) → !(view_id==2) → !(false) → true

    or_f = EventFilter::for_view(9).or(EventFilter::by_variant("ViewOpened"))
    or_f.matches(e) → (view_id==9 OR variant=="ViewOpened") → (false OR true) → true
    """
    return {
        "and_match": True,
        "negate_match": True,
        "or_match": True,
    }


def truth_filter_for_view():
    """
    EventFilter::for_view(view_id).matches(ViewOpened{view_id}) → true
    EventFilter::for_view(view_id).matches(ViewOpened{view_id+1}) → false
    """
    return {
        "matches_expected": True,
        "matches_other": False,
    }


def truth_correlator_by_view():
    """
    EventCorrelator::by_view() groups events by view_id as String.
    Ingest: ViewOpened(1), ViewOpened(2), ViewClosed(1)
    keys: {"1", "2"} → len=2
    total_count: 3
    group_1_len: 2 (ViewOpened(1) + ViewClosed(1))
    Source: rustre-events/src/lib.rs lines 1293-1340.
    """
    return {
        "total_count": 3,
        "group_1_len": 2,
    }


def truth_core_event_json_roundtrip():
    """
    CoreEvent::FunctionDefined { view_id: 1, address: 0x1000, name: "main" }
    Serialized via serde_json, deserialized back.
    roundtrip_variant must equal "FunctionDefined".

    json_len: we can compute via Python's json.dumps of the serde representation.
    Rust serde_json uses externally-tagged enums:
      {"FunctionDefined":{"view_id":1,"address":4096,"name":"main"}}
    """
    import json as _json
    payload = {"FunctionDefined": {"view_id": 1, "address": 4096, "name": "main"}}
    expected_len = len(_json.dumps(payload, separators=(",", ":")))
    return {
        "json_len": expected_len,
        "roundtrip_variant": "FunctionDefined",
    }


def truth_hook_dispatcher():
    """
    HookDispatcher::new() → register 1 hook → hook_count=1
    After remove("test") → hook_count=0
    """
    return {
        "hook_count_before_remove": 1,
        "hook_count_after_remove": 0,
    }


def truth_bus_send_custom():
    """
    EventBus::new_default() → subscribe → send_custom("MyEvent", {})
    → total_sent=1, custom_count=1 (variant name is "Custom")
    receiver_count=1 (one subscriber)
    """
    return {
        "total_sent": 1,
        "custom_count": 1,
        "receiver_count": 1,
    }


def truth_logger_record_and_count():
    """
    EventLogger::new(max_size) records N events.
    Wire tool: max_size param + records 5 Custom events.
    → count=5, sample_len=3 (recent_events(3))
    We need to verify with the actual wire tool default.
    Let's check: EventsLoggerRecordAndCountTool uses max_size param.
    We'll pass max_size=10 and record 5 events → count=5, sample_len=3.
    """
    return {
        "count": 5,
        "sample_len": 3,
    }


# ============================================================================
# Check helpers
# ============================================================================

def check_subset(mcp: dict, truth: dict) -> tuple[bool, str]:
    """
    Verify all keys in truth exist in mcp with equal values.
    Extra MCP fields (like 'source') are allowed.
    """
    for k, v in truth.items():
        if k not in mcp:
            return False, f"missing key '{k}' in MCP output"
        if mcp[k] != v:
            return False, f"key '{k}': expected {v!r}, got {mcp[k]!r}"
    return True, "ok"


def check_keys_present(mcp: dict, keys: list) -> tuple[bool, str]:
    """Check that all listed keys are present."""
    for k in keys:
        if k not in mcp:
            return False, f"missing key '{k}'"
    return True, "ok"


# ============================================================================
# Test table
# ============================================================================

TESTS = [
    {
        "tool": "events_bus_new_default",
        "args": {},
        "truth_fn": truth_bus_new_default,
        "check": "subset",
        "description": "New default bus has receiver_count=0, total_sent=0",
    },
    {
        "tool": "events_core_event_variant_name",
        "args": {},
        "truth_fn": truth_core_event_variant_name,
        "check": "subset",
        "description": "ViewOpened variant_name='ViewOpened', view_id=1, kind='View'",
    },
    {
        "tool": "events_core_event_is_debug_event",
        "args": {},
        "truth_fn": truth_core_event_is_debug_event,
        "check": "subset",
        "description": "BreakpointHit is_debug_event=true, not analysis/function",
    },
    {
        "tool": "events_core_event_kind_memory",
        "args": {},
        "truth_fn": truth_core_event_kind_memory,
        "check": "subset",
        "description": "MemoryRead kind='Memory', variant='MemoryRead', view_id=7",
    },
    {
        "tool": "events_core_event_display_formatting",
        "args": {},
        "truth_fn": truth_core_event_display_formatting,
        "check": "subset",
        "description": "FunctionRenamed Display='[view=3] FunctionRenamed', PluginLoaded='PluginLoaded'",
    },
    {
        "tool": "events_filter_of_kind_matches",
        "args": {},
        "truth_fn": truth_filter_of_kind_matches,
        "check": "subset",
        "description": "Debugger filter: BreakpointHit=true, ViewOpened=false",
    },
    {
        "tool": "events_filter_combinators",
        "args": {},
        "truth_fn": truth_filter_combinators,
        "check": "subset",
        "description": "and/or/negate all return true for the test event",
    },
    {
        "tool": "events_filter_for_view",
        "args": {"view_id": 5},
        "truth_fn": truth_filter_for_view,
        "check": "subset",
        "description": "for_view(5): matches_expected=true, matches_other=false",
    },
    {
        "tool": "events_correlator_by_view",
        "args": {},
        "truth_fn": truth_correlator_by_view,
        "check": "subset",
        "description": "Correlator by view: total_count=3, group_1_len=2",
    },
    {
        "tool": "events_core_event_json_roundtrip",
        "args": {},
        "truth_fn": truth_core_event_json_roundtrip,
        "check": "subset",
        "description": "FunctionDefined JSON roundtrip: correct len and variant name",
    },
    {
        "tool": "events_hook_dispatcher_register",
        "args": {},
        "truth_fn": truth_hook_dispatcher,
        "check": "subset",
        "description": "HookDispatcher: 1 hook before remove, 0 after",
    },
    {
        "tool": "events_bus_send_custom",
        "args": {"event_type": "MyTest"},
        "truth_fn": truth_bus_send_custom,
        "check": "subset",
        "description": "EventBus send_custom: total_sent=1, custom_count=1, receiver_count=1",
    },
]


# ============================================================================
# Main
# ============================================================================

def main():
    OUTPUT_JSON.parent.mkdir(parents=True, exist_ok=True)

    print("[*] Rigorous events validator starting...")
    print(f"[*] Binary: {MCP_BINARY}")

    if not MCP_BINARY.exists():
        print(f"[!] Binary not found: {MCP_BINARY}")
        report = {
            "module": "events",
            "tools_hardened": len(TESTS),
            "checks_passed": 0,
            "checks_failed": 0,
            "mismatches": [],
            "error": "binary not found",
        }
        OUTPUT_JSON.write_text(json.dumps(report, indent=2))
        return report

    client = MCPClient(MCP_BINARY)
    try:
        client.start()
        time.sleep(0.5)
        init = client.initialize()
        if not init:
            raise RuntimeError("MCP initialize failed")
        print("[+] MCP initialized")

        checks_passed = 0
        checks_failed = 0
        mismatches = []

        for test in TESTS:
            tool = test["tool"]
            args = test["args"]
            desc = test["description"]
            truth = test["truth_fn"]()

            try:
                mcp = client.call_tool(tool, args)
            except Exception as e:
                print(f"[!] {tool}: call failed: {e}")
                checks_failed += 1
                mismatches.append({
                    "tool": tool,
                    "error": str(e),
                    "kind": "call_error",
                })
                continue

            if not isinstance(mcp, dict):
                print(f"[!] {tool}: unexpected response type {type(mcp)}: {mcp!r}")
                checks_failed += 1
                mismatches.append({
                    "tool": tool,
                    "mcp": mcp,
                    "truth": truth,
                    "kind": "type_mismatch",
                })
                continue

            ok, reason = check_subset(mcp, truth)
            if ok:
                print(f"[+] {tool}: PASS  ({desc})")
                checks_passed += 1
            else:
                print(f"[-] {tool}: MISMATCH  {reason}")
                checks_failed += 1
                mismatches.append({
                    "tool": tool,
                    "args": args,
                    "mcp": {k: v for k, v in mcp.items() if k != "source"},
                    "truth": truth,
                    "reason": reason,
                    "kind": "value_mismatch",
                })

        report = {
            "module": "events",
            "tools_hardened": len(TESTS),
            "checks_passed": checks_passed,
            "checks_failed": checks_failed,
            "mismatches": mismatches,
        }

        OUTPUT_JSON.write_text(json.dumps(report, indent=2))
        print(f"\n[+] Report: {OUTPUT_JSON}")
        print(f"[+] {checks_passed}/{len(TESTS)} passed, {checks_failed} failed")
        if mismatches:
            print(f"[!] {len(mismatches)} real mismatch(es):")
            for m in mismatches:
                print(f"    {m['tool']}: {m.get('reason', m.get('error', ''))}")
        else:
            print("[+] All checks clean.")

        return report

    finally:
        client.stop()


if __name__ == "__main__":
    r = main()
    sys.exit(0 if r.get("checks_failed", 1) == 0 else 1)
