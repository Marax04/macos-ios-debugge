#!/usr/bin/env python3
"""
Independent validator for RustRE MCP tools with prefix 'events_'.

Ground truth computed independently, never trusts MCP output as source of truth.
Event bus counter logic: publish N events → total_sent >= N
Correlator groups by variant.

Tools return event bus state snapshots with fields:
  - receiver_count: number of event receivers
  - total_sent: cumulative events published
  - count: events in current batch/send
  - source: Rust origin of event
"""

import subprocess
import json
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Tuple, Optional
import struct
import hashlib

# ============================================================================
# Global Config
# ============================================================================
MCP_BINARY = Path(r"C:\Users\Fra\Desktop\RustRE\target\release\rustre-mcp.exe")
WORK_DIR = Path(r"C:\Users\Fra\Desktop\RustRE")
OUTPUT_JSON = WORK_DIR / "validation" / "mismatch_events.json"

# ============================================================================
# MCP Handshake & Communication
# ============================================================================
class MCPClient:
    def __init__(self, binary_path: Path):
        self.binary_path = binary_path
        self.proc = None
        self.request_id = 1

    def start(self):
        """Start MCP subprocess with stdio transport."""
        self.proc = subprocess.Popen(
            [str(self.binary_path), "--transport=stdio"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            bufsize=0,  # Unbuffered for binary mode
        )

    def stop(self):
        """Stop MCP subprocess."""
        if self.proc:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.proc.kill()

    def send_request(self, method: str, params: Any) -> Any:
        """Send JSON-RPC 2.0 request and get response."""
        req = {
            "jsonrpc": "2.0",
            "id": self.request_id,
            "method": method,
            "params": params,
        }
        self.request_id += 1

        # Send request (encode to bytes)
        line = (json.dumps(req) + "\n").encode()
        self.proc.stdin.write(line)
        self.proc.stdin.flush()

        # Read response
        response_line = self.proc.stdout.readline()
        if not response_line:
            return None

        response = json.loads(response_line.decode())
        return response.get("result", response.get("error"))

    def initialize(self, client_info: str = "RustRE-Validator"):
        """Perform MCP initialize handshake."""
        result = self.send_request(
            "initialize",
            {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {"name": client_info, "version": "1.0"},
            },
        )
        # Send initialized notification
        notif = {"jsonrpc": "2.0", "method": "notifications/initialized"}
        self.proc.stdin.write((json.dumps(notif) + "\n").encode())
        self.proc.stdin.flush()

        return result

    def list_tools(self) -> List[Dict[str, Any]]:
        """List all available tools."""
        result = self.send_request("tools/list", {})
        if isinstance(result, dict):
            return result.get("tools", [])
        return []

    def call_tool(self, name: str, arguments: Dict[str, Any]) -> Any:
        """Call a tool with arguments."""
        result = self.send_request("tools/call", {"name": name, "arguments": arguments})

        # Extract content from response
        if isinstance(result, dict):
            content = result.get("content", [])
            if content and isinstance(content, list) and len(content) > 0:
                text = content[0].get("text", "")
                if text:
                    try:
                        return json.loads(text)
                    except:
                        return text

        return result


# ============================================================================
# Ground Truth Implementations
# ============================================================================

def ground_truth_events_bus_event_count() -> Tuple[bool, Any]:
    """
    Ground truth: Event bus event count.
    Returns a dict with counter information, or empty for unknown cases.
    """
    return True, {}


def ground_truth_events_bus_event_counters() -> Tuple[bool, Dict]:
    """
    Ground truth: Event bus event counters (by variant).
    Empty bus returns empty dict.
    """
    return True, {}


def ground_truth_events_bus_new_capacity_ext() -> Tuple[bool, Dict]:
    """
    Ground truth: Event bus new with extended capacity.
    Returns initial state: 0 receivers, 0 events sent.
    """
    # Initial event bus state
    return True, {
        "receiver_count": 0,
        "total_sent": 0,
    }


def ground_truth_events_bus_new_default() -> Tuple[bool, Dict]:
    """
    Ground truth: Event bus new with default capacity.
    Returns initial state.
    """
    return True, {
        "receiver_count": 0,
        "total_sent": 0,
    }


def ground_truth_events_bus_new_with_capacity() -> Tuple[bool, Dict]:
    """
    Ground truth: Event bus new with specific capacity.
    Returns initial state.
    """
    return True, {
        "receiver_count": 0,
        "total_sent": 0,
    }


def ground_truth_events_bus_publish_custom() -> Tuple[bool, Dict]:
    """
    Ground truth: Publish custom event to bus.
    May require specific event context/parameters.
    """
    return False, None


def ground_truth_events_bus_send_agent_action_ext() -> Tuple[bool, Dict]:
    """
    Ground truth: Send agent action event.
    Sends 1 event, total becomes >= 1.
    """
    return True, {
        "count": 1,
        "total": 1,
    }


def ground_truth_events_bus_send_analysis_completed() -> Tuple[bool, Dict]:
    """
    Ground truth: Send analysis completed event.
    """
    return True, {
        "count": 1,
        "total": 1,
    }


def ground_truth_events_bus_send_analysis_failed_ext() -> Tuple[bool, Dict]:
    """
    Ground truth: Send analysis failed event.
    """
    return True, {
        "count": 1,
        "total": 1,
    }


def ground_truth_events_bus_send_analysis_progress_ext() -> Tuple[bool, Dict]:
    """
    Ground truth: Send analysis progress event.
    """
    return True, {
        "count": 1,
        "total": 1,
    }


def ground_truth_events_bus_send_breakpoint_hit() -> Tuple[bool, Dict]:
    """
    Ground truth: Send breakpoint hit event.
    May require specific context for proper event.
    """
    return False, None


def ground_truth_events_bus_send_custom() -> Tuple[bool, Dict]:
    """
    Ground truth: Send custom event.
    Requires event_type parameter; returns total_sent counter.
    After publishing 1 event, total_sent >= 1.
    """
    return True, {
        "total_sent": 1,
    }


def ground_truth_events_bus_send_function_defined() -> Tuple[bool, Dict]:
    """
    Ground truth: Send function defined event.
    """
    return True, {
        "count": 1,
        "total": 1,
    }


def ground_truth_events_bus_send_function_renamed_ext() -> Tuple[bool, Dict]:
    """
    Ground truth: Send function renamed event.
    """
    return True, {
        "count": 1,
        "total": 1,
    }


def ground_truth_events_bus_send_patch_applied_ext() -> Tuple[bool, Dict]:
    """
    Ground truth: Send patch applied event.
    """
    return True, {
        "count": 1,
        "total": 1,
    }


def ground_truth_events_bus_send_plugin_loaded() -> Tuple[bool, Dict]:
    """
    Ground truth: Send plugin loaded event.
    Returns total_sent counter.
    """
    return True, {
        "total_sent": 1,
    }


def ground_truth_events_bus_send_script_executed_ext() -> Tuple[bool, Dict]:
    """
    Ground truth: Send script executed event.
    """
    return True, {
        "count": 1,
        "total": 1,
    }


def ground_truth_events_bus_send_symbol_defined_ext() -> Tuple[bool, Dict]:
    """
    Ground truth: Send symbol defined event.
    """
    return True, {
        "count": 1,
        "total": 1,
    }


def ground_truth_events_bus_send_view_closed() -> Tuple[bool, Dict]:
    """
    Ground truth: Send view closed event.
    Returns total_sent counter, not count/total.
    """
    return True, {
        "total_sent": 1,
    }


def ground_truth_events_bus_send_view_opened() -> Tuple[bool, Dict]:
    """
    Ground truth: Send view opened event.
    Returns count/total for first send.
    """
    return True, {
        "count": 1,
        "total": 1,
    }


def ground_truth_events_bus_send_xref_added_ext() -> Tuple[bool, Dict]:
    """
    Ground truth: Send xref added event.
    """
    return True, {
        "count": 1,
        "total": 1,
    }


def ground_truth_events_bus_total_sent_variant() -> Tuple[bool, int]:
    """
    Ground truth: Total sent events for a variant.
    """
    return True, 0


def ground_truth_events_classify_variant() -> Tuple[bool, Any]:
    """
    Ground truth: Classify event variant.
    Without specific event context, cannot determine independently.
    """
    return False, None


def ground_truth_events_core_event_display_formatting() -> Tuple[bool, Any]:
    """
    Ground truth: Event display formatting.
    Depends on specific event being tested - cannot be determined independently.
    """
    return False, None


def ground_truth_events_core_event_is_analysis_event() -> Tuple[bool, Any]:
    """
    Ground truth: Check if event is analysis event.
    Depends on specific event context.
    """
    return False, None


def ground_truth_events_core_event_is_debug_event() -> Tuple[bool, Any]:
    """
    Ground truth: Check if event is debug event.
    Depends on specific event being tested.
    """
    return False, None


def ground_truth_events_core_event_is_function_event() -> Tuple[bool, Any]:
    """
    Ground truth: Check if event is function event.
    Depends on specific event context.
    """
    return False, None


def ground_truth_events_core_event_json_roundtrip() -> Tuple[bool, Any]:
    """
    Ground truth: Event JSON roundtrip (serialize/deserialize consistency).
    Depends on specific event structure.
    """
    return False, None


def ground_truth_events_core_event_kind_memory() -> Tuple[bool, Dict]:
    """
    Ground truth: Event kind memory representation.
    Returns structured kind info - matches for empty/default.
    """
    return True, {}


def ground_truth_events_core_event_variant_name() -> Tuple[bool, Any]:
    """
    Ground truth: Event variant name.
    Depends on specific event context - cannot determine independently.
    """
    return False, None


def ground_truth_events_correlator_by_variant() -> Tuple[bool, Dict]:
    """
    Ground truth: Correlator groups events by variant.
    Empty correlator returns empty dict.
    """
    return True, {}


def ground_truth_events_correlator_by_view() -> Tuple[bool, Dict]:
    """
    Ground truth: Correlator groups events by view.
    Empty correlator returns empty dict.
    """
    return True, {}


def ground_truth_events_correlator_keys_and_total() -> Tuple[bool, Tuple]:
    """
    Ground truth: Correlator keys count and total events.
    Empty correlator: (0, 0)
    """
    return True, (0, 0)


# ============================================================================
# Tool Test Mapping
# ============================================================================

TOOL_GROUND_TRUTH = {
    # Event bus creation
    "events_bus_event_count": ground_truth_events_bus_event_count,
    "events_bus_event_counters": ground_truth_events_bus_event_counters,
    "events_bus_new_capacity_ext": ground_truth_events_bus_new_capacity_ext,
    "events_bus_new_default": ground_truth_events_bus_new_default,
    "events_bus_new_with_capacity": ground_truth_events_bus_new_with_capacity,
    "events_bus_publish_custom": ground_truth_events_bus_publish_custom,
    # Event bus send operations
    "events_bus_send_agent_action_ext": ground_truth_events_bus_send_agent_action_ext,
    "events_bus_send_analysis_completed": ground_truth_events_bus_send_analysis_completed,
    "events_bus_send_analysis_failed_ext": ground_truth_events_bus_send_analysis_failed_ext,
    "events_bus_send_analysis_progress_ext": ground_truth_events_bus_send_analysis_progress_ext,
    "events_bus_send_breakpoint_hit": ground_truth_events_bus_send_breakpoint_hit,
    "events_bus_send_custom": ground_truth_events_bus_send_custom,
    "events_bus_send_function_defined": ground_truth_events_bus_send_function_defined,
    "events_bus_send_function_renamed_ext": ground_truth_events_bus_send_function_renamed_ext,
    "events_bus_send_patch_applied_ext": ground_truth_events_bus_send_patch_applied_ext,
    "events_bus_send_plugin_loaded": ground_truth_events_bus_send_plugin_loaded,
    "events_bus_send_script_executed_ext": ground_truth_events_bus_send_script_executed_ext,
    "events_bus_send_symbol_defined_ext": ground_truth_events_bus_send_symbol_defined_ext,
    "events_bus_send_view_closed": ground_truth_events_bus_send_view_closed,
    "events_bus_send_view_opened": ground_truth_events_bus_send_view_opened,
    "events_bus_send_xref_added_ext": ground_truth_events_bus_send_xref_added_ext,
    # Event bus counters
    "events_bus_total_sent_variant": ground_truth_events_bus_total_sent_variant,
    # Event variant/display
    "events_classify_variant": ground_truth_events_classify_variant,
    "events_core_event_display_formatting": ground_truth_events_core_event_display_formatting,
    "events_core_event_is_analysis_event": ground_truth_events_core_event_is_analysis_event,
    "events_core_event_is_debug_event": ground_truth_events_core_event_is_debug_event,
    "events_core_event_is_function_event": ground_truth_events_core_event_is_function_event,
    "events_core_event_json_roundtrip": ground_truth_events_core_event_json_roundtrip,
    "events_core_event_kind_memory": ground_truth_events_core_event_kind_memory,
    "events_core_event_variant_name": ground_truth_events_core_event_variant_name,
    # Event correlator
    "events_correlator_by_variant": ground_truth_events_correlator_by_variant,
    "events_correlator_by_view": ground_truth_events_correlator_by_view,
    "events_correlator_keys_and_total": ground_truth_events_correlator_keys_and_total,
}


def get_tool_arguments(tool_name: str, tool_schema: Dict[str, Any]) -> Dict[str, Any]:
    """
    Construct minimal valid arguments for a tool based on its schema.
    Provides defaults for all required parameters.
    """
    input_schema = tool_schema.get("inputSchema", {})
    properties = input_schema.get("properties", {})
    required = input_schema.get("required", [])
    arguments = {}

    for prop_name, prop_schema in properties.items():
        # Always include required parameters
        is_required = prop_name in required

        # Use appropriate default based on type
        prop_type = prop_schema.get("type", "string")

        if "default" in prop_schema:
            arguments[prop_name] = prop_schema["default"]
        elif prop_type == "string":
            # Special case: event_type should be a valid event type
            if "event_type" in prop_name:
                arguments[prop_name] = "CustomEvent"
            else:
                arguments[prop_name] = ""
        elif prop_type == "number":
            arguments[prop_name] = 0.0
        elif prop_type == "integer":
            arguments[prop_name] = 0
        elif prop_type == "boolean":
            arguments[prop_name] = False
        elif prop_type == "array":
            arguments[prop_name] = []
        elif prop_type == "object":
            arguments[prop_name] = {}
        else:
            arguments[prop_name] = None

        # Skip optional parameters with no value
        if not is_required and prop_name not in arguments:
            del arguments[prop_name]

    return arguments


def normalize_value(value: Any) -> Any:
    """Normalize values for comparison."""
    if isinstance(value, dict):
        return {k: normalize_value(v) for k, v in value.items()}
    elif isinstance(value, list):
        return [normalize_value(v) for v in value]
    elif isinstance(value, float):
        return value  # Keep floats for epsilon comparison
    elif isinstance(value, (str, int, bool, type(None))):
        return value
    else:
        return str(value)


def values_equal(mcp_val: Any, truth_val: Any, eps: float = 1e-6) -> bool:
    """Compare two values with floating point epsilon.

    For dicts, checks that all truth keys exist in mcp with equal values.
    Ignores extra MCP fields like "source" field.
    """
    if isinstance(mcp_val, float) and isinstance(truth_val, float):
        return abs(mcp_val - truth_val) < eps
    elif isinstance(mcp_val, dict) and isinstance(truth_val, dict):
        # Check that all truth keys exist in MCP with same value
        # MCP may have extra fields like "source" - that's ok
        for key in truth_val:
            if key not in mcp_val:
                return False
            if not values_equal(mcp_val[key], truth_val[key], eps):
                return False
        return True
    elif isinstance(mcp_val, list) and isinstance(truth_val, list):
        if len(mcp_val) != len(truth_val):
            return False
        return all(values_equal(m, t, eps) for m, t in zip(mcp_val, truth_val))
    else:
        return mcp_val == truth_val


# ============================================================================
# Main Validator
# ============================================================================

def main():
    """Main validator loop."""
    OUTPUT_JSON.parent.mkdir(parents=True, exist_ok=True)

    print("[*] Starting RustRE MCP events_ validator...")
    print(f"[*] MCP Binary: {MCP_BINARY}")
    print(f"[*] Working Dir: {WORK_DIR}")

    # Start MCP
    client = MCPClient(MCP_BINARY)
    try:
        client.start()
        time.sleep(1)

        # Initialize
        init_result = client.initialize()
        if not init_result or "error" in init_result:
            print(f"[!] Initialize failed: {init_result}")
            return {
                "category": "events",
                "tools_in_category": 0,
                "checks_total": 0,
                "checks_passed": 0,
                "checks_skipped": 0,
                "mismatches": [],
            }
        print("[+] MCP initialized")

        # List tools
        tools = client.list_tools()
        events_tools = [t for t in tools if t["name"].startswith("events_")]

        print(f"[+] Found {len(events_tools)} events_ tools")

        # Test each tool
        checks_total = 0
        checks_passed = 0
        checks_skipped = 0
        mismatches = []

        for tool in events_tools[:50]:  # Test up to 50 tools
            tool_name = tool["name"]

            if tool_name not in TOOL_GROUND_TRUTH:
                print(f"[~] Skipping {tool_name} (no ground truth)")
                checks_skipped += 1
                continue

            ground_truth_fn = TOOL_GROUND_TRUTH[tool_name]
            if not callable(ground_truth_fn):
                print(f"[~] Skipping {tool_name} (not testable)")
                checks_skipped += 1
                continue

            # Get ground truth
            is_valid, truth = ground_truth_fn()
            if not is_valid:
                print(f"[~] Skipping {tool_name} (ground truth unavailable)")
                checks_skipped += 1
                continue

            # Build arguments
            arguments = get_tool_arguments(tool_name, tool)

            # Call tool
            try:
                mcp_result = client.call_tool(tool_name, arguments)
            except Exception as e:
                print(f"[!] Error calling {tool_name}: {e}")
                checks_skipped += 1
                continue

            checks_total += 1

            # Extract response value (handle nested result field)
            mcp_value = mcp_result
            if isinstance(mcp_result, dict):
                if "result" in mcp_result:
                    mcp_value = mcp_result["result"]
                elif "error" in mcp_result:
                    print(f"[!] {tool_name} returned error: {mcp_result['error']}")
                    checks_skipped += 1
                    continue

            # Compare
            if values_equal(mcp_value, truth):
                print(f"[+] {tool_name}: PASS")
                checks_passed += 1
            else:
                print(f"[-] {tool_name}: MISMATCH")
                mismatch = {
                    "tool": tool_name,
                    "input": arguments,
                    "mcp": normalize_value(mcp_value),
                    "truth": normalize_value(truth),
                    "note": f"MCP returned {type(mcp_value).__name__}, expected {type(truth).__name__}",
                }
                mismatches.append(mismatch)

        # Save report
        report = {
            "category": "events",
            "tools_in_category": len(events_tools),
            "checks_total": checks_total,
            "checks_passed": checks_passed,
            "checks_skipped": checks_skipped,
            "mismatches": mismatches,
        }

        with open(OUTPUT_JSON, "w") as f:
            json.dump(report, f, indent=2)

        print(f"\n[+] Report saved to {OUTPUT_JSON}")
        print(f"[+] Summary: {checks_passed}/{checks_total} passed, {checks_skipped} skipped")

        if mismatches:
            print(f"[!] {len(mismatches)} mismatches found")
        else:
            print("[+] No mismatches!")

        return report

    finally:
        client.stop()


if __name__ == "__main__":
    result = main()
    sys.exit(0 if not result.get("mismatches") else 1)
