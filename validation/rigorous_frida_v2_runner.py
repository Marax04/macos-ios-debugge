#!/usr/bin/env python3
"""
Rigorous ground-truth validation for all MCP tools prefixed with frida_.
Each tool is called with deterministic inputs and the response is compared
against an independently-computed Python reference.
"""
import json, subprocess, sys, traceback

EXE = r"C:\Users\Fra\Desktop\RustRE\target\release\rustre-mcp.exe"
TARGET = r"C:\Users\Fra\Desktop\Zyphora\target\release\cargo-zyphora.exe"
OUT_PASS = r"C:\Users\Fra\Desktop\RustRE\validation\rigorous_frida_v2.json"
OUT_SKIP = r"C:\Users\Fra\Desktop\RustRE\validation\skip_frida.json"

# ── MCP JSON-RPC helpers ────────────────────────────────────────────────────

p = subprocess.Popen(
    [EXE, "--transport=stdio"],
    stdin=subprocess.PIPE,
    stdout=subprocess.PIPE,
    stderr=subprocess.DEVNULL,
    bufsize=0,
)

_rid = 0

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
        return {"error": {"message": f"bad-line: {line[:200]!r}"}}

def call_tool(name, arguments):
    global _rid
    _rid += 1
    send({"jsonrpc": "2.0", "id": _rid, "method": "tools/call",
          "params": {"name": name, "arguments": arguments}})
    resp = recv()
    if "error" in resp:
        return None, str(resp["error"])
    result = resp.get("result", {})
    is_err = result.get("isError", False)
    content = result.get("content", [])
    txt = content[0].get("text", "") if content else ""
    if is_err:
        return None, txt
    try:
        return json.loads(txt), None
    except Exception:
        return txt, None  # text tool result

# ── Handshake ───────────────────────────────────────────────────────────────

send({"jsonrpc": "2.0", "id": 1, "method": "initialize",
      "params": {"protocolVersion": "2024-11-05", "capabilities": {},
                 "clientInfo": {"name": "rigorous_frida", "version": "1"}}})
recv()
send({"jsonrpc": "2.0", "method": "notifications/initialized"})

# Open project (required by some tools; ignore failure here)
_rid = 10
send({"jsonrpc": "2.0", "id": _rid, "method": "tools/call",
      "params": {"name": "project.open", "arguments": {"path": TARGET}}})
_proj = recv()
_rid = 20

# ── Python reference implementations ────────────────────────────────────────

def ref_frida_device_display(kind, value=""):
    """Reference: FridaDevice::Display impl."""
    if kind == "local":
        return "local"
    elif kind == "remote":
        return f"remote:{value}"
    elif kind == "usb":
        return f"usb:{value}"
    raise ValueError(f"unknown kind: {kind}")

def ref_frida_target_local_pid(pid):
    """Reference: FridaTarget::local_pid fields."""
    return {"pid": pid, "process_name": None, "device": "local"}

def ref_frida_target_local_name(name):
    """Reference: FridaTarget::local_name fields."""
    return {"pid": None, "process_name": name, "device": "local"}

def ref_stalker_event_display(kind, a=0, b=0):
    """Reference: StalkerEvent::Display impl."""
    if kind == "call":
        return f"call {hex(a)} -> {hex(b)}"
    elif kind == "block":
        return f"block {hex(a)}..{hex(b)}"
    elif kind == "compile":
        return f"compile {hex(a)}"
    raise ValueError(f"unknown kind: {kind}")

def ref_mock_stalker_events(count):
    """Reference: FridaManager::mock_stalker_events algorithm."""
    events = []
    for i in range(count):
        base = i * 0x100
        r = i % 3
        if r == 0:
            events.append(f"call {hex(base)} -> {hex(base + 0x1000)}")
        elif r == 1:
            events.append(f"block {hex(base)}..{hex(base + 0x20)}")
        else:
            events.append(f"compile {hex(base)}")
    return events

# ── Test cases ───────────────────────────────────────────────────────────────
# Each entry: (tool_name, arguments, check_fn)
# check_fn(actual_json) -> (passed: bool, detail: str)

results = []
skipped = []
mismatches = []

def run_test(tool_name, arguments, check_fn, description=""):
    actual, err = call_tool(tool_name, arguments)
    entry = {
        "tool": tool_name,
        "args": arguments,
        "description": description,
    }
    if err is not None:
        # Unexpected error from MCP server
        entry["status"] = "FAIL"
        entry["expected"] = "no error"
        entry["actual"] = f"TOOL_ERROR: {err}"
        results.append(entry)
        mismatches.append({"tool": tool_name, "expected": "no error",
                           "actual": f"TOOL_ERROR: {err}"})
        return
    try:
        passed, detail = check_fn(actual)
    except Exception:
        passed = False
        detail = traceback.format_exc()
    if passed:
        entry["status"] = "PASS"
        entry["detail"] = detail
    else:
        entry["status"] = "FAIL"
        entry["detail"] = detail
        mismatches.append({"tool": tool_name, "expected": detail.split("expected=")[1].split(",")[0] if "expected=" in detail else "?",
                           "actual": str(actual)[:300]})
    results.append(entry)

def skip_test(tool_name, reason):
    skipped.append({"tool": tool_name, "reason": reason})

# ── 1. frida_session_initial_state ──────────────────────────────────────────
def check_initial_state(actual):
    expected_state = "detached"
    got = actual.get("state") if isinstance(actual, dict) else None
    if got == expected_state:
        return True, f"state={got!r} matches expected={expected_state!r}"
    return False, f"expected={expected_state!r}, got={got!r}"

run_test(
    "frida_session_initial_state", {},
    check_initial_state,
    "new FridaDebugSession starts in Detached state"
)

# ── 2. frida_mock_stalker_events (count=5) ──────────────────────────────────
def check_mock_stalker_5(actual):
    if not isinstance(actual, dict):
        return False, f"expected dict, got {type(actual)}"
    got_count = actual.get("count")
    got_events = actual.get("events", [])
    exp_events = ref_mock_stalker_events(5)
    if got_count != 5:
        return False, f"expected count=5, got={got_count}"
    if got_events != exp_events:
        return False, (f"events mismatch:\n"
                       f"  expected={exp_events}\n"
                       f"  got={got_events}")
    return True, f"count=5 events match expected={exp_events}"

run_test(
    "frida_mock_stalker_events", {"count": 5},
    check_mock_stalker_5,
    "mock_stalker_events(5): deterministic pattern i%3"
)

# ── 3. frida_device_display — local ─────────────────────────────────────────
def check_device_local(actual):
    exp = ref_frida_device_display("local")
    got = actual.get("display") if isinstance(actual, dict) else None
    if got == exp:
        return True, f"display={got!r} matches expected={exp!r}"
    return False, f"expected={exp!r}, got={got!r}"

run_test(
    "frida_device_display", {"kind": "local"},
    check_device_local,
    "FridaDevice::Local displays as 'local'"
)

# ── 4. frida_device_display — remote ────────────────────────────────────────
def check_device_remote(actual):
    exp = ref_frida_device_display("remote", "192.168.1.1")
    got = actual.get("display") if isinstance(actual, dict) else None
    if got == exp:
        return True, f"display={got!r} matches expected={exp!r}"
    return False, f"expected={exp!r}, got={got!r}"

run_test(
    "frida_device_display", {"kind": "remote", "value": "192.168.1.1"},
    check_device_remote,
    "FridaDevice::Remote('192.168.1.1') displays as 'remote:192.168.1.1'"
)

# ── 5. frida_device_display — usb ───────────────────────────────────────────
def check_device_usb(actual):
    exp = ref_frida_device_display("usb", "abc123")
    got = actual.get("display") if isinstance(actual, dict) else None
    if got == exp:
        return True, f"display={got!r} matches expected={exp!r}"
    return False, f"expected={exp!r}, got={got!r}"

run_test(
    "frida_device_display", {"kind": "usb", "value": "abc123"},
    check_device_usb,
    "FridaDevice::Usb('abc123') displays as 'usb:abc123'"
)

# ── 6. frida_target_local_pid ───────────────────────────────────────────────
def check_target_pid(actual):
    exp = ref_frida_target_local_pid(1234)
    if not isinstance(actual, dict):
        return False, f"expected dict, got {type(actual)}"
    errors = []
    if actual.get("pid") != exp["pid"]:
        errors.append(f"pid: expected={exp['pid']}, got={actual.get('pid')}")
    if actual.get("process_name") != exp["process_name"]:
        errors.append(f"process_name: expected={exp['process_name']}, got={actual.get('process_name')}")
    if actual.get("device") != exp["device"]:
        errors.append(f"device: expected={exp['device']!r}, got={actual.get('device')!r}")
    if errors:
        return False, "; ".join(errors)
    return True, f"pid={actual['pid']}, process_name=None, device=local"

run_test(
    "frida_target_local_pid", {"pid": 1234},
    check_target_pid,
    "FridaTarget::local_pid(1234) has pid=1234, process_name=null, device=local"
)

# ── 7. frida_target_local_name ──────────────────────────────────────────────
def check_target_name(actual):
    exp = ref_frida_target_local_name("chrome")
    if not isinstance(actual, dict):
        return False, f"expected dict, got {type(actual)}"
    errors = []
    if actual.get("pid") != exp["pid"]:
        errors.append(f"pid: expected={exp['pid']}, got={actual.get('pid')}")
    if actual.get("process_name") != exp["process_name"]:
        errors.append(f"process_name: expected={exp['process_name']!r}, got={actual.get('process_name')!r}")
    if actual.get("device") != exp["device"]:
        errors.append(f"device: expected={exp['device']!r}, got={actual.get('device')!r}")
    if errors:
        return False, "; ".join(errors)
    return True, f"pid=None, process_name='chrome', device=local"

run_test(
    "frida_target_local_name", {"name": "chrome"},
    check_target_name,
    "FridaTarget::local_name('chrome') has pid=null, process_name='chrome', device=local"
)

# ── 8. frida_manager_attach_detach ──────────────────────────────────────────
def check_attach_detach(actual):
    if not isinstance(actual, dict):
        return False, f"expected dict, got {type(actual)}"
    errors = []
    # session_id is alloc_id() starting at 1 — new manager each call, so id=1
    if actual.get("session_id") != 1:
        errors.append(f"session_id: expected=1, got={actual.get('session_id')}")
    if actual.get("attached") is not True:
        errors.append(f"attached: expected=True, got={actual.get('attached')}")
    if actual.get("count_after_attach") != 1:
        errors.append(f"count_after_attach: expected=1, got={actual.get('count_after_attach')}")
    if actual.get("count_after_detach") != 0:
        errors.append(f"count_after_detach: expected=0, got={actual.get('count_after_detach')}")
    if errors:
        return False, "; ".join(errors)
    return True, "attach→detach cycle counters correct"

run_test(
    "frida_manager_attach_detach", {"pid": 42},
    check_attach_detach,
    "FridaManager attach+detach lifecycle: session_id=1, counts 1→0"
)

# ── 9. frida_manager_add_interceptor ────────────────────────────────────────
def check_add_interceptor(actual):
    if not isinstance(actual, dict):
        return False, f"expected dict, got {type(actual)}"
    got = actual.get("interceptor_count")
    if got == 1:
        return True, f"interceptor_count=1 as expected=1"
    return False, f"expected=1, got={got}"

run_test(
    "frida_manager_add_interceptor", {"address": 0xDEADBEEF, "id": 7},
    check_add_interceptor,
    "add_interceptor adds exactly one rule → interceptor_count=1"
)

# ── 10. frida_stalker_event_display — call ──────────────────────────────────
def check_stalker_call(actual):
    exp = ref_stalker_event_display("call", 0x1000, 0x2000)
    got = actual.get("display") if isinstance(actual, dict) else None
    if got == exp:
        return True, f"display={got!r} matches expected={exp!r}"
    return False, f"expected={exp!r}, got={got!r}"

run_test(
    "frida_stalker_event_display", {"kind": "call", "a": 0x1000, "b": 0x2000},
    check_stalker_call,
    "StalkerEvent::Call{0x1000→0x2000} display"
)

# ── 11. frida_stalker_event_display — block ─────────────────────────────────
def check_stalker_block(actual):
    exp = ref_stalker_event_display("block", 0x3000, 0x3020)
    got = actual.get("display") if isinstance(actual, dict) else None
    if got == exp:
        return True, f"display={got!r} matches expected={exp!r}"
    return False, f"expected={exp!r}, got={got!r}"

run_test(
    "frida_stalker_event_display", {"kind": "block", "a": 0x3000, "b": 0x3020},
    check_stalker_block,
    "StalkerEvent::Block{0x3000..0x3020} display"
)

# ── 12. frida_stalker_event_display — compile ───────────────────────────────
def check_stalker_compile(actual):
    exp = ref_stalker_event_display("compile", 0x4000)
    got = actual.get("display") if isinstance(actual, dict) else None
    if got == exp:
        return True, f"display={got!r} matches expected={exp!r}"
    return False, f"expected={exp!r}, got={got!r}"

run_test(
    "frida_stalker_event_display", {"kind": "compile", "a": 0x4000},
    check_stalker_compile,
    "StalkerEvent::Compile(0x4000) display"
)

# ── 13. frida_session_script_count ──────────────────────────────────────────
def check_session_script_count(actual):
    if not isinstance(actual, dict):
        return False, f"expected dict, got {type(actual)}"
    errors = []
    # Default: id=1 (unwrap_or(1)), attached=false (unwrap_or(false)), scripts=0
    if actual.get("id") != 1:
        errors.append(f"id: expected=1, got={actual.get('id')}")
    if actual.get("attached") is not False:
        errors.append(f"attached: expected=False, got={actual.get('attached')}")
    if actual.get("script_count") != 0:
        errors.append(f"script_count: expected=0, got={actual.get('script_count')}")
    if errors:
        return False, "; ".join(errors)
    return True, "FridaSession defaults: id=1, attached=false, script_count=0"

run_test(
    "frida_session_script_count", {},
    check_session_script_count,
    "FridaSession default construction: id=1, not attached, 0 scripts"
)

# ── 14. frida_mock_stalker_events (count=0) — edge case ────────────────────
def check_mock_stalker_0(actual):
    if not isinstance(actual, dict):
        return False, f"expected dict, got {type(actual)}"
    got_count = actual.get("count")
    got_events = actual.get("events", [])
    if got_count != 0:
        return False, f"expected count=0, got={got_count}"
    if got_events != []:
        return False, f"expected empty events, got={got_events}"
    return True, "count=0 → empty events list"

run_test(
    "frida_mock_stalker_events", {"count": 0},
    check_mock_stalker_0,
    "mock_stalker_events(0): empty list"
)

# ── 15. frida_mock_stalker_events (count=3) — all variants ─────────────────
def check_mock_stalker_3(actual):
    if not isinstance(actual, dict):
        return False, f"expected dict, got {type(actual)}"
    got_events = actual.get("events", [])
    exp_events = ref_mock_stalker_events(3)
    if got_events != exp_events:
        return False, (f"expected={exp_events}, got={got_events}")
    return True, f"count=3 events={got_events} match expected={exp_events}"

run_test(
    "frida_mock_stalker_events", {"count": 3},
    check_mock_stalker_3,
    "mock_stalker_events(3): covers Call/Block/Compile variants"
)

# ── Shut down ────────────────────────────────────────────────────────────────
try:
    p.stdin.close()
    p.terminate()
    p.wait(timeout=5)
except Exception:
    pass

# ── Summarise ────────────────────────────────────────────────────────────────
passed = [r for r in results if r["status"] == "PASS"]
failed = [r for r in results if r["status"] == "FAIL"]

print(f"\n=== Frida rigorous validation ===")
print(f"  PASS:  {len(passed)}")
print(f"  FAIL:  {len(failed)}")
print(f"  SKIP:  {len(skipped)}")
if failed:
    print("\nFailed tests:")
    for r in failed:
        print(f"  {r['tool']}: {r.get('detail', r.get('actual', '?'))[:120]}")

with open(OUT_PASS, "w") as f:
    json.dump(results, f, indent=2)
with open(OUT_SKIP, "w") as f:
    json.dump(skipped, f, indent=2)

print(f"\nResults written to {OUT_PASS}")
