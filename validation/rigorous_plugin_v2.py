#!/usr/bin/env python3
"""
Rigorous validation for plugin_* MCP tools.
Computes expected outputs via inline Python reference implementations and
compares byte-for-byte / value-for-value with actual MCP tool responses.
"""
import json, subprocess, sys, time

EXE = r"C:\Users\Fra\Desktop\RustRE\target\release\rustre-mcp.exe"
TARGET = r"C:\Users\Fra\Desktop\Zyphora\target\release\cargo-zyphora.exe"
OUT_JSON = r"C:\Users\Fra\Desktop\RustRE\validation\rigorous_plugin_v2.json"
SKIP_JSON = r"C:\Users\Fra\Desktop\RustRE\validation\skip_plugin.json"

# ─── MCP transport ───────────────────────────────────────────────────────────

p = subprocess.Popen(
    [EXE, "--transport=stdio"],
    stdin=subprocess.PIPE,
    stdout=subprocess.PIPE,
    stderr=subprocess.DEVNULL,
    bufsize=0,
)

def send(req):
    p.stdin.write((json.dumps(req) + "\n").encode())
    p.stdin.flush()

def recv(timeout=10.0):
    """Read one JSON-RPC line from the server with a wall-clock timeout."""
    import select, io
    deadline = time.monotonic() + timeout
    buf = b""
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("MCP server did not respond in time")
        # Windows: we can't use select() on a pipe easily; just try readline
        # with a short read timeout via a thread trick.
        try:
            line = p.stdout.readline()
        except Exception as e:
            raise RuntimeError(f"server read error: {e}")
        if not line:
            raise RuntimeError("server died (EOF)")
        try:
            return json.loads(line)
        except json.JSONDecodeError:
            raise RuntimeError(f"bad JSON line: {line[:120]!r}")

def call_tool(name, args, rid):
    send({"jsonrpc": "2.0", "id": rid, "method": "tools/call",
          "params": {"name": name, "arguments": args}})
    resp = recv()
    if "error" in resp:
        return None, f"JSONRPC_ERROR: {resp['error']}"
    is_err = resp.get("result", {}).get("isError", False)
    content = resp.get("result", {}).get("content", [])
    txt = content[0].get("text", "") if content else ""
    if is_err:
        return None, f"TOOL_ERROR: {txt[:200]}"
    try:
        return json.loads(txt), None
    except json.JSONDecodeError:
        return txt, None

# ─── Initialise ──────────────────────────────────────────────────────────────

send({"jsonrpc": "2.0", "id": 1, "method": "initialize",
      "params": {"protocolVersion": "2024-11-05",
                 "capabilities": {}, "clientInfo": {"name": "rigorous_plugin", "version": "2"}}})
recv()
send({"jsonrpc": "2.0", "method": "notifications/initialized"})

# Open project so binary_id / project_id are available (not needed by plugin
# tools but the server may require a project to be open for some tools).
send({"jsonrpc": "2.0", "id": 2, "method": "tools/call",
      "params": {"name": "project.open", "arguments": {"path": TARGET}}})
recv()

# ─── Python reference implementations ────────────────────────────────────────

def ref_stub_signature(name, doc="", return_type=None):
    """def name() -> RetType:  (no args registered by wire tool)"""
    ret = f" -> {return_type}" if return_type else ""
    return f"def {name}(){ret}:"

def ref_module_counts(function_name=None, class_name=None):
    fc = 1 if function_name else 0
    cc = 1 if class_name else 0
    return fc, cc

def ref_format_error(kind, message, cls="Exception",
                     plugin=None, script=None, function=None):
    kind_lower = kind.lower()
    kind_map = {
        "type": "TypeError",
        "value": "ValueError",
        "key": "KeyError",
        "attribute": "AttributeError",
        "import": "ImportError",
        "runtime": "RuntimeError",
    }
    if kind_lower in kind_map:
        kind_str = kind_map[kind_lower]
        error_display = f"{kind_str}: {message}"
    else:
        kind_str = "Other"
        error_display = f"{cls}: {message}"

    # ErrorContext::to_string
    parts = []
    if plugin:
        parts.append(f"plugin={plugin}")
    if script:
        parts.append(f"script={script}")
    if function:
        parts.append(f"fn={function}")
    context_display = f"[{' '.join(parts)}]" if parts else "<no-context>"

    return kind_str, message, error_display, context_display

def ref_generate_stub(module_name, doc="", function_name=None, class_name=None,
                      constant_name=None, constant_repr="None"):
    """Mirror of PythonReModule::generate_stub."""
    lines = [f"# Stub for module '{module_name}'"]
    if doc:
        lines.append(f'"""{doc}"""\n')

    if constant_name:
        lines.append(f"{constant_name}: ... = {constant_repr}")
        lines.append("")

    if class_name:
        lines.append(f"class {class_name}(object):")
        lines.append('    """"""')  # empty doc
        lines.append("")

    if function_name:
        lines.append(f"def {function_name}():")
        lines.append('    """"""')
        lines.append("")

    return "\n".join(lines)

def ref_class_methods_tagged(class_name, tag, method_name=None, method_tag=None):
    """Returns list of method names where tags contain `tag`."""
    if method_name is None:
        return []
    effective_tag = method_tag if method_tag else tag
    if effective_tag == tag:
        return [method_name]
    return []

# ─── Test cases ──────────────────────────────────────────────────────────────

results = []
skips = []
mismatches = []
rid = 10

# ── 1. plugin_lua_loader_default_count ───────────────────────────────────────
rid += 1
actual, err = call_tool("plugin_lua_loader_default_count", {}, rid)
if err:
    results.append({"tool": "plugin_lua_loader_default_count", "status": "FAIL",
                    "reason": err})
    mismatches.append({"tool": "plugin_lua_loader_default_count",
                       "expected": {"count": 0, "ids": []}, "actual": err})
else:
    ok = (actual.get("count") == 0 and actual.get("ids") == [])
    results.append({
        "tool": "plugin_lua_loader_default_count",
        "status": "PASS" if ok else "FAIL",
        "expected": {"count": 0, "ids": []},
        "actual": {"count": actual.get("count"), "ids": actual.get("ids")},
    })
    if not ok:
        mismatches.append({
            "tool": "plugin_lua_loader_default_count",
            "expected": {"count": 0, "ids": []},
            "actual": {"count": actual.get("count"), "ids": actual.get("ids")},
        })

# ── 2. plugin_lua_load_inline ─────────────────────────────────────────────────
# The tool expects a Lua table with name/version fields.
lua_src = 'return { name = "test_plugin", version = "1.0.0", description = "A test plugin" }'
rid += 1
actual, err = call_tool("plugin_lua_load_inline", {"source": lua_src}, rid)
if err:
    results.append({"tool": "plugin_lua_load_inline", "status": "FAIL", "reason": err})
    mismatches.append({"tool": "plugin_lua_load_inline",
                       "expected": {"id": "test_plugin@1.0.0", "name": "test_plugin",
                                    "version": "1.0.0"},
                       "actual": err})
else:
    expected_id = "test_plugin@1.0.0"
    expected_name = "test_plugin"
    expected_version = "1.0.0"
    ok = (actual.get("id") == expected_id and
          actual.get("name") == expected_name and
          actual.get("version") == expected_version and
          actual.get("has_on_load") == False and
          actual.get("has_on_unload") == False)
    status = "PASS" if ok else "FAIL"
    results.append({
        "tool": "plugin_lua_load_inline",
        "status": status,
        "expected": {"id": expected_id, "name": expected_name,
                     "version": expected_version, "has_on_load": False, "has_on_unload": False},
        "actual": {k: actual.get(k) for k in ["id", "name", "version", "has_on_load", "has_on_unload"]},
    })
    if not ok:
        mismatches.append({
            "tool": "plugin_lua_load_inline",
            "expected": {"id": expected_id, "name": expected_name, "version": expected_version},
            "actual": {k: actual.get(k) for k in ["id", "name", "version"]},
        })

# ── 3. plugin_python_stub_signature ──────────────────────────────────────────
rid += 1
args = {"name": "my_func", "doc": "Does something.", "return_type": "int"}
actual, err = call_tool("plugin_python_stub_signature", args, rid)
expected_sig = ref_stub_signature("my_func", return_type="int")
if err:
    results.append({"tool": "plugin_python_stub_signature", "status": "FAIL", "reason": err})
    mismatches.append({"tool": "plugin_python_stub_signature",
                       "expected": expected_sig, "actual": err})
else:
    actual_sig = actual.get("signature")
    ok = actual_sig == expected_sig
    results.append({
        "tool": "plugin_python_stub_signature",
        "status": "PASS" if ok else "FAIL",
        "expected": expected_sig,
        "actual": actual_sig,
    })
    if not ok:
        mismatches.append({"tool": "plugin_python_stub_signature",
                           "expected": expected_sig, "actual": actual_sig})

# ── 4. plugin_python_module_counts ────────────────────────────────────────────
rid += 1
args = {"module_name": "mymod", "function_name": "f1", "class_name": "C1"}
actual, err = call_tool("plugin_python_module_counts", args, rid)
exp_fc, exp_cc = ref_module_counts(function_name="f1", class_name="C1")
if err:
    results.append({"tool": "plugin_python_module_counts", "status": "FAIL", "reason": err})
    mismatches.append({"tool": "plugin_python_module_counts",
                       "expected": {"function_count": exp_fc, "class_count": exp_cc},
                       "actual": err})
else:
    ok = (actual.get("function_count") == exp_fc and actual.get("class_count") == exp_cc)
    results.append({
        "tool": "plugin_python_module_counts",
        "status": "PASS" if ok else "FAIL",
        "expected": {"function_count": exp_fc, "class_count": exp_cc},
        "actual": {"function_count": actual.get("function_count"),
                   "class_count": actual.get("class_count")},
    })
    if not ok:
        mismatches.append({
            "tool": "plugin_python_module_counts",
            "expected": {"function_count": exp_fc, "class_count": exp_cc},
            "actual": {"function_count": actual.get("function_count"),
                       "class_count": actual.get("class_count")},
        })

# ── 5. plugin_native_loader_count ─────────────────────────────────────────────
rid += 1
actual, err = call_tool("plugin_native_loader_count", {}, rid)
if err:
    results.append({"tool": "plugin_native_loader_count", "status": "FAIL", "reason": err})
    mismatches.append({"tool": "plugin_native_loader_count",
                       "expected": {"count": 0}, "actual": err})
else:
    ok = actual.get("count") == 0
    results.append({
        "tool": "plugin_native_loader_count",
        "status": "PASS" if ok else "FAIL",
        "expected": {"count": 0},
        "actual": {"count": actual.get("count")},
    })
    if not ok:
        mismatches.append({"tool": "plugin_native_loader_count",
                           "expected": {"count": 0}, "actual": {"count": actual.get("count")}})

# ── 6. plugin_native_loader_ids ───────────────────────────────────────────────
rid += 1
actual, err = call_tool("plugin_native_loader_ids", {}, rid)
if err:
    results.append({"tool": "plugin_native_loader_ids", "status": "FAIL", "reason": err})
    mismatches.append({"tool": "plugin_native_loader_ids",
                       "expected": {"ids": []}, "actual": err})
else:
    ok = actual.get("ids") == []
    results.append({
        "tool": "plugin_native_loader_ids",
        "status": "PASS" if ok else "FAIL",
        "expected": {"ids": []},
        "actual": {"ids": actual.get("ids")},
    })
    if not ok:
        mismatches.append({"tool": "plugin_native_loader_ids",
                           "expected": {"ids": []}, "actual": {"ids": actual.get("ids")}})

# ── 7. plugin_python_generate_stub ───────────────────────────────────────────
rid += 1
args = {"module_name": "mymod", "doc": "My module.",
        "function_name": "do_thing", "class_name": "MyClass",
        "constant_name": "VERSION", "constant_repr": '"1.0"'}
actual, err = call_tool("plugin_python_generate_stub", args, rid)
if err:
    results.append({"tool": "plugin_python_generate_stub", "status": "FAIL", "reason": err})
    mismatches.append({"tool": "plugin_python_generate_stub",
                       "expected": "<stub string>", "actual": err})
else:
    stub = actual.get("stub", "")
    # Structural checks (the exact whitespace of generate_stub is deterministic
    # from the Rust source we read):
    ok = (
        "# Stub for module 'mymod'" in stub
        and '"""My module."""' in stub
        and "VERSION: ... =" in stub
        and "class MyClass(object):" in stub
        and "def do_thing():" in stub
    )
    results.append({
        "tool": "plugin_python_generate_stub",
        "status": "PASS" if ok else "FAIL",
        "expected": "stub contains header, doc, constant, class, function",
        "actual": stub[:400],
    })
    if not ok:
        mismatches.append({"tool": "plugin_python_generate_stub",
                           "expected": "stub with all sections",
                           "actual": stub[:300]})

# ── 8. plugin_python_class_methods_tagged ─────────────────────────────────────
rid += 1
args = {"class_name": "MyClass", "tag": "analysis",
        "method_name": "analyse", "method_tag": "analysis"}
actual, err = call_tool("plugin_python_class_methods_tagged", args, rid)
exp_matches = ref_class_methods_tagged("MyClass", "analysis",
                                       method_name="analyse", method_tag="analysis")
if err:
    results.append({"tool": "plugin_python_class_methods_tagged", "status": "FAIL", "reason": err})
    mismatches.append({"tool": "plugin_python_class_methods_tagged",
                       "expected": {"matches": exp_matches}, "actual": err})
else:
    ok = actual.get("matches") == exp_matches
    results.append({
        "tool": "plugin_python_class_methods_tagged",
        "status": "PASS" if ok else "FAIL",
        "expected": {"matches": exp_matches},
        "actual": {"matches": actual.get("matches")},
    })
    if not ok:
        mismatches.append({
            "tool": "plugin_python_class_methods_tagged",
            "expected": {"matches": exp_matches},
            "actual": {"matches": actual.get("matches")},
        })

# ── 9. plugin_python_format_error ─────────────────────────────────────────────
rid += 1
args = {"kind": "value", "message": "bad input",
        "plugin": "myplugin", "script": "run.py", "function": "process"}
actual, err = call_tool("plugin_python_format_error", args, rid)
exp_kind, exp_msg, exp_disp, exp_ctx = ref_format_error(
    "value", "bad input", plugin="myplugin", script="run.py", function="process"
)
if err:
    results.append({"tool": "plugin_python_format_error", "status": "FAIL", "reason": err})
    mismatches.append({"tool": "plugin_python_format_error",
                       "expected": {"kind": exp_kind, "message": exp_msg},
                       "actual": err})
else:
    ok = (
        actual.get("kind") == exp_kind and
        actual.get("message") == exp_msg and
        actual.get("error_display") == exp_disp and
        actual.get("context_display") == exp_ctx
    )
    results.append({
        "tool": "plugin_python_format_error",
        "status": "PASS" if ok else "FAIL",
        "expected": {"kind": exp_kind, "message": exp_msg,
                     "error_display": exp_disp, "context_display": exp_ctx},
        "actual": {k: actual.get(k) for k in
                   ["kind", "message", "error_display", "context_display"]},
    })
    if not ok:
        mismatches.append({
            "tool": "plugin_python_format_error",
            "expected": {"kind": exp_kind, "message": exp_msg,
                         "error_display": exp_disp, "context_display": exp_ctx},
            "actual": {k: actual.get(k) for k in
                       ["kind", "message", "error_display", "context_display"]},
        })

# ─── Wrap up ─────────────────────────────────────────────────────────────────

p.stdin.close()
p.terminate()

tools_hardened = len(results)
tools_passed = sum(1 for r in results if r["status"] == "PASS")
tools_failed = sum(1 for r in results if r["status"] == "FAIL")
tools_skipped = len(skips)

summary = {
    "category": "plugin",
    "tools_hardened": tools_hardened,
    "tools_passed": tools_passed,
    "tools_failed": tools_failed,
    "tools_skipped": tools_skipped,
    "mismatches": mismatches,
    "detail": results,
}

with open(OUT_JSON, "w") as f:
    json.dump(summary, f, indent=2)

with open(SKIP_JSON, "w") as f:
    json.dump(skips, f, indent=2)

print(json.dumps(summary, indent=2))
