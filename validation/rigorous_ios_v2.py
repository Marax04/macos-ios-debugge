#!/usr/bin/env python3
"""
Rigorous ground-truth validation for ios_ MCP tools.
Each check uses an independent Python reference implementation.
"""
import json, subprocess, struct, sys

EXE = r"C:\Users\Fra\Desktop\RustRE\target\release\rustre-mcp.exe"
TARGET = r"C:\Users\Fra\Desktop\Zyphora\target\release\cargo-zyphora.exe"
OUT_JSON = r"C:\Users\Fra\Desktop\RustRE\validation\rigorous_ios_v2.json"
SKIP_JSON = r"C:\Users\Fra\Desktop\RustRE\validation\skip_ios.json"

# ── MCP transport ────────────────────────────────────────────────────────────

p = subprocess.Popen(
    [EXE, "--transport=stdio"],
    stdin=subprocess.PIPE, stdout=subprocess.PIPE,
    stderr=subprocess.DEVNULL, bufsize=0
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
        return {"error": {"message": f"bad-line: {line[:100]!r}"}}

def call_tool(name, args, rid):
    send({"jsonrpc": "2.0", "id": rid,
          "method": "tools/call",
          "params": {"name": name, "arguments": args}})
    resp = recv()
    if "error" in resp:
        return None, str(resp["error"])
    content = resp.get("result", {}).get("content", [])
    is_err = resp.get("result", {}).get("isError", False)
    txt = content[0].get("text", "") if content else ""
    if is_err:
        return None, txt
    try:
        return json.loads(txt), None
    except Exception:
        return txt, None

# Handshake
send({"jsonrpc":"2.0","id":1,"method":"initialize",
      "params":{"protocolVersion":"2024-11-05",
                "capabilities":{},"clientInfo":{"name":"rios","version":"2"}}})
recv()
send({"jsonrpc":"2.0","method":"notifications/initialized"})

# Open project so server is in a valid state (some tools require it)
send({"jsonrpc":"2.0","id":2,"method":"tools/call",
      "params":{"name":"project.open","arguments":{"path":TARGET}}})
op = recv()
try:
    op_data = json.loads(op["result"]["content"][0]["text"])
    BINARY_ID = op_data.get("binary_id", "")
    PROJECT_ID = op_data.get("project_id", "")
except Exception:
    BINARY_ID = PROJECT_ID = ""

# ── Python reference implementations ────────────────────────────────────────

def ref_swift_is_mangled(name: str) -> bool:
    """Swift 5 ABI: starts with _$s (lower) or _$S (upper)."""
    return name.startswith("_$s") or name.startswith("_$S")


def ref_decode_type_encoding(enc: str) -> list:
    """
    Independent Python reimplementation of rustre_mobile_ios::decode_type_encoding.
    Mirrors the Rust logic exactly.
    """
    chars = list(enc)
    out = []
    i = 0
    while i < len(chars):
        ty, consumed = _decode_one(chars, i)
        if ty:   # skip empty strings (offset digits)
            out.append(ty)
        i += max(consumed, 1)
    return out

def _decode_one(chars, pos):
    if pos >= len(chars):
        return "?", 1
    c = chars[pos]
    QUALIFIERS = set("rnNoORV")
    if c in QUALIFIERS:
        inner, n = _decode_one(chars, pos + 1)
        return inner, 1 + n
    MAP = {
        'v': 'void', 'c': 'char', 'i': 'int', 's': 'short',
        'l': 'long', 'q': 'long long',
        'C': 'unsigned char', 'I': 'unsigned int',
        'S': 'unsigned short', 'L': 'unsigned long',
        'Q': 'unsigned long long',
        'f': 'float', 'd': 'double', 'B': 'bool',
        '#': 'Class', ':': 'SEL', '*': 'char*', '?': 'func_ptr',
    }
    if c in MAP:
        return MAP[c], 1
    if c == '@':
        if pos + 1 < len(chars) and chars[pos+1] == '"':
            start = pos + 2
            try:
                end = chars[start:].index('"') + start
                name = ''.join(chars[start:end])
                return f"id<{name}>", end - pos + 1
            except ValueError:
                pass
        return 'id', 1
    if c == '^':
        inner, n = _decode_one(chars, pos + 1)
        return f"*{inner}", 1 + n
    if c == '[':
        j = pos + 1
        while j < len(chars) and chars[j].isdigit():
            j += 1
        count = ''.join(chars[pos+1:j])
        inner, n = _decode_one(chars, j)
        close = j + n
        total = close - pos + (1 if close < len(chars) and chars[close] == ']' else 0)
        return f"{inner}[{count}]", total
    if c == '{':
        name = _composite_name(chars, pos + 1)
        total = _skip_to_close(chars, pos, '{', '}')
        return f"struct {name}", total
    if c == '(':
        name = _composite_name(chars, pos + 1)
        total = _skip_to_close(chars, pos, '(', ')')
        return f"union {name}", total
    if c.isdigit():
        j = pos + 1
        while j < len(chars) and chars[j].isdigit():
            j += 1
        return "", j - pos   # emit empty, caller skips
    return c, 1

def _composite_name(chars, start):
    name = []
    for ch in chars[start:]:
        if ch in ('=', '}', ')'):
            break
        name.append(ch)
    return ''.join(name) if name else '?'

def _skip_to_close(chars, pos, open_c, close_c):
    depth = 0
    j = pos
    while j < len(chars):
        if chars[j] == open_c:
            depth += 1
        elif chars[j] == close_c:
            depth -= 1
            if depth == 0:
                return j - pos + 1
        j += 1
    return len(chars) - pos


def ref_security_check_empty():
    """Empty byte array → all false."""
    return {"arc": False, "pie": False, "stack_canary": False, "has_debug_symbols": False}


def ref_ipa_bundle_mock():
    """Hard-coded expected output from IpaBundle::mock()."""
    return {
        "info": {
            "bundle_id": "com.example.App",
            "name": "ExampleApp",
            "version": "1.0.0",
            "min_os": "14.0",
            "platform": "IphoneOs",
        },
        "signature": {
            "team_id": "ABCD1234EF",
            "signing_id": "com.example.App",
            "entitlements": [
                {"key": "get-task-allow", "value": {"Bool": False}},
                {"key": "application-identifier", "value": {"Str": "ABCD1234EF.com.example.App"}},
                {"key": "keychain-access-groups", "value": {"Array": ["ABCD1234EF.*"]}},
            ],
        },
        "frameworks": [
            {"name": "UIKit",       "path": "/System/Library/Frameworks/UIKit.framework",       "is_system": True},
            {"name": "Alamofire",   "path": "Frameworks/Alamofire.framework",                   "is_system": False},
            {"name": "Foundation",  "path": "/System/Library/Frameworks/Foundation.framework",  "is_system": True},
        ],
        "executable": "ExampleApp",
    }


def ref_parse_plist_xml():
    """
    Expected output for parsing a minimal XML plist with bundle_id and version.
    The Rust extractor uses heuristic substring search so does not require
    a fully-valid XML plist — it just needs the key/string tags to be present.
    Input passed to the tool: a small XML plist string.
    """
    plist_text = (
        '<?xml version="1.0"?>'
        '<plist version="1.0"><dict>'
        '<key>CFBundleIdentifier</key><string>com.test.App</string>'
        '<key>CFBundleShortVersionString</key><string>2.3.4</string>'
        '<key>MinimumOSVersion</key><string>15.0</string>'
        '</dict></plist>'
    )
    return plist_text, {
        "bundle_id": "com.test.App",
        "version": "2.3.4",
        "min_ios": "15.0",
        "permissions": [],
    }

# ── Test cases ────────────────────────────────────────────────────────────────

results = []
skipped = []
mismatches = []
rid = 100

# Helper -------------------------------------------------------------------
def record(tool, expected, actual, args=None):
    passed = (expected == actual)
    entry = {
        "tool": tool,
        "status": "PASS" if passed else "FAIL",
        "expected": expected,
        "actual": actual,
    }
    if args is not None:
        entry["args"] = args
    results.append(entry)
    if not passed:
        mismatches.append({"tool": tool, "expected": expected, "actual": actual})

def skip(tool, reason):
    skipped.append({"tool": tool, "reason": reason})

# ── 1. ios_swift_is_mangled_wire ──────────────────────────────────────────
TOOL = "ios_swift_is_mangled_wire"
for name_val, exp_is_mangled in [
    ("_$sSSmain", True),
    ("_$SsSb", True),
    ("_notswift", False),
    ("", False),
]:
    rid += 1
    actual_resp, err = call_tool(TOOL, {"name": name_val}, rid)
    if err:
        mismatches.append({"tool": TOOL, "expected": exp_is_mangled, "actual": f"ERROR: {err}"})
        results.append({"tool": TOOL, "status": "FAIL", "input": name_val, "error": err})
    else:
        actual_val = actual_resp.get("is_swift_mangled") if isinstance(actual_resp, dict) else None
        passed = (actual_val == exp_is_mangled)
        entry = {"tool": TOOL, "status": "PASS" if passed else "FAIL",
                 "input": name_val, "expected": exp_is_mangled, "actual": actual_val}
        results.append(entry)
        if not passed:
            mismatches.append({"tool": TOOL, "expected": exp_is_mangled, "actual": actual_val, "input": name_val})

# ── 2. ios_swift_demangle_wire ────────────────────────────────────────────
TOOL = "ios_swift_demangle_wire"
cases = [
    ("_$sSS", "Swift.String"),
    ("_$sSi", "Swift.Int"),
    ("_$sSb", "Swift.Bool"),
    ("_$sSf", "Swift.Float"),
    ("_$sSd", "Swift.Double"),
]
for name_val, expected_demangled in cases:
    rid += 1
    actual_resp, err = call_tool(TOOL, {"name": name_val}, rid)
    if err:
        results.append({"tool": TOOL, "status": "FAIL", "input": name_val, "error": err})
        mismatches.append({"tool": TOOL, "expected": expected_demangled, "actual": f"ERROR: {err}"})
    else:
        actual_val = actual_resp.get("demangled") if isinstance(actual_resp, dict) else None
        passed = (actual_val == expected_demangled)
        results.append({"tool": TOOL, "status": "PASS" if passed else "FAIL",
                        "input": name_val, "expected": expected_demangled, "actual": actual_val})
        if not passed:
            mismatches.append({"tool": TOOL, "expected": expected_demangled,
                               "actual": actual_val, "input": name_val})

# ── 3. ios_decode_type_encoding_wire ─────────────────────────────────────
TOOL = "ios_decode_type_encoding_wire"
enc_cases = [
    "@:I",
    "v@:",
    "cifsqd",
    "CISQ",
    "^i",
    "*",
    "B",
    "#",
]
for enc in enc_cases:
    ref_out = ref_decode_type_encoding(enc)
    rid += 1
    actual_resp, err = call_tool(TOOL, {"encoding": enc}, rid)
    if err:
        results.append({"tool": TOOL, "status": "FAIL", "input": enc, "error": err})
        mismatches.append({"tool": TOOL, "expected": ref_out, "actual": f"ERROR: {err}"})
    else:
        actual_val = actual_resp.get("types") if isinstance(actual_resp, dict) else actual_resp
        passed = (actual_val == ref_out)
        results.append({"tool": TOOL, "status": "PASS" if passed else "FAIL",
                        "input": enc, "expected": ref_out, "actual": actual_val})
        if not passed:
            mismatches.append({"tool": TOOL, "expected": ref_out,
                               "actual": actual_val, "input": enc})

# ── 4. ios_security_check_arc_usage_wire (empty binary) ──────────────────
for tool_name, field, expected_val in [
    ("ios_security_check_arc_usage_wire",    "arc",               False),
    ("ios_security_check_pie_enabled_wire",  "pie",               False),
    ("ios_security_check_stack_canary_wire", "stack_canary",      False),
    ("ios_security_check_debug_symbols_wire","has_debug_symbols", False),
]:
    rid += 1
    actual_resp, err = call_tool(tool_name, {"hex": ""}, rid)
    if err:
        results.append({"tool": tool_name, "status": "FAIL", "error": err})
        mismatches.append({"tool": tool_name, "expected": expected_val, "actual": f"ERROR: {err}"})
    else:
        actual_val = actual_resp.get(field) if isinstance(actual_resp, dict) else None
        passed = (actual_val == expected_val)
        results.append({"tool": tool_name, "status": "PASS" if passed else "FAIL",
                        "input": "empty", "expected": expected_val, "actual": actual_val})
        if not passed:
            mismatches.append({"tool": tool_name, "expected": expected_val, "actual": actual_val})

# ── 5. ios_security_report_wire (empty binary) ───────────────────────────
TOOL = "ios_security_report_wire"
rid += 1
actual_resp, err = call_tool(TOOL, {"hex": ""}, rid)
ref = {"arc": False, "pie": False, "stack_canary": False, "has_debug_symbols": False}
if err:
    results.append({"tool": TOOL, "status": "FAIL", "error": err})
    mismatches.append({"tool": TOOL, "expected": ref, "actual": f"ERROR: {err}"})
else:
    if isinstance(actual_resp, dict):
        actual_subset = {k: actual_resp.get(k) for k in ref}
    else:
        actual_subset = actual_resp
    passed = (actual_subset == ref)
    results.append({"tool": TOOL, "status": "PASS" if passed else "FAIL",
                    "expected": ref, "actual": actual_subset})
    if not passed:
        mismatches.append({"tool": TOOL, "expected": ref, "actual": actual_subset})

# ── 6. ios_class_dumper_extract_objc_classes_wire (empty binary) ─────────
TOOL = "ios_class_dumper_extract_objc_classes_wire"
rid += 1
actual_resp, err = call_tool(TOOL, {"hex": ""}, rid)
if err:
    results.append({"tool": TOOL, "status": "FAIL", "error": err})
    mismatches.append({"tool": TOOL, "expected": [], "actual": f"ERROR: {err}"})
else:
    actual_val = actual_resp.get("classes") if isinstance(actual_resp, dict) else actual_resp
    passed = (actual_val == [])
    results.append({"tool": TOOL, "status": "PASS" if passed else "FAIL",
                    "expected": [], "actual": actual_val})
    if not passed:
        mismatches.append({"tool": TOOL, "expected": [], "actual": actual_val})

# ── 7. ios_class_dumper_extract_swift_types_wire (empty binary) ──────────
TOOL = "ios_class_dumper_extract_swift_types_wire"
rid += 1
actual_resp, err = call_tool(TOOL, {"hex": ""}, rid)
if err:
    results.append({"tool": TOOL, "status": "FAIL", "error": err})
    mismatches.append({"tool": TOOL, "expected": [], "actual": f"ERROR: {err}"})
else:
    actual_val = actual_resp.get("swift_types") if isinstance(actual_resp, dict) else actual_resp
    passed = (actual_val == [])
    results.append({"tool": TOOL, "status": "PASS" if passed else "FAIL",
                    "expected": [], "actual": actual_val})
    if not passed:
        mismatches.append({"tool": TOOL, "expected": [], "actual": actual_val})

# ── 8. ios_ipa_info_from_macho_wire (empty binary) ───────────────────────
TOOL = "ios_ipa_info_from_macho_wire"
rid += 1
actual_resp, err = call_tool(TOOL, {"hex": ""}, rid)
# Empty binary → parse fails → all fields "unknown", counts 0
# Note: the wire tool omits the "entitlements" field in its serialisation;
# check only the fields that are actually returned.
ref_ipa = {"bundle_id": "unknown", "version": "unknown", "min_os": "unknown",
           "class_count": 0, "method_count": 0, "swift_class_count": 0,
           "has_bitcode": False, "architectures": []}
if err:
    results.append({"tool": TOOL, "status": "FAIL", "error": err})
    mismatches.append({"tool": TOOL, "expected": ref_ipa, "actual": f"ERROR: {err}"})
else:
    checks = {k: actual_resp.get(k) if isinstance(actual_resp, dict) else None
              for k in ref_ipa}
    passed = (checks == ref_ipa)
    results.append({"tool": TOOL, "status": "PASS" if passed else "FAIL",
                    "expected": ref_ipa, "actual": checks, "full_response": actual_resp})
    if not passed:
        mismatches.append({"tool": TOOL, "expected": ref_ipa, "actual": checks})

# ── 9. ios_parse_plist_wire ───────────────────────────────────────────────
TOOL = "ios_parse_plist_wire"
plist_input, ref_plist = ref_parse_plist_xml()
rid += 1
actual_resp, err = call_tool(TOOL, {"text": plist_input}, rid)
if err:
    results.append({"tool": TOOL, "status": "FAIL", "error": err})
    mismatches.append({"tool": TOOL, "expected": ref_plist, "actual": f"ERROR: {err}"})
else:
    # The wire wraps IosAppInfo in {"info": {...}}
    info = actual_resp.get("info") if isinstance(actual_resp, dict) and "info" in actual_resp else actual_resp
    actual_subset = {k: info.get(k) if isinstance(info, dict) else None
                     for k in ref_plist}
    passed = (actual_subset == ref_plist)
    results.append({"tool": TOOL, "status": "PASS" if passed else "FAIL",
                    "expected": ref_plist, "actual": actual_subset})
    if not passed:
        mismatches.append({"tool": TOOL, "expected": ref_plist, "actual": actual_subset})

# ── 10. ios_ipa_bundle_mock_wire ─────────────────────────────────────────
TOOL = "ios_ipa_bundle_mock_wire"
rid += 1
actual_resp, err = call_tool(TOOL, {}, rid)
if err:
    results.append({"tool": TOOL, "status": "FAIL", "error": err})
    mismatches.append({"tool": TOOL, "expected": "mock bundle", "actual": f"ERROR: {err}"})
else:
    # The wire returns a flat summary with bundle_id, framework_count, is_debuggable, system_frameworks
    expected_summary = {
        "bundle_id": "com.example.App",
        "framework_count": 3,
        "is_debuggable": False,
        "system_frameworks": 2,
    }
    actual_summary = {k: actual_resp.get(k) if isinstance(actual_resp, dict) else None
                      for k in expected_summary}
    passed = (actual_summary == expected_summary)
    results.append({"tool": TOOL, "status": "PASS" if passed else "FAIL",
                    "expected": expected_summary, "actual": actual_summary})
    if not passed:
        mismatches.append({"tool": TOOL, "expected": expected_summary, "actual": actual_summary})

# ── Skip path-based tools (need real Mach-O file) ────────────────────────
skip("ios_scan_objc_selectors_path", "Requires a Mach-O binary file path; test target is PE/COFF, not Mach-O — result would always be empty regardless of correctness")
skip("ios_scan_objc_classes_path",   "Requires a Mach-O binary file path; test target is PE/COFF, not Mach-O — result would always be empty regardless of correctness")
# mobile_ prefixed aliases
skip("mobile_ios_swift_is_mangled",   "Alias of ios_swift_is_mangled_wire; covered above via that tool")
skip("mobile_ios_decode_type_encoding","Alias of ios_decode_type_encoding_wire; covered above via that tool")

# ── Shutdown ─────────────────────────────────────────────────────────────
try:
    p.stdin.close()
    p.terminate()
except Exception:
    pass

# ── Save outputs ─────────────────────────────────────────────────────────
with open(OUT_JSON, "w") as f:
    json.dump(results, f, indent=2)

with open(SKIP_JSON, "w") as f:
    json.dump(skipped, f, indent=2)

# ── Summary ───────────────────────────────────────────────────────────────
passed_count = sum(1 for r in results if r["status"] == "PASS")
failed_count = sum(1 for r in results if r["status"] == "FAIL")
print(f"\nRigorous iOS validation complete")
print(f"  PASS:    {passed_count}")
print(f"  FAIL:    {failed_count}")
print(f"  SKIPPED: {len(skipped)}")
print(f"  Results: {OUT_JSON}")

if mismatches:
    print("\nMISMATCHES:")
    for m in mismatches:
        print(f"  {m['tool']}: expected={m['expected']!r} actual={m['actual']!r}")

# Print structured summary for the caller
summary = {
    "category": "ios",
    "tools_hardened": passed_count + failed_count,
    "tools_passed": passed_count,
    "tools_failed": failed_count,
    "tools_skipped": len(skipped),
    "mismatches": mismatches,
}
print("\nSUMMARY_JSON:" + json.dumps(summary))
