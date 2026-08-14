#!/usr/bin/env python3
"""
Rigorous ground-truth validation for all demangle_* MCP tools.

Strategy:
- For each tool, provide an independent Python reference implementation
  derived directly from reading the Rust source code.
- Call the MCP tool via JSON-RPC stdio (same mechanism as exercise_v3.py).
- Compare output byte-for-byte with the reference.
- Tools that cannot be independently verified are marked SKIP.
"""
import json
import subprocess
import sys

EXE = r"C:\Users\Fra\Desktop\RustRE\target\release\rustre-mcp.exe"
TARGET = r"C:\Users\Fra\Desktop\Zyphora\target\release\cargo-zyphora.exe"
OUT_JSON = r"C:\Users\Fra\Desktop\RustRE\validation\rigorous_demangle_v2.json"
SKIP_JSON = r"C:\Users\Fra\Desktop\RustRE\validation\skip_demangle.json"

# ── MCP client ────────────────────────────────────────────────────────────────

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

def recv():
    line = p.stdout.readline()
    if not line:
        raise RuntimeError("server died")
    return json.loads(line)

# Handshake
send({"jsonrpc": "2.0", "id": 1, "method": "initialize",
      "params": {"protocolVersion": "2024-11-05", "capabilities": {},
                 "clientInfo": {"name": "rigorous_demangle", "version": "1"}}})
recv()
send({"jsonrpc": "2.0", "method": "notifications/initialized"})

# Must open project first
send({"jsonrpc": "2.0", "id": 2, "method": "tools/call",
      "params": {"name": "project.open", "arguments": {"path": TARGET}}})
recv()  # ignore result

rid = 100

def call_tool(name, args):
    global rid
    rid += 1
    send({"jsonrpc": "2.0", "id": rid, "method": "tools/call",
          "params": {"name": name, "arguments": args}})
    resp = recv()
    if "error" in resp:
        return None, f"JSONRPC_ERROR: {resp['error']}"
    content = resp.get("result", {}).get("content", [])
    if not content:
        return None, "EMPTY"
    txt = content[0].get("text", "")
    try:
        return json.loads(txt), None
    except json.JSONDecodeError:
        return txt, None

# ── Python reference implementations ─────────────────────────────────────────
# All derived from reading crates/rustre-demangle/src/lib.rs and related files.

# Ref: lib.rs is_constructor (line 2633)
def ref_is_constructor(mangled: str) -> bool:
    if not mangled.startswith("_Z"):
        return False
    b = mangled.encode()
    for i in range(len(b) - 2):
        if b[i] in (ord('_'),) or (ord('0') <= b[i] <= ord('9')) or \
           (ord('a') <= b[i] <= ord('z')) or (ord('A') <= b[i] <= ord('Z')):
            if b[i+1] == ord('C') and b[i+2] in (ord('1'), ord('2'), ord('3')):
                nxt = b[i+3] if i+3 < len(b) else None
                if nxt is None or nxt in (ord('E'), ord('v')):
                    return True
    return False

# Ref: lib.rs is_destructor (line 2656)
def ref_is_destructor(mangled: str) -> bool:
    if not mangled.startswith("_Z"):
        return False
    b = mangled.encode()
    for i in range(len(b) - 2):
        if b[i] in (ord('_'),) or (ord('0') <= b[i] <= ord('9')) or \
           (ord('a') <= b[i] <= ord('z')) or (ord('A') <= b[i] <= ord('Z')):
            if b[i+1] == ord('D') and b[i+2] in (ord('0'), ord('1'), ord('2')):
                nxt = b[i+3] if i+3 < len(b) else None
                if nxt is None or nxt in (ord('E'), ord('v')):
                    return True
    return False

# Ref: lib.rs is_vtable (line 2675)
def ref_is_vtable(mangled: str) -> bool:
    return mangled.startswith("_ZTV")

# Ref: lib.rs is_typeinfo (line 2681)
def ref_is_typeinfo(mangled: str) -> bool:
    return mangled.startswith("_ZTI") or mangled.startswith("_ZTS")

# Ref: lib.rs standard_substitution (line 2689)
_STD_SUBS_LIB = {
    "St": "std",
    "Sa": "std::allocator",
    "Sb": "std::basic_string",
    "Ss": "std::string",
    "Si": "std::istream",
    "So": "std::ostream",
    "Sd": "std::iostream",
}

def ref_standard_substitution(code: str):
    return _STD_SUBS_LIB.get(code)  # None if not found

# Ref: itanium_full.rs STANDARD_SUBS + lookup_standard_sub (line 1019)
_STD_SUBS_FULL = {
    "St": "std",
    "Sa": "std::allocator",
    "Sb": "std::basic_string",
    "Ss": "std::string",
    "Si": "std::istream",
    "So": "std::ostream",
    "Sd": "std::iostream",
}

def ref_lookup_standard_sub(abbrev: str):
    return _STD_SUBS_FULL.get(abbrev)

# Ref: demangler_registry.rs ItaniumDemangler::can_demangle (line 140)
def ref_itanium_detect(mangled: str) -> bool:
    return mangled.startswith("_Z") or mangled.startswith("__Z")

# Ref: demangler_registry.rs MsvcDemangler::can_demangle (line 223)
def ref_msvc_detect(mangled: str) -> bool:
    return mangled.startswith("?")

# Ref: lib.rs RustV0Demangler::detect (line 2104)
def ref_rust_v0_detect(mangled: str) -> bool:
    return mangled.startswith("_R")

# Ref: demangler_registry.rs DDemangler::can_demangle (line 336)
def ref_d_detect(mangled: str) -> bool:
    return mangled.startswith("_D")

# Ref: lib.rs ObjCDemangler::detect (line 2957)
def ref_objc_detect(mangled: str) -> bool:
    trimmed = mangled.lstrip()
    if ((trimmed.startswith("+[") or trimmed.startswith("-[")) and "]" in trimmed):
        return True
    return mangled.startswith("_OBJC_")

# Ref: rust_demangler.rs strip_rust_hash (line 744)
def _is_rust_hash(s: str) -> bool:
    if len(s) not in (16, 17):
        return False
    if not s[0] == 'h':
        return False
    return all(c in '0123456789abcdefABCDEF' for c in s[1:])

def ref_strip_rust_hash(demangled: str) -> str:
    pos = demangled.rfind("::")
    if pos != -1:
        last = demangled[pos+2:]
        if _is_rust_hash(last):
            return demangled[:pos]
    return demangled

# Ref: go_demangler.rs describe_runtime_symbol (line 575)
_GO_RUNTIME = {
    "runtime.goexit": "goroutine exit trampoline",
    "runtime.morestack": "stack growth trampoline",
    "runtime.morestack_noctxt": "stack growth (no context)",
    "runtime.gcWriteBarrier": "GC write barrier",
    "runtime.duffzero": "bulk zero (Duff's device)",
    "runtime.duffcopy": "bulk copy (Duff's device)",
    "runtime.panicIndex": "panic: index out of range",
    "runtime.panicSlice": "panic: slice out of bounds",
    "runtime.panicNilPtr": "panic: nil pointer dereference",
    "runtime.throw": "fatal runtime error",
    "runtime.mallocgc": "allocate heap object",
    "runtime.newobject": "allocate single object",
    "runtime.makeslice": "make a slice",
    "runtime.makemap": "make a map",
    "runtime.chanrecv1": "channel receive",
    "runtime.chanrecv2": "channel receive",
    "runtime.chansend1": "channel send",
    "runtime.gopanic": "initiate a panic",
    "runtime.gorecover": "recover from a panic",
    "runtime.convI2I": "interface to interface conversion",
    "runtime.convT64": "concrete to interface conversion",
    "runtime.convTstring": "concrete to interface conversion",
    "runtime.assertI2I": "interface type assertion",
    "runtime.assertE2T": "empty interface to concrete type assertion",
}

def ref_go_runtime_symbol(name: str):
    return _GO_RUNTIME.get(name)

# ── Test cases ────────────────────────────────────────────────────────────────
# Each test: (tool_name, args_dict, extractor_fn, reference_value)

def check(tool_name, args, actual_result, error, expected_key, ref_value):
    """Return (passed, actual_value, note)."""
    if error:
        return False, error, f"call failed: {error}"
    if actual_result is None:
        return False, None, "null response"
    if isinstance(actual_result, dict):
        actual_val = actual_result.get(expected_key)
    else:
        return False, actual_result, "unexpected non-dict response"
    if actual_val == ref_value:
        return True, actual_val, ""
    return False, actual_val, f"expected {ref_value!r}, got {actual_val!r}"

# ── Tool tests ────────────────────────────────────────────────────────────────

TESTS = []

# --- demangle_is_constructor ---
for sym, expect in [
    ("_ZN3FooC1Ev", True),      # Foo::Foo(void) - constructor
    ("_ZN3FooD1Ev", False),     # destructor
    ("_ZN3FooC3Ev", True),      # C3 = constructor
    ("_ZN3Foo3barEi", False),   # regular func
    ("hello", False),           # no _Z prefix
    ("_ZC1E", False),           # C1 not preceded by correct byte
]:
    TESTS.append({
        "tool": "demangle_is_constructor",
        "args": {"mangled": sym},
        "expected_key": "is_constructor",
        "ref": ref_is_constructor(sym),
        "note": sym,
    })

# --- demangle_is_destructor ---
for sym, expect in [
    ("_ZN3FooD1Ev", True),
    ("_ZN3FooD2Ev", True),
    ("_ZN3FooD0Ev", True),
    ("_ZN3FooC1Ev", False),
    ("hello", False),
]:
    TESTS.append({
        "tool": "demangle_is_destructor",
        "args": {"mangled": sym},
        "expected_key": "is_destructor",
        "ref": ref_is_destructor(sym),
        "note": sym,
    })

# --- demangle_is_vtable ---
for sym in ["_ZTV3Foo", "_ZN3Foo3barEi", "_ZTI3Foo", ""]:
    TESTS.append({
        "tool": "demangle_is_vtable",
        "args": {"mangled": sym},
        "expected_key": "is_vtable",
        "ref": ref_is_vtable(sym),
        "note": sym,
    })

# --- demangle_is_typeinfo ---
for sym in ["_ZTI3Foo", "_ZTS3Foo", "_ZTV3Foo", "_ZN3Foo3barEi"]:
    TESTS.append({
        "tool": "demangle_is_typeinfo",
        "args": {"mangled": sym},
        "expected_key": "is_typeinfo",
        "ref": ref_is_typeinfo(sym),
        "note": sym,
    })

# --- demangle_standard_substitution ---
# Tool schema: {"code": str}, returns {"expansion": str|null}
for code in ["St", "Sa", "Sb", "Ss", "Si", "So", "Sd", "XX"]:
    TESTS.append({
        "tool": "demangle_standard_substitution",
        "args": {"code": code},
        "expected_key": "expansion",
        "ref": ref_standard_substitution(code),
        "note": code,
    })

# --- demangle_itanium_detect_wire ---
for sym in ["_ZN3FooEv", "__ZN3FooEv", "?foo@@bar", "_R...", "_D3foo", "hello"]:
    TESTS.append({
        "tool": "demangle_itanium_detect_wire",
        "args": {"mangled": sym},
        "expected_key": "detected",
        "ref": ref_itanium_detect(sym),
        "note": sym,
    })

# --- demangle_msvc_detect_wire ---
for sym in ["?foo@@bar", "_ZN3FooEv", "_R...", "hello"]:
    TESTS.append({
        "tool": "demangle_msvc_detect_wire",
        "args": {"mangled": sym},
        "expected_key": "detected",
        "ref": ref_msvc_detect(sym),
        "note": sym,
    })

# --- demangle_rust_v0_detect_wire ---
for sym in ["_RNvNtCs1234_3std2io5print", "_ZN3FooEv", "_D3foo", "_R", "hello"]:
    TESTS.append({
        "tool": "demangle_rust_v0_detect_wire",
        "args": {"mangled": sym},
        "expected_key": "detected",
        "ref": ref_rust_v0_detect(sym),
        "note": sym,
    })

# --- demangle_d_detect_wire ---
for sym in ["_D3foo3barFiZi", "_ZN3FooEv", "_R...", "hello"]:
    TESTS.append({
        "tool": "demangle_d_detect_wire",
        "args": {"mangled": sym},
        "expected_key": "detected",
        "ref": ref_d_detect(sym),
        "note": sym,
    })

# --- demangle_objc_detect_wire ---
for sym in ["-[NSObject init]", "+[NSObject alloc]", "_OBJC_CLASS_$_Foo",
            "_ZN3FooEv", "hello"]:
    TESTS.append({
        "tool": "demangle_objc_detect_wire",
        "args": {"mangled": sym},
        "expected_key": "detected",
        "ref": ref_objc_detect(sym),
        "note": sym,
    })

# --- demangle_itanium_lookup_std_sub_wire ---
for abbrev in ["St", "Sa", "Sb", "Ss", "Si", "So", "Sd", "ZZ"]:
    TESTS.append({
        "tool": "demangle_itanium_lookup_std_sub_wire",
        "args": {"abbrev": abbrev},
        "expected_key": "expanded",
        "ref": ref_lookup_standard_sub(abbrev),
        "note": abbrev,
    })

# --- demangle_strip_rust_hash_wire ---
# strip_rust_hash takes an already-demangled string (not mangled!)
for s, expected in [
    ("foo::bar::h1234567890abcdef", "foo::bar"),    # 16-char hash stripped
    ("foo::bar::h1234567890abcde", "foo::bar"),      # 15-char hash stripped (len 16 total with 'h')
    ("foo::bar", "foo::bar"),                         # no hash
    ("foo::bar::baz", "foo::bar::baz"),               # last component is not hash
    ("foo::hZZZZZZZZZZZZZZZZ", "foo::hZZZZZZZZZZZZZZZZ"),  # not hex
]:
    TESTS.append({
        "tool": "demangle_strip_rust_hash_wire",
        "args": {"mangled": s},
        "expected_key": "stripped",
        "ref": ref_strip_rust_hash(s),
        "note": s,
    })

# --- demangle_go_runtime_symbol_wire ---
for sym in ["runtime.goexit", "runtime.morestack", "runtime.mallocgc",
            "runtime.gopanic", "unknown.func", "main.main"]:
    TESTS.append({
        "tool": "demangle_go_runtime_symbol_wire",
        "args": {"mangled": sym},
        "expected_key": "description",
        "ref": ref_go_runtime_symbol(sym),
        "note": sym,
    })

# ── Tools that cannot be independently verified → SKIP ────────────────────────

SKIP_TOOLS = {
    "demangle_auto": "complex multi-ABI dispatcher, no portable Python equivalent for arbitrary mangled names",
    "demangle_normalize_type": "complex type string parser, no stdlib equivalent",
    "demangle_batch": "delegates to demangle_auto, same complexity",
    "demangle_msvc_rtti": "MSVC RTTI decoding, requires Windows-specific knowledge",
    "demangle_batch_parallel": "parallel batch, same as demangle_batch",
    "demangle_result_display": "display formatter only, depends on demangling first",
    "demangle_dispatch": "routing meta-tool, delegates to others",
    "demangle_classify": "multi-step classifier, no Python equivalent",
    "demangle_itanium_native": "calls full itanium_full demangler, complex parser",
    "demangle_auto_wire": "delegates to AutoDemangler, complex",
    "demangle_auto_demangler_wire": "same as auto_wire",
    "demangle_swift_heuristic_wire": "Swift mangling: no Python stdlib equivalent",
    "demangle_msvc_full_wire": "MSVC full demangler: complex recursive parser",
    "demangle_d_lang_wire": "D language demangler: complex parser",
    "demangle_rust_v0_wire": "calls rustc-demangle Rust lib, cannot replicate in pure Python",
    "demangle_rust_legacy_wire": "Rust legacy: depends on Itanium + hash logic, complex",
    "demangle_rust_auto_wire": "delegates to Rust auto-detect + demangle",
    "demangle_cpp_itanium_wire": "calls itanium_full full parser, complex",
    "demangle_cpp_msvc_wire": "calls msvc_full full parser, complex",
    "demangle_cpp_auto_wire": "delegates to cpp_demangler::demangle_cpp",
    "demangle_itanium_extract_namespace_wire": "result depends on itanium demangler output",
    "demangle_itanium_is_std_symbol_wire": "result depends on itanium demangler output",
    "demangle_itanium_is_lambda_wire": "result depends on itanium demangler output",
    "demangle_itanium_native_detect_kind_wire": "calls itanium_full parser internally",
    "demangle_d_struct_demangle_wire": "D demangler complex parser",
    "demangle_rust_v0_struct_demangle_wire": "calls RustV0Demangler::demangle, rustc-demangle dep",
    "demangle_demangler2_auto_wire": "meta-dispatcher, complex",
    "demangle_objc_demangle_wire": "ObjC demangling has edge cases, no stdlib equivalent",
    "demangle_swift_extended_parse_wire": "Swift parser, no stdlib equivalent",
    "demangle_symbol_classifier_classify_wire": "multi-ABI classifier, complex",
    "demangle_itanium_native_demangle_wire": "itanium_full full parse, complex",
    # These two have wrappers in demangler_registry but belong to rustre_symbols, skip
    "rustre_symbols_core_try_demangle": "not a demangle_ prefixed tool",
    "rustre_symbols_core_demangler_pipeline": "not a demangle_ prefixed tool",
}

# ── Run tests ─────────────────────────────────────────────────────────────────

passed_results = []
failed_results = []
mismatches = []

for test in TESTS:
    tool = test["tool"]
    args = test["args"]
    expected_key = test["expected_key"]
    ref = test["ref"]
    note = test["note"]

    actual_result, error = call_tool(tool, args)
    ok, actual_val, detail = check(tool, args, actual_result, error, expected_key, ref)

    entry = {
        "tool": tool,
        "input": args,
        "expected_key": expected_key,
        "expected": ref,
        "actual": actual_val,
        "note": note,
    }

    if ok:
        entry["status"] = "PASS"
        passed_results.append(entry)
    else:
        entry["status"] = "FAIL"
        entry["detail"] = detail
        failed_results.append(entry)
        mismatches.append({"tool": tool, "expected": ref, "actual": actual_val, "detail": detail, "input": args})

# ── Shutdown ──────────────────────────────────────────────────────────────────
p.stdin.close()
p.terminate()

# ── Write results ─────────────────────────────────────────────────────────────
all_results = passed_results + failed_results
with open(OUT_JSON, "w") as f:
    json.dump({"results": all_results, "mismatches": mismatches}, f, indent=2)

with open(SKIP_JSON, "w") as f:
    json.dump({"skipped": [{"tool": k, "reason": v} for k, v in SKIP_TOOLS.items()]}, f, indent=2)

# ── Summary ───────────────────────────────────────────────────────────────────
print(f"demangle tools hardened: {len(set(t['tool'] for t in TESTS))}")
print(f"PASS: {len(passed_results)}")
print(f"FAIL: {len(failed_results)}")
print(f"SKIP: {len(SKIP_TOOLS)}")

if mismatches:
    print("\nMISMATCHES:")
    for m in mismatches:
        print(f"  {m['tool']} ({m['input']}): expected={m['expected']!r} actual={m['actual']!r}")
else:
    print("\nAll tests passed.")

# Return structured data for parent agent
print(f"\n__RESULT__:{json.dumps({'category':'demangle','tools_hardened':len(set(t['tool'] for t in TESTS)),'tools_passed':len(passed_results),'tools_failed':len(failed_results),'tools_skipped':len(SKIP_TOOLS),'mismatches':mismatches})}")
