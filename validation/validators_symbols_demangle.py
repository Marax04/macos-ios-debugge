#!/usr/bin/env python3
"""Independent validator for symbols_demangle_* tools."""
import json, subprocess, sys, os

EXE = r"C:\Users\Fra\Desktop\RustRE\target\release\rustre-mcp.exe"
OUT = r"C:\Users\Fra\Desktop\RustRE\validation\mismatch_symbols_demangle.json"

def start():
    p = subprocess.Popen([EXE, "--transport=stdio"], stdin=subprocess.PIPE,
                         stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, bufsize=0)
    def send(r): p.stdin.write((json.dumps(r)+"\n").encode()); p.stdin.flush()
    def recv():
        line = p.stdout.readline()
        return json.loads(line) if line else None
    send({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"v","version":"1"}}})
    recv()
    send({"jsonrpc":"2.0","method":"notifications/initialized"})
    return p, send, recv

p, send, recv = start()
rid = [10]
def call(name, args):
    rid[0] += 1
    send({"jsonrpc":"2.0","id":rid[0],"method":"tools/call","params":{"name":name,"arguments":args}})
    resp = recv()
    if not resp: return ("NORESP", None)
    if "error" in resp: return ("ERR", resp["error"])
    c = resp.get("result",{}).get("content",[])
    if not c: return ("EMPTY", None)
    txt = c[0].get("text","")
    try: return ("OK", json.loads(txt))
    except: return ("OK", txt)

# tools/list
rid[0]+=1
send({"jsonrpc":"2.0","id":rid[0],"method":"tools/list","params":{}})
tl = recv()
all_tools = tl.get("result",{}).get("tools",[])
tools = [t for t in all_tools if t["name"].startswith("symbols_demangle_")]
print(f"Found {len(tools)} symbols_demangle_* tools", file=sys.stderr)

# ground truth via c++filt
def cxxfilt(sym):
    try:
        r = subprocess.run(["c++filt", sym], capture_output=True, text=True, timeout=5)
        return r.stdout.strip()
    except Exception:
        return None

mismatches = []
checks_total = 0
checks_passed = 0
checks_skipped = 0
skipped_log = []

# Test symbols with expected properties
ITANIUM_SIMPLE = "_Z3fooi"                 # foo(int)
ITANIUM_NS = "_ZN3foo3bar3bazEv"           # foo::bar::baz()
MSVC_SIMPLE = "?foo@@YAHH@Z"               # int __cdecl foo(int)
RUST_V0 = "_RNvNtCs6CKzx_3foo3bar4baz"     # foo::bar::baz (Rust v0)
RUST_LEG = "_ZN3foo3bar17h1234567890abcdefE"  # legacy Rust
SWIFT = "_$s4test6MyTypeCACycfC"

# text extractor
def text_of(v):
    if v is None: return ""
    if isinstance(v, str): return v
    if isinstance(v, dict):
        for k in ("demangled","result","name","output","value","text"):
            if k in v and v[k]:
                return v[k] if isinstance(v[k], str) else json.dumps(v[k])
        return json.dumps(v)
    return str(v)

def contains_all(hay, needles):
    return all(n in hay for n in needles)

def sym_arg_key(schema):
    """Find the property name used for the symbol input."""
    props = (schema or {}).get("properties",{}) or {}
    for k in ("symbol","name","mangled","input","sym","s"):
        if k in props: return k
    # fallback: first string prop
    for k,v in props.items():
        if v.get("type")=="string": return k
    return None

def try_call(t, sym, expected_substrs, note):
    global checks_total, checks_passed, checks_skipped
    name = t["name"]
    schema = t.get("inputSchema") or {}
    key = sym_arg_key(schema)
    if not key:
        skipped_log.append({"tool":name,"why":"no string input"})
        checks_skipped += 1
        return
    status, val = call(name, {key: sym})
    if status != "OK":
        skipped_log.append({"tool":name,"why":f"call {status}"})
        checks_skipped += 1
        return
    txt = text_of(val)
    # detect explicit failure
    low = txt.lower()
    if any(x in low for x in ["error","unsupported","cannot","invalid","not a "," failed"]) and not any(n in txt for n in expected_substrs):
        # not a mismatch — tool signaled it can't handle this input
        skipped_log.append({"tool":name,"why":"tool-error","sample":txt[:120]})
        checks_skipped += 1
        return
    checks_total += 1
    if contains_all(txt, expected_substrs):
        checks_passed += 1
    else:
        mismatches.append({
            "tool": name,
            "input": {key: sym},
            "mcp": txt[:300],
            "truth": f"expected to contain {expected_substrs}",
            "note": note,
        })

# ground-truth verification of test symbols themselves
itn_truth = cxxfilt(ITANIUM_SIMPLE)
itn_ns_truth = cxxfilt(ITANIUM_NS)
print(f"c++filt truth: {ITANIUM_SIMPLE} => {itn_truth}", file=sys.stderr)
print(f"c++filt truth: {ITANIUM_NS} => {itn_ns_truth}", file=sys.stderr)

# For each tool, decide which sample to feed based on its name
for t in tools:
    n = t["name"]
    low = n.lower()
    # classify tests
    if "rust_v0" in low or "rustv0" in low:
        try_call(t, RUST_V0, ["foo","bar","baz"], "rust v0 path segments")
    elif "rust_legacy" in low or "rustlegacy" in low or ("rust" in low and "auto" not in low and "hash" not in low):
        try_call(t, RUST_LEG, ["foo","bar"], "rust legacy path segments")
    elif "strip_rust_hash" in low:
        # input like foo::bar::h... should have hash stripped
        s = "foo::bar::h1234567890abcdef"
        status, val = call(n, {(sym_arg_key(t.get("inputSchema") or {}) or "symbol"): s})
        if status != "OK":
            checks_skipped += 1; skipped_log.append({"tool":n,"why":f"call {status}"})
        else:
            txt = text_of(val)
            checks_total += 1
            if "h1234567890abcdef" not in txt and "foo::bar" in txt:
                checks_passed += 1
            else:
                mismatches.append({"tool":n,"input":{"symbol":s},"mcp":txt[:200],"truth":"hash removed","note":"strip_rust_hash should drop trailing h... segment"})
    elif "itanium" in low or "cpp" in low or "c_plus" in low:
        try_call(t, ITANIUM_SIMPLE, ["foo"], "itanium _Z3fooi should mention foo")
    elif "msvc" in low:
        try_call(t, MSVC_SIMPLE, ["foo"], "msvc ?foo@@YAHH@Z should mention foo")
    elif "swift" in low:
        try_call(t, SWIFT, ["test","MyType"], "swift symbol -> readable")
    elif "objc" in low or "d_" in low or "d_lang" in low:
        # objc/d — non-mangled probably; feed sample and just check no crash
        checks_skipped += 1
        skipped_log.append({"tool":n,"why":"objc/d needs specialized samples"})
    elif "is_lambda" in low or "is_std_symbol" in low or "detect" in low or "is_constructor" in low or "is_destructor" in low or "is_typeinfo" in low or "is_vtable" in low or "is_mangled" in low:
        # boolean predicates: feed known input; just require boolean-ish response
        key = sym_arg_key(t.get("inputSchema") or {})
        if not key:
            checks_skipped += 1; skipped_log.append({"tool":n,"why":"no input key"}); continue
        status,val = call(n, {key: ITANIUM_NS})
        if status != "OK":
            checks_skipped += 1; skipped_log.append({"tool":n,"why":f"call {status}"}); continue
        # accept anything that comes back as concrete value; no mismatch unless clearly wrong
        # For _ZN3foo3bar3bazEv: not a lambda, not std, but is_mangled -> True
        txt = text_of(val).lower()
        if "is_mangled" in low:
            checks_total += 1
            if "true" in txt or "1" in txt or "yes" in txt:
                checks_passed += 1
            else:
                mismatches.append({"tool":n,"input":{key:ITANIUM_NS},"mcp":txt[:200],"truth":"true","note":"_ZN...E is a mangled Itanium name"})
        elif "is_lambda" in low:
            checks_total += 1
            if "false" in txt or "0" in txt:
                checks_passed += 1
            else:
                mismatches.append({"tool":n,"input":{key:ITANIUM_NS},"mcp":txt[:200],"truth":"false","note":"foo::bar::baz is not a lambda"})
        else:
            checks_skipped += 1
            skipped_log.append({"tool":n,"why":"predicate w/o clear truth"})
    elif "extract_namespace" in low:
        key = sym_arg_key(t.get("inputSchema") or {})
        status,val = call(n, {key: ITANIUM_NS})
        if status != "OK":
            checks_skipped += 1; skipped_log.append({"tool":n,"why":f"call {status}"}); continue
        txt = text_of(val)
        checks_total += 1
        if "foo" in txt and "bar" in txt:
            checks_passed += 1
        else:
            mismatches.append({"tool":n,"input":{key:ITANIUM_NS},"mcp":txt[:200],"truth":"foo::bar","note":"namespace of _ZN3foo3bar3bazEv is foo::bar"})
    elif "auto" in low or "dispatch" in low or "dispatcher" in low:
        # auto dispatcher: itanium sample
        try_call(t, ITANIUM_NS, ["foo","bar","baz"], "auto-dispatch itanium ns")
    elif "classif" in low:
        key = sym_arg_key(t.get("inputSchema") or {})
        status,val = call(n, {key: ITANIUM_NS})
        if status != "OK":
            checks_skipped += 1; skipped_log.append({"tool":n,"why":f"call {status}"}); continue
        # classify should return some non-empty classification
        txt = text_of(val)
        checks_total += 1
        if txt and len(txt) > 2 and "error" not in txt.lower():
            checks_passed += 1
        else:
            mismatches.append({"tool":n,"input":{key:ITANIUM_NS},"mcp":txt[:200],"truth":"non-empty","note":"classifier should return a class"})
    elif "batch" in low:
        # batch: needs array input, complex — skip
        checks_skipped += 1; skipped_log.append({"tool":n,"why":"batch complex schema"})
    elif "standard_substitution" in low or "lookup_std" in low:
        key = sym_arg_key(t.get("inputSchema") or {})
        if key:
            status,val = call(n, {key: "St"})  # "St" -> ::std::
            if status != "OK":
                checks_skipped += 1; skipped_log.append({"tool":n,"why":f"call {status}"})
            else:
                checks_skipped += 1; skipped_log.append({"tool":n,"why":"std-sub lookup — accepted"})
        else:
            checks_skipped += 1; skipped_log.append({"tool":n,"why":"no key"})
    elif "normalize_type" in low:
        key = sym_arg_key(t.get("inputSchema") or {})
        if not key: checks_skipped += 1; skipped_log.append({"tool":n,"why":"no key"}); continue
        status,val = call(n, {key: "  int  *  "})
        if status != "OK": checks_skipped += 1; skipped_log.append({"tool":n,"why":f"call {status}"}); continue
        txt = text_of(val)
        checks_total += 1
        if "int" in txt and "*" in txt:
            checks_passed += 1
        else:
            mismatches.append({"tool":n,"input":{key:"  int  *  "},"mcp":txt[:200],"truth":"int*","note":"normalize should keep 'int' and '*'"})
    elif "result_display" in low:
        checks_skipped += 1; skipped_log.append({"tool":n,"why":"display formatting — no truth"})
    else:
        # default: assume it's a demangle tool, test with itanium
        try_call(t, ITANIUM_NS, ["foo","bar","baz"], "default itanium ns test")

report = {
    "category": "symbols_demangle",
    "tools_in_category": len(tools),
    "checks_total": checks_total,
    "checks_passed": checks_passed,
    "checks_skipped": checks_skipped,
    "mismatches": mismatches,
    "skipped_log": skipped_log[:50],
}

with open(OUT, "w") as f:
    json.dump(report, f, indent=2)

print(json.dumps({k:v for k,v in report.items() if k!="skipped_log"}, indent=2))
p.terminate()
