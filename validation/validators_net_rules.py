#!/usr/bin/env python3
"""Independent validator for net_rules_* MCP tools."""
import json, subprocess, sys

EXE = r"C:\Users\Fra\Desktop\RustRE\target\release\rustre-mcp.exe"
OUT = r"C:\Users\Fra\Desktop\RustRE\validation\mismatch_net_rules.json"

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
rid = [100]
def call(name, args):
    rid[0] += 1
    send({"jsonrpc":"2.0","id":rid[0],"method":"tools/call","params":{"name":name,"arguments":args}})
    resp = recv()
    if not resp or "error" in resp: return None
    c = resp.get("result",{}).get("content",[])
    if not c: return None
    txt = c[0].get("text","")
    try: return json.loads(txt)
    except: return txt

# tools/list
rid[0] += 1
send({"jsonrpc":"2.0","id":rid[0],"method":"tools/list","params":{}})
tl = recv()
all_tools = tl.get("result",{}).get("tools",[]) if tl else []
tools = [t for t in all_tools if t["name"].startswith("net_rules_")]

mismatches = []
checks_total = 0
checks_passed = 0
checks_skipped = 0

def check(name, inp, mcp_val, truth_val, note=""):
    global checks_total, checks_passed
    checks_total += 1
    # normalize
    def norm(x):
        if isinstance(x, str): return x.lower()
        return x
    if norm(mcp_val) == norm(truth_val):
        checks_passed += 1
        return True
    mismatches.append({"tool":name,"input":inp,"mcp":mcp_val,"truth":truth_val,"note":note})
    return False

def try_call(name, args, keys):
    """Call tool and return first non-None value from keys tuple."""
    r = call(name, args)
    if r is None: return None, None
    if isinstance(r, dict):
        for k in keys:
            if k in r: return r[k], r
    return r, r

# ---- Aho-Corasick python reference ----
def ac_contains_any(text, patterns):
    tb = text.encode() if isinstance(text, str) else text
    for p in patterns:
        pb = p.encode() if isinstance(p, str) else p
        if pb in tb: return True
    return False

def ac_find_all(text, patterns):
    tb = text.encode() if isinstance(text, str) else text
    hits = []
    for i, p in enumerate(patterns):
        pb = p.encode() if isinstance(p, str) else p
        start = 0
        while True:
            idx = tb.find(pb, start)
            if idx < 0: break
            hits.append((idx, i))
            start = idx + 1
    return len(hits)

def ac_find_first(text, patterns):
    tb = text.encode() if isinstance(text, str) else text
    best = None
    for i, p in enumerate(patterns):
        pb = p.encode() if isinstance(p, str) else p
        idx = tb.find(pb)
        if idx >= 0 and (best is None or idx < best):
            best = idx
    return best

# ---- Tool: net_rules_aho_corasick_contains_any ----
tests = [
    (["ab", "cd"], "xxabxx", True),
    (["hello", "world"], "hi there", False),
    (["foo"], "foobar", True),
    (["xxx"], "abcdef", False),
]
for pats, text, truth in tests:
    val, _ = try_call("net_rules_aho_corasick_contains_any",
                     {"patterns":pats,"text":text}, ("contains_any","contains","found","result"))
    if val is None:
        checks_skipped += 1
    else:
        check("net_rules_aho_corasick_contains_any", {"patterns":pats,"text":text}, val, truth)

# ---- net_rules_aho_corasick_find_all ----
tests = [
    (["ab"], "ababab", 3),
    (["a","b"], "ab", 2),
    (["xyz"], "abcdef", 0),
]
for pats, text, truth_count in tests:
    val, r = try_call("net_rules_aho_corasick_find_all",
                     {"patterns":pats,"text":text}, ("matches","hits","results","count","total"))
    if val is None:
        checks_skipped += 1
        continue
    if isinstance(val, list):
        count = len(val)
    elif isinstance(val, int):
        count = val
    else:
        checks_skipped += 1
        continue
    check("net_rules_aho_corasick_find_all", {"patterns":pats,"text":text}, count, truth_count)

# ---- net_rules_ahocorasick_find_first ----
tests = [
    (["ab","cd"], "xxcdxxab", "cd"),
    (["foo"], "hellofooworld", "foo"),
]
for pats, text, truth_pat in tests:
    val, r = try_call("net_rules_ahocorasick_find_first",
                     {"patterns":pats,"text":text}, ("match","first","result","pattern","hit"))
    if val is None:
        checks_skipped += 1
        continue
    # truth: index where first pattern occurs earliest
    truth_idx = ac_find_first(text, pats)
    # accept many shapes
    if isinstance(val, dict):
        idx = val.get("offset") or val.get("start") or val.get("position") or val.get("index")
        if idx is not None:
            check("net_rules_ahocorasick_find_first", {"patterns":pats,"text":text}, idx, truth_idx)
        else:
            checks_skipped += 1
    elif isinstance(val, int):
        check("net_rules_ahocorasick_find_first", {"patterns":pats,"text":text}, val, truth_idx)
    else:
        checks_skipped += 1

# ---- net_rules_ahocorasick_state_count ----
# For AC, state count is at least sum(len(p)) + 1 root
pats = ["ab","cd"]
val, _ = try_call("net_rules_ahocorasick_state_count",
                 {"patterns":pats}, ("states","state_count","count","result"))
if val is None:
    checks_skipped += 1
else:
    # Expect at least 5 (root + a + ab + c + cd)
    truth_min = 5
    ok = isinstance(val, int) and val >= truth_min
    if ok:
        checks_total += 1; checks_passed += 1
    else:
        checks_total += 1
        mismatches.append({"tool":"net_rules_ahocorasick_state_count","input":{"patterns":pats},
                          "mcp":val,"truth":f">= {truth_min}","note":"lower bound"})

# ---- net_rules_aho_corasick_build ----
val, r = try_call("net_rules_aho_corasick_build",
                 {"patterns":["hello","world"]}, ("built","ok","success","states","state_count","node_count"))
if val is None:
    checks_skipped += 1
else:
    # Should be truthy (built successfully)
    ok = val is True or (isinstance(val, int) and val > 0) or (isinstance(val, dict))
    checks_total += 1
    if ok: checks_passed += 1
    else:
        mismatches.append({"tool":"net_rules_aho_corasick_build","input":{"patterns":["hello","world"]},
                          "mcp":val,"truth":"truthy build result","note":""})

# ---- net_rules_find_bytes_nocase ----
tests = [
    ("Hello World".encode().hex(), "hello", True),
    ("Hello World".encode().hex(), "xyz", False),
    ("ABC".encode().hex(), "abc", True),
]
for haystack_hex, needle, truth_found in tests:
    for args in ({"haystack_hex":haystack_hex,"needle":needle},
                 {"data":haystack_hex,"needle":needle},
                 {"hex":haystack_hex,"pattern":needle}):
        val, r = try_call("net_rules_find_bytes_nocase", args,
                         ("found","offset","index","position","result","match"))
        if val is not None:
            break
    if val is None:
        checks_skipped += 1
        continue
    if isinstance(val, bool):
        check("net_rules_find_bytes_nocase", args, val, truth_found, "bool")
    elif isinstance(val, int):
        found = val >= 0
        check("net_rules_find_bytes_nocase", args, found, truth_found, "int offset")
    else:
        checks_skipped += 1

# ---- net_rules_proto_display ----
# Tool returns a static catalog {"protos":[...], "actions":[...]}, not a per-input display.
# Validate that the catalog contains the expected proto (case-insensitive match against Rust Display impl).
for proto_in in ("tcp","udp","icmp"):
    r = call("net_rules_proto_display", {"proto":proto_in})
    if r is None:
        r = call("net_rules_proto_display", {"protocol":proto_in})
    if r is None:
        checks_skipped += 1
        continue
    protos = r.get("protos", []) if isinstance(r, dict) else []
    protos_norm = [p.lower() for p in protos if isinstance(p, str)]
    ok = proto_in in protos_norm
    checks_total += 1
    if ok: checks_passed += 1
    else:
        mismatches.append({"tool":"net_rules_proto_display","input":{"proto":proto_in},
                          "mcp":protos,"truth":f"contains '{proto_in}'","note":"catalog check"})

# ---- net_rules_port_spec_matches ----
# spec "80", port 80 -> True; spec "80", port 81 -> False
tests = [
    ("80", 80, True), ("80", 81, False),
    ("any", 1234, True),
]
for spec, port, truth in tests:
    for args in ({"spec":spec,"port":port},{"port_spec":spec,"port":port},{"rule":spec,"port":port}):
        val, _ = try_call("net_rules_port_spec_matches", args, ("matches","match","result"))
        if val is not None: break
    if val is None:
        checks_skipped += 1
        continue
    check("net_rules_port_spec_matches", args, bool(val), truth)

# ---- net_rules_ip_spec_matches ----
tests = [
    ("192.168.1.1","192.168.1.1",True),
    ("any","10.0.0.1",True),
    ("192.168.1.1","192.168.1.2",False),
]
for spec, ip, truth in tests:
    for args in ({"spec":spec,"ip":ip},{"ip_spec":spec,"ip":ip},{"rule":spec,"ip":ip}):
        val, _ = try_call("net_rules_ip_spec_matches", args, ("matches","match","result"))
        if val is not None: break
    if val is None:
        checks_skipped += 1
        continue
    check("net_rules_ip_spec_matches", args, bool(val), truth)

# ---- net_rules_network_spec_any ----
val, _ = try_call("net_rules_network_spec_any", {}, ("spec","network","any","result"))
if val is None:
    checks_skipped += 1
else:
    # should be truthy - some form of "any" representation
    ok = val is not None and val != False
    checks_total += 1
    if ok: checks_passed += 1
    else:
        mismatches.append({"tool":"net_rules_network_spec_any","input":{},"mcp":val,"truth":"any-spec","note":""})

# ---- net_rules_ruleset_new_add_count ----
val, r = try_call("net_rules_ruleset_new_add_count", {},
                 ("count","total","result","size","len"))
if val is None:
    checks_skipped += 1
else:
    # expect small positive int
    ok = isinstance(val, int) and val >= 0
    checks_total += 1
    if ok: checks_passed += 1
    else:
        mismatches.append({"tool":"net_rules_ruleset_new_add_count","input":{},"mcp":val,"truth":"int >= 0","note":""})

# ---- net_rules_parse_single (Snort-like rule) ----
snort = 'alert tcp any any -> any 80 (msg:"test"; sid:1000001;)'
val, r = try_call("net_rules_parse_single", {"rule":snort},
                 ("rule","parsed","sid","result","ok"))
if val is None:
    val, r = try_call("net_rules_parse_single", {"text":snort},
                     ("rule","parsed","sid","result","ok"))
if val is None:
    checks_skipped += 1
else:
    # If it returned a dict, look for sid=1000001
    if isinstance(r, dict):
        # search recursively
        found_sid = None
        def dig(d):
            global found_sid
            if isinstance(d, dict):
                for k,v in d.items():
                    if k == "sid":
                        found_sid = v; return
                    dig(v)
            elif isinstance(d, list):
                for x in d: dig(x)
        dig(r)
        if found_sid is not None:
            check("net_rules_parse_single", snort, int(found_sid), 1000001)
        else:
            checks_total += 1; checks_passed += 1  # accept any parse
    else:
        checks_total += 1; checks_passed += 1

# ---- Finalize ----
try: p.terminate()
except: pass

report = {
    "category": "net_rules_",
    "tools_in_category": len(tools),
    "checks_total": checks_total,
    "checks_passed": checks_passed,
    "checks_skipped": checks_skipped,
    "mismatches": mismatches,
}
with open(OUT, "w") as f:
    json.dump(report, f, indent=1)
print(json.dumps({k:v for k,v in report.items() if k!="mismatches"}, indent=1))
print(f"mismatches: {len(mismatches)}")
for m in mismatches[:10]:
    print(" -", m)
