#!/usr/bin/env python3
"""
Rigorous validator for net_rules_* MCP tools.
Replaces any_valid() with exact Python-computed truth values.
"""
import json
import subprocess
import sys

EXE = r"C:\Users\Fra\Desktop\RustRE\target\release\rustre-mcp.exe"
OUT = r"C:\Users\Fra\Desktop\RustRE\validation\rigorous_net_rules.json"


# ──────────────────────────────────────────────────────────────────────────────
# MCP session helpers
# ──────────────────────────────────────────────────────────────────────────────

def start_session():
    p = subprocess.Popen(
        [EXE, "--transport=stdio"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        bufsize=0,
    )

    def send(r):
        p.stdin.write((json.dumps(r) + "\n").encode())
        p.stdin.flush()

    def recv():
        line = p.stdout.readline()
        return json.loads(line) if line else None

    send({
        "jsonrpc": "2.0", "id": 1, "method": "initialize",
        "params": {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": {"name": "rigorous-validator", "version": "1"},
        },
    })
    recv()
    send({"jsonrpc": "2.0", "method": "notifications/initialized"})
    return p, send, recv


p, send, recv = start_session()
_rid = [200]


def call_tool(name, args):
    _rid[0] += 1
    send({
        "jsonrpc": "2.0", "id": _rid[0],
        "method": "tools/call",
        "params": {"name": name, "arguments": args},
    })
    resp = recv()
    if not resp or "error" in resp:
        return None
    content = resp.get("result", {}).get("content", [])
    if not content:
        return None
    text = content[0].get("text", "")
    try:
        return json.loads(text)
    except Exception:
        return text


# ──────────────────────────────────────────────────────────────────────────────
# Scoring helpers
# ──────────────────────────────────────────────────────────────────────────────

checks_passed = 0
checks_failed = 0
mismatches = []
tools_hardened = set()


def check(tool, label, got, expected, note=""):
    global checks_passed, checks_failed
    tools_hardened.add(tool)
    if got == expected:
        checks_passed += 1
        return True
    else:
        checks_failed += 1
        mismatches.append({
            "tool": tool,
            "label": label,
            "got": got,
            "expected": expected,
            "note": note,
        })
        return False


def skip(tool):
    global checks_failed
    tools_hardened.add(tool)
    checks_failed += 1
    mismatches.append({"tool": tool, "label": "TOOL_ERROR", "got": None,
                       "expected": "non-null response", "note": "tool returned None"})


# ──────────────────────────────────────────────────────────────────────────────
# Python reference implementations
# ──────────────────────────────────────────────────────────────────────────────

def py_contains_any(text: str, patterns: list[str]) -> bool:
    tb = text.encode()
    return any(p.encode() in tb for p in patterns)


def py_find_all_count(text: str, patterns: list[str]) -> int:
    tb = text.encode()
    total = 0
    for p in patterns:
        pb = p.encode()
        start = 0
        while True:
            idx = tb.find(pb, start)
            if idx < 0:
                break
            total += 1
            start = idx + 1
    return total


def py_find_first_offset(text: str, patterns: list[str]):
    """Return offset of the earliest pattern match, or None."""
    tb = text.encode()
    best = None
    for p in patterns:
        pb = p.encode()
        idx = tb.find(pb)
        if idx >= 0 and (best is None or idx < best):
            best = idx
    return best


def py_find_bytes_nocase(haystack_hex: str, needle: str):
    """Return offset of case-insensitive match or None."""
    data = bytes.fromhex(haystack_hex)
    needle_lo = needle.lower().encode()
    data_lo = data.lower()
    idx = data_lo.find(needle_lo)
    return idx if idx >= 0 else None


# ──────────────────────────────────────────────────────────────────────────────
# 1. net_rules_aho_corasick_contains_any
# ──────────────────────────────────────────────────────────────────────────────
TOOL = "net_rules_aho_corasick_contains_any"
cases = [
    (["ab", "cd"], "xxabxx", True),
    (["hello", "world"], "hi there", False),
    (["foo"], "foobar", True),
    (["xxx"], "abcdef", False),
    (["ab"], "", False),
]
for pats, text, truth in cases:
    r = call_tool(TOOL, {"patterns": pats, "text": text})
    if r is None:
        skip(TOOL)
    else:
        got = r.get("contains_any") if isinstance(r, dict) else None
        check(TOOL, f"contains_any({pats!r},{text!r})", got, truth)

# ──────────────────────────────────────────────────────────────────────────────
# 2. net_rules_aho_corasick_find_all  (returns {"match_count": int})
# ──────────────────────────────────────────────────────────────────────────────
TOOL = "net_rules_aho_corasick_find_all"
cases = [
    (["ab"], "ababab", 3),
    (["a", "b"], "ab", 2),
    (["xyz"], "abcdef", 0),
    (["aa"], "aaaa", 3),   # overlapping: aa at 0,1,2
]
for pats, text, truth_count in cases:
    r = call_tool(TOOL, {"patterns": pats, "text": text})
    if r is None:
        skip(TOOL)
        continue
    if isinstance(r, dict):
        # actual key is "match_count"
        got = r.get("match_count", r.get("count", r.get("matches")))
        if isinstance(got, list):
            got = len(got)
    elif isinstance(r, int):
        got = r
    else:
        got = None
    check(TOOL, f"find_all count({pats!r},{text!r})", got, truth_count)

# ──────────────────────────────────────────────────────────────────────────────
# 3. net_rules_ahocorasick_find_first
#    Returns {"match": {"pattern_idx": int, "start": int, "end": int}} or
#            {"match": null} for no-match.
# ──────────────────────────────────────────────────────────────────────────────
TOOL = "net_rules_ahocorasick_find_first"
cases = [
    (["ab", "cd"], "xxcdxxab", py_find_first_offset("xxcdxxab", ["ab", "cd"])),   # 2
    (["foo"], "hellofooworld", py_find_first_offset("hellofooworld", ["foo"])),    # 5
    (["zzz"], "hello", None),
]
for pats, text, truth_offset in cases:
    r = call_tool(TOOL, {"patterns": pats, "text": text})
    if r is None:
        skip(TOOL)
        continue
    if isinstance(r, dict):
        match_obj = r.get("match")
        if match_obj is None:
            got = None
        elif isinstance(match_obj, dict):
            got = match_obj.get("start", match_obj.get("offset"))
        else:
            got = None
    elif isinstance(r, int):
        got = r
    else:
        got = None
    check(TOOL, f"find_first offset({pats!r},{text!r})", got, truth_offset)

# ──────────────────────────────────────────────────────────────────────────────
# 4. net_rules_ahocorasick_state_count
#    Building AC on ["ab","cd"] yields at least 5 states (root + a + ab + c + cd).
#    We verify exact lower bound.
# ──────────────────────────────────────────────────────────────────────────────
TOOL = "net_rules_ahocorasick_state_count"
pats = ["ab", "cd"]
r = call_tool(TOOL, {"patterns": pats})
if r is None:
    skip(TOOL)
else:
    got = r.get("state_count", r.get("states")) if isinstance(r, dict) else None
    truth_min = 5  # root + a + ab + c + cd
    ok = isinstance(got, int) and got >= truth_min
    tools_hardened.add(TOOL)
    if ok:
        checks_passed += 1
    else:
        checks_failed += 1
        mismatches.append({"tool": TOOL, "label": "state_count >= 5",
                           "got": got, "expected": f">= {truth_min}",
                           "note": "AC automaton must have at least 5 states for ['ab','cd']"})

# ──────────────────────────────────────────────────────────────────────────────
# 5. net_rules_find_bytes_nocase
#    Requires haystack_hex + needle_hex (or needle as int array).
#    Returns {"position": int|null}.
# ──────────────────────────────────────────────────────────────────────────────
TOOL = "net_rules_find_bytes_nocase"
cases = [
    ("Hello World".encode().hex(), "hello", 0),       # found at 0
    ("Hello World".encode().hex(), "WORLD", 6),        # found at 6
    ("Hello World".encode().hex(), "xyz", None),       # not found
    ("ABC".encode().hex(), "abc", 0),
    (b"\x41\x42\x43".hex(), "BC", 1),
]
for hay_hex, needle_str, truth_position in cases:
    needle_hex = needle_str.encode().hex()
    r = call_tool(TOOL, {"haystack_hex": hay_hex, "needle_hex": needle_hex})
    if r is None:
        skip(TOOL)
        continue
    if isinstance(r, dict):
        # response key is "position" (may be null/None for not found)
        pos = r.get("position")
        check(TOOL, f"nocase position({needle_str!r})", pos, truth_position)
    else:
        skip(TOOL)

# ──────────────────────────────────────────────────────────────────────────────
# 6. net_rules_proto_display
#    Catalog must contain tcp, udp, icmp, any (case-insensitive).
#    Actions must contain alert, pass, drop, log, reject.
# ──────────────────────────────────────────────────────────────────────────────
TOOL = "net_rules_proto_display"
r = call_tool(TOOL, {})
if r is None:
    skip(TOOL)
else:
    protos = [p.lower() for p in r.get("protos", [])]
    actions = [a.lower() for a in r.get("actions", [])]
    for expected_proto in ["tcp", "udp", "icmp", "any"]:
        check(TOOL, f"proto in catalog: {expected_proto}", expected_proto in protos, True)
    for expected_action in ["alert", "pass", "drop", "log", "reject"]:
        check(TOOL, f"action in catalog: {expected_action}", expected_action in actions, True)

# ──────────────────────────────────────────────────────────────────────────────
# 7. net_rules_ruleset_new_add_count
#    Adds exactly 1 rule, so count must be 1.
# ──────────────────────────────────────────────────────────────────────────────
TOOL = "net_rules_ruleset_new_add_count"
r = call_tool(TOOL, {})
if r is None:
    skip(TOOL)
else:
    got = r.get("count") if isinstance(r, dict) else None
    check(TOOL, "count == 1", got, 1)

# ──────────────────────────────────────────────────────────────────────────────
# 8. net_rules_ruleset_by_sid
#    The tool always inserts sid=42 then looks up the provided sid.
# ──────────────────────────────────────────────────────────────────────────────
TOOL = "net_rules_ruleset_by_sid"
for sid_in, expected_found in [(42, True), (99, False)]:
    r = call_tool(TOOL, {"sid": sid_in})
    if r is None:
        skip(TOOL)
        continue
    got_found = r.get("found") if isinstance(r, dict) else None
    got_sid = r.get("sid") if isinstance(r, dict) else None
    check(TOOL, f"by_sid({sid_in}) found", got_found, expected_found)
    check(TOOL, f"by_sid({sid_in}) echoes sid", got_sid, sid_in)

# ──────────────────────────────────────────────────────────────────────────────
# 9. net_rules_specrule_sid_msg
#    Tool echoes back the sid and msg provided.
# ──────────────────────────────────────────────────────────────────────────────
TOOL = "net_rules_specrule_sid_msg"
for sid, msg in [(7, "test"), (1234, "my alert"), (0, "empty_msg_test")]:
    r = call_tool(TOOL, {"sid": sid, "msg": msg})
    if r is None:
        skip(TOOL)
        continue
    got_sid = r.get("sid") if isinstance(r, dict) else None
    got_msg = r.get("msg") if isinstance(r, dict) else None
    check(TOOL, f"specrule sid echo ({sid})", got_sid, sid)
    check(TOOL, f"specrule msg echo ({msg!r})", got_msg, msg)

# ──────────────────────────────────────────────────────────────────────────────
# 10. net_rules_specrule_content_patterns
#     Fixed rule with Content("GET ") + Content("HTTP") + Nocase.
#     content_patterns() must return exactly ["GET ", "HTTP"].
# ──────────────────────────────────────────────────────────────────────────────
TOOL = "net_rules_specrule_content_patterns"
r = call_tool(TOOL, {})
if r is None:
    skip(TOOL)
else:
    pats = r.get("patterns") if isinstance(r, dict) else None
    check(TOOL, "pattern count == 2", len(pats) if pats is not None else None, 2)
    if pats and len(pats) >= 2:
        check(TOOL, "pattern[0] == 'GET '", pats[0], "GET ")
        check(TOOL, "pattern[1] == 'HTTP'", pats[1], "HTTP")

# ──────────────────────────────────────────────────────────────────────────────
# 11. net_rules_engine_add_remove
#     Adds 1 rule (before=1), removes it (after=0).
# ──────────────────────────────────────────────────────────────────────────────
TOOL = "net_rules_engine_add_remove"
r = call_tool(TOOL, {})
if r is None:
    skip(TOOL)
else:
    before = r.get("before") if isinstance(r, dict) else None
    after = r.get("after") if isinstance(r, dict) else None
    check(TOOL, "before == 1", before, 1)
    check(TOOL, "after == 0", after, 0)

# ──────────────────────────────────────────────────────────────────────────────
# 12. net_rules_ruledir_display
#     Must have "->", "<>" in dirs and tcp/udp/icmp/any in protos.
# ──────────────────────────────────────────────────────────────────────────────
TOOL = "net_rules_ruledir_display"
r = call_tool(TOOL, {})
if r is None:
    skip(TOOL)
else:
    dirs = r.get("dirs", []) if isinstance(r, dict) else []
    protos = [p.lower() for p in r.get("protos", [])]
    # Snort uses -> for unidirectional, <> for bidirectional
    check(TOOL, "dirs contains '->'", "->" in dirs, True)
    check(TOOL, "dirs contains '<>'", "<>" in dirs, True)
    for proto in ["tcp", "udp", "icmp", "any"]:
        check(TOOL, f"proto in ruledir protos: {proto}", proto in protos, True)

# ──────────────────────────────────────────────────────────────────────────────
# 13. net_rules_ip_spec_matches  (uses "addr" param not "ip")
# ──────────────────────────────────────────────────────────────────────────────
TOOL = "net_rules_ip_spec_matches"
cases = [
    ("192.168.1.1", "192.168.1.1", True),
    ("any", "10.0.0.1", True),
    ("192.168.1.1", "192.168.1.2", False),
    ("any", "0.0.0.0", True),
]
for spec, addr, truth in cases:
    r = call_tool(TOOL, {"spec": spec, "addr": addr})
    if r is None:
        skip(TOOL)
        continue
    got = r.get("matches") if isinstance(r, dict) else None
    check(TOOL, f"ip_spec({spec!r},{addr!r})", got, truth)

# ──────────────────────────────────────────────────────────────────────────────
# 14. net_rules_port_spec_matches
# ──────────────────────────────────────────────────────────────────────────────
TOOL = "net_rules_port_spec_matches"
cases = [
    ("80", 80, True),
    ("80", 81, False),
    ("any", 1234, True),
    ("any", 0, True),
    ("443", 443, True),
    ("443", 80, False),
]
for spec, port, truth in cases:
    r = call_tool(TOOL, {"spec": spec, "port": port})
    if r is None:
        skip(TOOL)
        continue
    got = r.get("matches") if isinstance(r, dict) else None
    check(TOOL, f"port_spec({spec!r},{port})", got, truth)

# ──────────────────────────────────────────────────────────────────────────────
# 15. net_rules_parse_many
#     2 valid rules -> total=2, ok=2, errors=0
# ──────────────────────────────────────────────────────────────────────────────
TOOL = "net_rules_parse_many"
rules_text = (
    'alert tcp any any -> any 80 (msg:"web"; sid:1;)\n'
    'alert udp any any -> any 53 (msg:"dns"; sid:2;)\n'
)
r = call_tool(TOOL, {"text": rules_text})
if r is None:
    skip(TOOL)
else:
    total = r.get("total") if isinstance(r, dict) else None
    ok = r.get("ok") if isinstance(r, dict) else None
    errors = r.get("errors") if isinstance(r, dict) else None
    check(TOOL, "parse_many total==2", total, 2)
    check(TOOL, "parse_many ok==2", ok, 2)
    check(TOOL, "parse_many errors==0", errors, 0)

# ──────────────────────────────────────────────────────────────────────────────
# 16. net_rules_engine_evaluate  (match_count for matching rule)
# ──────────────────────────────────────────────────────────────────────────────
TOOL = "net_rules_engine_evaluate"
# Rule: alert tcp any any -> any 80 (msg:"web"; content:"GET"; sid:1;)
# Engine test uses src_port=1234, dst_port=80, ip_proto=6 by default
rule_text = 'alert tcp any any -> any 80 (msg:"web"; content:"GET"; sid:1;)'
r = call_tool(TOOL, {
    "rules_text": rule_text,
    "src_port": 1234,
    "dst_port": 80,
    "ip_proto": 6,
    "payload_hex": "474554202f20485454502f312e310d0a",  # "GET / HTTP/1.1\r\n"
})
if r is None:
    skip(TOOL)
else:
    rule_count = r.get("rule_count") if isinstance(r, dict) else None
    check(TOOL, "evaluate rule_count==1", rule_count, 1)
    # match_count should be >= 1 (rule fires on GET payload to port 80)
    match_count = r.get("match_count") if isinstance(r, dict) else None
    tools_hardened.add(TOOL)
    ok = isinstance(match_count, int) and match_count >= 1
    if ok:
        checks_passed += 1
    else:
        checks_failed += 1
        mismatches.append({"tool": TOOL, "label": "evaluate match_count >= 1",
                           "got": match_count, "expected": ">= 1",
                           "note": "rule should fire on GET payload to port 80"})

# ──────────────────────────────────────────────────────────────────────────────
# 17. net_rules_spec_engine_match  (content match)
# ──────────────────────────────────────────────────────────────────────────────
TOOL = "net_rules_spec_engine_match"
# Content "GET" in payload -> should match
r = call_tool(TOOL, {
    "content": "GET",
    "payload_hex": "474554202f20485454502f312e310d0a",  # "GET / HTTP/1.1\r\n"
    "sid": 999,
})
if r is None:
    skip(TOOL)
else:
    mc = r.get("match_count") if isinstance(r, dict) else None
    tools_hardened.add(TOOL)
    ok = isinstance(mc, int) and mc >= 1
    if ok:
        checks_passed += 1
    else:
        checks_failed += 1
        mismatches.append({"tool": TOOL, "label": "spec_engine match_count >= 1",
                           "got": mc, "expected": ">= 1",
                           "note": "content 'GET' should be found in payload"})

# No match case
r2 = call_tool(TOOL, {
    "content": "ZZZNOTFOUND",
    "payload_hex": "474554202f20485454502f312e310d0a",
    "sid": 998,
})
if r2 is not None:
    mc2 = r2.get("match_count") if isinstance(r2, dict) else None
    check(TOOL, "spec_engine no match == 0", mc2, 0)

# ──────────────────────────────────────────────────────────────────────────────
# 18. net_rules_aho_corasick_build  (state count > 0)
# ──────────────────────────────────────────────────────────────────────────────
TOOL = "net_rules_aho_corasick_build"
r = call_tool(TOOL, {"patterns": ["hello", "world"]})
if r is None:
    skip(TOOL)
else:
    states = r.get("state_count", r.get("states")) if isinstance(r, dict) else None
    tools_hardened.add(TOOL)
    ok = isinstance(states, int) and states >= 11  # root+h+he+hel+hell+hello+w+wo+wor+worl+world
    if ok:
        checks_passed += 1
    else:
        checks_failed += 1
        mismatches.append({"tool": TOOL, "label": "build states >= 11",
                           "got": states, "expected": ">= 11",
                           "note": "['hello','world'] needs at least 11 states"})

# ──────────────────────────────────────────────────────────────────────────────
# 19. net_rules_network_spec_any
#    Returns some non-null, non-false representation of "any"
# ──────────────────────────────────────────────────────────────────────────────
TOOL = "net_rules_network_spec_any"
r = call_tool(TOOL, {})
if r is None:
    skip(TOOL)
else:
    # Should be a non-empty dict
    tools_hardened.add(TOOL)
    ok = isinstance(r, dict) and len(r) > 0
    if ok:
        checks_passed += 1
    else:
        checks_failed += 1
        mismatches.append({"tool": TOOL, "label": "any returns non-empty dict",
                           "got": r, "expected": "non-empty dict", "note": ""})

# ──────────────────────────────────────────────────────────────────────────────
# Finalize
# ──────────────────────────────────────────────────────────────────────────────
try:
    p.terminate()
except Exception:
    pass

report = {
    "module": "net_rules",
    "tools_hardened": len(tools_hardened),
    "checks_passed": checks_passed,
    "checks_failed": checks_failed,
    "mismatches": mismatches,
}

with open(OUT, "w") as f:
    json.dump(report, f, indent=2)

summary = {k: v for k, v in report.items() if k != "mismatches"}
print(json.dumps(summary, indent=2))
print(f"real_mismatches: {len(mismatches)}")
for m in mismatches:
    print(" -", m)
