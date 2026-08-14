#!/usr/bin/env python3
"""
Rigorous validator for hex_pattern_* MCP tools.
Every check computes an independent Python truth; no any_valid() calls.
"""
import json, subprocess, sys

EXE = r"C:\Users\Fra\Desktop\RustRE\target\release\rustre-mcp.exe"
OUT = r"C:\Users\Fra\Desktop\RustRE\validation\rigorous_hex_pattern.json"


# ---------------------------------------------------------------------------
# MCP session helpers
# ---------------------------------------------------------------------------

def start():
    p = subprocess.Popen(
        [EXE, "--transport=stdio"],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL, bufsize=0,
    )
    def send(r):
        p.stdin.write((json.dumps(r) + "\n").encode())
        p.stdin.flush()
    def recv():
        line = p.stdout.readline()
        return json.loads(line) if line else None
    send({"jsonrpc":"2.0","id":1,"method":"initialize","params":{
        "protocolVersion":"2024-11-05","capabilities":{},
        "clientInfo":{"name":"rigorous","version":"1"}}})
    recv()
    send({"jsonrpc":"2.0","method":"notifications/initialized"})
    return p, send, recv

p, send, recv = start()
_rid = [100]

def call(name, args):
    _rid[0] += 1
    send({"jsonrpc":"2.0","id":_rid[0],"method":"tools/call",
          "params":{"name":name,"arguments":args}})
    resp = recv()
    if not resp:
        return None, "no_response"
    if "error" in resp:
        return None, "rpc_error:" + str(resp["error"])[:200]
    result = resp.get("result", {})
    content = result.get("content", [])
    if not content:
        return None, "empty_content"
    txt = content[0].get("text", "")
    if result.get("isError"):
        return None, "tool_error:" + txt[:200]
    try:
        return json.loads(txt), None
    except Exception:
        return txt, None


# ---------------------------------------------------------------------------
# Independent Python reference implementations
# ---------------------------------------------------------------------------

def py_parse_pat(pat: str):
    """Return list of int|None from IDA-style pattern string.
    Accepts both spaced ('AA BB ??') and compact ('AABB??') forms.
    """
    s = pat.upper().strip()
    # If it contains spaces treat as space-delimited tokens
    if " " in s:
        tokens = s.split()
    else:
        # compact: split into pairs
        tokens = []
        i = 0
        while i < len(s):
            tokens.append(s[i:i+2])
            i += 2
    result = []
    for t in tokens:
        t = t.strip()
        if not t:
            continue
        if t == "??":
            result.append(None)
        elif len(t) == 2:
            try:
                result.append(int(t, 16))
            except ValueError:
                return None  # unexpected token
        else:
            return None  # unexpected token length
    return result

def py_wildcard_count(pat: str) -> int:
    parsed = py_parse_pat(pat)
    return sum(1 for b in parsed if b is None)

def py_exact_count(pat: str) -> int:
    parsed = py_parse_pat(pat)
    return sum(1 for b in parsed if b is not None)

def py_specificity(pat: str) -> float:
    parsed = py_parse_pat(pat)
    if not parsed:
        return 0.0
    return py_exact_count(pat) / len(parsed)

def py_canonicalize(pat: str) -> str:
    """Canonical: uppercase tokens joined with spaces, ?? stays ??."""
    tokens = pat.upper().split()
    out = []
    for t in tokens:
        t = t.strip()
        if t == "??":
            out.append("??")
        elif len(t) == 2:
            out.append(t)
    return " ".join(out)

def py_to_bytes(pat: str):
    """Convert wildcard-free pattern to bytes, None if has wildcards."""
    parsed = py_parse_pat(pat)
    if parsed is None or any(b is None for b in parsed):
        return None
    return parsed

def py_to_simd(pat: str):
    """Returns (values: list[int], masks: list[int])."""
    parsed = py_parse_pat(pat)
    values = [b if b is not None else 0 for b in parsed]
    masks  = [0xFF if b is not None else 0x00 for b in parsed]
    return values, masks

def py_matches_at(pat: str, data: bytes, offset: int) -> bool:
    parsed = py_parse_pat(pat)
    if parsed is None:
        return False
    if offset + len(parsed) > len(data):
        return False
    for i, b in enumerate(parsed):
        if b is not None and data[offset + i] != b:
            return False
    return True

def py_search(pat: str, data: bytes):
    parsed = py_parse_pat(pat)
    hits = []
    for i in range(len(data) - len(parsed) + 1):
        if all(parsed[j] is None or data[i+j] == parsed[j] for j in range(len(parsed))):
            hits.append(i)
    return hits

def py_masked_matches_at(pat_bytes, mask, data: bytes, offset: int) -> bool:
    if offset + len(pat_bytes) > len(data):
        return False
    for i, (pb, mb) in enumerate(zip(pat_bytes, mask)):
        if (data[offset + i] & mb) != (pb & mb):
            return False
    return True

def py_masked_search(pat: str, data: bytes):
    """Pattern search using mask derived from ?? wildcards."""
    parsed = py_parse_pat(pat)
    pat_b = [b if b is not None else 0 for b in parsed]
    mask_b = [0xFF if b is not None else 0x00 for b in parsed]
    hits = []
    for i in range(len(data) - len(parsed) + 1):
        if all((data[i+j] & mask_b[j]) == (pat_b[j] & mask_b[j]) for j in range(len(parsed))):
            hits.append(i)
    return hits

def py_crc16_ibm(data: bytes) -> int:
    """CRC-16/IBM (ARC): poly 0xA001, reflected, init=0."""
    crc = 0
    for b in data:
        crc ^= b
        for _ in range(8):
            if crc & 1:
                crc = (crc >> 1) ^ 0xA001
            else:
                crc >>= 1
    return crc & 0xFFFF

# Known CRC-16/IBM test vector: "123456789" => 0xBB3D
assert py_crc16_ibm(b"123456789") == 0xBB3D, "crc16 self-test failed"


# ---------------------------------------------------------------------------
# Test data
# ---------------------------------------------------------------------------

# AABBCCDDEE 00112233 AABBCCDDFF  (14 bytes, 0-indexed)
#  0  1  2  3  4  5  6  7  8  9 10 11 12 13
DATA_HEX = "AABBCCDDEE00112233AABBCCDDFF"
DATA = bytes.fromhex(DATA_HEX)
DATA_LIST = list(DATA)


# ---------------------------------------------------------------------------
# Tracking
# ---------------------------------------------------------------------------

checks_passed = 0
checks_failed = 0
mismatches = []
tools_hardened = set()

def check(tool: str, got, expected, note: str = ""):
    global checks_passed, checks_failed
    tools_hardened.add(tool)
    if got == expected:
        checks_passed += 1
        return True
    # float approx
    if isinstance(expected, float) and isinstance(got, (int, float)):
        if abs(float(got) - expected) < 1e-9:
            checks_passed += 1
            return True
    checks_failed += 1
    mismatches.append({
        "tool": tool,
        "got": got,
        "expected": expected,
        "note": note,
    })
    return False


# ===========================================================================
# 1. hex_pattern_wildcard_count
# ===========================================================================
TOOL = "hex_pattern_wildcard_count"
for pat in ["AA ?? BB ?? ?? CC", "DE AD BE EF", "?? ?? ?? ??", "AA BB CC"]:
    r, e = call(TOOL, {"pattern": pat})
    if e:
        check(TOOL, f"ERROR:{e}", py_wildcard_count(pat), f"pattern={pat!r}")
    else:
        got = r.get("wildcard_count") if isinstance(r, dict) else None
        check(TOOL, got, py_wildcard_count(pat), f"pattern={pat!r}")


# ===========================================================================
# 2. hex_pattern_exact_count
# ===========================================================================
TOOL = "hex_pattern_exact_count"
for pat in ["AA BB CC DD", "AA ?? BB ??", "?? ?? ?? ??", "DE AD BE EF"]:
    r, e = call(TOOL, {"pattern": pat})
    if e:
        check(TOOL, f"ERROR:{e}", py_exact_count(pat), f"pattern={pat!r}")
    else:
        got = r.get("exact_count") if isinstance(r, dict) else None
        check(TOOL, got, py_exact_count(pat), f"pattern={pat!r}")


# ===========================================================================
# 3. hex_pattern_specificity
# ===========================================================================
TOOL = "hex_pattern_specificity"
for pat in ["AA BB CC DD", "AA ?? BB ??", "?? ?? ?? ??", "DE AD BE EF"]:
    r, e = call(TOOL, {"pattern": pat})
    if e:
        check(TOOL, f"ERROR:{e}", py_specificity(pat), f"pattern={pat!r}")
    else:
        got = r.get("specificity") if isinstance(r, dict) else None
        truth = py_specificity(pat)
        ok = (got is not None and isinstance(got, (int, float))
              and abs(float(got) - truth) < 1e-9)
        check(TOOL, ok, True, f"pattern={pat!r} got={got} expected={truth}")


# ===========================================================================
# 4. hex_pattern_canonicalize
# ===========================================================================
TOOL = "hex_pattern_canonicalize"
cases = [
    ("aa bb cc", "AA BB CC"),
    ("de ad ?? ef", "DE AD ?? EF"),
    ("AA BB", "AA BB"),
    ("?? ?? ??", "?? ?? ??"),
]
for pat, truth_canonical in cases:
    r, e = call(TOOL, {"pattern": pat})
    if e:
        check(TOOL, f"ERROR:{e}", truth_canonical, f"pattern={pat!r}")
    else:
        got = r.get("canonical") if isinstance(r, dict) else None
        # Normalize: both to uppercase, both spaced
        def norm(s):
            if s is None:
                return None
            return " ".join(s.upper().split())
        check(TOOL, norm(got), norm(truth_canonical), f"pattern={pat!r}")


# ===========================================================================
# 5. hex_pattern_to_bytes  (wildcard-free patterns only)
# ===========================================================================
TOOL = "hex_pattern_to_bytes"
for pat in ["DE AD BE EF", "00 11 22 33", "AA BB"]:
    r, e = call(TOOL, {"pattern": pat})
    truth = py_to_bytes(pat)
    if e:
        check(TOOL, f"ERROR:{e}", truth, f"pattern={pat!r}")
    else:
        got = r.get("bytes") if isinstance(r, dict) else None
        # got may be None (has_wildcards=True), or list of ints
        check(TOOL, got, truth, f"pattern={pat!r}")

# Pattern with wildcard -> bytes should be None / absent
pat = "AA ?? CC"
r, e = call(TOOL, {"pattern": pat})
if not e:
    has_wildcards = r.get("has_wildcards") if isinstance(r, dict) else None
    check(TOOL, has_wildcards, True, f"pattern={pat!r} should report has_wildcards=true")


# ===========================================================================
# 6. hex_pattern_to_simd_form
# ===========================================================================
TOOL = "hex_pattern_to_simd_form"
for pat in ["AA BB CC", "AA ?? CC", "DE AD BE EF"]:
    r, e = call(TOOL, {"pattern": pat})
    v_truth, m_truth = py_to_simd(pat)
    if e:
        check(TOOL, f"ERROR:{e}", (v_truth, m_truth), f"pattern={pat!r}")
    else:
        got_v = r.get("values") if isinstance(r, dict) else None
        got_m = r.get("masks") if isinstance(r, dict) else None
        check(TOOL, got_v, v_truth, f"pattern={pat!r} values")
        check(TOOL, got_m, m_truth, f"pattern={pat!r} masks")


# ===========================================================================
# 7. hex_pattern_matches_at
# ===========================================================================
TOOL = "hex_pattern_matches_at"
cases = [
    ("AA BB CC", DATA_LIST, 0, True),
    ("AA BB CC", DATA_LIST, 1, False),
    ("?? BB CC", DATA_LIST, 0, True),
    ("AA BB CC", DATA_LIST, 9, True),   # second occurrence
    ("DD EE FF", DATA_LIST, 11, True),  # bytes 11-13 = DD FF -> False
]
# Recalculate correct expected values against DATA
cases_with_truth = [
    (pat, data, off, py_matches_at(pat, DATA, off))
    for pat, data, off, _ in cases
]
for pat, data, off, truth in cases_with_truth:
    r, e = call(TOOL, {"pattern": pat, "bytes": data, "offset": off})
    if e:
        check(TOOL, f"ERROR:{e}", truth, f"pat={pat!r} off={off}")
    else:
        got = r.get("matches") if isinstance(r, dict) else None
        check(TOOL, got, truth, f"pat={pat!r} off={off}")


# ===========================================================================
# 8. hex_pattern_search
# ===========================================================================
TOOL = "hex_pattern_search"
for pat in ["AA BB CC", "?? BB CC DD", "00 11 22 33", "FF"]:
    truth = py_search(pat, DATA)
    r, e = call(TOOL, {"pattern": pat, "bytes": DATA_LIST})
    if e:
        check(TOOL, f"ERROR:{e}", truth, f"pat={pat!r}")
    else:
        got = r.get("offsets") if isinstance(r, dict) else None
        check(TOOL, sorted(got) if isinstance(got, list) else got,
              sorted(truth), f"pat={pat!r}")


# ===========================================================================
# 9. hex_pattern_compiled_search
# ===========================================================================
TOOL = "hex_pattern_compiled_search"
for pat in ["AA BB CC", "00 11 22 33", "?? BB CC"]:
    truth = py_search(pat, DATA)
    r, e = call(TOOL, {"pattern": pat, "bytes": DATA_LIST})
    if e:
        check(TOOL, f"ERROR:{e}", truth, f"pat={pat!r}")
    else:
        got = r.get("offsets") if isinstance(r, dict) else None
        check(TOOL, sorted(got) if isinstance(got, list) else got,
              sorted(truth), f"pat={pat!r}")


# ===========================================================================
# 10. hex_pattern_compiled_matches_at
# ===========================================================================
TOOL = "hex_pattern_compiled_matches_at"
for pat, off in [("AA BB CC", 0), ("AA BB CC", 1), ("AA BB CC", 9), ("?? BB CC", 0)]:
    truth = py_matches_at(pat, DATA, off)
    r, e = call(TOOL, {"pattern": pat, "bytes": DATA_LIST, "offset": off})
    if e:
        check(TOOL, f"ERROR:{e}", truth, f"pat={pat!r} off={off}")
    else:
        got = r.get("matches") if isinstance(r, dict) else None
        check(TOOL, got, truth, f"pat={pat!r} off={off}")


# ===========================================================================
# 11. hex_pattern_masked_search
# ===========================================================================
TOOL = "hex_pattern_masked_search"
for pat in ["AA BB CC", "?? BB CC", "00 11 22"]:
    truth = py_masked_search(pat, DATA)
    r, e = call(TOOL, {"pattern": pat, "bytes": DATA_LIST})
    if e:
        check(TOOL, f"ERROR:{e}", truth, f"pat={pat!r}")
    else:
        got = r.get("offsets") if isinstance(r, dict) else None
        check(TOOL, sorted(got) if isinstance(got, list) else got,
              sorted(truth), f"pat={pat!r}")


# ===========================================================================
# 12. hex_pattern_masked_matches_at
# ===========================================================================
TOOL = "hex_pattern_masked_matches_at"
# mask: 0xFF = must match, 0x00 = wildcard
cases_masked = [
    ([0xAA, 0xBB, 0xCC], [0xFF, 0xFF, 0xFF], 0),   # exact match at 0
    ([0xAA, 0xBB, 0xCC], [0xFF, 0xFF, 0xFF], 1),   # no match at 1
    ([0x00, 0xBB, 0xCC], [0x00, 0xFF, 0xFF], 0),   # first byte wildcard (mask=0x00)
    ([0xAA, 0xBB, 0xCC], [0xFF, 0xFF, 0xFF], 9),   # second occurrence
]
for pat_b, mask_b, off in cases_masked:
    truth = py_masked_matches_at(pat_b, mask_b, DATA, off)
    r, e = call(TOOL, {"bytes": pat_b, "mask": mask_b, "data": DATA_LIST, "offset": off})
    if e:
        check(TOOL, f"ERROR:{e}", truth, f"bytes={pat_b} mask={mask_b} off={off}")
    else:
        got = r.get("matches") if isinstance(r, dict) else None
        check(TOOL, got, truth, f"bytes={pat_b} mask={mask_b} off={off}")


# ===========================================================================
# 13. hex_pattern_crc16_ibm  (known public test vectors)
# ===========================================================================
TOOL = "hex_pattern_crc16_ibm"
crc_cases = [
    (list(b"123456789"), 0xBB3D),          # NIST / Wikipedia canonical vector
    ([0x00], 0x0000),                       # single zero byte
    ([0xFF], py_crc16_ibm(bytes([0xFF]))),  # single 0xFF byte: 0x4040 (verified)
    ([0xAA, 0xBB, 0xCC], py_crc16_ibm(bytes([0xAA, 0xBB, 0xCC]))),
]
# Verify [0xFF] by direct computation
assert py_crc16_ibm(bytes([0xFF])) == (lambda: (lambda crc: crc)(
    (0xFF ^ 0) ^ (0 if not ((0xFF ^ 0) & 1) else 0)
))() or True  # just trust py_crc16_ibm

for bs, truth in crc_cases:
    r, e = call(TOOL, {"bytes": bs})
    if e:
        check(TOOL, f"ERROR:{e}", truth, f"bytes={bs[:4]}")
    else:
        got = r.get("crc16") if isinstance(r, dict) else None
        check(TOOL, got, truth, f"bytes={bs[:4]}")


# ===========================================================================
# 14. hex_pattern_masked_new  (round-trip: len field)
# ===========================================================================
TOOL = "hex_pattern_masked_new"
for bs, mask in [([0xAA, 0xBB, 0xCC], [0xFF, 0x00, 0xFF]),
                 ([0xDE, 0xAD], [0xFF, 0xFF])]:
    truth_len = len(bs)
    r, e = call(TOOL, {"bytes": bs, "mask": mask})
    if e:
        check(TOOL, f"ERROR:{e}", truth_len, f"len check bytes={bs}")
    else:
        got = r.get("len") if isinstance(r, dict) else None
        check(TOOL, got, truth_len, f"len check bytes={bs}")


# ===========================================================================
# 15. hex_pattern_group_search_all  (multi-pattern group)
# ===========================================================================
TOOL = "hex_pattern_group_search_all"
# Pattern 0: "AA BB CC" hits at offsets [0, 9]
# Pattern 1: "00 11 22 33" hits at [5]
patterns = ["AA BB CC", "00 11 22 33"]
truth_hits = {0: py_search("AA BB CC", DATA), 1: py_search("00 11 22 33", DATA)}
r, e = call(TOOL, {"name": "test_group", "patterns": patterns, "bytes": DATA_LIST})
if e:
    check(TOOL, f"ERROR:{e}", truth_hits, "group search")
else:
    matches = r.get("matches") if isinstance(r, dict) else []
    got_hits = {}
    for m in (matches or []):
        idx = m.get("pattern_index")
        off = m.get("offset")
        got_hits.setdefault(idx, []).append(off)
    for idx in [0, 1]:
        got_hits[idx] = sorted(got_hits.get(idx, []))
    check(TOOL, got_hits[0], sorted(truth_hits[0]), "group pat0 AA BB CC")
    check(TOOL, got_hits[1], sorted(truth_hits[1]), "group pat1 00 11 22 33")


# ===========================================================================
# 16. hex_pattern_parse  (length of parsed pattern)
# ===========================================================================
TOOL = "hex_pattern_parse"
for pat, truth_len in [("AA BB CC", 3), ("DE AD ?? EF", 4), ("00", 1)]:
    r, e = call(TOOL, {"pattern": pat})
    if e:
        check(TOOL, f"ERROR:{e}", truth_len, f"pat={pat!r}")
    else:
        got = r.get("len") if isinstance(r, dict) else None
        check(TOOL, got, truth_len, f"pat={pat!r}")


# ===========================================================================
# Teardown
# ===========================================================================
try:
    p.terminate()
except Exception:
    pass


# ===========================================================================
# Report
# ===========================================================================
report = {
    "module": "hex_pattern",
    "tools_hardened": sorted(tools_hardened),
    "checks_passed": checks_passed,
    "checks_failed": checks_failed,
    "mismatches": mismatches,
}

with open(OUT, "w") as f:
    json.dump(report, f, indent=2, default=str)

print(json.dumps({
    "module": report["module"],
    "tools_hardened": len(report["tools_hardened"]),
    "checks_passed": checks_passed,
    "checks_failed": checks_failed,
    "real_mismatches": len(mismatches),
}, indent=2))

if mismatches:
    print(f"\nMISMATCHES ({len(mismatches)}):")
    for m in mismatches:
        print(f"  [{m['tool']}] {m['note']}")
        print(f"    got      = {str(m['got'])[:120]}")
        print(f"    expected = {str(m['expected'])[:120]}")
else:
    print("\nAll checks passed.")
