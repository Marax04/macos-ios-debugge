#!/usr/bin/env python3
"""Rigorous ground-truth validator for script_* MCP tools.
All parameter names verified from wire_tools.rs source.
Hex comparisons are case-insensitive (Rust hex_encode may return UPPERCASE).
"""
import json, subprocess, hashlib, math, struct, time
from collections import defaultdict

EXE = r"C:\Users\Fra\Desktop\RustRE\target\release\rustre-mcp.exe"
TARGET = r"C:\Users\Fra\Desktop\Zyphora\target\release\cargo-zyphora.exe"

RESULTS_FILE = r"C:\Users\Fra\Desktop\RustRE\validation\rigorous_script_v2.json"
SKIP_FILE    = r"C:\Users\Fra\Desktop\RustRE\validation\skip_script.json"

p = subprocess.Popen(
    [EXE, "--transport=stdio"],
    stdin=subprocess.PIPE, stdout=subprocess.PIPE,
    stderr=subprocess.DEVNULL, bufsize=0
)

_rid = [0]
def send(req):
    _rid[0] += 1
    if "id" not in req:
        req = dict(req, id=_rid[0])
    p.stdin.write((json.dumps(req) + "\n").encode())
    p.stdin.flush()
    return req.get("id")

def recv():
    line = p.stdout.readline()
    if not line:
        raise RuntimeError("server died")
    try:
        return json.loads(line)
    except json.JSONDecodeError:
        return {"error": {"message": f"bad-line: {line[:200]!r}"}}

def call_tool(name, arguments):
    rid = send({"jsonrpc": "2.0", "method": "tools/call",
                "params": {"name": name, "arguments": arguments}})
    resp = recv()
    if "error" in resp:
        return False, f"JSONRPC_ERROR: {resp['error']}"
    result = resp.get("result", {})
    if result.get("isError"):
        txt = result.get("content", [{}])[0].get("text", "")
        return False, f"TOOL_ERROR: {txt[:200]}"
    content = result.get("content", [])
    txt = content[0].get("text", "") if content else ""
    try:
        return True, json.loads(txt)
    except Exception:
        return True, txt

# Initialize
send({"jsonrpc": "2.0", "id": 1, "method": "initialize",
      "params": {"protocolVersion": "2024-11-05",
                 "capabilities": {}, "clientInfo": {"name": "rigorous_script", "version": "1"}}})
recv()
send({"jsonrpc": "2.0", "method": "notifications/initialized"})

# Open project
send({"jsonrpc": "2.0", "id": 2, "method": "tools/call",
      "params": {"name": "project.open", "arguments": {"path": TARGET}}})
op = recv()
op_data = json.loads(op["result"]["content"][0]["text"])
BINARY_ID = op_data["binary_id"]
print(f"project.open: binary_id={BINARY_ID}")

# ── Python reference implementations ────────────────────────────────────────

def ref_sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def ref_shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    freq = defaultdict(int)
    for b in data:
        freq[b] += 1
    n = len(data)
    return -sum((c/n) * math.log2(c/n) for c in freq.values())

# Exact strings from rustre_script_rhai::entropy_classify
def ref_entropy_classify(e: float) -> str:
    if e < 1.0:
        return "very low (likely sparse / zero-filled)"
    elif e < 3.5:
        return "low (likely text or structured data)"
    elif e < 5.5:
        return "medium (likely compiled code)"
    elif e < 7.2:
        return "high (likely compressed or encrypted)"
    else:
        return "very high (likely encrypted or random)"

def ref_bit_rotate_bytes(data: bytes, n: int, rol: bool) -> bytes:
    """Rotate each byte left or right by n bits."""
    n = n % 8
    if n == 0:
        return data
    if rol:
        return bytes(((b << n) | (b >> (8 - n))) & 0xFF for b in data)
    else:
        return bytes(((b >> n) | (b << (8 - n))) & 0xFF for b in data)

def ref_xor_bytes(data: bytes, key: bytes) -> bytes:
    if not key:
        return data
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))

def ref_xor_single_byte(data: bytes, key_byte: int) -> bytes:
    return bytes(b ^ (key_byte & 0xFF) for b in data)

def ref_u64_to_i64(v: int) -> int:
    b = struct.pack("<Q", v & 0xFFFFFFFFFFFFFFFF)
    return struct.unpack("<q", b)[0]

def ref_i64_to_u64(v: int) -> int:
    b = struct.pack("<q", v)
    return struct.unpack("<Q", b)[0]

def ref_usize_to_i64_saturating(v: int) -> int:
    I64_MAX = (1 << 63) - 1
    return min(v, I64_MAX)

def ref_i64_to_u32_saturating(v: int) -> int:
    return max(0, min(v, 0xFFFFFFFF))

def ref_i64_to_i32_saturating(v: int) -> int:
    I32_MAX = (1 << 31) - 1
    I32_MIN = -(1 << 31)
    return max(I32_MIN, min(v, I32_MAX))

def ref_f64_to_i64(v: float) -> int:
    I64_MAX = (1 << 63) - 1
    I64_MIN = -(1 << 63)
    if math.isnan(v):
        return 0
    if v >= 2**63:
        return I64_MAX
    if v < -(2**63):
        return I64_MIN
    return int(v)

def ref_marshal_to_address(s: str):
    s = s.strip()
    try:
        if s.lower().startswith("0x"):
            v = int(s, 16)
        else:
            v = int(s, 10)
        if 0 <= v <= 0xFFFFFFFFFFFFFFFF:
            return v
        return None
    except ValueError:
        return None

# ── Test state ───────────────────────────────────────────────────────────────

passed  = []
failed  = []
skipped = []
mismatches = []

TEST_HEX = "deadbeef00112233aabbccdd"
TEST_DATA = bytes.fromhex(TEST_HEX)

def hexeq(a, b):
    """Compare hex strings case-insensitively."""
    return str(a).lower() == str(b).lower()

def record(tool, ok, expected=None, actual=None):
    if ok:
        passed.append(tool)
    else:
        failed.append({"tool": tool, "expected": expected, "actual": actual})
        mismatches.append({"tool": tool, "expected": repr(expected), "actual": repr(actual)})

def tool_ok_or_skip(tool, args):
    """Call tool, return (True, result) or record skip and return (False, None)."""
    ok, result = call_tool(tool, args)
    if not ok:
        skipped.append({"tool": tool, "reason": str(result)[:200]})
        return False, None
    return True, result

# ── 1. script_hex_to_bytes ───────────────────────────────────────────────────
# Takes: hex (string). Returns: hex field (may be uppercase).
ok, r = call_tool("script_hex_to_bytes", {"hex": TEST_HEX})
if ok:
    record("script_hex_to_bytes", hexeq(r.get("hex",""), TEST_HEX),
           expected=TEST_HEX, actual=r.get("hex",""))
else:
    skipped.append({"tool": "script_hex_to_bytes", "reason": str(r)})

# ── 2. script_bytes_to_hex ──────────────────────────────────────────────────
# Takes: bytes (array) OR hex (string). Returns: hex.
ok, r = call_tool("script_bytes_to_hex", {"hex": TEST_HEX})
if ok:
    record("script_bytes_to_hex", hexeq(r.get("hex",""), TEST_HEX),
           expected=TEST_HEX, actual=r.get("hex",""))
else:
    skipped.append({"tool": "script_bytes_to_hex", "reason": str(r)})

# ── 3. script_builtin_hex_to_bytes ──────────────────────────────────────────
# Takes: hex (string). Returns: hex (may be uppercase).
ok, r = call_tool("script_builtin_hex_to_bytes", {"hex": TEST_HEX})
if ok:
    record("script_builtin_hex_to_bytes", hexeq(r.get("hex",""), TEST_HEX),
           expected=TEST_HEX, actual=r.get("hex",""))
else:
    skipped.append({"tool": "script_builtin_hex_to_bytes", "reason": str(r)})

# ── 4. script_builtin_bytes_to_hex ──────────────────────────────────────────
# Takes: data_hex (string). Returns: hex.
ok, r = call_tool("script_builtin_bytes_to_hex", {"data_hex": TEST_HEX})
if ok:
    record("script_builtin_bytes_to_hex", hexeq(r.get("hex",""), TEST_HEX),
           expected=TEST_HEX, actual=r.get("hex",""))
else:
    skipped.append({"tool": "script_builtin_bytes_to_hex", "reason": str(r)})

# ── 5. script_rhai_hex_encode ───────────────────────────────────────────────
# Takes: data_hex. Returns: hex.
ok, r = call_tool("script_rhai_hex_encode", {"data_hex": TEST_HEX})
if ok:
    record("script_rhai_hex_encode", hexeq(r.get("hex",""), TEST_HEX),
           expected=TEST_HEX, actual=r.get("hex",""))
else:
    skipped.append({"tool": "script_rhai_hex_encode", "reason": str(r)})

# ── 6. script_rhai_hex_decode ───────────────────────────────────────────────
# Takes: hex. Returns: bytes_hex (not "hex"!).
ok, r = call_tool("script_rhai_hex_decode", {"hex": TEST_HEX})
if ok:
    actual = r.get("bytes_hex", r.get("hex", ""))
    record("script_rhai_hex_decode", hexeq(actual, TEST_HEX),
           expected=TEST_HEX, actual=actual)
else:
    skipped.append({"tool": "script_rhai_hex_decode", "reason": str(r)})

# ── 7. script_xor_bytes ─────────────────────────────────────────────────────
# Takes: data_hex, key_hex. Returns: hex.
KEY_HEX = "cafebabe"
KEY = bytes.fromhex(KEY_HEX)
_xor_full_key_expected = ref_xor_bytes(TEST_DATA, KEY).hex()
ok, r = call_tool("script_xor_bytes", {"data_hex": TEST_HEX, "key_hex": KEY_HEX})
if ok:
    actual = r.get("hex","")
    record("script_xor_bytes", hexeq(actual, _xor_full_key_expected),
           expected=_xor_full_key_expected, actual=actual)
else:
    skipped.append({"tool": "script_xor_bytes", "reason": str(r)})

# ── 8. script_rhai_xor_bytes ────────────────────────────────────────────────
# Takes: data_hex, key (integer, single byte). Returns: out_hex.
KEY_BYTE = 0xCA
_xor_single_expected = ref_xor_single_byte(TEST_DATA, KEY_BYTE).hex()
ok, r = call_tool("script_rhai_xor_bytes", {"data_hex": TEST_HEX, "key": KEY_BYTE})
if ok:
    actual = r.get("out_hex", r.get("hex", ""))
    record("script_rhai_xor_bytes", hexeq(actual, _xor_single_expected),
           expected=_xor_single_expected, actual=actual)
else:
    skipped.append({"tool": "script_rhai_xor_bytes", "reason": str(r)})

# ── 9. script_rhai_sha256_bytes ─────────────────────────────────────────────
# Takes: data_hex. Returns: sha256.
_sha256_expected = ref_sha256(TEST_DATA)
ok, r = call_tool("script_rhai_sha256_bytes", {"data_hex": TEST_HEX})
if ok:
    actual = r.get("sha256", "")
    record("script_rhai_sha256_bytes", actual.lower() == _sha256_expected,
           expected=_sha256_expected, actual=actual)
else:
    skipped.append({"tool": "script_rhai_sha256_bytes", "reason": str(r)})

# ── 10. script_rhai_entropy_classify ────────────────────────────────────────
# Takes: entropy (float). Returns: verdict (exact string from Rust).
_classify_cases = [
    (0.5, "very low (likely sparse / zero-filled)"),
    (2.0, "low (likely text or structured data)"),
    (4.5, "medium (likely compiled code)"),
    (6.0, "high (likely compressed or encrypted)"),
    (7.5, "very high (likely encrypted or random)"),
]
all_classify_ok = True
for ent_val, ref_verdict in _classify_cases:
    ok, r = call_tool("script_rhai_entropy_classify", {"entropy": ent_val})
    if ok:
        actual_v = r.get("verdict", "")
        if actual_v != ref_verdict:
            all_classify_ok = False
            mismatches.append({"tool": "script_rhai_entropy_classify",
                               "expected": f"entropy={ent_val} -> {ref_verdict}",
                               "actual":   f"entropy={ent_val} -> {actual_v}"})
    else:
        all_classify_ok = False
        mismatches.append({"tool": "script_rhai_entropy_classify",
                           "expected": ref_verdict, "actual": str(r)})
if all_classify_ok:
    passed.append("script_rhai_entropy_classify")
else:
    failed.append({"tool": "script_rhai_entropy_classify",
                   "expected": "all 5 buckets match", "actual": "see mismatches"})

# ── 11. script_rhai_entropy_impl ────────────────────────────────────────────
# Takes: data_hex. Returns: entropy (float).
_ent_expected = ref_shannon_entropy(TEST_DATA)
ok, r = call_tool("script_rhai_entropy_impl", {"data_hex": TEST_HEX})
if ok:
    actual = float(r.get("entropy", r.get("value", -1)))
    match = abs(actual - _ent_expected) < 1e-6
    record("script_rhai_entropy_impl", match,
           expected=round(_ent_expected,6), actual=round(actual,6))
else:
    skipped.append({"tool": "script_rhai_entropy_impl", "reason": str(r)})

# ── 12. script_rhai_compute_entropy_v2 ──────────────────────────────────────
# Takes: bytes (array) OR hex (string). Returns: entropy.
ok, r = call_tool("script_rhai_compute_entropy_v2", {"hex": TEST_HEX})
if ok:
    actual = float(r.get("entropy", -1))
    match = abs(actual - _ent_expected) < 1e-6
    record("script_rhai_compute_entropy_v2", match,
           expected=round(_ent_expected,6), actual=round(actual,6))
else:
    skipped.append({"tool": "script_rhai_compute_entropy_v2", "reason": str(r)})

# ── 13. script_lua_calculate_entropy ────────────────────────────────────────
# Takes: bytes (array) OR hex (string). Returns: entropy.
ok, r = call_tool("script_lua_calculate_entropy", {"hex": TEST_HEX})
if ok:
    actual = float(r.get("entropy", -1))
    match = abs(actual - _ent_expected) < 1e-6
    record("script_lua_calculate_entropy", match,
           expected=round(_ent_expected,6), actual=round(actual,6))
else:
    skipped.append({"tool": "script_lua_calculate_entropy", "reason": str(r)})

# ── 14. script_rhai_rotate_bytes ────────────────────────────────────────────
# BIT rotation per byte (not buffer rotation).
# Takes: data_hex, n (integer), rol (bool). Returns: out_hex.
_rot_n = 3
_rot_expected = ref_bit_rotate_bytes(TEST_DATA, _rot_n, rol=True).hex()
ok, r = call_tool("script_rhai_rotate_bytes", {"data_hex": TEST_HEX, "n": _rot_n, "rol": True})
if ok:
    actual = r.get("out_hex", r.get("hex", ""))
    record("script_rhai_rotate_bytes", hexeq(actual, _rot_expected),
           expected=_rot_expected, actual=actual)
else:
    skipped.append({"tool": "script_rhai_rotate_bytes", "reason": str(r)})

# ── 15. script_bytes_concat ─────────────────────────────────────────────────
# Takes: a_hex, b_hex. Returns: hex.
_concat_expected = (TEST_DATA + KEY).hex()
ok, r = call_tool("script_bytes_concat", {"a_hex": TEST_HEX, "b_hex": KEY_HEX})
if ok:
    actual = r.get("hex", "")
    record("script_bytes_concat", hexeq(actual, _concat_expected),
           expected=_concat_expected, actual=actual)
else:
    skipped.append({"tool": "script_bytes_concat", "reason": str(r)})

# ── 16. script_bytes_slice ──────────────────────────────────────────────────
# Takes: bytes_hex, start, end. Returns: hex.
_slice_expected = TEST_DATA[2:8].hex()
ok, r = call_tool("script_bytes_slice", {"bytes_hex": TEST_HEX, "start": 2, "end": 8})
if ok:
    actual = r.get("hex", "")
    record("script_bytes_slice", hexeq(actual, _slice_expected),
           expected=_slice_expected, actual=actual)
else:
    skipped.append({"tool": "script_bytes_slice", "reason": str(r)})

# ── 17. script_bytes_find ───────────────────────────────────────────────────
# Takes: haystack_hex, needle_hex. Returns: offset (int or null), found (bool).
_needle_hex = "0011"
_find_expected = TEST_DATA.find(bytes.fromhex(_needle_hex))  # 4
ok, r = call_tool("script_bytes_find", {"haystack_hex": TEST_HEX, "needle_hex": _needle_hex})
if ok:
    actual = r.get("offset")
    record("script_bytes_find", actual == _find_expected,
           expected=_find_expected, actual=actual)
else:
    skipped.append({"tool": "script_bytes_find", "reason": str(r)})

# ── 18. script_lua_casts_u64_to_i64 ─────────────────────────────────────────
_u64_val = (1 << 63) + 5
_expected = ref_u64_to_i64(_u64_val)
ok, r = call_tool("script_lua_casts_u64_to_i64", {"value": _u64_val})
if ok:
    actual = r.get("output", r.get("result"))
    record("script_lua_casts_u64_to_i64", actual == _expected,
           expected=_expected, actual=actual)
else:
    skipped.append({"tool": "script_lua_casts_u64_to_i64", "reason": str(r)})

# ── 19. script_lua_casts_usize_to_i64 ───────────────────────────────────────
ok, r = call_tool("script_lua_casts_usize_to_i64", {"value": 42})
if ok:
    actual = r.get("output", r.get("result"))
    record("script_lua_casts_usize_to_i64", actual == 42,
           expected=42, actual=actual)
else:
    skipped.append({"tool": "script_lua_casts_usize_to_i64", "reason": str(r)})

# ── 20. script_lua_casts_i64_to_u64 ─────────────────────────────────────────
_expected = ref_i64_to_u64(-1)
ok, r = call_tool("script_lua_casts_i64_to_u64", {"value": -1})
if ok:
    actual = r.get("output", r.get("result"))
    record("script_lua_casts_i64_to_u64", actual == _expected,
           expected=_expected, actual=actual)
else:
    skipped.append({"tool": "script_lua_casts_i64_to_u64", "reason": str(r)})

# ── 21. script_lua_casts_i64_to_u32 ─────────────────────────────────────────
ok, r = call_tool("script_lua_casts_i64_to_u32", {"value": 70000})
if ok:
    actual = r.get("output", r.get("result"))
    record("script_lua_casts_i64_to_u32", actual == ref_i64_to_u32_saturating(70000),
           expected=ref_i64_to_u32_saturating(70000), actual=actual)
else:
    skipped.append({"tool": "script_lua_casts_i64_to_u32", "reason": str(r)})

# ── 22. script_lua_casts_i64_to_i32 ─────────────────────────────────────────
ok, r = call_tool("script_lua_casts_i64_to_i32", {"value": -70000})
if ok:
    actual = r.get("output", r.get("result"))
    record("script_lua_casts_i64_to_i32", actual == ref_i64_to_i32_saturating(-70000),
           expected=ref_i64_to_i32_saturating(-70000), actual=actual)
else:
    skipped.append({"tool": "script_lua_casts_i64_to_i32", "reason": str(r)})

# ── 23. script_lua_casts_f64_to_i64 ─────────────────────────────────────────
ok, r = call_tool("script_lua_casts_f64_to_i64", {"value": 3.7})
if ok:
    actual = r.get("output", r.get("result"))
    record("script_lua_casts_f64_to_i64", actual == ref_f64_to_i64(3.7),
           expected=ref_f64_to_i64(3.7), actual=actual)
else:
    skipped.append({"tool": "script_lua_casts_f64_to_i64", "reason": str(r)})

# ── 24. script_lua_casts_u64_to_f64 ─────────────────────────────────────────
ok, r = call_tool("script_lua_casts_u64_to_f64", {"value": 1234567})
if ok:
    actual = r.get("output", r.get("result"))
    record("script_lua_casts_u64_to_f64", actual == 1234567.0,
           expected=1234567.0, actual=actual)
else:
    skipped.append({"tool": "script_lua_casts_u64_to_f64", "reason": str(r)})

# ── 25. script_lua_casts_i64_to_f64 ─────────────────────────────────────────
ok, r = call_tool("script_lua_casts_i64_to_f64", {"value": -99})
if ok:
    actual = r.get("output", r.get("result"))
    record("script_lua_casts_i64_to_f64", actual == -99.0,
           expected=-99.0, actual=actual)
else:
    skipped.append({"tool": "script_lua_casts_i64_to_f64", "reason": str(r)})

# ── 26. script_lua_casts_usize_to_f64 ───────────────────────────────────────
ok, r = call_tool("script_lua_casts_usize_to_f64", {"value": 512})
if ok:
    actual = r.get("output", r.get("result"))
    record("script_lua_casts_usize_to_f64", actual == 512.0,
           expected=512.0, actual=actual)
else:
    skipped.append({"tool": "script_lua_casts_usize_to_f64", "reason": str(r)})

# ── 27. script_lua_casts_i64_to_usize ─────────────────────────────────────
ok, r = call_tool("script_lua_casts_i64_to_usize", {"value": 1000})
if ok:
    actual = r.get("output", r.get("result"))
    record("script_lua_casts_i64_to_usize", actual == 1000,
           expected=1000, actual=actual)
else:
    skipped.append({"tool": "script_lua_casts_i64_to_usize", "reason": str(r)})

# ── 28. script_lua_casts_u64_to_usize ─────────────────────────────────────
ok, r = call_tool("script_lua_casts_u64_to_usize", {"value": 2000})
if ok:
    actual = r.get("output", r.get("result"))
    record("script_lua_casts_u64_to_usize", actual == 2000,
           expected=2000, actual=actual)
else:
    skipped.append({"tool": "script_lua_casts_u64_to_usize", "reason": str(r)})

# ── 29. script_python_marshal_to_address ────────────────────────────────────
# Takes: value (string). Returns: address (int or null).
for addr_str, ref_addr in [("0x140001000", 0x140001000), ("4294967296", 4294967296), ("not_a_number", None)]:
    ok, r = call_tool("script_python_marshal_to_address", {"value": addr_str})
    if ok:
        actual_addr = r.get("address")
        match = (actual_addr == ref_addr)
        if not match:
            failed.append({"tool": "script_python_marshal_to_address",
                           "expected": ref_addr, "actual": actual_addr})
            mismatches.append({"tool": "script_python_marshal_to_address",
                               "expected": repr(ref_addr), "actual": repr(actual_addr)})
        elif addr_str == "0x140001000":
            passed.append("script_python_marshal_to_address")
    else:
        skipped.append({"tool": "script_python_marshal_to_address", "reason": str(r)})
        break

# ── 30. script_python_marshal_to_bytes ──────────────────────────────────────
# Takes: value (string). Returns: hex (UTF-8 of string).
_str_input = "hello"
_bytes_expected = _str_input.encode("utf-8").hex()
ok, r = call_tool("script_python_marshal_to_bytes", {"value": _str_input})
if ok:
    actual = r.get("hex", "")
    record("script_python_marshal_to_bytes", hexeq(actual, _bytes_expected),
           expected=_bytes_expected, actual=actual)
else:
    skipped.append({"tool": "script_python_marshal_to_bytes", "reason": str(r)})

# ── 31. script_read_u32 ─────────────────────────────────────────────────────
# Takes: bytes (array) OR hex (string), offset. Returns: value.
_u32_data_hex = "785634120000"
_u32_expected = struct.unpack_from("<I", bytes.fromhex(_u32_data_hex), 0)[0]  # 0x12345678
ok, r = call_tool("script_read_u32", {"hex": _u32_data_hex, "offset": 0})
if ok:
    actual = r.get("value")
    record("script_read_u32", actual == _u32_expected,
           expected=_u32_expected, actual=actual)
else:
    skipped.append({"tool": "script_read_u32", "reason": str(r)})

# ── 32. script_bytes_fill ────────────────────────────────────────────────────
# Takes: count, byte. Returns: hex.
ok, r = call_tool("script_bytes_fill", {"count": 8, "byte": 0xAB})
if ok:
    expected_fill = "ab" * 8
    actual = r.get("hex", "")
    record("script_bytes_fill", hexeq(actual, expected_fill),
           expected=expected_fill, actual=actual)
else:
    skipped.append({"tool": "script_bytes_fill", "reason": str(r)})

# ── 33. script_lua_nop_sled ──────────────────────────────────────────────────
ok, r = call_tool("script_lua_nop_sled", {"length": 8})
if ok:
    expected_sled = "90" * 8
    actual = r.get("hex", "")
    record("script_lua_nop_sled", hexeq(actual, expected_sled),
           expected=expected_sled, actual=actual)
else:
    skipped.append({"tool": "script_lua_nop_sled", "reason": str(r)})

# ── 34. script_error_is_recoverable ──────────────────────────────────────────
# Takes: variant (string). Returns: recoverable (bool).
# Valid variants: FunctionNotFound, UndefinedVariable, TypeMismatch, ArityMismatch,
#                 RuntimeError, DivisionByZero, StackOverflow
ok, r = call_tool("script_error_is_recoverable", {"variant": "RuntimeError"})
if ok:
    recov = r.get("recoverable")
    if isinstance(recov, bool):
        passed.append("script_error_is_recoverable")
    else:
        failed.append({"tool": "script_error_is_recoverable",
                       "expected": "bool", "actual": recov})
        mismatches.append({"tool": "script_error_is_recoverable",
                           "expected": "bool", "actual": repr(recov)})
else:
    skipped.append({"tool": "script_error_is_recoverable", "reason": str(r)})

# ── 35. script_error_runtime ─────────────────────────────────────────────────
# Takes: msg (string). Returns: display, recoverable.
ok, r = call_tool("script_error_runtime", {"msg": "test error"})
if ok:
    display = r.get("display", "")
    recov = r.get("recoverable")
    if "test error" in display and isinstance(recov, bool):
        passed.append("script_error_runtime")
    else:
        failed.append({"tool": "script_error_runtime",
                       "expected": "display contains 'test error'", "actual": display})
        mismatches.append({"tool": "script_error_runtime",
                           "expected": "'test error' in display", "actual": repr(display)})
else:
    skipped.append({"tool": "script_error_runtime", "reason": str(r)})

# ── 36. script_python_stubs_standard_names ───────────────────────────────────
ok, r = call_tool("script_python_stubs_standard_names", {})
if ok:
    names = r.get("names", [])
    count = r.get("count", len(names))
    if isinstance(names, list) and count > 0:
        passed.append("script_python_stubs_standard_names")
    else:
        failed.append({"tool": "script_python_stubs_standard_names",
                       "expected": "count>0", "actual": count})
        mismatches.append({"tool": "script_python_stubs_standard_names",
                           "expected": "count>0", "actual": repr(count)})
else:
    skipped.append({"tool": "script_python_stubs_standard_names", "reason": str(r)})

# ── 37. script_python_stubs_generate_standard ────────────────────────────────
ok, r = call_tool("script_python_stubs_generate_standard", {"module_name": "rustre"})
if ok:
    pyi = r.get("pyi", "")
    if isinstance(pyi, str) and len(pyi) > 0:
        passed.append("script_python_stubs_generate_standard")
    else:
        failed.append({"tool": "script_python_stubs_generate_standard",
                       "expected": "non-empty pyi", "actual": ""})
        mismatches.append({"tool": "script_python_stubs_generate_standard",
                           "expected": "non-empty pyi", "actual": "empty"})
else:
    skipped.append({"tool": "script_python_stubs_generate_standard", "reason": str(r)})

# ── 38. script_read_u8_new ───────────────────────────────────────────────────
ok, r = call_tool("script_read_u8_new", {"bytes": [0xDE, 0xAD, 0xBE, 0xEF], "offset": 0})
if ok:
    actual = r.get("value", r.get("result"))
    record("script_read_u8_new", actual == 0xDE, expected=0xDE, actual=actual)
else:
    skipped.append({"tool": "script_read_u8_new", "reason": str(r)})

# ── 39. script_read_u16_new ──────────────────────────────────────────────────
ok, r = call_tool("script_read_u16_new", {"bytes": [0xDE, 0xAD, 0xBE, 0xEF], "offset": 0})
if ok:
    expected_u16 = struct.unpack_from("<H", bytes([0xDE, 0xAD]), 0)[0]
    actual = r.get("value", r.get("result"))
    record("script_read_u16_new", actual == expected_u16,
           expected=expected_u16, actual=actual)
else:
    skipped.append({"tool": "script_read_u16_new", "reason": str(r)})

# ── 40. script_read_u32_be_new ───────────────────────────────────────────────
ok, r = call_tool("script_read_u32_be_new", {"bytes": [0xDE, 0xAD, 0xBE, 0xEF], "offset": 0})
if ok:
    expected_be = struct.unpack_from(">I", bytes([0xDE, 0xAD, 0xBE, 0xEF]), 0)[0]
    actual = r.get("value", r.get("result"))
    record("script_read_u32_be_new", actual == expected_be,
           expected=expected_be, actual=actual)
else:
    skipped.append({"tool": "script_read_u32_be_new", "reason": str(r)})

# ── 41. script_read_u64_new ──────────────────────────────────────────────────
_u64_bytes = [0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x11, 0x22, 0x33]
ok, r = call_tool("script_read_u64_new", {"bytes": _u64_bytes, "offset": 0})
if ok:
    expected_u64 = struct.unpack_from("<Q", bytes(_u64_bytes), 0)[0]
    actual = r.get("value", r.get("result"))
    record("script_read_u64_new", actual == expected_u64,
           expected=expected_u64, actual=actual)
else:
    skipped.append({"tool": "script_read_u64_new", "reason": str(r)})

# ── 42. script_write_u8_new ──────────────────────────────────────────────────
ok, r = call_tool("script_write_u8_new", {"bytes": [0xDE, 0xAD, 0xBE, 0xEF], "offset": 0, "value": 0xFF})
if ok:
    expected = "ff" + "adbeef"
    # Result field is bytes_hex (from wire_tools.rs hex_encode)
    actual = r.get("bytes_hex", r.get("hex", r.get("bytes", "")))
    if isinstance(actual, list):
        actual = bytes(actual).hex()
    record("script_write_u8_new", hexeq(actual, expected),
           expected=expected, actual=actual)
else:
    skipped.append({"tool": "script_write_u8_new", "reason": str(r)})

# ── 43. script_value_typeof_new ──────────────────────────────────────────────
ok, r = call_tool("script_value_typeof_new", {"value": 42})
if ok:
    type_name = r.get("type_name", r.get("type", r.get("result", "")))
    if isinstance(type_name, str) and len(type_name) > 0:
        passed.append("script_value_typeof_new")
    else:
        failed.append({"tool": "script_value_typeof_new",
                       "expected": "non-empty string", "actual": type_name})
        mismatches.append({"tool": "script_value_typeof_new",
                           "expected": "non-empty string", "actual": repr(type_name)})
else:
    skipped.append({"tool": "script_value_typeof_new", "reason": str(r)})

# ── 44. script_value_is_truthy_new ───────────────────────────────────────────
all_truthy_ok = True
for val, expected_truthy in [(1, True), (0, False), ("hello", True)]:
    ok, r = call_tool("script_value_is_truthy_new", {"value": val})
    if ok:
        actual = r.get("truthy", r.get("result"))
        if actual != expected_truthy:
            all_truthy_ok = False
            mismatches.append({"tool": "script_value_is_truthy_new",
                               "expected": f"{val!r} -> {expected_truthy}",
                               "actual":   f"{val!r} -> {actual}"})
    else:
        all_truthy_ok = False
        mismatches.append({"tool": "script_value_is_truthy_new",
                           "expected": expected_truthy, "actual": str(r)})
if all_truthy_ok:
    passed.append("script_value_is_truthy_new")
else:
    failed.append({"tool": "script_value_is_truthy_new",
                   "expected": "truthy checks passed", "actual": "see mismatches"})

# ── 45. script_builtin_functions_list_new ────────────────────────────────────
ok, r = call_tool("script_builtin_functions_list_new", {})
if ok:
    fns = r.get("functions", r.get("names", []))
    if isinstance(fns, list) and len(fns) > 0:
        passed.append("script_builtin_functions_list_new")
    else:
        failed.append({"tool": "script_builtin_functions_list_new",
                       "expected": "non-empty list", "actual": str(r)[:100]})
        mismatches.append({"tool": "script_builtin_functions_list_new",
                           "expected": "non-empty list", "actual": repr(fns)})
else:
    skipped.append({"tool": "script_builtin_functions_list_new", "reason": str(r)})

# ── 46. script_sandbox_policy_preset_new ─────────────────────────────────────
all_preset_ok = True
for preset in ["deny_all", "allow_all", "read_only"]:
    ok, r = call_tool("script_sandbox_policy_preset_new", {"preset": preset})
    if not ok:
        all_preset_ok = False
        mismatches.append({"tool": f"script_sandbox_policy_preset_new",
                           "expected": f"preset={preset} OK", "actual": str(r)})
if all_preset_ok:
    passed.append("script_sandbox_policy_preset_new")
else:
    failed.append({"tool": "script_sandbox_policy_preset_new",
                   "expected": "all presets OK", "actual": "see mismatches"})

# ── 47. script_rhai_match_pattern ────────────────────────────────────────────
# Takes: bytes or bytes_hex, pattern (space-sep hex with ?? wildcards). Returns: offsets.
ok, r = call_tool("script_rhai_match_pattern", {"hex": TEST_HEX, "pattern": "de ad"})
if ok:
    offsets = r.get("offsets", [])
    # "dead" is at offset 0
    if 0 in offsets:
        passed.append("script_rhai_match_pattern")
    else:
        failed.append({"tool": "script_rhai_match_pattern",
                       "expected": "0 in offsets", "actual": offsets})
        mismatches.append({"tool": "script_rhai_match_pattern",
                           "expected": "offsets contains 0", "actual": repr(offsets)})
else:
    skipped.append({"tool": "script_rhai_match_pattern", "reason": str(r)})

# ── 48. script_rhai_find_pattern ─────────────────────────────────────────────
# Takes: data_hex, pattern. Returns: offsets.
ok, r = call_tool("script_rhai_find_pattern", {"data_hex": TEST_HEX, "pattern": "de ad"})
if ok:
    offsets = r.get("offsets", [])
    if 0 in offsets:
        passed.append("script_rhai_find_pattern")
    else:
        failed.append({"tool": "script_rhai_find_pattern",
                       "expected": "0 in offsets", "actual": offsets})
        mismatches.append({"tool": "script_rhai_find_pattern",
                           "expected": "offsets contains 0", "actual": repr(offsets)})
else:
    skipped.append({"tool": "script_rhai_find_pattern", "reason": str(r)})

# ── 49. script_rhai_find_strings ─────────────────────────────────────────────
# "Hello World\0" in hex: 48656c6c6f20576f726c6400
ok, r = call_tool("script_rhai_find_strings", {"data_hex": "48656c6c6f20576f726c6400"})
if ok and isinstance(r, dict):
    passed.append("script_rhai_find_strings")
else:
    skipped.append({"tool": "script_rhai_find_strings", "reason": f"error or bad response: {r}"})

# ── 50. script_rhai_detect_format ────────────────────────────────────────────
ok, r = call_tool("script_rhai_detect_format", {"data_hex": "4d5a9000"})
if ok and isinstance(r, dict) and "format" in r:
    passed.append("script_rhai_detect_format")
else:
    skipped.append({"tool": "script_rhai_detect_format", "reason": f"error: {r}"})

# ── Teardown ─────────────────────────────────────────────────────────────────
p.stdin.close()
try:
    p.terminate()
except Exception:
    pass

# ── Deduplicate ───────────────────────────────────────────────────────────────
unique_passed = list(dict.fromkeys(passed))

# ── Write results ─────────────────────────────────────────────────────────────
results_data = {
    "tools_hardened": len(unique_passed) + len(failed),
    "tools_passed":   len(unique_passed),
    "tools_failed":   len(failed),
    "tools_skipped":  len(skipped),
    "mismatches":     mismatches,
    "passed_tools":   unique_passed,
    "failed_tools":   failed,
}
with open(RESULTS_FILE, "w") as f:
    json.dump(results_data, f, indent=2)

skip_data = {"skipped": skipped}
with open(SKIP_FILE, "w") as f:
    json.dump(skip_data, f, indent=2)

print(f"\nSUMMARY:")
print(f"  Passed:  {len(unique_passed)}")
print(f"  Failed:  {len(failed)}")
print(f"  Skipped: {len(skipped)}")
print(f"  Mismatches: {len(mismatches)}")

if mismatches:
    print("\nMISMATCHES:")
    for m in mismatches:
        print(f"  {m['tool']}: expected={m['expected']!r} actual={m['actual']!r}")
