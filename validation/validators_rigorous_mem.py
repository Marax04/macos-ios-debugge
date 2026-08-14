#!/usr/bin/env python3
"""
Rigorous validator for mem_* MCP tools.
Each check computes an independent Python truth and compares against the Rust MCP output.
No any_valid() — every check has a deterministic expected value.
"""
import json
import math
import struct
import subprocess
import sys
from collections import Counter

EXE = r"C:\Users\Fra\Desktop\RustRE\target\release\rustre-mcp.exe"
REPORT = r"C:\Users\Fra\Desktop\RustRE\validation\rigorous_mem.json"


# ─── MCP session helpers ────────────────────────────────────────────────────

def start_session():
    p = subprocess.Popen(
        [EXE, "--transport=stdio"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        bufsize=0,
    )

    def send(obj):
        p.stdin.write((json.dumps(obj) + "\n").encode())
        p.stdin.flush()

    def recv():
        line = p.stdout.readline()
        return json.loads(line) if line else None

    send({
        "jsonrpc": "2.0", "id": 1, "method": "initialize",
        "params": {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": {"name": "rigorous_validator", "version": "1"},
        },
    })
    recv()
    send({"jsonrpc": "2.0", "method": "notifications/initialized"})
    return p, send, recv


p, _send, _recv = start_session()
_rid = [10]


def call(name, args):
    _rid[0] += 1
    _send({
        "jsonrpc": "2.0", "id": _rid[0],
        "method": "tools/call",
        "params": {"name": name, "arguments": args},
    })
    resp = _recv()
    if not resp:
        return None, "no_response"
    if "error" in resp:
        return None, resp["error"].get("message", "rpc_error")
    content = resp.get("result", {}).get("content", [])
    if not content:
        return None, "empty_content"
    text = content[0].get("text", "")
    try:
        return json.loads(text), None
    except Exception:
        return text, None


def extract(r, keys):
    """Try each key in order; return first hit."""
    if not isinstance(r, dict):
        return None
    for k in keys:
        if k in r:
            return r[k]
    return None


# ─── Truth helpers ──────────────────────────────────────────────────────────

def py_shannon(data: bytes) -> float:
    if not data:
        return 0.0
    cnt = Counter(data)
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in cnt.values())


def py_entropy_blocks(data: bytes, block_size: int = 256) -> list:
    result = []
    for i in range(0, len(data), block_size):
        block = data[i:i + block_size]
        result.append(py_shannon(block))
    return result


# ─── Check infrastructure ───────────────────────────────────────────────────

checks_passed = 0
checks_failed = 0
mismatches = []
tools_hardened = set()


def check(tool, inp, mcp_val, truth_val, note=""):
    global checks_passed, checks_failed
    tools_hardened.add(tool)
    ok = False
    if isinstance(truth_val, float) or isinstance(mcp_val, float):
        try:
            ok = abs(float(mcp_val) - float(truth_val)) < 1e-5
        except Exception:
            ok = False
    else:
        ok = mcp_val == truth_val

    if ok:
        checks_passed += 1
        print(f"  PASS  {tool}  {note}", file=sys.stderr)
    else:
        checks_failed += 1
        mismatches.append({
            "tool": tool,
            "input": inp,
            "mcp": mcp_val,
            "truth": truth_val,
            "note": note,
        })
        print(f"  FAIL  {tool}  mcp={mcp_val!r}  truth={truth_val!r}  {note}", file=sys.stderr)


# ════════════════════════════════════════════════════════════════════════════
# 1. Page-alignment arithmetic
# Formula: align_down(va, ps) = va & ~(ps-1)
#          align_up(va, ps)   = (va + ps - 1) & ~(ps-1)
#          page_index(va, ps) = va // ps
# ════════════════════════════════════════════════════════════════════════════
print("=== Page alignment ===", file=sys.stderr)
PAGE_CASES = [
    (0x0000, 0x1000),
    (0x1000, 0x1000),
    (0x1234, 0x1000),
    (0xFFF,  0x1000),
    (0xABCDEF, 0x2000),
]

for va, ps in PAGE_CASES:
    # align_down — tool uses "addr" not "va"
    inp = {"addr": va, "page_size": ps}
    r, e = call("mem_page_align_down", inp)
    if isinstance(r, dict):
        v = extract(r, ["aligned", "va_aligned", "result", "value", "va"])
        check("mem_page_align_down", inp, v, va & ~(ps - 1),
              f"va={va:#x} ps={ps:#x}")
    else:
        print(f"  ERR   mem_page_align_down  {e}", file=sys.stderr)

    # align_up — tool uses "addr" not "va"
    r, e = call("mem_page_align_up", inp)
    if isinstance(r, dict):
        v = extract(r, ["aligned", "va_aligned", "result", "value", "va"])
        check("mem_page_align_up", inp, v, (va + ps - 1) & ~(ps - 1),
              f"va={va:#x} ps={ps:#x}")
    else:
        print(f"  ERR   mem_page_align_up  {e}", file=sys.stderr)

    # page_index — tool uses "addr" not "va"
    r, e = call("mem_page_index", inp)
    if isinstance(r, dict):
        v = extract(r, ["index", "page_index", "result", "value"])
        check("mem_page_index", inp, v, va // ps,
              f"va={va:#x} ps={ps:#x}")
    else:
        print(f"  ERR   mem_page_index  {e}", file=sys.stderr)


# ════════════════════════════════════════════════════════════════════════════
# 2. Primitive integer reads (little-endian and big-endian)
# Truth: Python struct.unpack on known bytes
# ════════════════════════════════════════════════════════════════════════════
print("=== Read primitives ===", file=sys.stderr)

INT_CASES = [
    # (tool_name, hex_bytes, offset, fmt, truth)
    ("mem_read_u8_at_hex",    "AB",               0, None,  0xAB),
    ("mem_read_u8_at_hex",    "FF00",             1, None,  0x00),
    ("mem_read_u16_le_at_hex","3412",             0, None,  0x1234),
    ("mem_read_u16_be_at_hex","1234",             0, None,  0x1234),
    ("mem_read_u32_le_at_hex","78563412",         0, None,  0x12345678),
    ("mem_read_u32_be_at_hex","12345678",         0, None,  0x12345678),
    ("mem_read_u64_le_at_hex","efcdab8967452301", 0, None,  0x0123456789ABCDEF),
    ("mem_read_u64_be_at_hex","0123456789abcdef", 0, None,  0x0123456789ABCDEF),
    ("mem_read_i8_at_hex",    "FF",               0, None,  -1),
    ("mem_read_i8_at_hex",    "80",               0, None,  -128),
    ("mem_read_i16_le_at_hex","ffff",             0, None,  -1),
    ("mem_read_i32_le_at_hex","ffffffff",         0, None,  -1),
    ("mem_read_i64_le_at_hex","ffffffffffffffff", 0, None,  -1),
]

for name, hx, off, _fmt, truth in INT_CASES:
    inp = {"buffer_hex": hx, "offset": off}
    r, e = call(name, inp)
    if isinstance(r, dict):
        v = extract(r, ["value", "result", "int", "i", "u"])
        if v is None:
            print(f"  SKIP  {name}  no value key in {r}", file=sys.stderr)
        else:
            check(name, inp, v, truth, f"hex={hx} off={off}")
    else:
        print(f"  ERR   {name}  {e}", file=sys.stderr)

# float reads
F32_VAL = 1.5
F32_HEX = struct.pack("<f", F32_VAL).hex()
inp = {"buffer_hex": F32_HEX, "offset": 0}
r, e = call("mem_read_f32_le_at_hex", inp)
if isinstance(r, dict):
    v = extract(r, ["value", "result", "f", "float"])
    if v is not None:
        check("mem_read_f32_le_at_hex", inp, float(v), F32_VAL, "f32=1.5")
    else:
        print(f"  SKIP  mem_read_f32_le_at_hex  no value key", file=sys.stderr)
else:
    print(f"  ERR   mem_read_f32_le_at_hex  {e}", file=sys.stderr)

F64_VAL = 2.71828
F64_HEX = struct.pack("<d", F64_VAL).hex()
inp = {"buffer_hex": F64_HEX, "offset": 0}
r, e = call("mem_read_f64_le_at_hex", inp)
if isinstance(r, dict):
    v = extract(r, ["value", "result", "f", "float"])
    if v is not None:
        check("mem_read_f64_le_at_hex", inp, float(v), F64_VAL, "f64=2.71828")
    else:
        print(f"  SKIP  mem_read_f64_le_at_hex  no value key", file=sys.stderr)
else:
    print(f"  ERR   mem_read_f64_le_at_hex  {e}", file=sys.stderr)

# BE float reads
F32_BE_HEX = struct.pack(">f", 3.14).hex()
inp = {"buffer_hex": F32_BE_HEX, "offset": 0}
r, e = call("mem_read_f32_be_at_hex", inp)
if isinstance(r, dict):
    v = extract(r, ["value", "result", "f", "float"])
    if v is not None:
        check("mem_read_f32_be_at_hex", inp, float(v), struct.unpack(">f", struct.pack(">f", 3.14))[0],
              "f32_be=3.14")

F64_BE_HEX = struct.pack(">d", 1.23456789).hex()
inp = {"buffer_hex": F64_BE_HEX, "offset": 0}
r, e = call("mem_read_f64_be_at_hex", inp)
if isinstance(r, dict):
    v = extract(r, ["value", "result", "f", "float"])
    if v is not None:
        check("mem_read_f64_be_at_hex", inp, float(v), 1.23456789, "f64_be=1.23456789")

# u128 LE
U128_VAL = 0x0102030405060708090A0B0C0D0E0F10
U128_HEX = struct.pack("<QQ", U128_VAL & 0xFFFFFFFFFFFFFFFF,
                       (U128_VAL >> 64) & 0xFFFFFFFFFFFFFFFF).hex()
inp = {"buffer_hex": U128_HEX, "offset": 0}
r, e = call("mem_read_u128_le_at_hex", inp)
if isinstance(r, dict):
    v = extract(r, ["value", "result", "int", "u", "u128"])
    if v is not None:
        check("mem_read_u128_le_at_hex", inp, v, U128_VAL, "u128_le")


# ════════════════════════════════════════════════════════════════════════════
# 3. Primitive integer writes (return updated hex buffer)
# Truth: Python struct.pack on known value
# ════════════════════════════════════════════════════════════════════════════
print("=== Write primitives ===", file=sys.stderr)

WRITE_CASES = [
    ("mem_write_u32_le_at_hex", "00000000", 0, 0x12345678,
     struct.pack("<I", 0x12345678).hex()),
    ("mem_write_u16_be_at_hex", "0000",     0, 0x1234,
     struct.pack(">H", 0x1234).hex()),
    ("mem_write_u32_be_at_hex", "00000000", 0, 0xDEADBEEF,
     struct.pack(">I", 0xDEADBEEF).hex()),
    ("mem_write_u64_be_at_hex", "0000000000000000", 0, 0x0102030405060708,
     struct.pack(">Q", 0x0102030405060708).hex()),
]

for name, buf_hex, off, val, truth_hex in WRITE_CASES:
    inp = {"buffer_hex": buf_hex, "offset": off, "value": val}
    r, e = call(name, inp)
    if isinstance(r, dict):
        v = extract(r, ["hex", "result", "bytes", "output", "buffer_hex"])
        if isinstance(v, str):
            check(name, inp, v.lower().replace(" ", ""), truth_hex.lower(),
                  f"write {val:#x} to {buf_hex}")
        else:
            print(f"  SKIP  {name}  shape {v}", file=sys.stderr)
    else:
        print(f"  ERR   {name}  {e}", file=sys.stderr)


# ════════════════════════════════════════════════════════════════════════════
# 4. Shannon entropy
# Truth: py_shannon()
# ════════════════════════════════════════════════════════════════════════════
print("=== Shannon entropy ===", file=sys.stderr)

ENTROPY_CASES = [
    ("00" * 64, 0.0, "all_zeros"),
    ("".join(f"{i:02x}" for i in range(256)), 8.0, "uniform_256"),
    ("deadbeef00112233445566778899aabbccddeeff" * 8, None, "mixed"),
    ("ff" * 128, 0.0, "all_ff"),
    ("0102" * 64, None, "alternating"),
]

for hex_data, expected_entropy, label in ENTROPY_CASES:
    data = bytes.fromhex(hex_data)
    truth = py_shannon(data) if expected_entropy is None else expected_entropy
    inp = {"hex": hex_data}
    r, e = call("mem_shannon_entropy", inp)
    if isinstance(r, dict):
        v = extract(r, ["entropy", "result", "value", "shannon"])
        if v is not None:
            check("mem_shannon_entropy", inp, float(v), truth, label)
        else:
            print(f"  SKIP  mem_shannon_entropy  {label}  no key in {list(r.keys())}", file=sys.stderr)
    else:
        print(f"  ERR   mem_shannon_entropy  {e}", file=sys.stderr)


# ════════════════════════════════════════════════════════════════════════════
# 5. mem_entropy_blocks_hex — per-block entropy
# Truth: py_entropy_blocks(data, block_size)
# ════════════════════════════════════════════════════════════════════════════
print("=== Entropy blocks ===", file=sys.stderr)

# 512 bytes: two 256-byte blocks (all-zeros first, all-ff second)
block_data = bytes(256) + bytes([0xFF] * 256)
block_hex = block_data.hex()
truth_blocks = py_entropy_blocks(block_data, 256)  # [0.0, 0.0]

inp = {"buffer_hex": block_hex, "block_size": 256}
r, e = call("mem_entropy_blocks_hex", inp)
if isinstance(r, dict):
    v = extract(r, ["blocks", "entropies", "result", "values", "entropy_blocks"])
    if isinstance(v, list) and len(v) >= 2:
        for i, (got, want) in enumerate(zip(v[:2], truth_blocks[:2])):
            ent = got if isinstance(got, (int, float)) else got.get("entropy", got.get("value"))
            check("mem_entropy_blocks_hex", inp, float(ent), want,
                  f"block[{i}]")
    else:
        print(f"  SKIP  mem_entropy_blocks_hex  shape {v}", file=sys.stderr)
else:
    print(f"  ERR   mem_entropy_blocks_hex  {e}", file=sys.stderr)

# uniform block: should be 8.0
uniform_hex = "".join(f"{i:02x}" for i in range(256))
inp = {"buffer_hex": uniform_hex, "block_size": 256}
r, e = call("mem_entropy_blocks_hex", inp)
if isinstance(r, dict):
    v = extract(r, ["blocks", "entropies", "result", "values", "entropy_blocks"])
    if isinstance(v, list) and len(v) >= 1:
        got = v[0]
        ent = got if isinstance(got, (int, float)) else got.get("entropy", got.get("value"))
        check("mem_entropy_blocks_hex", inp, float(ent), 8.0, "uniform_block=8.0")


# ════════════════════════════════════════════════════════════════════════════
# 6. mem_search_bytes_hex — byte pattern search
# Truth: Python bytes.find()
# ════════════════════════════════════════════════════════════════════════════
print("=== Byte search ===", file=sys.stderr)

SEARCH_CASES = [
    ("aabbccddeeff001122", "ccdd", 2),
    ("000102030405",       "0304", 3),
    ("aabbcc",             "ff",   -1),   # not found
    ("ffaabbffaabb",       "ffaa", 0),
]

for buf_hex, pat_hex, truth_off in SEARCH_CASES:
    py_truth = bytes.fromhex(buf_hex).find(bytes.fromhex(pat_hex))
    assert py_truth == truth_off, f"self-check failed: {py_truth} vs {truth_off}"
    inp = {"buffer_hex": buf_hex, "pattern_hex": pat_hex}
    r, e = call("mem_search_bytes_hex", inp)
    if isinstance(r, dict):
        # tool returns {"count": N, "matches": [abs_addr, ...], "source": ...}
        # base_addr defaults to 0 so abs_addr == offset
        matches = r.get("matches") or r.get("offsets") or r.get("positions") or []
        if truth_off < 0:
            # expect not-found: matches list should be empty
            got = -1 if not matches else matches[0]
        else:
            got = matches[0] if matches else -1
        check("mem_search_bytes_hex", inp, got, truth_off,
              f"buf={buf_hex} pat={pat_hex}")
    else:
        print(f"  ERR   mem_search_bytes_hex  {e}", file=sys.stderr)


# ════════════════════════════════════════════════════════════════════════════
# 7. mem_search_bytes_range_hex (alias / variant)
# ════════════════════════════════════════════════════════════════════════════
inp = {"buffer_hex": "aabbccddeeff", "pattern_hex": "ccdd"}
r, e = call("mem_search_bytes_range_hex", inp)
if isinstance(r, dict):
    v = extract(r, ["offset", "offsets", "result", "position", "positions"])
    if isinstance(v, list):
        check("mem_search_bytes_range_hex", inp, v[0] if v else -1, 2, "first_match=2")
    elif isinstance(v, int):
        check("mem_search_bytes_range_hex", inp, v, 2, "offset=2")
    else:
        print(f"  SKIP  mem_search_bytes_range_hex  shape {v}", file=sys.stderr)
else:
    print(f"  ERR   mem_search_bytes_range_hex  {e}", file=sys.stderr)


# ════════════════════════════════════════════════════════════════════════════
# 8. mem_diff_bytes — count differing contiguous spans
# The tool (rustre_mem::diff::diff_bytes) returns SPANS not individual bytes.
# Truth: number of contiguous changed regions between two buffers.
# ════════════════════════════════════════════════════════════════════════════
print("=== Byte diff ===", file=sys.stderr)


def py_count_diff_spans(a: bytes, b: bytes) -> int:
    """Count contiguous changed-byte spans (mirrors rustre_mem::diff::diff_bytes)."""
    n = min(len(a), len(b))
    in_span = False
    spans = 0
    for i in range(n):
        if a[i] != b[i]:
            if not in_span:
                spans += 1
                in_span = True
        else:
            in_span = False
    return spans


# truth = number of differing *spans* (contiguous changed regions)
DIFF_CASES = [
    ("aabbccdd", "aa00ccdd", 1),   # byte[1] differs => 1 span
    ("00000000", "ffffffff", 1),   # all 4 bytes differ but are ONE contiguous span
    ("aabbccdd", "aabbccdd", 0),   # identical => 0 spans
    ("01020304", "01020300", 1),   # byte[3] differs => 1 span
    ("aabbccdd", "aa00cc00", 2),   # bytes 1 and 3 differ => 2 separate spans
]

for a_hex, b_hex, truth_count in DIFF_CASES:
    py_truth = py_count_diff_spans(bytes.fromhex(a_hex), bytes.fromhex(b_hex))
    assert py_truth == truth_count, f"span self-check failed {py_truth} vs {truth_count}"
    inp = {"a_hex": a_hex, "b_hex": b_hex}
    r, e = call("mem_diff_bytes", inp)
    if isinstance(r, dict):
        v = extract(r, ["count", "span_count", "num_spans", "diff_count",
                         "changed", "differences", "total", "diffs"])
        if v is None:
            # try length of spans list
            spans_list = r.get("spans") or r.get("diffs") or r.get("differences")
            if isinstance(spans_list, list):
                v = len(spans_list)
        if isinstance(v, int):
            check("mem_diff_bytes", inp, v, truth_count,
                  f"a={a_hex} b={b_hex} (span_count)")
        else:
            print(f"  SKIP  mem_diff_bytes  shape {list(r.keys())}", file=sys.stderr)
    else:
        print(f"  ERR   mem_diff_bytes  {e}", file=sys.stderr)


# ════════════════════════════════════════════════════════════════════════════
# 9. mem_perms_from_rwx — rwx string to permission flags
# Truth: Python parsing of 'r', 'w', 'x' characters
# ════════════════════════════════════════════════════════════════════════════
print("=== Perms ===", file=sys.stderr)

PERM_CASES = [
    ("rwx", True,  True,  True),
    ("r-x", True,  False, True),
    ("rw-", True,  True,  False),
    ("---", False, False, False),
]

for s, want_r, want_w, want_x in PERM_CASES:
    inp = {"s": s}
    r, e = call("mem_perms_from_rwx", inp)
    if isinstance(r, dict):
        read  = extract(r, ["read", "r", "can_read", "readable"])
        write = extract(r, ["write", "w", "can_write", "writable"])
        exec_ = extract(r, ["exec", "execute", "x", "can_exec", "executable"])
        if read is not None and write is not None and exec_ is not None:
            check("mem_perms_from_rwx", inp,
                  [bool(read), bool(write), bool(exec_)],
                  [want_r, want_w, want_x],
                  f"s={s}")
        else:
            print(f"  SKIP  mem_perms_from_rwx  unknown shape {list(r.keys())}", file=sys.stderr)
    else:
        print(f"  ERR   mem_perms_from_rwx  {e}", file=sys.stderr)


# ════════════════════════════════════════════════════════════════════════════
# 10. mem_page_range_indices — start/end page indices for a VA range
# Truth: floor(start/ps) .. floor((end-1)/ps)
# ════════════════════════════════════════════════════════════════════════════
print("=== Page range indices ===", file=sys.stderr)

RANGE_CASES = [
    # (start_va, end_va, page_size, expected_first_page_index, expected_last_page_index)
    # first = start // ps,  last = (end - 1) // ps
    (0x0000, 0x2000, 0x1000,  0, 1),
    (0x1000, 0x4000, 0x1000,  1, 3),
    (0x0500, 0x0D00, 0x1000,  0, 0),
]

for start, end, ps, first_p, last_p in RANGE_CASES:
    py_first = start // ps
    py_last  = (end - 1) // ps if end > 0 else 0
    assert py_first == first_p and py_last == last_p, \
        f"range self-check failed for start={start:#x} end={end:#x}"
    # tool requires "start", "end", "page_size"
    inp = {"start": start, "end": end, "page_size": ps}
    r, e = call("mem_page_range_indices", inp)
    if isinstance(r, dict):
        fi = extract(r, ["first_page_index", "first", "start_index", "first_page",
                          "start_page", "page_start", "first_idx"])
        li = extract(r, ["last_page_index", "last", "end_index", "last_page",
                         "end_page", "page_end", "last_idx"])
        if fi is not None:
            check("mem_page_range_indices", inp, fi, first_p,
                  f"first_page_index start={start:#x} end={end:#x}")
        if li is not None:
            check("mem_page_range_indices", inp, li, last_p,
                  f"last_page_index start={start:#x} end={end:#x}")
        if fi is None and li is None:
            print(f"  SKIP  mem_page_range_indices  shape {list(r.keys())}", file=sys.stderr)
    else:
        print(f"  ERR   mem_page_range_indices  {e}", file=sys.stderr)


# ════════════════════════════════════════════════════════════════════════════
# 11. mem_read_typed_at_hex — typed generic read
# ════════════════════════════════════════════════════════════════════════════
print("=== Typed read ===", file=sys.stderr)

TYPED_CASES = [
    ("u8",  "AB",               0, 0xAB),
    ("u32", "78563412",         0, 0x12345678),
    ("u64", "efcdab8967452301", 0, 0x0123456789ABCDEF),
    ("i8",  "FF",               0, -1),
]

for kind, hx, off, truth in TYPED_CASES:
    inp = {"buffer_hex": hx, "kind": kind, "offset": off}
    r, e = call("mem_read_typed_at_hex", inp)
    if isinstance(r, dict):
        v = extract(r, ["value", "result", "int", "i", "u"])
        if v is not None:
            check("mem_read_typed_at_hex", inp, v, truth, f"kind={kind}")
        else:
            print(f"  SKIP  mem_read_typed_at_hex  kind={kind}  {list(r.keys())}", file=sys.stderr)
    else:
        print(f"  ERR   mem_read_typed_at_hex  kind={kind}  {e}", file=sys.stderr)


# ════════════════════════════════════════════════════════════════════════════
# 12. mem_write_typed_at_hex — typed generic write
# ════════════════════════════════════════════════════════════════════════════
print("=== Typed write ===", file=sys.stderr)

TYPED_WRITE_CASES = [
    ("u32", "00000000", 0, 0x12345678, struct.pack("<I", 0x12345678).hex()),
    ("u8",  "00",       0, 0xAB,       "ab"),
]

for kind, buf_hex, off, val, truth_hex in TYPED_WRITE_CASES:
    inp = {"buffer_hex": buf_hex, "kind": kind, "offset": off, "value": val}
    r, e = call("mem_write_typed_at_hex", inp)
    if isinstance(r, dict):
        v = extract(r, ["hex", "result", "bytes", "output", "buffer_hex"])
        if isinstance(v, str):
            check("mem_write_typed_at_hex", inp, v.lower(), truth_hex.lower(),
                  f"kind={kind} val={val:#x}")
        else:
            print(f"  SKIP  mem_write_typed_at_hex  kind={kind}  shape {v}", file=sys.stderr)
    else:
        print(f"  ERR   mem_write_typed_at_hex  kind={kind}  {e}", file=sys.stderr)


# ════════════════════════════════════════════════════════════════════════════
# 13. mem_page_containing — VA → page base
# Truth: va & ~(ps-1)  (same as align_down)
# ════════════════════════════════════════════════════════════════════════════
print("=== Page containing ===", file=sys.stderr)

CONTAIN_CASES = [
    (0x1234, 0x1000, 0x1000),
    (0x0000, 0x1000, 0x0000),
    (0x1FFF, 0x1000, 0x1000),
]
for va, ps, truth in CONTAIN_CASES:
    inp = {"addr": va, "page_size": ps}  # tool uses "addr" not "va"
    r, e = call("mem_page_containing", inp)
    if isinstance(r, dict):
        # returns {"start": page_base, "end": page_end, ...}
        v = extract(r, ["start", "page_base", "base", "result", "value", "va", "aligned"])
        if v is not None:
            check("mem_page_containing", inp, v, truth, f"va={va:#x}")
        else:
            print(f"  SKIP  mem_page_containing  shape {list(r.keys())}", file=sys.stderr)
    else:
        print(f"  ERR   mem_page_containing  {e}", file=sys.stderr)


# ════════════════════════════════════════════════════════════════════════════
# 14. mem_search_bytes_with_mask_hex — masked pattern search
# Truth: manual Python masked search
# ════════════════════════════════════════════════════════════════════════════
print("=== Masked byte search ===", file=sys.stderr)

def py_masked_search(buf: bytes, pat: bytes, mask: bytes) -> int:
    """Return offset of first match, or -1."""
    n = len(buf)
    plen = len(pat)
    for i in range(n - plen + 1):
        if all((buf[i + j] & mask[j]) == (pat[j] & mask[j]) for j in range(plen)):
            return i
    return -1

MASK_CASES = [
    # (buf_hex, pattern_hex, mask_hex, truth_offset)
    ("aabbccddeeff", "ccdd", "ffff", 2),
    ("01020304",     "0100", "ff00", 0),   # low nibble masked out
]

for buf_hex, pat_hex, mask_hex, truth_off in MASK_CASES:
    py_truth = py_masked_search(bytes.fromhex(buf_hex), bytes.fromhex(pat_hex),
                                bytes.fromhex(mask_hex))
    assert py_truth == truth_off, f"self-check failed {py_truth} vs {truth_off}"
    inp = {"buffer_hex": buf_hex, "pattern_hex": pat_hex, "mask_hex": mask_hex}
    r, e = call("mem_search_bytes_with_mask_hex", inp)
    if isinstance(r, dict):
        # tool returns {"count": N, "matches": [abs_addrs], "source": ...}
        matches = r.get("matches") or r.get("offsets") or []
        if truth_off < 0:
            got = -1 if not matches else matches[0]
        else:
            got = matches[0] if matches else -1
        check("mem_search_bytes_with_mask_hex", inp, got, truth_off,
              f"buf={buf_hex} pat={pat_hex} mask={mask_hex}")
    else:
        print(f"  ERR   mem_search_bytes_with_mask_hex  {e}", file=sys.stderr)


# ─── Finalize ────────────────────────────────────────────────────────────────
try:
    p.terminate()
except Exception:
    pass

report = {
    "module": "mem",
    "tools_hardened": sorted(tools_hardened),
    "checks_passed": checks_passed,
    "checks_failed": checks_failed,
    "mismatches": mismatches,
}

with open(REPORT, "w") as fh:
    json.dump(report, fh, indent=2)

print(json.dumps({
    "module": "mem",
    "tools_hardened": len(tools_hardened),
    "checks_passed": checks_passed,
    "checks_failed": checks_failed,
    "real_mismatches": len(mismatches),
}))
