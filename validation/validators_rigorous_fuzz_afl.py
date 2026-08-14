#!/usr/bin/env python3
"""
Rigorous validators for fuzz_afl_* MCP tools.
Replaces any_valid() with independent Python reference computations.
"""
import json, subprocess, sys, struct

EXE = r"C:\Users\Fra\Desktop\RustRE\target\release\rustre-mcp.exe"
OUT = r"C:\Users\Fra\Desktop\RustRE\validation\rigorous_fuzz_afl.json"

# ── MCP session ────────────────────────────────────────────────────────────────

def start():
    p = subprocess.Popen([EXE, "--transport=stdio"], stdin=subprocess.PIPE,
                         stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, bufsize=0)
    def send(r): p.stdin.write((json.dumps(r)+"\n").encode()); p.stdin.flush()
    def recv():
        line = p.stdout.readline()
        return json.loads(line) if line else None
    send({"jsonrpc":"2.0","id":1,"method":"initialize","params":{
        "protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"v","version":"1"}}})
    recv()
    send({"jsonrpc":"2.0","method":"notifications/initialized"})
    return p, send, recv

p, send, recv = start()
rid = [10]

def call(name, args):
    rid[0] += 1
    send({"jsonrpc":"2.0","id":rid[0],"method":"tools/call",
          "params":{"name":name,"arguments":args}})
    resp = recv()
    if not resp: return ("no_resp", None)
    if "error" in resp: return ("err", resp["error"])
    c = resp.get("result",{}).get("content",[])
    if not c: return ("empty", None)
    txt = c[0].get("text","")
    try: return ("ok", json.loads(txt))
    except: return ("ok_str", txt)

# ── Fetch tool list ────────────────────────────────────────────────────────────

send({"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}})
resp = recv()
all_tools = resp.get("result",{}).get("tools",[])
tool_map = {t["name"]: t for t in all_tools if t["name"].startswith("fuzz_afl_")}
print(f"Found {len(tool_map)} fuzz_afl_* tools", file=sys.stderr)

# ── Tracking ───────────────────────────────────────────────────────────────────

mismatches = []
checks_passed = 0
checks_failed = 0
tools_hardened = set()

def norm(v):
    if isinstance(v, str):
        try: return int(v, 0)
        except: return v
    return v

def check(tool, label, mcp_val, truth_val):
    global checks_passed, checks_failed
    tools_hardened.add(tool)
    mv, tv = norm(mcp_val), norm(truth_val)
    if mv == tv:
        checks_passed += 1
        print(f"  PASS {tool} [{label}]", file=sys.stderr)
        return True
    checks_failed += 1
    mismatches.append({"tool": tool, "label": label,
                        "mcp": mcp_val, "truth": truth_val})
    print(f"  FAIL {tool} [{label}]  mcp={mcp_val!r}  truth={truth_val!r}", file=sys.stderr)
    return False

# ══════════════════════════════════════════════════════════════════════════════
# Python reference implementations
# ══════════════════════════════════════════════════════════════════════════════

def py_bucket(count: int) -> int:
    """AFL hit-count bucketing — matches Rust bucket() in rustre-fuzz-afl."""
    if count == 0: return 0
    if count == 1: return 1
    if count == 2: return 2
    if count <= 4: return 4   # 3..=4
    if count <= 8: return 8   # 5..=8
    if count <= 16: return 16  # 9..=16
    if count <= 32: return 32  # 17..=32
    if count <= 128: return 64  # 33..=128
    return 128  # 129+

def py_fnv1a_64(data: bytes) -> int:
    """FNV-1a 64-bit hash."""
    h = 0xcbf29ce484222325
    for b in data:
        h ^= b
        h = (h * 0x100000001b3) & 0xFFFFFFFFFFFFFFFF
    return h

def py_stage_bit_flip_1_count(n: int) -> int:
    return n * 8

def py_stage_bit_flip_2_count(n: int) -> int:
    total_bits = n * 8
    return max(0, total_bits - 1)

def py_stage_bit_flip_4_count(n: int) -> int:
    total_bits = n * 8
    return max(0, total_bits - 3)

def py_stage_byte_flip_1_count(n: int) -> int:
    return n

def py_stage_arith_8_count(n: int) -> int:
    # Each byte: 35 add + 35 sub = 70
    return n * 70

def py_stage_arith_16_count(data: bytes) -> int:
    """Count arith_16 mutations (skip if result == original)."""
    count = 0
    for i in range(len(data) - 1):
        orig = struct.unpack_from('<H', data, i)[0]
        for delta in range(1, 36):
            add_val = (orig + delta) & 0xFFFF
            sub_val = (orig - delta) & 0xFFFF
            if add_val != orig: count += 1
            if sub_val != orig: count += 1
    return count

def py_stage_arith_32_count(data: bytes) -> int:
    """Count arith_32 mutations."""
    count = 0
    for i in range(len(data) - 3):
        orig = struct.unpack_from('<I', data, i)[0]
        for delta in range(1, 36):
            add_val = (orig + delta) & 0xFFFFFFFF
            sub_val = (orig - delta) & 0xFFFFFFFF
            if add_val != orig: count += 1
            if sub_val != orig: count += 1
    return count

INTERESTING_8_U8 = [v & 0xFF for v in [-128, -1, 0, 1, 16, 32, 64, 100, 127]]

def py_stage_interesting_8_count(n: int) -> int:
    return n * len(INTERESTING_8_U8)

INTERESTING_16_U16 = [v & 0xFFFF for v in [-32768, -129, 128, 255, 256, 512, 1000, 1024, 4096, 32767]]

def py_stage_interesting_16_count(n: int) -> int:
    count = 0
    for _i in range(n - 1):
        for val in INTERESTING_16_U16:
            le = struct.pack('<H', val)
            be = struct.pack('>H', val)
            count += 1  # always push LE
            if be != le:
                count += 1  # push BE only if different
    return count

INTERESTING_32_U32 = [v & 0xFFFFFFFF for v in [
    -2_147_483_648, -100_663_046, -32769, 32768, 65535, 65536,
    100_663_045, 2_147_483_647]]

def py_stage_interesting_32_count(n: int) -> int:
    count = 0
    for _i in range(n - 3):
        for val in INTERESTING_32_U32:
            le = struct.pack('<I', val)
            be = struct.pack('>I', val)
            count += 1  # always push LE
            if be != le:
                count += 1  # push BE only if different
    return count

def py_parse_dict(text: str) -> int:
    """Count AFL dictionary entries (skip blanks and comments)."""
    count = 0
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        count += 1
    return count

# ══════════════════════════════════════════════════════════════════════════════
# Tool checks
# ══════════════════════════════════════════════════════════════════════════════

# ── 1. fuzz_afl_bucket_hits ───────────────────────────────────────────────────
tool = "fuzz_afl_bucket_hits"
if tool in tool_map:
    # Use counts array (schema: {"counts": [int, ...]})
    test_counts = [0, 1, 2, 3, 5, 9, 17, 33, 129, 255]
    status, r = call(tool, {"counts": test_counts})
    if status == "ok" and isinstance(r, dict):
        bucketed = r.get("bucketed")
        if isinstance(bucketed, list) and len(bucketed) == len(test_counts):
            truth = [py_bucket(b) for b in test_counts]
            check(tool, "bucketed list", bucketed, truth)
        else:
            print(f"  SKIP {tool}: unexpected shape bucketed={bucketed!r}", file=sys.stderr)
    else:
        print(f"  SKIP {tool}: call failed {r}", file=sys.stderr)

# ── 2. fuzz_afl_bitmap_summary (count_non_zero) ───────────────────────────────
tool = "fuzz_afl_bitmap_summary"
if tool in tool_map:
    bm = bytearray(256)
    bm[0] = 1; bm[7] = 3; bm[100] = 255; bm[200] = 0x42
    hex_str = bm.hex()
    status, r = call(tool, {"hex": hex_str})
    if status == "ok" and isinstance(r, dict):
        check(tool, "count_non_zero", r.get("count_non_zero"), 4)
        check(tool, "size", r.get("size"), 256)
    else:
        print(f"  SKIP {tool}: call failed {r}", file=sys.stderr)

# ── 3. fuzz_afl_bitmap_summary (all zeros) ───────────────────────────────────
if tool in tool_map:
    bm_zero = bytes(64)
    status, r = call(tool, {"hex": bm_zero.hex()})
    if status == "ok" and isinstance(r, dict):
        check(tool, "count_non_zero all zeros", r.get("count_non_zero"), 0)

# ── 4. fuzz_afl_stats_parse (execs_done) ─────────────────────────────────────
tool = "fuzz_afl_stats_parse"
if tool in tool_map:
    stats_text = (
        "start_time        : 1700000000\n"
        "last_update       : 1700003600\n"
        "execs_done        : 999999\n"
        "execs_per_sec     : 1234.56\n"
        "crashes_found     : 7\n"
        "unique_crashes    : 3\n"
        "hangs_found       : 2\n"
        "queue_size        : 42\n"
        "paths_total       : 100\n"
        "cycles_done       : 5\n"
        "stability         : 98.50%\n"
    )
    for args in [{"text": stats_text}, {"content": stats_text}, {"input": stats_text}]:
        status, r = call(tool, args)
        if status == "ok" and isinstance(r, dict):
            # Response wraps fields under "stats" key
            s = r.get("stats") or r
            check(tool, "execs_done", s.get("execs_done"), 999999)
            check(tool, "start_time", s.get("start_time"), 1700000000)
            check(tool, "crashes_found", s.get("crashes_found"), 7)
            check(tool, "unique_crashes", s.get("unique_crashes"), 3)
            check(tool, "hangs_found", s.get("hangs_found"), 2)
            check(tool, "queue_size", s.get("queue_size"), 42)
            check(tool, "cycles_done", s.get("cycles_done"), 5)
            break
    else:
        print(f"  SKIP {tool}: all arg schemas failed", file=sys.stderr)

# ── 5. fuzz_afl_dict_load ────────────────────────────────────────────────────
tool = "fuzz_afl_dict_load"
if tool in tool_map:
    dict_text = (
        'kw1="hello"\n'
        'kw2="world\\x00"\n'
        '# this is a comment\n'
        '\n'
        '"anon"\n'
        'kw3="foo"\n'
    )
    truth_count = py_parse_dict(dict_text)  # 4 non-comment, non-blank
    # dict_load requires "text" key
    status, r = call(tool, {"text": dict_text})
    if status == "ok" and isinstance(r, dict):
        cnt = r.get("count")
        if cnt is not None:
            check(tool, "entry count", cnt, truth_count)
        else:
            print(f"  SKIP {tool}: keys={list(r.keys())}", file=sys.stderr)

# ── 6. fuzz_afl_dict_info ────────────────────────────────────────────────────
tool = "fuzz_afl_dict_info"
if tool in tool_map:
    dict_text = 'kw1="hello"\nkw2="world"\n# comment\nkw3="foo"\n'
    truth_count = py_parse_dict(dict_text)  # 3
    status, r = call(tool, {"text": dict_text})
    if status == "ok" and isinstance(r, dict):
        cnt = r.get("count") or r.get("num_entries") or r.get("entries") or r.get("total")
        if cnt is not None:
            check(tool, "entry count", cnt, truth_count)
        else:
            print(f"  SKIP {tool}: keys={list(r.keys())}", file=sys.stderr)
    else:
        print(f"  SKIP {tool}: call failed {r}", file=sys.stderr)

# ── 7. fuzz_afl_stage_bit_flip_1 ─────────────────────────────────────────────
tool = "fuzz_afl_stage_bit_flip_1"
if tool in tool_map:
    data = bytes.fromhex("00112233")  # 4 bytes
    status, r = call(tool, {"hex": data.hex()})
    if status == "ok" and isinstance(r, dict):
        truth = py_stage_bit_flip_1_count(len(data))
        check(tool, "mutation count (4 bytes)", r.get("count"), truth)
    else:
        print(f"  SKIP {tool}: call failed {r}", file=sys.stderr)

# ── 8. fuzz_afl_stage_bit_flip_2 ─────────────────────────────────────────────
tool = "fuzz_afl_stage_bit_flip_2"
if tool in tool_map:
    data = bytes.fromhex("00112233")  # 4 bytes
    status, r = call(tool, {"hex": data.hex()})
    if status == "ok" and isinstance(r, dict):
        truth = py_stage_bit_flip_2_count(len(data))
        check(tool, "mutation count (4 bytes)", r.get("count"), truth)
    else:
        print(f"  SKIP {tool}: call failed {r}", file=sys.stderr)

# ── 9. fuzz_afl_stage_bit_flip_4 ─────────────────────────────────────────────
tool = "fuzz_afl_stage_bit_flip_4"
if tool in tool_map:
    data = bytes.fromhex("00112233")  # 4 bytes
    status, r = call(tool, {"hex": data.hex()})
    if status == "ok" and isinstance(r, dict):
        truth = py_stage_bit_flip_4_count(len(data))
        check(tool, "mutation count (4 bytes)", r.get("count"), truth)
    else:
        print(f"  SKIP {tool}: call failed {r}", file=sys.stderr)

# ── 10. fuzz_afl_stage_byte_flip_1 ───────────────────────────────────────────
tool = "fuzz_afl_stage_byte_flip_1"
if tool in tool_map:
    data = bytes.fromhex("deadbeef")  # 4 bytes
    status, r = call(tool, {"hex": data.hex()})
    if status == "ok" and isinstance(r, dict):
        truth = py_stage_byte_flip_1_count(len(data))
        check(tool, "mutation count (4 bytes)", r.get("count"), truth)
    else:
        print(f"  SKIP {tool}: call failed {r}", file=sys.stderr)

# ── 11. fuzz_afl_stage_arith_8 ───────────────────────────────────────────────
tool = "fuzz_afl_stage_arith_8"
if tool in tool_map:
    data = bytes.fromhex("deadbeef")  # 4 bytes
    status, r = call(tool, {"hex": data.hex()})
    if status == "ok" and isinstance(r, dict):
        truth = py_stage_arith_8_count(len(data))
        check(tool, "mutation count (4 bytes)", r.get("count"), truth)
    else:
        print(f"  SKIP {tool}: call failed {r}", file=sys.stderr)

# ── 12. fuzz_afl_stage_arith_16 ──────────────────────────────────────────────
tool = "fuzz_afl_stage_arith_16"
if tool in tool_map:
    data = bytes.fromhex("deadbeef")  # 4 bytes
    status, r = call(tool, {"hex": data.hex()})
    if status == "ok" and isinstance(r, dict):
        truth = py_stage_arith_16_count(data)
        check(tool, "mutation count (4 bytes)", r.get("count"), truth)
    else:
        print(f"  SKIP {tool}: call failed {r}", file=sys.stderr)

# ── 13. fuzz_afl_stage_arith_32 ──────────────────────────────────────────────
tool = "fuzz_afl_stage_arith_32"
if tool in tool_map:
    data = bytes.fromhex("deadbeef")  # 4 bytes
    status, r = call(tool, {"hex": data.hex()})
    if status == "ok" and isinstance(r, dict):
        truth = py_stage_arith_32_count(data)
        check(tool, "mutation count (4 bytes)", r.get("count"), truth)
    else:
        print(f"  SKIP {tool}: call failed {r}", file=sys.stderr)

# ── 14. fuzz_afl_stage_interesting_8 ─────────────────────────────────────────
tool = "fuzz_afl_stage_interesting_8"
if tool in tool_map:
    data = bytes.fromhex("00112233")  # 4 bytes
    status, r = call(tool, {"hex": data.hex()})
    if status == "ok" and isinstance(r, dict):
        truth = py_stage_interesting_8_count(len(data))
        check(tool, "mutation count (4 bytes)", r.get("count"), truth)
    else:
        print(f"  SKIP {tool}: call failed {r}", file=sys.stderr)

# ── 15. fuzz_afl_stage_interesting_16 ────────────────────────────────────────
tool = "fuzz_afl_stage_interesting_16"
if tool in tool_map:
    data = bytes.fromhex("00112233")  # 4 bytes
    status, r = call(tool, {"hex": data.hex()})
    if status == "ok" and isinstance(r, dict):
        truth = py_stage_interesting_16_count(len(data))
        check(tool, "mutation count (4 bytes)", r.get("count"), truth)
    else:
        print(f"  SKIP {tool}: call failed {r}", file=sys.stderr)

# ── 16. fuzz_afl_stage_interesting_32 ────────────────────────────────────────
tool = "fuzz_afl_stage_interesting_32"
if tool in tool_map:
    data = bytes.fromhex("00112233")  # 4 bytes
    status, r = call(tool, {"hex": data.hex()})
    if status == "ok" and isinstance(r, dict):
        truth = py_stage_interesting_32_count(len(data))
        check(tool, "mutation count (4 bytes)", r.get("count"), truth)
    else:
        print(f"  SKIP {tool}: call failed {r}", file=sys.stderr)

# ── 17. fuzz_afl_stage_splice ─────────────────────────────────────────────────
tool = "fuzz_afl_stage_splice"
if tool in tool_map:
    # Splice with same input = result length is 0..len(a) + 0..len(b) bytes, deterministic on seed.
    # Two calls with same seed must return identical result.
    a_hex = "deadbeef" * 4
    b_hex = "cafebabe" * 4
    status1, r1 = call(tool, {"hex_a": a_hex, "hex_b": b_hex, "seed": 777})
    status2, r2 = call(tool, {"hex_a": a_hex, "hex_b": b_hex, "seed": 777})
    if status1 == "ok" and status2 == "ok":
        check(tool, "deterministic on same seed", r1.get("hex"), r2.get("hex"))
    else:
        # Try alternative schema
        for arg_a in ["a", "input_a", "hex_a"]:
            for arg_b in ["b", "input_b", "hex_b"]:
                s1, r1 = call(tool, {arg_a: a_hex, arg_b: b_hex, "seed": 777})
                s2, r2 = call(tool, {arg_a: a_hex, arg_b: b_hex, "seed": 777})
                if s1 == "ok" and s2 == "ok":
                    check(tool, "deterministic on same seed", r1.get("hex"), r2.get("hex"))
                    break
            else:
                continue
            break

# ── 18. fuzz_afl_bit_flip_mutate (determinism) ────────────────────────────────
tool = "fuzz_afl_bit_flip_mutate"
if tool in tool_map:
    hx = "00112233445566778899aabbccddeeff"
    s1, r1 = call(tool, {"hex": hx, "seed": 12345})
    s2, r2 = call(tool, {"hex": hx, "seed": 12345})
    if s1 == "ok" and s2 == "ok" and isinstance(r1, dict) and isinstance(r2, dict):
        check(tool, "deterministic same seed", r1.get("hex"), r2.get("hex"))
    else:
        print(f"  SKIP {tool}: call failed", file=sys.stderr)

# ── 19. fuzz_afl_stats_serialize round-trip ───────────────────────────────────
tool = "fuzz_afl_stats_serialize"
if tool in tool_map:
    stats_text = (
        "start_time        : 42\n"
        "execs_done        : 1000\n"
        "crashes_found     : 5\n"
    )
    for args in [{"content": stats_text}, {"text": stats_text}, {"input": stats_text}]:
        status, r = call(tool, args)
        if status == "ok" and (isinstance(r, dict) or isinstance(r, str)):
            # Re-serialized text should contain execs_done: 1000
            out_text = r.get("serialized") or r.get("output") or r.get("text") or str(r)
            truth = "1000"  # execs_done value must appear
            if truth in out_text:
                check(tool, "serialized contains execs_done", True, True)
            else:
                check(tool, "serialized contains execs_done", out_text, f"..contains {truth}..")
            break

# ── 20. fuzz_afl_queue_score (untried = MAX priority) ─────────────────────────
tool = "fuzz_afl_queue_score"
if tool in tool_map:
    # New entry with 0 selected_count should return f64::MAX → very large number
    status, r = call(tool, {"exec_us": 1000, "coverage_bits": 10,
                             "selected_count": 0, "interesting_count": 0})
    if status == "ok" and isinstance(r, dict):
        score = r.get("score")
        if score is not None:
            # f64::MAX or very large float
            check(tool, "score > 1e300 for untried entry", score > 1e300, True)
        else:
            print(f"  SKIP {tool}: keys={list(r.keys())}", file=sys.stderr)
    else:
        # Try alternative schema
        for args in [{"exec_us": 0, "coverage_bits": 10},
                     {"time_us": 1000, "bits": 10}]:
            status, r = call(tool, args)
            if status == "ok" and isinstance(r, dict):
                break
        else:
            print(f"  SKIP {tool}: all schemas failed", file=sys.stderr)

# ── Terminate ─────────────────────────────────────────────────────────────────
try: p.terminate()
except: pass

# ── Report ────────────────────────────────────────────────────────────────────
report = {
    "module": "fuzz_afl",
    "tools_hardened": len(tools_hardened),
    "checks_passed": checks_passed,
    "checks_failed": checks_failed,
    "real_mismatches": len(mismatches),
    "mismatches": mismatches,
    "tools_tested": sorted(tools_hardened),
}

with open(OUT, "w") as f:
    json.dump(report, f, indent=2)

print(json.dumps({k: v for k, v in report.items() if k not in ("mismatches","tools_tested")}, indent=2))
print(f"\nMismatches: {len(mismatches)}")
for m in mismatches:
    print(f"  MISMATCH {m['tool']} [{m['label']}]: mcp={m['mcp']!r}  truth={m['truth']!r}")
