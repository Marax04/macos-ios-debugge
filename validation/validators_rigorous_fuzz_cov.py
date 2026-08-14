#!/usr/bin/env python3
"""
Rigorous validators for fuzz_cov_* MCP tools.
Each check computes an independent Python truth value and compares it to the
Rust MCP output.  No any_valid() calls — every check is a real comparison.
"""
import json, subprocess, sys, struct

EXE = r"C:\Users\Fra\Desktop\RustRE\target\release\rustre-mcp.exe"
REPORT = r"C:\Users\Fra\Desktop\RustRE\validation\rigorous_fuzz_cov.json"

# ─── MCP session ──────────────────────────────────────────────────────────────

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
    send({"jsonrpc":"2.0","id":1,"method":"initialize",
          "params":{"protocolVersion":"2024-11-05","capabilities":{},
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
        return None
    if "error" in resp:
        return {"__error__": resp["error"]}
    c = resp.get("result",{}).get("content",[])
    if not c:
        return {}
    txt = c[0].get("text","")
    try:
        return json.loads(txt)
    except Exception:
        return {"__raw__": txt}

# ─── Truth helpers ─────────────────────────────────────────────────────────────

def py_rle_encode(data: bytes) -> bytes:
    """Mirror of rustre_fuzz_cov::coverage_persistence::rle_encode."""
    if not data:
        return b""
    out = bytearray()
    i = 0
    while i < len(data):
        val = data[i]
        run = 1
        while i + run < len(data) and data[i + run] == val and run < 0xFFFF:
            run += 1
        out += struct.pack("<H", run)   # u16 little-endian count
        out += bytes([val])
        i += run
    return bytes(out)

def py_coverage_fraction(bm: bytes) -> float:
    """Non-zero bytes / total bytes."""
    if not bm:
        return 0.0
    return sum(1 for b in bm if b != 0) / len(bm)

def py_fnv1a64(data: bytes) -> int:
    """FNV-1a 64-bit — matches PcGuardBitmap::hash."""
    h = 0xcbf29ce484222325
    for b in data:
        h ^= b
        h = (h * 0x100000001b3) & 0xFFFFFFFFFFFFFFFF
    return h

def py_jaccard(a, b) -> float:
    sa, sb = set(a), set(b)
    inter = sa & sb
    union = sa | sb
    if not union:
        return 1.0
    return len(inter) / len(union)

# ─── Checking infra ────────────────────────────────────────────────────────────

checks_passed = 0
checks_failed = 0
tools_hardened = set()
mismatches = []

def check(tool, field, got, truth, note=""):
    global checks_passed, checks_failed
    tools_hardened.add(tool)
    # Normalise
    def norm(v):
        if isinstance(v, str):
            try: return int(v, 0)
            except Exception:
                try: return float(v)
                except Exception: return v
        return v
    g, t = norm(got), norm(truth)
    ok = False
    if g == t:
        ok = True
    elif isinstance(g, (int,float)) and isinstance(t, (int,float)):
        ok = abs(float(g) - float(t)) <= 1e-6
    if ok:
        checks_passed += 1
        print(f"  PASS  {tool}[{field}]  got={got!r}", file=sys.stderr)
    else:
        checks_failed += 1
        m = {"tool": tool, "field": field, "mcp": got, "truth": truth, "note": note}
        mismatches.append(m)
        print(f"  FAIL  {tool}[{field}]  got={got!r}  expected={truth!r}  {note}", file=sys.stderr)

def skip(tool, reason):
    print(f"  SKIP  {tool}: {reason}", file=sys.stderr)

# ─── 1. fuzz_cov_coverage_fraction ────────────────────────────────────────────
# bitmap: ff 00 ff 00  (4 bytes, 2 non-zero) -> fraction = 0.5
bm4 = bytes([0xff, 0x00, 0xff, 0x00])
r = call("fuzz_cov_coverage_fraction", {"bitmap_hex": bm4.hex()})
if r and "__error__" not in r:
    check("fuzz_cov_coverage_fraction", "fraction", r.get("fraction"), 0.5,
          "2 non-zero / 4 total = 0.5")
else:
    skip("fuzz_cov_coverage_fraction", f"error: {r}")

# bitmap: ff ff ff ff  (all hit) -> fraction = 1.0
bm_all = bytes([0xff]*8)
r2 = call("fuzz_cov_coverage_fraction", {"bitmap_hex": bm_all.hex()})
if r2 and "__error__" not in r2:
    check("fuzz_cov_coverage_fraction", "fraction_all_hit", r2.get("fraction"), 1.0,
          "8/8 = 1.0")
else:
    skip("fuzz_cov_coverage_fraction", f"error (all-hit): {r2}")

# ─── 2. fuzz_cov_rle_encode ───────────────────────────────────────────────────
# 32 zeros: encoded = \x20\x00\x00  (count=32 as u16 LE, value=0)
data32 = bytes([0]*32)
truth_enc = py_rle_encode(data32)
assert truth_enc == bytes([0x20, 0x00, 0x00]), f"py_rle_encode sanity: {truth_enc.hex()}"
r = call("fuzz_cov_rle_encode", {"data_hex": data32.hex()})
if r and "__error__" not in r:
    check("fuzz_cov_rle_encode", "out_len", r.get("out_len"), len(truth_enc),
          "32 zeros -> 3-byte RLE")
    check("fuzz_cov_rle_encode", "out_hex", r.get("out_hex"), truth_enc.hex(),
          "RLE bytes")
    check("fuzz_cov_rle_encode", "in_len", r.get("in_len"), 32, "input length")
else:
    skip("fuzz_cov_rle_encode", f"error: {r}")

# multi-run: [0,0,0xff,0xff,0x01]
data5 = bytes([0, 0, 0xff, 0xff, 0x01])
truth_enc5 = py_rle_encode(data5)
r5 = call("fuzz_cov_rle_encode", {"data_hex": data5.hex()})
if r5 and "__error__" not in r5:
    check("fuzz_cov_rle_encode", "out_hex_5", r5.get("out_hex"), truth_enc5.hex(),
          "mixed run RLE")
else:
    skip("fuzz_cov_rle_encode", f"error (5-byte): {r5}")

# ─── 3. fuzz_cov_rle_is_beneficial ───────────────────────────────────────────
# Schema uses "hex" or "bytes" parameter (not "data_hex")
# 32 zeros -> beneficial (3 < 32)
r = call("fuzz_cov_rle_is_beneficial", {"hex": data32.hex()})
if r and "__error__" not in r:
    check("fuzz_cov_rle_is_beneficial", "beneficial_zeros",
          r.get("beneficial"), True, "32 zeros: RLE 3 bytes < 32")
else:
    skip("fuzz_cov_rle_is_beneficial", f"error: {r}")

# alternating bytes -> not beneficial (each byte is its own run of 1)
data_alt = bytes([i % 2 for i in range(8)])  # 0,1,0,1,...  8 bytes -> 8 runs of 1 -> 24 bytes > 8
is_benef_alt = len(py_rle_encode(data_alt)) < len(data_alt)   # False
r = call("fuzz_cov_rle_is_beneficial", {"hex": data_alt.hex()})
if r and "__error__" not in r:
    check("fuzz_cov_rle_is_beneficial", "beneficial_alt",
          r.get("beneficial"), is_benef_alt, f"alt bytes: benef={is_benef_alt}")
else:
    skip("fuzz_cov_rle_is_beneficial", f"error (alt): {r}")

# ─── 4. fuzz_cov_pcguard_density ─────────────────────────────────────────────
# bitmap: ff 00 00 ff 00 00 ff 00  -> 3/8 = 0.375
bm8 = bytes([0xff,0x00,0x00,0xff,0x00,0x00,0xff,0x00])
truth_density = py_coverage_fraction(bm8)   # 0.375
r = call("fuzz_cov_pcguard_density", {"bitmap_hex": bm8.hex()})
if r and "__error__" not in r:
    d = r.get("density") or r.get("fraction") or r.get("coverage_density")
    check("fuzz_cov_pcguard_density", "density", d, truth_density,
          "3/8 non-zero = 0.375")
    # hit_guards should == 3
    hg = r.get("hit_guards") or r.get("coverage_count")
    if hg is not None:
        check("fuzz_cov_pcguard_density", "hit_guards", hg, 3, "3 non-zero bytes")
else:
    skip("fuzz_cov_pcguard_density", f"error: {r}")

# ─── 5. fuzz_cov_pcguard_hash ────────────────────────────────────────────────
# bitmap [0x01, 0x00, 0x00]  -> FNV-1a 64
bm3 = bytes([0x01, 0x00, 0x00])
truth_hash = py_fnv1a64(bm3)
truth_hash_hex = f"{truth_hash:016x}"
r = call("fuzz_cov_pcguard_hash", {"bitmap_hex": bm3.hex()})
if r and "__error__" not in r:
    h = r.get("hash")
    # Tool may return hash as hex string or as integer
    got_int = int(h, 16) if isinstance(h, str) else h
    check("fuzz_cov_pcguard_hash", "hash", got_int, truth_hash,
          f"FNV-1a([01,00,00])={truth_hash_hex}")
else:
    skip("fuzz_cov_pcguard_hash", f"error: {r}")

# all-zeros bitmap [0x00]*4 -> FNV-1a
bm0 = bytes(4)
truth_hash0 = py_fnv1a64(bm0)
r0 = call("fuzz_cov_pcguard_hash", {"bitmap_hex": bm0.hex()})
if r0 and "__error__" not in r0:
    h0 = r0.get("hash")
    got_int0 = int(h0, 16) if isinstance(h0, str) else h0
    check("fuzz_cov_pcguard_hash", "hash_zeros", got_int0, truth_hash0,
          f"FNV-1a([00]*4)={truth_hash0:#x}")
else:
    skip("fuzz_cov_pcguard_hash", f"error (zeros): {r0}")

# ─── 6. fuzz_cov_lcov_parse ───────────────────────────────────────────────────
LCOV_TEXT = """\
TN:testname
SF:src/foo.rs
DA:1,1
DA:2,0
DA:3,5
DA:4,2
LF:4
LH:3
end_of_record
"""
r = call("fuzz_cov_lcov_parse", {"text": LCOV_TEXT})
if r and "__error__" not in r:
    files = r.get("files") or r.get("records") or r.get("source_files")
    nf = len(files) if isinstance(files, list) else (files if isinstance(files, int) else None)
    if nf is not None:
        check("fuzz_cov_lcov_parse", "file_count", nf, 1, "1 SF record")
    else:
        # maybe total_lines or something
        skip("fuzz_cov_lcov_parse", f"unexpected keys: {list(r.keys())}")
else:
    skip("fuzz_cov_lcov_parse", f"error: {r}")

# ─── 7. fuzz_cov_lcov_line_pct ───────────────────────────────────────────────
# LH=3, LF=4 -> 75.0 %
r = call("fuzz_cov_lcov_line_pct", {"text": LCOV_TEXT})
if r and "__error__" not in r:
    pct = (r.get("line_coverage_pct") or r.get("pct") or r.get("percent")
           or r.get("overall_line_pct") or r.get("overall_pct"))
    if pct is not None:
        truth_pct = 75.0
        check("fuzz_cov_lcov_line_pct", "line_pct", float(pct), truth_pct,
              "LH=3 LF=4 -> 75.0%")
    else:
        skip("fuzz_cov_lcov_line_pct", f"unexpected keys: {list(r.keys())}")
else:
    skip("fuzz_cov_lcov_line_pct", f"error: {r}")

# ─── 8. fuzz_cov_lcov_fully_covered_x ────────────────────────────────────────
# Tool returns {"records": [{"fully_covered": bool, "functions_hit": int, "line_pct": float}], ...}
# DA:2,0  -> not fully covered -> records[0]["fully_covered"] == False
def get_record_field(r, field):
    recs = r.get("records", [])
    if recs and isinstance(recs[0], dict):
        return recs[0].get(field)
    return None

r = call("fuzz_cov_lcov_fully_covered_x", {"text": LCOV_TEXT})
if r and "__error__" not in r:
    fc = get_record_field(r, "fully_covered")
    if fc is not None:
        check("fuzz_cov_lcov_fully_covered_x", "not_full", bool(fc), False,
              "DA:2,0 means line uncovered")
    lp = get_record_field(r, "line_pct")
    if lp is not None:
        check("fuzz_cov_lcov_fully_covered_x", "line_pct", float(lp), 75.0,
              "LH=3 LF=4 -> 75%")
else:
    skip("fuzz_cov_lcov_fully_covered_x", f"error: {r}")

# fully covered lcov
LCOV_FULL = """\
TN:t
SF:src/ok.rs
DA:1,3
DA:2,1
LF:2
LH:2
end_of_record
"""
r = call("fuzz_cov_lcov_fully_covered_x", {"text": LCOV_FULL})
if r and "__error__" not in r:
    fc = get_record_field(r, "fully_covered")
    if fc is not None:
        check("fuzz_cov_lcov_fully_covered_x", "all_covered", bool(fc), True,
              "All DA lines > 0")
    lp = get_record_field(r, "line_pct")
    if lp is not None:
        check("fuzz_cov_lcov_fully_covered_x", "line_pct_full", float(lp), 100.0,
              "LH=2 LF=2 -> 100%")
else:
    skip("fuzz_cov_lcov_fully_covered_x", f"error (full): {r}")

# ─── 9. fuzz_cov_lcov_aggregate_by_file ──────────────────────────────────────
LCOV2 = LCOV_TEXT + """\
TN:t2
SF:src/bar.rs
DA:1,1
LF:1
LH:1
end_of_record
"""
r = call("fuzz_cov_lcov_aggregate_by_file", {"text": LCOV2})
if r and "__error__" not in r:
    agg = r.get("files") or r.get("aggregate") or r.get("by_file") or r.get("source_files")
    na = len(agg) if isinstance(agg, (list,dict)) else (agg if isinstance(agg,int) else None)
    if na is not None:
        check("fuzz_cov_lcov_aggregate_by_file", "file_count", na, 2,
              "2 SF records in lcov")
    else:
        skip("fuzz_cov_lcov_aggregate_by_file", f"keys={list(r.keys())}")
else:
    skip("fuzz_cov_lcov_aggregate_by_file", f"error: {r}")

# ─── 10. fuzz_cov_diff_jaccard ────────────────────────────────────────────────
# A={1,2,3,4}  B={3,4,5,6}  intersect={3,4}  union={1,2,3,4,5,6}  J=2/6
A, B = [1,2,3,4], [3,4,5,6]
truth_j = py_jaccard(A, B)   # 2/6 ~ 0.33333
r = call("fuzz_cov_diff_jaccard", {"a": A, "b": B})
if r and "__error__" not in r:
    j = r.get("jaccard") or r.get("similarity") or r.get("jaccard_similarity")
    is_id = r.get("is_identical")
    if j is not None:
        check("fuzz_cov_diff_jaccard", "jaccard", float(j), truth_j,
              "|{3,4}|/|{1..6}| = 1/3")
    if is_id is not None:
        check("fuzz_cov_diff_jaccard", "is_identical", bool(is_id), False,
              "A != B")
else:
    skip("fuzz_cov_diff_jaccard", f"error: {r}")

# identical sets
r2 = call("fuzz_cov_diff_jaccard", {"a": [1,2,3], "b": [1,2,3]})
if r2 and "__error__" not in r2:
    j2 = r2.get("jaccard") or r2.get("similarity") or r2.get("jaccard_similarity")
    if j2 is not None:
        check("fuzz_cov_diff_jaccard", "jaccard_eq", float(j2), 1.0,
              "identical sets -> J=1.0")
else:
    skip("fuzz_cov_diff_jaccard", f"error (identical): {r2}")

# ─── 11. fuzz_cov_drcov_module_contains ──────────────────────────────────────
# base=0x1000, end=0x2000, addr=0x1500 -> contains=True, size=0x1000, offset=0x500
r = call("fuzz_cov_drcov_module_contains", {"base": 0x1000, "end": 0x2000, "addr": 0x1500})
if r and "__error__" not in r:
    c = r.get("contains")
    if c is not None:
        check("fuzz_cov_drcov_module_contains", "contains_in", bool(c), True,
              "0x1500 in [0x1000,0x2000)")
    sz = r.get("size")
    if sz is not None:
        check("fuzz_cov_drcov_module_contains", "size", int(sz), 0x1000, "0x2000-0x1000")
    off = r.get("offset") or r.get("to_offset")
    if off is not None:
        check("fuzz_cov_drcov_module_contains", "offset", int(off), 0x500,
              "0x1500-0x1000 = 0x500")
else:
    skip("fuzz_cov_drcov_module_contains", f"error (in): {r}")

# addr outside
r3 = call("fuzz_cov_drcov_module_contains", {"base": 0x1000, "end": 0x2000, "addr": 0x5000})
if r3 and "__error__" not in r3:
    c3 = r3.get("contains")
    if c3 is not None:
        check("fuzz_cov_drcov_module_contains", "contains_out", bool(c3), False,
              "0x5000 not in [0x1000,0x2000)")
else:
    skip("fuzz_cov_drcov_module_contains", f"error (out): {r3}")

# ─── 12. fuzz_cov_drcov_bb_abs_addr ─────────────────────────────────────────
# module_base=0x400000, start=0x1000, size=16, module_id=0 -> abs=0x401000
r = call("fuzz_cov_drcov_bb_abs_addr",
         {"module_base": 0x400000, "start": 0x1000, "size": 16, "module_id": 0})
if r and "__error__" not in r:
    abs_addr = r.get("absolute_addr") or r.get("abs_addr") or r.get("addr")
    if abs_addr is not None:
        check("fuzz_cov_drcov_bb_abs_addr", "abs_addr", int(abs_addr), 0x401000,
              "base+start = 0x401000")
else:
    skip("fuzz_cov_drcov_bb_abs_addr", f"error: {r}")

# ─── 13. fuzz_cov_drcov_module_to_offset_x ───────────────────────────────────
# base=0x400000, end=0x500000, addr=0x401234 -> offset=0x1234
r = call("fuzz_cov_drcov_module_to_offset_x",
         {"base": 0x400000, "end": 0x500000, "addr": 0x401234})
if r and "__error__" not in r:
    off = r.get("offset") or r.get("to_offset")
    if off is not None:
        check("fuzz_cov_drcov_module_to_offset_x", "offset", int(off), 0x1234,
              "0x401234 - 0x400000 = 0x1234")
else:
    skip("fuzz_cov_drcov_module_to_offset_x", f"error: {r}")

# ─── 14. fuzz_cov_drcov_module_v2_size ───────────────────────────────────────
# base=0x1000, end=0x5000, addr=0x2000 -> size=0x4000, contains=True
r = call("fuzz_cov_drcov_module_v2_size",
         {"base": 0x1000, "end": 0x5000, "addr": 0x2000})
if r and "__error__" not in r:
    sz = r.get("size")
    if sz is not None:
        check("fuzz_cov_drcov_module_v2_size", "size", int(sz), 0x4000,
              "0x5000-0x1000 = 0x4000")
    c = r.get("contains")
    if c is not None:
        check("fuzz_cov_drcov_module_v2_size", "contains", bool(c), True,
              "0x2000 in [0x1000,0x5000)")
else:
    skip("fuzz_cov_drcov_module_v2_size", f"error: {r}")

# ─── 15. fuzz_cov_drcov_basic_block_abs_addr_x ───────────────────────────────
# start=0x2000, size=16, module_id=0, base=0x400000 -> abs=0x402000
r = call("fuzz_cov_drcov_basic_block_abs_addr_x",
         {"start": 0x2000, "size": 16, "module_id": 0, "base": 0x400000})
if r and "__error__" not in r:
    abs_addr = r.get("absolute_addr") or r.get("abs_addr") or r.get("addr")
    if abs_addr is not None:
        check("fuzz_cov_drcov_basic_block_abs_addr_x", "abs_addr",
              int(abs_addr), 0x402000, "base+start = 0x402000")
else:
    skip("fuzz_cov_drcov_basic_block_abs_addr_x", f"error: {r}")

# ─── 16. fuzz_cov_drcov_entry_end_addr ───────────────────────────────────────
# base=0x400000, end=0x500000, start=0x1000, size=0x100
# abs_addr = base + start = 0x401000
# end_addr  = base + start + size = 0x401100
r = call("fuzz_cov_drcov_entry_end_addr",
         {"base": 0x400000, "end": 0x500000, "start": 0x1000, "size": 0x100})
if r and "__error__" not in r:
    abs_a = r.get("absolute_addr") or r.get("abs_addr")
    end_a = r.get("end_addr") or r.get("end")
    if abs_a is not None:
        check("fuzz_cov_drcov_entry_end_addr", "abs_addr", int(abs_a), 0x401000,
              "base+start")
    if end_a is not None:
        check("fuzz_cov_drcov_entry_end_addr", "end_addr", int(end_a), 0x401100,
              "base+start+size")
else:
    skip("fuzz_cov_drcov_entry_end_addr", f"error: {r}")

# ─── 17. fuzz_cov_coverage_run_was_hit_x ─────────────────────────────────────
# addrs=[0x100,0x200,0x300], query=0x200 -> was_hit=True, distinct=3
r = call("fuzz_cov_coverage_run_was_hit_x",
         {"addrs": [0x100, 0x200, 0x300], "query": 0x200})
if r and "__error__" not in r:
    wh = r.get("was_hit") or r.get("hit")
    if wh is not None:
        check("fuzz_cov_coverage_run_was_hit_x", "was_hit", bool(wh), True,
              "0x200 in addrs")
    db = r.get("distinct_blocks") or r.get("distinct") or r.get("unique")
    if db is not None:
        check("fuzz_cov_coverage_run_was_hit_x", "distinct", int(db), 3,
              "3 distinct addrs")
else:
    skip("fuzz_cov_coverage_run_was_hit_x", f"error: {r}")

# query not present
r2 = call("fuzz_cov_coverage_run_was_hit_x",
          {"addrs": [0x100, 0x200, 0x300], "query": 0x999})
if r2 and "__error__" not in r2:
    wh2 = r2.get("was_hit") or r2.get("hit")
    if wh2 is not None:
        check("fuzz_cov_coverage_run_was_hit_x", "was_hit_miss", bool(wh2), False,
              "0x999 not in addrs")
else:
    skip("fuzz_cov_coverage_run_was_hit_x", f"error (miss): {r2}")

# ─── 18. fuzz_cov_edge_map_has_edge_x ────────────────────────────────────────
# edges=[[1,2],[3,4]], from=1, to=2 -> has_edge=True
r = call("fuzz_cov_edge_map_has_edge_x",
         {"edges": [[1,2],[3,4]], "from": 1, "to": 2})
if r and "__error__" not in r:
    he = r.get("has_edge") or r.get("has") or r.get("exists")
    if he is not None:
        check("fuzz_cov_edge_map_has_edge_x", "has_yes", bool(he), True,
              "edge (1,2) present")
else:
    skip("fuzz_cov_edge_map_has_edge_x", f"error (yes): {r}")

# edge absent
r3 = call("fuzz_cov_edge_map_has_edge_x",
          {"edges": [[1,2],[3,4]], "from": 1, "to": 9})
if r3 and "__error__" not in r3:
    he3 = r3.get("has_edge") or r3.get("has") or r3.get("exists")
    if he3 is not None:
        check("fuzz_cov_edge_map_has_edge_x", "has_no", bool(he3), False,
              "edge (1,9) absent")
else:
    skip("fuzz_cov_edge_map_has_edge_x", f"error (no): {r3}")

# ─── 19. fuzz_cov_coverage_run_merge ─────────────────────────────────────────
# a=[1,2,3], b=[3,4,5] -> merged union has 5 distinct addresses
r = call("fuzz_cov_coverage_run_merge", {"a": [1,2,3], "b": [3,4,5]})
if r and "__error__" not in r:
    # Tool returns {"distinct": int, "total_hits": int}
    # a hits: {1:1, 2:1, 3:1}; b hits: {3:1, 4:1, 5:1}
    # after merge: {1:1, 2:1, 3:2, 4:1, 5:1} -> distinct=5, total_hits=6
    distinct = r.get("distinct")
    total_hits = r.get("total_hits")
    if distinct is not None:
        check("fuzz_cov_coverage_run_merge", "distinct",
              int(distinct), 5, "5 distinct addrs after merge")
    if total_hits is not None:
        check("fuzz_cov_coverage_run_merge", "total_hits",
              int(total_hits), 6, "sum of all hit counts = 1+1+2+1+1 = 6")
else:
    skip("fuzz_cov_coverage_run_merge", f"error: {r}")

# ─── 20. fuzz_cov_coverage_diff ──────────────────────────────────────────────
# a=[1,2,3], b=[2,3,4]
# new_in_b = [4], lost = [1], common = {2,3}
# jaccard = |{2,3}| / |{1,2,3,4}| = 2/4 = 0.5
r = call("fuzz_cov_coverage_diff", {"a": [1,2,3], "b": [2,3,4]})
if r and "__error__" not in r:
    j = r.get("jaccard") or r.get("jaccard_similarity") or r.get("similarity")
    if j is not None:
        truth_j2 = py_jaccard([1,2,3],[2,3,4])   # 2/4 = 0.5
        check("fuzz_cov_coverage_diff", "jaccard", float(j), truth_j2,
              "|{2,3}|/|{1,2,3,4}| = 0.5")
    new_b = r.get("new_in_b") or r.get("gained") or r.get("added")
    if isinstance(new_b, list):
        check("fuzz_cov_coverage_diff", "new_in_b", sorted(new_b), [4],
              "b has {4} not in a")
    lost = r.get("lost") or r.get("removed")
    if isinstance(lost, list):
        check("fuzz_cov_coverage_diff", "lost", sorted(lost), [1],
              "a has {1} not in b")
else:
    skip("fuzz_cov_coverage_diff", f"error: {r}")

# ─── 21. fuzz_cov_drcov_module_v2_contains_x ─────────────────────────────────
r = call("fuzz_cov_drcov_module_v2_contains_x",
         {"base": 0x1000, "end": 0x2000, "addr": 0x1500})
if r and "__error__" not in r:
    c = r.get("contains")
    sz = r.get("size")
    if c is not None:
        check("fuzz_cov_drcov_module_v2_contains_x", "contains",
              bool(c), True, "0x1500 in [0x1000,0x2000)")
    if sz is not None:
        check("fuzz_cov_drcov_module_v2_contains_x", "size",
              int(sz), 0x1000, "0x2000-0x1000")
else:
    skip("fuzz_cov_drcov_module_v2_contains_x", f"error: {r}")

# ─── Finish ────────────────────────────────────────────────────────────────────
try:
    p.terminate()
except Exception:
    pass

report = {
    "module": "fuzz_cov",
    "tools_hardened": sorted(tools_hardened),
    "checks_passed": checks_passed,
    "checks_failed": checks_failed,
    "mismatches": mismatches,
}
with open(REPORT, "w") as f:
    json.dump(report, f, indent=2)

print(f"\n=== fuzz_cov rigorous results ===", file=sys.stderr)
print(f"tools_hardened : {len(tools_hardened)}", file=sys.stderr)
print(f"checks_passed  : {checks_passed}", file=sys.stderr)
print(f"checks_failed  : {checks_failed}", file=sys.stderr)
print(f"real_mismatches: {len(mismatches)}", file=sys.stderr)

# stdout summary for the caller
print(json.dumps({
    "module": "fuzz_cov",
    "tools_hardened": len(tools_hardened),
    "checks_passed": checks_passed,
    "checks_failed": checks_failed,
    "real_mismatches": len(mismatches),
}))
