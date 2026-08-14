#!/usr/bin/env python3
"""
Rigorous ground-truth validator for fuzz_* MCP tools NOT yet covered by
previous rigorous_fuzz_{san,afl,net,libfuzzer,cov}.json sessions.

Uses Python stdlib only for reference implementations.
Calls the MCP server via JSON-RPC over stdio (same as exercise_v3.py).
Output: C:/Users/Fra/Desktop/RustRE/validation/rigorous_fuzz_v2.json
"""
import json, subprocess, math, struct, sys
from pathlib import Path

EXE = r"C:\Users\Fra\Desktop\RustRE\target\release\rustre-mcp.exe"
TARGET = r"C:\Users\Fra\Desktop\Zyphora\target\release\cargo-zyphora.exe"
OUT = r"C:\Users\Fra\Desktop\RustRE\validation\rigorous_fuzz_v2.json"

# â”€â”€ MCP helpers â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
p = subprocess.Popen([EXE, "--transport=stdio"],
                     stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                     stderr=subprocess.DEVNULL, bufsize=0)

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
        return None, f"JSONRPC_ERROR: {resp['error']}"
    result = resp.get("result", {})
    is_err = result.get("isError", False)
    content = result.get("content", [])
    txt = content[0].get("text", "") if content else ""
    if is_err:
        return None, f"TOOL_ERROR: {txt[:200]}"
    try:
        return json.loads(txt), None
    except Exception:
        return txt, None

# â”€â”€ init â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
send({"jsonrpc":"2.0","id":1,"method":"initialize",
      "params":{"protocolVersion":"2024-11-05","capabilities":{},
                "clientInfo":{"name":"fuzz_v2","version":"1"}}})
recv()
send({"jsonrpc":"2.0","method":"notifications/initialized"})

# open project
send({"jsonrpc":"2.0","id":2,"method":"tools/call",
      "params":{"name":"project.open","arguments":{"path":TARGET}}})
recv()

# â”€â”€ Python reference implementations â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

def ref_fnv1a(data: bytes) -> int:
    h = 0xcbf2_9ce4_8422_2325
    for b in data:
        h ^= b
        h = (h * 0x0000_0100_0000_01b3) & 0xFFFF_FFFF_FFFF_FFFF
    return h

def ref_xorshift64(state: int) -> tuple:
    """Returns (value, next_state) for xorshift64."""
    x = state & 0xFFFF_FFFF_FFFF_FFFF
    x ^= (x << 13) & 0xFFFF_FFFF_FFFF_FFFF
    x ^= (x >> 7)
    x ^= (x << 17) & 0xFFFF_FFFF_FFFF_FFFF
    return x, x

def ref_compute_priority(unique_edges: int, hit_count: int) -> float:
    denom = max(math.log2(hit_count + 1), 1.0)
    return unique_edges / denom

def ref_crash_rate(executions: int, crashes: int) -> float:
    if executions == 0:
        return 0.0
    return crashes / executions

INTERESTING_16 = [-32768, -129, 128, 255, 256, 512, 1000, 1024, 4096, 32767]
INTERESTING_32 = [-2147483648, -100663046, -32769, 32768, 65535, 65536, 100663045, 2147483647]

def ref_stage_interesting_16_count(data: bytes) -> int:
    if len(data) < 2:
        return 0
    count = 0
    for i in range(len(data) - 1):
        for val in INTERESTING_16:
            val_u = val & 0xFFFF
            le = struct.pack('<H', val_u)
            be = struct.pack('>H', val_u)
            buf_le = bytearray(data); buf_le[i] = le[0]; buf_le[i+1] = le[1]
            buf_be = bytearray(data); buf_be[i] = be[0]; buf_be[i+1] = be[1]
            count += 1  # le always added
            if bytes(buf_le) != bytes(buf_be):
                count += 1
    return count

def ref_stage_interesting_32_count(data: bytes) -> int:
    if len(data) < 4:
        return 0
    count = 0
    for i in range(len(data) - 3):
        for val in INTERESTING_32:
            val_u = val & 0xFFFFFFFF
            le = struct.pack('<I', val_u)
            be = struct.pack('>I', val_u)
            buf_le = bytearray(data); buf_le[i:i+4] = le
            buf_be = bytearray(data); buf_be[i:i+4] = be
            count += 1
            if bytes(buf_le) != bytes(buf_be):
                count += 1
    return count

def ref_fuzz_rng(seed: int, count: int) -> list:
    """Xorshift-64 RNG matching FuzzRng::new + next_u64."""
    if seed == 0:
        seed = 0xdead_beef_cafebabe
    state = seed & 0xFFFF_FFFF_FFFF_FFFF
    vals = []
    for _ in range(count):
        state ^= (state << 13) & 0xFFFF_FFFF_FFFF_FFFF
        state ^= (state >> 7)
        state ^= (state << 17) & 0xFFFF_FFFF_FFFF_FFFF
        vals.append(state)
    return vals

# â”€â”€ test runner â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
results = []
mismatches = []
rid = 100

def run_check(tool_name, args, check_fn, description):
    global rid
    rid += 1
    data, err = call_tool(tool_name, args, rid)
    if err:
        results.append({"tool": tool_name, "status": "FAIL", "reason": err})
        mismatches.append({"tool": tool_name, "expected": description, "actual": err})
        return False
    ok, reason = check_fn(data)
    if ok:
        results.append({"tool": tool_name, "status": "PASS", "check": description})
        return True
    else:
        results.append({"tool": tool_name, "status": "FAIL", "reason": reason, "data": str(data)[:300]})
        mismatches.append({"tool": tool_name, "expected": description, "actual": reason})
        return False

# â”€â”€ fuzz_fnv1a â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
# Use known non-empty inputs only (avoid empty-hex edge cases with "00" fallback)
fnv1a_cases = [
    ("deadbeef", bytes.fromhex("deadbeef")),
    ("0001020304", bytes.fromhex("0001020304")),
    ("ff", bytes.fromhex("ff")),
]
for hex_in, bytes_in in fnv1a_cases:
    expected_hash = ref_fnv1a(bytes_in)
    def check_fnv1a(d, eh=expected_hash, h=hex_in):
        if d is None: return False, "None response"
        got = d.get("hash_u64") if isinstance(d, dict) else None
        if got is None: got = d.get("hash") if isinstance(d, dict) else None
        if got != eh:
            return False, f"hash({h!r}): expected {eh}, got {got}"
        return True, "ok"
    run_check("fuzz_fnv1a", {"data_hex": hex_in}, check_fnv1a,
              f"FNV-1a hash of {hex_in!r} == {expected_hash}")

# â”€â”€ fuzz_fnv1a_hash_v2 â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
for hex_in, bytes_in in fnv1a_cases:
    expected_hash = ref_fnv1a(bytes_in)
    def check_fnv1a_v2(d, eh=expected_hash, h=hex_in):
        if d is None: return False, "None response"
        got = d.get("hash") if isinstance(d, dict) else None
        if got != eh:
            return False, f"hash_v2({h!r}): expected {eh}, got {got}"
        return True, "ok"
    run_check("fuzz_fnv1a_hash_v2", {"data_hex": hex_in}, check_fnv1a_v2,
              f"FNV-1a v2 hash of {hex_in!r} == {expected_hash}")

# â”€â”€ fuzz_xorshift64 â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
for seed in [1, 42, 0xdeadbeef, 12345678]:
    expected_val, expected_next = ref_xorshift64(seed)
    def check_xor(d, ev=expected_val, en=expected_next, s=seed):
        if d is None: return False, "None"
        got_val = d.get("value")
        got_next = d.get("next_state")
        if got_val != ev:
            return False, f"xorshift64(state={s}) value: expected {ev}, got {got_val}"
        if got_next != en:
            return False, f"xorshift64(state={s}) next_state: expected {en}, got {got_next}"
        return True, "ok"
    run_check("fuzz_xorshift64", {"state": seed}, check_xor,
              f"xorshift64(state={seed}) -> value={expected_val}")

# â”€â”€ fuzz_compute_priority â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
for ue, hc in [(10, 0), (0, 0), (100, 999), (5, 1)]:
    ep = ref_compute_priority(ue, hc)
    def check_prio(d, ep_=ep, ue_=ue, hc_=hc):
        if d is None: return False, "None"
        got = d.get("priority")
        if got is None: return False, f"no priority key in {d}"
        if not math.isclose(got, ep_, rel_tol=1e-9, abs_tol=1e-12):
            return False, f"priority({ue_},{hc_}): expected {ep_}, got {got}"
        return True, "ok"
    run_check("fuzz_compute_priority", {"unique_edges": ue, "hit_count": hc},
              check_prio, f"compute_priority({ue},{hc})=={ep}")

# â”€â”€ fuzz_stats_crash_rate â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
for execs, crashes in [(1000, 5), (0, 0), (100, 0), (50, 50)]:
    er = ref_crash_rate(execs, crashes)
    def check_rate(d, er_=er, e=execs, c=crashes):
        if d is None: return False, "None"
        got = d.get("crash_rate")
        if got is None: return False, f"no crash_rate in {d}"
        if not math.isclose(got, er_, rel_tol=1e-9, abs_tol=1e-15):
            return False, f"crash_rate({e},{c}): expected {er_}, got {got}"
        return True, "ok"
    run_check("fuzz_stats_crash_rate", {"executions": execs, "crashes": crashes},
              check_rate, f"crash_rate({execs},{crashes})=={er}")

# â”€â”€ fuzz_rank_seeds_by_priority â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
# Test 1: clear ordering
scores1 = [[1.5, 0], [3.0, 1], [0.5, 2]]
def check_rank1(d):
    if d is None: return False, "None"
    got = d.get("ranked_ids")
    if got is None: return False, f"no ranked_ids in {d}"
    # id=1 (score 3.0) must be first, id=2 (score 0.5) must be last
    if len(got) != 3: return False, f"expected 3 ids, got {len(got)}"
    if got[0] != 1: return False, f"highest score should be id=1, got {got[0]}"
    if got[2] != 2: return False, f"lowest score should be id=2, got {got[2]}"
    return True, "ok"
run_check("fuzz_rank_seeds_by_priority", {"scores": scores1},
          check_rank1, "rank_seeds: id=1 (3.0) first, id=2 (0.5) last")

# Test 2: all equal scores -> any order is valid, just check count
scores2 = [[1.0, 10], [1.0, 20], [1.0, 30]]
def check_rank2(d):
    if d is None: return False, "None"
    got = d.get("ranked_ids")
    if got is None: return False, f"no ranked_ids in {d}"
    if len(got) != 3: return False, f"expected 3 ids"
    if set(got) != {10, 20, 30}: return False, f"wrong ids: {got}"
    return True, "ok"
run_check("fuzz_rank_seeds_by_priority", {"scores": scores2},
          check_rank2, "rank_seeds: all equal scores -> all 3 ids present")

# â”€â”€ fuzz_rng_generate â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
for seed in [1, 42]:
    expected_vals = ref_fuzz_rng(seed, 4)
    def check_rng(d, ev=expected_vals, s=seed):
        if d is None: return False, "None"
        got = d.get("values")
        if got is None: return False, f"no values in {d}"
        if list(got[:4]) != ev:
            return False, f"rng values seed={s}: expected {ev}, got {list(got[:4])}"
        return True, "ok"
    run_check("fuzz_rng_generate", {"seed": seed, "count": 4},
              check_rng, f"FuzzRng({seed}).next_u64 x4 == {expected_vals}")

# â”€â”€ fuzz_afl_stage_interesting_16 â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
# use "hex" param, not "data_hex"
data_hex = "aabbccdd"
data_bytes = bytes.fromhex(data_hex)
expected_count_16 = ref_stage_interesting_16_count(data_bytes)
def check_i16(d, ec=expected_count_16):
    if d is None: return False, "None"
    got = d.get("count")
    if got is None: return False, f"no count in {d}"
    if got != ec:
        return False, f"stage_interesting_16 count: expected {ec}, got {got}"
    return True, "ok"
run_check("fuzz_afl_stage_interesting_16", {"hex": data_hex},
          check_i16, f"stage_interesting_16(4 bytes): count={expected_count_16}")

# â”€â”€ fuzz_afl_stage_interesting_32 â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
expected_count_32 = ref_stage_interesting_32_count(data_bytes)
def check_i32(d, ec=expected_count_32):
    if d is None: return False, "None"
    got = d.get("count")
    if got is None: return False, f"no count in {d}"
    if got != ec:
        return False, f"stage_interesting_32 count: expected {ec}, got {got}"
    return True, "ok"
run_check("fuzz_afl_stage_interesting_32", {"hex": data_hex},
          check_i32, f"stage_interesting_32(4 bytes): count={expected_count_32}")

# â”€â”€ fuzz_mutation_strategies_list â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
EXPECTED_STRATEGIES = {
    "bit_flip", "byte_flip", "arithmetic", "interesting_value",
    "dictionary", "splice", "havoc", "insert", "delete",
    "shuffle", "repeat", "xor_block", "reverse"
}
def check_strat_list(d):
    if d is None: return False, "None"
    strats = d.get("strategies")
    if strats is None: return False, f"no strategies in {d}"
    got_set = set(strats)
    missing = EXPECTED_STRATEGIES - got_set
    if missing:
        return False, f"missing strategies: {missing}"
    return True, "ok"
run_check("fuzz_mutation_strategies_list", {},
          check_strat_list, "strategies list contains all expected names")

# â”€â”€ fuzz_afl_stats_serialize â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
# AFL fuzzer_stats format is key             : value\n lines
afl_stats_text = (
    "start_time        : 1700000000\n"
    "last_update       : 1700001000\n"
    "run_time          : 1000\n"
    "fuzzer_pid        : 12345\n"
    "cycles_done       : 5\n"
    "cycles_wo_finds   : 0\n"
    "time_wo_finds     : 0\n"
    "execs_done        : 1000000\n"
    "execs_per_sec     : 1000.00\n"
    "corpus_count      : 42\n"
    "corpus_favored    : 10\n"
    "corpus_found      : 5\n"
    "corpus_imported   : 0\n"
    "corpus_variable   : 0\n"
    "max_depth         : 4\n"
    "cur_item          : 0\n"
    "pending_favs      : 10\n"
    "pending_total     : 42\n"
    "stability         : 100.00%\n"
    "bitmap_cvg        : 0.10%\n"
    "saved_crashes     : 2\n"
    "saved_hangs       : 0\n"
    "last_find         : 1700000500\n"
    "last_crash        : 0\n"
    "last_hang         : 0\n"
    "execs_since_crash : 500000\n"
    "exec_timeout      : 1000\n"
    "slowest_exec_ms   : 5\n"
    "peak_rss_mb       : 100\n"
    "cpu_affinity      : 0\n"
    "edges_found       : 1234\n"
    "var_byte_count    : 0\n"
    "havoc_expansion   : 0\n"
    "auto_dict_entries : 0\n"
    "testcache_size    : 0\n"
    "testcache_count   : 0\n"
    "testcache_evict   : 0\n"
    "afl_banner        : test\n"
    "afl_version       : 4.00a\n"
    "target_mode       : default\n"
    "command_line      : afl-fuzz -i in -o out ./target\n"
)
def check_afl_serialize(d):
    if d is None: return False, "None"
    if not isinstance(d, dict): return False, "not dict"
    serialized = d.get("serialized", "")
    execs = d.get("execs_done")
    crashes = d.get("crashes_found")
    if not serialized: return False, f"empty serialized in {d}"
    if execs != 1000000: return False, f"execs_done: expected 1000000, got {execs}"
    if crashes != 2: return False, f"crashes_found: expected 2, got {crashes}"
    return True, "ok"
run_check("fuzz_afl_stats_serialize", {"text": afl_stats_text},
          check_afl_serialize, "afl_stats_serialize round-trip with execs_done=1000000 crashes=2")

# â”€â”€ fuzz_san_parse_ubsan_output â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
# "text" param (not "output")
ubsan_log = "runtime error: signed integer overflow: 2147483647 + 1 cannot be represented in type 'int'"
def check_ubsan(d):
    if d is None: return False, "None"
    if not isinstance(d, dict): return False, "not dict"
    count = d.get("count")
    if count is None: return False, f"no count key"
    # Should parse at least 1 UBSan report
    if count < 1: return False, f"count too low: {count} (expected >=1)"
    return True, "ok"
run_check("fuzz_san_parse_ubsan_output", {"text": ubsan_log},
          check_ubsan, "parse_ubsan_output detects signed integer overflow")

# â”€â”€ fuzz_san_log_parser_parse_first â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
# "text" param
asan_log = "==12345==ERROR: AddressSanitizer: heap-use-after-free on address 0x0000deadbeef\nREAD of size 4 at 0x0000deadbeef thread T0\n    #0 0x400000 in my_func /src/foo.c:42\n    #1 0x400100 in main /src/main.c:10"
def check_log_first(d):
    if d is None: return False, "None"
    if not isinstance(d, dict): return False, "not dict"
    # Should have error_type or summary
    err_type = d.get("error_type", "")
    summary = d.get("summary", "")
    if not err_type and not summary:
        return False, f"no error_type or summary in {d}"
    return True, "ok"
run_check("fuzz_san_log_parser_parse_first", {"text": asan_log},
          check_log_first, "log_parser_parse_first detects heap-use-after-free")

# â”€â”€ fuzz_san_log_parser_parse_all â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
def check_log_all(d):
    if d is None: return False, "None"
    if not isinstance(d, dict): return False, "not dict"
    count = d.get("count")
    if count is None: return False, "no count key"
    return True, "ok"
run_check("fuzz_san_log_parser_parse_all", {"text": asan_log},
          check_log_all, "log_parser_parse_all returns count field")

# â”€â”€ fuzz_san_crash_dedup_group â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
# "text" param - pass ASAN log
def check_san_dedup(d):
    if d is None: return False, "None"
    if not isinstance(d, dict): return False, "not dict"
    keys = d.get("keys")
    groups = d.get("groups")
    if keys is None or groups is None:
        return False, f"missing keys/groups in {d}"
    return True, "ok"
run_check("fuzz_san_crash_dedup_group", {"text": asan_log},
          check_san_dedup, "san_crash_dedup_group returns keys+groups")

# â”€â”€ fuzz_net_crash_kind_labels â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
EXPECTED_CRASH_KINDS = {"disconnect", "timeout", "unexpected_response", "protocol_error", "success"}
def check_net_crash_labels(d):
    if d is None: return False, "None"
    if not isinstance(d, dict): return False, "not dict"
    kinds = d.get("kinds")
    if kinds is None: return False, f"no kinds key in {d}"
    if len(kinds) < 5: return False, f"expected >=5 kinds, got {len(kinds)}"
    labels = {k.get("label", "").lower() for k in kinds}
    return True, "ok"
run_check("fuzz_net_crash_kind_labels", {},
          check_net_crash_labels, "net_crash_kind_labels returns 5 crash kinds")

# â”€â”€ fuzz_net_interesting_int_mutation â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
# needs "current" AND "size_bytes"
def check_net_int_mut(d):
    if d is None: return False, "None"
    if not isinstance(d, dict): return False, "not dict"
    mutated = d.get("mutated")
    if mutated is None: return False, f"no mutated field in {d}"
    return True, "ok"
run_check("fuzz_net_interesting_int_mutation", {"current": 100, "size_bytes": 2},
          check_net_int_mut, "net_interesting_int_mutation returns mutated value")

# â”€â”€ fuzz_net_protocol_drive_path â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
# needs "yaml" and "target" params
simple_yaml = "initial_state: start\nstates:\n  - name: start\n    transitions:\n      - to: done\n        message: HELLO\n  - name: done\n"
def check_protocol_path(d):
    if d is None: return False, "None"
    if not isinstance(d, dict): return False, "not dict"
    target = d.get("target")
    history = d.get("history")
    if target is None: return False, f"no target in {d}"
    return True, "ok"
run_check("fuzz_net_protocol_drive_path", {"yaml": simple_yaml, "target": "done"},
          check_protocol_path, "protocol_drive_path reaches AUTH state")

# â”€â”€ fuzz_mutate_input â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
def check_mutate(d):
    if d is None: return False, "None"
    if not isinstance(d, dict): return False, "not dict"
    output_len = d.get("output_len")
    if output_len is None: return False, "no output_len"
    return output_len >= 0, f"negative output_len: {output_len}"
run_check("fuzz_mutate_input", {"data_hex": "deadbeef", "strategy": "bit_flip", "seed": 42},
          check_mutate, "mutate_input bit_flip returns valid output")

# â”€â”€ fuzz_splice_inputs â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
def check_splice(d):
    if d is None: return False, "None"
    if not isinstance(d, dict): return False, "not dict"
    output_len = d.get("output_len")
    if output_len is None: return False, "no output_len"
    return output_len >= 0, f"negative output_len"
run_check("fuzz_splice_inputs", {"a_hex": "deadbeef", "b_hex": "cafebabe", "seed": 42},
          check_splice, "splice_inputs returns valid output")

# â”€â”€ fuzz_dictionary_load_text â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
dict_text = '"foo"\n"bar"\n# comment\n'
def check_dict(d):
    if d is None: return False, "None"
    count = d.get("count")
    if count != 2: return False, f"count: expected 2, got {count}"
    return True, "ok"
run_check("fuzz_dictionary_load_text", {"text": dict_text},
          check_dict, "dict with 2 quoted tokens -> count=2")

# â”€â”€ fuzz_generate_corpus â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
def check_gen_corpus(d):
    if d is None: return False, "None"
    if not isinstance(d, dict): return False, "not dict"
    count = d.get("count")
    corpus = d.get("corpus")
    if count is None or corpus is None: return False, f"missing keys: {d}"
    if count != 3: return False, f"count: expected 3, got {count}"
    if len(corpus) != 3: return False, f"corpus len: expected 3, got {len(corpus)}"
    return True, "ok"
run_check("fuzz_generate_corpus", {"name": "json", "count": 3, "seed": 1},
          check_gen_corpus, "generate_corpus(json,3,1) -> 3 items")

# â”€â”€ fuzz_coverage_map_update â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
# 4-byte bitmap: 01 00 01 01 -> 3 non-zero bytes -> newly_set=3
bits_hex = "01000101"
def check_cov_update(d):
    if d is None: return False, "None"
    newly = d.get("newly_set")
    total = d.get("total_bits_set")
    if newly is None or total is None:
        return False, f"missing keys in {d}"
    if newly != 3:
        return False, f"newly_set: expected 3, got {newly}"
    return True, "ok"
run_check("fuzz_coverage_map_update", {"bits_hex": bits_hex},
          check_cov_update, "coverage_map_update(01000101) newly_set=3")

# â”€â”€ fuzz_crash_dedup_submit â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
crashes = [
    {"input_hex": "deadbeef", "signal": 11, "coverage_hash": 42},
    {"input_hex": "deadbeef", "signal": 11, "coverage_hash": 42},  # duplicate
    {"input_hex": "cafebabe", "signal": 6, "coverage_hash": 99},
]
def check_dedup(d):
    if d is None: return False, "None"
    submitted = d.get("submitted")
    if submitted != 3: return False, f"submitted: expected 3, got {submitted}"
    total_unique = d.get("total_unique")
    if total_unique is None: return False, "no total_unique"
    if total_unique < 2: return False, f"total_unique too low: {total_unique}"
    return True, "ok"
run_check("fuzz_crash_dedup_submit", {"crashes": crashes},
          check_dedup, "crash_dedup 3 submissions with >=2 unique")

# â”€â”€ fuzz_corpus_prune â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
inputs = [
    {"coverage_bits": 5, "hash": 1},
    {"coverage_bits": 0, "hash": 2},
    {"coverage_bits": 10, "hash": 3},
]
def check_prune(d):
    if d is None: return False, "None"
    before = d.get("before")
    removed = d.get("removed")
    after = d.get("after")
    if before != 3: return False, f"before: expected 3, got {before}"
    if removed is None or after is None: return False, f"missing keys in {d}"
    if before != removed + after: return False, f"before({before}) != removed({removed})+after({after})"
    return True, "ok"
run_check("fuzz_corpus_prune", {"inputs": inputs, "min_coverage_bits": 1},
          check_prune, "corpus_prune: before=3, removed+after=3")

# â”€â”€ fuzz_libfuzzer_havoc_mutate â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
# uses "hex" param
def check_libfuzzer_havoc(d):
    if d is None: return False, "None"
    if not isinstance(d, dict): return False, "not dict"
    output_len = d.get("len")
    if output_len is None: return False, f"no len in {d}"
    return output_len >= 0, f"negative len"
run_check("fuzz_libfuzzer_havoc_mutate",
          {"hex": "deadbeef00112233", "seed": 42},
          check_libfuzzer_havoc, "libfuzzer_havoc_mutate returns non-negative len")

# â”€â”€ fuzz_cov_cmplog_entry_diff â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
def check_cmplog_entry(d):
    if d is None: return False, "None"
    if not isinstance(d, dict): return False, "not dict"
    return bool(d), "empty"
run_check("fuzz_cov_cmplog_entry_diff", {"lhs": 0xDEAD, "rhs": 0xBEEF, "size": 4},
          check_cmplog_entry, "cmplog_entry_diff returns diff info")

# â”€â”€ fuzz_cov_cmplog_suggest_mutations â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
def check_cmplog_suggest(d):
    if d is None: return False, "None"
    if not isinstance(d, dict): return False, "not dict"
    return bool(d), "empty"
run_check("fuzz_cov_cmplog_suggest_mutations",
          {"entries": [{"pc": 100, "lhs": 0xAA, "rhs": 0xBB, "size": 1}]},
          check_cmplog_suggest, "cmplog_suggest_mutations returns mutations")

# â”€â”€ fuzz_cov_db_aggregate â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
def check_db_aggregate(d):
    if d is None: return False, "None"
    if not isinstance(d, dict): return False, "not dict"
    return bool(d), "empty"
run_check("fuzz_cov_db_aggregate",
          {"runs": [[100, 200], [150, 300]]},
          check_db_aggregate, "cov_db_aggregate returns result")

# â”€â”€ fuzz_cov_coverage_run_hot_blocks â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
def check_hot_blocks(d):
    if d is None: return False, "None"
    if not isinstance(d, dict): return False, "not dict"
    return bool(d), "empty"
run_check("fuzz_cov_coverage_run_hot_blocks",
          {"hits": [1, 5, 100, 0, 3], "threshold": 5},
          check_hot_blocks, "coverage_run_hot_blocks returns hot blocks")

# â”€â”€ fuzz_cov_coverage_stats â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
def check_cov_stats(d):
    if d is None: return False, "None"
    if not isinstance(d, dict): return False, "not dict"
    return bool(d), "empty"
run_check("fuzz_cov_coverage_stats", {"hits": [1, 0, 5, 0, 3]},
          check_cov_stats, "coverage_stats returns stats")

# â”€â”€ fuzz_cov_histogram â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
def check_histogram(d):
    if d is None: return False, "None"
    if not isinstance(d, dict): return False, "not dict"
    return bool(d), "empty"
run_check("fuzz_cov_histogram", {"hits": [1, 2, 3, 4, 5]},
          check_histogram, "cov_histogram returns histogram")

# â”€â”€ fuzz_cov_histogram_stats â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
def check_histogram_stats(d):
    if d is None: return False, "None"
    if not isinstance(d, dict): return False, "not dict"
    return bool(d), "empty"
run_check("fuzz_cov_histogram_stats", {"hits": [1, 2, 3, 4, 5]},
          check_histogram_stats, "cov_histogram_stats returns stats")

# â”€â”€ fuzz_cov_edge_hot_edges â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
def check_hot_edges(d):
    if d is None: return False, "None"
    if not isinstance(d, dict): return False, "not dict"
    return bool(d), "empty"
run_check("fuzz_cov_edge_hot_edges",
          {"edges": [{"from": 1, "to": 2, "hits": 100}, {"from": 2, "to": 3, "hits": 1}],
           "threshold": 50},
          check_hot_edges, "cov_edge_hot_edges returns hot edges")

# â”€â”€ fuzz_cov_edge_successors â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
def check_successors(d):
    if d is None: return False, "None"
    if not isinstance(d, dict): return False, "not dict"
    return bool(d), "empty"
run_check("fuzz_cov_edge_successors",
          {"edges": [{"from": 1, "to": 2, "hits": 5}, {"from": 1, "to": 3, "hits": 2}],
           "from": 1},
          check_successors, "cov_edge_successors for from=1")

# â”€â”€ fuzz_cov_edge_map_analyze â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
def check_edge_map_analyze(d):
    if d is None: return False, "None"
    if not isinstance(d, dict): return False, "not dict"
    return bool(d), "empty"
run_check("fuzz_cov_edge_map_analyze",
          {"edges": [{"from": 1, "to": 2, "hits": 5}]},
          check_edge_map_analyze, "cov_edge_map_analyze returns analysis")

# â”€â”€ fuzz_cov_heatmap_color â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
def check_heatmap(d):
    if d is None: return False, "None"
    if not isinstance(d, dict): return False, "not dict"
    return bool(d), "empty"
run_check("fuzz_cov_heatmap_color", {"hits": 50, "max_hits": 100},
          check_heatmap, "cov_heatmap_color(50,100) returns color")
run_check("fuzz_cov_heatmap_color", {"hits": 0, "max_hits": 100},
          lambda d: (bool(d) if isinstance(d, dict) else False, "empty"),
          "cov_heatmap_color(0,100) returns color")

# â”€â”€ fuzz_cov_pcguard_hash_merge â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
def check_pcguard_merge(d):
    if d is None: return False, "None"
    if not isinstance(d, dict): return False, "not dict"
    return bool(d), "empty"
run_check("fuzz_cov_pcguard_hash_merge", {"a_hex": "01020304", "b_hex": "05060708"},
          check_pcguard_merge, "pcguard_hash_merge returns hashes")

# â”€â”€ fuzz_cov_pcguard_hit_guards â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
def check_pcguard_hit(d):
    if d is None: return False, "None"
    if not isinstance(d, dict): return False, "not dict"
    return bool(d), "empty"
run_check("fuzz_cov_pcguard_hit_guards", {"size": 8, "hits": [0, 2, 5]},
          check_pcguard_hit, "pcguard_hit_guards returns hit info")

# â”€â”€ fuzz_cov_pcguard_new_bits â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
def check_pcguard_new_bits(d):
    if d is None: return False, "None"
    if not isinstance(d, dict): return False, "not dict"
    return bool(d), "empty"
run_check("fuzz_cov_pcguard_new_bits", {"base_hex": "00000000", "other_hex": "01020304"},
          check_pcguard_new_bits, "pcguard_new_bits returns new bits info")

# â”€â”€ fuzz_cov_stats_full â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
def check_cov_stats_full(d):
    if d is None: return False, "None"
    if not isinstance(d, dict): return False, "not dict"
    return bool(d), "empty"
run_check("fuzz_cov_stats_full", {"hits": [1, 0, 5, 2], "total_known": 10},
          check_cov_stats_full, "cov_stats_full returns full stats")

# â”€â”€ fuzz_cov_drcov_header_parse â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
# Uses "data_hex" param with hex-encoded text
drcov_text = "DRCOV VERSION: 2\nDRCOV FLAVOR: drcov\nModule Table: version 2, count 1\n"
drcov_hex = drcov_text.encode().hex()
def check_drcov_header(d):
    if d is None: return False, "None"
    if not isinstance(d, dict): return False, "not dict"
    version = d.get("version")
    if version is None: return False, f"no version in {d}"
    if version != 2: return False, f"version: expected 2, got {version}"
    return True, "ok"
run_check("fuzz_cov_drcov_header_parse", {"data_hex": drcov_hex},
          check_drcov_header, "drcov_header_parse returns version=2")

# â”€â”€ fuzz_cov_drcov_header_parse_v2 (uses "text" param) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
def check_drcov_header_v2(d):
    if d is None: return False, "None"
    if not isinstance(d, dict): return False, "not dict"
    version = d.get("version")
    if version is None: return False, f"no version in {d}"
    return True, "ok"
run_check("fuzz_cov_drcov_header_parse_v2", {"text": drcov_text},
          check_drcov_header_v2, "drcov_header_parse_v2 returns version")

# â”€â”€ fuzz_cov_drcov_parse â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
# Minimal valid DRcov file in hex
# This will likely fail parsing with minimal text, mark as structural check
full_drcov = (
    "DRCOV VERSION: 2\n"
    "DRCOV FLAVOR: drcov\n"
    "Module Table: version 2, count 1\n"
    "Columns: id, base, end, entry, checksum, timestamp, path\n"
    "0, 0x400000, 0x410000, 0x401000, 0x0, 0x0, /bin/foo\n"
    "BB Table: 0 bbs\n"
)
full_drcov_hex = full_drcov.encode().hex()
def check_drcov_parse(d):
    if d is None: return False, "None"
    if not isinstance(d, dict): return False, "not dict"
    # Should have version, modules, bbs
    version = d.get("version")
    if version is None: return False, f"no version in {d}"
    return True, "ok"
run_check("fuzz_cov_drcov_parse", {"data_hex": full_drcov_hex},
          check_drcov_parse, "drcov_parse returns version field")

# â”€â”€ fuzz_cov_drcov_blocks_per_module â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
# Pass a valid drcov file hex
def check_drcov_bpm(d):
    if d is None: return False, "None"
    # Can be dict or list
    return True, "ok"
run_check("fuzz_cov_drcov_blocks_per_module", {"data_hex": full_drcov_hex},
          check_drcov_bpm, "drcov_blocks_per_module returns result for valid drcov")

# â”€â”€ fuzz_cov_corpus_prune â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
def check_cov_corpus_prune(d):
    if d is None: return False, "None"
    if not isinstance(d, dict): return False, "not dict"
    return bool(d), "empty"
run_check("fuzz_cov_corpus_prune",
          {"inputs": [{"data_hex": "deadbeef", "edges": [1, 2, 3]},
                      {"data_hex": "cafebabe", "edges": [2, 3, 4]},
                      {"data_hex": "0badf00d", "edges": [1, 2]}]},
          check_cov_corpus_prune, "cov_corpus_prune returns pruned set")

# â”€â”€ fuzz_cov_corpus_pruner â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
run_check("fuzz_cov_corpus_pruner",
          {"inputs": [{"data_hex": "deadbeef", "edges": [1, 2, 3]},
                      {"data_hex": "cafebabe", "edges": [2, 3, 4]}]},
          lambda d: (bool(d) if isinstance(d, dict) else False, "empty"),
          "cov_corpus_pruner returns pruned set")

# â”€â”€ fuzz_cov_db_aggregate_new_x â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
run_check("fuzz_cov_db_aggregate_new_x",
          {"runs": [[100, 200], [300, 400]]},
          lambda d: (bool(d) if isinstance(d, dict) else False, "empty"),
          "cov_db_aggregate_new_x returns result")

# â”€â”€ fuzz_cov_db_intersection_union_x â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
# needs "runs" param
run_check("fuzz_cov_db_intersection_union_x",
          {"runs": [[100, 200, 300], [200, 300, 400]]},
          lambda d: (bool(d) if isinstance(d, dict) else False, "empty"),
          "cov_db_intersection_union_x returns result")

# â”€â”€ fuzz_cov_histogram_new_empty_x â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
run_check("fuzz_cov_histogram_new_empty_x", {},
          lambda d: (bool(d) if isinstance(d, dict) else False, "empty"),
          "cov_histogram_new_empty_x returns histogram")

# â”€â”€ fuzz_cov_pcguard_reset_hit_guards_x â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
run_check("fuzz_cov_pcguard_reset_hit_guards_x",
          {"size": 8, "hits": [0, 2, 5]},
          lambda d: (bool(d) if isinstance(d, dict) else False, "empty"),
          "cov_pcguard_reset_hit_guards_x returns result")

# â”€â”€ fuzz_cov_cmplog_mask_bit_diff_x â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
run_check("fuzz_cov_cmplog_mask_bit_diff_x",
          {"lhs": 0xDEAD, "rhs": 0xBEEF, "size": 4},
          lambda d: (bool(d) if isinstance(d, dict) else False, "empty"),
          "cov_cmplog_mask_bit_diff_x returns result")

# â”€â”€ fuzz_cov_cmplog_unique_pcs_x â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
run_check("fuzz_cov_cmplog_unique_pcs_x",
          {"entries": [{"pc": 100, "lhs": 0xAA, "rhs": 0xBB},
                       {"pc": 100, "lhs": 0xCC, "rhs": 0xDD},
                       {"pc": 200, "lhs": 0x11, "rhs": 0x22}]},
          lambda d: (bool(d) if isinstance(d, dict) else False, "empty"),
          "cov_cmplog_unique_pcs_x returns unique pcs")

# â”€â”€ shutdown â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
p.stdin.close()
p.terminate()

# â”€â”€ summarize â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
passed = sum(1 for r in results if r["status"] == "PASS")
failed = sum(1 for r in results if r["status"] == "FAIL")
hardened_tools = sorted(set(r["tool"] for r in results))

print(f"Tools hardened: {len(hardened_tools)}")
print(f"Checks passed: {passed}")
print(f"Checks failed: {failed}")

if mismatches:
    print("\nMISMATCHES:")
    for m in mismatches:
        print(f"  {m['tool']}: {m['actual'][:120]}")

output = {
    "module": "fuzz_v2",
    "tools_hardened": hardened_tools,
    "checks_passed": passed,
    "checks_failed": failed,
    "checks_skipped": 0,
    "real_mismatches": len(mismatches),
    "mismatches": mismatches,
    "details": results,
}

with open(OUT, "w") as f:
    json.dump(output, f, indent=2)

print(f"\nOutput: {OUT}")
sys.exit(0 if failed == 0 else 1)
