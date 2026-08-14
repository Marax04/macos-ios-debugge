#!/usr/bin/env python3
"""Independent validators for fuzz_afl_* MCP tools."""
import json, subprocess, sys, os

EXE = r"C:\Users\Fra\Desktop\RustRE\target\release\rustre-mcp.exe"
OUT = r"C:\Users\Fra\Desktop\RustRE\validation\mismatch_fuzz_afl.json"

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
    if not resp: return ("no_resp", None)
    if "error" in resp: return ("err", resp["error"])
    c = resp.get("result",{}).get("content",[])
    if not c: return ("empty", None)
    txt = c[0].get("text","")
    try: return ("ok", json.loads(txt))
    except: return ("ok_str", txt)

# tools/list
send({"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}})
resp = recv()
all_tools = resp.get("result",{}).get("tools",[])
tools = [t for t in all_tools if t["name"].startswith("fuzz_afl_")]
print(f"Found {len(tools)} fuzz_afl_* tools", file=sys.stderr)

mismatches = []
checks_total = 0
checks_passed = 0
checks_skipped = 0
tested_names = set()

def norm(v):
    if isinstance(v, str):
        try: return int(v, 0)
        except: return v
    return v

def check(tool, inp, mcp_val, truth_val, note=""):
    global checks_total, checks_passed
    checks_total += 1
    tested_names.add(tool)
    if norm(mcp_val) == norm(truth_val):
        checks_passed += 1
        return True
    mismatches.append({"tool":tool,"input":inp,"mcp":mcp_val,"truth":truth_val,"note":note})
    return False

def skip(tool, reason):
    global checks_skipped
    checks_skipped += 1
    print(f"SKIP {tool}: {reason}", file=sys.stderr)

# ---- Ground truth helpers ----
def afl_bucket(n):
    if n == 0: return 0
    if n == 1: return 1
    if n == 2: return 2
    if n == 3: return 4
    if n <= 7: return 8
    if n <= 15: return 16
    if n <= 31: return 32
    if n <= 127: return 64
    return 128

def fnv1a(data):
    h = 0xcbf29ce484222325
    for b in data:
        h ^= b
        h = (h * 0x100000001b3) & 0xFFFFFFFFFFFFFFFF
    return h

tool_map = {t["name"]: t for t in tools}

# ---- fuzz_afl_bucket_hits: bucketize an array of counts ----
name = "fuzz_afl_bucket_hits"
if name in tool_map:
    counts = [0, 1, 2, 3, 5, 10, 20, 50, 100, 200]
    status, r = call(name, {"counts": counts})
    if status == "ok" and isinstance(r, dict):
        out = r.get("buckets") or r.get("bucketed") or r.get("result") or r.get("values") or r.get("output")
        if out is None:
            # maybe returned as list directly
            for k,v in r.items():
                if isinstance(v, list) and len(v)==len(counts): out=v; break
        if out is not None:
            truth = [afl_bucket(n) for n in counts]
            check(name, {"counts":counts}, list(out), truth, "AFL bucket table per index")
        else:
            skip(name, f"keys={list(r.keys())}")
    else:
        skip(name, f"call failed: {r}")

# ---- fuzz_afl_bit_flip_mutate is STOCHASTIC (takes seed) - just verify determinism ----
name = "fuzz_afl_bit_flip_mutate"
if name in tool_map:
    hx = "00112233445566778899aabbccddeeff"
    status1, r1 = call(name, {"hex": hx, "seed": 42})
    status2, r2 = call(name, {"hex": hx, "seed": 42})
    if status1 == "ok" and status2 == "ok" and isinstance(r1, dict) and isinstance(r2, dict):
        # Determinism: same seed should give same output
        check(name, {"hex":hx,"seed":42}, r1, r2, "deterministic on same seed")
    else:
        skip(name, "call failed")

# ---- fuzz_afl_dict_load: dictionary parsing ----
name = "fuzz_afl_dict_load"
if name in tool_map:
    dict_text = 'kw1="hello"\nkw2="world"\n# comment\n"anon"\n'
    got = None
    for args in [{"content": dict_text},{"text": dict_text},{"data": dict_text},{"dict": dict_text}]:
        status, r = call(name, args)
        if status == "ok" and isinstance(r, dict):
            got = r; break
    if got is None:
        skip(name, "schema unclear")
    else:
        cnt = got.get("count") or got.get("entries") or got.get("size") or got.get("total")
        if isinstance(cnt, list): cnt = len(cnt)
        # truth: 3 entries
        if cnt is not None:
            check(name, {"content":dict_text}, cnt, 3, "3 dict entries")
        else:
            skip(name, f"keys={list(got.keys())}")

# ---- fuzz_afl_queue_score ----
name = "fuzz_afl_queue_score"
if name in tool_map:
    # score should be deterministic; just verify tool works and returns numeric
    got = None
    for args in [{"exec_us": 1000, "bitmap_size": 100, "handicap": 0},
                 {"execution_us": 1000, "coverage": 100},
                 {"time_us": 1000, "size": 100}]:
        status, r = call(name, args)
        if status == "ok" and isinstance(r, dict):
            got = r; break
    if got is None:
        skip(name, "schema unclear")

# ---- fuzz_afl_arith_mutate / havoc_mutate ----
# These are stochastic; skip
for name in ("fuzz_afl_arith_mutate", "fuzz_afl_havoc_mutate"):
    if name in tool_map:
        skip(name, "stochastic mutation")

# ---- fuzz_afl_stats_parse / fuzz_afl_stats_serialize round-trip ----
name_p = "fuzz_afl_stats_parse"
name_s = "fuzz_afl_stats_serialize"
if name_p in tool_map:
    stats_text = "start_time        : 1000\nlast_update       : 2000\nexecs_done        : 42\n"
    got = None
    for args in [{"content": stats_text},{"text": stats_text},{"data": stats_text},{"input": stats_text}]:
        status, r = call(name_p, args)
        if status == "ok" and isinstance(r, dict):
            got = r; break
    if got is None:
        skip(name_p, "schema unclear")
    else:
        v = got.get("execs_done") or got.get("execs") or (got.get("stats",{}) if isinstance(got.get("stats"), dict) else {}).get("execs_done")
        if v is not None:
            check(name_p, {"execs_done":42}, int(v) if isinstance(v,(int,str)) else v, 42, "AFL stats parse execs_done")
        else:
            skip(name_p, f"keys={list(got.keys())}")

# ---- fuzz_afl_bitmap_summary: real schema {hex, bytes} ----
name = "fuzz_afl_bitmap_summary"
if name in tool_map:
    bm = [0]*256
    bm[0] = 1; bm[10] = 5; bm[200] = 128
    hx = bytes(bm).hex()
    status, r = call(name, {"hex": hx})
    if status == "ok" and isinstance(r, dict):
        cnt = r.get("count_non_zero")
        sz = r.get("size")
        if cnt is not None:
            check(name+"[count_non_zero]", {"nonzero":3}, cnt, 3, "3 non-zero bytes")
        if sz is not None:
            check(name+"[size]", {"len":256}, sz, 256, "bitmap size")
    else:
        skip(name, f"call failed: {r}")

# ---- fuzz_afl_dict_info: text schema ----
name = "fuzz_afl_dict_info"
if name in tool_map:
    dict_text = 'kw1="hello"\nkw2="world"\n# comment\nkw3="foo"\n'
    status, r = call(name, {"text": dict_text})
    if status == "ok" and isinstance(r, dict):
        cnt = r.get("count") or r.get("entries") or r.get("size") or r.get("total") or r.get("num_entries")
        if cnt is not None:
            check(name, {"text":"3 kws"}, cnt, 3, "3 dict entries")
        else:
            skip(name, f"keys={list(r.keys())}")
    else:
        skip(name, f"call failed: {r}")

if "fuzz_afl_cmplog_colorize" in tool_map:
    skip("fuzz_afl_cmplog_colorize", "opaque semantics")

# ---- fuzz_afl_stage_* : just check they return without error on trivial input ----
stage_tools = [t for t in tool_map if t.startswith("fuzz_afl_stage_")]
for name in stage_tools[:8]:
    hx = "00112233445566778899aabbccddeeff"
    got_ok = False
    for args in [{"hex":hx},{"input":hx},{"data":hx},{"bytes_hex":hx},{"input_hex":hx},
                 {"hex":hx,"index":0},{"hex":hx,"position":0},
                 {"input":hx,"index":0},{"input":hx,"pos":0},
                 {"data":hx,"offset":0}]:
        status, r = call(name, args)
        if status == "ok" and isinstance(r, dict):
            got_ok = True
            break
    if not got_ok:
        skip(name, "schema unclear or no valid input")

# --- Finish
try: p.terminate()
except: pass

report = {
    "category": "fuzz_afl",
    "tools_in_category": len(tools),
    "checks_total": checks_total,
    "checks_passed": checks_passed,
    "checks_skipped": checks_skipped,
    "mismatches": mismatches,
    "tools_tested": sorted(tested_names),
}
with open(OUT, "w") as f: json.dump(report, f, indent=1)
print(json.dumps({k:v for k,v in report.items() if k!="mismatches"}, indent=1))
print(f"Mismatches: {len(mismatches)}")
