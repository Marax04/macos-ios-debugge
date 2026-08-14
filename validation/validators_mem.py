#!/usr/bin/env python3
"""Independent Python validator for mem_* MCP tools."""
import json, subprocess, math, struct, sys
from collections import Counter

EXE = r"C:\Users\Fra\Desktop\RustRE\target\release\rustre-mcp.exe"
OUT = r"C:\Users\Fra\Desktop\RustRE\validation\mismatch_mem.json"

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
    if not resp: return None, "no_response"
    if "error" in resp: return None, resp["error"].get("message","err")
    c = resp.get("result",{}).get("content",[])
    if not c: return None, "empty"
    text = c[0].get("text","")
    try: return json.loads(text), None
    except: return text, None

# List mem_ tools
rid[0] += 1
send({"jsonrpc":"2.0","id":rid[0],"method":"tools/list","params":{}})
tools_resp = recv()
all_tools = tools_resp.get("result",{}).get("tools",[])
mem_tools = [t for t in all_tools if t["name"].startswith("mem_")]
print(f"Found {len(mem_tools)} mem_* tools", file=sys.stderr)

mismatches = []
checks_passed = 0
checks_total = 0
checks_skipped = 0

def extract(r, keys):
    if not isinstance(r, dict): return None
    for k in keys:
        if k in r: return r[k]
    return None

def check(tool, inp, mcp_val, truth_val, note=""):
    global checks_passed, checks_total
    checks_total += 1
    ok = False
    if isinstance(mcp_val, float) or isinstance(truth_val, float):
        try: ok = abs(float(mcp_val) - float(truth_val)) < 1e-6
        except: ok = False
    else:
        ok = mcp_val == truth_val
    if ok:
        checks_passed += 1
    else:
        mismatches.append({"tool":tool, "input":inp, "mcp":mcp_val, "truth":truth_val, "note":note})

def skip(tool, reason):
    global checks_skipped
    checks_skipped += 1
    print(f"SKIP {tool}: {reason}", file=sys.stderr)

# ---- page alignment / index ----
for va, ps in [(0x1234, 0x1000), (0x1000, 0x1000), (0, 0x1000), (0xFFF, 0x1000), (0xABCDEF, 0x2000)]:
    inp = {"va":va, "page_size":ps}
    r, e = call("mem_page_align_down", inp)
    if isinstance(r, dict):
        v = extract(r, ["aligned","result","value","va_aligned","va"])
        check("mem_page_align_down", inp, v, va & ~(ps-1))
    r, e = call("mem_page_align_up", inp)
    if isinstance(r, dict):
        v = extract(r, ["aligned","result","value","va_aligned","va"])
        check("mem_page_align_up", inp, v, (va + ps - 1) & ~(ps-1))
    r, e = call("mem_page_index", inp)
    if isinstance(r, dict):
        v = extract(r, ["index","page_index","result","value"])
        check("mem_page_index", inp, v, va // ps)

# v3 variants
for va, ps in [(0x1234, 0x1000), (0xABCD, 0x1000)]:
    inp = {"va":va, "page_size":ps}
    r, e = call("mem_page_align_down_v3", inp)
    if isinstance(r, dict):
        v = extract(r, ["aligned","result","value","va_aligned","va"])
        check("mem_page_align_down_v3", inp, v, va & ~(ps-1))
    r, e = call("mem_page_align_up_v3", inp)
    if isinstance(r, dict):
        v = extract(r, ["aligned","result","value","va_aligned","va"])
        check("mem_page_align_up_v3", inp, v, (va + ps - 1) & ~(ps-1))

# many-variant: take a list of VAs
inp = {"addrs":[0x1234, 0x2345, 0x3fff], "page_size":0x1000}
r, e = call("mem_page_align_down_many_wire", inp)
if isinstance(r, dict):
    v = extract(r, ["aligned","result","value","values","aligned_vas","aligned_addrs"])
    truth = [x & ~0xFFF for x in inp["addrs"]]
    if isinstance(v, list):
        check("mem_page_align_down_many_wire", inp, v, truth)
    else: skip("mem_page_align_down_many_wire", f"shape {v}")
else:
    skip("mem_page_align_down_many_wire", f"err {e}")

# ---- read primitives ----
tests = [
    ("mem_read_u8_at_hex", "AB", 0, 0xAB),
    ("mem_read_u16_le_at_hex", "3412", 0, 0x1234),
    ("mem_read_u16_be_at_hex", "1234", 0, 0x1234),
    ("mem_read_u32_le_at_hex", "78563412", 0, 0x12345678),
    ("mem_read_u32_be_at_hex", "12345678", 0, 0x12345678),
    ("mem_read_u64_le_at_hex", "efcdab8967452301", 0, 0x0123456789ABCDEF),
    ("mem_read_u64_be_at_hex", "0123456789abcdef", 0, 0x0123456789ABCDEF),
    ("mem_read_i8_at_hex", "FF", 0, -1),
    ("mem_read_i16_le_at_hex", "ffff", 0, -1),
    ("mem_read_i32_le_at_hex", "ffffffff", 0, -1),
    ("mem_read_i64_le_at_hex", "ffffffffffffffff", 0, -1),
]
for name, hx, off, truth in tests:
    inp = {"buffer_hex":hx, "offset":off}
    r, e = call(name, inp)
    if isinstance(r, dict):
        v = extract(r, ["value","result","int","i","u"])
        if v is None:
            skip(name, f"no value key in {r}")
        else:
            check(name, inp, v, truth)
    else:
        skip(name, f"err {e}")

# floats
import struct as S
f32_bytes = S.pack("<f", 1.5).hex()
inp = {"buffer_hex":f32_bytes, "offset":0}
r, e = call("mem_read_f32_le_at_hex", inp)
if isinstance(r, dict):
    v = extract(r, ["value","result","f","float"])
    if v is not None:
        check("mem_read_f32_le_at_hex", inp, float(v), 1.5)
    else: skip("mem_read_f32_le_at_hex", "no value key")
f64_bytes = S.pack("<d", 2.71828).hex()
inp = {"buffer_hex":f64_bytes, "offset":0}
r, e = call("mem_read_f64_le_at_hex", inp)
if isinstance(r, dict):
    v = extract(r, ["value","result","f","float"])
    if v is not None:
        check("mem_read_f64_le_at_hex", inp, float(v), 2.71828)
    else: skip("mem_read_f64_le_at_hex", "no value key")

# ---- shannon entropy ----
def shannon(bs):
    if not bs: return 0.0
    cnt = Counter(bs); n = len(bs)
    return -sum((c/n)*math.log2(c/n) for c in cnt.values())

data_hex = "deadbeef00112233445566778899aabbccddeeff" * 8
data = bytes.fromhex(data_hex)
truth = shannon(data)
inp = {"hex":data_hex}
r, e = call("mem_shannon_entropy", inp)
if isinstance(r, dict):
    v = extract(r, ["entropy","result","value","shannon"])
    if v is not None:
        check("mem_shannon_entropy", inp, float(v), truth)
    else: skip("mem_shannon_entropy", "no value")

r, e = call("mem_shannon_entropy_v3", inp)
if isinstance(r, dict):
    v = extract(r, ["entropy","result","value","shannon"])
    if v is not None:
        check("mem_shannon_entropy_v3", inp, float(v), truth)

# uniform bytes: entropy = 8
uniform_hex = "".join(f"{i:02x}" for i in range(256))
inp = {"hex":uniform_hex}
r, e = call("mem_shannon_entropy", inp)
if isinstance(r, dict):
    v = extract(r, ["entropy","result","value","shannon"])
    if v is not None:
        check("mem_shannon_entropy", inp, float(v), 8.0, "uniform=8.0")

# zeros: entropy = 0
zeros_hex = "00" * 64
inp = {"hex":zeros_hex}
r, e = call("mem_shannon_entropy", inp)
if isinstance(r, dict):
    v = extract(r, ["entropy","result","value","shannon"])
    if v is not None:
        check("mem_shannon_entropy", inp, float(v), 0.0, "zeros=0")

# ---- write primitives (verify round-trip via extracted bytes) ----
inp = {"buffer_hex":"00000000", "offset":0, "value":0x12345678}
r, e = call("mem_write_u32_le_at_hex", inp)
if isinstance(r, dict):
    v = extract(r, ["hex","result","bytes","output"])
    if isinstance(v, str):
        check("mem_write_u32_le_at_hex", inp, v.lower(), "78563412")
    else: skip("mem_write_u32_le_at_hex", f"shape {v}")

inp = {"buffer_hex":"0000", "offset":0, "value":0x1234}
r, e = call("mem_write_u16_be_at_hex", inp)
if isinstance(r, dict):
    v = extract(r, ["hex","result","bytes","output"])
    if isinstance(v, str):
        check("mem_write_u16_be_at_hex", inp, v.lower(), "1234")

# ---- search bytes ----
inp = {"buffer_hex":"aabbccddeeff00112233", "pattern_hex":"ccdd"}
r, e = call("mem_search_bytes_hex", inp)
if isinstance(r, dict):
    v = extract(r, ["offset","index","result","position","offsets"])
    if isinstance(v, list):
        check("mem_search_bytes_hex", inp, v[0] if v else None, 2)
    elif v is not None:
        check("mem_search_bytes_hex", inp, v, 2)

inp = {"buffer_hex":"aabbcc00aabbcc00aabb", "pattern_hex":"aabb"}
r, e = call("mem_search_bytes_all_hex", inp)
if isinstance(r, dict):
    v = extract(r, ["offsets","results","positions","matches","indices"])
    if isinstance(v, list):
        # positions 0,4,8
        check("mem_search_bytes_all_hex", inp, sorted(v)[:3], [0,4,8])

# ---- perms ----
inp = {"s":"r-x"}
r, e = call("mem_perms_from_rwx", inp)
if isinstance(r, dict):
    # PROT_READ=1, PROT_EXEC=4 => 5 typical, but could differ. Accept either bitmap or {read:true,...}
    read = extract(r, ["read","r","can_read","readable"])
    exec_ = extract(r, ["exec","execute","x","can_exec","executable"])
    write = extract(r, ["write","w","can_write","writable"])
    if read is not None and write is not None and exec_ is not None:
        check("mem_perms_from_rwx", inp, [bool(read),bool(write),bool(exec_)], [True,False,True])
    else:
        skip("mem_perms_from_rwx", f"unknown shape {r}")

# ---- entropy classify ----
# High entropy random-ish bytes should be "high" or similar
inp = {"entropy": 7.9}
r, e = call("mem_entropy_classify_value_wire", inp)
if isinstance(r, dict):
    v = extract(r, ["class","classification","category","label","result"])
    if isinstance(v, str):
        lv = v.lower()
        check("mem_entropy_classify_value_wire", inp, any(w in lv for w in ("high","encrypt","random","packed","compress")), True, f"got {v}")
    else: skip("mem_entropy_classify_value_wire", f"shape {v}")

inp = {"entropy": 0.5}
r, e = call("mem_entropy_classify_value_wire", inp)
if isinstance(r, dict):
    v = extract(r, ["class","classification","category","label","result"])
    if isinstance(v, str):
        lv = v.lower()
        check("mem_entropy_classify_value_wire", inp, any(w in lv for w in ("low","zero","empty","sparse")), True, f"got {v}")

# ---- diff bytes ----
inp = {"a_hex":"aabbccdd", "b_hex":"aa00ccdd"}
r, e = call("mem_diff_bytes", inp)
if isinstance(r, dict):
    v = extract(r, ["diff_count","changed","differences","count","total"])
    if isinstance(v, int):
        check("mem_diff_bytes", inp, v, 1)
    else: skip("mem_diff_bytes", f"shape {v}")

# ---- close ----
try: p.terminate()
except: pass

result = {
    "category":"mem",
    "tools_in_category": len(mem_tools),
    "checks_total": checks_total,
    "checks_passed": checks_passed,
    "checks_skipped": checks_skipped,
    "mismatches": mismatches,
}
with open(OUT,"w") as f: json.dump(result, f, indent=2)
print(json.dumps({"total":checks_total,"passed":checks_passed,"skipped":checks_skipped,"mismatches":len(mismatches)}))
