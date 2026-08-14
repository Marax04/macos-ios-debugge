#!/usr/bin/env python3
"""V2: better regexes + report per-criterion progress."""
import json, subprocess, re
from statistics import mean

EXE = r"C:\Users\Fra\Desktop\RustRE\target\release\rustre-mcp.exe"
TARGET = r"C:\Users\Fra\Desktop\Zyphora\target\release\cargo-zyphora.exe"

def start():
    p = subprocess.Popen([EXE, "--transport=stdio"], stdin=subprocess.PIPE,
                         stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, bufsize=0)
    def send(r): p.stdin.write((json.dumps(r)+"\n").encode()); p.stdin.flush()
    def recv():
        line = p.stdout.readline()
        return json.loads(line) if line else None
    send({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"q","version":"1"}}})
    recv()
    send({"jsonrpc":"2.0","method":"notifications/initialized"})
    return p, send, recv

def call_json(send, recv, name, args):
    send({"jsonrpc":"2.0","id":100,"method":"tools/call","params":{"name":name,"arguments":args}})
    r = recv()
    if not r or "error" in r: return None
    c = r.get("result", {}).get("content", [])
    if not c: return None
    try: return json.loads(c[0].get("text", ""))
    except: return None

def score_decomp(code, meta):
    if not code:
        return 0, {}
    b = {}
    s = 0

    # 1. Function signature has any type keyword before name
    if re.search(r'\b(int|void|__int64|int8_t|int16_t|int32_t|int64_t|uint8_t|uint16_t|uint32_t|uint64_t|char\s*\*|bool)\b[^(]*?\w+\s*\(', code[:400]):
        s += 1; b['1_signature'] = 1
    else: b['1_signature'] = 0

    # 2. Balanced braces
    if code.count('{') == code.count('}') and code.count('{') > 0:
        s += 1; b['2_braces'] = 1
    else: b['2_braces'] = 0

    # 3. Control flow (if/while/for)
    if re.search(r'\b(if|while|for|do|switch)\s*\(', code):
        s += 1; b['3_control_flow'] = 1
    else: b['3_control_flow'] = 0

    # 4. Meaningful vars (>= 4 distinct non-r_XX vars)
    non_r = re.findall(r'\b(?![vV]\d+|arg\d+|a\d+|r_[a-z0-9]+|_\d+)([a-z_][a-z_0-9]{2,})\b', code)
    if len(set(non_r)) > 4:
        s += 1; b['4_var_names'] = 1
    else: b['4_var_names'] = 0

    # 5. Resolved calls (not just sub_HEX)
    if re.search(r'\b(?!sub_[0-9a-fA-F]{6,})[A-Za-z_][A-Za-z0-9_]{2,}\s*\([^);]*\)\s*;', code):
        s += 1; b['5_call_resolve'] = 1
    else: b['5_call_resolve'] = 0

    # 6. Return statement
    if 'return' in code:
        s += 1; b['6_return'] = 1
    else: b['6_return'] = 0

    # 7. Multi-statement (>=3 stmts)
    stmts = [x for x in code.split(';') if x.strip()]
    if len(stmts) >= 3:
        s += 1; b['7_multi_stmt'] = 1
    else: b['7_multi_stmt'] = 0

    # 8. No raw asm-level [reg]=[reg] patterns
    if len(re.findall(r'\[[a-z]+[0-9]*\]\s*=\s*\[', code)) < 2:
        s += 1; b['8_no_raw_asm'] = 1
    else: b['8_no_raw_asm'] = 0

    # 9. Typed variable declarations (int/uint/int64_t etc) — NOT just void*
    # Count decls that are NOT "void *"
    non_void_decls = len(re.findall(r'\b(int8_t|int16_t|int32_t|int64_t|uint8_t|uint16_t|uint32_t|uint64_t|__int64|int|bool|char|float|double|__int32)\s+\w+\s*;', code))
    void_decls = len(re.findall(r'\bvoid\s*\*\s*\w+\s*;', code))
    if non_void_decls > 0 and non_void_decls >= void_decls / 2:
        s += 1; b['9_types'] = 1
    else: b['9_types'] = 0

    # 10. Meta OK
    if meta and meta.get('confidence', 0) >= 50:
        s += 1; b['10_meta'] = 1
    else: b['10_meta'] = 0

    return s, b


p, send, recv = start()
call_json(send, recv, "project.open", {"path": TARGET})
r = call_json(send, recv, "analyze.function", {"binary_id":"bin-0001", "address":0x140000000})
funcs = r.get("functions", []) if r else []
seen = set()
addrs = []
for f in funcs:
    a = int(f["addr"], 16) if isinstance(f.get("addr"), str) else f.get("addr", 0)
    if a not in seen and f.get("confidence") in ("Medium", "High", "Certain"):
        addrs.append(a); seen.add(a)

sample = addrs[:30]
scores = []
btotals = {}
first_out = None
for i, a in enumerate(sample):
    d = call_json(send, recv, "decompile.function", {"binary_id":"bin-0001", "address":a})
    if not d or not isinstance(d, dict): continue
    pc = d.get("pseudo_code", "")
    if first_out is None: first_out = (hex(a), pc)
    s, br = score_decomp(pc, d)
    scores.append(s)
    for k, v in br.items(): btotals[k] = btotals.get(k, 0) + v

try: p.terminate()
except: pass

avg = mean(scores) if scores else 0
print(f"DECOMPILER QUALITY SCORE V2: {avg:.2f} / 10 (sample={len(scores)})")
print(f"Range: {min(scores) if scores else 0} - {max(scores) if scores else 0}")
crit = {'1_signature':"Sig typed",'2_braces':"Braces",'3_control_flow':"Control flow",'4_var_names':"Var names",'5_call_resolve':"Call resolve",'6_return':"Return",'7_multi_stmt':"Multi-stmt",'8_no_raw_asm':"No raw asm",'9_types':"Typed decls",'10_meta':"Meta"}
for k, cnt in sorted(btotals.items()):
    pct = 100*cnt/len(scores) if scores else 0
    print(f"  {k}: {cnt:3d}/{len(scores)} ({pct:5.1f}%) — {crit.get(k,k)}")
if first_out:
    print(f"\nFirst sample {first_out[0]}:")
    print(first_out[1][:500])

with open(r"C:\Users\Fra\Desktop\RustRE\validation\DECOMP_SCORE_V2.json", "w") as f:
    json.dump({"score": avg, "sample_size": len(scores), "breakdown": btotals}, f, indent=2)
