#!/usr/bin/env python3
"""Score decompiler quality on cargo-zyphora sample of 30 functions.
Score based on 10 criteria per function (0-10 scale total)."""
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
    """Score 0-10 based on 10 quality criteria."""
    if not code:
        return 0, {}
    breakdown = {}
    score = 0

    # 1. Has function signature with return type + name
    # Accept: "int64_t name(", "int64_t __fastcall name(", "int name(", etc.
    if re.search(r'\b(int|void|__int64|int8_t|int16_t|int32_t|int64_t|uint8_t|uint16_t|uint32_t|uint64_t|char\s*\*|unsigned|bool)\b.*?\w+\s*\(', code[:400]):
        score += 1; breakdown['1_signature'] = 1
    else:
        breakdown['1_signature'] = 0

    # 2. Has proper braces balance
    if code.count('{') == code.count('}') and code.count('{') > 0:
        score += 1; breakdown['2_braces'] = 1
    else:
        breakdown['2_braces'] = 0

    # 3. Has structured control flow (if/while/for)
    if re.search(r'\b(if|while|for|do|switch)\s*\(', code):
        score += 1; breakdown['3_control_flow'] = 1
    else:
        breakdown['3_control_flow'] = 0

    # 4. Has meaningful variable names (not just v1, v2, v3)
    non_generic_vars = re.findall(r'\b(?![vV]\d+|arg\d+|a\d+|r\d+|_\d+)([a-z_][a-z_0-9]{2,})\b', code)
    if len(set(non_generic_vars)) > 3:
        score += 1; breakdown['4_var_names'] = 1
    else:
        breakdown['4_var_names'] = 0

    # 5. Has resolved function calls (not just sub_XXX)
    if re.search(r'\b(?!sub_[0-9a-f]+)([A-Za-z_][A-Za-z0-9_]{3,})\s*\([^;]*\)\s*;', code):
        score += 1; breakdown['5_call_resolve'] = 1
    else:
        breakdown['5_call_resolve'] = 0

    # 6. Has return statement
    if 'return' in code:
        score += 1; breakdown['6_return'] = 1
    else:
        breakdown['6_return'] = 0

    # 7. Not just single-line dump (multi-statement)
    stmts = [s for s in code.split(';') if s.strip()]
    if len(stmts) >= 3:
        score += 1; breakdown['7_multi_stmt'] = 1
    else:
        breakdown['7_multi_stmt'] = 0

    # 8. No raw memory accesses like [v1] = [v1] + al (indicates raw asm-level)
    raw_mem_count = len(re.findall(r'\[[a-z]+[0-9]*\]\s*=\s*\[', code))
    if raw_mem_count < 2:
        score += 1; breakdown['8_no_raw_asm'] = 1
    else:
        breakdown['8_no_raw_asm'] = 0

    # 9. Has typed variables (not just untyped assignments)
    if re.search(r'\b(int|unsigned|char|long|short|bool|void\s*\*)\s+\w+\s*=', code):
        score += 1; breakdown['9_types'] = 1
    else:
        breakdown['9_types'] = 0

    # 10. Metadata: confidence >= 50 AND variables >= 1
    if meta and meta.get('confidence', 0) >= 50 and len(meta.get('variables', [])) >= 1:
        score += 1; breakdown['10_meta'] = 1
    else:
        breakdown['10_meta'] = 0

    return score, breakdown


p, send, recv = start()
call_json(send, recv, "project.open", {"path": TARGET})
call_json(send, recv, "analyze.function", {"binary_id":"bin-0001", "address":0x140000000})
r = call_json(send, recv, "analyze.function", {"binary_id":"bin-0001", "address":0x140000000})
funcs = r.get("functions", []) if r else []
addrs = []
seen = set()
for f in funcs:
    a = int(f["addr"], 16) if isinstance(f.get("addr"), str) else f.get("addr", 0)
    if a not in seen and f.get("confidence") in ("Medium", "High", "Certain"):
        addrs.append(a); seen.add(a)

sample = addrs[:30]
print(f"Sampling {len(sample)} functions (Medium+ confidence)")

scores = []
breakdown_totals = {}
sample_outputs = []
for i, a in enumerate(sample):
    d = call_json(send, recv, "decompile.function", {"binary_id":"bin-0001", "address":a})
    if not d or not isinstance(d, dict):
        continue
    pc = d.get("pseudo_code", "")
    s, b = score_decomp(pc, d)
    scores.append(s)
    for k, v in b.items():
        breakdown_totals[k] = breakdown_totals.get(k, 0) + v
    if i < 3:
        sample_outputs.append({"addr": hex(a), "score": s, "code_preview": pc[:200]})

try: p.terminate()
except: pass

avg = mean(scores) if scores else 0
print()
print("="*60)
print(f"DECOMPILER QUALITY SCORE: {avg:.2f} / 10")
print("="*60)
print(f"Sample size: {len(scores)}")
print(f"Min: {min(scores) if scores else 0} | Max: {max(scores) if scores else 0} | Std: from {len(scores)} runs")
print()
print("Per-criterion pass rate (out of {} functions):".format(len(scores)))
crit_names = {
    '1_signature': "Function signature typed",
    '2_braces': "Balanced braces",
    '3_control_flow': "Structured control flow (if/while/for)",
    '4_var_names': "Meaningful variable names",
    '5_call_resolve': "Resolved function calls",
    '6_return': "Return statement",
    '7_multi_stmt': "Multi-statement body",
    '8_no_raw_asm': "No raw asm-level [reg] accesses",
    '9_types': "Typed variables",
    '10_meta': "Confidence >= 50 AND variables inferred",
}
for k, cnt in sorted(breakdown_totals.items()):
    pct = 100*cnt/len(scores) if scores else 0
    print(f"  {k}: {cnt:3d}/{len(scores)} ({pct:5.1f}%) — {crit_names.get(k, k)}")

print()
print("Sample outputs (first 3):")
for s in sample_outputs:
    print(f"\n{s['addr']} (score {s['score']}/10):")
    print(f"  {s['code_preview']}")

with open(r"C:\Users\Fra\Desktop\RustRE\validation\DECOMP_SCORE.json", "w") as f:
    json.dump({"score_out_of_10": avg, "sample_size": len(scores), "breakdown": breakdown_totals}, f, indent=2)

print(f"\nSaved to validation/DECOMP_SCORE.json")
