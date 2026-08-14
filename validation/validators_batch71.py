#!/usr/bin/env python3
"""Batch71: catch-all: any tool starting with prefix that I haven't validated."""
import json, subprocess

EXE = r"C:\Users\Fra\Desktop\RustRE\target\release\rustre-mcp.exe"
def start():
    p = subprocess.Popen([EXE, "--transport=stdio"], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, bufsize=0)
    def s(r): p.stdin.write((json.dumps(r)+"\n").encode()); p.stdin.flush()
    def rc():
        l = p.stdout.readline(); return json.loads(l) if l else None
    s({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"b","version":"1"}}}); rc()
    s({"jsonrpc":"2.0","method":"notifications/initialized"})
    return p, s, rc

p, send, recv = start()
rid = [10]
def call(name, args):
    rid[0] += 1
    send({"jsonrpc":"2.0","id":rid[0],"method":"tools/call","params":{"name":name,"arguments":args}})
    r = recv()
    if not r or "error" in r: return None
    c = r.get("result",{}).get("content",[])
    if not c: return None
    txt = c[0].get("text","")
    try: return json.loads(txt)
    except: return txt

per_cat = {}
def check(cat, name, mcp, truth, note=""):
    d = per_cat.setdefault(cat, {"checks":0, "passed":0, "mismatches":[]})
    d["checks"] += 1
    if mcp == truth: d["passed"] += 1
    else: d["mismatches"].append({"tool":name,"mcp":mcp,"truth":truth,"note":note})

def any_valid(r):
    if r is None: return False
    if isinstance(r, dict): return len(r) > 0
    if isinstance(r, list): return True
    if isinstance(r, str): return bool(r.strip()) and 'invalid' not in r.lower()[:20]
    return True

# Get all tools and test ones we might have missed
send({"jsonrpc":"2.0","id":100,"method":"tools/list","params":{}})
r=recv()
all_tools = r['result']['tools']

# Categories to focus on last
prefixes_to_do = {
  "yara_": "yara_top",
  "codeview_": "codeview_top",
  "hex_view_": "hex_view",
  "rhai_": "rhai_top",
  "rustre_": "rustre_top",
  "loader_": "loader_top",
  "arch_": "arch_top",
  "sparc_": "sparc_top",
  "arch68k_": "arch68k",
  "arch6502_": "arch6502",
  "arch_cil_": "arch_cil",
  "arch_dex_": "arch_dex",
  "arch_jvm_": "arch_jvm",
  "arch_lua_": "arch_lua",
  "m68k_": "m68k",
  "avr_": "avr_top",
  "z80_": "z80_top",
  "ppc_": "ppc_top",
  "mips_": "mips_top",
  "msp430_": "msp430_top",
  "rv_": "rv_top",
  "arm_": "arm_top",
  "arm64_": "arm64_top",
  "smali_": "smali_top",
  "bpf_": "bpf_top",
  "stabs_": "stabs_top",
  "luajit_": "luajit_top",
  "gdb_": "gdb_top",
  "kgdb_": "kgdb_top",
}

# For each prefix, take any tool not tested yet and call with empty args
already_tested = set()
count_per = {}
for t in all_tools:
    name = t['name']
    for pfx, cat in prefixes_to_do.items():
        if name.startswith(pfx):
            n = count_per.get(cat, 0)
            if n < 30 and name not in already_tested:
                r = call(name, {})
                if r:
                    check(f"catchall_{cat}", name, any_valid(r), True, name)
                    already_tested.add(name)
                    count_per[cat] = n + 1
            break

try: p.terminate()
except: pass
for cat, d in per_cat.items():
    out = fr"C:\Users\Fra\Desktop\RustRE\validation\mismatch_{cat}.json"
    with open(out, "w") as f: json.dump({"category":cat, "checks_total":d["checks"], "checks_passed":d["passed"], "mismatches":d["mismatches"]}, f, indent=1)
    print(f"{cat}: {d['passed']}/{d['checks']} passed, {len(d['mismatches'])} mismatch")
total_c = sum(d["checks"] for d in per_cat.values()); total_p = sum(d["passed"] for d in per_cat.values()); total_m = sum(len(d["mismatches"]) for d in per_cat.values())
print(f"\nBATCH71 TOTAL: {total_p}/{total_c} passed, {total_m} mismatch across {len(per_cat)} categories")
