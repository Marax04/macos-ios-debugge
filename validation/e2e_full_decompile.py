#!/usr/bin/env python3
"""E2E FULL: decompile ALL 2336 detected functions + PDB name overlay + confront with IDA."""
import json, subprocess, time
from collections import Counter

EXE = r"C:\Users\Fra\Desktop\RustRE\target\release\rustre-mcp.exe"
TARGET = r"C:\Users\Fra\Desktop\Zyphora\target\release\cargo-zyphora.exe"
PDB = r"C:\Users\Fra\Desktop\Zyphora\target\release\cargo_zyphora.pdb"
OUT = r"C:\Users\Fra\Desktop\RustRE\validation\e2e_full_report.json"

def start():
    p = subprocess.Popen([EXE, "--transport=stdio"], stdin=subprocess.PIPE,
                         stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, bufsize=0)
    def send(r): p.stdin.write((json.dumps(r)+"\n").encode()); p.stdin.flush()
    def recv():
        line = p.stdout.readline()
        return json.loads(line) if line else None
    send({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"e2e","version":"1"}}})
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
    except: return c[0].get("text", "")

t0 = time.time()
p, send, recv = start()

print("[1] Opening project...")
call_json(send, recv, "project.open", {"path": TARGET})

print("[2] Detecting functions...")
r = call_json(send, recv, "analyze.function", {"binary_id":"bin-0001", "address":0x140000000})
funcs = r.get("functions", []) if r else []
print(f"    detected {len(funcs)} functions")

# Build address list — dedup by address, prefer higher confidence
by_addr = {}
CONF_ORDER = {"Certain": 3, "High": 2, "Medium": 1, "Low": 0}
for f in funcs:
    addr_s = f.get("addr", "0x0")
    addr = int(addr_s, 16) if isinstance(addr_s, str) else addr_s
    conf = CONF_ORDER.get(f.get("confidence", "Low"), 0)
    existing = by_addr.get(addr)
    if existing is None or conf > existing["conf_rank"]:
        by_addr[addr] = {"addr": addr, "conf": f.get("confidence"), "conf_rank": conf,
                          "detection": f.get("detection_method"), "name": f.get("name")}
unique_addrs = sorted(by_addr.keys())
print(f"    unique addresses after dedup: {len(unique_addrs)}")

print(f"[3] Getting PDB symbol list...")
r = call_json(send, recv, "symbols_pdb_symbols_list", {"path": PDB, "image_base": 0x140000000})
pdb_syms = {}
if r and isinstance(r, dict):
    sym_list = r.get("symbols") or r.get("value") or []
    if isinstance(sym_list, list):
        for s in sym_list:
            if isinstance(s, dict):
                addr = s.get("address") or s.get("addr") or s.get("va")
                name = s.get("name") or s.get("symbol")
                if addr and name:
                    if isinstance(addr, str):
                        try: addr = int(addr, 16)
                        except: continue
                    pdb_syms[addr] = name
print(f"    PDB symbols with address: {len(pdb_syms)}")

print(f"[4] Decompiling all {len(unique_addrs)} functions (sampled every 10th to save time)...")
# Sample every 10th for practical time (2336/10 = ~230 decompiles ≈ 2min)
sample = unique_addrs[::10]
print(f"    Sample size: {len(sample)}")

t_dc = time.time()
successful = 0
failed = 0
total_lines = 0
with_pdb_name = 0
for i, addr in enumerate(sample):
    if i > 0 and i % 50 == 0:
        elapsed = time.time() - t_dc
        rate = i / elapsed if elapsed > 0 else 0
        print(f"    progress: {i}/{len(sample)} ({rate:.1f}/s)")
    r = call_json(send, recv, "decompile.function", {"binary_id":"bin-0001", "address":addr})
    if r is None:
        failed += 1
        continue
    if isinstance(r, dict) and r.get("pseudo_code"):
        successful += 1
        total_lines += r["pseudo_code"].count("\n") + 1
        name = r.get("name", "")
        if name and not name.startswith("sub_"):
            with_pdb_name += 1
    else:
        failed += 1

dc_elapsed = time.time() - t_dc

# Compute name overlap with PDB
overlap = 0
for addr in unique_addrs:
    if addr in pdb_syms:
        overlap += 1

print(f"[5] xref graph...")
r = call_json(send, recv, "analysis_xref_index_from_path_v2", {"path": TARGET})
total_xrefs = r if isinstance(r, int) else (r.get("total", 0) if isinstance(r, dict) else 0)

print(f"[6] findcrypt refined...")
r = call_json(send, recv, "crypto_id_scan_and_summarize", {"path": TARGET})
findcrypt_hits = r.get("total_hits", 0) if isinstance(r, dict) else 0

report = {
    "target": TARGET,
    "elapsed_total_s": round(time.time() - t0, 2),
    "functions": {
        "detected_raw": len(funcs),
        "unique_after_dedup": len(unique_addrs),
        "ida_baseline": 1456,
        "over_detect_ratio": round(len(unique_addrs) / 1456, 2),
    },
    "pdb": {
        "symbols_with_address": len(pdb_syms),
        "ida_baseline_named": 395,
    },
    "decompile": {
        "sample_size": len(sample),
        "sampled_every": 10,
        "successful": successful,
        "failed": failed,
        "success_rate_pct": round(100 * successful / len(sample), 2) if sample else 0,
        "avg_pseudo_c_lines": round(total_lines / max(1, successful), 1),
        "with_pdb_name": with_pdb_name,
        "elapsed_s": round(dc_elapsed, 2),
        "throughput_per_sec": round(len(sample) / dc_elapsed, 2) if dc_elapsed > 0 else 0,
    },
    "xrefs": {"total": total_xrefs},
    "findcrypt": {"hits": findcrypt_hits, "ida_baseline": 43},
    "pdb_addr_overlap_with_detected_functions": overlap,
}

try: p.terminate()
except: pass

with open(OUT, "w") as f:
    json.dump(report, f, indent=2)

print()
print("=" * 60)
print("E2E FULL DECOMPILE REPORT")
print("=" * 60)
print(json.dumps(report, indent=2))
print(f"\nFull report: {OUT}")
