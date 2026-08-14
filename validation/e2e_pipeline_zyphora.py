#!/usr/bin/env python3
"""END-TO-END pipeline test on cargo-zyphora.exe.
Steps:
  1. project.open
  2. analyze.function → get all 2336 detected fn addresses
  3. decompile.function on N of them (sample 20 for speed) — verify output non-empty
  4. Get PDB symbol names via symbols_pdb_symbols_list
  5. Build xref graph via analysis_xref_index_from_path_v2
  6. Compare against IDA baseline (from memory: 1456 fn, 395 named)

Output: validation/e2e_report.json with full metrics.
"""
import json, subprocess, time

EXE = r"C:\Users\Fra\Desktop\RustRE\target\release\rustre-mcp.exe"
TARGET = r"C:\Users\Fra\Desktop\Zyphora\target\release\cargo-zyphora.exe"
PDB = r"C:\Users\Fra\Desktop\Zyphora\target\release\cargo_zyphora.pdb"
OUT = r"C:\Users\Fra\Desktop\RustRE\validation\e2e_report.json"

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

def call_text(send, recv, name, args):
    send({"jsonrpc":"2.0","id":100,"method":"tools/call","params":{"name":name,"arguments":args}})
    r = recv()
    if not r or "error" in r: return None
    c = r.get("result", {}).get("content", [])
    if not c: return None
    return c[0].get("text", "")

def call_json(send, recv, name, args):
    txt = call_text(send, recv, name, args)
    if txt is None: return None
    try: return json.loads(txt)
    except: return None

report = {"target": TARGET, "stages": {}, "ida_baseline": {"funcs": 1456, "named": 395, "findcrypt": 43, "imports": 106}}
t0 = time.time()

p, send, recv = start()

# STAGE 1: project.open
t = time.time()
r = call_json(send, recv, "project.open", {"path": TARGET})
report["stages"]["1_project_open"] = {
    "elapsed_s": round(time.time()-t, 2),
    "ok": bool(r and "binary_id" in str(r)),
    "response_excerpt": str(r)[:200] if r else None,
}
print(f"[1] project.open: {report['stages']['1_project_open']['ok']} in {report['stages']['1_project_open']['elapsed_s']}s")

# STAGE 2: analyze.function to trigger detection
t = time.time()
r = call_json(send, recv, "analyze.function", {"binary_id":"bin-0001", "address":0x140000000})
n_detected = r.get("functions_found", 0) if r else 0
first_fns = [int(f["addr"], 16) if isinstance(f.get("addr"), str) else f.get("addr", 0)
             for f in (r.get("functions") or [])[:100]]
report["stages"]["2_detect"] = {
    "elapsed_s": round(time.time()-t, 2),
    "functions_detected": n_detected,
    "sample_first_100": [hex(a) for a in first_fns[:10]],
}
print(f"[2] detected {n_detected} functions in {report['stages']['2_detect']['elapsed_s']}s")

# STAGE 3: decompile 20 sample functions
decomp_results = []
t = time.time()
sample = first_fns[:20]
for addr in sample:
    tt = time.time()
    r = call_json(send, recv, "decompile.function", {"binary_id":"bin-0001", "address":addr})
    if r is None:
        # tool_error text
        txt = call_text(send, recv, "decompile.function", {"binary_id":"bin-0001", "address":addr})
        decomp_results.append({"addr": hex(addr), "ok": False, "note": (txt or "no response")[:80]})
        continue
    pc = r.get("pseudo_code", "") if isinstance(r, dict) else ""
    decomp_results.append({
        "addr": hex(addr),
        "ok": bool(pc),
        "confidence": r.get("confidence") if isinstance(r, dict) else None,
        "code_len": len(pc),
        "code_preview": pc[:100].replace("\n"," ")
    })
report["stages"]["3_decompile"] = {
    "elapsed_s": round(time.time()-t, 2),
    "sample_size": len(sample),
    "successful": sum(1 for d in decomp_results if d["ok"]),
    "sample_results": decomp_results,
}
print(f"[3] decompiled {report['stages']['3_decompile']['successful']}/{len(sample)} in {report['stages']['3_decompile']['elapsed_s']}s")

# STAGE 4: PDB symbol import
t = time.time()
r = call_json(send, recv, "symbols_pdb_parse_info", {"path": PDB})
pdb_symbols = 0
if r:
    pdb_symbols = r.get("symbol_count") or r.get("symbols") or 0
r2 = call_json(send, recv, "symbols_pdb_symbols_list", {"path": PDB})
if r2 and isinstance(r2, dict):
    sym_list = r2.get("symbols") or []
    pdb_symbols = max(pdb_symbols, len(sym_list) if isinstance(sym_list, list) else 0)
report["stages"]["4_pdb"] = {
    "elapsed_s": round(time.time()-t, 2),
    "pdb_symbols_found": pdb_symbols,
    "ida_baseline_named": 395,
    "gap_vs_ida": 395 - pdb_symbols,
}
print(f"[4] PDB: {pdb_symbols} symbols (IDA: 395)")

# STAGE 5: xref index
t = time.time()
r = call_json(send, recv, "analysis_xref_index_from_path_v2", {"path": TARGET})
if isinstance(r, int): total_xrefs = r
elif isinstance(r, dict): total_xrefs = r.get("total", 0)
else: total_xrefs = 0
report["stages"]["5_xrefs"] = {
    "elapsed_s": round(time.time()-t, 2),
    "total_xrefs": total_xrefs,
}
print(f"[5] xrefs: {total_xrefs} total")

# STAGE 6: findcrypt
t = time.time()
r = call_json(send, recv, "crypto_id_scan_and_summarize", {"path": TARGET})
if r is None:
    r = call_json(send, recv, "analysis_crypto_scan_path", {"path": TARGET})
findcrypt_hits = 0
if r and isinstance(r, dict):
    findcrypt_hits = r.get("total_hits") or r.get("count") or len(r.get("hits", []) or [])
report["stages"]["6_findcrypt"] = {
    "elapsed_s": round(time.time()-t, 2),
    "hits": findcrypt_hits,
    "ida_baseline_hits": 43,
    "gap_vs_ida": 43 - findcrypt_hits,
}
print(f"[6] findcrypt: {findcrypt_hits} (IDA: 43)")

# STAGE 7: imports
t = time.time()
r = call_json(send, recv, "loader_pe_parse_info", {"path": TARGET})
imports_count = 0
if isinstance(r, int):
    imports_count = r
elif isinstance(r, dict):
    ic = r.get("import_count") or r.get("imports_count")
    if isinstance(ic, int) and ic > 0:
        imports_count = ic
    else:
        imps = r.get("imports", []) or []
        if isinstance(imps, list):
            imports_count = len(imps)
        elif isinstance(imps, int):
            imports_count = imps
report["stages"]["7_imports"] = {
    "elapsed_s": round(time.time()-t, 2),
    "imports": imports_count,
    "ida_baseline": 106,
}
print(f"[7] imports: {imports_count} (IDA: 106)")

report["total_elapsed_s"] = round(time.time()-t0, 2)

# Summary
report["summary"] = {
    "functions_ratio": f"{n_detected}/1456 (IDA)",
    "pdb_names_ratio": f"{pdb_symbols}/395 (IDA)",
    "findcrypt_ratio": f"{findcrypt_hits}/43 (IDA)",
    "imports_ratio": f"{imports_count}/106 (IDA)",
    "decompile_success_rate": f"{report['stages']['3_decompile']['successful']}/20",
    "xrefs_extracted": total_xrefs,
}

try: p.terminate()
except: pass

with open(OUT, "w") as f:
    json.dump(report, f, indent=2)

print()
print("="*50)
print("E2E PIPELINE COMPLETE")
print("="*50)
print(json.dumps(report["summary"], indent=2))
print(f"Full report: {OUT}")
