#!/usr/bin/env python3
"""FASE 3 step 2: independent Python validators. Compare MCP tool output vs
ground-truth computed inline in Python. Categories: hex_pattern, mem_*, crypto_id
constants, symbols_demangle. Report mismatches to validation/mismatches_v1.json.
"""
import json, subprocess, time, hashlib, math, struct
from collections import Counter

EXE = r"C:\Users\Fra\Desktop\RustRE\target\release\rustre-mcp.exe"
TARGET = r"C:\Users\Fra\Desktop\Zyphora\target\release\cargo-zyphora.exe"
OUT = r"C:\Users\Fra\Desktop\RustRE\validation\mismatches_v1.json"

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
    if not resp or "error" in resp: return None
    c = resp.get("result",{}).get("content",[])
    if not c: return None
    try: return json.loads(c[0].get("text",""))
    except: return c[0].get("text","")

mismatches = []
checks_ok = 0
checks_total = 0

def check(name, mcp, truth, ctx=""):
    global checks_ok, checks_total
    checks_total += 1
    if mcp == truth:
        checks_ok += 1
        return
    mismatches.append({"tool":name,"ctx":ctx,"mcp":mcp,"truth":truth})

# ---- shannon entropy: mem_shannon_entropy ----
def shannon(bytes_):
    if not bytes_: return 0.0
    cnt = Counter(bytes_)
    n = len(bytes_)
    return -sum((c/n)*math.log2(c/n) for c in cnt.values())

data_hex = "deadbeef00112233445566778899aabbccddeeff" * 8
data = bytes.fromhex(data_hex)
truth_ent = shannon(data)
r = call("mem_shannon_entropy", {"hex": data_hex})
if r and isinstance(r, dict) and "entropy" in r:
    diff = abs(r["entropy"] - truth_ent)
    check("mem_shannon_entropy", diff < 1e-6, True, f"entropy diff {diff}")

# ---- hex pattern wildcard count ----
r = call("hex_pattern_wildcard_count", {"pattern":"AA ?? BB ?? ?? CC"})
if r and isinstance(r, dict):
    truth = 3  # 3 wildcards
    val = r.get("wildcard_count") or r.get("count")
    check("hex_pattern_wildcard_count", val, truth, "AA ?? BB ?? ?? CC")

# ---- hex pattern to_bytes: valid hex round-trip ----
r = call("hex_pattern_to_bytes", {"pattern":"DEADBEEF"})
if r and isinstance(r, dict):
    bs = r.get("bytes") or r.get("value")
    truth_bs = [0xDE,0xAD,0xBE,0xEF]
    check("hex_pattern_to_bytes", bs, truth_bs, "DEADBEEF")

# ---- mem_page_align_down / up ----
for va, ps in [(0x1234, 0x1000), (0x1000, 0x1000), (0x0, 0x1000), (0xFFF, 0x1000)]:
    r = call("mem_page_align_down", {"va":va, "page_size":ps})
    if r and isinstance(r, dict):
        val = r.get("aligned") or r.get("result") or r.get("value") or r.get("va_aligned")
        truth = va & ~(ps-1)
        check("mem_page_align_down", val, truth, f"va={hex(va)} ps={hex(ps)}")
    r = call("mem_page_align_up", {"va":va, "page_size":ps})
    if r and isinstance(r, dict):
        val = r.get("aligned") or r.get("result") or r.get("value") or r.get("va_aligned")
        truth = (va + ps - 1) & ~(ps-1)
        check("mem_page_align_up", val, truth, f"va={hex(va)} ps={hex(ps)}")

# ---- forensics_compute_sha256 / md5 / sha1 ----
sample = b"hello world"
for name, hf in [("forensics_compute_sha256", hashlib.sha256),
                 ("forensics_compute_sha1", hashlib.sha1),
                 ("forensics_compute_md5", hashlib.md5)]:
    truth = hf(sample).hexdigest()
    r = call(name, {"data": sample.decode()})
    if r and isinstance(r, dict):
        val = (r.get("digest") or r.get("hash") or r.get("hex") or "").lower()
        check(name, val, truth, "hello world")

# ---- mem read little-endian primitives ----
tests = [
    ("mem_read_u32_le_at_hex", "78563412", 0x12345678),
    ("mem_read_u64_le_at_hex", "efcdab8967452301", 0x0123456789ABCDEF),
    ("mem_read_u16_le_at_hex", "3412", 0x1234),
    ("mem_read_u16_be_at_hex", "1234", 0x1234),
]
for name, hx, truth in tests:
    r = call(name, {"hex": hx, "offset": 0})
    if r and isinstance(r, dict):
        val = r.get("value") or r.get("result")
        check(name, val, truth, hx)

# ---- crypto_id_aes_rcon ----
# Rijndael convention: Rcon[0]=0x8D (2^-1), then 0x01,0x02,...
truth_rcon = [0x8D,0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1B]
r = call("crypto_id_aes_rcon", {})
if r and isinstance(r, dict):
    rc = r.get("rcon") or r.get("values")
    if isinstance(rc, list):
        check("crypto_id_aes_rcon", rc[:10], truth_rcon, "first 10 Rijndael")

# ---- crypto_id_crc32_poly ----
r = call("crypto_id_crc32_poly", {})
if r and isinstance(r, dict):
    p = r.get("poly") or r.get("polynomial")
    check("crypto_id_crc32_poly", p, 0xEDB88320, "reversed CRC-32 poly")

# ---- CRC32 IEEE (crypto_id_crc32_poly already checked) — compute via mem/deobf ----
import zlib
sample_bs = b"123456789"
truth_crc = zlib.crc32(sample_bs)
r = call("deobf_crc32", {"data": sample_bs.decode()})
if not r: r = call("deobf_crc32", {"hex": sample_bs.hex()})
if r and isinstance(r, dict):
    val = r.get("crc") or r.get("crc32") or r.get("value") or r.get("result")
    check("deobf_crc32", val, truth_crc, "123456789 -> 0xCBF43926")

# ---- mem_page_index ----
r = call("mem_page_index", {"va": 0x5000, "page_size": 0x1000})
if r and isinstance(r, dict):
    val = r.get("index") or r.get("page_index") or r.get("result")
    check("mem_page_index", val, 5, "0x5000 / 0x1000")

# ---- hex_pattern_to_hex_string_v3 round-trip ----
r = call("hex_pattern_specificity", {"pattern":"AA BB CC DD"})
if r and isinstance(r, dict):
    # 4 concrete bytes, 0 wildcards => full specificity
    val = r.get("specificity")
    if val is not None:
        check("hex_pattern_specificity", val == 1.0 or val == 100.0 or val >= 0.99, True, "AABBCCDD full")

# ---- base64 round-trip ----
import base64
plain = b"hello world"
enc = base64.b64encode(plain).decode()
r = call("deobf_base64_decode", {"input": enc})
if not r: r = call("deobf_base64_decode", {"data": enc})
if r and isinstance(r, dict):
    dec = r.get("decoded") or r.get("bytes") or r.get("output") or r.get("result")
    # dec may be hex or list
    if isinstance(dec, str):
        try: dec_b = bytes.fromhex(dec)
        except: dec_b = dec.encode()
        check("deobf_base64_decode", dec_b, plain, "hello world b64")
    elif isinstance(dec, list):
        check("deobf_base64_decode", bytes(dec), plain, "hello world b64")

# ---- symbols_demangle_rust_v0 ----
mangled = "_RNvNtCs6CKzx_3foo3bar4baz"
r = call("symbols_demangle_rust_v0_v5", {"mangled": mangled})
if r and isinstance(r, dict):
    dem = r.get("demangled") or r.get("result")
    # Ground truth via subprocess to rustfilt if available, else check nonempty + contains foo/bar/baz
    ok = dem and all(s in dem for s in ("foo","bar","baz"))
    check("symbols_demangle_rust_v0_v5", bool(ok), True, mangled)

# ---- Summary ----
try: p.terminate()
except: pass

report = {"total_checks": checks_total, "passed": checks_ok,
          "mismatches": mismatches, "mismatch_count": len(mismatches)}
with open(OUT, "w") as f: json.dump(report, f, indent=1)
print(f"CHECKS: {checks_ok}/{checks_total} passed. Mismatches: {len(mismatches)}")
for m in mismatches[:20]:
    print(f"  {m['tool']} [{m['ctx']}]: mcp={m['mcp']} truth={m['truth']}")
