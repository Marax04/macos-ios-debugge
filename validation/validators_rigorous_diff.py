#!/usr/bin/env python3
"""
Rigorous ground-truth validator for diff_* MCP tools.
Uses inline Python reference implementations derived directly from Rust source.
"""
import json
import subprocess
import math
import sys

EXE = r"C:\Users\Fra\Desktop\RustRE\target\release\rustre-mcp.exe"
TARGET = r"C:\Users\Fra\Desktop\Zyphora\target\release\cargo-zyphora.exe"
OUT_JSON = r"C:\Users\Fra\Desktop\RustRE\validation\rigorous_diff_v2.json"
SKIP_JSON = r"C:\Users\Fra\Desktop\RustRE\validation\skip_diff.json"

# ─── MCP transport helpers ──────────────────────────────────────────────────

proc = subprocess.Popen(
    [EXE, "--transport=stdio"],
    stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
    bufsize=0,
)

def send(req):
    proc.stdin.write((json.dumps(req) + "\n").encode())
    proc.stdin.flush()

def recv():
    line = proc.stdout.readline()
    if not line:
        raise RuntimeError("MCP server died")
    return json.loads(line)

def mcp_call(name, args, req_id):
    send({"jsonrpc": "2.0", "id": req_id, "method": "tools/call",
          "params": {"name": name, "arguments": args}})
    resp = recv()
    if "error" in resp:
        return None, f"JSONRPC_ERROR: {resp['error']}"
    result = resp.get("result", {})
    if result.get("isError"):
        content = result.get("content", [{}])
        return None, f"TOOL_ERROR: {content[0].get('text', '')[:200]}"
    content = result.get("content", [{}])
    txt = content[0].get("text", "")
    try:
        return json.loads(txt), None
    except Exception:
        return txt, None

# ─── Init ──────────────────────────────────────────────────────────────────

send({"jsonrpc": "2.0", "id": 1, "method": "initialize",
      "params": {"protocolVersion": "2024-11-05", "capabilities": {},
                 "clientInfo": {"name": "rigorous_diff", "version": "1"}}})
recv()
send({"jsonrpc": "2.0", "method": "notifications/initialized"})

# Open project so binary_id is available (some diff tools need it)
send({"jsonrpc": "2.0", "id": 2, "method": "tools/call",
      "params": {"name": "project.open", "arguments": {"path": TARGET}}})
recv()  # ignore response; diff tools don't need binary_id

# ─── Python reference implementations ──────────────────────────────────────

FNV_BASIS = 0xcbf2_9ce4_8422_2325
FNV_PRIME = 0x0000_0100_0000_01b3
UINT64_MAX = (1 << 64) - 1

def py_fnv1a_64(data: bytes) -> int:
    h = FNV_BASIS
    for b in data:
        h ^= b
        h = (h * FNV_PRIME) & UINT64_MAX
    return h

def py_lcs_similarity(a: bytes, b: bytes) -> float:
    if not a and not b:
        return 1.0
    if not a or not b:
        return 0.0
    full_len_a = len(a)
    full_len_b = len(b)
    la = min(full_len_a, 512)
    lb = min(full_len_b, 512)
    a = a[:la]
    b = b[:lb]
    # DP LCS
    dp = [[0] * (lb + 1) for _ in range(la + 1)]
    for i in range(1, la + 1):
        for j in range(1, lb + 1):
            if a[i-1] == b[j-1]:
                dp[i][j] = dp[i-1][j-1] + 1
            else:
                dp[i][j] = max(dp[i-1][j], dp[i][j-1])
    lcs = dp[la][lb]
    raw_score = 2.0 * lcs / (la + lb)
    coverage_a = la / full_len_a
    coverage_b = lb / full_len_b
    coverage = min(coverage_a, coverage_b)
    return raw_score * coverage

def py_byte_histogram_similarity(a: bytes, b: bytes) -> float:
    if not a and not b:
        return 1.0
    if not a or not b:
        return 0.0
    hist_a = [0] * 256
    hist_b = [0] * 256
    for x in a:
        hist_a[x] += 1
    for x in b:
        hist_b[x] += 1
    len_a = len(a)
    len_b = len(b)
    bhatt = 0.0
    for i in range(256):
        pa = hist_a[i] / len_a
        pb = hist_b[i] / len_b
        bhatt += math.sqrt(pa * pb)
    return max(0.0, min(1.0, bhatt))

def py_ngram_jaccard(a: bytes, b: bytes, n: int = 4) -> float:
    MAX_INPUT = 4096
    a = a[:MAX_INPUT]
    b = b[:MAX_INPUT]
    if not a and not b:
        return 1.0
    if not a or not b:
        return 0.0
    if len(a) < n and len(b) < n:
        return 1.0 if a == b else 0.0
    def ngrams(data):
        return set(bytes(data[i:i+n]) for i in range(len(data) - n + 1))
    sa = ngrams(a)
    sb = ngrams(b)
    inter = len(sa & sb)
    union = len(sa | sb)
    return inter / union if union else 1.0

def py_combined_byte_similarity(a: bytes, b: bytes) -> float:
    hist_sim = py_byte_histogram_similarity(a, b)
    gram_sim = py_ngram_jaccard(a, b, 4)
    return 0.6 * hist_sim + 0.4 * gram_sim

def py_cfg_hash_linear(block_count: int) -> int:
    h = FNV_BASIS
    for i in range(block_count):
        h ^= i
        h = (h * FNV_PRIME) & UINT64_MAX
    return h

def py_fnv1a_mix(h: int, val: int) -> int:
    # XOR each byte of val (little-endian u64)
    val_bytes = val.to_bytes(8, 'little')
    for b in val_bytes:
        h ^= b
        h = (h * FNV_PRIME) & UINT64_MAX
    return h

def py_wl_hash(adjacency: list, iterations: int = 3) -> int:
    if not adjacency:
        return 0
    # Build index: id -> position
    idx = {entry["id"]: pos for pos, entry in enumerate(adjacency)}
    # Init labels with out-degree
    labels = [len(entry.get("successors", [])) for entry in adjacency]
    for _ in range(iterations):
        new_labels = list(labels)
        for pos, entry in enumerate(adjacency):
            succs = entry.get("successors", [])
            neighbour_labels = sorted(labels[idx[s]] for s in succs if s in idx)
            h = FNV_BASIS
            h = py_fnv1a_mix(h, labels[pos])
            for nl in neighbour_labels:
                h = py_fnv1a_mix(h, nl)
            new_labels[pos] = h
        labels = new_labels
    labels_sorted = sorted(labels)
    final_hash = FNV_BASIS
    for l in labels_sorted:
        final_hash = py_fnv1a_mix(final_hash, l)
    return final_hash

def py_minhash_estimate_jaccard(sig_a: list, sig_b: list) -> float:
    if not sig_a or len(sig_a) != len(sig_b):
        return 0.0
    equal = sum(1 for a, b in zip(sig_a, sig_b) if a == b)
    return equal / len(sig_a)

MINHASH_PRIME = 4_294_967_311  # first prime > 2^32

def py_minhash_signature(num_hashes: int, elements: list) -> list:
    # Deterministic xorshift64 seeded by num_hashes
    state = ((num_hashes * 6_364_136_223_846_793_005) & UINT64_MAX) + 1
    coefficients = []
    for _ in range(num_hashes):
        state ^= (state << 13) & UINT64_MAX
        state ^= (state >> 7)
        state ^= (state << 17) & UINT64_MAX
        a = state % MINHASH_PRIME
        state ^= (state << 13) & UINT64_MAX
        state ^= (state >> 7)
        state ^= (state << 17) & UINT64_MAX
        b = state % MINHASH_PRIME
        coefficients.append((max(a, 1), b))
    if not elements:
        return [UINT64_MAX] * num_hashes
    sig = [UINT64_MAX] * num_hashes
    for elem in elements:
        for i, (a, b) in enumerate(coefficients):
            h = (a * elem + b) % MINHASH_PRIME
            if h < sig[i]:
                sig[i] = h
    return sig

# ─── Test cases ────────────────────────────────────────────────────────────

TESTA = [0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x11, 0x22, 0x33]
TESTB = [0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE]
TESTC = [0x90, 0x90, 0x90, 0x90]  # NOPs
TESTA_BYTES = bytes(TESTA)
TESTB_BYTES = bytes(TESTB)
TESTC_BYTES = bytes(TESTC)

results = []
skips = []
mismatches = []
req_id = 100

def check(tool_name, args, expected_key, expected_val, tolerance=None):
    global req_id
    req_id += 1
    data, err = mcp_call(tool_name, args, req_id)
    if err:
        results.append({"tool": tool_name, "status": "FAIL", "error": err})
        mismatches.append({"tool": tool_name, "expected": expected_val, "actual": err})
        return False
    actual = data.get(expected_key) if isinstance(data, dict) else data
    if tolerance is not None:
        ok = abs(float(actual) - float(expected_val)) <= tolerance
    else:
        ok = actual == expected_val
    if ok:
        results.append({"tool": tool_name, "status": "PASS",
                         "expected": expected_val, "actual": actual})
    else:
        results.append({"tool": tool_name, "status": "FAIL",
                         "expected": expected_val, "actual": actual})
        mismatches.append({"tool": tool_name, "expected": expected_val, "actual": actual})
    return ok

def skip(tool_name, reason):
    skips.append({"tool": tool_name, "reason": reason})

# ── diff_simple_hash ─────────────────────────────────────────────────────────
# FNV-1a 64-bit
py_hash_a = py_fnv1a_64(TESTA_BYTES)
check("diff_simple_hash", {"data": TESTA}, "hash", py_hash_a)

py_hash_empty = py_fnv1a_64(b"")
check("diff_simple_hash", {"data": []}, "hash", py_hash_empty)

# Single byte
py_hash_one = py_fnv1a_64(bytes([0x42]))
check("diff_simple_hash", {"data": [0x42]}, "hash", py_hash_one)

# ── diff_lcs_similarity ──────────────────────────────────────────────────────
py_lcs_same = py_lcs_similarity(TESTA_BYTES, TESTA_BYTES)
check("diff_lcs_similarity", {"a": TESTA, "b": TESTA}, "similarity", py_lcs_same, tolerance=1e-9)

py_lcs_diff = py_lcs_similarity(TESTA_BYTES, TESTC_BYTES)
check("diff_lcs_similarity", {"a": TESTA, "b": TESTC}, "similarity", py_lcs_diff, tolerance=1e-9)

py_lcs_partial = py_lcs_similarity(TESTA_BYTES, TESTB_BYTES)
check("diff_lcs_similarity", {"a": TESTA, "b": TESTB}, "similarity", py_lcs_partial, tolerance=1e-9)

py_lcs_empty_empty = py_lcs_similarity(b"", b"")
check("diff_lcs_similarity", {"a": [], "b": []}, "similarity", py_lcs_empty_empty, tolerance=1e-9)

# ── diff_byte_histogram_similarity ───────────────────────────────────────────
py_bhatt_same = py_byte_histogram_similarity(TESTA_BYTES, TESTA_BYTES)
check("diff_byte_histogram_similarity", {"a": TESTA, "b": TESTA}, "similarity", py_bhatt_same, tolerance=1e-9)

py_bhatt_diff = py_byte_histogram_similarity(TESTA_BYTES, TESTC_BYTES)
check("diff_byte_histogram_similarity", {"a": TESTA, "b": TESTC}, "similarity", py_bhatt_diff, tolerance=1e-9)

py_bhatt_partial = py_byte_histogram_similarity(TESTA_BYTES, TESTB_BYTES)
check("diff_byte_histogram_similarity", {"a": TESTA, "b": TESTB}, "similarity", py_bhatt_partial, tolerance=1e-9)

# ── diff_ngram_jaccard_similarity ────────────────────────────────────────────
py_ngram_same = py_ngram_jaccard(TESTA_BYTES, TESTA_BYTES, 4)
check("diff_ngram_jaccard_similarity", {"a": TESTA, "b": TESTA, "n": 4}, "similarity", py_ngram_same, tolerance=1e-9)

py_ngram_diff = py_ngram_jaccard(TESTA_BYTES, TESTC_BYTES, 4)
check("diff_ngram_jaccard_similarity", {"a": TESTA, "b": TESTC, "n": 4}, "similarity", py_ngram_diff, tolerance=1e-9)

py_ngram_partial = py_ngram_jaccard(TESTA_BYTES, TESTB_BYTES, 4)
check("diff_ngram_jaccard_similarity", {"a": TESTA, "b": TESTB, "n": 4}, "similarity", py_ngram_partial, tolerance=1e-9)

py_ngram_n2 = py_ngram_jaccard(TESTA_BYTES, TESTB_BYTES, 2)
check("diff_ngram_jaccard_similarity", {"a": TESTA, "b": TESTB, "n": 2}, "similarity", py_ngram_n2, tolerance=1e-9)

# ── diff_combined_byte_similarity ────────────────────────────────────────────
py_combined_same = py_combined_byte_similarity(TESTA_BYTES, TESTA_BYTES)
check("diff_combined_byte_similarity", {"a": TESTA, "b": TESTA}, "similarity", py_combined_same, tolerance=1e-9)

py_combined_diff = py_combined_byte_similarity(TESTA_BYTES, TESTC_BYTES)
check("diff_combined_byte_similarity", {"a": TESTA, "b": TESTC}, "similarity", py_combined_diff, tolerance=1e-9)

# ── diff_bindiff_cfg_hash_linear ─────────────────────────────────────────────
for bc in [0, 1, 3, 5, 10]:
    py_h = py_cfg_hash_linear(bc)
    check("diff_bindiff_cfg_hash_linear", {"block_count": bc}, "hash", py_h)

# ── diff_bindiff_wl_hash ─────────────────────────────────────────────────────
# Empty graph
py_wl_empty = py_wl_hash([])
check("diff_bindiff_wl_hash",
      {"adjacency": [], "iterations": 3}, "hash", py_wl_empty)

# Linear 3-node chain: 0->1->2
adj_linear = [
    {"id": 0, "successors": [1]},
    {"id": 1, "successors": [2]},
    {"id": 2, "successors": []}
]
py_wl_linear = py_wl_hash(adj_linear, 3)
check("diff_bindiff_wl_hash",
      {"adjacency": adj_linear, "iterations": 3}, "hash", py_wl_linear)

# Diamond: 0->{1,2}->3
adj_diamond = [
    {"id": 0, "successors": [1, 2]},
    {"id": 1, "successors": [3]},
    {"id": 2, "successors": [3]},
    {"id": 3, "successors": []}
]
py_wl_diamond = py_wl_hash(adj_diamond, 3)
check("diff_bindiff_wl_hash",
      {"adjacency": adj_diamond, "iterations": 3}, "hash", py_wl_diamond)

# ── diff_semantic_minhash_estimate_jaccard ───────────────────────────────────
# Identical signatures -> 1.0
sig = [10, 20, 30, 40]
py_jac_same = py_minhash_estimate_jaccard(sig, sig)
check("diff_semantic_minhash_estimate_jaccard",
      {"sig_a": sig, "sig_b": sig}, "estimated_jaccard", py_jac_same, tolerance=1e-9)

# Completely different -> 0.0
sig_a = [1, 2, 3, 4]
sig_b = [5, 6, 7, 8]
py_jac_zero = py_minhash_estimate_jaccard(sig_a, sig_b)
check("diff_semantic_minhash_estimate_jaccard",
      {"sig_a": sig_a, "sig_b": sig_b}, "estimated_jaccard", py_jac_zero, tolerance=1e-9)

# Half equal -> 0.5
sig_c = [1, 2, 7, 8]
py_jac_half = py_minhash_estimate_jaccard(sig_a, sig_c)
check("diff_semantic_minhash_estimate_jaccard",
      {"sig_a": sig_a, "sig_b": sig_c}, "estimated_jaccard", py_jac_half, tolerance=1e-9)

# ── diff_semantic_minhash_signature ─────────────────────────────────────────
# Verify signature matches our Python reference
elems_4 = [1, 2, 3, 4]
py_sig_4 = py_minhash_signature(4, elems_4)
req_id += 1
data_sig, err_sig = mcp_call("diff_semantic_minhash_signature",
                              {"num_hashes": 4, "elements": elems_4}, req_id)
if err_sig:
    results.append({"tool": "diff_semantic_minhash_signature", "status": "FAIL", "error": err_sig})
    mismatches.append({"tool": "diff_semantic_minhash_signature", "expected": py_sig_4, "actual": err_sig})
else:
    actual_sig = data_sig.get("signature", []) if isinstance(data_sig, dict) else []
    if actual_sig == py_sig_4:
        results.append({"tool": "diff_semantic_minhash_signature", "status": "PASS",
                         "expected": py_sig_4, "actual": actual_sig})
    else:
        results.append({"tool": "diff_semantic_minhash_signature", "status": "FAIL",
                         "expected": py_sig_4, "actual": actual_sig})
        mismatches.append({"tool": "diff_semantic_minhash_signature",
                            "expected": py_sig_4, "actual": actual_sig})

# Empty elements -> all u64::MAX
py_sig_empty = py_minhash_signature(3, [])
req_id += 1
data_empty, err_empty = mcp_call("diff_semantic_minhash_signature",
                                  {"num_hashes": 3, "elements": []}, req_id)
if err_empty:
    results.append({"tool": "diff_semantic_minhash_signature(empty)", "status": "FAIL", "error": err_empty})
    mismatches.append({"tool": "diff_semantic_minhash_signature(empty)", "expected": py_sig_empty, "actual": err_empty})
else:
    actual_empty = data_empty.get("signature", []) if isinstance(data_empty, dict) else []
    if actual_empty == py_sig_empty:
        results.append({"tool": "diff_semantic_minhash_signature(empty)", "status": "PASS"})
    else:
        results.append({"tool": "diff_semantic_minhash_signature(empty)", "status": "FAIL",
                         "expected": py_sig_empty, "actual": actual_empty})
        mismatches.append({"tool": "diff_semantic_minhash_signature(empty)",
                            "expected": py_sig_empty, "actual": actual_empty})

# ── SKIPs ────────────────────────────────────────────────────────────────────
skip("diff_bindiff_similarity_score",
     "Multi-component score (name/bytes/cfg/md_index) depends on internal normalization "
     "that requires the full FunctionInfo struct construction; nondeterministic w.r.t. name hash")
skip("diff_bindiff_cfg_hash",
     "Delegates to wl_hash with 3 iterations; already verified via diff_bindiff_wl_hash")
skip("diff_bindiff_jaccard_bb_score",
     "Jaccard over basic-block hash sets — requires building FunctionInfo with bb_hashes, "
     "which comes from internal hashing of BB bytes; not independently verifiable without the binary")
skip("diff_bindiff_cfg_similarity",
     "Weighted CFG similarity combining WL hash distance + edge/block ratios; "
     "too many internal weight factors to replicate exactly without source constants")
skip("diff_semantic_signature_compute",
     "Depends on x86/arm64 disassembly of real binary bytes — nondeterministic without binary")
skip("diff_exports",
     "Pure set-diff over export entries — presence/shape test sufficient; "
     "no numeric ground truth needed")

# ─── Shutdown ──────────────────────────────────────────────────────────────

proc.stdin.close()
proc.terminate()

# ─── Write outputs ─────────────────────────────────────────────────────────

passed = sum(1 for r in results if r["status"] == "PASS")
failed = sum(1 for r in results if r["status"] == "FAIL")

output = {
    "category": "diff",
    "tools_hardened": len(results),
    "tools_passed": passed,
    "tools_failed": failed,
    "tools_skipped": len(skips),
    "mismatches": mismatches,
    "details": results,
}

with open(OUT_JSON, "w") as f:
    json.dump(output, f, indent=2)

with open(SKIP_JSON, "w") as f:
    json.dump(skips, f, indent=2)

print(f"PASS={passed}  FAIL={failed}  SKIP={len(skips)}")
if mismatches:
    for m in mismatches:
        print(f"  MISMATCH {m['tool']}: expected={m['expected']!r}  actual={m['actual']!r}")
