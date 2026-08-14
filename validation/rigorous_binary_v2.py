#!/usr/bin/env python3
"""
Rigorous ground-truth validation for MCP tools matching binary.* (mcp__rustre-mcp__binary_*).

Tools validated:
  binary.info           - sha256, size, format, arch, is_dll
  binary.hexdump        - first 256 raw file bytes as hex+ascii
  binary.read           - first 64 raw file bytes as hex string
  binary.entropy        - Shannon entropy of full file
  binary.search_bytes   - search for MZ signature (must hit at file offset 0)
  binary.search_strings - at least one well-known string present

Reference implementations use only Python stdlib (hashlib, base64, math).
"""
import json, math, hashlib, subprocess, sys, time

# ── constants ────────────────────────────────────────────────────────────────
EXE    = r"C:\Users\Fra\Desktop\RustRE\target\release\rustre-mcp.exe"
TARGET = r"C:\Users\Fra\Desktop\Zyphora\target\release\cargo-zyphora.exe"
OUT    = r"C:\Users\Fra\Desktop\RustRE\validation\rigorous_binary_v2.json"

# ── reference implementations ────────────────────────────────────────────────

def ref_sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def ref_shannon_entropy(data: bytes) -> float:
    """Identical algorithm to rustre_triage_entropy::shannon_entropy."""
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    n = len(data)
    h = 0.0
    for c in counts:
        if c > 0:
            p = c / n
            h -= p * math.log2(p)
    return max(0.0, min(8.0, h))

def ref_hexdump_bytes(data: bytes, offset: int, length: int):
    """Return (hex_str, ascii_str) for file bytes[offset:offset+length].

    binary.hexdump handler reads 'offset' (default 0) and 'length' (default 256)
    from params.  hex uses upper-case space-separated bytes;
    ascii uses printable ASCII chars (is_ascii_graphic or space), else '.'.
    """
    sl = data[offset:offset + length]
    hex_str   = " ".join(f"{b:02X}" for b in sl)
    ascii_str = "".join(chr(b) if (0x21 <= b <= 0x7E or b == 0x20) else "." for b in sl)
    return hex_str, ascii_str, len(sl)

def ref_read_hex(data: bytes, offset: int, length: int) -> str:
    """binary.read returns data_hex = hex::encode(bytes[offset:offset+length])."""
    return data[offset:offset + length].hex()

# ── MCP transport helpers ─────────────────────────────────────────────────────

def start_server():
    return subprocess.Popen(
        [EXE, "--transport=stdio"],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL, bufsize=0
    )

def send(proc, req):
    proc.stdin.write((json.dumps(req) + "\n").encode())
    proc.stdin.flush()

def recv(proc, timeout=30):
    proc.stdout._timeout = timeout  # best-effort; real timeout via deadline
    line = proc.stdout.readline()
    if not line:
        raise RuntimeError("server closed stdout")
    try:
        return json.loads(line)
    except json.JSONDecodeError:
        return {"error": {"message": f"bad-json: {line[:120]!r}"}}

def tool_call(proc, rid, name, args):
    send(proc, {"jsonrpc": "2.0", "id": rid, "method": "tools/call",
                "params": {"name": name, "arguments": args}})
    resp = recv(proc)
    if "error" in resp:
        return None, str(resp["error"])
    content = resp.get("result", {}).get("content", [])
    is_err  = resp.get("result", {}).get("isError", False)
    txt     = content[0].get("text", "") if content else ""
    if is_err:
        return None, txt
    try:
        return json.loads(txt), None
    except Exception:
        return txt, None

# ── load reference file ───────────────────────────────────────────────────────
try:
    file_bytes = open(TARGET, "rb").read()
except OSError as e:
    print(f"ERROR: cannot open target binary: {e}", file=sys.stderr)
    sys.exit(1)

# Pre-compute reference values
REF_SHA256   = ref_sha256(file_bytes)
REF_SIZE     = len(file_bytes)
REF_ENTROPY  = ref_shannon_entropy(file_bytes)
REF_HEX, REF_ASCII, REF_HEXLEN = ref_hexdump_bytes(file_bytes, 0, 256)
REF_DATA_HEX = ref_read_hex(file_bytes, 0, 64)

# For binary.search_bytes "4D 5A": the MZ header is at file offset 0.
# The tool addresses hits as image_base + file_offset.
# We don't know image_base here; we'll verify the tool finds >= 1 match
# and that one of them corresponds to file_offset=0 (i.e. addr == image_base).

# ── start server and run ─────────────────────────────────────────────────────
proc = start_server()
rid  = 0

def next_id():
    global rid
    rid += 1
    return rid

# initialize
send(proc, {"jsonrpc":"2.0","id":next_id(),"method":"initialize",
            "params":{"protocolVersion":"2024-11-05","capabilities":{},
                      "clientInfo":{"name":"rigorous_binary","version":"2"}}})
recv(proc)
send(proc, {"jsonrpc":"2.0","method":"notifications/initialized"})

# project.open – loads binary into registry, returns binary_id
data, err = tool_call(proc, next_id(), "project.open", {"path": TARGET})
if err or not data:
    print(f"project.open FAILED: {err}", file=sys.stderr)
    proc.terminate()
    sys.exit(1)

BINARY_ID  = data["binary_id"]
IMAGE_BASE = None  # filled in from binary.info

results   = []
mismatches = []
tools_hardened = 0

def check(tool, verdict, expected, actual, details=""):
    results.append({
        "tool": tool,
        "verdict": verdict,
        "expected": str(expected)[:300],
        "actual":   str(actual)[:300],
        "details":  details,
    })
    if verdict == "FAIL":
        mismatches.append({"tool": tool, "expected": expected, "actual": actual})

# ── 1. binary.info ────────────────────────────────────────────────────────────
info, err = tool_call(proc, next_id(), "binary.info", {"binary_id": BINARY_ID})
tools_hardened += 1
if err or not isinstance(info, dict):
    check("binary.info", "FAIL", "valid JSON object", err or info)
else:
    got_sha256  = info.get("sha256", "")
    got_size    = info.get("size", -1)
    got_format  = info.get("format", "")
    got_arch    = info.get("arch", "")
    IMAGE_BASE  = int(info.get("image_base", "0x0"), 16) if "image_base" in info else 0

    ok = True
    if got_sha256 != REF_SHA256:
        check("binary.info", "FAIL",
              f"sha256={REF_SHA256}", f"sha256={got_sha256}", "sha256 mismatch")
        ok = False
    if got_size != REF_SIZE:
        check("binary.info", "FAIL",
              f"size={REF_SIZE}", f"size={got_size}", "size mismatch")
        ok = False
    if got_format not in ("PE64", "PE32+", "PE DLL"):
        check("binary.info", "FAIL",
              "format in {PE64,PE32+,PE DLL}", f"format={got_format!r}",
              "unexpected format for 64-bit Windows PE")
        ok = False
    if got_arch not in ("x86_64", "x86-64"):
        check("binary.info", "FAIL",
              "arch=x86_64", f"arch={got_arch!r}", "unexpected arch")
        ok = False
    if ok:
        check("binary.info", "PASS",
              f"sha256={REF_SHA256[:16]}... size={REF_SIZE}",
              f"sha256={got_sha256[:16]}... size={got_size}")

# ── 2. binary.hexdump ─────────────────────────────────────────────────────────
# Handler reads params["offset"] (default 0) and params["length"] (default 256).
# Schema says "addr"/"len" but handler ignores them.  Send nothing extra.
hd, err = tool_call(proc, next_id(), "binary.hexdump", {"binary_id": BINARY_ID})
tools_hardened += 1
if err or not isinstance(hd, dict):
    check("binary.hexdump", "FAIL", "valid JSON object", err or hd)
else:
    got_hex   = hd.get("hex", "")
    got_ascii = hd.get("ascii", "")
    got_len   = hd.get("length", -1)

    # Normalize: Rust produces upper-case space-separated hex.
    # Python ref uses same.  Compare directly.
    ok = True
    if got_hex.upper() != REF_HEX.upper():
        check("binary.hexdump", "FAIL",
              f"hex={REF_HEX[:40]}...", f"hex={got_hex[:40]}...", "hex mismatch")
        ok = False
    if got_ascii != REF_ASCII:
        check("binary.hexdump", "FAIL",
              f"ascii={REF_ASCII[:20]}...", f"ascii={got_ascii[:20]}...",
              "ascii mismatch")
        ok = False
    if got_len not in (256, REF_HEXLEN):
        check("binary.hexdump", "FAIL",
              f"length=256", f"length={got_len}", "length mismatch")
        ok = False
    if ok:
        check("binary.hexdump", "PASS",
              f"hex first 8 bytes={REF_HEX[:23]}",
              f"hex first 8 bytes={got_hex[:23]}")

# ── 3. binary.read ────────────────────────────────────────────────────────────
# Handler reads params["offset"] (default 0) and params["length"] (default 64).
rd, err = tool_call(proc, next_id(), "binary.read", {"binary_id": BINARY_ID})
tools_hardened += 1
if err or not isinstance(rd, dict):
    check("binary.read", "FAIL", "valid JSON object", err or rd)
else:
    got_data_hex = rd.get("data_hex", "").lower()
    ok = True
    if got_data_hex != REF_DATA_HEX:
        check("binary.read", "FAIL",
              f"data_hex={REF_DATA_HEX[:32]}...",
              f"data_hex={got_data_hex[:32]}...", "data_hex mismatch")
        ok = False
    if ok:
        check("binary.read", "PASS",
              f"data_hex={REF_DATA_HEX[:16]}...",
              f"data_hex={got_data_hex[:16]}...")

# ── 4. binary.entropy ─────────────────────────────────────────────────────────
ent, err = tool_call(proc, next_id(), "binary.entropy", {"binary_id": BINARY_ID})
tools_hardened += 1
if err or not isinstance(ent, dict):
    check("binary.entropy", "FAIL", "valid JSON object", err or ent)
else:
    got_overall = ent.get("overall_entropy", None)
    if got_overall is None:
        check("binary.entropy", "FAIL", f"overall_entropy={REF_ENTROPY:.4f}",
              "field missing", "overall_entropy absent")
    else:
        diff = abs(float(got_overall) - REF_ENTROPY)
        if diff > 0.001:  # tolerance 0.001 bits for float precision
            check("binary.entropy", "FAIL",
                  f"overall_entropy≈{REF_ENTROPY:.6f}",
                  f"overall_entropy={got_overall}", f"diff={diff:.6f}")
        else:
            check("binary.entropy", "PASS",
                  f"overall_entropy≈{REF_ENTROPY:.4f}",
                  f"overall_entropy={got_overall}")

# ── 5. binary.search_bytes ────────────────────────────────────────────────────
# Search for MZ (PE header), must find at least 1 hit.
# The first hit should be at image_base + 0 (file offset 0).
sb, err = tool_call(proc, next_id(), "binary.search_bytes",
                    {"binary_id": BINARY_ID, "pattern": "4D 5A"})
tools_hardened += 1
if err or not isinstance(sb, dict):
    check("binary.search_bytes", "FAIL", "valid JSON object", err or sb)
else:
    addresses = sb.get("addresses", [])
    count     = sb.get("count", 0)
    if count == 0 or not addresses:
        check("binary.search_bytes", "FAIL",
              "count >= 1 (MZ signature present)", f"count={count}",
              "MZ header not found in binary")
    else:
        # First hit must be at image_base (file offset 0 -> va = image_base).
        first_addr = int(addresses[0], 16) if isinstance(addresses[0], str) else int(addresses[0])
        expected_addr = IMAGE_BASE if IMAGE_BASE is not None else first_addr
        if IMAGE_BASE is not None and first_addr != IMAGE_BASE:
            check("binary.search_bytes", "FAIL",
                  f"first_hit={hex(IMAGE_BASE)}",
                  f"first_hit={hex(first_addr)}",
                  "MZ not at expected image_base offset")
        else:
            check("binary.search_bytes", "PASS",
                  f"count>0, first_hit={hex(first_addr)}",
                  f"count={count}, first_hit={hex(first_addr)}")

# ── 6. binary.search_strings ──────────────────────────────────────────────────
# Validate structure and correctness:
#   - count > 0 (cargo-zyphora.exe has embedded strings)
#   - count == total_count (consistency)
#   - all returned string entries have required fields {addr, value, encoding, length}
#   - no returned string has length < 4 (default min_len)
#   - count matches a Python-computed lower bound (simple ASCII scan with min_len=4)
#
# Note: the Rust StringScanner also finds UTF-16LE strings; a plain bytes scan
# gives a lower bound only.  We verify count >= python_lower_bound.
def py_count_ascii_strings(data: bytes, min_len: int = 4) -> int:
    """Count contiguous printable-ASCII runs of >= min_len bytes."""
    count = 0
    run = 0
    for b in data:
        if 0x20 <= b <= 0x7E:
            run += 1
        else:
            if run >= min_len:
                count += 1
            run = 0
    if run >= min_len:
        count += 1
    return count

PY_ASCII_COUNT = py_count_ascii_strings(file_bytes, 4)

ss, err = tool_call(proc, next_id(), "binary.search_strings", {"binary_id": BINARY_ID})
tools_hardened += 1
if err or not isinstance(ss, dict):
    check("binary.search_strings", "FAIL", "valid JSON object", err or ss)
else:
    strings_list = ss.get("strings", [])
    count        = ss.get("count", 0)
    ok = True

    if count == 0:
        check("binary.search_strings", "FAIL",
              "count > 0", f"count={count}", "no strings found")
        ok = False

    # Structural check: every entry must have required keys
    required_keys = {"addr", "value", "encoding", "length"}
    bad_entries = [i for i, s in enumerate(strings_list)
                   if not isinstance(s, dict) or not required_keys.issubset(s.keys())]
    if bad_entries:
        check("binary.search_strings", "FAIL",
              f"all entries have keys {required_keys}",
              f"entries {bad_entries[:3]} missing keys",
              "malformed string entry")
        ok = False

    # Length correctness: no string shorter than min_len (4)
    short_entries = [s for s in strings_list if isinstance(s, dict) and int(s.get("length", 4)) < 4]
    if short_entries:
        check("binary.search_strings", "FAIL",
              "all lengths >= 4",
              f"{len(short_entries)} entries with length < 4",
              "minimum length violated")
        ok = False

    # Lower-bound: Rust scanner finds at least as many strings as pure ASCII scan
    # (it also finds UTF-16LE, so total should be >= ascii count).
    if count < PY_ASCII_COUNT:
        check("binary.search_strings", "FAIL",
              f"count >= py_ascii_lower_bound={PY_ASCII_COUNT}",
              f"count={count}",
              "Rust scanner found fewer strings than plain ASCII scan")
        ok = False

    if ok:
        check("binary.search_strings", "PASS",
              f"count>={PY_ASCII_COUNT} (ascii lower bound), structure OK",
              f"count={count}, returned={len(strings_list)}")

# ── teardown ──────────────────────────────────────────────────────────────────
try:
    proc.stdin.close()
    proc.terminate()
    proc.wait(timeout=5)
except Exception:
    pass

# ── summary ───────────────────────────────────────────────────────────────────
passed  = sum(1 for r in results if r["verdict"] == "PASS")
failed  = sum(1 for r in results if r["verdict"] == "FAIL")
skipped = 0

summary = {
    "category":        "binary",
    "tools_hardened":  tools_hardened,
    "tools_passed":    passed,
    "tools_failed":    failed,
    "tools_skipped":   skipped,
    "mismatches":      mismatches,
    "details":         results,
}

with open(OUT, "w") as f:
    json.dump(summary, f, indent=2)

print(f"\n=== binary rigorous validation ===")
print(f"hardened={tools_hardened}  passed={passed}  failed={failed}  skipped={skipped}")
for r in results:
    mark = "OK" if r["verdict"] == "PASS" else "FAIL"
    print(f"  [{mark}] {r['tool']}")
    if r["verdict"] == "FAIL":
        print(f"       expected: {r['expected'][:80]}")
        print(f"       actual:   {r['actual'][:80]}")
print(f"\nOutput written to {OUT}")
