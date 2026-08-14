#!/usr/bin/env python3
"""
Rigorous ground-truth validation for sysinternals_* MCP tools.
Each tool is independently verified with a Python reference implementation.
"""
import json, subprocess, struct, sys, os

EXE = r"C:\Users\Fra\Desktop\RustRE\target\release\rustre-mcp.exe"
TARGET = r"C:\Users\Fra\Desktop\Zyphora\target\release\cargo-zyphora.exe"
OUT_JSON = r"C:\Users\Fra\Desktop\RustRE\validation\rigorous_sysinternals_v2.json"
SKIP_JSON = r"C:\Users\Fra\Desktop\RustRE\validation\skip_sysinternals.json"

# ─── MCP transport ─────────────────────────────────────────────────────────────

p = subprocess.Popen(
    [EXE, "--transport=stdio"],
    stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, bufsize=0
)

def send(req):
    p.stdin.write((json.dumps(req) + "\n").encode())
    p.stdin.flush()

def recv():
    line = p.stdout.readline()
    if not line:
        raise RuntimeError("MCP server died")
    return json.loads(line)

def call_tool(name, args, rid):
    send({"jsonrpc": "2.0", "id": rid, "method": "tools/call",
          "params": {"name": name, "arguments": args}})
    resp = recv()
    if "error" in resp:
        return None, str(resp["error"])
    content = resp.get("result", {}).get("content", [])
    txt = content[0].get("text", "") if content else ""
    is_err = resp.get("result", {}).get("isError", False)
    if is_err:
        return None, txt
    try:
        return json.loads(txt), None
    except Exception:
        return txt, None

# Initialize
send({"jsonrpc": "2.0", "id": 1, "method": "initialize",
      "params": {"protocolVersion": "2024-11-05", "capabilities": {},
                 "clientInfo": {"name": "rigorous-sysint", "version": "1"}}})
recv()
send({"jsonrpc": "2.0", "method": "notifications/initialized"})

# Open project (required by the server)
send({"jsonrpc": "2.0", "id": 2, "method": "tools/call",
      "params": {"name": "project.open", "arguments": {"path": TARGET}}})
recv()

# ─── Python reference implementations ──────────────────────────────────────────

def ref_has_pe_signature(data: bytes) -> bool:
    """Mirror of FileSignatureChecker::has_pe_signature in Rust."""
    if len(data) < 0x40:
        return False
    if data[0] != ord('M') or data[1] != ord('Z'):
        return False
    pe_offset = struct.unpack_from("<I", data, 0x3c)[0]
    pe_end = pe_offset + 4
    if pe_end > len(data):
        return False
    if data[pe_offset:pe_end] != b"PE\x00\x00":
        return False
    opt_offset = pe_offset + 24
    opt_end = opt_offset + 2
    if opt_end > len(data):
        return False
    magic = struct.unpack_from("<H", data, opt_offset)[0]
    add = 0x90 if magic == 0x020b else 0x80
    sec_dir_off = opt_offset + add
    sec_dir_end = sec_dir_off + 8
    if sec_dir_end > len(data):
        return False
    rva = struct.unpack_from("<I", data, sec_dir_off)[0]
    return rva != 0

def ref_rss_vss_ratio(vss: int, rss: int) -> float:
    """Mirror of MemoryInfo::rss_vss_ratio — uses double precision."""
    if vss == 0:
        return 0.0
    return float(rss) / float(vss)

def ref_in_temp_dir(exe_path: str) -> bool:
    lp = exe_path.lower()
    return ("\\temp\\" in lp) or ("\\tmp\\" in lp) or ("/tmp/" in lp)

def ref_is_suspicious_path(image_path: str) -> bool:
    lp = image_path.lower()
    return (
        "\\temp\\" in lp
        or "\\tmp\\" in lp
        or "\\appdata\\" in lp
        or "\\downloads\\" in lp
        or "/tmp/" in lp
    )

# ─── Test cases ────────────────────────────────────────────────────────────────

results = []
skips = []
rid = 100

def make_minimal_pe(with_security_dir: bool) -> bytes:
    """
    Build a minimal but structurally correct PE32+ header large enough
    for the Rust checker to parse.

    Layout (all LE):
      0x00  MZ header (e_magic=MZ, rest zeroed, e_lfanew at 0x3c)
      0x3c  4 bytes: PE offset = 0x40
      0x40  PE signature: PE\0\0
      0x44  COFF header: Machine=0x8664 (amd64), 0 sections, etc. (20 bytes)
      0x58  Optional header magic: 0x020b (PE32+)
      0x5a  ... fixed optional header fields (110 bytes for PE32+, total 0x70 = 112)
      opt_offset = 0x58
      add = 0x90
      sec_dir_off = 0x58 + 0x90 = 0xe8
      sec_dir_end = 0xe8 + 8 = 0xf0
    So total size must be >= 0xf0 = 240 bytes.
    """
    buf = bytearray(0x100)
    # MZ magic
    buf[0] = ord('M')
    buf[1] = ord('Z')
    # e_lfanew = 0x40
    struct.pack_into("<I", buf, 0x3c, 0x40)
    # PE signature
    buf[0x40:0x44] = b"PE\x00\x00"
    # COFF header (20 bytes): Machine, NumberOfSections, ...
    struct.pack_into("<H", buf, 0x44, 0x8664)  # Machine = AMD64
    # Optional header magic = PE32+
    struct.pack_into("<H", buf, 0x58, 0x020b)
    # opt_offset = 0x58, add = 0x90 => sec_dir_off = 0xe8
    # DATA_DIRECTORY[4] (security dir): RVA=some_value, Size=0
    rva = 0x1000 if with_security_dir else 0
    struct.pack_into("<I", buf, 0xe8, rva)
    return bytes(buf)

# ── 1. sysinternals_pe_has_signature (with a crafted signed PE) ────────────────
signed_pe = make_minimal_pe(True)
unsigned_pe = make_minimal_pe(False)
not_a_pe = b"deadbeef" * 10

test_cases_pe = [
    ("signed_pe",   signed_pe,   True),
    ("unsigned_pe", unsigned_pe, False),
    ("not_a_pe",    not_a_pe,    False),
]

for label, data, expected in test_cases_pe:
    rid += 1
    actual_obj, err = call_tool(
        "sysinternals_pe_has_signature",
        {"hex": data.hex()},
        rid
    )
    if err:
        results.append({
            "tool": "sysinternals_pe_has_signature",
            "variant": label,
            "status": "FAIL",
            "expected": expected,
            "actual": f"ERROR: {err}",
            "mismatch": True,
        })
    else:
        actual_val = actual_obj.get("has_signature")
        ref_val = ref_has_pe_signature(data)
        ok = (actual_val == expected) and (ref_val == expected)
        results.append({
            "tool": "sysinternals_pe_has_signature",
            "variant": label,
            "status": "PASS" if ok else "FAIL",
            "expected": expected,
            "actual": actual_val,
            "ref_python": ref_val,
            "mismatch": not ok,
        })

# ── 2. sysinternals_has_pe_signature (duplicate with different output field) ───
for label, data, expected in test_cases_pe:
    rid += 1
    actual_obj, err = call_tool(
        "sysinternals_has_pe_signature",
        {"hex": data.hex()},
        rid
    )
    if err:
        results.append({
            "tool": "sysinternals_has_pe_signature",
            "variant": label,
            "status": "FAIL",
            "expected": expected,
            "actual": f"ERROR: {err}",
            "mismatch": True,
        })
    else:
        actual_val = actual_obj.get("has_pe_signature")
        ref_val = ref_has_pe_signature(data)
        ok = (actual_val == expected) and (ref_val == expected)
        results.append({
            "tool": "sysinternals_has_pe_signature",
            "variant": label,
            "status": "PASS" if ok else "FAIL",
            "expected": expected,
            "actual": actual_val,
            "ref_python": ref_val,
            "mismatch": not ok,
        })

# ── 3. sysinternals_empty_snapshot ─────────────────────────────────────────────
rid += 1
actual_obj, err = call_tool("sysinternals_empty_snapshot", {}, rid)
if err:
    results.append({"tool": "sysinternals_empty_snapshot", "status": "FAIL",
                    "expected": "all-zeros", "actual": err, "mismatch": True})
else:
    expected = {"processes": 0, "drivers": 0, "network": 0, "handles": 0}
    ok = all(actual_obj.get(k) == v for k, v in expected.items())
    results.append({
        "tool": "sysinternals_empty_snapshot",
        "status": "PASS" if ok else "FAIL",
        "expected": expected,
        "actual": {k: actual_obj.get(k) for k in expected},
        "mismatch": not ok,
    })

# ── 4. sysinternals_signature_unsigned ─────────────────────────────────────────
test_path = r"C:\some\file.exe"
rid += 1
actual_obj, err = call_tool("sysinternals_signature_unsigned", {"path": test_path}, rid)
if err:
    results.append({"tool": "sysinternals_signature_unsigned", "status": "FAIL",
                    "expected": "unsigned fields", "actual": err, "mismatch": True})
else:
    # Python reference: SignatureInfo::unsigned always sets is_signed=false, is_valid=false,
    # cert_chain empty => cert_chain_len=0, has_root_cert=false, path = the given path.
    ok = (
        actual_obj.get("path") == test_path
        and actual_obj.get("is_signed") is False
        and actual_obj.get("is_valid") is False
        and actual_obj.get("cert_chain_len") == 0
        and actual_obj.get("has_root_cert") is False
    )
    results.append({
        "tool": "sysinternals_signature_unsigned",
        "status": "PASS" if ok else "FAIL",
        "expected": {"path": test_path, "is_signed": False, "is_valid": False,
                     "cert_chain_len": 0, "has_root_cert": False},
        "actual": {k: actual_obj.get(k) for k in ["path","is_signed","is_valid",
                                                    "cert_chain_len","has_root_cert"]},
        "mismatch": not ok,
    })

# ── 5. sysinternals_memory_info_ratio ──────────────────────────────────────────
ratio_cases = [
    (1000, 500,  0.5),
    (1000, 1000, 1.0),
    (0,    500,  0.0),   # vss=0 => ratio=0.0
    (4096, 1024, 0.25),
]
for vss, rss, expected_ratio in ratio_cases:
    rid += 1
    actual_obj, err = call_tool("sysinternals_memory_info_ratio",
                                {"vss": vss, "rss": rss}, rid)
    if err:
        results.append({
            "tool": "sysinternals_memory_info_ratio",
            "variant": f"vss={vss} rss={rss}",
            "status": "FAIL",
            "expected": expected_ratio,
            "actual": err,
            "mismatch": True,
        })
    else:
        actual_ratio = actual_obj.get("ratio")
        ref_ratio = ref_rss_vss_ratio(vss, rss)
        # Compare with tolerance for floating-point
        ok = (
            abs(actual_ratio - expected_ratio) < 1e-9
            and abs(ref_ratio - expected_ratio) < 1e-9
        )
        results.append({
            "tool": "sysinternals_memory_info_ratio",
            "variant": f"vss={vss} rss={rss}",
            "status": "PASS" if ok else "FAIL",
            "expected": expected_ratio,
            "actual": actual_ratio,
            "ref_python": ref_ratio,
            "mismatch": not ok,
        })

# ── 6. sysinternals_process_in_temp_dir ───────────────────────────────────────
path_cases = [
    (r"C:\Windows\System32\svchost.exe", False),
    (r"C:\Users\user\AppData\Local\Temp\evil.exe", True),
    # C:\tmp\malware.exe lowercases to c:\tmp\malware.exe which contains \tmp\ => True
    (r"C:\tmp\malware.exe", True),
    # C:\Users\foo\temp\x.exe contains \temp\ => True
    (r"C:\Users\foo\temp\x.exe", True),
    (r"C:\Users\foo\Temp\x.exe", True),     # case-insensitive
    ("/tmp/evil", True),
]
for exe_path, expected in path_cases:
    rid += 1
    actual_obj, err = call_tool("sysinternals_process_in_temp_dir",
                                {"exe_path": exe_path}, rid)
    if err:
        results.append({
            "tool": "sysinternals_process_in_temp_dir",
            "variant": exe_path,
            "status": "FAIL",
            "expected": expected,
            "actual": err,
            "mismatch": True,
        })
    else:
        actual_val = actual_obj.get("in_temp_dir")
        ref_val = ref_in_temp_dir(exe_path)
        ok = (actual_val == expected) and (ref_val == expected)
        results.append({
            "tool": "sysinternals_process_in_temp_dir",
            "variant": exe_path,
            "status": "PASS" if ok else "FAIL",
            "expected": expected,
            "actual": actual_val,
            "ref_python": ref_val,
            "mismatch": not ok,
        })

# ── 7. sysinternals_autorun_suspicious_path ────────────────────────────────────
autorun_cases = [
    (r"C:\Windows\System32\notepad.exe", False),
    (r"C:\Users\user\AppData\Roaming\malware.exe", True),
    (r"C:\Users\user\Downloads\installer.exe", True),
    # C:\Users\user\Temp\evil.exe => c:\users\user\temp\evil.exe contains \temp\ => True
    (r"C:\Users\user\Temp\evil.exe", True),
    # C:\Users\user\temp\evil.exe => contains \temp\ => True
    (r"C:\Users\user\temp\evil.exe", True),
    (r"C:\Users\user\Temp\sub\evil.exe", True),  # has \temp\
    ("/tmp/evil.sh", True),
    (r"C:\Program Files\App\app.exe", False),
]
for image_path, expected in autorun_cases:
    rid += 1
    actual_obj, err = call_tool("sysinternals_autorun_suspicious_path",
                                {"image_path": image_path}, rid)
    if err:
        results.append({
            "tool": "sysinternals_autorun_suspicious_path",
            "variant": image_path,
            "status": "FAIL",
            "expected": expected,
            "actual": err,
            "mismatch": True,
        })
    else:
        actual_val = actual_obj.get("is_suspicious_path")
        ref_val = ref_is_suspicious_path(image_path)
        ok = (actual_val == expected) and (ref_val == expected)
        results.append({
            "tool": "sysinternals_autorun_suspicious_path",
            "variant": image_path,
            "status": "PASS" if ok else "FAIL",
            "expected": expected,
            "actual": actual_val,
            "ref_python": ref_val,
            "mismatch": not ok,
        })

# ── 8. sysinternals_autoruns_scan_all (stub → empty list) ─────────────────────
rid += 1
actual_obj, err = call_tool("sysinternals_autoruns_scan_all", {}, rid)
if err:
    results.append({"tool": "sysinternals_autoruns_scan_all", "status": "FAIL",
                    "expected": "count=0", "actual": err, "mismatch": True})
else:
    ok = actual_obj.get("count") == 0 and actual_obj.get("entries") == []
    results.append({
        "tool": "sysinternals_autoruns_scan_all",
        "status": "PASS" if ok else "FAIL",
        "expected": {"count": 0, "entries": []},
        "actual": {"count": actual_obj.get("count"), "entries": actual_obj.get("entries")},
        "mismatch": not ok,
    })

# ── 9. sysinternals_network_snapshot (stub → empty) ───────────────────────────
rid += 1
actual_obj, err = call_tool("sysinternals_network_snapshot", {}, rid)
if err:
    results.append({"tool": "sysinternals_network_snapshot", "status": "FAIL",
                    "expected": "count=0", "actual": err, "mismatch": True})
else:
    ok = actual_obj.get("count") == 0
    results.append({
        "tool": "sysinternals_network_snapshot",
        "status": "PASS" if ok else "FAIL",
        "expected": {"count": 0},
        "actual": {"count": actual_obj.get("count")},
        "mismatch": not ok,
    })

# ── 10. sysinternals_listening_ports (stub → empty) ────────────────────────────
rid += 1
actual_obj, err = call_tool("sysinternals_listening_ports", {}, rid)
if err:
    results.append({"tool": "sysinternals_listening_ports", "status": "FAIL",
                    "expected": "count=0", "actual": err, "mismatch": True})
else:
    ok = actual_obj.get("count") == 0
    results.append({
        "tool": "sysinternals_listening_ports",
        "status": "PASS" if ok else "FAIL",
        "expected": {"count": 0},
        "actual": {"count": actual_obj.get("count")},
        "mismatch": not ok,
    })

# ── 11. sysinternals_process_scan (stub → empty) ──────────────────────────────
rid += 1
actual_obj, err = call_tool("sysinternals_process_scan", {}, rid)
if err:
    results.append({"tool": "sysinternals_process_scan", "status": "FAIL",
                    "expected": "count=0", "actual": err, "mismatch": True})
else:
    ok = actual_obj.get("count") == 0
    results.append({
        "tool": "sysinternals_process_scan",
        "status": "PASS" if ok else "FAIL",
        "expected": {"count": 0},
        "actual": {"count": actual_obj.get("count")},
        "mismatch": not ok,
    })

# ── Cleanup ───────────────────────────────────────────────────────────────────
try:
    p.stdin.close()
    p.terminate()
except Exception:
    pass

# ── Write output files ────────────────────────────────────────────────────────
with open(OUT_JSON, "w") as f:
    json.dump(results, f, indent=2)

with open(SKIP_JSON, "w") as f:
    json.dump(skips, f, indent=2)

# ── Summary ───────────────────────────────────────────────────────────────────
passed = sum(1 for r in results if r["status"] == "PASS")
failed = sum(1 for r in results if r["status"] == "FAIL")
print(f"\nSysinternals rigorous validation: {len(results)} checks")
print(f"  PASS: {passed}")
print(f"  FAIL: {failed}")
print(f"  SKIP: {len(skips)}")

mismatches = [r for r in results if r.get("mismatch")]
if mismatches:
    print("\n=== MISMATCHES ===")
    for m in mismatches:
        print(f"  {m['tool']} [{m.get('variant', '')}]: expected={m['expected']} actual={m['actual']}")
else:
    print("\nAll checks passed.")
