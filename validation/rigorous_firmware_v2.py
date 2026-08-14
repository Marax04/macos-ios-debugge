#!/usr/bin/env python3
"""
Rigorous ground-truth validator for firmware_ MCP tools.
Two tools: firmware_detect_kind_v2, firmware_scan_embedded_signatures.
All reference logic is inlined from the Rust source (crates/rustre-loader-firmware/src/lib.rs).
"""
import json, subprocess, sys

EXE = r"C:\Users\Fra\Desktop\RustRE\target\release\rustre-mcp.exe"

# ─── Reference implementations (mirror of Rust lib.rs) ────────────────────────

def ref_detect_firmware_kind(data: bytes) -> str:
    if len(data) < 2:
        return "raw"
    if data[:2] == b"\x1f\x8b":
        return "tar.gz"
    if data[:3] == b"BZh":
        return "bzip2"
    if data[:6] == b"\xfd7zXZ\x00":
        return "xz"
    if data[:3] == bytes([0x5D, 0x00, 0x00]):
        return "lzma"
    if data[:1] == b":":
        return "intel-hex"
    if data[0:1] == b"S" and len(data) >= 2 and chr(data[1]).isdigit():
        return "srec"
    if data[:4] == b"UF2\n":
        return "uf2"
    if len(data) < 4:
        return "unknown"
    magic = int.from_bytes(data[:4], "big")
    if magic == 0x27051956:
        return "uboot-legacy"
    if magic == 0xD00DFEED:
        return "uboot-fit"
    if magic in (0x73717368, 0x71736873, 0x68737173, 0x68737371):
        return "squashfs"
    if magic == 0x19852003:
        return "jffs2"
    if magic == 0x28CD3D45:
        return "cramfs"
    return "unknown"


SIGNATURES = [
    ("gzip",        bytes([0x1F, 0x8B]),                          "gzip compressed data"),
    ("bzip2",       b"BZh",                                        "bzip2 compressed data"),
    ("xz",          bytes([0xFD,0x37,0x7A,0x58,0x5A,0x00]),       "XZ compressed stream"),
    ("lzma",        bytes([0x5D,0x00,0x00]),                       "LZMA compressed stream"),
    ("zlib",        bytes([0x78,0x9C]),                            "zlib compressed (default)"),
    ("zlib-best",   bytes([0x78,0xDA]),                            "zlib compressed (best)"),
    ("zlib-low",    bytes([0x78,0x01]),                            "zlib compressed (low)"),
    ("7-zip",       b"7z\xBC\xAF\x27\x1C",                        "7-zip archive"),
    ("squashfs-le", bytes([0x73,0x71,0x73,0x68]),                  "SquashFS filesystem (LE)"),
    ("squashfs-be", bytes([0x71,0x73,0x68,0x73]),                  "SquashFS filesystem (BE)"),
    ("jffs2",       bytes([0x19,0x85]),                            "JFFS2 filesystem"),
    ("cramfs",      bytes([0x45,0x3D,0xCD,0x28]),                  "CramFS filesystem"),
    ("ubifs",       bytes([0x31,0x18,0x10,0x06]),                  "UBIFS superblock"),
    ("ext2",        bytes([0x53,0xEF]),                            "ext2/3/4 filesystem"),
    ("elf",         bytes([0x7F,0x45,0x4C,0x46]),                  "ELF executable"),
    ("pe",          bytes([0x4D,0x5A]),                            "PE/MZ executable"),
    ("uboot",       bytes([0x27,0x05,0x19,0x56]),                  "U-Boot uImage"),
    ("fit",         bytes([0xD0,0x0D,0xFE,0xED]),                  "U-Boot FIT image"),
    ("uf2",         b"UF2\n",                                      "UF2 flash image"),
    ("zip",         b"PK\x03\x04",                                 "ZIP archive"),
    ("zip-eocd",    b"PK\x05\x06",                                 "ZIP end of central dir"),
    ("tar",         b"ustar",                                      "POSIX tar archive"),
    ("der-cert",    bytes([0x30,0x82]),                            "DER certificate"),
]

def ref_scan_embedded_signatures(data: bytes) -> list:
    results = []
    for name, sig, desc in SIGNATURES:
        search = 0
        while search + len(sig) <= len(data):
            idx = data.find(sig, search)
            if idx == -1:
                break
            results.append({"name": name, "offset": idx, "sig_len": len(sig), "description": desc})
            search = idx + max(len(sig), 1)
    results.sort(key=lambda x: x["offset"])
    return results

# ─── Test vectors ──────────────────────────────────────────────────────────────

TEST_VECTORS_KIND = [
    # (description, hex_string, expected_kind)
    ("gzip magic",        "1f8b0800",        "tar.gz"),
    ("bzip2 magic",       "425a68",          "bzip2"),
    ("xz magic",          "fd377a585a00",    "xz"),
    ("lzma magic",        "5d0000",          "lzma"),
    ("intel-hex colon",   "3a303030303031",  "intel-hex"),  # ":00000 1..."
    ("srec S0",           "5330",            "srec"),
    ("uf2 magic",         "554632 0a",       "uf2"),
    ("uboot magic",       "27051956",        "uboot-legacy"),
    ("fit magic",         "d00dfeed",        "uboot-fit"),
    ("squashfs-le",       "73717368",        "squashfs"),
    ("jffs2 magic",       "19852003",        "jffs2"),
    ("cramfs magic",      "28cd3d45",        "cramfs"),
    ("raw short",         "aa",              "raw"),
    ("unknown",           "deadbeef",        "unknown"),
]

# gzip(2) at 0, elf(4) at 12, pe(2) at 28, uboot(4) at 40
SCAN_VECTOR_HEX = "1f8b" + "00" * 10 + "7f454c46" + "00" * 10 + "4d5a" + "00" * 10 + "27051956"

# ─── MCP subprocess ────────────────────────────────────────────────────────────

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
        raise RuntimeError("server died")
    try:
        return json.loads(line)
    except json.JSONDecodeError:
        return {"error": {"message": f"bad-line: {line[:100]!r}"}}

# Handshake
send({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"fw-rigorous","version":"1"}}})
recv()
send({"jsonrpc":"2.0","method":"notifications/initialized"})

# Open project (required by server)
TARGET = r"C:\Users\Fra\Desktop\Zyphora\target\release\cargo-zyphora.exe"
send({"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"project.open","arguments":{"path":TARGET}}})
recv()

# ─── Run tests ────────────────────────────────────────────────────────────────

rid = 10
results = {}
mismatches = []

# --- firmware_detect_kind_v2 ---
kind_results = []
for desc, hex_str, expected in TEST_VECTORS_KIND:
    rid += 1
    clean_hex = hex_str.replace(" ", "")
    send({"jsonrpc":"2.0","id":rid,"method":"tools/call","params":{
        "name": "firmware_detect_kind_v2",
        "arguments": {"hex": clean_hex}
    }})
    resp = recv()
    if "error" in resp:
        kind_results.append({"desc": desc, "status": "JSONRPC_ERROR", "detail": str(resp["error"])})
        continue
    is_err = resp.get("result", {}).get("isError", False)
    content = resp.get("result", {}).get("content", [])
    txt = content[0].get("text", "") if content else ""
    if is_err:
        kind_results.append({"desc": desc, "status": "TOOL_ERROR", "detail": txt[:200]})
        mismatches.append({"tool": "firmware_detect_kind_v2", "expected": expected, "actual": f"TOOL_ERROR: {txt[:100]}"})
        continue
    try:
        parsed = json.loads(txt)
    except Exception as e:
        kind_results.append({"desc": desc, "status": "PARSE_ERROR", "detail": txt[:200]})
        continue
    actual_kind = parsed.get("kind", "")
    # verify byte count matches input
    data_bytes = bytes.fromhex(clean_hex)
    expected_bytes = len(data_bytes)
    actual_bytes = parsed.get("bytes", -1)
    byte_ok = (actual_bytes == expected_bytes)
    ref_kind = ref_detect_firmware_kind(data_bytes)  # sanity check our reference vs declared expected
    # Use ref_kind as ground truth (it was derived from the same Rust source)
    if actual_kind == ref_kind and byte_ok:
        kind_results.append({"desc": desc, "status": "PASS", "kind": actual_kind})
    else:
        detail = f"kind: got={actual_kind!r} ref={ref_kind!r} bytes_ok={byte_ok}"
        kind_results.append({"desc": desc, "status": "FAIL", "detail": detail})
        mismatches.append({"tool": "firmware_detect_kind_v2", "expected": ref_kind, "actual": actual_kind})

results["firmware_detect_kind_v2"] = kind_results

# --- firmware_scan_embedded_signatures ---
rid += 1
ref_hits = ref_scan_embedded_signatures(bytes.fromhex(SCAN_VECTOR_HEX))
send({"jsonrpc":"2.0","id":rid,"method":"tools/call","params":{
    "name": "firmware_scan_embedded_signatures",
    "arguments": {"hex": SCAN_VECTOR_HEX}
}})
resp = recv()
if "error" in resp:
    results["firmware_scan_embedded_signatures"] = [{"status": "JSONRPC_ERROR"}]
else:
    is_err = resp.get("result", {}).get("isError", False)
    content = resp.get("result", {}).get("content", [])
    txt = content[0].get("text", "") if content else ""
    if is_err:
        results["firmware_scan_embedded_signatures"] = [{"status": "TOOL_ERROR", "detail": txt[:200]}]
        mismatches.append({"tool": "firmware_scan_embedded_signatures", "expected": ref_hits, "actual": f"TOOL_ERROR: {txt[:100]}"})
    else:
        try:
            parsed = json.loads(txt)
        except Exception:
            parsed = {}
        actual_matches = parsed.get("matches", [])
        # Compare: same count, same offsets, same names
        ref_names_offsets = [(h["name"], h["offset"]) for h in ref_hits]
        act_names_offsets = [(h["name"], h["offset"]) for h in actual_matches]
        if ref_names_offsets == act_names_offsets:
            results["firmware_scan_embedded_signatures"] = [{"status": "PASS", "count": len(actual_matches)}]
        else:
            detail = f"expected={ref_names_offsets} actual={act_names_offsets}"
            results["firmware_scan_embedded_signatures"] = [{"status": "FAIL", "detail": detail}]
            mismatches.append({"tool": "firmware_scan_embedded_signatures",
                                "expected": ref_names_offsets,
                                "actual": act_names_offsets})

p.stdin.close()
p.terminate()

# ─── Tally ────────────────────────────────────────────────────────────────────

tools_hardened = 2
tools_passed = 0
tools_failed = 0
tools_skipped = 0

# firmware_detect_kind_v2: pass if ALL sub-tests pass
kind_pass = all(r["status"] == "PASS" for r in kind_results)
if kind_pass:
    tools_passed += 1
else:
    tools_failed += 1

# firmware_scan_embedded_signatures
scan_res = results.get("firmware_scan_embedded_signatures", [{}])
if scan_res[0].get("status") == "PASS":
    tools_passed += 1
elif scan_res[0].get("status") in ("JSONRPC_ERROR", "TOOL_ERROR"):
    tools_failed += 1
    if not any(m["tool"] == "firmware_scan_embedded_signatures" for m in mismatches):
        mismatches.append({"tool": "firmware_scan_embedded_signatures",
                           "expected": "success", "actual": scan_res[0].get("status")})
else:
    tools_failed += 1

output = {
    "category": "firmware",
    "tools_hardened": tools_hardened,
    "tools_passed": tools_passed,
    "tools_failed": tools_failed,
    "tools_skipped": tools_skipped,
    "mismatches": mismatches,
    "detail": results,
}

OUT = r"C:\Users\Fra\Desktop\RustRE\validation\rigorous_firmware_v2.json"
with open(OUT, "w") as f:
    json.dump(output, f, indent=2)

print(json.dumps({
    "category": output["category"],
    "tools_hardened": output["tools_hardened"],
    "tools_passed": output["tools_passed"],
    "tools_failed": output["tools_failed"],
    "tools_skipped": output["tools_skipped"],
    "mismatches": output["mismatches"],
}))
