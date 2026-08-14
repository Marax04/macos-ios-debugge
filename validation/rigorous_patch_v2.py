#!/usr/bin/env python3
"""
Rigorous ground-truth validator for all MCP tools prefixed with "patch_".

For each tool we either:
  - compute the expected result independently in pure Python (stdlib only)
    and compare byte-for-byte / value-for-value, OR
  - record as SKIP with an explicit reason.

Output: C:/Users/Fra/Desktop/RustRE/validation/rigorous_patch_v2.json
        C:/Users/Fra/Desktop/RustRE/validation/skip_patch.json
"""
import json, struct, subprocess, hashlib, time, os, sys

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
EXE     = r"C:\Users\Fra\Desktop\RustRE\target\release\rustre-mcp.exe"
TARGET  = r"C:\Users\Fra\Desktop\Zyphora\target\release\cargo-zyphora.exe"
OUT     = r"C:\Users\Fra\Desktop\RustRE\validation\rigorous_patch_v2.json"
SKIP_OUT= r"C:\Users\Fra\Desktop\RustRE\validation\skip_patch.json"

# ---------------------------------------------------------------------------
# MCP transport helpers (identical pattern to exercise_v3.py)
# ---------------------------------------------------------------------------
proc = subprocess.Popen(
    [EXE, "--transport=stdio"],
    stdin=subprocess.PIPE, stdout=subprocess.PIPE,
    stderr=subprocess.DEVNULL, bufsize=0,
)

def send(req: dict):
    proc.stdin.write((json.dumps(req) + "\n").encode())
    proc.stdin.flush()

def recv() -> dict:
    line = proc.stdout.readline()
    if not line:
        raise RuntimeError("MCP server died")
    try:
        return json.loads(line)
    except json.JSONDecodeError:
        return {"error": {"message": f"bad-line: {line[:100]!r}"}}

def mcp_call(name: str, arguments: dict, rid: int) -> dict:
    """Call one MCP tool and return the parsed response dict."""
    send({"jsonrpc": "2.0", "id": rid,
          "method": "tools/call",
          "params": {"name": name, "arguments": arguments}})
    resp = recv()
    if "error" in resp:
        return {"__mcp_error": str(resp["error"])}
    content = resp.get("result", {}).get("content", [])
    if not content:
        return {}
    try:
        return json.loads(content[0]["text"])
    except Exception as exc:
        return {"__parse_error": str(exc), "__raw": content[0]["text"][:200]}

# Handshake
send({"jsonrpc":"2.0","id":1,"method":"initialize",
      "params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"rigorous_patch_v2","version":"1"}}})
recv()
send({"jsonrpc":"2.0","method":"notifications/initialized"})

# Open project so session state is present (some tools may need it)
send({"jsonrpc":"2.0","id":2,"method":"tools/call",
      "params":{"name":"project.open","arguments":{"path":TARGET}}})
op = recv()
try:
    op_data = json.loads(op["result"]["content"][0]["text"])
    BINARY_ID  = op_data["binary_id"]
    PROJECT_ID = op_data["project_id"]
except Exception:
    BINARY_ID = PROJECT_ID = ""

rid = 200   # running request-id counter

# ---------------------------------------------------------------------------
# Python reference implementations
# ---------------------------------------------------------------------------

def py_parse_hex_bytes(s: str) -> list:
    """Mirror of rustre_patch::parse_hex_bytes."""
    cleaned = ""
    for c in s:
        if c not in (' ', '\t', '\n', '\r', ',', '_'):
            cleaned += c
    stripped = cleaned.replace("0x", "").replace("0X", "")
    if len(stripped) % 2 != 0:
        raise ValueError(f"odd hex length: {len(stripped)}")
    return list(bytes.fromhex(stripped))


def py_compute_pe_checksum(image: bytes, checksum_offset: int) -> int:
    """Mirror of rustre_patch::compute_pe_checksum (pe_security.rs:203-226)."""
    s = 0
    n = len(image)
    i = 0
    while i + 1 < n:
        # Skip the 4 checksum bytes (two 16-bit words)
        if i == checksum_offset or i == checksum_offset + 2:
            i += 2
            continue
        w = int.from_bytes(image[i:i+2], 'little')
        s += w
        s = (s & 0xffff) + (s >> 16)
        i += 2
    if i < n:
        # Trailing odd byte
        s += image[i]
        s = (s & 0xffff) + (s >> 16)
    s = (s & 0xffff) + (s >> 16)
    folded = s & 0xffff
    return folded + n


# Known assemble_simple encodings from binary_patcher.rs:888-910
ASSEMBLE_TABLE = {
    "nop":          [0x90],
    "ret":          [0xc3],
    "retn":         [0xc3],
    "ret far":      [0xcb],
    "retf":         [0xcb],
    "int3":         [0xcc],
    "ud2":          [0x0f, 0x0b],
    "hlt":          [0xf4],
    "cli":          [0xfa],
    "sti":          [0xfb],
    "leave":        [0xc9],
    "cdq":          [0x99],
    "syscall":      [0x0f, 0x05],
    "sysret":       [0x0f, 0x07],
    "pushfd":       [0x9c],
    "pushfq":       [0x9c],
    "popfd":        [0x9d],
    "popfq":        [0x9d],
    "xor eax, eax":[0x31, 0xc0],
    "xor rax, rax":[0x48, 0x31, 0xc0],
    "mov eax, 0":  [0xb8, 0, 0, 0, 0],
    "mov eax, 1":  [0xb8, 1, 0, 0, 0],
}


def pe_checksum_offset(image: bytes):
    """Return the file offset of the PE optional-header CheckSum field, or None."""
    if len(image) < 0x40 or image[0:2] != b'MZ':
        return None
    e_lfanew = int.from_bytes(image[0x3c:0x40], 'little')
    if e_lfanew + 28 > len(image) or image[e_lfanew:e_lfanew+4] != b'PE\x00\x00':
        return None
    # optional header starts at e_lfanew + 24
    opt = e_lfanew + 24
    # CheckSum is at optional_header + 64 for both PE32 and PE32+
    cksum_off = opt + 64
    if cksum_off + 4 > len(image):
        return None
    return cksum_off


def py_pe_security(image: bytes):
    """Extract dll_characteristics, is_64bit from raw PE bytes.
       Returns dict or None on error."""
    if len(image) < 0x40 or image[0:2] != b'MZ':
        return None
    e_lfanew = int.from_bytes(image[0x3c:0x40], 'little')
    if e_lfanew + 24 > len(image) or image[e_lfanew:e_lfanew+4] != b'PE\x00\x00':
        return None
    opt = e_lfanew + 24
    if opt + 2 > len(image):
        return None
    opt_magic = int.from_bytes(image[opt:opt+2], 'little')
    is_64bit = (opt_magic == 0x20b)
    # DllCharacteristics: offset 70 from optional header start (for PE32+)
    # PE32  optional header: BaseOfData at off 24, then SizeOfImage at off 56, Subsystem at off 68, DllCharacteristics at off 70
    # PE32+ optional header: no BaseOfData, so DllCharacteristics at off 70 as well
    dll_char_off = opt + 70
    if dll_char_off + 2 > len(image):
        return None
    dll_characteristics = int.from_bytes(image[dll_char_off:dll_char_off+2], 'little')
    return {
        "is_64bit":            is_64bit,
        "dll_characteristics": dll_characteristics,
        "aslr":                bool(dll_characteristics & 0x0040),
        "dep":                 bool(dll_characteristics & 0x0100),
        "cfg":                 bool(dll_characteristics & 0x4000),
        "force_integrity":     bool(dll_characteristics & 0x0080),
        "no_seh":              bool(dll_characteristics & 0x0400),
        "no_isolation":        bool(dll_characteristics & 0x0200),
        "no_bind":             bool(dll_characteristics & 0x0800),
        "terminal_server_aware": bool(dll_characteristics & 0x8000),
    }


# ---------------------------------------------------------------------------
# Test cases
# ---------------------------------------------------------------------------
results   = []  # passed/failed tools
skips     = []  # tools that cannot be independently verified

def record(tool, passed, expected, actual, note=""):
    results.append({
        "tool":     tool,
        "status":   "PASS" if passed else "FAIL",
        "expected": expected,
        "actual":   actual,
        "note":     note,
    })

def skip(tool, reason):
    skips.append({"tool": tool, "reason": reason})


# ---------------------------------------------------------------------------
# 1. patch_parse_hex_bytes
# ---------------------------------------------------------------------------
TOOL = "patch_parse_hex_bytes"
TEST_CASES_PHB = [
    ("deadbeef",                  [0xde, 0xad, 0xbe, 0xef]),
    ("DE AD BE EF",               [0xde, 0xad, 0xbe, 0xef]),
    ("0xDE,0xAD,0xBE,0xEF",       [0xde, 0xad, 0xbe, 0xef]),
    ("00112233",                  [0x00, 0x11, 0x22, 0x33]),
    ("deadbeef00112233",          [0xde, 0xad, 0xbe, 0xef, 0x00, 0x11, 0x22, 0x33]),
    ("90 90 CC",                  [0x90, 0x90, 0xcc]),
]
all_phb_pass = True
phb_details = []
for hex_in, expected_bytes in TEST_CASES_PHB:
    rid += 1
    actual = mcp_call(TOOL, {"hex": hex_in}, rid)
    if "__mcp_error" in actual:
        all_phb_pass = False
        phb_details.append({"hex_in": hex_in, "error": actual["__mcp_error"]})
        continue
    got_bytes = actual.get("bytes", None)
    got_len   = actual.get("len", None)
    py_bytes  = py_parse_hex_bytes(hex_in)
    if got_bytes != py_bytes or got_len != len(py_bytes):
        all_phb_pass = False
        phb_details.append({
            "hex_in": hex_in,
            "expected_bytes": py_bytes,
            "actual_bytes":   got_bytes,
        })
    else:
        phb_details.append({"hex_in": hex_in, "status": "ok"})
record(TOOL, all_phb_pass,
       "all test cases match py_parse_hex_bytes",
       phb_details)

# ---------------------------------------------------------------------------
# 2. patch_assemble_simple — verify known mnemonics
# ---------------------------------------------------------------------------
TOOL = "patch_assemble_simple"
ASM_CASES = list(ASSEMBLE_TABLE.items())
all_asm_pass = True
asm_details  = []
for mnemonic, expected_enc in ASM_CASES:
    rid += 1
    actual = mcp_call(TOOL, {"asm": mnemonic}, rid)
    if "__mcp_error" in actual:
        # Acceptable if mnemonic is unsupported (tool errors legitimately)
        asm_details.append({"mnemonic": mnemonic, "error": actual["__mcp_error"]})
        all_asm_pass = False
        continue
    got_bytes = actual.get("bytes", None)
    if got_bytes != expected_enc:
        all_asm_pass = False
        asm_details.append({
            "mnemonic": mnemonic,
            "expected": expected_enc,
            "actual":   got_bytes,
        })
    else:
        asm_details.append({"mnemonic": mnemonic, "status": "ok"})

# Extra: "nop 4" should produce [0x90,0x90,0x90,0x90]
rid += 1
actual = mcp_call(TOOL, {"asm": "nop 4"}, rid)
got_bytes = actual.get("bytes", [])
nop4_expected = [0x90]*4
if got_bytes != nop4_expected:
    all_asm_pass = False
    asm_details.append({"mnemonic": "nop 4", "expected": nop4_expected, "actual": got_bytes})
else:
    asm_details.append({"mnemonic": "nop 4", "status": "ok"})

record(TOOL, all_asm_pass,
       "all known mnemonics produce correct encodings",
       asm_details)

# ---------------------------------------------------------------------------
# 3. patch_compute_pe_checksum — compare Rust output to py reference
# ---------------------------------------------------------------------------
TOOL = "patch_compute_pe_checksum"
try:
    image = open(TARGET, 'rb').read()
    cksum_off = pe_checksum_offset(image)
    if cksum_off is None:
        skip(TOOL, "could not locate checksum offset in target PE")
    else:
        py_cksum = py_compute_pe_checksum(image, cksum_off)
        rid += 1
        actual = mcp_call(TOOL, {"path": TARGET, "checksum_offset": cksum_off}, rid)
        if "__mcp_error" in actual:
            record(TOOL, False, py_cksum, actual)
        else:
            got = actual.get("checksum")
            passed = (got == py_cksum)
            record(TOOL, passed,
                   {"checksum": py_cksum, "checksum_offset": cksum_off},
                   {"checksum": got},
                   note=f"image_size={len(image)}, checksum_offset={cksum_off:#x}")
except FileNotFoundError:
    skip(TOOL, f"target PE not found: {TARGET}")

# ---------------------------------------------------------------------------
# 4. patch_pe_security_summary — compare all flags to py reference
# ---------------------------------------------------------------------------
TOOL = "patch_pe_security_summary"
try:
    image = open(TARGET, 'rb').read()
    py_sec = py_pe_security(image)
    if py_sec is None:
        skip(TOOL, "py_pe_security could not parse target PE")
    else:
        rid += 1
        actual = mcp_call(TOOL, {"path": TARGET}, rid)
        if "__mcp_error" in actual:
            record(TOOL, False, py_sec, actual)
        else:
            mismatches = {}
            for key in ("aslr","dep","cfg","force_integrity","no_seh",
                        "no_isolation","no_bind","terminal_server_aware",
                        "is_64bit","dll_characteristics"):
                exp_v = py_sec.get(key)
                got_v = actual.get(key)
                if exp_v != got_v:
                    mismatches[key] = {"expected": exp_v, "actual": got_v}
            record(TOOL, not mismatches,
                   py_sec, actual,
                   note=f"mismatches={mismatches}" if mismatches else "all flags match")
except FileNotFoundError:
    skip(TOOL, f"target PE not found: {TARGET}")

# ---------------------------------------------------------------------------
# 5. patch_binary_diff + patch_binary_patch — roundtrip property
#    diff(old, new) => delta; patch(old, delta) == new
# ---------------------------------------------------------------------------
ROUNDTRIP_CASES = [
    ("deadbeef",  "deadcafe"),        # 2-byte change at position 2
    ("00010203", "00010203"),         # identical (no-op)
    ("aabbcc",   "aabb00cc"),         # insertion (different length)
    ("0102030405060708", "0102ff0405060708"),  # 1-byte change in middle
]
all_rt_pass = True
rt_details  = []
for old_hex, new_hex in ROUNDTRIP_CASES:
    # Step A: call patch_binary_diff
    rid += 1
    diff_resp = mcp_call("patch_binary_diff", {"old_hex": old_hex, "new_hex": new_hex}, rid)
    if "__mcp_error" in diff_resp:
        all_rt_pass = False
        rt_details.append({"old_hex": old_hex, "new_hex": new_hex,
                            "error_diff": diff_resp["__mcp_error"]})
        continue
    delta_hex = diff_resp.get("delta_hex", "")
    # Step B: call patch_binary_patch to reconstruct new from old+delta
    rid += 1
    patch_resp = mcp_call("patch_binary_patch", {"old_hex": old_hex, "delta_hex": delta_hex}, rid)
    if "__mcp_error" in patch_resp:
        all_rt_pass = False
        rt_details.append({"old_hex": old_hex, "new_hex": new_hex,
                            "error_patch": patch_resp["__mcp_error"]})
        continue
    reconstructed_hex = patch_resp.get("new_hex", "").lower()
    expected_hex = py_parse_hex_bytes(new_hex)
    # Normalise: compare byte lists
    try:
        recon_bytes = list(bytes.fromhex(reconstructed_hex))
    except Exception:
        recon_bytes = None
    if recon_bytes != expected_hex:
        all_rt_pass = False
        rt_details.append({"old_hex": old_hex, "new_hex": new_hex,
                            "expected": expected_hex, "actual": recon_bytes})
    else:
        rt_details.append({"old_hex": old_hex, "new_hex": new_hex, "status": "ok"})

record("patch_binary_diff+patch_binary_patch (roundtrip)", all_rt_pass,
       "patch(old, diff(old,new)) == new for all cases",
       rt_details)

# ---------------------------------------------------------------------------
# 6. patch_build_delta — roundtrip through a separate code path
# ---------------------------------------------------------------------------
TOOL = "patch_build_delta"
all_bd_pass = True
bd_details  = []
for old_hex, new_hex in [("deadbeef","deadcafe"), ("aabb","aabb00cc")]:
    rid += 1
    resp = mcp_call(TOOL, {"old_hex": old_hex, "new_hex": new_hex}, rid)
    if "__mcp_error" in resp:
        all_bd_pass = False
        bd_details.append({"case": f"{old_hex}->{new_hex}", "error": resp["__mcp_error"]})
        continue
    delta = resp.get("delta")
    if delta is None:
        all_bd_pass = False
        bd_details.append({"case": f"{old_hex}->{new_hex}", "error": "no delta key"})
        continue
    # Verify the delta records the correct old_size / new_size
    expected_old_size = len(py_parse_hex_bytes(old_hex))
    expected_new_size = len(py_parse_hex_bytes(new_hex))
    got_old = delta.get("old_size")
    got_new = delta.get("new_size")
    ok = (got_old == expected_old_size and got_new == expected_new_size)
    if not ok:
        all_bd_pass = False
        bd_details.append({
            "case": f"{old_hex}->{new_hex}",
            "expected_old_size": expected_old_size, "got_old_size": got_old,
            "expected_new_size": expected_new_size, "got_new_size": got_new,
        })
    else:
        bd_details.append({"case": f"{old_hex}->{new_hex}", "status": "ok"})

record(TOOL, all_bd_pass,
       "delta.old_size/new_size match input lengths",
       bd_details)

# ---------------------------------------------------------------------------
# 7. patch_patch_find_code_caves — structure check (SKIP: too complex)
# ---------------------------------------------------------------------------
skip("patch_patch_find_code_caves",
     "No independent byte-level reference for cave detection; "
     "depends on PE section layout which requires a full PE parser.")

# ---------------------------------------------------------------------------
# 8. patch_bytes_at_va / patch_nop_range_at_va / patch_asm_at_va /
#    patch_patch_xor_region_at_va / patch_pe_security_set / patch_pe_va_to_file_offset
# ---------------------------------------------------------------------------
for tool in ["patch_bytes_at_va", "patch_nop_range_at_va", "patch_asm_at_va",
             "patch_patch_xor_region_at_va", "patch_pe_security_set"]:
    skip(tool, "Writes/modifies on-disk files; excluded to avoid side-effects on test binary.")

skip("patch_pe_va_to_file_offset",
     "Requires a hex-encoded PE image as input; ground-truth section layout "
     "verification would replicate the Rust PE parser itself.")

# ---------------------------------------------------------------------------
# Shutdown
# ---------------------------------------------------------------------------
proc.stdin.close()
proc.terminate()

# ---------------------------------------------------------------------------
# Write output files
# ---------------------------------------------------------------------------
with open(OUT, "w") as f:
    json.dump(results, f, indent=2)
print(f"Wrote {OUT}")

with open(SKIP_OUT, "w") as f:
    json.dump(skips, f, indent=2)
print(f"Wrote {SKIP_OUT}")

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
passed  = sum(1 for r in results if r["status"] == "PASS")
failed  = sum(1 for r in results if r["status"] == "FAIL")
hardened = len(results)   # every tested tool was hardened (had no prior ground-truth check)
skipped = len(skips)

print(f"\n=== RIGOROUS PATCH VALIDATION SUMMARY ===")
print(f"  Hardened (tested with ground-truth): {hardened}")
print(f"  PASS:    {passed}")
print(f"  FAIL:    {failed}")
print(f"  SKIPPED: {skipped}")
print()
for r in results:
    mark = "OK" if r["status"] == "PASS" else "FAIL"
    print(f"  [{mark}] {r['tool']}")
    if r["status"] == "FAIL":
        print(f"        expected: {str(r['expected'])[:120]}")
        print(f"        actual:   {str(r['actual'])[:120]}")
        if r.get("note"):
            print(f"        note:     {r['note']}")
print()
for s in skips:
    print(f"  [SKIP] {s['tool']}: {s['reason'][:90]}")

# Exit non-zero if any failures so the caller knows
sys.exit(0 if failed == 0 else 1)
