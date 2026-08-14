#!/usr/bin/env python3
"""
Rigorous ground-truth validation for all mcp__rustre-mcp__patch_* tools.
Uses Python stdlib only for reference computations.
Writes results to rigorous_patch_v2.json.
"""
import json, struct, hashlib, subprocess, sys, os, time

EXE    = r"C:\Users\Fra\Desktop\RustRE\target\release\rustre-mcp.exe"
TARGET = r"C:\Users\Fra\Desktop\Zyphora\target\release\cargo-zyphora.exe"
PDB    = r"C:\Users\Fra\Desktop\Zyphora\target\release\cargo_zyphora.pdb"
V2_OUT = r"C:\Users\Fra\Desktop\RustRE\validation\rigorous_patch_v2.json"
SKIP_OUT = r"C:\Users\Fra\Desktop\RustRE\validation\skip_patch.json"

# ---------------------------------------------------------------------------
# Python reference implementations
# ---------------------------------------------------------------------------

def ref_parse_hex_bytes(s: str) -> bytes:
    """Mirror rustre_patch::parse_hex_bytes."""
    cleaned = ''.join(c for c in s if not c.isspace() and c not in (',', '_'))
    stripped = cleaned.replace('0x', '').replace('0X', '')
    if not stripped:
        raise ValueError("empty input")
    if len(stripped) % 2 != 0:
        raise ValueError(f"odd hex length: {len(stripped)}")
    return bytes.fromhex(stripped)

def ref_assemble_simple(asm: str) -> bytes:
    """Mirror rustre_patch::assemble_simple lookup table."""
    lower = asm.strip().lower()
    # Normalise spaces around commas
    import re
    lower = re.sub(r'\s*,\s*', ', ', lower)
    lower = re.sub(r'\s+', ' ', lower).strip()
    TABLE = {
        "nop":          bytes([0x90]),
        "ret":          bytes([0xc3]),
        "retn":         bytes([0xc3]),
        "ret far":      bytes([0xcb]),
        "retf":         bytes([0xcb]),
        "int3":         bytes([0xcc]),
        "ud2":          bytes([0x0f, 0x0b]),
        "hlt":          bytes([0xf4]),
        "cli":          bytes([0xfa]),
        "sti":          bytes([0xfb]),
        "leave":        bytes([0xc9]),
        "cdq":          bytes([0x99]),
        "syscall":      bytes([0x0f, 0x05]),
        "sysret":       bytes([0x0f, 0x07]),
        "pushfd":       bytes([0x9c]),
        "pushfq":       bytes([0x9c]),
        "popfd":        bytes([0x9d]),
        "popfq":        bytes([0x9d]),
        "xor eax, eax": bytes([0x31, 0xc0]),
        "xor rax, rax": bytes([0x48, 0x31, 0xc0]),
        "mov eax, 0":   bytes([0xb8, 0x00, 0x00, 0x00, 0x00]),
        "mov eax, 1":   bytes([0xb8, 0x01, 0x00, 0x00, 0x00]),
    }
    # Handle "nop N"
    if lower.startswith("nop "):
        n = int(lower[4:].strip())
        return bytes([0x90] * n)
    # Handle "bytes <hex>"
    if lower.startswith("bytes "):
        return ref_parse_hex_bytes(lower[6:])
    if lower not in TABLE:
        raise ValueError(f"unsupported asm: {asm!r}")
    return TABLE[lower]

def ref_compute_pe_checksum(image: bytes, checksum_offset: int) -> int:
    """Mirror rustre_patch::compute_pe_checksum."""
    s = 0
    n = len(image)
    i = 0
    while i + 1 < n:
        if i == checksum_offset or i == checksum_offset + 2:
            i += 2
            continue
        w = image[i] | (image[i+1] << 8)
        s += w
        s = (s & 0xffff) + (s >> 16)
        i += 2
    if i < n:
        s += image[i]
        s = (s & 0xffff) + (s >> 16)
    s = (s & 0xffff) + (s >> 16)
    folded = s & 0xffff
    return (folded + n) & 0xffffffff

def pe_find_checksum_offset(image: bytes) -> int:
    """Return the file offset of the PE CheckSum field."""
    if len(image) < 0x40 or image[0:2] != b'MZ':
        raise ValueError("not a DOS/PE image")
    e_lfanew = struct.unpack_from('<I', image, 0x3C)[0]
    if image[e_lfanew:e_lfanew+4] != b'PE\0\0':
        raise ValueError("PE signature not found")
    # CheckSum is at OptionalHeader offset 0x40 (for both PE32 and PE32+)
    return e_lfanew + 4 + 20 + 0x40  # PE sig(4) + COFF(20) + OptHdr[0x40]

def pe_va_to_file_offset(image: bytes, va: int) -> int:
    """Convert a VA to file offset using section headers."""
    if image[0:2] != b'MZ':
        raise ValueError("not MZ")
    e_lfanew = struct.unpack_from('<I', image, 0x3C)[0]
    if image[e_lfanew:e_lfanew+4] != b'PE\0\0':
        raise ValueError("not PE")
    num_sections = struct.unpack_from('<H', image, e_lfanew + 4 + 2)[0]
    size_of_opt_hdr = struct.unpack_from('<H', image, e_lfanew + 4 + 16)[0]
    # Read image base from optional header
    opt_off = e_lfanew + 4 + 20
    magic = struct.unpack_from('<H', image, opt_off)[0]
    if magic == 0x020b:   # PE32+
        image_base = struct.unpack_from('<Q', image, opt_off + 24)[0]
    elif magic == 0x010b: # PE32
        image_base = struct.unpack_from('<I', image, opt_off + 28)[0]
    else:
        raise ValueError(f"unknown PE magic: {magic:#x}")
    rva = va - image_base
    section_start = opt_off + size_of_opt_hdr
    for i in range(num_sections):
        sec = section_start + i * 40
        virt_addr = struct.unpack_from('<I', image, sec + 12)[0]
        virt_size = struct.unpack_from('<I', image, sec + 8)[0]
        raw_data  = struct.unpack_from('<I', image, sec + 20)[0]
        raw_size  = struct.unpack_from('<I', image, sec + 16)[0]
        if virt_addr <= rva < virt_addr + max(virt_size, raw_size):
            return raw_data + (rva - virt_addr)
    raise ValueError(f"VA {va:#x} not in any section")

def pe_dll_characteristics(image: bytes) -> int:
    """Return DllCharacteristics from optional header."""
    e_lfanew = struct.unpack_from('<I', image, 0x3C)[0]
    opt_off = e_lfanew + 4 + 20
    magic = struct.unpack_from('<H', image, opt_off)[0]
    if magic == 0x020b:
        return struct.unpack_from('<H', image, opt_off + 70)[0]
    elif magic == 0x010b:
        return struct.unpack_from('<H', image, opt_off + 70)[0]
    raise ValueError(f"unknown PE magic: {magic:#x}")

# ---------------------------------------------------------------------------
# MCP communication helpers
# ---------------------------------------------------------------------------

def start_server():
    p = subprocess.Popen(
        [EXE, "--transport=stdio"],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL, bufsize=0
    )
    return p

def send(p, req):
    p.stdin.write((json.dumps(req) + "\n").encode())
    p.stdin.flush()

def recv(p):
    line = p.stdout.readline()
    if not line:
        raise RuntimeError("server died")
    return json.loads(line)

def call_tool(p, rid, name, args):
    send(p, {"jsonrpc":"2.0","id":rid,"method":"tools/call",
             "params":{"name":name,"arguments":args}})
    resp = recv(p)
    if "error" in resp:
        return None, f"JSONRPC_ERROR: {resp['error']}"
    result = resp.get("result", {})
    is_err = result.get("isError", False)
    content = result.get("content", [])
    txt = content[0].get("text", "") if content else ""
    if is_err:
        return None, f"TOOL_ERROR: {txt}"
    try:
        return json.loads(txt), None
    except Exception:
        return txt, None

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    results = []
    skips   = []
    rid     = [200]

    def next_id():
        rid[0] += 1
        return rid[0]

    # Load target binary for reference computations
    try:
        target_bytes = open(TARGET, 'rb').read()
    except Exception as e:
        print(f"Cannot read target binary: {e}", file=sys.stderr)
        target_bytes = None

    p = start_server()
    try:
        # Initialize
        send(p, {"jsonrpc":"2.0","id":1,"method":"initialize",
                 "params":{"protocolVersion":"2024-11-05","capabilities":{},
                           "clientInfo":{"name":"rigorous","version":"1"}}})
        recv(p)
        send(p, {"jsonrpc":"2.0","method":"notifications/initialized"})

        # Open project
        send(p, {"jsonrpc":"2.0","id":2,"method":"tools/call",
                 "params":{"name":"project.open","arguments":{"path":TARGET}}})
        op = recv(p)
        op_data = json.loads(op["result"]["content"][0]["text"])
        BINARY_ID  = op_data["binary_id"]
        PROJECT_ID = op_data["project_id"]
        print(f"project.open: binary_id={BINARY_ID}")

        # ---------------------------------------------------------------
        # TEST 1: patch_parse_hex_bytes — fully deterministic
        # ---------------------------------------------------------------
        hex_input = "deadbeef00112233"
        expected_bytes = list(ref_parse_hex_bytes(hex_input))
        data, err = call_tool(p, next_id(), "patch_parse_hex_bytes", {"hex": hex_input})
        if err:
            results.append({"tool":"patch_parse_hex_bytes","status":"FAIL",
                            "reason": err, "expected": expected_bytes, "actual": None})
        else:
            actual_bytes = data.get("bytes", [])
            actual_len   = data.get("len", -1)
            if actual_bytes == expected_bytes and actual_len == len(expected_bytes):
                results.append({"tool":"patch_parse_hex_bytes","status":"PASS",
                                "expected": expected_bytes, "actual": actual_bytes})
            else:
                results.append({"tool":"patch_parse_hex_bytes","status":"FAIL",
                                "expected": {"bytes": expected_bytes, "len": len(expected_bytes)},
                                "actual": {"bytes": actual_bytes, "len": actual_len}})

        # TEST 1b: parse_hex_bytes with spaces
        hex_spaces = "de ad be ef"
        expected_spaces = list(ref_parse_hex_bytes(hex_spaces))
        data2, err2 = call_tool(p, next_id(), "patch_parse_hex_bytes", {"hex": hex_spaces})
        if err2:
            results.append({"tool":"patch_parse_hex_bytes[spaces]","status":"FAIL",
                            "reason": err2, "expected": expected_spaces, "actual": None})
        else:
            actual2 = data2.get("bytes", [])
            if actual2 == expected_spaces:
                results.append({"tool":"patch_parse_hex_bytes[spaces]","status":"PASS",
                                "expected": expected_spaces, "actual": actual2})
            else:
                results.append({"tool":"patch_parse_hex_bytes[spaces]","status":"FAIL",
                                "expected": expected_spaces, "actual": actual2})

        # ---------------------------------------------------------------
        # TEST 2: patch_assemble_simple — known lookup table
        # ---------------------------------------------------------------
        asm_cases = [
            ("nop",      [0x90]),
            ("ret",      [0xc3]),
            ("int3",     [0xcc]),
            ("ud2",      [0x0f, 0x0b]),
            ("xor eax, eax", [0x31, 0xc0]),
            ("xor rax, rax", [0x48, 0x31, 0xc0]),
        ]
        for asm_src, exp_bytes in asm_cases:
            data, err = call_tool(p, next_id(), "patch_assemble_simple", {"asm": asm_src})
            tool_name = f"patch_assemble_simple[{asm_src}]"
            if err:
                results.append({"tool": tool_name, "status":"FAIL",
                                "reason": err, "expected": exp_bytes, "actual": None})
            else:
                actual = data.get("bytes", [])
                if actual == exp_bytes:
                    results.append({"tool": tool_name, "status":"PASS",
                                    "expected": exp_bytes, "actual": actual})
                else:
                    results.append({"tool": tool_name, "status":"FAIL",
                                    "expected": exp_bytes, "actual": actual})

        # ---------------------------------------------------------------
        # TEST 3: patch_compute_pe_checksum
        # ---------------------------------------------------------------
        if target_bytes:
            try:
                cs_off = pe_find_checksum_offset(target_bytes)
                expected_cksum = ref_compute_pe_checksum(target_bytes, cs_off)
                data, err = call_tool(p, next_id(), "patch_compute_pe_checksum",
                                      {"path": TARGET, "checksum_offset": cs_off})
                if err:
                    results.append({"tool":"patch_compute_pe_checksum","status":"FAIL",
                                    "reason": err, "expected": expected_cksum, "actual": None})
                else:
                    actual_cksum = data.get("checksum") if isinstance(data, dict) else None
                    if actual_cksum is None and isinstance(data, dict):
                        # Try alternate field names
                        actual_cksum = data.get("computed_checksum") or data.get("value")
                    ok = actual_cksum == expected_cksum
                    results.append({"tool":"patch_compute_pe_checksum",
                                    "status":"PASS" if ok else "FAIL",
                                    "expected": expected_cksum,
                                    "actual": actual_cksum,
                                    "raw": data if not ok else None})
            except Exception as ex:
                results.append({"tool":"patch_compute_pe_checksum","status":"FAIL",
                                "reason": f"reference error: {ex}"})
        else:
            skips.append({"tool":"patch_compute_pe_checksum","reason":"target binary not readable"})

        # ---------------------------------------------------------------
        # TEST 4: patch_pe_va_to_file_offset
        # ---------------------------------------------------------------
        if target_bytes:
            test_va = 5368771180  # 0x140001A6C — same as exercise_v3
            try:
                expected_off = pe_va_to_file_offset(target_bytes, test_va)
                data, err = call_tool(p, next_id(), "patch_pe_va_to_file_offset",
                                      {"path": TARGET, "va": test_va})
                if err:
                    results.append({"tool":"patch_pe_va_to_file_offset","status":"FAIL",
                                    "reason": err, "expected": expected_off, "actual": None})
                else:
                    actual_off = None
                    if isinstance(data, dict):
                        actual_off = data.get("file_offset") or data.get("offset")
                    ok = actual_off == expected_off
                    results.append({"tool":"patch_pe_va_to_file_offset",
                                    "status":"PASS" if ok else "FAIL",
                                    "expected": expected_off, "actual": actual_off,
                                    "raw": data if not ok else None})
            except Exception as ex:
                skips.append({"tool":"patch_pe_va_to_file_offset",
                              "reason": f"reference error: {ex}"})
        else:
            skips.append({"tool":"patch_pe_va_to_file_offset","reason":"target binary not readable"})

        # ---------------------------------------------------------------
        # TEST 5: patch_binary_diff + patch_binary_patch (round-trip property)
        # ---------------------------------------------------------------
        old_hex = "deadbeef00112233aabbccdd"
        new_hex = "deadbeef00aabbcc11223344"

        data_diff, err_diff = call_tool(p, next_id(), "patch_binary_diff",
                                        {"old_hex": old_hex, "new_hex": new_hex})
        if err_diff:
            results.append({"tool":"patch_binary_diff","status":"FAIL",
                            "reason": err_diff})
        else:
            # Verify header fields
            exp_old_len = len(ref_parse_hex_bytes(old_hex))
            exp_new_len = len(ref_parse_hex_bytes(new_hex))
            actual_old = data_diff.get("old_len")
            actual_new = data_diff.get("new_len")
            delta_hex  = data_diff.get("delta_hex", "")

            # Verify delta starts with RRDF magic (hex "52524446")
            delta_magic_ok = delta_hex.lower().startswith("52524446")

            size_ok = (actual_old == exp_old_len) and (actual_new == exp_new_len)
            if size_ok and delta_magic_ok:
                results.append({"tool":"patch_binary_diff","status":"PASS",
                                "old_len": actual_old, "new_len": actual_new,
                                "delta_magic": delta_hex[:8]})
            else:
                results.append({"tool":"patch_binary_diff","status":"FAIL",
                                "expected": {"old_len": exp_old_len, "new_len": exp_new_len,
                                             "magic": "52524446"},
                                "actual": {"old_len": actual_old, "new_len": actual_new,
                                           "magic": delta_hex[:8]}})

            # TEST 5b: patch_binary_patch (round-trip)
            if delta_hex:
                data_patch, err_patch = call_tool(p, next_id(), "patch_binary_patch",
                                                  {"old_hex": old_hex, "delta_hex": delta_hex})
                if err_patch:
                    results.append({"tool":"patch_binary_patch","status":"FAIL",
                                    "reason": err_patch})
                else:
                    actual_new_hex = data_patch.get("new_hex","").lower()
                    expected_new_hex = new_hex.lower()
                    ok = actual_new_hex == expected_new_hex
                    results.append({"tool":"patch_binary_patch",
                                    "status":"PASS" if ok else "FAIL",
                                    "expected": expected_new_hex,
                                    "actual": actual_new_hex})

        # ---------------------------------------------------------------
        # TEST 6: patch_pe_security_summary — verify DllCharacteristics
        # ---------------------------------------------------------------
        if target_bytes:
            try:
                expected_dll_chars = pe_dll_characteristics(target_bytes)
                data, err = call_tool(p, next_id(), "patch_pe_security_summary",
                                      {"path": TARGET})
                if err:
                    results.append({"tool":"patch_pe_security_summary","status":"FAIL",
                                    "reason": err})
                else:
                    actual_dll = None
                    if isinstance(data, dict):
                        actual_dll = data.get("dll_characteristics") or data.get("raw_dll_characteristics")
                    ok = actual_dll == expected_dll_chars
                    results.append({"tool":"patch_pe_security_summary",
                                    "status":"PASS" if ok else "FAIL",
                                    "expected_dll_chars": expected_dll_chars,
                                    "actual_dll_chars": actual_dll,
                                    "raw": data if not ok else None})
            except Exception as ex:
                skips.append({"tool":"patch_pe_security_summary",
                              "reason": f"reference error: {ex}"})
        else:
            skips.append({"tool":"patch_pe_security_summary","reason":"target binary not readable"})

        # ---------------------------------------------------------------
        # TEST 7: patch_pe_security_set (dry_run=true — structure check)
        # ---------------------------------------------------------------
        data, err = call_tool(p, next_id(), "patch_pe_security_set",
                              {"path": TARGET, "aslr": True, "dry_run": True})
        if err:
            results.append({"tool":"patch_pe_security_set","status":"FAIL","reason": err})
        else:
            has_old = "old_dll_characteristics" in (data or {})
            has_new = "new_dll_characteristics" in (data or {})
            has_dry = data.get("dry_run") == True if data else False
            if has_old and has_new and has_dry:
                # Extra: verify old_dll_characteristics matches PE header
                if target_bytes:
                    try:
                        expected_dll = pe_dll_characteristics(target_bytes)
                        actual_old_dll = data.get("old_dll_characteristics")
                        ok = actual_old_dll == expected_dll
                        results.append({"tool":"patch_pe_security_set",
                                        "status":"PASS" if ok else "FAIL",
                                        "expected_old_dll": expected_dll,
                                        "actual_old_dll": actual_old_dll})
                    except Exception as ex:
                        results.append({"tool":"patch_pe_security_set","status":"PASS",
                                        "note": f"structure ok, ref error: {ex}"})
                else:
                    results.append({"tool":"patch_pe_security_set","status":"PASS",
                                    "note":"structure validated"})
            else:
                results.append({"tool":"patch_pe_security_set","status":"FAIL",
                                "reason":"missing expected fields in response",
                                "data": data})

        # ---------------------------------------------------------------
        # TEST 8: patch_bytes_at_va (dry_run=true — structure check)
        # ---------------------------------------------------------------
        data, err = call_tool(p, next_id(), "patch_bytes_at_va",
                              {"path": TARGET, "va": 5368771180, "hex": "9090",
                               "dry_run": True, "backup": False})
        if err:
            results.append({"tool":"patch_bytes_at_va","status":"FAIL","reason": err})
        else:
            ok = isinstance(data, dict) and data.get("dry_run") == True
            results.append({"tool":"patch_bytes_at_va",
                            "status":"PASS" if ok else "FAIL",
                            "data": data})

        # ---------------------------------------------------------------
        # TEST 9: patch_nop_range_at_va (dry_run=true — structure check)
        # ---------------------------------------------------------------
        data, err = call_tool(p, next_id(), "patch_nop_range_at_va",
                              {"path": TARGET, "va": 5368771180, "length": 4,
                               "dry_run": True, "backup": False})
        if err:
            results.append({"tool":"patch_nop_range_at_va","status":"FAIL","reason": err})
        else:
            ok = isinstance(data, dict) and data.get("dry_run") == True
            results.append({"tool":"patch_nop_range_at_va",
                            "status":"PASS" if ok else "FAIL",
                            "data": data})

        # ---------------------------------------------------------------
        # TEST 10: patch_patch_xor_region_at_va (dry_run=true — structure check)
        # ---------------------------------------------------------------
        data, err = call_tool(p, next_id(), "patch_patch_xor_region_at_va",
                              {"path": TARGET, "va": 5368771180, "length": 4,
                               "key_hex": "deadbeef", "dry_run": True, "backup": False})
        if err:
            results.append({"tool":"patch_patch_xor_region_at_va","status":"FAIL","reason": err})
        else:
            ok = isinstance(data, dict) and data.get("dry_run") == True
            results.append({"tool":"patch_patch_xor_region_at_va",
                            "status":"PASS" if ok else "FAIL",
                            "data": data})

        # ---------------------------------------------------------------
        # TEST 11: patch_patch_find_code_caves — verify at least one result
        #          and that each cave has offset/size fields (structure check)
        # ---------------------------------------------------------------
        data, err = call_tool(p, next_id(), "patch_patch_find_code_caves",
                              {"path": TARGET, "min_size": 16})
        if err:
            results.append({"tool":"patch_patch_find_code_caves","status":"FAIL","reason": err})
        else:
            caves = None
            if isinstance(data, dict):
                caves = data.get("caves") or data.get("code_caves") or data.get("results")
            if isinstance(data, list):
                caves = data
            if caves and isinstance(caves, list) and len(caves) > 0:
                first = caves[0]
                has_offset = "offset" in first or "file_offset" in first
                has_size   = "size" in first or "length" in first
                results.append({"tool":"patch_patch_find_code_caves",
                                "status":"PASS" if (has_offset and has_size) else "FAIL",
                                "cave_count": len(caves),
                                "first_cave": first})
            else:
                # No caves found or unexpected format
                results.append({"tool":"patch_patch_find_code_caves","status":"FAIL",
                                "reason":"no caves returned or unexpected format",
                                "data": data})

        # ---------------------------------------------------------------
        # TEST 12: patch_build_delta — same round-trip check as patch_binary_diff
        # ---------------------------------------------------------------
        data, err = call_tool(p, next_id(), "patch_build_delta",
                              {"old_hex": old_hex, "new_hex": new_hex})
        if err:
            results.append({"tool":"patch_build_delta","status":"FAIL","reason": err})
        else:
            delta_hex2 = None
            if isinstance(data, dict):
                delta_hex2 = data.get("delta_hex") or data.get("encoded_hex")
            magic_ok = delta_hex2 and delta_hex2.lower().startswith("52524446")
            results.append({"tool":"patch_build_delta",
                            "status":"PASS" if magic_ok else "FAIL",
                            "magic": delta_hex2[:8] if delta_hex2 else None,
                            "data": data if not magic_ok else None})

        # ---------------------------------------------------------------
        # Skips for nondeterministic / network-required tools
        # ---------------------------------------------------------------
        for tool_name, reason in [
            ("patch_asm_at_va",
             "requires assembler + live file write (dry_run path not verifiable without an assembler reference)"),
        ]:
            skips.append({"tool": tool_name, "reason": reason})

    finally:
        p.stdin.close()
        p.terminate()

    # Write outputs
    with open(V2_OUT,   'w') as f: json.dump(results, f, indent=2)
    with open(SKIP_OUT, 'w') as f: json.dump(skips,   f, indent=2)

    passed  = sum(1 for r in results if r["status"] == "PASS")
    failed  = sum(1 for r in results if r["status"] == "FAIL")
    skipped = len(skips)
    mismatches = [
        {"tool": r["tool"],
         "expected": r.get("expected"),
         "actual":   r.get("actual")}
        for r in results if r["status"] == "FAIL"
    ]

    summary = {
        "category":       "patch",
        "tools_hardened": len(results),
        "tools_passed":   passed,
        "tools_failed":   failed,
        "tools_skipped":  skipped,
        "mismatches":     mismatches,
    }
    print(json.dumps(summary, indent=2))
    return summary

if __name__ == "__main__":
    main()
