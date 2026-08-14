#!/usr/bin/env python3
"""
Rigorous loader validation v2 — independent Python reference implementations.
Each MCP tool is called via the same json-rpc-over-stdio mechanism as exercise_v3.py.
"""
import json, subprocess, hashlib, zlib, struct, sys

EXE    = r"C:\Users\Fra\Desktop\RustRE\target\release\rustre-mcp.exe"
TARGET = r"C:\Users\Fra\Desktop\Zyphora\target\release\cargo-zyphora.exe"
OUT    = r"C:\Users\Fra\Desktop\RustRE\validation\rigorous_loader_v2.json"
SKIP_F = r"C:\Users\Fra\Desktop\RustRE\validation\skip_loader.json"

# ─── MCP transport (identical pattern to exercise_v3.py) ─────────────────────
p = subprocess.Popen(
    [EXE, "--transport=stdio"],
    stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, bufsize=0,
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
        return None, f"JSONRPC_ERROR: {resp['error']}"
    content = resp.get("result", {}).get("content", [])
    is_err  = resp.get("result", {}).get("isError", False)
    txt = content[0].get("text", "") if content else ""
    if is_err:
        return None, f"TOOL_ERROR: {txt[:300]}"
    if not txt:
        return None, "EMPTY"
    try:
        return json.loads(txt), None
    except Exception:
        return txt, None

# Initialize session
send({"jsonrpc": "2.0", "id": 1, "method": "initialize",
      "params": {"protocolVersion": "2024-11-05", "capabilities": {},
                 "clientInfo": {"name": "rigorous_loader_v2", "version": "1"}}})
recv()
send({"jsonrpc": "2.0", "method": "notifications/initialized"})

# Open project (required before using binary-aware tools)
send({"jsonrpc": "2.0", "id": 2, "method": "tools/call",
      "params": {"name": "project.open", "arguments": {"path": TARGET}}})
recv()

# ─── Python reference implementations ────────────────────────────────────────

def ref_md5(hex_str: str) -> str:
    return hashlib.md5(bytes.fromhex(hex_str)).hexdigest()

def ref_sha256(hex_str: str) -> str:
    return hashlib.sha256(bytes.fromhex(hex_str)).hexdigest()

def ref_gnu_hash(data: bytes) -> int:
    """GNU symbol hash (djb2-style with shift-5 multiply, 32-bit)."""
    h = 5381
    for b in data:
        h = ((h << 5) + h + b) & 0xFFFFFFFF
    return h

def ref_adler32(hex_str: str) -> int:
    return zlib.adler32(bytes.fromhex(hex_str)) & 0xFFFFFFFF

def ref_uleb128(data: bytes, pos: int = 0):
    """Unsigned LEB128 decode; returns (value, next_pos) or None."""
    result, shift, i = 0, 0, pos
    while i < len(data):
        b = data[i]; i += 1
        result |= (b & 0x7F) << shift
        shift += 7
        if (b & 0x80) == 0:
            return result, i
    return None

def ref_sleb128(data: bytes, pos: int = 0):
    """Signed LEB128 decode; returns (value, next_pos) or None."""
    result, shift, i = 0, 0, pos
    while i < len(data):
        b = data[i]; i += 1
        result |= (b & 0x7F) << shift
        shift += 7
        if (b & 0x80) == 0:
            if (b & 0x40) and shift < 64:
                result |= -(1 << shift)
            return result, i
    return None

def ref_dotnet_compressed_uint(data: bytes):
    """ECMA-335 §II.23.2 compressed unsigned integer; returns (value, consumed)."""
    if not data:
        return None, 0
    b0 = data[0]
    if (b0 & 0x80) == 0:
        return b0, 1
    if (b0 & 0xC0) == 0x80 and len(data) >= 2:
        return ((b0 & 0x3F) << 8) | data[1], 2
    if (b0 & 0xE0) == 0xC0 and len(data) >= 4:
        return (((b0 & 0x1F) << 24) | (data[1] << 16)
                | (data[2] << 8) | data[3]), 4
    return None, 0

def ref_xor_checksum(data: bytes) -> int:
    result = 0
    for b in data:
        result ^= b
    return result & 0xFF

def make_minimal_pe() -> list:
    """Craft a minimal buffer that passes is_pe: MZ + e_lfanew + PE\\0\\0."""
    pe_offset = 0x40
    buf = bytearray(pe_offset + 8)
    buf[0], buf[1] = 0x4D, 0x5A                        # MZ
    struct.pack_into("<I", buf, 0x3C, pe_offset)        # e_lfanew
    struct.pack_into("<I", buf, pe_offset, 0x00004550)  # PE\0\0
    return list(buf)

# ─── Test harness ─────────────────────────────────────────────────────────────
results    = []
mismatches = []
rid        = 100

HEX  = "deadbeef00112233"
DATA = bytes.fromhex(HEX)

def check(tool, args, field, expected, label=None):
    """Call tool, compare result[field] == expected. Records pass/fail."""
    global rid
    rid += 1
    out, err = call_tool(tool, args, rid)
    lbl = label or tool
    if err:
        rec = {"tool": tool, "label": lbl, "status": "TOOL_ERROR",
               "expected": expected, "actual": err}
        results.append(rec)
        mismatches.append({"tool": tool, "expected": expected, "actual": err})
        return False
    actual = out.get(field) if isinstance(out, dict) else out
    ok = (actual == expected)
    results.append({"tool": tool, "label": lbl, "status": "PASS" if ok else "FAIL",
                    "expected": expected, "actual": actual})
    if not ok:
        mismatches.append({"tool": tool, "expected": expected, "actual": actual})
    return ok

def check_leb(tool, key, test_bytes, pos, ref_fn, label):
    """Validate LEB128 tools that return {value, next_pos, ok}."""
    global rid
    rid += 1
    out, err = call_tool(tool, {"data": list(test_bytes), "pos": pos}, rid)
    ref = ref_fn(test_bytes, pos)
    if err:
        results.append({"tool": tool, "label": label, "status": "TOOL_ERROR",
                        "expected": str(ref), "actual": err})
        mismatches.append({"tool": tool, "expected": str(ref), "actual": err})
        return
    if ref is None:
        # edge case – both should report ok=false
        actual_ok = out.get("ok") if isinstance(out, dict) else None
        ok = (actual_ok is False)
        results.append({"tool": tool, "label": label,
                        "status": "PASS" if ok else "FAIL",
                        "expected": {"ok": False}, "actual": out})
        if not ok:
            mismatches.append({"tool": tool,
                               "expected": {"ok": False}, "actual": out})
        return
    exp_val, exp_pos = ref
    actual_val = out.get("value") if isinstance(out, dict) else None
    actual_pos = out.get("next_pos") if isinstance(out, dict) else None
    ok = (actual_val == exp_val and actual_pos == exp_pos)
    results.append({"tool": tool, "label": label,
                    "status": "PASS" if ok else "FAIL",
                    "expected": {"value": exp_val, "next_pos": exp_pos},
                    "actual":   {"value": actual_val, "next_pos": actual_pos}})
    if not ok:
        mismatches.append({"tool": tool,
                           "expected": {"value": exp_val, "next_pos": exp_pos},
                           "actual":   {"value": actual_val, "next_pos": actual_pos}})

# ─── 1. loader_core_md5 ───────────────────────────────────────────────────────
check("loader_core_md5", {"hex": HEX}, "md5", ref_md5(HEX))
check("loader_core_md5", {"hex": "00"}, "md5", ref_md5("00"), "md5(0x00)")
check("loader_core_md5", {"hex": ""}, "md5", ref_md5(""), "md5(empty)")

# ─── 2. loader_core_sha256 ────────────────────────────────────────────────────
check("loader_core_sha256", {"hex": HEX}, "sha256", ref_sha256(HEX))
check("loader_core_sha256", {"hex": "00"}, "sha256", ref_sha256("00"), "sha256(0x00)")

# ─── 3. loader_elf_gnu_hash_str ──────────────────────────────────────────────
for sym in ["main", "_start", "printf", "malloc", ""]:
    check("loader_elf_gnu_hash_str", {"name": sym}, "gnu_hash",
          ref_gnu_hash(sym.encode()), f"gnu_hash_str({sym!r})")

# ─── 4. loader_elf_gnu_hash_bytes ────────────────────────────────────────────
check("loader_elf_gnu_hash_bytes", {"hex": HEX}, "gnu_hash", ref_gnu_hash(DATA))
check("loader_elf_gnu_hash_bytes", {"hex": "00"}, "gnu_hash",
      ref_gnu_hash(b"\x00"), "gnu_hash_bytes(0x00)")

# ─── 5. loader_android_adler32 ───────────────────────────────────────────────
check("loader_android_adler32", {"hex": HEX}, "adler32", ref_adler32(HEX))
check("loader_android_adler32", {"hex": "0102030405"}, "adler32",
      ref_adler32("0102030405"), "adler32(01..05)")

# ─── 6. loader_luajit_read_uleb128 ───────────────────────────────────────────
check_leb("loader_luajit_read_uleb128", "value", b"\x05", 0, ref_uleb128, "uleb128: 5")
check_leb("loader_luajit_read_uleb128", "value", b"\x80\x01", 0, ref_uleb128, "uleb128: 128")
check_leb("loader_luajit_read_uleb128", "value", b"\xe5\x8e\x26", 0, ref_uleb128, "uleb128: 624485")
check_leb("loader_luajit_read_uleb128", "value", b"\xff\x7f", 0, ref_uleb128, "uleb128: 16383")

# ─── 7. loader_luajit_read_sleb128 ───────────────────────────────────────────
check_leb("loader_luajit_read_sleb128", "value", b"\x3f", 0, ref_sleb128, "sleb128: +63")
check_leb("loader_luajit_read_sleb128", "value", b"\x40", 0, ref_sleb128, "sleb128: -64")
check_leb("loader_luajit_read_sleb128", "value", b"\x7f", 0, ref_sleb128, "sleb128: -1")
check_leb("loader_luajit_read_sleb128", "value", b"\x80\x01", 0, ref_sleb128, "sleb128: +128")

# ─── 8. loader_dotnet_read_compressed_uint ───────────────────────────────────
for hex_in, desc in [("03", "1-byte:3"), ("817f", "2-byte:381"), ("c0002000", "4-byte:8192")]:
    exp_val, _ = ref_dotnet_compressed_uint(bytes.fromhex(hex_in))
    check("loader_dotnet_read_compressed_uint", {"hex": hex_in}, "value",
          exp_val, f"dotnet_compressed_uint({desc})")

# ─── 9. loader_lua_is_bytecode ───────────────────────────────────────────────
# Rust requires data.len() >= 5: \x1bLua + at least one version byte.
LUA_MAGIC = [0x1b, 0x4c, 0x75, 0x61, 0x54]  # \x1bLua + version=0x54 (Lua 5.4)
check("loader_lua_is_bytecode", {"bytes": LUA_MAGIC}, "is_lua_bytecode", True,  "lua magic (5 bytes)->true")
check("loader_lua_is_bytecode", {"hex":  HEX},        "is_lua_bytecode", False, "deadbeef->false")

# ─── 10. loader_java_is_class (rustre_loader_java) ───────────────────────────
CAFEBABE = [0xCA, 0xFE, 0xBA, 0xBE]
check("loader_java_is_class", {"bytes": CAFEBABE}, "is_class", True,  "CAFEBABE->true")
check("loader_java_is_class", {"hex":  HEX},       "is_class", False, "deadbeef->false")

# ─── 11. loader_is_java_class (FormatDetector) ───────────────────────────────
# FormatDetector::is_java_class uses classify_cafebabe which inspects the major
# version at bytes[6..8].  Major version must be >= 44 (Java 1.0) to be classified
# as JavaClass rather than FatMacho.  55 = Java 11.
JAVA_CLASS_BYTES = [0xCA, 0xFE, 0xBA, 0xBE, 0x00, 0x00, 0x00, 55]
check("loader_is_java_class", {"bytes": JAVA_CLASS_BYTES}, "is_java_class", True,  "CAFEBABE+major55->true")
check("loader_is_java_class", {"hex":  HEX},               "is_java_class", False, "deadbeef->false")

# ─── 12. loader_is_elf ───────────────────────────────────────────────────────
ELF_MAGIC = [0x7F, 0x45, 0x4C, 0x46, 0x02, 0x01, 0x01, 0x00]  # \x7fELF 64-bit LE
check("loader_is_elf", {"bytes": ELF_MAGIC}, "is_elf", True,  "ELF magic->true")
check("loader_is_elf", {"hex":  HEX},        "is_elf", False, "deadbeef->false")

# ─── 13. loader_is_pe ────────────────────────────────────────────────────────
PE_BYTES = make_minimal_pe()
check("loader_is_pe", {"bytes": PE_BYTES}, "is_pe", True,  "MZ+PE sig->true")
check("loader_is_pe", {"hex":  HEX},       "is_pe", False, "deadbeef->false")

# ─── 14. loader_is_macho ─────────────────────────────────────────────────────
MACHO_64_LE = [0xCF, 0xFA, 0xED, 0xFE]  # MH_CIGAM_64 (little-endian 64-bit)
MACHO_FAT   = [0xCA, 0xFE, 0xBA, 0xBE]  # FAT_MAGIC
check("loader_is_macho", {"bytes": MACHO_64_LE}, "is_macho", True,  "Mach-O 64LE->true")
check("loader_is_macho", {"bytes": MACHO_FAT},   "is_macho", True,  "Mach-O fat->true")
check("loader_is_macho", {"hex":  HEX},           "is_macho", False, "deadbeef->false")

# ─── 15. loader_ole_is_ole ───────────────────────────────────────────────────
OLE_MAGIC = [0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1]
check("loader_ole_is_ole", {"bytes": OLE_MAGIC}, "is_ole", True,  "OLE2 magic->true")
check("loader_ole_is_ole", {"hex":  HEX},         "is_ole", False, "deadbeef->false")

# ─── 16. loader_pdf_version ──────────────────────────────────────────────────
check("loader_pdf_version", {"bytes": list(b"%PDF-1.7\n")}, "version", "1.7", "PDF 1.7")
check("loader_pdf_version", {"bytes": list(b"%PDF-2.0\n")}, "version", "2.0", "PDF 2.0")
check("loader_pdf_version", {"bytes": list(b"%PDF-1.4\n")}, "version", "1.4", "PDF 1.4")

# ─── 17. loader_pdf_has_javascript ───────────────────────────────────────────
check("loader_pdf_has_javascript",
      {"bytes": list(b"%PDF-1.4\n/JavaScript (alert(1))\n")},
      "has_javascript", True,  "PDF with /JavaScript->true")
check("loader_pdf_has_javascript",
      {"bytes": list(b"%PDF-1.7\n%comment\n")},
      "has_javascript", False, "PDF without /JavaScript->false")

# ─── 18. loader_pdf_has_embedded_files ───────────────────────────────────────
check("loader_pdf_has_embedded_files",
      {"bytes": list(b"%PDF-1.4\n/EmbeddedFile (foo.bin)\n")},
      "has_embedded_files", True,  "PDF with /EmbeddedFile->true")
check("loader_pdf_has_embedded_files",
      {"bytes": list(b"%PDF-1.7\n%comment\n")},
      "has_embedded_files", False, "PDF without /EmbeddedFile->false")

# ─── 19. loader_android_is_apk ───────────────────────────────────────────────
# Rust: is_apk = starts_with(b"PK\x03\x04") AND windows(11).any(|w| w == b"classes.dex")
# So the buffer must contain BOTH the ZIP local file header AND the string "classes.dex".
APK_BYTES = list(b"PK\x03\x04" + b"\x00" * 20 + b"classes.dex")
check("loader_android_is_apk", {"bytes": APK_BYTES}, "is_apk", True,  "PK+classes.dex->true")
check("loader_android_is_apk", {"bytes": [0x50, 0x4B, 0x03, 0x04]},
      "is_apk", False, "PK only, no classes.dex->false")
check("loader_android_is_apk", {"hex": HEX}, "is_apk", False, "deadbeef->false")

# ─── 20. loader_android_is_vdex ──────────────────────────────────────────────
VDEX_MAGIC = list(b"vdex035\x00")  # vdex magic + version string
check("loader_android_is_vdex", {"bytes": VDEX_MAGIC}, "is_vdex", True,  "VDEX magic->true")
check("loader_android_is_vdex", {"hex":   HEX},         "is_vdex", False, "deadbeef->false")

# ─── 21. loader_android_is_dex ───────────────────────────────────────────────
DEX_MAGIC = list(b"dex\n035\x00")  # standard DEX magic
check("loader_android_is_dex", {"bytes": DEX_MAGIC}, "is_dex", True,  "DEX magic->true")
check("loader_android_is_dex", {"hex":   HEX},        "is_dex", False, "deadbeef->false")

# ─── 22. loader_wasm_opcode_mnemonic ─────────────────────────────────────────
# WebAssembly core spec §6.6 binary format opcode table
WASM_TABLE = {
    0x00: "unreachable",
    0x01: "nop",
    0x02: "block",
    0x03: "loop",
    0x04: "if",
    0x05: "else",
    0x0B: "end",
    0x0C: "br",
    0x0D: "br_if",
    0x0F: "return",
    0x10: "call",
    0x1A: "drop",
    0x1B: "select",
    0x20: "local.get",
    0x21: "local.set",
    0x22: "local.tee",
    0x23: "global.get",
    0x24: "global.set",
    0x28: "i32.load",
    0x36: "i32.store",
    0x41: "i32.const",
    0x42: "i64.const",
    0x45: "i32.eqz",
    0x46: "i32.eq",
    0x6A: "i32.add",
    0x6B: "i32.sub",
    0x6C: "i32.mul",
}
for op, mnemonic in WASM_TABLE.items():
    check("loader_wasm_opcode_mnemonic", {"opcode": op}, "mnemonic",
          mnemonic, f"wasm 0x{op:02x}={mnemonic}")

# ─── 23. loader_console_xor_checksum ─────────────────────────────────────────
check("loader_console_xor_checksum", {"hex": HEX}, "checksum",
      ref_xor_checksum(DATA), "xor_checksum(deadbeef00112233)")
check("loader_console_xor_checksum", {"bytes": [0x00, 0xFF, 0xAA, 0x55]},
      "checksum", ref_xor_checksum(bytes([0x00, 0xFF, 0xAA, 0x55])),
      "xor_checksum(00 FF AA 55)")

# ─── Teardown ────────────────────────────────────────────────────────────────
p.stdin.close(); p.terminate()

# ─── Skipped tools (nondeterministic / binary-file-dependent) ─────────────────
skips = [
    {"tool": "loader_pe_is_signed",              "reason": "Authenticode chain; no stdlib equivalent for independent verification"},
    {"tool": "loader_pe_pdb_path",               "reason": "PE debug directory parsing; file-specific"},
    {"tool": "loader_pe_parse_info",             "reason": "Requires PE binary; parse output is file-specific"},
    {"tool": "loader_pe_entry_points",           "reason": "Requires PE binary"},
    {"tool": "loader_pe_imports_from_dll",       "reason": "Requires PE binary"},
    {"tool": "loader_wasm_parse",                "reason": "Requires WASM binary file; none available"},
    {"tool": "loader_wasm_stats",                "reason": "Requires WASM binary file"},
    {"tool": "loader_elf_info_summary",          "reason": "Requires ELF binary; output is file-specific"},
    {"tool": "loader_elf_parse_info",            "reason": "Requires ELF binary"},
    {"tool": "loader_elf_plt_entries",           "reason": "Requires ELF binary"},
    {"tool": "loader_macho_parse",               "reason": "Requires Mach-O binary"},
    {"tool": "loader_macho_parse_fat",           "reason": "Requires Mach-O fat binary"},
    {"tool": "loader_macho_parse_summary",       "reason": "Requires Mach-O binary"},
    {"tool": "loader_android_verify_dex_checksum", "reason": "Requires structurally valid DEX file with correct header"},
    {"tool": "loader_console_detect_format",     "reason": "Algorithm internals not exposed; partially magic-byte driven"},
    {"tool": "loader_console_is_nes",            "reason": "Requires iNES ROM (NES\\x1a magic); trivial but covered by magic-byte pattern — low value"},
    {"tool": "loader_lua_opcode_name",           "reason": "Opcode tables are Lua-version-specific; no authoritative Python table"},
    {"tool": "loader_lua_read_string",           "reason": "Requires full Lua bytecode stream context"},
    {"tool": "loader_luajit_is_luajit",          "reason": "Requires LuaJIT bytecode with versioned magic"},
    {"tool": "loader_java_parse_class",          "reason": "Requires valid Java class file"},
    {"tool": "loader_java_is_jar",               "reason": "Requires valid JAR with .class entries"},
    {"tool": "loader_ole_list_streams",          "reason": "Requires valid OLE2 compound file"},
    {"tool": "loader_ole_extract_macros",        "reason": "Requires valid OLE2 with VBA streams"},
]

# ─── Summary ─────────────────────────────────────────────────────────────────
passed  = sum(1 for r in results if r["status"] == "PASS")
failed  = sum(1 for r in results if r["status"] in ("FAIL", "TOOL_ERROR"))
hardened = len(set(r["tool"] for r in results))

summary = {
    "module": "loader",
    "tools_hardened": hardened,
    "checks_run": len(results),
    "checks_passed": passed,
    "checks_failed": failed,
    "mismatches": mismatches,
    "results": results,
}

with open(OUT,    "w") as f: json.dump(summary, f, indent=2)
with open(SKIP_F, "w") as f: json.dump({"skipped": skips}, f, indent=2)

print(f"Checks: {len(results)}  passed: {passed}  failed: {failed}  hardened tools: {hardened}")
print(f"Skipped tools: {len(skips)}")
if mismatches:
    print(f"\nMISMATCHES ({len(mismatches)}):")
    for m in mismatches:
        print(f"  {m['tool']}: expected={m['expected']!r}  actual={m['actual']!r}")
else:
    print("All checks passed.")
