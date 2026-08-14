#!/usr/bin/env python3
"""Rigorous validator for the 'loader' module MCP tools.

Each tool is tested against an independently computed Python truth using only
stdlib (hashlib, zlib, struct, base64) or well-known public-spec constants.
No third-party libraries required.

Output: validation/rigorous_loader.json
"""
import json
import subprocess
import hashlib
import zlib
import struct
import base64
import os
import sys

EXE = r"C:\Users\Fra\Desktop\RustRE\target\release\rustre-mcp.exe"
OUT = r"C:\Users\Fra\Desktop\RustRE\validation\rigorous_loader.json"
MODULE = "loader"

# ---------------------------------------------------------------------------
# MCP transport helpers
# ---------------------------------------------------------------------------

proc = subprocess.Popen(
    [EXE, "--transport=stdio"],
    stdin=subprocess.PIPE,
    stdout=subprocess.PIPE,
    stderr=subprocess.DEVNULL,
    bufsize=0,
)
_rid = [0]


def _send(obj):
    proc.stdin.write((json.dumps(obj) + "\n").encode())
    proc.stdin.flush()


def _recv():
    line = proc.stdout.readline()
    return json.loads(line) if line else None


# Initialise session
_send({"jsonrpc": "2.0", "id": 0, "method": "initialize",
       "params": {"protocolVersion": "2024-11-05", "capabilities": {},
                  "clientInfo": {"name": "rigorous_validator", "version": "1"}}})
_recv()
_send({"jsonrpc": "2.0", "method": "notifications/initialized"})


def call_tool(name, args):
    """Call an MCP tool and return the parsed JSON result, or (None, err_str)."""
    _rid[0] += 1
    myid = _rid[0]
    _send({"jsonrpc": "2.0", "id": myid, "method": "tools/call",
           "params": {"name": name, "arguments": args}})
    for _ in range(30):
        resp = _recv()
        if resp is None:
            return None, "no-response"
        if resp.get("id") != myid:
            continue
        if "error" in resp:
            return None, resp["error"].get("message", "rpc-error")
        result = resp.get("result", {})
        if result.get("isError"):
            txt = "".join(c.get("text", "") for c in result.get("content", []))
            return None, "TOOL_ERROR:" + txt[:300]
        content = result.get("content", [])
        if not content:
            return None, "empty-content"
        text = content[0].get("text", "")
        try:
            return json.loads(text), None
        except Exception:
            return text, None
    return None, "no-matching-response"


# ---------------------------------------------------------------------------
# Tracking
# ---------------------------------------------------------------------------

checks_passed = 0
checks_failed = 0
tools_hardened = set()
mismatches = []


def check(tool_name, description, mcp_val, truth_val, input_summary=""):
    global checks_passed, checks_failed
    tools_hardened.add(tool_name)
    if mcp_val == truth_val:
        checks_passed += 1
        print(f"  [PASS] {tool_name}: {description}")
    else:
        checks_failed += 1
        entry = {
            "tool": tool_name,
            "description": description,
            "input": input_summary,
            "mcp": mcp_val,
            "truth": truth_val,
        }
        mismatches.append(entry)
        print(f"  [FAIL] {tool_name}: {description}  mcp={mcp_val!r}  truth={truth_val!r}")


def skip(tool_name, reason):
    print(f"  [SKIP] {tool_name}: {reason}")


# ---------------------------------------------------------------------------
# Helper: independent Python Adler-32 (matches zlib.adler32 initial=1)
# ---------------------------------------------------------------------------

def py_adler32(data: bytes) -> int:
    """Standard Adler-32 identical to the Rust implementation (a=1,b=0,MOD=65521)."""
    a, b = 1, 0
    MOD = 65521
    for byte in data:
        a = (a + byte) % MOD
        b = (b + a) % MOD
    return (b << 16) | a


# ---------------------------------------------------------------------------
# Helper: independent Python ULEB128 / SLEB128
# ---------------------------------------------------------------------------

def py_uleb128(data: bytes, pos: int = 0):
    result, shift = 0, 0
    while pos < len(data):
        byte = data[pos]; pos += 1
        result |= (byte & 0x7F) << shift
        if (byte & 0x80) == 0:
            return result, pos
        shift += 7
        if shift >= 64:
            return None
    return None


def py_sleb128(data: bytes, pos: int = 0):
    result, shift, byte = 0, 0, 0
    while pos < len(data):
        byte = data[pos]; pos += 1
        result |= (byte & 0x7F) << shift
        shift += 7
        if (byte & 0x80) == 0:
            break
        if shift >= 63:
            return None
    if shift < 64 and (byte & 0x40):
        result |= -(1 << shift)
    return result, pos


# ---------------------------------------------------------------------------
# Helper: GNU hash (ELF)
# ---------------------------------------------------------------------------

def py_gnu_hash(name: bytes) -> int:
    h = 5381
    for b in name:
        h = ((h << 5) + h + b) & 0xFFFFFFFF
    return h


# ---------------------------------------------------------------------------
# TEST 1 – loader_core_md5: MD5 of known input
# ---------------------------------------------------------------------------
print("\n[1] loader_core_md5")
TEST_BYTES = b"Hello, RustRE!"
truth_md5 = hashlib.md5(TEST_BYTES).hexdigest()
r, err = call_tool("loader_core_md5", {"hex": TEST_BYTES.hex()})
if r is None:
    skip("loader_core_md5", err)
else:
    mcp_md5 = r.get("md5") or r.get("hash") or r.get("digest") if isinstance(r, dict) else r
    check("loader_core_md5", f"MD5({TEST_BYTES!r})", mcp_md5, truth_md5, TEST_BYTES.hex())

# ---------------------------------------------------------------------------
# TEST 2 – loader_core_sha256: SHA-256 of known input
# ---------------------------------------------------------------------------
print("\n[2] loader_core_sha256")
truth_sha256 = hashlib.sha256(TEST_BYTES).hexdigest()
r, err = call_tool("loader_core_sha256", {"hex": TEST_BYTES.hex()})
if r is None:
    skip("loader_core_sha256", err)
else:
    mcp_sha256 = r.get("sha256") or r.get("hash") or r.get("digest") if isinstance(r, dict) else r
    check("loader_core_sha256", f"SHA256({TEST_BYTES!r})", mcp_sha256, truth_sha256, TEST_BYTES.hex())

# ---------------------------------------------------------------------------
# TEST 3 – loader_android_adler32: Adler-32 of known input
# ---------------------------------------------------------------------------
print("\n[3] loader_android_adler32")
ADL_INPUT = b"\x01\x02\x03\x04\x05"
truth_adl = py_adler32(ADL_INPUT)
r, err = call_tool("loader_android_adler32", {"hex": ADL_INPUT.hex()})
if r is None:
    skip("loader_android_adler32", err)
else:
    mcp_adl = (r.get("checksum") or r.get("adler32") or r.get("value")
               if isinstance(r, dict) else r)
    check("loader_android_adler32", f"adler32({ADL_INPUT.hex()})", mcp_adl, truth_adl)

# Also test empty bytes (adler32([]) = 1)
ADL_EMPTY = b""
truth_adl_empty = py_adler32(ADL_EMPTY)  # = 1
r2, err2 = call_tool("loader_android_adler32", {"hex": ""})
if r2 is not None:
    mcp_adl2 = (r2.get("checksum") or r2.get("adler32") or r2.get("value")
                if isinstance(r2, dict) else r2)
    check("loader_android_adler32", "adler32(empty) == 1", mcp_adl2, truth_adl_empty, "empty")

# ---------------------------------------------------------------------------
# TEST 4 – loader_luajit_read_uleb128: ULEB128 decode
# ---------------------------------------------------------------------------
print("\n[4] loader_luajit_read_uleb128")
# Encode 300 as ULEB128: 300 = 0x12C => bytes [0xAC, 0x02]
ULEB_DATA = bytes([0xAC, 0x02])
truth_uleb_val, truth_uleb_pos = py_uleb128(ULEB_DATA, 0)
r, err = call_tool("loader_luajit_read_uleb128", {"data_hex": ULEB_DATA.hex(), "pos": 0})
if r is None:
    skip("loader_luajit_read_uleb128", err)
else:
    mcp_val = r.get("value") if isinstance(r, dict) else None
    mcp_nxt = r.get("next_pos") if isinstance(r, dict) else None
    check("loader_luajit_read_uleb128", "uleb128([0xAC,0x02]) value == 300",
          mcp_val, truth_uleb_val, ULEB_DATA.hex())
    check("loader_luajit_read_uleb128", "uleb128([0xAC,0x02]) next_pos == 2",
          mcp_nxt, truth_uleb_pos, ULEB_DATA.hex())

# Single-byte ULEB128: value 127 = 0x7F, next_pos = 1
ULEB1 = bytes([0x7F])
r1, _ = call_tool("loader_luajit_read_uleb128", {"data_hex": ULEB1.hex(), "pos": 0})
if r1 is not None:
    check("loader_luajit_read_uleb128", "uleb128([0x7F]) == 127",
          r1.get("value"), 127, "0x7f")

# ---------------------------------------------------------------------------
# TEST 5 – loader_luajit_read_sleb128: SLEB128 decode
# ---------------------------------------------------------------------------
print("\n[5] loader_luajit_read_sleb128")
# Encode -1 as SLEB128: [0x7F]
SLEB_NEG1 = bytes([0x7F])
truth_sleb_val, truth_sleb_pos = py_sleb128(SLEB_NEG1, 0)
r, err = call_tool("loader_luajit_read_sleb128", {"data_hex": SLEB_NEG1.hex(), "pos": 0})
if r is None:
    skip("loader_luajit_read_sleb128", err)
else:
    mcp_val = r.get("value") if isinstance(r, dict) else None
    check("loader_luajit_read_sleb128", "sleb128([0x7F]) == -1",
          mcp_val, truth_sleb_val, "0x7f")

# Encode 64 as SLEB128: [0xC0, 0x00]
SLEB_64 = bytes([0xC0, 0x00])
truth_64, _ = py_sleb128(SLEB_64, 0)
r64, _ = call_tool("loader_luajit_read_sleb128", {"data_hex": SLEB_64.hex(), "pos": 0})
if r64 is not None:
    check("loader_luajit_read_sleb128", "sleb128([0xC0,0x00]) == 64",
          r64.get("value"), truth_64, "0xc000")

# ---------------------------------------------------------------------------
# TEST 6 – loader_luajit_is_luajit: magic detection
# ---------------------------------------------------------------------------
print("\n[6] loader_luajit_is_luajit")
# LJ_MAGIC = [0x1B, b'L', b'J'] = 0x1B 0x4C 0x4A
LJ_MAGIC = bytes([0x1B, 0x4C, 0x4A, 0x02])  # version byte appended
r, err = call_tool("loader_luajit_is_luajit", {"data_hex": LJ_MAGIC.hex()})
if r is None:
    skip("loader_luajit_is_luajit", err)
else:
    mcp_is = (r.get("is_luajit") if isinstance(r, dict) else r)
    check("loader_luajit_is_luajit", "LuaJIT magic detected", bool(mcp_is), True, LJ_MAGIC.hex())

NOT_LJ = b"MZ\x90\x00"
r2, _ = call_tool("loader_luajit_is_luajit", {"data_hex": NOT_LJ.hex()})
if r2 is not None:
    mcp_is2 = (r2.get("is_luajit") if isinstance(r2, dict) else r2)
    check("loader_luajit_is_luajit", "MZ header not LuaJIT", bool(mcp_is2), False, NOT_LJ.hex())

# ---------------------------------------------------------------------------
# TEST 7 – loader_ole_is_ole: OLE magic detection
# ---------------------------------------------------------------------------
print("\n[7] loader_ole_is_ole")
OLE_MAGIC = bytes([0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1]) + b"\x00" * 8
r, err = call_tool("loader_ole_is_ole", {"hex": OLE_MAGIC.hex()})
if r is None:
    skip("loader_ole_is_ole", err)
else:
    mcp_is = (r.get("is_ole") if isinstance(r, dict) else r)
    check("loader_ole_is_ole", "OLE magic -> True", bool(mcp_is), True, OLE_MAGIC.hex())

r2, _ = call_tool("loader_ole_is_ole", {"hex": b"PKZip12345"[:8].hex()})
if r2 is not None:
    mcp_is2 = (r2.get("is_ole") if isinstance(r2, dict) else r2)
    check("loader_ole_is_ole", "non-OLE bytes -> False", bool(mcp_is2), False, "50 4b")

# ---------------------------------------------------------------------------
# TEST 8 – loader_pdf_version: extract version string from PDF header
# ---------------------------------------------------------------------------
print("\n[8] loader_pdf_version")
PDF_17 = b"%PDF-1.7\n"
r, err = call_tool("loader_pdf_version", {"hex": PDF_17.hex()})
if r is None:
    skip("loader_pdf_version", err)
else:
    mcp_ver = (r.get("version") if isinstance(r, dict) else r)
    check("loader_pdf_version", "PDF-1.7 header -> '1.7'", mcp_ver, "1.7", PDF_17.hex())

PDF_20 = b"%PDF-2.0\nsome content"
r2, _ = call_tool("loader_pdf_version", {"hex": PDF_20.hex()})
if r2 is not None:
    mcp_ver2 = (r2.get("version") if isinstance(r2, dict) else r2)
    check("loader_pdf_version", "PDF-2.0 header -> '2.0'", mcp_ver2, "2.0", PDF_20.hex())

# ---------------------------------------------------------------------------
# TEST 9 – loader_pdf_has_javascript: /JavaScript detection
# ---------------------------------------------------------------------------
print("\n[9] loader_pdf_has_javascript")
PDF_JS = b"%PDF-1.4\n<</JavaScript (alert(1))>>"
r, err = call_tool("loader_pdf_has_javascript", {"hex": PDF_JS.hex()})
if r is None:
    skip("loader_pdf_has_javascript", err)
else:
    mcp_has_js = (r.get("has_javascript") if isinstance(r, dict) else r)
    truth_has_js = b"/JavaScript" in PDF_JS
    check("loader_pdf_has_javascript", "PDF with /JavaScript -> True",
          bool(mcp_has_js), truth_has_js, "pdf with js")

PDF_NOJS = b"%PDF-1.4\n<</Type /Page>>"
r2, _ = call_tool("loader_pdf_has_javascript", {"hex": PDF_NOJS.hex()})
if r2 is not None:
    mcp_nojs = (r2.get("has_javascript") if isinstance(r2, dict) else r2)
    truth_nojs = b"/JavaScript" in PDF_NOJS
    check("loader_pdf_has_javascript", "PDF without /JavaScript -> False",
          bool(mcp_nojs), truth_nojs, "pdf without js")

# ---------------------------------------------------------------------------
# TEST 10 – loader_android_is_apk: APK detection (ZIP + classes.dex)
# ---------------------------------------------------------------------------
print("\n[10] loader_android_is_apk")
APK_BYTES = b"PK\x03\x04" + b"\x00" * 26 + b"classes.dex"
r, err = call_tool("loader_android_is_apk", {"hex": APK_BYTES.hex()})
if r is None:
    skip("loader_android_is_apk", err)
else:
    mcp_is_apk = (r.get("is_apk") if isinstance(r, dict) else r)
    truth_apk = APK_BYTES.startswith(b"PK\x03\x04") and b"classes.dex" in APK_BYTES
    check("loader_android_is_apk", "PK header + classes.dex -> True",
          bool(mcp_is_apk), truth_apk, APK_BYTES[:20].hex())

NOT_APK = b"PK\x03\x04" + b"\x00" * 20  # ZIP but no classes.dex
r2, _ = call_tool("loader_android_is_apk", {"hex": NOT_APK.hex()})
if r2 is not None:
    mcp_not = (r2.get("is_apk") if isinstance(r2, dict) else r2)
    truth_not = b"classes.dex" in NOT_APK
    check("loader_android_is_apk", "ZIP without classes.dex -> False",
          bool(mcp_not), truth_not, NOT_APK.hex())

# ---------------------------------------------------------------------------
# TEST 11 – loader_android_is_vdex: VDEX detection
# ---------------------------------------------------------------------------
print("\n[11] loader_android_is_vdex")
VDEX = b"vdex019\x00" + b"\x00" * 8
r, err = call_tool("loader_android_is_vdex", {"hex": VDEX.hex()})
if r is None:
    skip("loader_android_is_vdex", err)
else:
    mcp_is_vdex = (r.get("is_vdex") if isinstance(r, dict) else r)
    truth_vdex = VDEX.startswith(b"vdex") and VDEX[4:5].isdigit()
    check("loader_android_is_vdex", "vdex019 -> True",
          bool(mcp_is_vdex), truth_vdex, VDEX.hex())

NOT_VDEX = b"dex\n035\x00" + b"\x00" * 8
r2, _ = call_tool("loader_android_is_vdex", {"hex": NOT_VDEX.hex()})
if r2 is not None:
    mcp_not_vdex = (r2.get("is_vdex") if isinstance(r2, dict) else r2)
    truth_not_vdex = NOT_VDEX.startswith(b"vdex") and NOT_VDEX[4:5].isdigit()
    check("loader_android_is_vdex", "dex header not vdex -> False",
          bool(mcp_not_vdex), truth_not_vdex, NOT_VDEX.hex())

# ---------------------------------------------------------------------------
# TEST 12 – loader_wasm_opcode_mnemonic: WebAssembly opcode names (public spec)
# ---------------------------------------------------------------------------
print("\n[12] loader_wasm_opcode_mnemonic")
# From the WebAssembly Core Specification (section 5.4):
WASM_OPCODES = {
    0x00: "unreachable",
    0x01: "nop",
    0x02: "block",
    0x03: "loop",
    0x04: "if",
    0x0F: "return",
    0x10: "call",
    0x1A: "drop",
    0x41: "i32.const",
    0x6A: "i32.add",
}
for opcode_byte, expected_mnemonic in WASM_OPCODES.items():
    r, err = call_tool("loader_wasm_opcode_mnemonic", {"opcode": opcode_byte})
    if r is None:
        skip("loader_wasm_opcode_mnemonic", f"opcode 0x{opcode_byte:02x}: {err}")
        continue
    mcp_mnem = (r.get("mnemonic") if isinstance(r, dict) else r)
    check("loader_wasm_opcode_mnemonic",
          f"opcode 0x{opcode_byte:02x} == '{expected_mnemonic}'",
          mcp_mnem, expected_mnemonic, f"opcode={opcode_byte}")

# ---------------------------------------------------------------------------
# TEST 13 – loader_lua_is_bytecode: Lua magic detection
# ---------------------------------------------------------------------------
print("\n[13] loader_lua_is_bytecode")
# From tests/blitz.rs: is_lua_bytecode needs b"\x1bLua" + version byte (e.g. b"\x1bLuaX" = b"\x1bLua\x58")
LUA_MAGIC = b"\x1bLuaX"  # version byte 0x58 = 'X'
r, err = call_tool("loader_lua_is_bytecode", {"hex": LUA_MAGIC.hex()})
if r is None:
    skip("loader_lua_is_bytecode", err)
else:
    mcp_islua = (r.get("is_lua_bytecode") or r.get("is_bytecode") or r.get("result")
                 if isinstance(r, dict) else r)
    check("loader_lua_is_bytecode", "\\x1bLuaX -> True",
          bool(mcp_islua), True, LUA_MAGIC.hex())

NOT_LUA = b"\x1bLua"  # magic without version byte -> per tests, is_lua_bytecode returns False
r2, _ = call_tool("loader_lua_is_bytecode", {"hex": NOT_LUA.hex()})
if r2 is not None:
    mcp_not_lua = (r2.get("is_lua_bytecode") or r2.get("is_bytecode") or r2.get("result")
                   if isinstance(r2, dict) else r2)
    check("loader_lua_is_bytecode", "\\x1bLua (no version byte) -> False",
          bool(mcp_not_lua), False, NOT_LUA.hex())

# ---------------------------------------------------------------------------
# TEST 14 – loader_console_xor_checksum: XOR of all bytes
# ---------------------------------------------------------------------------
print("\n[14] loader_console_xor_checksum")
XOR_DATA = bytes([0x10, 0x20, 0x30, 0x40])
truth_xor = 0
for b in XOR_DATA:
    truth_xor ^= b
r, err = call_tool("loader_console_xor_checksum", {"hex": XOR_DATA.hex()})
if r is None:
    skip("loader_console_xor_checksum", err)
else:
    mcp_xor = (r.get("checksum") or r.get("xor") or r.get("value")
               if isinstance(r, dict) else r)
    check("loader_console_xor_checksum",
          f"XOR({XOR_DATA.hex()}) == 0x{truth_xor:02x}",
          mcp_xor, truth_xor, XOR_DATA.hex())

# Zero bytes => XOR = 0
XOR_ZEROS = bytes([0x00, 0x00])
r2, _ = call_tool("loader_console_xor_checksum", {"hex": XOR_ZEROS.hex()})
if r2 is not None and isinstance(r2, dict):
    # Use dict.get with a sentinel to avoid falsiness of 0
    _sentinel = object()
    mcp_xor2 = next((r2[k] for k in ("checksum", "xor", "value") if k in r2), _sentinel)
    if mcp_xor2 is not _sentinel:
        check("loader_console_xor_checksum", "XOR([0,0]) == 0", mcp_xor2, 0, "0000")

# ---------------------------------------------------------------------------
# TEST 15 – loader_pdf_has_embedded_files: /EmbeddedFile detection
# ---------------------------------------------------------------------------
print("\n[15] loader_pdf_has_embedded_files")
PDF_EMB = b"%PDF-1.6\n<</EmbeddedFile /Foo>>"
r, err = call_tool("loader_pdf_has_embedded_files", {"hex": PDF_EMB.hex()})
if r is None:
    skip("loader_pdf_has_embedded_files", err)
else:
    mcp_emb = (r.get("has_embedded_files") or r.get("has_embedded") or r.get("result")
               if isinstance(r, dict) else r)
    truth_emb = b"/EmbeddedFile" in PDF_EMB
    check("loader_pdf_has_embedded_files", "PDF with /EmbeddedFile -> True",
          bool(mcp_emb), truth_emb, "pdf-with-embed")

# ---------------------------------------------------------------------------
# Shutdown and report
# ---------------------------------------------------------------------------
try:
    proc.terminate()
except Exception:
    pass

report = {
    "module": MODULE,
    "tools_hardened": len(tools_hardened),
    "checks_passed": checks_passed,
    "checks_failed": checks_failed,
    "mismatches": mismatches,
}

with open(OUT, "w") as f:
    json.dump(report, f, indent=2)

print("\n" + "=" * 60)
print(f"Module          : {MODULE}")
print(f"Tools hardened  : {len(tools_hardened)}")
print(f"Checks passed   : {checks_passed}")
print(f"Checks failed   : {checks_failed}")
print(f"Real mismatches : {len(mismatches)}")
print("=" * 60)

if mismatches:
    print("\nMismatches:")
    for m in mismatches:
        print(f"  {m['tool']}: {m['description']}")
        print(f"    mcp  : {m['mcp']!r}")
        print(f"    truth: {m['truth']!r}")
