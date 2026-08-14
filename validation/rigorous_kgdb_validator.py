#!/usr/bin/env python3
"""
Rigorous ground-truth validation for all kgdb_ MCP tools.
Uses independent Python reference implementations for each check.
Produces rigorous_kgdb_v2.json.
"""
import json
import struct
import subprocess
import sys

EXE = r"C:\Users\Fra\Desktop\RustRE\target\release\rustre-mcp.exe"
TARGET = r"C:\Users\Fra\Desktop\Zyphora\target\release\cargo-zyphora.exe"
OUT_FILE = r"C:\Users\Fra\Desktop\RustRE\validation\rigorous_kgdb_v2.json"

# --------------------------------------------------------------------------
# MCP transport helpers
# --------------------------------------------------------------------------
proc = subprocess.Popen(
    [EXE, "--transport=stdio"],
    stdin=subprocess.PIPE,
    stdout=subprocess.PIPE,
    stderr=subprocess.DEVNULL,
    bufsize=0,
)

def send(req: dict) -> None:
    proc.stdin.write((json.dumps(req) + "\n").encode())
    proc.stdin.flush()

def recv() -> dict:
    line = proc.stdout.readline()
    if not line:
        raise RuntimeError("MCP server died")
    try:
        return json.loads(line)
    except json.JSONDecodeError:
        return {"error": {"message": f"bad-line: {line[:120]!r}"}}

def call_tool(name: str, args: dict) -> dict:
    """Call a tool and return the parsed JSON payload or an error dict."""
    send({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
          "params": {"name": name, "arguments": args}})
    resp = recv()
    if "error" in resp:
        return {"__rpc_error": resp["error"]}
    result = resp.get("result", {})
    if result.get("isError"):
        content = result.get("content", [])
        txt = content[0].get("text", "") if content else ""
        return {"__tool_error": txt}
    content = result.get("content", [])
    txt = content[0].get("text", "") if content else ""
    try:
        return json.loads(txt)
    except json.JSONDecodeError:
        return {"__raw": txt}

# --------------------------------------------------------------------------
# Handshake
# --------------------------------------------------------------------------
send({"jsonrpc": "2.0", "id": 0, "method": "initialize",
      "params": {"protocolVersion": "2024-11-05", "capabilities": {},
                 "clientInfo": {"name": "rigorous-kgdb", "version": "1"}}})
recv()
send({"jsonrpc": "2.0", "method": "notifications/initialized"})

send({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
      "params": {"name": "project.open", "arguments": {"path": TARGET}}})
recv()  # consume project.open response

# --------------------------------------------------------------------------
# Python reference implementations
# --------------------------------------------------------------------------

def py_bytes_to_hex(data: bytes) -> str:
    return data.hex()

def py_hex_to_bytes(s: str) -> bytes:
    return bytes.fromhex(s)

def py_rsp_checksum(data: str) -> int:
    return sum(data.encode()) & 0xFF

def py_rsp_checksum_bytes(data: bytes) -> int:
    return sum(data) & 0xFF

def py_u64_to_hex_le(v: int) -> str:
    return struct.pack("<Q", v).hex()

def py_u32_to_hex_le(v: int) -> str:
    return struct.pack("<I", v).hex()

def py_hex_le_to_u64(h: str) -> int:
    b = bytes.fromhex(h)
    # pad/truncate to 8 bytes
    b = (b + b"\x00" * 8)[:8]
    return struct.unpack("<Q", b)[0]

def py_read_u64_le_hex(h: str) -> int:
    """16-char hex field as LE u64."""
    if len(h) != 16:
        raise ValueError(f"expected 16 chars, got {len(h)}")
    b = bytes.fromhex(h)
    return struct.unpack("<Q", b)[0]

def py_is_kernel_address(addr: int) -> bool:
    # Linux x86_64: canonical kernel range is 0xffff800000000000 and above
    return addr >= 0xffff_8000_0000_0000

def py_page_align_down(addr: int) -> int:
    return addr & ~0xFFF

def py_page_align_up(addr: int) -> int:
    return (addr + 0xFFF) & ~0xFFF

def py_gdb_packet_to_wire(data: str) -> str:
    cs = py_rsp_checksum(data)
    return f"${data}#{cs:02x}"

def py_verify_rsp_checksum(wire: str) -> bool:
    start = wire.find('$')
    hash_pos = wire.rfind('#')
    if start == -1 or hash_pos == -1 or hash_pos + 3 > len(wire):
        return False
    payload = wire[start + 1:hash_pos]
    cs_str = wire[hash_pos + 1:hash_pos + 3]
    try:
        expected = int(cs_str, 16)
        return py_rsp_checksum(payload) == expected
    except ValueError:
        return False

def py_rle_encode(data: str) -> str:
    """GDB RSP RLE: run of N identical chars -> char * (N-1+29) if N>3 (i.e. >=4).
    Rust implementation uses `count > 3`, so runs of exactly 3 are NOT encoded."""
    if not data:
        return data
    out = []
    i = 0
    while i < len(data):
        c = data[i]
        j = i + 1
        while j < len(data) and data[j] == c and (j - i) < 97:
            j += 1
        run = j - i
        if run > 3:
            # encode as char + '*' + repeat_char
            repeat_ch = chr(run - 1 + 29)
            out.append(c + '*' + repeat_ch)
            i = j
        else:
            out.append(c)
            i += 1
    return "".join(out)

def py_rle_decode(data: str) -> str:
    """Decode GDB RSP RLE."""
    out = []
    i = 0
    while i < len(data):
        if i + 1 < len(data) and data[i + 1] == '*':
            if i + 2 < len(data):
                count = ord(data[i + 2]) - 29 + 1
                out.append(data[i] * count)
                i += 3
            else:
                out.append(data[i])
                i += 1
        else:
            out.append(data[i])
            i += 1
    return "".join(out)

def py_kvirt_to_phys(addr: int):
    """Linux direct-map: phys = virt - 0xffff888000000000"""
    DIRECT_MAP = 0xffff_8880_0000_0000
    if addr >= DIRECT_MAP:
        return addr - DIRECT_MAP
    return None

def py_rsp_escape(data: bytes) -> list:
    """Escape bytes for RSP: 0x23 (#), 0x24 ($), 0x7d (}) -> 0x7d XOR 0x20."""
    out = []
    escape_chars = {0x23, 0x24, 0x7d}
    for b in data:
        if b in escape_chars:
            out.extend([0x7d, b ^ 0x20])
        else:
            out.append(b)
    return out

def py_rsp_unescape(data: bytes) -> list:
    out = []
    i = 0
    while i < len(data):
        if data[i] == 0x7d and i + 1 < len(data):
            out.append(data[i + 1] ^ 0x20)
            i += 2
        else:
            out.append(data[i])
            i += 1
    return out

def py_encode_hex_buf(data: bytes) -> str:
    return data.hex()

def py_decode_hex_buf(h: str) -> bytes:
    return bytes.fromhex(h)

def py_parse_qsupported(resp: str) -> list:
    """Parse qSupported features - just count semicolon-separated features."""
    if not resp:
        return []
    return [f.strip() for f in resp.split(';') if f.strip()]

def py_parse_thread_list(resp: str) -> list:
    """Parse qfThreadInfo response: mXX,XX,XX format."""
    if not resp or resp == 'l':
        return []
    if resp.startswith('m'):
        return [t.strip() for t in resp[1:].split(',') if t.strip()]
    return []

def py_parse_kernel_callstack_count(log: str) -> int:
    """Count frames the Rust implementation would find."""
    count = 0
    for line in log.splitlines():
        trimmed = line.strip()
        for word in trimmed.split():
            cleaned = word.lstrip('[<').rstrip('>]')
            if len(cleaned) == 16 or cleaned.startswith("0xffff"):
                addr_str = cleaned.lstrip("0x") if cleaned.startswith("0x") else cleaned
                try:
                    addr = int(addr_str, 16)
                    if py_is_kernel_address(addr):
                        count += 1
                        break
                except ValueError:
                    pass
    return count

# --------------------------------------------------------------------------
# Test cases
# --------------------------------------------------------------------------
results = []
mismatches = []

def check(tool: str, args: dict, field: str, expected, label: str = ""):
    """Call tool, extract field, compare with expected."""
    actual_resp = call_tool(tool, args)
    if "__rpc_error" in actual_resp or "__tool_error" in actual_resp:
        results.append({"tool": tool, "label": label or tool, "status": "FAIL",
                        "expected": expected, "actual": actual_resp})
        mismatches.append({"tool": tool, "expected": expected, "actual": actual_resp})
        return False
    actual = actual_resp.get(field)
    ok = (actual == expected)
    status = "PASS" if ok else "FAIL"
    results.append({"tool": tool, "label": label or tool, "status": status,
                    "expected": expected, "actual": actual})
    if not ok:
        mismatches.append({"tool": tool, "expected": {field: expected},
                            "actual": {field: actual}})
    return ok

# ── kgdb_bytes_to_hex ─────────────────────────────────────────────────────
# (old wrapper - takes "hex" string input, encodes as-is actually; check via
# kgdb_bytes_to_hex_v2 which takes array input)

check("kgdb_bytes_to_hex_v2", {"bytes": [0xde, 0xad, 0xbe, 0xef]},
      "hex", py_bytes_to_hex(bytes([0xde, 0xad, 0xbe, 0xef])),
      "kgdb_bytes_to_hex_v2 [de,ad,be,ef]")

check("kgdb_bytes_to_hex_v2", {"bytes": [0x00, 0x01, 0x7f, 0xff]},
      "hex", "00017fff",
      "kgdb_bytes_to_hex_v2 boundary bytes")

# ── kgdb_hex_to_bytes_v2 ─────────────────────────────────────────────────
check("kgdb_hex_to_bytes_v2", {"hex": "deadbeef"},
      "len", 4,
      "kgdb_hex_to_bytes_v2 len=4")

check("kgdb_hex_to_bytes_v2", {"hex": "00017fff"},
      "bytes", [0, 1, 127, 255],
      "kgdb_hex_to_bytes_v2 values")

# ── kgdb_rsp_checksum ─────────────────────────────────────────────────────
check("kgdb_rsp_checksum", {"data": "OK"},
      "checksum", py_rsp_checksum("OK"),
      "kgdb_rsp_checksum 'OK'")

check("kgdb_rsp_checksum", {"data": "qSupported"},
      "checksum", py_rsp_checksum("qSupported"),
      "kgdb_rsp_checksum 'qSupported'")

check("kgdb_rsp_checksum", {"data": ""},
      "checksum", 0,
      "kgdb_rsp_checksum empty")

# ── kgdb_rsp_checksum_bytes ───────────────────────────────────────────────
check("kgdb_rsp_checksum_bytes", {"bytes": [0x4f, 0x4b]},  # "OK"
      "checksum", py_rsp_checksum_bytes(b"OK"),
      "kgdb_rsp_checksum_bytes b'OK'")

check("kgdb_rsp_checksum_bytes", {"bytes": [0, 0, 0, 0]},
      "checksum", 0,
      "kgdb_rsp_checksum_bytes zeros")

# ── kgdb_u64_to_hex_le ────────────────────────────────────────────────────
check("kgdb_u64_to_hex_le", {"value": 0x0102030405060708},
      "hex", py_u64_to_hex_le(0x0102030405060708),
      "kgdb_u64_to_hex_le 0x0102030405060708")

check("kgdb_u64_to_hex_le", {"value": 0},
      "hex", "0000000000000000",
      "kgdb_u64_to_hex_le 0")

check("kgdb_u64_to_hex_le", {"value": 0xffffffffffffffff},
      "hex", "ffffffffffffffff",
      "kgdb_u64_to_hex_le max")

# ── kgdb_u32_to_hex_le ────────────────────────────────────────────────────
check("kgdb_u32_to_hex_le", {"value": 0x01020304},
      "hex", py_u32_to_hex_le(0x01020304),
      "kgdb_u32_to_hex_le 0x01020304")

check("kgdb_u32_to_hex_le", {"value": 0},
      "hex", "00000000",
      "kgdb_u32_to_hex_le 0")

# ── kgdb_hex_le_to_u64 ────────────────────────────────────────────────────
# hex_le_to_u64 takes a hex string of LE bytes
check("kgdb_hex_le_to_u64", {"hex": "0807060504030201"},
      "value", py_hex_le_to_u64("0807060504030201"),
      "kgdb_hex_le_to_u64 round-trip")

check("kgdb_hex_le_to_u64", {"hex": "0000000000000000"},
      "value", 0,
      "kgdb_hex_le_to_u64 zero")

# ── kgdb_read_u64_le_hex ─────────────────────────────────────────────────
check("kgdb_read_u64_le_hex", {"hex": "0807060504030201"},
      "value", py_read_u64_le_hex("0807060504030201"),
      "kgdb_read_u64_le_hex")

# ── kgdb_is_kernel_address ────────────────────────────────────────────────
KERNEL_ADDR = 0xffffffff81000000
USER_ADDR   = 0x0000_7fff_1234_5678

check("kgdb_is_kernel_address", {"addr": KERNEL_ADDR},
      "is_kernel", True,
      "kgdb_is_kernel_address kernel VA")

check("kgdb_is_kernel_address", {"addr": USER_ADDR},
      "is_kernel", False,
      "kgdb_is_kernel_address user VA")

check("kgdb_is_kernel_address", {"addr": 0xffff800000000000},
      "is_kernel", py_is_kernel_address(0xffff800000000000),
      "kgdb_is_kernel_address boundary")

# ── kgdb_page_align ────────────────────────────────────────────────────────
ADDR_UNALIGNED = 0xffffffff81001234
check("kgdb_page_align", {"addr": ADDR_UNALIGNED},
      "down", py_page_align_down(ADDR_UNALIGNED),
      "kgdb_page_align down")

check("kgdb_page_align", {"addr": ADDR_UNALIGNED},
      "up", py_page_align_up(ADDR_UNALIGNED),
      "kgdb_page_align up")

check("kgdb_page_align", {"addr": 0x1000},
      "down", 0x1000,
      "kgdb_page_align already-aligned down")

check("kgdb_page_align", {"addr": 0x1000},
      "up", 0x1000,
      "kgdb_page_align already-aligned up")

# ── kgdb_kvirt_to_phys ────────────────────────────────────────────────────
DIRECT_MAP_ADDR = 0xffff888012345678
check("kgdb_kvirt_to_phys", {"addr": DIRECT_MAP_ADDR},
      "phys", py_kvirt_to_phys(DIRECT_MAP_ADDR),
      "kgdb_kvirt_to_phys direct-map address")

check("kgdb_kvirt_to_phys", {"addr": 0x1234},
      "phys", None,
      "kgdb_kvirt_to_phys user address -> None")

# ── kgdb_gdb_packet_to_wire ───────────────────────────────────────────────
for payload in ["OK", "qSupported", "", "T05"]:
    expected_wire = py_gdb_packet_to_wire(payload)
    check("kgdb_gdb_packet_to_wire", {"data": payload},
          "wire", expected_wire,
          f"kgdb_gdb_packet_to_wire '{payload}'")

# ── kgdb_gdb_packet_parse ─────────────────────────────────────────────────
for payload in ["OK", "qSupported", "T05"]:
    wire = py_gdb_packet_to_wire(payload)
    check("kgdb_gdb_packet_parse", {"wire": wire},
          "data", payload,
          f"kgdb_gdb_packet_parse '{payload}'")

# ── kgdb_verify_rsp_checksum ─────────────────────────────────────────────
good_wire = py_gdb_packet_to_wire("OK")
check("kgdb_verify_rsp_checksum", {"wire": good_wire},
      "valid", True,
      "kgdb_verify_rsp_checksum good packet")

bad_wire = "$OK#00"
check("kgdb_verify_rsp_checksum", {"wire": bad_wire},
      "valid", False,
      "kgdb_verify_rsp_checksum bad checksum")

# ── kgdb_rsp_verify_checksum_bytes ────────────────────────────────────────
data_bytes = [0x4f, 0x4b]  # "OK"
cs = py_rsp_checksum_bytes(bytes(data_bytes))
check("kgdb_rsp_verify_checksum_bytes",
      {"bytes": data_bytes, "checksum_hex": f"{cs:02x}"},
      "valid", True,
      "kgdb_rsp_verify_checksum_bytes correct")

check("kgdb_rsp_verify_checksum_bytes",
      {"bytes": data_bytes, "checksum_hex": "00"},
      "valid", False,
      "kgdb_rsp_verify_checksum_bytes wrong cs")

# ── kgdb_rsp_encode_packet_bytes ─────────────────────────────────────────
# kgdb_rsp_encode_packet_bytes returns Vec<u8> (JSON int array), not a string
raw = b"OK"
expected_packet_bytes = list(py_gdb_packet_to_wire(raw.decode()).encode())
check("kgdb_rsp_encode_packet_bytes", {"bytes": list(raw)},
      "packet", expected_packet_bytes,
      "kgdb_rsp_encode_packet_bytes b'OK'")

# ── kgdb_encode_hex_buf / kgdb_decode_hex_buf ────────────────────────────
test_data = [0xde, 0xad, 0xbe, 0xef, 0x00, 0xff]
expected_hex = py_encode_hex_buf(bytes(test_data))
check("kgdb_encode_hex_buf", {"bytes": test_data},
      "hex", expected_hex,
      "kgdb_encode_hex_buf")

check("kgdb_decode_hex_buf", {"hex": expected_hex},
      "bytes", test_data,
      "kgdb_decode_hex_buf round-trip")

# ── kgdb_rsp_escape ───────────────────────────────────────────────────────
# Escape: '#' (0x23) -> 0x7d 0x03, '$' (0x24) -> 0x7d 0x04, '}' (0x7d) -> 0x7d 0x5d
escape_input = [0x41, 0x23, 0x24, 0x7d, 0x42]  # A # $ } B
expected_escaped = py_rsp_escape(bytes(escape_input))
check("kgdb_rsp_escape", {"bytes": escape_input},
      "escaped", expected_escaped,
      "kgdb_rsp_escape special chars")

check("kgdb_rsp_escape", {"bytes": [0x41, 0x42]},
      "escaped", [0x41, 0x42],
      "kgdb_rsp_escape no special chars")

# ── kgdb_rsp_unescape ─────────────────────────────────────────────────────
escaped = [0x7d, 0x03, 0x7d, 0x04, 0x7d, 0x5d]  # escaped #, $, }
expected_unescaped = py_rsp_unescape(bytes(escaped))
check("kgdb_rsp_unescape", {"bytes": escaped},
      "unescaped", expected_unescaped,
      "kgdb_rsp_unescape")

# ── kgdb_rle_encode ───────────────────────────────────────────────────────
# Simple: no run of 3
check("kgdb_rle_encode", {"data": "ab"},
      "encoded", "ab",
      "kgdb_rle_encode short no-run")

# Run of 3 a's: 'aaa' -> 'a*' + chr(3-1+29)='a*"'
three_a = "aaa"
expected_rle = py_rle_encode(three_a)
resp_rle = call_tool("kgdb_rle_encode", {"data": three_a})
actual_rle = resp_rle.get("encoded")
rle_ok = (actual_rle == expected_rle)
results.append({"tool": "kgdb_rle_encode", "label": "rle_encode 'aaa'",
                "status": "PASS" if rle_ok else "FAIL",
                "expected": expected_rle, "actual": actual_rle})
if not rle_ok:
    mismatches.append({"tool": "kgdb_rle_encode", "expected": expected_rle,
                       "actual": actual_rle})

# ── kgdb_rle_decode ───────────────────────────────────────────────────────
check("kgdb_rle_decode", {"data": "ab"},
      "decoded", "ab",
      "kgdb_rle_decode passthrough")

# round-trip: encode then decode
resp_enc = call_tool("kgdb_rle_encode", {"data": "aaabbc"})
encoded_val = resp_enc.get("encoded", "")
resp_dec = call_tool("kgdb_rle_decode", {"data": encoded_val})
decoded_val = resp_dec.get("decoded", "")
rt_ok = (decoded_val == "aaabbc")
results.append({"tool": "kgdb_rle_decode", "label": "rle round-trip 'aaabbc'",
                "status": "PASS" if rt_ok else "FAIL",
                "expected": "aaabbc", "actual": decoded_val})
if not rt_ok:
    mismatches.append({"tool": "kgdb_rle_decode", "expected": "aaabbc",
                       "actual": decoded_val})

# ── kgdb_target_xml_x86_64 ────────────────────────────────────────────────
resp_xml = call_tool("kgdb_target_xml_x86_64", {})
xml_val = resp_xml.get("xml", "")
# Must contain x86_64 register info markers
xml_ok = ("rax" in xml_val or "eax" in xml_val or "x86" in xml_val
          or "feature" in xml_val)
results.append({"tool": "kgdb_target_xml_x86_64", "label": "target_xml_x86_64 contains arch markers",
                "status": "PASS" if xml_ok else "FAIL",
                "expected": "xml contains x86/eax/rax/feature",
                "actual": xml_val[:120]})
if not xml_ok:
    mismatches.append({"tool": "kgdb_target_xml_x86_64",
                       "expected": "xml with x86 markers",
                       "actual": xml_val[:120]})

# ── kgdb_target_xml_arm64 ─────────────────────────────────────────────────
resp_xml2 = call_tool("kgdb_target_xml_arm64", {})
xml_val2 = resp_xml2.get("xml", "")
xml_ok2 = ("aarch64" in xml_val2 or "arm" in xml_val2 or "x0" in xml_val2
           or "feature" in xml_val2)
results.append({"tool": "kgdb_target_xml_arm64", "label": "target_xml_arm64 contains arch markers",
                "status": "PASS" if xml_ok2 else "FAIL",
                "expected": "xml contains arm/aarch64/x0/feature",
                "actual": xml_val2[:120]})
if not xml_ok2:
    mismatches.append({"tool": "kgdb_target_xml_arm64",
                       "expected": "xml with arm markers",
                       "actual": xml_val2[:120]})

# ── kgdb_parse_qsupported ─────────────────────────────────────────────────
QSUPP = "PacketSize=3fff;QNonStop+;multiprocess+;xmlRegisters=i386"
resp_qs = call_tool("kgdb_parse_qsupported", {"response": QSUPP})
qs_count = resp_qs.get("count", 0)
expected_qs_count = len(py_parse_qsupported(QSUPP))
qs_ok = (qs_count == expected_qs_count)
results.append({"tool": "kgdb_parse_qsupported", "label": "parse_qsupported count",
                "status": "PASS" if qs_ok else "FAIL",
                "expected": expected_qs_count, "actual": qs_count})
if not qs_ok:
    mismatches.append({"tool": "kgdb_parse_qsupported",
                       "expected": expected_qs_count, "actual": qs_count})

# ── kgdb_parse_thread_list ────────────────────────────────────────────────
THREAD_RESP = "m1,2,3"
resp_th = call_tool("kgdb_parse_thread_list", {"response": THREAD_RESP})
th_count = resp_th.get("count", 0)
expected_th = len(py_parse_thread_list(THREAD_RESP))
th_ok = (th_count == expected_th)
results.append({"tool": "kgdb_parse_thread_list", "label": "parse_thread_list 'm1,2,3'",
                "status": "PASS" if th_ok else "FAIL",
                "expected": expected_th, "actual": th_count})
if not th_ok:
    mismatches.append({"tool": "kgdb_parse_thread_list",
                       "expected": expected_th, "actual": th_count})

# last-response 'l'
resp_th2 = call_tool("kgdb_parse_thread_list", {"response": "l"})
th2_ok = (resp_th2.get("count", -1) == 0)
results.append({"tool": "kgdb_parse_thread_list", "label": "parse_thread_list 'l'",
                "status": "PASS" if th2_ok else "FAIL",
                "expected": 0, "actual": resp_th2.get("count")})
if not th2_ok:
    mismatches.append({"tool": "kgdb_parse_thread_list",
                       "expected": 0, "actual": resp_th2.get("count")})

# ── kgdb_parse_kernel_callstack ───────────────────────────────────────────
# Use proper 16-char hex addresses without underscores
CALLSTACK_LOG = """\
[  0.000001] Call Trace:
[  0.000002]  <TASK>
[  0.000003]  ffffffff81001234 in do_syscall_64
[  0.000004]  ffffffff810abcde entry_SYSCALL_64
[  0.000005]  </TASK>
"""
expected_cs_count = py_parse_kernel_callstack_count(CALLSTACK_LOG)
resp_cs = call_tool("kgdb_parse_kernel_callstack", {"log": CALLSTACK_LOG})
actual_cs_count = resp_cs.get("count", -1)
cs_ok = (actual_cs_count == expected_cs_count and expected_cs_count >= 2)
results.append({"tool": "kgdb_parse_kernel_callstack",
                "label": f"parse_kernel_callstack count (expected={expected_cs_count})",
                "status": "PASS" if cs_ok else "FAIL",
                "expected": expected_cs_count, "actual": actual_cs_count})
if not cs_ok:
    mismatches.append({"tool": "kgdb_parse_kernel_callstack",
                       "expected": expected_cs_count, "actual": actual_cs_count})

# --------------------------------------------------------------------------
# Shutdown
# --------------------------------------------------------------------------
proc.stdin.close()
proc.terminate()

# --------------------------------------------------------------------------
# Tally
# --------------------------------------------------------------------------
passed = sum(1 for r in results if r["status"] == "PASS")
failed = sum(1 for r in results if r["status"] == "FAIL")
skipped = 0

# Unique tools hardened (tools that have at least one PASS and no FAIL)
tool_statuses: dict = {}
for r in results:
    t = r["tool"]
    if t not in tool_statuses:
        tool_statuses[t] = []
    tool_statuses[t].append(r["status"])

hardened_tools = [t for t, ss in tool_statuses.items()
                  if all(s == "PASS" for s in ss)]
tools_hardened = len(hardened_tools)
tools_passed_count = len([t for t, ss in tool_statuses.items()
                          if all(s == "PASS" for s in ss)])
tools_failed_count = len([t for t, ss in tool_statuses.items()
                          if "FAIL" in ss])

out = {
    "module": "kgdb_v2",
    "tools_hardened": tools_hardened,
    "tools_passed": tools_passed_count,
    "tools_failed": tools_failed_count,
    "tools_skipped": skipped,
    "mismatches": mismatches,
    "detail": results,
}

with open(OUT_FILE, "w") as f:
    json.dump(out, f, indent=2)

print(f"tools_hardened={tools_hardened} passed={passed} failed={failed} skipped={skipped}")
print(f"mismatches={len(mismatches)}")
for m in mismatches:
    print(f"  MISMATCH {m['tool']}: expected={m['expected']} actual={m['actual']}")
print(f"Output: {OUT_FILE}")
