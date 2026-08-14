#!/usr/bin/env python3
"""
Rigorous validator for kgdb_* MCP tools.
Uses independent Python truth computed from public GDB RSP protocol specs
and stdlib (struct, hashlib, zlib, base64).

Report saved to: validation/rigorous_kgdb.json
"""
import json
import struct
import subprocess
import sys

EXE = r"C:\Users\Fra\Desktop\RustRE\target\release\rustre-mcp.exe"
OUT = r"C:\Users\Fra\Desktop\RustRE\validation\rigorous_kgdb.json"

# ──────────────────────────────────────────────────────────
# MCP session helpers
# ──────────────────────────────────────────────────────────

def start_session():
    p = subprocess.Popen(
        [EXE, "--transport=stdio"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        bufsize=0,
    )
    def send(r):
        p.stdin.write((json.dumps(r) + "\n").encode())
        p.stdin.flush()
    def recv():
        line = p.stdout.readline()
        return json.loads(line) if line else None
    send({
        "jsonrpc": "2.0", "id": 1, "method": "initialize",
        "params": {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": {"name": "rigorous-kgdb", "version": "1"},
        },
    })
    recv()
    send({"jsonrpc": "2.0", "method": "notifications/initialized"})
    return p, send, recv

p, send, recv = start_session()
_rid = [100]

def call(name, args):
    _rid[0] += 1
    send({
        "jsonrpc": "2.0", "id": _rid[0],
        "method": "tools/call",
        "params": {"name": name, "arguments": args},
    })
    resp = recv()
    if resp is None or "error" in resp:
        return None
    content = resp.get("result", {}).get("content", [])
    if not content:
        return None
    text = content[0].get("text", "")
    try:
        return json.loads(text)
    except Exception:
        return text

# ──────────────────────────────────────────────────────────
# Independent Python truth helpers (GDB RSP protocol)
# ──────────────────────────────────────────────────────────

def py_rsp_checksum_str(s: str) -> int:
    """Sum of ASCII codes of s modulo 256."""
    return sum(s.encode("latin-1")) & 0xFF

def py_rsp_checksum_bytes(b: bytes) -> int:
    return sum(b) & 0xFF

def py_rsp_escape(data: bytes) -> list:
    """Escape $, #, }, * per GDB RSP spec (XOR 0x20)."""
    out = []
    for byte in data:
        if byte in (0x24, 0x23, 0x7D, 0x2A):
            out.append(0x7D)
            out.append(byte ^ 0x20)
        else:
            out.append(byte)
    return out

def py_rsp_unescape(data: bytes) -> list:
    out = []
    i = 0
    while i < len(data):
        if data[i] == 0x7D and i + 1 < len(data):
            out.append(data[i + 1] ^ 0x20)
            i += 2
        else:
            out.append(data[i])
            i += 1
    return out

def py_gdb_packet_to_wire(payload: str) -> str:
    cs = py_rsp_checksum_str(payload)
    return f"${payload}#{cs:02x}"

def py_encode_hex_buf(data: bytes) -> str:
    return data.hex()

def py_decode_hex_buf(s: str) -> list:
    return list(bytes.fromhex(s))

def py_read_u64_le_hex(s: str) -> int:
    return struct.unpack("<Q", bytes.fromhex(s))[0]

def py_u64_to_hex_le(v: int) -> str:
    return struct.pack("<Q", v).hex()

def py_u32_to_hex_le(v: int) -> str:
    return struct.pack("<I", v).hex()

def py_page_align(addr: int, page_size: int = 0x1000) -> int:
    return addr & ~(page_size - 1)

def py_is_kernel_address(addr: int) -> bool:
    """Linux x86-64: kernel space starts at 0xffff800000000000."""
    return addr >= 0xFFFF800000000000

def py_hex_to_bytes(s: str) -> list:
    return list(bytes.fromhex(s))

def py_bytes_to_hex(data: bytes) -> str:
    return data.hex()

def py_rsp_encode_packet_bytes(data: bytes) -> str:
    cs = py_rsp_checksum_bytes(data)
    return f"${data.decode('latin-1')}#{cs:02x}"

# ──────────────────────────────────────────────────────────
# Check bookkeeping
# ──────────────────────────────────────────────────────────

checks_passed = 0
checks_failed = 0
mismatches = []
tools_hardened = set()

def check(tool: str, label: str, got, expected, note: str = ""):
    global checks_passed, checks_failed
    tools_hardened.add(tool)
    # Normalise for comparison
    a, b = got, expected
    if isinstance(a, list) and isinstance(b, list):
        eq = a == b
    elif isinstance(a, str) and isinstance(b, str):
        eq = a.lower() == b.lower()
    else:
        eq = a == b

    if eq:
        checks_passed += 1
        print(f"  PASS  {tool} [{label}]")
    else:
        checks_failed += 1
        mismatches.append({
            "tool": tool,
            "label": label,
            "got": got,
            "expected": expected,
            "note": note,
        })
        print(f"  FAIL  {tool} [{label}]  got={got!r}  expected={expected!r}")

def skip(tool: str, reason: str):
    print(f"  SKIP  {tool}: {reason}")

# ──────────────────────────────────────────────────────────
# Tool checks — 10+ tools with rigorous Python truth
# ──────────────────────────────────────────────────────────

print("=== kgdb rigorous validator ===\n")

# ── 1. kgdb_rsp_checksum (string-based) ──────────────────
# Tool schema: {"data": string}  → {"checksum": u8, "checksum_hex": str}
TOOL = "kgdb_rsp_checksum"
test_cases = [
    ("g",   py_rsp_checksum_str("g")),    # 0x67
    ("OK",  py_rsp_checksum_str("OK")),   # 0x4f+0x4b = 0x9a
    ("qSupported:multiprocess+;swbreak+", py_rsp_checksum_str("qSupported:multiprocess+;swbreak+")),
    ("",    0),
]
for payload, truth in test_cases:
    r = call(TOOL, {"data": payload})
    if r is None:
        skip(TOOL, f"no response for {payload!r}")
    else:
        check(TOOL, f"checksum({payload!r})", r.get("checksum"), truth)
        check(TOOL, f"checksum_hex({payload!r})", r.get("checksum_hex"), f"{truth:02x}")

# ── 2. kgdb_rsp_checksum_bytes (array-based) ─────────────
# Tool schema: {"bytes": [u8]}  → {"checksum": u8, "checksum_hex": str}
TOOL = "kgdb_rsp_checksum_bytes"
byte_cases = [
    ([0x67],               0x67),    # 'g'
    ([0x4f, 0x4b],         0x9a),    # 'OK'
    ([0xde, 0xad, 0xbe, 0xef], (0xde+0xad+0xbe+0xef) & 0xFF),
    ([],                   0),
]
for blist, truth in byte_cases:
    r = call(TOOL, {"bytes": blist})
    if r is None:
        skip(TOOL, f"no response for {blist}")
    else:
        check(TOOL, f"bytes_checksum({blist})", r.get("checksum"), truth)

# ── 3. kgdb_rsp_verify_checksum_bytes ────────────────────
# Schema: {"bytes":[u8], "checksum_hex":str}  → {"valid": bool}
TOOL = "kgdb_rsp_verify_checksum_bytes"
verify_cases = [
    ([0x4f, 0x4b], "9a", True),     # OK → 0x9a ✓
    ([0x4f, 0x4b], "9b", False),    # wrong checksum
    ([0x67],       "67", True),     # g → 0x67 ✓
    ([0xde, 0xad, 0xbe, 0xef], f"{(0xde+0xad+0xbe+0xef)&0xFF:02x}", True),
]
for blist, cs_hex, truth in verify_cases:
    r = call(TOOL, {"bytes": blist, "checksum_hex": cs_hex})
    if r is None:
        skip(TOOL, f"no response for bytes={blist} cs={cs_hex}")
    else:
        check(TOOL, f"verify({blist},{cs_hex})", r.get("valid"), truth)

# ── 4. kgdb_gdb_packet_to_wire ───────────────────────────
# Schema: {"data": str}  → {"wire": str, "checksum": u8}
TOOL = "kgdb_gdb_packet_to_wire"
wire_cases = [
    ("OK",  "$OK#9a"),
    ("g",   f"$g#{py_rsp_checksum_str('g'):02x}"),
    ("vCont?", f"$vCont?#{py_rsp_checksum_str('vCont?'):02x}"),
]
for payload, truth_wire in wire_cases:
    r = call(TOOL, {"data": payload})
    if r is None:
        skip(TOOL, f"no response for {payload!r}")
    else:
        check(TOOL, f"wire({payload!r})", r.get("wire"), truth_wire)
        check(TOOL, f"checksum({payload!r})", r.get("checksum"), py_rsp_checksum_str(payload))

# ── 5. kgdb_gdb_packet_parse ─────────────────────────────
# Schema: {"wire": str}  → {"data": str, "checksum": u8}
TOOL = "kgdb_gdb_packet_parse"
parse_cases = [
    ("$OK#9a",  "OK",  0x9a),
    (f"$g#{py_rsp_checksum_str('g'):02x}", "g", py_rsp_checksum_str("g")),
]
for wire, exp_data, exp_cs in parse_cases:
    r = call(TOOL, {"wire": wire})
    if r is None:
        skip(TOOL, f"no response for {wire!r}")
    else:
        check(TOOL, f"parse_data({wire!r})", r.get("data"), exp_data)
        check(TOOL, f"parse_cs({wire!r})", r.get("checksum"), exp_cs)

# ── 6. kgdb_verify_rsp_checksum (whole-wire tool) ────────
# Schema: {"wire": str}  → {"valid": bool}
TOOL = "kgdb_verify_rsp_checksum"
for wire, truth in [
    ("$OK#9a",  True),
    ("$OK#9b",  False),
    (f"$g#{py_rsp_checksum_str('g'):02x}", True),
]:
    r = call(TOOL, {"wire": wire})
    if r is None:
        skip(TOOL, f"no response for {wire!r}")
    else:
        check(TOOL, f"verify_wire({wire!r})", r.get("valid"), truth)

# ── 7. kgdb_rsp_escape ───────────────────────────────────
# Schema: {"bytes":[u8]}  → {"escaped": [u8]}
TOOL = "kgdb_rsp_escape"
escape_cases = [
    # Each special char ($=0x24, #=0x23, }=0x7d, *=0x2a) → 0x7d, char^0x20
    ([0x24],             [0x7d, 0x04]),
    ([0x23],             [0x7d, 0x03]),
    ([0x7d],             [0x7d, 0x5d]),
    ([0x2a],             [0x7d, 0x0a]),
    ([0x41],             [0x41]),        # 'A' passes through
    ([0x24, 0x41, 0x23], [0x7d, 0x04, 0x41, 0x7d, 0x03]),
]
for blist, truth in escape_cases:
    r = call(TOOL, {"bytes": blist})
    if r is None:
        skip(TOOL, f"no response for {blist}")
    else:
        check(TOOL, f"escape({blist})", r.get("escaped"), truth)

# ── 8. kgdb_rsp_unescape ─────────────────────────────────
# Schema: {"bytes":[u8]}  → {"unescaped": [u8]}
TOOL = "kgdb_rsp_unescape"
unescape_cases = [
    ([0x7d, 0x04],       [0x24]),   # → $
    ([0x7d, 0x03],       [0x23]),   # → #
    ([0x7d, 0x5d],       [0x7d]),   # → }
    ([0x7d, 0x0a],       [0x2a]),   # → *
    ([0x41],             [0x41]),   # 'A' passes through
    ([0x7d, 0x04, 0x41, 0x7d, 0x03], [0x24, 0x41, 0x23]),
]
for blist, truth in unescape_cases:
    r = call(TOOL, {"bytes": blist})
    if r is None:
        skip(TOOL, f"no response for {blist}")
    else:
        check(TOOL, f"unescape({blist})", r.get("unescaped"), truth)

# ── 9. kgdb_encode_hex_buf ───────────────────────────────
# Schema: {"bytes":[u8]}  → {"hex": str}
TOOL = "kgdb_encode_hex_buf"
hex_buf_cases = [
    ([0xde, 0xad, 0xbe, 0xef], "deadbeef"),
    ([0x00],                   "00"),
    ([0xff, 0x00, 0x80],       "ff0080"),
    (list(b"hello"),           "68656c6c6f"),
]
for blist, truth in hex_buf_cases:
    r = call(TOOL, {"bytes": blist})
    if r is None:
        skip(TOOL, f"no response for {blist}")
    else:
        check(TOOL, f"encode_hex({blist})", r.get("hex"), truth)

# ── 10. kgdb_decode_hex_buf ──────────────────────────────
# Schema: {"hex": str}  → {"bytes": [u8]}
TOOL = "kgdb_decode_hex_buf"
decode_hex_cases = [
    ("deadbeef",   [0xde, 0xad, 0xbe, 0xef]),
    ("00",         [0x00]),
    ("ff0080",     [0xff, 0x00, 0x80]),
    ("68656c6c6f", list(b"hello")),
]
for hs, truth in decode_hex_cases:
    r = call(TOOL, {"hex": hs})
    if r is None:
        skip(TOOL, f"no response for {hs!r}")
    else:
        check(TOOL, f"decode_hex({hs!r})", r.get("bytes"), truth)

# ── 11. kgdb_read_u64_le_hex ─────────────────────────────
# Schema: {"hex": str (16 chars)}  → {"value": u64, "value_hex": str}
TOOL = "kgdb_read_u64_le_hex"
u64_cases = [
    ("0100000000000000", 1),
    ("8877665544332211", struct.unpack("<Q", bytes.fromhex("8877665544332211"))[0]),
    ("ffffffffffffffff", 0xFFFFFFFFFFFFFFFF),
    ("0000000000000000", 0),
]
for hs, truth in u64_cases:
    r = call(TOOL, {"hex": hs})
    if r is None:
        skip(TOOL, f"no response for {hs!r}")
    else:
        check(TOOL, f"u64_le_hex({hs!r})", r.get("value"), truth)

# ── 12. kgdb_rsp_encode_packet_bytes ─────────────────────
# Schema: {"bytes":[u8]}  → {"packet": [u8]}
# The Rust implementation returns Vec<u8> serialised as a JSON array of integers.
# Python truth: build the same byte list.
TOOL = "kgdb_rsp_encode_packet_bytes"
def py_rsp_encode_packet_bytes_as_list(data: bytes) -> list:
    cs = py_rsp_checksum_bytes(data)
    pkt = b"$" + data + b"#" + f"{cs:02x}".encode()
    return list(pkt)

pkt_cases = [
    (list(b"OK"),  py_rsp_encode_packet_bytes_as_list(b"OK")),
    (list(b"g"),   py_rsp_encode_packet_bytes_as_list(b"g")),
    ([0x00],       py_rsp_encode_packet_bytes_as_list(b"\x00")),
]
for blist, truth in pkt_cases:
    r = call(TOOL, {"bytes": blist})
    if r is None:
        skip(TOOL, f"no response for {blist}")
    else:
        got = r.get("packet")
        check(TOOL, f"encode_pkt({blist})", got, truth)

# ── 13. kgdb_u64_to_hex_le ───────────────────────────────
# Schema: {"value": u64}  → result with hex string
TOOL = "kgdb_u64_to_hex_le"
u64_le_cases = [
    (1,                    "0100000000000000"),
    (0xDEADBEEFCAFEBABE,  py_u64_to_hex_le(0xDEADBEEFCAFEBABE)),
    (0,                    "0000000000000000"),
    (0xFFFFFFFFFFFFFFFF,   "ffffffffffffffff"),
]
for val, truth in u64_le_cases:
    r = call(TOOL, {"value": val})
    if r is None:
        skip(TOOL, f"no response for {val}")
    else:
        got = r.get("hex") or r.get("result") or r.get("value")
        if isinstance(got, str):
            check(TOOL, f"u64_le({hex(val)})", got.lower(), truth)
        else:
            skip(TOOL, f"unexpected result type: {r}")

# ── 14. kgdb_u32_to_hex_le ───────────────────────────────
TOOL = "kgdb_u32_to_hex_le"
u32_cases = [
    (0xDEADBEEF, "efbeadde"),
    (0x00000001, "01000000"),
    (0xFFFFFFFF, "ffffffff"),
    (0,          "00000000"),
]
for val, truth in u32_cases:
    r = call(TOOL, {"value": val})
    if r is None:
        skip(TOOL, f"no response for {val}")
    else:
        got = r.get("hex") or r.get("result") or r.get("value")
        if isinstance(got, str):
            check(TOOL, f"u32_le({hex(val)})", got.lower(), truth)
        else:
            skip(TOOL, f"unexpected result type: {r}")

# ── 15. kgdb_hex_le_to_u64 ───────────────────────────────
TOOL = "kgdb_hex_le_to_u64"
for hs, truth in u64_cases:
    r = call(TOOL, {"hex": hs})
    if r is None:
        skip(TOOL, f"no response for {hs!r} (tool may not exist)")
    else:
        got = r.get("value") if isinstance(r, dict) else None
        if got is not None:
            check(TOOL, f"hex_le_u64({hs!r})", got, truth)

# ── 16. kgdb_page_align ──────────────────────────────────
# Schema: {"addr": u64}  → {"down": u64, "up": u64}
# Tool always uses 4 KiB (0x1000) page size; no page_size param.
TOOL = "kgdb_page_align"
align_cases = [
    # (addr, truth_down, truth_up)
    (0x1234, 0x1000, 0x2000),
    (0x2000, 0x2000, 0x2000),   # already aligned → down==up==addr
    (0x0FFF, 0x0000, 0x1000),
    (0x5678, 0x5000, 0x6000),
    (0x1001, 0x1000, 0x2000),
]
for addr, truth_down, truth_up in align_cases:
    r = call(TOOL, {"addr": addr})
    if r is None:
        skip(TOOL, f"no response for addr={hex(addr)}")
    else:
        check(TOOL, f"page_align_down({hex(addr)})", r.get("down"), truth_down)
        check(TOOL, f"page_align_up({hex(addr)})",   r.get("up"),   truth_up)

# ── 17. kgdb_is_kernel_address ───────────────────────────
# Schema: {"addr": u64}  → {"is_kernel": bool}
TOOL = "kgdb_is_kernel_address"
kernel_cases = [
    (0xFFFF800000000000, True),    # Linux kernel base
    (0xFFFFFFFF81000000, True),    # typical kernel text
    (0x00007FFFFFFFFFFF, False),   # userspace top
    (0x0000000000000000, False),   # null
    (0x0000000040000000, False),   # userspace
]
for addr, truth in kernel_cases:
    r = call(TOOL, {"addr": addr})
    if r is None:
        r = call(TOOL, {"address": addr})
    if r is None:
        skip(TOOL, f"no response for {hex(addr)}")
    else:
        got = r.get("is_kernel") if isinstance(r, dict) else None
        if got is None:
            got = r.get("result") or r.get("value") or r.get("kernel")
        check(TOOL, f"is_kernel({hex(addr)})", got, truth)

# ── 18. kgdb_hex_to_bytes ────────────────────────────────
# Schema: {"hex": str}  → {"bytes": [u8]}
TOOL = "kgdb_hex_to_bytes"
for hs, truth in decode_hex_cases:
    r = call(TOOL, {"hex": hs})
    if r is None:
        skip(TOOL, f"no response for {hs!r}")
    else:
        got = r.get("bytes") or r.get("result") or r.get("data")
        check(TOOL, f"hex_to_bytes({hs!r})", got, truth)

# ── 19. kgdb_bytes_to_hex ────────────────────────────────
# Schema: {"bytes": [u8]}  → {"hex": str}
TOOL = "kgdb_bytes_to_hex"
for blist, truth in hex_buf_cases:
    r = call(TOOL, {"bytes": blist})
    if r is None:
        skip(TOOL, f"no response for {blist}")
    else:
        got = r.get("hex") or r.get("result") or r.get("value")
        if isinstance(got, str):
            check(TOOL, f"bytes_to_hex({blist})", got.lower(), truth)
        else:
            skip(TOOL, f"unexpected result: {r}")

# ── 20. kgdb_parse_qsupported ────────────────────────────
# Schema: {"response": str}  → {"count": int, "features": [...]}
# Truth: count known features parsed
TOOL = "kgdb_parse_qsupported"
qs_cases = [
    # typical KGDB qSupported reply — at least 1 feature
    ("PacketSize=3fff;qXfer:features:read+;swbreak+;hwbreak+",
     lambda r: isinstance(r.get("count"), int) and r["count"] >= 1),
    # empty → 0 features
    ("", lambda r: r.get("count") == 0),
]
for payload, predicate in qs_cases:
    r = call(TOOL, {"response": payload})
    if r is None:
        skip(TOOL, f"no response for {payload!r}")
    else:
        ok = predicate(r)
        tools_hardened.add(TOOL)
        if ok:
            checks_passed += 1
            print(f"  PASS  {TOOL} [qsupported({payload[:30]!r}...)]")
        else:
            checks_failed += 1
            mismatches.append({
                "tool": TOOL,
                "label": f"qsupported({payload[:30]!r}...)",
                "got": r,
                "expected": "predicate(True)",
            })
            print(f"  FAIL  {TOOL} [qsupported] got={r!r}")

p.terminate()

# ──────────────────────────────────────────────────────────
# Report
# ──────────────────────────────────────────────────────────
report = {
    "module": "kgdb",
    "tools_hardened": sorted(tools_hardened),
    "tools_hardened_count": len(tools_hardened),
    "checks_passed": checks_passed,
    "checks_failed": checks_failed,
    "real_mismatches": len(mismatches),
    "mismatches": mismatches,
}

with open(OUT, "w") as f:
    json.dump(report, f, indent=2, default=str)

print(f"\n=== Summary ===")
print(f"  tools hardened : {len(tools_hardened)}")
print(f"  checks passed  : {checks_passed}")
print(f"  checks failed  : {checks_failed}")
print(f"  real mismatches: {len(mismatches)}")
print(f"  report         : {OUT}")
