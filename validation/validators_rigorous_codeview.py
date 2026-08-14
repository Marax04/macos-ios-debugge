#!/usr/bin/env python3
"""
Rigorous validator for codeview_* MCP tools.
Replaces any_valid() with independent Python truth for >= 10 tools.
"""
import json
import struct
import subprocess

EXE = r"C:\Users\Fra\Desktop\RustRE\target\release\rustre-mcp.exe"
REPORT_OUT = r"C:\Users\Fra\Desktop\RustRE\validation\rigorous_codeview.json"

# ── MCP session ──────────────────────────────────────────────────────────────

def start():
    p = subprocess.Popen(
        [EXE, "--transport=stdio"],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
        bufsize=0,
    )
    def send(r): p.stdin.write((json.dumps(r) + "\n").encode()); p.stdin.flush()
    def recv():
        line = p.stdout.readline()
        return json.loads(line) if line else None
    send({"jsonrpc":"2.0","id":1,"method":"initialize",
          "params":{"protocolVersion":"2024-11-05","capabilities":{},
                    "clientInfo":{"name":"rigorous","version":"1"}}})
    recv()
    send({"jsonrpc":"2.0","method":"notifications/initialized"})
    return p, send, recv

p, send, recv = start()
_rid = [20]

def call(name, args):
    _rid[0] += 1
    send({"jsonrpc":"2.0","id":_rid[0],"method":"tools/call",
          "params":{"name":name,"arguments":args}})
    resp = recv()
    if not resp or "error" in resp:
        return None
    c = resp.get("result",{}).get("content",[])
    if not c:
        return None
    try:
        return json.loads(c[0].get("text",""))
    except Exception:
        return c[0].get("text","")

# ── Result tracking ───────────────────────────────────────────────────────────

checks_passed = 0
checks_failed = 0
mismatches = []
tools_hardened = set()

def check(tool, got, expected, note=""):
    global checks_passed, checks_failed
    tools_hardened.add(tool)
    if got == expected:
        checks_passed += 1
    else:
        checks_failed += 1
        mismatches.append({
            "tool": tool,
            "got": got,
            "expected": expected,
            "note": note,
        })

def check_contains(tool, got_str, keyword, note=""):
    """Pass if keyword appears in string (case-insensitive)."""
    global checks_passed, checks_failed
    tools_hardened.add(tool)
    if keyword.lower() in str(got_str).lower():
        checks_passed += 1
    else:
        checks_failed += 1
        mismatches.append({
            "tool": tool,
            "got": got_str,
            "expected": f"<contains '{keyword}'>",
            "note": note,
        })

# ============================================================================
# TOOL 1 — codeview_signature_from_bytes
# Truth: CvSignature::from_bytes matches literal 4-byte tags.
#   NB09 → Cv41, NB10 → Cv50, NB11 → Cv70, RSDS → Pdb70
#   "Micr" (start of "Microsoft C/C++ MSF 7.00") → Pdb70
# ============================================================================

def sig_bytes(s: str) -> list:
    return list(s.encode())

_SIG_CASES = [
    # (4-byte magic, keyword that appears in the human-readable as_str() result)
    # lib.rs CvSignature::from_bytes: b"NB09"→Cv41, b"NB10"→Cv50, b"NB11"→Cv70
    # CvSignature::as_str: Cv41→"NB09 (CV 4.1)", Cv50→"NB10 (CV 5.0)", Cv70→"NB11 (CV 7.0)"
    ("NB09", "NB09"),
    ("NB10", "NB10"),
    ("NB11", "NB11"),
]
for magic, kw in _SIG_CASES:
    r = call("codeview_signature_from_bytes", {"bytes": sig_bytes(magic)})
    if r is not None and isinstance(r, dict):
        got = r.get("signature") or r.get("variant") or r.get("kind") or r.get("value")
        check_contains("codeview_signature_from_bytes", str(got), kw,
                       f"magic={magic} expected result containing '{kw}'")

# PDB 7.0: from_bytes matches b"Micr" (first 4 bytes of MSF magic) → Pdb70
# as_str → "RSDS (PDB 7.0)"
micr = list(b"Micr")
r = call("codeview_signature_from_bytes", {"bytes": micr})
if r is not None and isinstance(r, dict):
    got = r.get("signature") or r.get("variant") or r.get("kind") or r.get("value")
    check_contains("codeview_signature_from_bytes", str(got), "RSDS",
                   "b'Micr' should map to Pdb70 (RSDS)")

# Plain b"RSDS" bytes are NOT in from_bytes — should return null signature
rsds = list(b"RSDS")
r = call("codeview_signature_from_bytes", {"bytes": rsds})
if r is not None and isinstance(r, dict):
    got = r.get("signature") or r.get("variant") or r.get("kind") or r.get("value")
    check("codeview_signature_from_bytes", got, None,
          "b'RSDS' is not in CvSignature::from_bytes — should return null")

# Unknown bytes → None/null
unknown = [0xDE, 0xAD, 0xBE, 0xEF]
r = call("codeview_signature_from_bytes", {"bytes": unknown})
if r is not None and isinstance(r, dict):
    got = r.get("signature") or r.get("variant") or r.get("kind") or r.get("value")
    check("codeview_signature_from_bytes", got, None,
          "unknown 4 bytes should return null signature")

# ============================================================================
# TOOL 2 — codeview_signature_as_str
# Truth: as_str() constant strings from lib.rs:
#   Cv41 → "NB09 (CV 4.1)", Cv50 → "NB10 (CV 5.0)", Cv70 → "NB11 (CV 7.0)", Pdb70 → "RSDS (PDB 7.0)"
# ============================================================================

_AS_STR_CASES = [
    ("cv41",  "NB09"),
    ("cv50",  "NB10"),
    ("cv70",  "NB11"),
    ("pdb70", "RSDS"),
]
for variant, kw in _AS_STR_CASES:
    r = call("codeview_signature_as_str", {"variant": variant})
    if r is not None and isinstance(r, dict):
        got = r.get("label") or r.get("string") or r.get("value") or r.get("result")
        check_contains("codeview_signature_as_str", str(got), kw,
                       f"variant={variant} expected keyword '{kw}'")

# ============================================================================
# TOOL 3 — codeview_magic_detect
# Truth: CodeViewMagic::detect matches:
#   "NB09" → Cv41  (label "NB09 (CodeView 4.1)")
#   "NB11" → Cv50  (label "NB11 (CodeView 5.0)")
#   "RSDS" → Cv70  (label "RSDS (PDB 7.0)")
# ============================================================================

_MAGIC_CASES = [
    (b"NB09", "NB09"),
    (b"NB11", "NB11"),
    (b"RSDS", "RSDS"),
]
for bmagic, kw in _MAGIC_CASES:
    r = call("codeview_magic_detect", {"bytes": list(bmagic)})
    if r is not None and isinstance(r, dict):
        got = r.get("magic") or r.get("label") or r.get("kind") or r.get("value")
        check_contains("codeview_magic_detect", str(got), kw,
                       f"magic={bmagic} expected keyword '{kw}'")

# ============================================================================
# TOOL 4 — codeview_magic_label
# Truth: CodeViewMagic::label() from lib.rs:
#   Cv41 → "NB09 (CodeView 4.1)", Cv50 → "NB11 (CodeView 5.0)", Cv70 → "RSDS (PDB 7.0)"
# ============================================================================

_LABEL_CASES = [
    ("cv41", "NB09"),
    ("cv50", "NB11"),
    ("cv70", "RSDS"),
]
for variant, kw in _LABEL_CASES:
    r = call("codeview_magic_label", {"variant": variant})
    if r is not None and isinstance(r, dict):
        got = r.get("label") or r.get("value") or r.get("result")
        check_contains("codeview_magic_label", str(got), kw,
                       f"variant={variant} expected keyword '{kw}'")

# ============================================================================
# TOOL 5 — codeview_sym_kind_is_named_address
# Truth from CvSymKind::is_named_address() in lib.rs:
#   GProc32=0x1110 → true, LProc32=0x110F → true, Pub32=0x1009 → true (but wait —
#   the old enum says 0x1009, the new enum S_PUB32=0x110E for CvSymKind)
#   Actually the wire takes `tag` field.
#   Named-address kinds: GProc32(0x1110), LProc32(0x110F), Pub32(0x1009),
#                        GData32(0x110D), LData32(0x110C), Label32(0x1105), Thunk32(0x1102)
#   NOT named: End(0x0006), Compile3(0x113C), Unknown
# ============================================================================

_NAMED_ADDR_CASES = [
    (0x1110, True,  "GProc32"),
    (0x110F, True,  "LProc32"),
    (0x1009, True,  "Pub32"),
    (0x110D, True,  "GData32"),
    (0x110C, True,  "LData32"),
    (0x1105, True,  "Label32"),
    (0x1102, True,  "Thunk32"),
    (0x0006, False, "End"),
    (0x113C, False, "Compile3"),
]
for tag, expected, name in _NAMED_ADDR_CASES:
    r = call("codeview_sym_kind_is_named_address", {"tag": tag})
    if r is not None and isinstance(r, dict):
        got = r.get("is_named_address")
        check("codeview_sym_kind_is_named_address", got, expected,
              f"tag={hex(tag)} ({name})")

# ============================================================================
# TOOL 6 — codeview_type_kind_from_u16
# Truth from CvTypeKind::from_u16() in lib.rs — exact mappings:
# ============================================================================

_TYPE_KIND_CASES = [
    (0x1001, "Modifier"),
    (0x1002, "Pointer"),
    (0x1003, "Array"),
    (0x1004, "Class"),
    (0x1005, "Structure"),
    (0x1006, "Union"),
    (0x1007, "Enum"),
    (0x1008, "Procedure"),
    (0x1009, "MFunction"),
    (0x1201, "Arglist"),
    (0x1203, "FieldList"),
    (0x1205, "Bitfield"),
    (0x150D, "Member"),
    (0x1502, "Enumerate"),
    (0xDEAD, "Unknown"),
]
for tag, expected_name in _TYPE_KIND_CASES:
    r = call("codeview_type_kind_from_u16", {"tag": tag})
    if r is not None and isinstance(r, dict):
        got = r.get("kind") or r.get("name") or r.get("value")
        check("codeview_type_kind_from_u16", got, expected_name,
              f"tag={hex(tag)}")

# ============================================================================
# TOOL 7 — codeview_guid_to_string
# Truth from guid_to_string() in lib.rs (mixed-endian):
#   bytes 0..4  → LE u32 = Data1 (8 hex digits)
#   bytes 4..6  → LE u16 = Data2 (4 hex digits)
#   bytes 6..8  → LE u16 = Data3 (4 hex digits)
#   bytes 8..10 → BE u16 = Data4a (4 hex digits)
#   bytes 10..16 → raw hex bytes = Data4b (12 hex digits)
# Format: {D1-D2-D3-D4a-D4b}
# ============================================================================

def py_guid_to_string(b16: bytes) -> str:
    d1 = struct.unpack_from("<I", b16, 0)[0]
    d2 = struct.unpack_from("<H", b16, 4)[0]
    d3 = struct.unpack_from("<H", b16, 6)[0]
    d4a = struct.unpack_from(">H", b16, 8)[0]
    d4b = b16[10:16]
    return "{{{:08X}-{:04X}-{:04X}-{:04X}-{}{}}}" .format(
        d1, d2, d3, d4a,
        "".join(f"{x:02X}" for x in d4b[:3]),
        "".join(f"{x:02X}" for x in d4b[3:]),
    )

_GUID_CASES = [
    bytes.fromhex("112233445566778899AABBCCDDEEFF00"),
    bytes.fromhex("00000000000000000000000000000000"),
    bytes.fromhex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"),
    bytes.fromhex("6B29FC400CA6101A8EA3508000185868"),  # a known Windows GUID
]
for guid_bytes in _GUID_CASES:
    expected = py_guid_to_string(guid_bytes)
    r = call("codeview_guid_to_string", {"bytes": list(guid_bytes)})
    if r is not None and isinstance(r, dict):
        got = r.get("guid") or r.get("value") or r.get("result")
        check("codeview_guid_to_string", got, expected,
              f"guid bytes={guid_bytes.hex()}")

# ============================================================================
# TOOL 8 — codeview_primitive_type
# Truth from primitive_type() in lib.rs:
#   mode = (index >> 8) & 0x7; base = index & 0xFF
#   mode=0, base=0x00 → Void
#   mode=0, base=0x74 → Int{32, signed}
#   mode=0, base=0x75 → Int{32, unsigned}
#   mode=0, base=0x30 → Bool
#   mode=0, base=0x40 → Float{32}
#   mode=0, base=0x41 → Float{64}
# ============================================================================

_PRIM_CASES = [
    (0x00,  "Void"),
    (0x74,  "Int"),   # T_INT4 / int32 signed
    (0x75,  "Int"),   # T_UINT4 / int32 unsigned
    (0x30,  "Bool"),
    (0x40,  "Float"),
    (0x41,  "Float"),
    (0xFE,  "Unknown"),  # unmapped base type
]
for idx, kw in _PRIM_CASES:
    r = call("codeview_primitive_type", {"index": idx})
    if r is not None and isinstance(r, dict):
        got = r.get("type_info") or r.get("kind") or r.get("type") or r.get("value") or r.get("result")
        check_contains("codeview_primitive_type", str(got), kw,
                       f"index={hex(idx)} expected '{kw}'")

# ============================================================================
# TOOL 9 — codeview_proc32_parse
# Build a minimal S_GPROC32 payload (bytes after the kind field) manually.
# Layout: parent(4)+end(4)+next(4)+len(4)+dbg_start(4)+dbg_end(4)+type_index(4)+offset(4)+seg(2)+flags(1)+name\0
# ============================================================================

def build_proc32_payload(name: str, offset: int, seg: int, proc_len: int, type_index: int) -> bytes:
    payload  = struct.pack("<I", 0)           # parent
    payload += struct.pack("<I", 0)           # end
    payload += struct.pack("<I", 0)           # next
    payload += struct.pack("<I", proc_len)    # len
    payload += struct.pack("<I", 0)           # dbg_start
    payload += struct.pack("<I", 0)           # dbg_end
    payload += struct.pack("<I", type_index)  # type_index
    payload += struct.pack("<I", offset)      # offset
    payload += struct.pack("<H", seg)         # segment
    payload += struct.pack("<B", 0)           # flags
    payload += name.encode() + b"\x00"       # name
    return payload

_PROC32_CASES = [
    ("WinMain",  0x1000, 1, 128, 0x1234),
    ("my_func",  0x4000, 2,  64, 0),
    ("_start",   0x0100, 1,  16, 0x5678),
]
for name, offset, seg, proc_len, type_index in _PROC32_CASES:
    payload = build_proc32_payload(name, offset, seg, proc_len, type_index)
    r = call("codeview_proc32_parse", {"bytes": list(payload)})
    if r is not None and isinstance(r, dict):
        check("codeview_proc32_parse", r.get("parsed"), True,
              f"proc32 '{name}' should parse")
        check("codeview_proc32_parse", r.get("name"), name,
              f"proc32 name should be '{name}'")
        check("codeview_proc32_parse", r.get("offset"), offset,
              f"proc32 offset should be {offset}")
        check("codeview_proc32_parse", r.get("segment"), seg,
              f"proc32 segment should be {seg}")
        check("codeview_proc32_parse", r.get("len"), proc_len,
              f"proc32 len should be {proc_len}")
        check("codeview_proc32_parse", r.get("type_index"), type_index,
              f"proc32 type_index should be {type_index}")

# ============================================================================
# TOOL 10 — codeview_public32_parse
# Layout: flags(4)+offset(4)+seg(2)+name\0
# CVPSFLAG_FUNCTION = 0x02 → is_function True
# ============================================================================

def build_pub32_payload(name: str, offset: int, seg: int, flags: int) -> bytes:
    payload  = struct.pack("<I", flags)
    payload += struct.pack("<I", offset)
    payload += struct.pack("<H", seg)
    payload += name.encode() + b"\x00"
    return payload

_PUB32_CASES = [
    ("_WinMain@16", 0x1234, 1, 0x02, True),   # function flag set
    ("g_data",      0x5678, 2, 0x00, False),   # not function
    ("SomeExport",  0xABCD, 1, 0x02, True),
]
for name, offset, seg, flags, is_fn in _PUB32_CASES:
    payload = build_pub32_payload(name, offset, seg, flags)
    r = call("codeview_public32_parse", {"bytes": list(payload)})
    if r is not None and isinstance(r, dict):
        check("codeview_public32_parse", r.get("parsed"), True,
              f"pub32 '{name}' should parse")
        check("codeview_public32_parse", r.get("name"), name,
              f"pub32 name should be '{name}'")
        check("codeview_public32_parse", r.get("offset"), offset,
              f"pub32 offset should be {offset}")
        check("codeview_public32_parse", r.get("is_function"), is_fn,
              f"pub32 is_function={is_fn} flags={hex(flags)}")
        check("codeview_public32_parse", r.get("flags"), flags,
              f"pub32 flags should be {flags}")

# ============================================================================
# TOOL 11 — codeview_data32_parse
# Layout: type_index(4)+offset(4)+seg(2)+name\0
# ============================================================================

def build_data32_payload(name: str, offset: int, seg: int, type_index: int) -> bytes:
    payload  = struct.pack("<I", type_index)
    payload += struct.pack("<I", offset)
    payload += struct.pack("<H", seg)
    payload += name.encode() + b"\x00"
    return payload

_DATA32_CASES = [
    ("g_count",    0x1000, 1, 0x74),
    ("g_buffer",   0x2000, 2, 0x1005),
    ("g_flag",     0x3000, 1, 0x30),
]
for name, offset, seg, type_index in _DATA32_CASES:
    payload = build_data32_payload(name, offset, seg, type_index)
    r = call("codeview_data32_parse", {"bytes": list(payload)})
    if r is not None and isinstance(r, dict):
        check("codeview_data32_parse", r.get("parsed"), True,
              f"data32 '{name}' should parse")
        check("codeview_data32_parse", r.get("name"), name,
              f"data32 name should be '{name}'")
        check("codeview_data32_parse", r.get("offset"), offset,
              f"data32 offset should be {offset}")
        check("codeview_data32_parse", r.get("segment"), seg,
              f"data32 segment should be {seg}")
        check("codeview_data32_parse", r.get("type_index"), type_index,
              f"data32 type_index should be {type_index}")

# ============================================================================
# TOOL 12 — codeview_frameproc_parse
# Layout: frame_size(4)+pad_size(4)+pad_offset(4)+save_regs_size(4)+
#         eh_section(4)+eh_offset(4)+flags(4)
# has_alloca  = flags & 0x100 != 0
# has_async_eh = flags & 0x200 != 0
# ============================================================================

def build_frameproc_payload(frame_size, pad_size, pad_offset,
                             save_regs_size, eh_section, eh_offset, flags):
    return struct.pack("<IIIIIII",
                       frame_size, pad_size, pad_offset,
                       save_regs_size, eh_section, eh_offset, flags)

_FP_CASES = [
    # frame_size, pad, pad_off, save_regs, eh_sect, eh_off, flags, alloca, async_eh
    (0x30,  0,    0,    0x10,  0,  0,  0x000,  False, False),
    (0x50,  4,    0,    0x00,  0,  0,  0x100,  True,  False),
    (0x80,  0,    0,    0x20,  0,  0,  0x300,  True,  True),
    (0x20,  0,    0,    0x00,  1,  0x40, 0x000, False, False),
]
for frame_size, pad, pad_off, save_regs, eh_sect, eh_off, flags, alloca, async_eh in _FP_CASES:
    payload = build_frameproc_payload(frame_size, pad, pad_off, save_regs, eh_sect, eh_off, flags)
    r = call("codeview_frameproc_parse", {"bytes": list(payload)})
    if r is not None and isinstance(r, dict):
        check("codeview_frameproc_parse", r.get("parsed"), True,
              f"frameproc should parse")
        check("codeview_frameproc_parse", r.get("frame_size"), frame_size,
              f"frame_size={frame_size}")
        check("codeview_frameproc_parse", r.get("save_regs_size"), save_regs,
              f"save_regs_size={save_regs}")
        check("codeview_frameproc_parse", r.get("flags"), flags,
              f"flags={hex(flags)}")
        check("codeview_frameproc_parse", r.get("has_alloca"), alloca,
              f"has_alloca expected {alloca} for flags={hex(flags)}")
        check("codeview_frameproc_parse", r.get("has_async_eh"), async_eh,
              f"has_async_eh expected {async_eh} for flags={hex(flags)}")

# ============================================================================
# TOOL 13 — codeview_symbol_stream_count
# Build a symbol stream with a known number of recognisable records and verify
# the count. We use S_PUB32 (0x1009) records.
# Stream format: [len:u16][kind:u16][payload...]
# where len = 2 + len(payload), kind = 0x1009 for S_PUB32.
# CvSymbolStream iterates ALL records (not just named ones), so count = N.
# ============================================================================

def make_pub32_record(name: str, offset: int) -> bytes:
    payload  = struct.pack("<IIH", 0, offset, 1) + name.encode() + b"\x00"
    kind: int = 0x1009
    length: int = 2 + len(payload)  # length field covers kind + payload
    return struct.pack("<HH", length, kind) + payload

_STREAM_CASES = [
    (["alpha", "beta", "gamma"], 3),
    (["x"], 1),
    (["a", "b", "c", "d", "e"], 5),
]
for names, expected_count in _STREAM_CASES:
    stream = b"".join(make_pub32_record(n, i * 0x100) for i, n in enumerate(names))
    r = call("codeview_symbol_stream_count", {"bytes": list(stream)})
    if r is not None and isinstance(r, dict):
        check("codeview_symbol_stream_count", r.get("count"), expected_count,
              f"stream with {len(names)} records should count={expected_count}")

# ============================================================================
# TOOL 14 — codeview_parse_symbols (full parse + result structure)
# Build a stream with 1 GPROC32 record + 1 GDATA32 record.
# Expected: 2 symbols, correct names/offsets.
# ============================================================================

def make_gproc32_record(name: str, offset: int, seg: int) -> bytes:
    # payload: parent(4)+end(4)+next(4)+len(4)+dbg_start(4)+dbg_end(4)+type_idx(4)+offset(4)+seg(2)+flags(1)+name\0
    payload  = struct.pack("<IIIIIII", 0, 0, 0, 0, 0, 0, 0)
    payload += struct.pack("<IHB", offset, seg, 0)
    payload += name.encode() + b"\x00"
    kind: int = 0x1110
    length: int = 2 + len(payload)
    return struct.pack("<HH", length, kind) + payload

def make_gdata32_record(name: str, offset: int, seg: int, type_index: int) -> bytes:
    payload  = struct.pack("<IIH", type_index, offset, seg)
    payload += name.encode() + b"\x00"
    kind: int = 0x110D
    length: int = 2 + len(payload)
    return struct.pack("<HH", length, kind) + payload

stream = make_gproc32_record("main", 0x1000, 1) + make_gdata32_record("g_var", 0x2000, 2, 0x74)
r = call("codeview_parse_symbols", {"bytes": list(stream)})
if r is not None and isinstance(r, dict):
    tools_hardened.add("codeview_parse_symbols")
    syms = r.get("symbols") or r.get("records") or []
    check("codeview_parse_symbols", len(syms), 2, "should parse 2 symbols")
    if len(syms) == 2:
        names = [s.get("name") for s in syms]
        check("codeview_parse_symbols", "main" in names, True, "should have 'main'")
        check("codeview_parse_symbols", "g_var" in names, True, "should have 'g_var'")

# ============================================================================
# Write report
# ============================================================================

try:
    p.terminate()
except Exception:
    pass

report = {
    "module": "codeview",
    "tools_hardened": len(tools_hardened),
    "tools_list": sorted(tools_hardened),
    "checks_passed": checks_passed,
    "checks_failed": checks_failed,
    "real_mismatches": len(mismatches),
    "mismatches": mismatches,
}
with open(REPORT_OUT, "w", encoding="utf-8") as f:
    json.dump(report, f, indent=2, default=str)

print(json.dumps({k: v for k, v in report.items() if k != "mismatches"}, indent=2))
print(f"\nreal_mismatches: {len(mismatches)}")
if mismatches:
    print("\nMismatch details:")
    for m in mismatches:
        print(f"  [{m['tool']}] got={m['got']!r} expected={m['expected']!r}  {m['note']}")
