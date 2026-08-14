#!/usr/bin/env python3
"""
Rigorous ground-truth validation for gdb_* MCP tools.
Each check calls the MCP server and compares against an independent Python reference.
"""
import json, subprocess, sys, xml.etree.ElementTree as ET

EXE = r"C:\Users\Fra\Desktop\RustRE\target\release\rustre-mcp.exe"
TARGET = r"C:\Users\Fra\Desktop\Zyphora\target\release\cargo-zyphora.exe"
OUT_JSON = r"C:\Users\Fra\Desktop\RustRE\validation\rigorous_gdb_v2.json"
SKIP_JSON = r"C:\Users\Fra\Desktop\RustRE\validation\skip_gdb.json"

# ── MCP subprocess ────────────────────────────────────────────────────────────
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
        return {"error": {"message": f"bad-line: {line[:120]!r}"}}

# Initialise MCP
send({"jsonrpc":"2.0","id":1,"method":"initialize","params":{
    "protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"rigorous_gdb_v2","version":"1"}}})
recv()
send({"jsonrpc":"2.0","method":"notifications/initialized"})

# Open project (required for server initialisation)
send({"jsonrpc":"2.0","id":2,"method":"tools/call","params":{
    "name":"project.open","arguments":{"path":TARGET}}})
recv()

_rid = 100
def call_tool(mcp_name, args):
    """Call an MCP tool by its true MCP name (not the display label)."""
    global _rid
    _rid += 1
    send({"jsonrpc":"2.0","id":_rid,"method":"tools/call","params":{"name":mcp_name,"arguments":args}})
    resp = recv()
    if "error" in resp:
        return None, f"JSONRPC_ERROR: {resp['error']}"
    content = resp.get("result",{}).get("content",[])
    txt = content[0].get("text","") if content else ""
    if resp.get("result",{}).get("isError"):
        return None, f"TOOL_ERROR: {txt}"
    try:
        return json.loads(txt), None
    except Exception as e:
        return None, f"JSON_PARSE_ERROR: {e}: {txt[:120]}"

# ── Python reference helpers ──────────────────────────────────────────────────

def ref_checksum(data: bytes) -> int:
    return sum(data) & 0xFF

def ref_checksum_hex(data: bytes) -> str:
    return f"{ref_checksum(data):02x}"

def ref_escape(data: bytes) -> bytes:
    out = bytearray()
    for b in data:
        if b in (ord('#'), ord('$'), ord('}'), ord('*')):
            out.append(ord('}'))
            out.append(b ^ 0x20)
        else:
            out.append(b)
    return bytes(out)

def ref_unescape(data: bytes) -> bytes:
    out = bytearray()
    i = 0
    while i < len(data):
        if data[i] == ord('}') and i + 1 < len(data):
            out.append(data[i+1] ^ 0x20)
            i += 2
        else:
            out.append(data[i])
            i += 1
    return bytes(out)

def ref_encode_packet(payload: str) -> str:
    escaped = ref_escape(payload.encode('latin-1'))
    cs = ref_checksum_hex(escaped)
    return f"${escaped.decode('latin-1')}#{cs}"

def fromhex(s: str) -> bytes:
    return bytes.fromhex(s)

def ref_memory_read_cmd(addr: int, length: int) -> str:
    return f"m{addr:x},{length:x}"

def ref_memory_write_cmd(addr: int, data: bytes) -> str:
    hex_data = data.hex()
    return f"M{addr:x},{len(data):x}:{hex_data}"

def ref_bp_sw_cmd(addr: int):
    return f"Z0,{addr:x},1", f"z0,{addr:x},1"

def ref_bp_hw_cmd(addr: int):
    return f"Z1,{addr:x},1", f"z1,{addr:x},1"

def ref_watchpoint_cmd(addr: int, length: int, kind: str):
    code_map = {"write": 2, "read": 3, "readwrite": 4, "rw": 4}
    code = code_map.get(kind, 2)
    return f"Z{code},{addr:x},{length}", f"z{code},{addr:x},{length}"

def ref_register_def_byte_size(bitsize: int) -> int:
    return (bitsize + 7) // 8

def ref_stub_ok_packet() -> str:
    payload = "OK"
    cs = ref_checksum_hex(payload.encode())
    return f"${payload}#{cs}"

def ref_stub_error_packet(code: int) -> str:
    payload = f"E{code:02x}"
    cs = ref_checksum_hex(payload.encode())
    return f"${payload}#{cs}"

def ref_stub_empty_packet() -> str:
    return "$#00"

def ref_step_range_packet(start: int, end: int, tid=None) -> str:
    base = f"vCont;r{start:x},{end:x}"
    if tid is not None:
        base += f":{tid:x}"
    return base

def ref_memory_write_binary_cmd(addr: int, data: bytes) -> bytes:
    header = f"X{addr:x},{len(data):x}:".encode()
    payload = bytearray()
    for b in data:
        if b in (ord('#'), ord('$'), ord('}'), ord('*')):
            payload.append(ord('}'))
            payload.append(b ^ 0x20)
        else:
            payload.append(b)
    return header + bytes(payload)

def parse_target_xml_simple(xml_str: str):
    root = ET.fromstring(xml_str)
    def tag(e):
        t = e.tag
        return t.split('}', 1)[1] if '}' in t else t

    arch = None
    for child in root:
        if tag(child) == 'architecture':
            arch = child.text
            break

    regs = []
    regnum_counter = [0]
    def walk(node):
        for child in node:
            t = tag(child)
            if t == 'reg':
                name = child.get('name', '')
                bitsize = int(child.get('bitsize', '32'))
                rtype = child.get('type', 'int')
                group = child.get('group')
                regnum_attr = child.get('regnum')
                if regnum_attr is not None:
                    regnum_counter[0] = int(regnum_attr)
                rn = regnum_counter[0]
                regnum_counter[0] += 1
                regs.append({'name': name, 'bitsize': bitsize,
                             'type': rtype, 'group': group, 'regnum': rn})
            elif t in ('feature', 'target'):
                walk(child)
    walk(root)
    return arch, regs

# ── Test inputs ───────────────────────────────────────────────────────────────
TEST_HEX = "deadbeef00112233"
TEST_BYTES = fromhex(TEST_HEX)
TEST_ADDR = 5368771180
TEST_END  = 5368771260
TEST_LEN  = 16
TEST_PAYLOAD = "QStartNoAckMode"

SIMPLE_XML = (
    '<?xml version="1.0"?>'
    '<!DOCTYPE target SYSTEM "gdb-target.dtd">'
    '<target version="1.0">'
    '<architecture>i386:x86-64</architecture>'
    '<feature name="org.gnu.gdb.i386.core">'
    '<reg name="rax" bitsize="64" type="int"/>'
    '<reg name="rbx" bitsize="64" type="int"/>'
    '<reg name="rcx" bitsize="64" type="int"/>'
    '</feature>'
    '</target>'
)

results = []
mismatches = []
skipped = []

def lc(v):
    """Normalize a hex string to lowercase for comparison."""
    if isinstance(v, str):
        return v.lower()
    return v

def check(label, mcp_name, args, expected_fn, compare_fn):
    """Call tool by mcp_name, compute expected, compare. label is for reporting."""
    actual, err = call_tool(mcp_name, args)
    if err:
        results.append({"tool": label, "status": "TOOL_ERROR", "error": err})
        mismatches.append({"tool": label, "expected": "no error", "actual": err})
        return
    try:
        expected = expected_fn()
    except Exception as e:
        results.append({"tool": label, "status": "REF_ERROR", "error": str(e)})
        return
    ok, detail = compare_fn(actual, expected)
    if ok:
        results.append({"tool": label, "status": "PASS"})
    else:
        results.append({"tool": label, "status": "FAIL", "detail": detail,
                        "actual": actual, "expected": expected})
        mismatches.append({"tool": label, "expected": str(expected)[:300], "actual": str(actual)[:300]})

def skip(label, reason):
    skipped.append({"tool": label, "reason": reason})
    results.append({"tool": label, "status": "SKIP", "reason": reason})

# ── Checks ────────────────────────────────────────────────────────────────────

# 1. gdb_packet_checksum
check(
    "gdb_packet_checksum",
    "gdb_packet_checksum",
    {"hex": TEST_HEX},
    lambda: {"checksum": ref_checksum(TEST_BYTES), "checksum_hex": ref_checksum_hex(TEST_BYTES)},
    lambda a, e: (
        a.get("checksum") == e["checksum"] and lc(a.get("checksum_hex")) == e["checksum_hex"],
        f"checksum {a.get('checksum')} vs {e['checksum']}, hex {a.get('checksum_hex')} vs {e['checksum_hex']}"
    )
)

# 2. gdb_packet_encode
expected_encoded = ref_encode_packet(TEST_PAYLOAD)
check(
    "gdb_packet_encode",
    "gdb_packet_encode",
    {"data": TEST_PAYLOAD},
    lambda: expected_encoded,
    lambda a, e: (a.get("encoded") == e, f"{a.get('encoded')!r} != {e!r}")
)

# 3. gdb_packet_decode
check(
    "gdb_packet_decode",
    "gdb_packet_decode",
    {"raw": expected_encoded},
    lambda: TEST_PAYLOAD,
    lambda a, e: (a.get("ok") == True and a.get("data") == e, f"ok={a.get('ok')} data={a.get('data')!r} vs {e!r}")
)

# 4. gdb_packet_escape_data — bytes with special chars: "#$}*" = 0x23 0x24 0x7d 0x2a
SPECIAL_HEX = "23247d2a"
SPECIAL_BYTES = fromhex(SPECIAL_HEX)
expected_escaped_hex = ref_escape(SPECIAL_BYTES).hex()
check(
    "gdb_packet_escape_data",
    "gdb_packet_escape_data",
    {"hex": SPECIAL_HEX},
    lambda: expected_escaped_hex,
    lambda a, e: (lc(a.get("escaped_hex")) == e, f"{a.get('escaped_hex')!r} != {e!r}")
)

# 5. gdb_packet_unescape_data
ESCAPED_STR = "}" + chr(0x23 ^ 0x20) + "}" + chr(0x7d ^ 0x20)  # escapes for # and }
expected_unescaped_hex = ref_unescape(ESCAPED_STR.encode('latin-1')).hex()
check(
    "gdb_packet_unescape_data",
    "gdb_packet_unescape_data",
    {"data": ESCAPED_STR},
    lambda: expected_unescaped_hex,
    lambda a, e: (lc(a.get("unescaped_hex")) == e, f"{a.get('unescaped_hex')!r} != {e!r}")
)

# 6. gdb_memory_read_cmd
check(
    "gdb_memory_read_cmd",
    "gdb_memory_read_cmd",
    {"addr": TEST_ADDR, "len": TEST_LEN},
    lambda: ref_memory_read_cmd(TEST_ADDR, TEST_LEN),
    lambda a, e: (a.get("command") == e, f"{a.get('command')!r} != {e!r}")
)

# 7. gdb_memory_write_cmd
check(
    "gdb_memory_write_cmd",
    "gdb_memory_write_cmd",
    {"addr": TEST_ADDR, "hex": TEST_HEX},
    lambda: ref_memory_write_cmd(TEST_ADDR, TEST_BYTES),
    lambda a, e: (a.get("command") == e, f"{a.get('command')!r} != {e!r}")
)

# 8. gdb_breakpoint_sw_cmd
check(
    "gdb_breakpoint_sw_cmd",
    "gdb_breakpoint_sw_cmd",
    {"addr": TEST_ADDR},
    lambda: ref_bp_sw_cmd(TEST_ADDR),
    lambda a, e: (
        a.get("insert") == e[0] and a.get("remove") == e[1],
        f"insert {a.get('insert')!r} vs {e[0]!r}; remove {a.get('remove')!r} vs {e[1]!r}"
    )
)

# 9. gdb_breakpoint_hw_cmd
check(
    "gdb_breakpoint_hw_cmd",
    "gdb_breakpoint_hw_cmd",
    {"addr": TEST_ADDR},
    lambda: ref_bp_hw_cmd(TEST_ADDR),
    lambda a, e: (
        a.get("insert") == e[0] and a.get("remove") == e[1],
        f"insert {a.get('insert')!r} vs {e[0]!r}; remove {a.get('remove')!r} vs {e[1]!r}"
    )
)

# 10. gdb_watchpoint_cmd — write watchpoint
check(
    "gdb_watchpoint_cmd_write",
    "gdb_watchpoint_cmd",
    {"addr": TEST_ADDR, "len": 8, "kind": "write"},
    lambda: ref_watchpoint_cmd(TEST_ADDR, 8, "write"),
    lambda a, e: (
        a.get("insert") == e[0] and a.get("remove") == e[1],
        f"insert {a.get('insert')!r} vs {e[0]!r}; remove {a.get('remove')!r} vs {e[1]!r}"
    )
)

# 11. gdb_watchpoint_cmd — read watchpoint
check(
    "gdb_watchpoint_cmd_read",
    "gdb_watchpoint_cmd",
    {"addr": TEST_ADDR, "len": 4, "kind": "read"},
    lambda: ref_watchpoint_cmd(TEST_ADDR, 4, "read"),
    lambda a, e: (
        a.get("insert") == e[0] and a.get("remove") == e[1],
        f"insert {a.get('insert')!r} vs {e[0]!r}; remove {a.get('remove')!r} vs {e[1]!r}"
    )
)

# 12. gdb_register_def_byte_size — multiple bit widths
for bits, expected_bs in [(8, 1), (32, 4), (64, 8), (80, 10), (128, 16), (1, 1), (33, 5)]:
    check(
        f"gdb_register_def_byte_size_bits{bits}",
        "gdb_register_def_byte_size",
        {"bitsize": bits},
        lambda b=bits: ref_register_def_byte_size(b),
        lambda a, e: (a.get("byte_size") == e, f"{a.get('byte_size')} != {e}")
    )

# 13. gdb_stub_ok_packet
check(
    "gdb_stub_ok_packet",
    "gdb_stub_ok_packet",
    {},
    ref_stub_ok_packet,
    lambda a, e: (a.get("packet") == e, f"{a.get('packet')!r} != {e!r}")
)

# 14. gdb_stub_error_packet — multiple codes
for code in [0, 1, 5, 127, 255]:
    check(
        f"gdb_stub_error_packet_code{code}",
        "gdb_stub_error_packet",
        {"code": code},
        lambda c=code: ref_stub_error_packet(c),
        lambda a, e: (a.get("packet") == e, f"{a.get('packet')!r} != {e!r}")
    )

# 15. gdb_stub_empty_packet
check(
    "gdb_stub_empty_packet",
    "gdb_stub_empty_packet",
    {},
    ref_stub_empty_packet,
    lambda a, e: (a.get("packet") == e, f"{a.get('packet')!r} != {e!r}")
)

# 16. gdb_step_range_packet (no tid)
check(
    "gdb_step_range_packet_no_tid",
    "gdb_step_range_packet",
    {"start": TEST_ADDR, "end": TEST_END},
    lambda: ref_step_range_packet(TEST_ADDR, TEST_END),
    lambda a, e: (a.get("packet") == e, f"{a.get('packet')!r} != {e!r}")
)

# 17. gdb_step_range_packet (with tid)
check(
    "gdb_step_range_packet_tid1",
    "gdb_step_range_packet",
    {"start": TEST_ADDR, "end": TEST_END, "thread": 1},
    lambda: ref_step_range_packet(TEST_ADDR, TEST_END, tid=1),
    lambda a, e: (a.get("packet") == e, f"{a.get('packet')!r} != {e!r}")
)

# 18. gdb_memory_read_response_parse
PLAIN_HEX = "deadbeef00112233"
check(
    "gdb_memory_read_response_parse",
    "gdb_memory_read_response_parse",
    {"hex": PLAIN_HEX},
    lambda: (len(fromhex(PLAIN_HEX)), PLAIN_HEX),
    lambda a, e: (
        a.get("bytes") == e[0] and lc(a.get("hex")) == e[1],
        f"bytes={a.get('bytes')} vs {e[0]}; hex={a.get('hex')!r} vs {e[1]!r}"
    )
)

# 19. gdb_memory_write_binary_cmd — data with special chars
BINARY_DATA = bytes([0x00, 0x23, 0x41, 0x7d, 0x24, 0xff])
BINARY_HEX = BINARY_DATA.hex()
exp_bin_cmd_hex = ref_memory_write_binary_cmd(TEST_ADDR, BINARY_DATA).hex()
check(
    "gdb_memory_write_binary_cmd",
    "gdb_memory_write_binary_cmd",
    {"addr": TEST_ADDR, "hex": BINARY_HEX},
    lambda: exp_bin_cmd_hex,
    lambda a, e: (lc(a.get("command_hex")) == e, f"{a.get('command_hex')!r} != {e!r}")
)

# 20. gdb_target_xml_parse — structural check
exp_arch, exp_regs = parse_target_xml_simple(SIMPLE_XML)
check(
    "gdb_target_xml_parse",
    "gdb_target_xml_parse",
    {"xml": SIMPLE_XML},
    lambda: (exp_arch, len(exp_regs)),
    lambda a, e: (
        a.get("ok") == True and
        a.get("architecture") == e[0] and
        a.get("register_count") == e[1],
        f"ok={a.get('ok')} arch={a.get('architecture')!r} vs {e[0]!r} count={a.get('register_count')} vs {e[1]}"
    )
)

# 21. gdb_target_xml_total_bytes
exp_total = sum(ref_register_def_byte_size(r['bitsize']) for r in exp_regs)
check(
    "gdb_target_xml_total_bytes",
    "gdb_target_xml_total_bytes",
    {"xml": SIMPLE_XML},
    lambda: exp_total,
    lambda a, e: (a.get("total_bytes") == e, f"{a.get('total_bytes')} != {e}")
)

# 22. gdb_target_xml_register_by_name — look up "rax"
exp_rax = next(r for r in exp_regs if r['name'] == 'rax')
check(
    "gdb_target_xml_register_by_name_rax",
    "gdb_target_xml_register_by_name",
    {"xml": SIMPLE_XML, "name": "rax"},
    lambda: exp_rax,
    lambda a, e: (
        a.get("found") == True and
        a.get("name") == e['name'] and
        a.get("bitsize") == e['bitsize'],
        f"found={a.get('found')} name={a.get('name')!r} bitsize={a.get('bitsize')} vs {e}"
    )
)

# 23. gdb_target_xml_register_by_name — missing register
check(
    "gdb_target_xml_register_by_name_missing",
    "gdb_target_xml_register_by_name",
    {"xml": SIMPLE_XML, "name": "xyz_no_such"},
    lambda: False,
    lambda a, e: (a.get("found") == e, f"found={a.get('found')} != {e}")
)

# 24. gdb_target_xml_register_by_num — register 1 = "rbx"
exp_rbx = next(r for r in exp_regs if r['name'] == 'rbx')
check(
    "gdb_target_xml_register_by_num_1",
    "gdb_target_xml_register_by_num",
    {"xml": SIMPLE_XML, "regnum": 1},
    lambda: exp_rbx,
    lambda a, e: (
        a.get("found") == True and
        a.get("name") == e['name'] and
        a.get("bitsize") == e['bitsize'],
        f"found={a.get('found')} name={a.get('name')!r} bitsize={a.get('bitsize')} vs {e}"
    )
)

# 25. gdb_register_codec_encode_p
def ref_encode_p(regnum: int, value: int, byte_size: int) -> str:
    val_le = value.to_bytes(byte_size, 'little')
    return f"P{regnum:x}={val_le.hex()}"

expected_p_cmd = ref_encode_p(0, 0xdeadbeef, 8)
check(
    "gdb_register_codec_encode_p_rax",
    "gdb_register_codec_encode_p",
    {"xml": SIMPLE_XML, "regnum": 0, "value": 0xdeadbeef},
    lambda: expected_p_cmd,
    lambda a, e: (a.get("command") == e, f"{a.get('command')!r} != {e!r}")
)

# 26. gdb_register_codec_decode_p — decode same value back
val_le_hex = (0xdeadbeef).to_bytes(8, 'little').hex()
check(
    "gdb_register_codec_decode_p_rax",
    "gdb_register_codec_decode_p",
    {"xml": SIMPLE_XML, "regnum": 0, "hex": val_le_hex},
    lambda: 0xdeadbeef,
    lambda a, e: (a.get("ok") == True and a.get("value") == e,
                  f"ok={a.get('ok')} value={a.get('value')} vs {e}")
)

# 27-29. Skipped tools
skip("gdb_stop_reply_parse", "stop reason is emitted as Rust Debug repr; no stable string reference")
skip("gdb_memory_map_parse", "XML parsing with complex region structure; covered by Rust unit tests")
skip("gdb_register_codec_decode_g", "requires full g-packet sized to target total_bytes; covered by Rust tests")
skip("gdb_register_codec_encode_g", "requires RegisterSet map round-trip; covered by Rust tests")

# 30-31. gdb_target_desc_x86_64_linux / aarch64
def check_target_desc(label, tool_name, expected_arch_substr):
    actual, err = call_tool(tool_name, {})
    if err:
        results.append({"tool": label, "status": "TOOL_ERROR", "error": err})
        mismatches.append({"tool": label, "expected": "valid XML", "actual": err})
        return
    xml_str = actual.get("xml", "")
    has_arch = expected_arch_substr.lower() in xml_str.lower()
    try:
        ET.fromstring(xml_str)
        valid_xml = True
    except ET.ParseError:
        valid_xml = False
    ok = valid_xml and has_arch
    results.append({"tool": label, "status": "PASS" if ok else "FAIL",
                    "detail": f"valid_xml={valid_xml} has_arch={has_arch}"})
    if not ok:
        mismatches.append({"tool": label, "expected": f"valid XML with {expected_arch_substr}",
                           "actual": xml_str[:200]})

check_target_desc("gdb_target_desc_x86_64_linux", "gdb_target_desc_x86_64_linux", "x86")
check_target_desc("gdb_target_desc_aarch64_linux", "gdb_target_desc_aarch64_linux", "aarch64")

# ── Finalise ──────────────────────────────────────────────────────────────────
p.stdin.close()
p.terminate()

pass_count = sum(1 for r in results if r["status"] == "PASS")
fail_count = sum(1 for r in results if r["status"] == "FAIL")
tool_err_count = sum(1 for r in results if r["status"] == "TOOL_ERROR")
skip_count = sum(1 for r in results if r["status"] == "SKIP")
hardened_names = set(r["tool"] for r in results if r["status"] not in ("SKIP",))
tools_hardened = len(hardened_names)

summary = {
    "category": "gdb",
    "tools_hardened": tools_hardened,
    "tools_passed": pass_count,
    "tools_failed": fail_count + tool_err_count,
    "tools_skipped": skip_count,
    "mismatches": mismatches,
    "details": results,
}

with open(OUT_JSON, "w") as f:
    json.dump(summary, f, indent=2)

with open(SKIP_JSON, "w") as f:
    json.dump(skipped, f, indent=2)

print(f"PASS={pass_count}  FAIL={fail_count+tool_err_count}  SKIP={skip_count}")
print(f"Tools hardened: {tools_hardened}")
if mismatches:
    print("MISMATCHES:")
    for m in mismatches:
        print(f"  {m['tool']}: expected={m['expected']!r}  actual={m['actual']!r}")
