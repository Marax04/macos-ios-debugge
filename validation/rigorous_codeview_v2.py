#!/usr/bin/env python3
"""
Rigorous ground-truth validation for codeview_* MCP tools not covered by rigorous_codeview.json.

Tools already hardened (skip):
  codeview_data32_parse, codeview_frameproc_parse, codeview_guid_to_string,
  codeview_magic_detect, codeview_magic_label, codeview_parse_symbols,
  codeview_primitive_type, codeview_proc32_parse, codeview_public32_parse,
  codeview_signature_as_str, codeview_signature_from_bytes,
  codeview_sym_kind_is_named_address, codeview_symbol_stream_count,
  codeview_type_kind_from_u16

New tools to harden:
  codeview_build_test_pub32
  codeview_parse_type_records
  codeview_parse_cv8_lines
  codeview_symbol_filter_count
  codeview_parse_type_record_single
  codeview_pdb_path_from_pe
  codeview_pdb_superblock_parse
"""
import json
import struct
import subprocess
import sys

EXE = r"C:\Users\Fra\Desktop\RustRE\target\release\rustre-mcp.exe"
TARGET = r"C:\Users\Fra\Desktop\Zyphora\target\release\cargo-zyphora.exe"
OUT_JSON = r"C:\Users\Fra\Desktop\RustRE\validation\rigorous_codeview_v2.json"
SKIP_JSON = r"C:\Users\Fra\Desktop\RustRE\validation\skip_codeview.json"

# ─── MCP transport helpers ──────────────────────────────────────────────────

proc = subprocess.Popen(
    [EXE, "--transport=stdio"],
    stdin=subprocess.PIPE,
    stdout=subprocess.PIPE,
    stderr=subprocess.DEVNULL,
    bufsize=0,
)

_rid = [0]

def send(req):
    proc.stdin.write((json.dumps(req) + "\n").encode())
    proc.stdin.flush()

def recv():
    line = proc.stdout.readline()
    if not line:
        raise RuntimeError("MCP server died")
    return json.loads(line)

def call_tool(name, args):
    _rid[0] += 1
    send({"jsonrpc": "2.0", "id": _rid[0], "method": "tools/call",
          "params": {"name": name, "arguments": args}})
    resp = recv()
    if "error" in resp:
        raise RuntimeError(f"JSONRPC error: {resp['error']}")
    result = resp["result"]
    is_err = result.get("isError", False)
    content = result.get("content", [])
    text = content[0].get("text", "") if content else ""
    return is_err, text

# ─── Initialise ─────────────────────────────────────────────────────────────

_rid[0] = 1
send({"jsonrpc": "2.0", "id": 1, "method": "initialize",
      "params": {"protocolVersion": "2024-11-05",
                 "capabilities": {},
                 "clientInfo": {"name": "rigorous_v2", "version": "1"}}})
recv()
send({"jsonrpc": "2.0", "method": "notifications/initialized"})

_rid[0] = 2
send({"jsonrpc": "2.0", "id": 2, "method": "tools/call",
      "params": {"name": "project.open", "arguments": {"path": TARGET}}})
op = recv()
op_data = json.loads(op["result"]["content"][0]["text"])
BINARY_ID = op_data["binary_id"]
PROJECT_ID = op_data["project_id"]

_rid[0] = 100  # leave headroom

# ─── Python reference implementations ───────────────────────────────────────

def hex_encode(b: bytes) -> str:
    return b.hex().upper()

def read_u32_le(data: bytes, off: int) -> int:
    if off + 4 > len(data):
        return 0
    return struct.unpack_from("<I", data, off)[0]

def read_u16_le(data: bytes, off: int) -> int:
    if off + 2 > len(data):
        return 0
    return struct.unpack_from("<H", data, off)[0]

def ref_build_test_pub32(name: str, offset: int) -> dict:
    """Mirror of rustre_symbols_codeview::build_test_pub32."""
    flags = 0
    seg = 1
    payload = (struct.pack("<I", flags) +
               struct.pack("<I", offset) +
               struct.pack("<H", seg) +
               name.encode() + b"\x00")
    kind = 0x1009
    length = 2 + len(payload)
    record = struct.pack("<H", length) + struct.pack("<H", kind) + payload
    return {
        "name": name,
        "offset": offset,
        "len": len(record),
        "hex": hex_encode(record),
    }

def ref_parse_cv_symbols_count(data: bytes) -> int:
    """Count symbols parsed by the same logic as parse_cv_symbols."""
    count = 0
    off = 0
    while off + 4 <= len(data):
        ln = read_u16_le(data, off)
        kind_raw = read_u16_le(data, off + 2)
        if ln < 2:
            break
        record_end = off + 2 + ln
        if record_end > len(data):
            break
        # Only count record kinds that produce a CvSymbol
        NAMED_KINDS = {0x1009, 0x1110, 0x110F, 0x110D, 0x110C, 0x1105, 0x1102}
        if kind_raw in NAMED_KINDS:
            count += 1
        off = record_end
    return count

def build_pub32_stream(name: str, offset: int) -> bytes:
    """Build the same stream that build_test_pub32 returns (usable as symbol stream)."""
    r = ref_build_test_pub32(name, offset)
    return bytes.fromhex(r["hex"])

def ref_parse_type_records_count(data: bytes) -> int:
    """Count type records (each record is len(2)+leaf(2)+body)."""
    count = 0
    off = 0
    while off + 4 <= len(data):
        ln = read_u16_le(data, off)
        if ln < 2:
            break
        record_end = off + 2 + ln
        if record_end > len(data):
            break
        count += 1
        off = record_end
    return count

def build_lf_procedure_record() -> bytes:
    """Build a single LF_PROCEDURE type record."""
    # LF_PROCEDURE = 0x1008
    # body: return_type(4) + call_type(1) + func_attr(1) + param_count(2) + arg_list(4)
    leaf = 0x1008
    body = (struct.pack("<I", 0x0074)  # return_type = T_INT4
            + struct.pack("<B", 0)     # call_type = near C
            + struct.pack("<B", 0)     # func_attr
            + struct.pack("<H", 0)     # param_count
            + struct.pack("<I", 0))    # arg_list (empty)
    ln = 2 + len(body)
    return struct.pack("<H", ln) + struct.pack("<H", leaf) + body

def ref_parse_cv8_lines_count(data: bytes) -> int:
    """Count CV8 line blocks (the outer parse_cv8_lines logic)."""
    if len(data) < 12:
        return 0
    # header: code_offset(4) + segment(2) + flags(2) + code_len(4) = 12 bytes
    pos = 12
    count = 0
    while pos + 12 <= len(data):
        num_lines = read_u32_le(data, pos + 4)
        block_size = read_u32_le(data, pos + 8)
        pos += 12
        line_bytes = num_lines * 8
        if pos + line_bytes > len(data):
            break
        count += 1
        pos += line_bytes
        already_read = 12 + line_bytes
        if block_size > already_read:
            pos += block_size - already_read
    return count

def build_cv8_lines_payload(code_offset: int, segment: int, code_len: int,
                             file_index: int, lines: list) -> bytes:
    """Build a CV8 DEBUG_S_LINES payload for one block."""
    hdr = (struct.pack("<I", code_offset) +
           struct.pack("<H", segment) +
           struct.pack("<H", 0) +  # flags
           struct.pack("<I", code_len))
    line_data = b""
    for (line_off, line_num, is_stmt) in lines:
        raw = (line_num & 0x7FFF_FFFF) | (0 if is_stmt else 0x8000_0000)
        line_data += struct.pack("<I", line_off) + struct.pack("<I", raw)
    num_lines = len(lines)
    block_size = 12 + num_lines * 8
    block = (struct.pack("<I", file_index) +
             struct.pack("<I", num_lines) +
             struct.pack("<I", block_size) +
             line_data)
    return hdr + block

def ref_parse_type_record_single(data: bytes) -> dict:
    """
    Mirror of parse_type_record:
      - returns parsed=False for < 4 bytes
      - returns parsed=False if len<2 or 2+len > data_len
      - returns parsed=False for Unknown kind
    """
    if len(data) < 4:
        return {"parsed": False, "kind": None, "name": None, "size": None}
    ln = read_u16_le(data, 0)
    leaf = read_u16_le(data, 2)
    if ln < 2 or 2 + ln > len(data):
        return {"parsed": False, "kind": None, "name": None, "size": None}
    KNOWN_KINDS = {0x1001, 0x1002, 0x1003, 0x1004, 0x1005, 0x1006,
                   0x1007, 0x1008, 0x1009, 0x1201, 0x1203, 0x1205, 0x150D, 0x1502}
    if leaf not in KNOWN_KINDS:
        return {"parsed": False, "kind": None, "name": None, "size": None}
    return {"parsed": True}

def ref_pdb_superblock(data: bytes) -> dict:
    """Mirror of PdbSuperBlock::parse."""
    if len(data) < 52:
        return {"parsed": False}
    MSF_MAGIC = b"Microsoft C/C++ MSF 7.00\r\n\x1a\x44\x53\x00\x00\x00"
    magic_ok = data[:len(MSF_MAGIC)] == MSF_MAGIC
    page_size = read_u32_le(data, 32)
    num_pages = read_u32_le(data, 40)
    is_valid = magic_ok and (page_size >= 512) and (page_size & (page_size - 1)) == 0
    return {
        "parsed": True,
        "magic_ok": magic_ok,
        "page_size": page_size,
        "num_pages": num_pages,
        "valid": is_valid,
    }

# ─── Test harness ────────────────────────────────────────────────────────────

results = []
mismatches = []
skipped = []
tools_passed = 0
tools_failed = 0
tools_skipped = 0

def check(tool, args, verify_fn, label=""):
    """Call tool, apply verify_fn(is_err, parsed_json) -> (ok, reason)."""
    global tools_passed, tools_failed
    try:
        is_err, text = call_tool(tool, args)
        if is_err:
            tools_failed += 1
            m = {"tool": tool, "label": label, "expected": "no error",
                 "actual": f"TOOL_ERROR: {text[:200]}"}
            mismatches.append(m)
            results.append({"tool": tool, "label": label, "status": "FAIL",
                             "reason": f"TOOL_ERROR: {text[:200]}"})
            return
        parsed = json.loads(text) if text else {}
        ok, reason = verify_fn(parsed)
        if ok:
            tools_passed += 1
            results.append({"tool": tool, "label": label, "status": "PASS"})
        else:
            tools_failed += 1
            m = {"tool": tool, "label": label, "expected": reason.split("||")[0],
                 "actual": reason.split("||")[1] if "||" in reason else text[:300]}
            mismatches.append(m)
            results.append({"tool": tool, "label": label, "status": "FAIL",
                             "reason": reason})
    except Exception as e:
        tools_failed += 1
        results.append({"tool": tool, "label": label, "status": "ERROR",
                        "reason": str(e)})

def skip(tool, reason):
    global tools_skipped
    tools_skipped += 1
    skipped.append({"tool": tool, "reason": reason})

# ═══════════════════════════════════════════════════════════════════════════
# 1. codeview_build_test_pub32
# ═══════════════════════════════════════════════════════════════════════════

NAME = "my_func"
OFFSET = 0x1234

expected_pub32 = ref_build_test_pub32(NAME, OFFSET)

def verify_build_pub32(parsed):
    if parsed.get("len") != expected_pub32["len"]:
        return False, f"expected len={expected_pub32['len']}||got len={parsed.get('len')}"
    if parsed.get("hex") != expected_pub32["hex"]:
        return False, f"expected hex={expected_pub32['hex']}||got hex={parsed.get('hex')}"
    if parsed.get("name") != NAME:
        return False, f"expected name={NAME}||got name={parsed.get('name')}"
    if parsed.get("offset") != OFFSET:
        return False, f"expected offset={OFFSET}||got offset={parsed.get('offset')}"
    return True, ""

check("codeview_build_test_pub32",
      {"name": NAME, "offset": OFFSET},
      verify_build_pub32, "known name+offset")

# Test with empty name
NAME2 = ""
OFFSET2 = 0
expected_pub32_empty = ref_build_test_pub32(NAME2, OFFSET2)

def verify_build_pub32_empty(parsed):
    if parsed.get("len") != expected_pub32_empty["len"]:
        return False, (f"expected len={expected_pub32_empty['len']}"
                       f"||got len={parsed.get('len')}")
    if parsed.get("hex") != expected_pub32_empty["hex"]:
        return False, (f"expected hex={expected_pub32_empty['hex']}"
                       f"||got hex={parsed.get('hex')}")
    return True, ""

check("codeview_build_test_pub32",
      {"name": NAME2, "offset": OFFSET2},
      verify_build_pub32_empty, "empty name offset=0")

# ═══════════════════════════════════════════════════════════════════════════
# 2. codeview_parse_type_records
# ═══════════════════════════════════════════════════════════════════════════

# 2a: empty bytes → count=0
def verify_type_records_empty(parsed):
    if parsed.get("count") != 0:
        return False, f"expected count=0||got count={parsed.get('count')}"
    if parsed.get("records") != []:
        return False, f"expected records=[]||got records={parsed.get('records')}"
    return True, ""

check("codeview_parse_type_records",
      {"hex": ""},
      verify_type_records_empty, "empty bytes => 0 records")

# 2b: one LF_PROCEDURE record
proc_rec = build_lf_procedure_record()
expected_count_proc = ref_parse_type_records_count(proc_rec)  # should be 1

def verify_type_records_one(parsed):
    if parsed.get("count") != expected_count_proc:
        return False, (f"expected count={expected_count_proc}"
                       f"||got count={parsed.get('count')}")
    return True, ""

check("codeview_parse_type_records",
      {"hex": hex_encode(proc_rec)},
      verify_type_records_one, "one LF_PROCEDURE record")

# ═══════════════════════════════════════════════════════════════════════════
# 3. codeview_parse_cv8_lines
# ═══════════════════════════════════════════════════════════════════════════

# 3a: empty bytes → 0 blocks
def verify_cv8_empty(parsed):
    if parsed.get("count") != 0:
        return False, f"expected count=0||got count={parsed.get('count')}"
    return True, ""

check("codeview_parse_cv8_lines",
      {"hex": ""},
      verify_cv8_empty, "empty bytes => 0 blocks")

# 3b: one block with 2 line entries
lines_payload = build_cv8_lines_payload(
    code_offset=0x1000, segment=1, code_len=0x80, file_index=0,
    lines=[(0x00, 10, True), (0x10, 11, True)]
)
expected_cv8_count = ref_parse_cv8_lines_count(lines_payload)  # should be 1

def verify_cv8_one_block(parsed):
    if parsed.get("count") != expected_cv8_count:
        return False, (f"expected count={expected_cv8_count}"
                       f"||got count={parsed.get('count')}")
    blocks = parsed.get("blocks", [])
    if len(blocks) != expected_cv8_count:
        return False, f"expected {expected_cv8_count} blocks||got {len(blocks)}"
    if expected_cv8_count > 0:
        b0 = blocks[0]
        if b0.get("code_offset") != 0x1000:
            return False, f"expected code_offset=0x1000||got {b0.get('code_offset')}"
        if b0.get("line_count") != 2:
            return False, f"expected line_count=2||got {b0.get('line_count')}"
    return True, ""

check("codeview_parse_cv8_lines",
      {"hex": hex_encode(lines_payload)},
      verify_cv8_one_block, "one block with 2 lines")

# ═══════════════════════════════════════════════════════════════════════════
# 4. codeview_symbol_filter_count
# ═══════════════════════════════════════════════════════════════════════════

# Use the same build_test_pub32 to get a known symbol stream
pub32_stream = build_pub32_stream("test_sym", 0x5000)
expected_sym_count = ref_parse_cv_symbols_count(pub32_stream)  # 1

def verify_filter_count_one(parsed):
    if parsed.get("count") != expected_sym_count:
        return False, (f"expected count={expected_sym_count}"
                       f"||got count={parsed.get('count')}")
    return True, ""

check("codeview_symbol_filter_count",
      {"hex": hex_encode(pub32_stream)},
      verify_filter_count_one, "one PUB32 symbol")

# Empty stream → count=0
def verify_filter_count_zero(parsed):
    if parsed.get("count") != 0:
        return False, f"expected count=0||got count={parsed.get('count')}"
    return True, ""

check("codeview_symbol_filter_count",
      {"hex": ""},
      verify_filter_count_zero, "empty stream => count=0")

# ═══════════════════════════════════════════════════════════════════════════
# 5. codeview_parse_type_record_single
# ═══════════════════════════════════════════════════════════════════════════

# 5a: too short → parsed=false
def verify_single_too_short(parsed):
    if parsed.get("parsed") is not False:
        return False, f"expected parsed=false||got parsed={parsed.get('parsed')}"
    return True, ""

check("codeview_parse_type_record_single",
      {"hex": "0000"},  # only 2 bytes
      verify_single_too_short, "too short => parsed=false")

# 5b: LF_POINTER record (valid)
# LF_POINTER = 0x1002, body = target_type(4) + attributes(4)
lf_ptr_body = struct.pack("<I", 0x0074) + struct.pack("<I", 0x0000_000C)
lf_ptr_leaf = 0x1002
lf_ptr_len = 2 + len(lf_ptr_body)
lf_ptr_rec = struct.pack("<H", lf_ptr_len) + struct.pack("<H", lf_ptr_leaf) + lf_ptr_body

ref_single = ref_parse_type_record_single(lf_ptr_rec)

def verify_single_ptr(parsed):
    if parsed.get("parsed") is not True:
        return False, f"expected parsed=true||got parsed={parsed.get('parsed')}"
    return True, ""

check("codeview_parse_type_record_single",
      {"hex": hex_encode(lf_ptr_rec)},
      verify_single_ptr, "LF_POINTER record => parsed=true")

# 5c: unknown leaf → parsed=false
unknown_leaf = 0xBEEF
unknown_body = b"\x00" * 4
unknown_len = 2 + len(unknown_body)
unknown_rec = struct.pack("<H", unknown_len) + struct.pack("<H", unknown_leaf) + unknown_body

def verify_single_unknown(parsed):
    if parsed.get("parsed") is not False:
        return False, f"expected parsed=false (unknown leaf)||got parsed={parsed.get('parsed')}"
    return True, ""

check("codeview_parse_type_record_single",
      {"hex": hex_encode(unknown_rec)},
      verify_single_unknown, "unknown leaf => parsed=false")

# ═══════════════════════════════════════════════════════════════════════════
# 6. codeview_pdb_path_from_pe
# ═══════════════════════════════════════════════════════════════════════════

# Non-PE bytes → found=false
def verify_pdb_path_not_found(parsed):
    if parsed.get("found") is not False:
        return False, f"expected found=false||got found={parsed.get('found')}"
    return True, ""

check("codeview_pdb_path_from_pe",
      {"hex": "deadbeef00112233"},
      verify_pdb_path_not_found, "random bytes => found=false")

# Too short → found=false
check("codeview_pdb_path_from_pe",
      {"hex": "4d5a"},  # "MZ" but too short
      verify_pdb_path_not_found, "MZ only => found=false")

# ═══════════════════════════════════════════════════════════════════════════
# 7. codeview_pdb_superblock_parse
# ═══════════════════════════════════════════════════════════════════════════

# 7a: less than 52 bytes → parsed=false
def verify_sb_too_short(parsed):
    if parsed.get("parsed") is not False:
        return False, f"expected parsed=false||got parsed={parsed.get('parsed')}"
    return True, ""

check("codeview_pdb_superblock_parse",
      {"hex": "00" * 10},
      verify_sb_too_short, "< 52 bytes => parsed=false")

# 7b: 52 zero bytes → parsed=true, magic_ok=false, page_size=0, valid=false
zero52 = b"\x00" * 52
ref_sb_zeros = ref_pdb_superblock(zero52)

def verify_sb_zeros(parsed):
    if parsed.get("parsed") is not True:
        return False, f"expected parsed=true||got parsed={parsed.get('parsed')}"
    if parsed.get("magic_ok") is not False:
        return False, f"expected magic_ok=false||got magic_ok={parsed.get('magic_ok')}"
    if parsed.get("page_size") != 0:
        return False, f"expected page_size=0||got page_size={parsed.get('page_size')}"
    if parsed.get("valid") is not False:
        return False, f"expected valid=false||got valid={parsed.get('valid')}"
    return True, ""

check("codeview_pdb_superblock_parse",
      {"hex": hex_encode(zero52)},
      verify_sb_zeros, "52 zero bytes => parsed=true, magic_ok=false")

# 7c: valid MSF magic + plausible fields → magic_ok=true
MSF_MAGIC = b"Microsoft C/C++ MSF 7.00\r\n\x1a\x44\x53\x00\x00\x00"
PAGE_SIZE = 4096
FREE_PAGE_MAP = 1
NUM_PAGES = 100
NUM_DIR_BYTES = 256
BLOCK_MAP_ADDR = 3

sb_valid = (MSF_MAGIC +
            struct.pack("<I", PAGE_SIZE) +
            struct.pack("<I", FREE_PAGE_MAP) +
            struct.pack("<I", NUM_PAGES) +
            struct.pack("<I", NUM_DIR_BYTES) +
            struct.pack("<I", BLOCK_MAP_ADDR))

assert len(sb_valid) == 52, f"Expected 52 bytes, got {len(sb_valid)}"
ref_sb_valid = ref_pdb_superblock(sb_valid)

def verify_sb_valid(parsed):
    if parsed.get("parsed") is not True:
        return False, f"expected parsed=true||got parsed={parsed.get('parsed')}"
    if parsed.get("magic_ok") is not True:
        return False, f"expected magic_ok=true||got magic_ok={parsed.get('magic_ok')}"
    if parsed.get("page_size") != PAGE_SIZE:
        return False, (f"expected page_size={PAGE_SIZE}"
                       f"||got page_size={parsed.get('page_size')}")
    if parsed.get("num_pages") != NUM_PAGES:
        return False, (f"expected num_pages={NUM_PAGES}"
                       f"||got num_pages={parsed.get('num_pages')}")
    if parsed.get("valid") is not True:
        return False, f"expected valid=true||got valid={parsed.get('valid')}"
    return True, ""

check("codeview_pdb_superblock_parse",
      {"hex": hex_encode(sb_valid)},
      verify_sb_valid, "valid MSF magic+fields => magic_ok=true, valid=true")

# ─── Tear down ───────────────────────────────────────────────────────────────

proc.stdin.close()
proc.terminate()

# ─── Write outputs ───────────────────────────────────────────────────────────

output = {
    "module": "codeview_v2",
    "tools_hardened": 7,
    "tools_list": [
        "codeview_build_test_pub32",
        "codeview_parse_type_records",
        "codeview_parse_cv8_lines",
        "codeview_symbol_filter_count",
        "codeview_parse_type_record_single",
        "codeview_pdb_path_from_pe",
        "codeview_pdb_superblock_parse",
    ],
    "checks_run": len(results),
    "checks_passed": tools_passed,
    "checks_failed": tools_failed,
    "checks_skipped": tools_skipped,
    "real_mismatches": len(mismatches),
    "mismatches": mismatches,
    "detail": results,
}

with open(OUT_JSON, "w", encoding="utf-8") as f:
    json.dump(output, f, indent=2)

if skipped:
    with open(SKIP_JSON, "w", encoding="utf-8") as f:
        json.dump({"skipped": skipped}, f, indent=2)

print(f"\n=== rigorous_codeview_v2 results ===")
print(f"  Checks passed  : {tools_passed}")
print(f"  Checks failed  : {tools_failed}")
print(f"  Checks skipped : {tools_skipped}")
print(f"  Mismatches     : {len(mismatches)}")
for m in mismatches:
    print(f"  MISMATCH [{m['tool']} / {m.get('label','')}]")
    print(f"    expected: {m['expected']}")
    print(f"    actual  : {m['actual']}")

sys.exit(0 if tools_failed == 0 else 1)
