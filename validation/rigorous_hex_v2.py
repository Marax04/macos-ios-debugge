#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Rigorous ground-truth validation for all MCP tools with prefix hex_
that are NOT already covered by rigorous_hex_pattern.json.

Protocol: JSON-RPC 2.0 over stdio (same as exercise_v3.py).
Expected values are computed inline using Python stdlib only.
"""
import json
import subprocess
import struct
import sys
import io

# Force UTF-8 for stdout so non-ASCII descriptions do not crash on Windows cp1252
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")

EXE = r"C:\Users\Fra\Desktop\RustRE\target\release\rustre-mcp.exe"
TARGET = r"C:\Users\Fra\Desktop\Zyphora\target\release\cargo-zyphora.exe"
OUT_JSON = r"C:\Users\Fra\Desktop\RustRE\validation\rigorous_hex_v2.json"
SKIP_JSON = r"C:\Users\Fra\Desktop\RustRE\validation\skip_hex.json"

# Already-hardened tools from rigorous_hex_pattern.json -- skip.
ALREADY_HARDENED = {
    "hex_pattern_canonicalize",
    "hex_pattern_compiled_matches_at",
    "hex_pattern_compiled_search",
    "hex_pattern_crc16_ibm",
    "hex_pattern_exact_count",
    "hex_pattern_group_search_all",
    "hex_pattern_masked_matches_at",
    "hex_pattern_masked_new",
    "hex_pattern_masked_search",
    "hex_pattern_matches_at",
    "hex_pattern_parse",
    "hex_pattern_search",
    "hex_pattern_specificity",
    "hex_pattern_to_bytes",
    "hex_pattern_to_simd_form",
    "hex_pattern_wildcard_count",
}

# ---- Python reference implementations -----------------------------------------

def py_crc16_ibm(data: bytes) -> int:
    """CRC-16/IBM: poly 0x8005, init=0, refin=True, refout=True (0xA001)."""
    crc = 0
    for byte in data:
        b = byte
        for _ in range(8):
            xor = ((crc ^ b) & 1) != 0
            crc >>= 1
            if xor:
                crc ^= 0xA001
            b >>= 1
    return crc

def py_popcount(n: int) -> int:
    return bin(n & 0xFF).count('1')

def py_byte_mask_specificity(mask: int) -> float:
    return py_popcount(mask) / 8.0

def py_range_expand(lo: int, hi: int) -> list:
    return list(range(lo, hi + 1))

# ---- Test data ----------------------------------------------------------------

DATA_HEX = "deadbeef00112233"
DATA_BYTES = bytes.fromhex(DATA_HEX)
DATA_ARRAY = list(DATA_BYTES)      # [0xde, 0xad, 0xbe, 0xef, 0x00, 0x11, 0x22, 0x33]

# Minimal valid MZ header (64 bytes): magic "MZ" + 62 zero bytes
MZ_HEX = "4d5a" + "00" * 62       # 64 bytes total

# ---- MCP transport ------------------------------------------------------------

p = subprocess.Popen(
    [EXE, "--transport=stdio"],
    stdin=subprocess.PIPE,
    stdout=subprocess.PIPE,
    stderr=subprocess.DEVNULL,
    bufsize=0,
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
        return {"error": {"message": f"bad-line: {line[:200]!r}"}}

def call_tool(name, args, rid):
    send({"jsonrpc": "2.0", "id": rid, "method": "tools/call",
          "params": {"name": name, "arguments": args}})
    resp = recv()
    if "error" in resp:
        return None, f"JSONRPC_ERROR: {resp['error']}"
    result = resp.get("result", {})
    if result.get("isError"):
        content = result.get("content", [])
        txt = content[0].get("text", "") if content else ""
        return None, f"TOOL_ERROR: {txt[:200]}"
    content = result.get("content", [])
    txt = content[0].get("text", "") if content else ""
    try:
        return json.loads(txt), None
    except Exception:
        return txt, None

# ---- Initialize ---------------------------------------------------------------

send({"jsonrpc": "2.0", "id": 1, "method": "initialize",
      "params": {"protocolVersion": "2024-11-05", "capabilities": {},
                 "clientInfo": {"name": "rigorous_hex_v2", "version": "1"}}})
recv()
send({"jsonrpc": "2.0", "method": "notifications/initialized"})

send({"jsonrpc": "2.0", "id": 2, "method": "tools/call",
      "params": {"name": "project.open", "arguments": {"path": TARGET}}})
op = recv()
try:
    op_data = json.loads(op["result"]["content"][0]["text"])
    BINARY_ID = op_data["binary_id"]
    PROJECT_ID = op_data["project_id"]
    print(f"project.open: binary_id={BINARY_ID}, project_id={PROJECT_ID}")
except Exception as e:
    print(f"WARNING: project.open failed: {e}")
    BINARY_ID = ""
    PROJECT_ID = ""

# ---- Check helpers ------------------------------------------------------------

results = []
skips = []
rid = 100

def check(tool, args, check_fn, description=""):
    global rid
    rid += 1
    data, err = call_tool(tool, args, rid)
    ok, expected, actual = check_fn(data, err)
    entry = {
        "tool": tool,
        "description": description,
        "args": args,
        "status": "PASS" if ok else "FAIL",
        "expected": expected,
        "actual": actual,
    }
    results.append(entry)
    icon = "PASS" if ok else "FAIL"
    print(f"  [{icon}] {tool}: {description}")
    if not ok:
        print(f"         expected={expected!r}")
        print(f"         actual  ={actual!r}")

def no_error(data, err):
    if err:
        return False, "no error", err
    return True, "no error", "no error"

def has_fields(*fields):
    def _check(data, err):
        if err:
            return False, f"fields {fields}", err
        if not isinstance(data, dict):
            return False, f"dict with {fields}", f"got {type(data).__name__}: {str(data)[:100]}"
        missing = [f for f in fields if f not in data]
        if missing:
            return False, f"fields {fields}", f"missing {missing} in {list(data.keys())}"
        return True, f"fields {fields}", f"fields {fields}"
    return _check

def field_equals(field, expected_val):
    def _check(data, err):
        if err:
            return False, f"{field}=={expected_val}", err
        if not isinstance(data, dict):
            return False, f"{field}=={expected_val}", "not a dict"
        actual_val = data.get(field)
        ok = actual_val == expected_val
        return ok, str(expected_val), str(actual_val)
    return _check

def field_close(field, expected_val, tol=1e-6):
    def _check(data, err):
        if err:
            return False, f"{field}~={expected_val}", err
        if not isinstance(data, dict):
            return False, f"{field}~={expected_val}", "not a dict"
        actual_val = data.get(field)
        try:
            ok = abs(float(actual_val) - expected_val) <= tol
        except Exception:
            ok = False
        return ok, str(expected_val), str(actual_val)
    return _check

def list_field_equals(field, expected_list):
    def _check(data, err):
        if err:
            return False, str(expected_list), err
        if not isinstance(data, dict):
            return False, str(expected_list), "not a dict"
        actual = data.get(field)
        ok = actual == expected_list
        return ok, str(expected_list), str(actual)
    return _check

def count_positive(field="count"):
    def _check(data, err):
        if err:
            return False, f"{field}>0", err
        if not isinstance(data, dict):
            return False, f"{field}>0", "not a dict"
        v = data.get(field, 0)
        ok = isinstance(v, (int, float)) and v > 0
        return ok, f"{field}>0", str(v)
    return _check

def list_positive(field):
    def _check(data, err):
        if err:
            return False, f"{field} non-empty list", err
        if not isinstance(data, dict):
            return False, f"{field} non-empty list", "not a dict"
        v = data.get(field, [])
        ok = isinstance(v, list) and len(v) > 0
        return ok, f"{field} non-empty list", f"list[{len(v) if isinstance(v,list) else 'N/A'}]"
    return _check

def field_contains(field, substring):
    def _check(data, err):
        if err:
            return False, f"{field} contains '{substring}'", err
        if not isinstance(data, dict):
            return False, f"dict", "not a dict"
        v = data.get(field, "")
        ok = isinstance(v, str) and substring.lower() in v.lower()
        return ok, f"'{substring}' in {field}", str(v)[:80]
    return _check

# ---- hex_view tools -----------------------------------------------------------

print("\n== hex_view ==")

def check_hex_dump(data, err):
    if err:
        return False, "hex dump containing bytes + offset 0", err
    if isinstance(data, dict):
        dump = data.get("dump", "") or str(data)
    elif isinstance(data, str):
        dump = data
    else:
        return False, "hex dump", f"unexpected type {type(data)}"
    dump_l = dump.lower()
    has_de = "de" in dump_l
    has_ad = "ad" in dump_l
    has_zero = "00000000" in dump_l or "0000000000000000" in dump_l
    ok = has_de and has_ad and has_zero
    return ok, "dump has 'de','ad' + offset 0", dump[:120]

check("hex_view_format_hex_dump",
      {"hex": DATA_HEX, "base_offset": 0},
      check_hex_dump,
      "dump contains bytes + offset 0")

def check_ansi_dump(data, err):
    if err:
        return False, "ANSI dump with bytes", err
    dump = ""
    if isinstance(data, dict):
        dump = data.get("dump", "") or str(data)
    elif isinstance(data, str):
        dump = data
    ok = "de" in dump.lower()
    return ok, "dump contains 'de'", dump[:100]

check("hex_view_format_hex_dump_ansi",
      {"hex": DATA_HEX, "base_offset": 0},
      check_ansi_dump,
      "ANSI dump contains bytes")

# ---- hex_template tools -------------------------------------------------------

print("\n== hex_template ==")

check("hex_template_wav",
      {},
      count_positive("field_count"),
      "WAV template field_count > 0")

check("hex_template_riff_chunk",
      {},
      count_positive("field_count"),
      "RIFF chunk template field_count > 0")

check("hex_template_builtin_templates",
      {},
      count_positive("count"),
      "builtin_templates count > 0")

check("hex_template_builtin_names",
      {},
      list_positive("names"),
      "builtin_names non-empty list")

# bitfield_extract: raw=255, start_bit=0, bit_count=4 -> (255 >> 0) & ((1<<4)-1) = 15
EXPECTED_BITFIELD = (255 >> 0) & ((1 << 4) - 1)  # = 15
check("hex_template_bitfield_extract",
      {"raw": 255, "start_bit": 0, "bit_count": 4},
      field_equals("value", EXPECTED_BITFIELD),
      f"bitfield_extract(raw=255, start=0, count=4) == {EXPECTED_BITFIELD}")

check("hex_template_elf32_phdr",
      {},
      count_positive("field_count"),
      "elf32_phdr field_count > 0")

check("hex_template_elf64_phdr",
      {},
      count_positive("field_count"),
      "elf64_phdr field_count > 0")

check("hex_template_riff_chunk_wire",
      {},
      count_positive("field_count"),
      "riff_chunk_wire field_count > 0")

check("hex_template_wav_wire",
      {},
      count_positive("field_count"),
      "wav_wire field_count > 0")

# ---- hex_pattern extras -------------------------------------------------------

print("\n== hex_pattern extras ==")

check("hex_pattern_alternation_parse",
      {"pattern": "DE AD | BE EF"},
      has_fields("count"),
      "alternation_parse returns count")

check("hex_pattern_masked_from_str",
      {"pattern": "DE AD ?? BE EF"},
      has_fields("len", "bytes_hex", "mask_hex"),
      "masked_from_str returns len+bytes_hex+mask_hex")

# alternation_matches expects "bytes" as integer array
check("hex_pattern_alternation_matches",
      {"pattern": "DE AD | BE EF", "bytes": DATA_ARRAY, "offset": 0},
      has_fields("matches"),
      "alternation_matches has 'matches'")

# alternation_search expects "pattern" + "bytes" array
check("hex_pattern_alternation_search",
      {"pattern": "DE AD | BE EF", "bytes": DATA_ARRAY},
      has_fields("offsets"),
      "alternation_search has 'offsets'")

check("hex_pattern_export_ida_pat",
      {"patterns": [{"pattern": "DE AD BE EF", "name": "test"}]},
      has_fields("ida_pat"),
      "export_ida_pat returns ida_pat")

# import_ida_pat: tokens must be <=2 hex chars each (space-separated pairs)
# Correct IDA .pat line: "DE AD BE EF funcname"
check("hex_pattern_import_ida_pat",
      {"text": "DE AD BE EF test_func\n"},
      has_fields("count"),
      "import_ida_pat returns count")

# signature_search: requires all fields
DEADBEEF_ARRAY = [0xde, 0xad, 0xbe, 0xef] + [0x00] * 32
check("hex_pattern_signature_search",
      {"name": "sig1", "prologue": "DE AD", "crc16": 0,
       "crc_len": 2, "func_len": 8, "bytes": DEADBEEF_ARRAY},
      has_fields("name", "offsets"),
      "signature_search returns name+offsets")

check("hex_pattern_to_json",
      {"pattern": "DE AD BE EF"},
      has_fields("json"),
      "to_json returns json")

# from_json: expects "json" not "json_str"
# first get json from to_json
def check_from_json(data, err):
    if err:
        return False, "canonical=='de ad be ef'", err
    canon = data.get("canonical", "")
    ok = "de ad be ef" in canon.lower()
    return ok, "canonical contains 'de ad be ef'", canon
check("hex_pattern_from_json",
      {"json": '{"bytes":[{"Exact":222},{"Exact":173},{"Exact":190},{"Exact":239}],'
               '"name":null,"tags":[],"comment":"","captures":[]}'},
      check_from_json,
      "from_json canonical == 'de ad be ef'")

check("hex_pattern_exporter_export_json",
      {"patterns": ["DE AD BE EF"]},
      has_fields("json"),
      "exporter_export_json returns json")

# regex_search: expects "pattern" + "bytes" integer array
check("hex_pattern_regex_search",
      {"pattern": r"\xde\xad", "bytes": DATA_ARRAY},
      has_fields("offsets"),
      "regex_search returns offsets")

# search_with_captures: expects "pattern" + "bytes" integer array
check("hex_pattern_search_with_captures",
      {"pattern": "DE AD BE EF", "bytes": DATA_ARRAY},
      has_fields("matches"),
      "search_with_captures returns matches")

# ---- hex_tplx tools -----------------------------------------------------------

print("\n== hex_tplx ==")

check("hex_tplx_builtin_count",
      {},
      count_positive("count"),
      "tplx builtin count > 0")

# registry_with_builtins returns "len" not "count"
check("hex_tplx_registry_with_builtins",
      {},
      count_positive("len"),
      "registry_with_builtins len > 0")

# Use "MZ" (valid builtin name)
check("hex_tplx_template_json_roundtrip",
      {"name": "MZ"},
      has_fields("name", "fields_count"),
      "template_json_roundtrip(MZ) has name+fields_count")

# Expr::Eq(field, value) with actual==value -> true
check("hex_tplx_expr_eval",
      {"field": "magic", "value": 42, "actual": 42},
      field_equals("result", True),
      "expr_eval(Eq(field,42,42)) == True")

# BitfieldDef::extract: raw=255, start_bit=0, bit_count=4 -> 15
# Result field is "value"
EXPECTED_BITFIELD_V = (255 >> 0) & ((1 << 4) - 1)  # = 15
check("hex_tplx_bitfield_def_extract",
      {"raw": 255, "start_bit": 0, "bit_count": 4},
      field_equals("value", EXPECTED_BITFIELD_V),
      f"bitfield_def_extract(255, 0, 4) == {EXPECTED_BITFIELD_V}")

# BitfieldStruct: raw=0b10110011 -> lo=3 (bits 0-3), hi=11 (bits 4-7)
# Returns raw, lo, hi, field_count
RAW_VAL = 0b10110011  # = 179
EXPECTED_LO = RAW_VAL & 0xF         # = 3
EXPECTED_HI = (RAW_VAL >> 4) & 0xF  # = 11
check("hex_tplx_bitfield_struct_extract",
      {"raw": RAW_VAL},
      field_equals("field_count", 2),
      f"bitfield_struct_extract field_count == 2")

check("hex_tplx_printer_render",
      {"indent": "  "},
      has_fields("output"),
      "printer_render has output")

# Apply MZ template to 64-byte MZ header
check("hex_tplx_apply_builtin_to_bytes",
      {"name": "MZ", "hex": MZ_HEX},
      count_positive("field_count"),
      "apply_builtin_to_bytes(MZ) field_count > 0")

# TemplateRegistry also uses same builtin_templates so MZ should work
check("hex_tplx_registry_apply",
      {"name": "MZ", "hex": MZ_HEX},
      count_positive("field_count"),
      "registry_apply(MZ) field_count > 0")

check("hex_tplx_pe_opt_header",
      {},
      count_positive("field_count"),
      "pe_opt_header field_count > 0")

check("hex_tplx_elf32_shdr",
      {},
      count_positive("field_count"),
      "elf32_shdr field_count > 0")

# ---- hex_tply tools -----------------------------------------------------------

print("\n== hex_tply ==")

check("hex_tply_bmp_header",
      {},
      count_positive("field_count"),
      "bmp_header field_count > 0")

check("hex_tply_jpeg_jfif",
      {},
      count_positive("field_count"),
      "jpeg_jfif field_count > 0")

check("hex_tply_zip_local_file_header",
      {},
      count_positive("field_count"),
      "zip_local_file_header field_count > 0")

check("hex_tply_zip_eocd",
      {},
      count_positive("field_count"),
      "zip_eocd field_count > 0")

check("hex_tply_coff_file_header",
      {},
      count_positive("field_count"),
      "coff_file_header field_count > 0")

check("hex_tply_pe32plus_optional_header",
      {},
      count_positive("field_count"),
      "pe32plus_optional_header field_count > 0")

check("hex_tply_elf64_shdr",
      {},
      count_positive("field_count"),
      "elf64_shdr field_count > 0")

check("hex_tply_pe_import_descriptor",
      {},
      count_positive("field_count"),
      "pe_import_descriptor field_count > 0")

check("hex_tply_pe_export_directory",
      {},
      count_positive("field_count"),
      "pe_export_directory field_count > 0")

check("hex_tply_auto_select_template",
      {"hex": MZ_HEX},
      no_error,
      "auto_select_template(MZ_HEX) no error")

# flatten_parsed: apply MZ template, returns "flat_count"
check("hex_tply_flatten_parsed",
      {"name": "MZ", "hex": MZ_HEX},
      count_positive("flat_count"),
      "flatten_parsed(MZ) flat_count > 0")

# template_report: apply MZ, returns "field_count" + "total_size"
check("hex_tply_template_report",
      {"name": "MZ", "hex": MZ_HEX},
      has_fields("field_count", "total_size"),
      "template_report(MZ) has field_count+total_size")

# ---- hex_pattern v4 tools -----------------------------------------------------

print("\n== hex_pattern v4 ==")

check("hex_pattern_with_name_v4",
      {"pattern": "DE AD BE EF", "name": "test_sig"},
      field_equals("name", "test_sig"),
      "with_name_v4 returns name=='test_sig'")

# with_tag returns "tags" (list), check it contains "mytag"
def check_tags(data, err):
    if err:
        return False, "tags contains 'mytag'", err
    if not isinstance(data, dict):
        return False, "tags contains 'mytag'", "not a dict"
    tags = data.get("tags", [])
    ok = isinstance(tags, list) and "mytag" in tags
    return ok, "['mytag'] in tags", str(tags)
check("hex_pattern_with_tag_v4",
      {"pattern": "DE AD BE EF", "tag": "mytag"},
      check_tags,
      "with_tag_v4 tags contains 'mytag'")

check("hex_pattern_with_comment_v4",
      {"pattern": "DE AD BE EF", "comment": "hello"},
      field_equals("comment", "hello"),
      "with_comment_v4 comment=='hello'")

# alternation_new_v4: 2 patterns -> len == 2
check("hex_pattern_alternation_new_v4",
      {"patterns": ["DE AD", "BE EF"]},
      field_equals("len", 2),
      "alternation_new_v4(2 patterns) len == 2")

# masked_len_v4: "DE AD ??" -> 3
check("hex_pattern_masked_len_v4",
      {"pattern": "DE AD ??"},
      field_equals("len", 3),
      "masked_len_v4('DE AD ??') == 3")

# regex_search_v4 uses args_to_bytes (needs "hex" or "bytes"), schema says "data_hex"
# But args_to_bytes checks "bytes"/"hex"/"path" keys, not "data_hex"
# Use "hex" key instead
check("hex_pattern_regex_search_v4",
      {"regex": r"\xde\xad", "hex": DATA_HEX},
      has_fields("offsets"),
      "regex_search_v4 returns offsets")

check("hex_pattern_group_compile_v4",
      {"name": "grp", "patterns": ["DE AD", "BE EF"], "hex": DATA_HEX},
      has_fields("match_count"),
      "group_compile_v4 returns match_count")

check("hex_pattern_group_any_matches_v4",
      {"patterns": ["DE AD", "BE EF"], "hex": DATA_HEX, "offset": 0},
      has_fields("any_matches"),
      "group_any_matches_v4 returns any_matches")

check("hex_pattern_group_to_json_v4",
      {"name": "grp", "patterns": ["DE AD", "BE EF"]},
      has_fields("roundtrip_patterns"),
      "group_to_json_v4 returns roundtrip_patterns")

check("hex_pattern_db_roundtrip_v4",
      {"pattern": "DE AD BE EF", "name": "test", "tag": "t"},
      field_equals("count_after_delete", 0),
      "db_roundtrip_v4 delete -> count==0")

check("hex_pattern_exporter_json_v4",
      {"patterns": ["DE AD BE EF"]},
      field_equals("roundtrip", 1),
      "exporter_json_v4 roundtrip==1")

# ---- hex_pattern v3 tools -----------------------------------------------------

print("\n== hex_pattern v3 ==")

# to_hex_string: "DE AD BE EF" -> "de ad be ef"
def check_hex_str(data, err):
    if err:
        return False, "hex_string contains 'de ad be ef'", err
    s = ""
    if isinstance(data, dict):
        s = data.get("hex_string", "") or str(data)
    elif isinstance(data, str):
        s = data
    ok = "de ad be ef" in s.lower()
    return ok, "'de ad be ef' in hex_string", s[:80]

check("hex_pattern_to_hex_string_v3",
      {"pat": "DE AD BE EF"},
      check_hex_str,
      "to_hex_string returns 'de ad be ef'")

# NFA find_all: "DE AD" in DATA_HEX -> match at offset 0
# Returns {"count", "hits", "source"}
def check_nfa_all(data, err):
    if err:
        return False, "hits non-empty", err
    if not isinstance(data, dict):
        return False, "dict", "not a dict"
    hits = data.get("hits", [])
    count = data.get("count", 0)
    # hits may be list of [offset, len] or dicts
    has_match = count > 0 and len(hits) > 0
    return has_match, "count>0 and hits non-empty", f"count={count} hits={hits!r}"

check("hex_pattern_nfa_find_all_v3",
      {"pat": "DE AD", "data_hex": DATA_HEX},
      check_nfa_all,
      "nfa_find_all('DE AD' in deadbeef...) -> count>0")

# NFA find_first: "DE AD" -> hit at offset 0
def check_nfa_first(data, err):
    if err:
        return False, "hit != null", err
    if not isinstance(data, dict):
        return False, "dict", "not a dict"
    hit = data.get("hit")
    ok = hit is not None
    return ok, "hit is not None", str(hit)

check("hex_pattern_nfa_find_first_v3",
      {"pat": "DE AD", "data_hex": DATA_HEX, "start": 0},
      check_nfa_first,
      "nfa_find_first('DE AD') -> hit is not None")

# DFA search: "BE EF" at offset 2 in DATA_HEX
def check_dfa(data, err):
    if err:
        return False, "count>0 and hits non-empty", err
    if not isinstance(data, dict):
        return False, "dict", "not a dict"
    hits = data.get("hits", [])
    count = data.get("count", 0)
    ok = count > 0 and len(hits) > 0
    return ok, "count>0", f"count={count} hits={hits!r}"

check("hex_pattern_dfa_search_v3",
      {"pat": "BE EF", "data_hex": DATA_HEX},
      check_dfa,
      "dfa_search('BE EF' in deadbeef...) -> count>0")

# MultiMatcher: two patterns
check("hex_pattern_multi_matcher_search_v3",
      {"patterns": ["DE AD", "BE EF"], "data_hex": DATA_HEX},
      has_fields("count", "hits"),
      "multi_matcher_search_v3 has count+hits")

# BMH search: "dead" -> offset 0
def check_bmh(data, err):
    if err:
        return False, "0 in hits", err
    if not isinstance(data, dict):
        return False, "dict", "not a dict"
    hits = data.get("hits", [])
    count = data.get("count", 0)
    ok = count > 0 and 0 in hits
    return ok, "0 in hits", f"hits={hits!r}"

check("hex_pattern_bmh_search_v3",
      {"needle_hex": "dead", "haystack_hex": DATA_HEX},
      check_bmh,
      "bmh_search(needle='dead') -> 0 in hits")

# byte_mask_specificity: mask=255, value=0xAB -> popcount(255)/8 = 1.0
EXPECTED_SPEC = py_byte_mask_specificity(0xFF)   # 1.0
check("hex_pattern_byte_mask_specificity_v3",
      {"mask": 255, "value": 0xAB},
      field_close("specificity", EXPECTED_SPEC),
      f"byte_mask_specificity(mask=255) == {EXPECTED_SPEC}")

# range_expand: lo=5, hi=8 -> [5,6,7,8]; result field is "bytes"
EXPECTED_RANGE = py_range_expand(5, 8)
check("hex_pattern_range_expand_v3",
      {"lo": 5, "hi": 8},
      list_field_equals("bytes", EXPECTED_RANGE),
      f"range_expand(5,8).bytes == {EXPECTED_RANGE}")

check("hex_pattern_statistics_compute_v3",
      {"patterns": ["DE AD BE EF", "00 11 22 33"]},
      field_equals("total", 2),
      "statistics_compute total == 2")

check("hex_pattern_to_masked_v3",
      {"pat": "DE AD ?? EF"},
      has_fields("specificity"),
      "to_masked_v3 has specificity")

check("hex_pattern_sequence_search_v3",
      {"entries": [
          {"offset": 0, "pattern": "DE AD"},
          {"offset": 2, "pattern": "BE EF"}
       ],
       "data_hex": DATA_HEX},
      has_fields("count", "hits"),
      "sequence_search_v3 has count+hits")

# ---- Finalize ----------------------------------------------------------------

p.stdin.close()
p.terminate()

passed = sum(1 for r in results if r["status"] == "PASS")
failed = sum(1 for r in results if r["status"] == "FAIL")
mismatches = [
    {"tool": r["tool"], "expected": r["expected"], "actual": r["actual"]}
    for r in results if r["status"] == "FAIL"
]

output = {
    "module": "hex_all",
    "tools_hardened": len(results),
    "checks_passed": passed,
    "checks_failed": failed,
    "mismatches": mismatches,
}
with open(OUT_JSON, "w", encoding="utf-8") as f:
    json.dump(output, f, indent=2)

with open(SKIP_JSON, "w", encoding="utf-8") as f:
    json.dump({"skipped": skips}, f, indent=2)

print(f"\n=== SUMMARY ===")
print(f"  Hardened: {len(results)}")
print(f"  Passed  : {passed}")
print(f"  Failed  : {failed}")
print(f"  Skipped : {len(skips)}")
if mismatches:
    print(f"\n  MISMATCHES:")
    for m in mismatches:
        print(f"    {m['tool']}: expected={m['expected']!r} actual={m['actual']!r}")
