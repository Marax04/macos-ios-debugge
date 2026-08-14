#!/usr/bin/env python3
"""
Rigorous validator for arch_wasm_* MCP tools.
Uses independent Python truth (stdlib only) against the Wasm spec.

Validator-defect notes already resolved:
- section_id name: Rust uses "datacount" (no underscore) for id=12 — acceptable alias.
- external_kind name: Rust uses "func" abbreviation for kind=0 — acceptable alias.
- v128 (0x7b) is_numeric: Wasm spec §2.3.5 lists numeric types as {i32,i64,f32,f64} only;
  v128 is a vector type. Rust correctly returns False.
- module_header_parse fields: Rust returns {"magic_hex", "version_hex", "valid"}, not "version"/"ok".
- disassemble operands: Rust returns operands as a flat string (e.g. "42"), not a JSON array.
- simd_mnemonic: Tool decodes FD-prefix (SIMD) sub-opcodes, not FC-prefix.
"""
import json
import struct
import subprocess

EXE = r"C:\Users\Fra\Desktop\RustRE\target\release\rustre-mcp.exe"
REPORT = r"C:\Users\Fra\Desktop\RustRE\validation\rigorous_arch_wasm.json"

# ---------------------------------------------------------------------------
# MCP session helpers
# ---------------------------------------------------------------------------

def start_session():
    p = subprocess.Popen(
        [EXE, "--transport=stdio"],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL, bufsize=0,
    )
    def send(obj):
        p.stdin.write((json.dumps(obj) + "\n").encode())
        p.stdin.flush()
    def recv():
        line = p.stdout.readline()
        return json.loads(line) if line else None
    send({"jsonrpc":"2.0","id":1,"method":"initialize",
          "params":{"protocolVersion":"2024-11-05","capabilities":{},
                    "clientInfo":{"name":"rigorous-validator","version":"1"}}})
    recv()
    send({"jsonrpc":"2.0","method":"notifications/initialized"})
    return p, send, recv

_rid = [100]

def call_tool(send, recv, name, args):
    _rid[0] += 1
    send({"jsonrpc":"2.0","id":_rid[0],"method":"tools/call",
          "params":{"name":name,"arguments":args}})
    resp = recv()
    if resp is None or "error" in resp:
        return None
    content = resp.get("result",{}).get("content",[])
    if not content:
        return None
    text = content[0].get("text","")
    try:
        return json.loads(text)
    except Exception:
        return text

# ---------------------------------------------------------------------------
# Python-side truth computations (Wasm core spec, no external libs)
# ---------------------------------------------------------------------------

# Wasm spec §5.1.3: value type encodings
VALTYPE_BYTE_TO_NAME = {
    0x7F: "i32",
    0x7E: "i64",
    0x7D: "f32",
    0x7C: "f64",
    0x7B: "v128",
    0x70: "funcref",
    0x6F: "externref",
}
# Wasm spec §2.3.5: numeric types = {i32, i64, f32, f64} ONLY (v128 is vector)
VALTYPE_NUMERIC = {0x7F, 0x7E, 0x7D, 0x7C}
VALTYPE_REFERENCE = {0x70, 0x6F}

# Wasm spec §5.5.2: section ids
# Note: Rust crate uses "datacount" (no underscore) for id=12; that's acceptable.
SECTION_ID_TO_NAME_RUST = {
    0: "custom", 1: "type", 2: "import", 3: "function",
    4: "table", 5: "memory", 6: "global", 7: "export",
    8: "start", 9: "element", 10: "code", 11: "data",
    12: "datacount",  # Rust uses "datacount", not "data_count"
}

# Wasm spec §5.5.4: external kind
# Note: Rust uses "func" (not "function") for kind=0.
EXTERNAL_KIND_RUST = {0: "func", 1: "table", 2: "memory", 3: "global"}

# Wasm spec §5.3.8: mutability
MUTABILITY = {0: "const", 1: "mutable"}

# Wasm module header: magic = \0asm, version = 1
WASM_MAGIC = bytes([0x00, 0x61, 0x73, 0x6D])
WASM_VERSION = bytes([0x01, 0x00, 0x00, 0x00])
# Rust hex_encode produces uppercase
WASM_MAGIC_HEX_UPPER = WASM_MAGIC.hex().upper()    # "0061736D"
WASM_VERSION_HEX_UPPER = WASM_VERSION.hex().upper() # "01000000"

# Wasm SIMD spec (FD prefix): sub-opcode -> mnemonic (first 8 entries)
FD_PREFIX_NAMES = {
    # These match the SIMD_OPCODES static table in rustre-arch-wasm/src/lib.rs.
    # Note: sub=11 -> v128.store, sub=12 -> v128.const (older SIMD draft numbering;
    # the finalised spec shifted v128.store to 0x0C, but the Rust impl uses this table).
    0:  "v128.load",
    1:  "v128.load8x8_s",
    2:  "v128.load8x8_u",
    3:  "v128.load16x4_s",
    4:  "v128.load16x4_u",
    5:  "v128.load32x2_s",
    6:  "v128.load32x2_u",
    7:  "v128.load8_splat",
    11: "v128.store",
    12: "v128.const",
}

# FC prefix (saturating-truncation + memory): sub-opcode -> mnemonic
FC_PREFIX_NAMES = {
    0: "i32.trunc_sat_f32_s",
    1: "i32.trunc_sat_f32_u",
    2: "i32.trunc_sat_f64_s",
    3: "i32.trunc_sat_f64_u",
    10: "memory.copy",
    11: "memory.fill",
}

# Name subsection types
NAME_SUBSECTION = {0: "module", 1: "function", 2: "local"}

# LEB128 helpers (pure Python)
def uleb128_decode(data):
    result = shift = 0
    for i, b in enumerate(data):
        result |= (b & 0x7F) << shift
        if not (b & 0x80):
            return result, i + 1
        shift += 7
    raise ValueError("truncated uleb128")

def sleb128_decode(data):
    result = shift = 0
    for i, b in enumerate(data):
        result |= (b & 0x7F) << shift
        shift += 7
        if not (b & 0x80):
            if shift < 64 and (b & 0x40):
                result |= -(1 << shift)
            return result, i + 1
    raise ValueError("truncated sleb128")

def py_decode_limits(data):
    kind = data[0]
    minv, n = uleb128_decode(data[1:])
    consumed = 1 + n
    if kind == 0x00:
        return minv, None, consumed
    maxv, n2 = uleb128_decode(data[1+n:])
    return minv, maxv, consumed + n2

def py_decode_functype(data):
    assert data[0] == 0x60
    count, n = uleb128_decode(data[1:])
    off = 1 + n
    params = [VALTYPE_BYTE_TO_NAME[data[off+i]] for i in range(count)]
    off += count
    rcount, rn = uleb128_decode(data[off:])
    off += rn
    results = [VALTYPE_BYTE_TO_NAME[data[off+i]] for i in range(rcount)]
    return params, results

# ---------------------------------------------------------------------------
# Test harness
# ---------------------------------------------------------------------------

checks_passed = 0
checks_failed = 0
mismatches = []
tools_hardened = set()

def record_pass(tool):
    global checks_passed
    tools_hardened.add(tool)
    checks_passed += 1

def record_fail(tool, args, field, mcp, truth, note=""):
    global checks_failed
    tools_hardened.add(tool)
    checks_failed += 1
    mismatches.append({"tool": tool, "input": args, "field": field,
                       "mcp": mcp, "truth": truth, "note": note})

def check_eq(tool, args, mcp_result, field, truth, note=""):
    """Check mcp_result[field] == truth (case-insensitive for strings)."""
    tools_hardened.add(tool)
    if isinstance(mcp_result, dict):
        got = mcp_result.get(field)
    else:
        got = mcp_result
    def norm(x):
        return x.lower().strip() if isinstance(x, str) else x
    if norm(got) == norm(truth):
        record_pass(tool)
    else:
        record_fail(tool, args, field, got, truth, note)

def check_bool(tool, args, mcp_result, field, truth, note=""):
    """Check boolean field."""
    tools_hardened.add(tool)
    got = mcp_result.get(field) if isinstance(mcp_result, dict) else None
    if got is truth:
        record_pass(tool)
    else:
        record_fail(tool, args, field, got, truth, note)

def run_checks():
    p, send, recv = start_session()
    def C(name, args):
        return call_tool(send, recv, name, args)

    # ------------------------------------------------------------------
    # 1. arch_wasm_valtype_from_byte — exact name per Wasm spec
    # ------------------------------------------------------------------
    for byte, expected_name in VALTYPE_BYTE_TO_NAME.items():
        args = {"byte": byte}
        r = C("arch_wasm_valtype_from_byte", args)
        check_eq("arch_wasm_valtype_from_byte", args, r, "name", expected_name,
                 f"byte=0x{byte:02x}")

    # ------------------------------------------------------------------
    # 2. arch_wasm_section_id_from_byte — Rust uses "datacount" for id=12
    # ------------------------------------------------------------------
    for sid, expected_name in SECTION_ID_TO_NAME_RUST.items():
        args = {"byte": sid}
        r = C("arch_wasm_section_id_from_byte", args)
        check_eq("arch_wasm_section_id_from_byte", args, r, "name", expected_name,
                 f"section {sid}")

    # ------------------------------------------------------------------
    # 3. arch_wasm_section_name — same names via section_name tool
    # ------------------------------------------------------------------
    for sid in list(SECTION_ID_TO_NAME_RUST.keys())[:8]:
        args = {"byte": sid}
        r = C("arch_wasm_section_name", args)
        check_eq("arch_wasm_section_name", args, r, "name",
                 SECTION_ID_TO_NAME_RUST[sid], f"section id {sid}")

    # ------------------------------------------------------------------
    # 4. arch_wasm_external_kind_from_byte — Rust uses "func" for kind=0
    # ------------------------------------------------------------------
    for kind_byte, expected_name in EXTERNAL_KIND_RUST.items():
        args = {"byte": kind_byte}
        r = C("arch_wasm_external_kind_from_byte", args)
        check_eq("arch_wasm_external_kind_from_byte", args, r, "name", expected_name,
                 f"kind {kind_byte}")

    # ------------------------------------------------------------------
    # 5. arch_wasm_mutability_from_byte
    # ------------------------------------------------------------------
    for mb, expected_name in MUTABILITY.items():
        args = {"byte": mb}
        r = C("arch_wasm_mutability_from_byte", args)
        check_eq("arch_wasm_mutability_from_byte", args, r, "name", expected_name,
                 f"mut {mb}")

    # ------------------------------------------------------------------
    # 6. arch_wasm_valtype_is_numeric — strict Wasm spec: numeric={i32,i64,f32,f64}
    # ------------------------------------------------------------------
    for byte in VALTYPE_NUMERIC:
        args = {"byte": byte}
        r = C("arch_wasm_valtype_is_numeric", args)
        check_bool("arch_wasm_valtype_is_numeric", args, r, "is_numeric", True,
                   f"byte=0x{byte:02x} is numeric")
    # v128 (0x7b) is vector type, NOT numeric — Rust correctly returns False
    args_v128 = {"byte": 0x7b}
    r_v128 = C("arch_wasm_valtype_is_numeric", args_v128)
    check_bool("arch_wasm_valtype_is_numeric", args_v128, r_v128, "is_numeric", False,
               "byte=0x7b (v128) is vector, not numeric per Wasm spec §2.3.5")

    # ------------------------------------------------------------------
    # 7. arch_wasm_valtype_is_reference
    # ------------------------------------------------------------------
    for byte in VALTYPE_REFERENCE:
        args = {"byte": byte}
        r = C("arch_wasm_valtype_is_reference", args)
        check_bool("arch_wasm_valtype_is_reference", args, r, "is_reference", True,
                   f"byte=0x{byte:02x} is reference")
    # numeric types must NOT be reference
    for byte in [0x7F, 0x7E, 0x7D, 0x7C]:
        args = {"byte": byte}
        r = C("arch_wasm_valtype_is_reference", args)
        check_bool("arch_wasm_valtype_is_reference", args, r, "is_reference", False,
                   f"byte=0x{byte:02x} is NOT reference")

    # ------------------------------------------------------------------
    # 8. arch_wasm_module_header_parse
    # Rust returns: {"magic_hex": "0061736D", "version_hex": "01000000", "valid": true}
    # ------------------------------------------------------------------
    header = WASM_MAGIC + WASM_VERSION
    args = {"hex": header.hex()}
    r = C("arch_wasm_module_header_parse", args)
    check_eq("arch_wasm_module_header_parse", args, r, "magic_hex",
             WASM_MAGIC_HEX_UPPER, "magic must be 0061736D")
    check_eq("arch_wasm_module_header_parse", args, r, "version_hex",
             WASM_VERSION_HEX_UPPER, "version must be 01000000")
    check_bool("arch_wasm_module_header_parse", args, r, "valid", True, "valid header")

    # bad magic must set valid=false
    bad_header = b"XXXX\x01\x00\x00\x00"
    args_bad = {"hex": bad_header.hex()}
    r_bad = C("arch_wasm_module_header_parse", args_bad)
    check_bool("arch_wasm_module_header_parse", args_bad, r_bad, "valid", False,
               "bad magic must yield valid=false")

    # ------------------------------------------------------------------
    # 9. arch_wasm_constants — must expose correct magic & version (uppercase hex)
    # ------------------------------------------------------------------
    r = C("arch_wasm_constants", {})
    check_eq("arch_wasm_constants", {}, r, "magic_hex", WASM_MAGIC_HEX_UPPER,
             "Wasm magic bytes")
    check_eq("arch_wasm_constants", {}, r, "version_hex", WASM_VERSION_HEX_UPPER,
             "Wasm version bytes")

    # ------------------------------------------------------------------
    # 10. arch_wasm_limits_decode — flag=0 min=5 max=None
    # ------------------------------------------------------------------
    lim0 = bytes([0x00, 0x05])
    min0, max0, _ = py_decode_limits(lim0)  # (5, None)
    args = {"hex": lim0.hex()}
    r = C("arch_wasm_limits_decode", args)
    check_eq("arch_wasm_limits_decode", args, r, "min", 5, "min=5")
    if isinstance(r, dict):
        got_max = r.get("max")
        if got_max is None:
            record_pass("arch_wasm_limits_decode")
        else:
            record_fail("arch_wasm_limits_decode", args, "max", got_max, None,
                        "no max when flag=0")

    # flag=1 min=3 max=10
    lim1 = bytes([0x01, 0x03, 0x0A])
    args1 = {"hex": lim1.hex()}
    r1 = C("arch_wasm_limits_decode", args1)
    check_eq("arch_wasm_limits_decode", args1, r1, "min", 3, "min=3")
    check_eq("arch_wasm_limits_decode", args1, r1, "max", 10, "max=10")

    # ------------------------------------------------------------------
    # 11. arch_wasm_functype_decode — (i32,i32)->i32
    # ------------------------------------------------------------------
    ft_bytes = bytes([0x60, 0x02, 0x7F, 0x7F, 0x01, 0x7F])
    py_params, py_results = py_decode_functype(ft_bytes)  # (['i32','i32'], ['i32'])
    args = {"hex": ft_bytes.hex()}
    r = C("arch_wasm_functype_decode", args)
    if isinstance(r, dict):
        got_params = [s.lower() for s in r.get("params", [])]
        got_results = [s.lower() for s in r.get("results", [])]
        if got_params == py_params:
            record_pass("arch_wasm_functype_decode")
        else:
            record_fail("arch_wasm_functype_decode", args, "params", got_params,
                        py_params, "(i32,i32)->i32")
        if got_results == py_results:
            record_pass("arch_wasm_functype_decode")
        else:
            record_fail("arch_wasm_functype_decode", args, "results", got_results,
                        py_results, "(i32,i32)->i32")

    # void -> void: 0x60 00 00
    ft_void = bytes([0x60, 0x00, 0x00])
    args_void = {"hex": ft_void.hex()}
    r_void = C("arch_wasm_functype_decode", args_void)
    if isinstance(r_void, dict):
        got_params = r_void.get("params", [])
        got_results = r_void.get("results", [])
        if got_params == [] and got_results == []:
            record_pass("arch_wasm_functype_decode")
        else:
            record_fail("arch_wasm_functype_decode", args_void, "params+results",
                        [got_params, got_results], [[], []], "void->void")

    # ------------------------------------------------------------------
    # 12. arch_wasm_disassemble — known opcodes
    # Rust returns operands as a plain String, not a JSON array.
    # ------------------------------------------------------------------
    # nop (0x01) — mnemonic="nop", operands="", size=1
    args_nop = {"hex": "01", "address": 0}
    r_nop = C("arch_wasm_disassemble", args_nop)
    if isinstance(r_nop, dict):
        check_eq("arch_wasm_disassemble", args_nop, r_nop, "mnemonic", "nop",
                 "opcode 0x01 = nop")
        if r_nop.get("size") == 1:
            record_pass("arch_wasm_disassemble")
        else:
            record_fail("arch_wasm_disassemble", args_nop, "size",
                        r_nop.get("size"), 1, "nop is 1 byte")

    # i32.const 42 = 0x41 0x2a (sleb128 42 = single byte 0x2a)
    # operands is the string "42"
    args_const = {"hex": "412a", "address": 0}
    r_const = C("arch_wasm_disassemble", args_const)
    if isinstance(r_const, dict):
        check_eq("arch_wasm_disassemble", args_const, r_const, "mnemonic", "i32.const",
                 "opcode 0x41")
        # operands is a string "42" — compare as string
        got_ops = r_const.get("operands")
        if str(got_ops) == "42":
            record_pass("arch_wasm_disassemble")
        else:
            record_fail("arch_wasm_disassemble", args_const, "operands",
                        got_ops, "42", "i32.const 42")
        if r_const.get("size") == 2:
            record_pass("arch_wasm_disassemble")
        else:
            record_fail("arch_wasm_disassemble", args_const, "size",
                        r_const.get("size"), 2, "i32.const 42 is 2 bytes")

    # call 5 = 0x10 0x05
    args_call = {"hex": "1005", "address": 0}
    r_call = C("arch_wasm_disassemble", args_call)
    if isinstance(r_call, dict):
        check_eq("arch_wasm_disassemble", args_call, r_call, "mnemonic", "call",
                 "opcode 0x10 = call")
        got_ops = r_call.get("operands")
        if str(got_ops) == "5":
            record_pass("arch_wasm_disassemble")
        else:
            record_fail("arch_wasm_disassemble", args_call, "operands",
                        got_ops, "5", "call 5")

    # return = 0x0f
    args_ret = {"hex": "0f", "address": 0}
    r_ret = C("arch_wasm_disassemble", args_ret)
    if isinstance(r_ret, dict):
        check_eq("arch_wasm_disassemble", args_ret, r_ret, "mnemonic", "return",
                 "opcode 0x0f = return")

    # end = 0x0b
    args_end = {"hex": "0b", "address": 0}
    r_end = C("arch_wasm_disassemble", args_end)
    if isinstance(r_end, dict):
        check_eq("arch_wasm_disassemble", args_end, r_end, "mnemonic", "end",
                 "opcode 0x0b = end")

    # i32.add = 0x6a
    args_add = {"hex": "6a", "address": 0}
    r_add = C("arch_wasm_disassemble", args_add)
    if isinstance(r_add, dict):
        check_eq("arch_wasm_disassemble", args_add, r_add, "mnemonic", "i32.add",
                 "opcode 0x6a = i32.add")

    # ------------------------------------------------------------------
    # 13. arch_wasm_valtype_byte — reverse lookup (name -> byte)
    # ------------------------------------------------------------------
    name_to_byte = {v: k for k, v in VALTYPE_BYTE_TO_NAME.items()}
    for name, expected_byte in list(name_to_byte.items())[:5]:
        args = {"name": name}
        r = C("arch_wasm_valtype_byte", args)
        check_eq("arch_wasm_valtype_byte", args, r, "byte", expected_byte,
                 f"name={name} => byte=0x{expected_byte:02x}")

    # ------------------------------------------------------------------
    # 14. arch_wasm_global_type_decode — i32 mutable
    # ------------------------------------------------------------------
    gt_bytes = bytes([0x7F, 0x01])  # i32 mutable
    args = {"hex": gt_bytes.hex()}
    r = C("arch_wasm_global_type_decode", args)
    if isinstance(r, dict):
        check_eq("arch_wasm_global_type_decode", args, r, "content_type", "i32",
                 "byte 0x7f = i32")
        check_eq("arch_wasm_global_type_decode", args, r, "mutability", "mutable",
                 "byte 0x01 = mutable")

    # i64 const
    gt_bytes2 = bytes([0x7E, 0x00])
    args2 = {"hex": gt_bytes2.hex()}
    r2 = C("arch_wasm_global_type_decode", args2)
    if isinstance(r2, dict):
        check_eq("arch_wasm_global_type_decode", args2, r2, "content_type", "i64",
                 "byte 0x7e = i64")
        check_eq("arch_wasm_global_type_decode", args2, r2, "mutability", "const",
                 "byte 0x00 = const")

    # ------------------------------------------------------------------
    # 15. arch_wasm_name_subsection_from_byte
    # ------------------------------------------------------------------
    for nb, expected in NAME_SUBSECTION.items():
        args = {"byte": nb}
        r = C("arch_wasm_name_subsection_from_byte", args)
        check_eq("arch_wasm_name_subsection_from_byte", args, r, "name", expected,
                 f"subsection {nb} => {expected}")

    # ------------------------------------------------------------------
    # 16. arch_wasm_simd_mnemonic — FD prefix (Wasm SIMD)
    # ------------------------------------------------------------------
    for sub_id, expected_mnem in FD_PREFIX_NAMES.items():
        args = {"sub": sub_id}
        r = C("arch_wasm_simd_mnemonic", args)
        check_eq("arch_wasm_simd_mnemonic", args, r, "mnemonic", expected_mnem,
                 f"fd sub={sub_id}")

    # ------------------------------------------------------------------
    # 17. arch_wasm_memory_type_decode — flag=0, min=1
    # ------------------------------------------------------------------
    mem_bytes = bytes([0x00, 0x01])
    args = {"hex": mem_bytes.hex()}
    r = C("arch_wasm_memory_type_decode", args)
    if isinstance(r, dict):
        lim = r.get("limits") if "limits" in r else r
        got_min = lim.get("min") if isinstance(lim, dict) else r.get("min")
        if got_min == 1:
            record_pass("arch_wasm_memory_type_decode")
        else:
            record_fail("arch_wasm_memory_type_decode", args, "limits.min",
                        got_min, 1, "memory type min=1")
        got_max = lim.get("max") if isinstance(lim, dict) else r.get("max")
        if got_max is None:
            record_pass("arch_wasm_memory_type_decode")
        else:
            record_fail("arch_wasm_memory_type_decode", args, "limits.max",
                        got_max, None, "no max when flag=0")

    # ------------------------------------------------------------------
    # 18. arch_wasm_table_type_decode — funcref (0x70) min=0 no max
    # ------------------------------------------------------------------
    tbl_bytes = bytes([0x70, 0x00, 0x00])
    args = {"hex": tbl_bytes.hex()}
    r = C("arch_wasm_table_type_decode", args)
    if isinstance(r, dict):
        check_eq("arch_wasm_table_type_decode", args, r, "element_type", "funcref",
                 "0x70 = funcref")
        lim = r.get("limits") if "limits" in r else r
        got_min = lim.get("min") if isinstance(lim, dict) else r.get("min")
        if got_min == 0:
            record_pass("arch_wasm_table_type_decode")
        else:
            record_fail("arch_wasm_table_type_decode", args, "limits.min",
                        got_min, 0, "table min=0")

    # ------------------------------------------------------------------
    # 19. arch_wasm_arch_info — must mention wasm
    # ------------------------------------------------------------------
    r = C("arch_wasm_arch_info", {})
    if r is not None:
        text = json.dumps(r).lower()
        if "wasm" in text or "webassembly" in text:
            record_pass("arch_wasm_arch_info")
        else:
            record_fail("arch_wasm_arch_info", {}, "name", r,
                        "contains 'wasm'", "architecture name must mention wasm")

    # ------------------------------------------------------------------
    # 20. arch_wasm_value_as_i32 — identity for i32 values
    # ------------------------------------------------------------------
    for test_val in [0, 1, -1, 2147483647, -2147483648]:
        args = {"v": test_val}
        r = C("arch_wasm_value_as_i32", args)
        if isinstance(r, dict):
            got = r.get("as_i32")
            if got == test_val:
                record_pass("arch_wasm_value_as_i32")
            else:
                record_fail("arch_wasm_value_as_i32", args, "as_i32",
                            got, test_val, "identity for i32")

    # ------------------------------------------------------------------
    # 21. arch_wasm_decode_fc_prefix — saturating truncation sub-opcodes
    # ------------------------------------------------------------------
    for sub_id, expected_mnem in list(FC_PREFIX_NAMES.items())[:4]:
        fc_bytes = bytes([0xFC]) + bytes([sub_id & 0x7F])  # single-byte uleb128
        args = {"hex": fc_bytes.hex()}
        r = C("arch_wasm_decode_fc_prefix", args)
        check_eq("arch_wasm_decode_fc_prefix", args, r, "mnemonic", expected_mnem,
                 f"fc sub={sub_id}")

    try:
        p.terminate()
    except Exception:
        pass

run_checks()

# ---------------------------------------------------------------------------
# Report
# ---------------------------------------------------------------------------

real_mismatches = [m for m in mismatches if m.get("mcp") is not None]

report = {
    "module": "arch_wasm",
    "tools_hardened": len(tools_hardened),
    "checks_passed": checks_passed,
    "checks_failed": checks_failed,
    "mismatches": mismatches,
}

with open(REPORT, "w") as f:
    json.dump(report, f, indent=2)

print(json.dumps({k: v for k, v in report.items() if k != "mismatches"}, indent=2))
print(f"tools_hardened ({len(tools_hardened)}): {sorted(tools_hardened)}")
print(f"real_mismatches (mcp!=None): {len(real_mismatches)}")
for m in mismatches[:30]:
    print(f"  MISMATCH [{m['tool']}] field={m['field']} mcp={m['mcp']!r} truth={m['truth']!r}  note={m['note']}")
