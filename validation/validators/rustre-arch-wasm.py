#!/usr/bin/env python3
"""Independent Python validator for the rustre-arch-wasm crate.

Reimplements the same logic using only the Python standard library so its
outputs can be diffed against the Rust crate's behaviour.
"""

import json
import struct
import sys
from typing import Any, Dict, List, Optional, Tuple

# ---------------------------------------------------------------------------
# Constants (Wasm core spec §5)
# ---------------------------------------------------------------------------

WASM_MAGIC = bytes([0x00, 0x61, 0x73, 0x6D])
WASM_VERSION = bytes([0x01, 0x00, 0x00, 0x00])

VALUE_TYPES = {
    0x7F: "i32",
    0x7E: "i64",
    0x7D: "f32",
    0x7C: "f64",
    0x7B: "v128",
    0x70: "funcref",
    0x6F: "externref",
}
NUMERIC_VT = {0x7F, 0x7E, 0x7D, 0x7C, 0x7B}
REFERENCE_VT = {0x70, 0x6F}

SECTION_IDS = {
    0: "custom", 1: "type", 2: "import", 3: "function",
    4: "table", 5: "memory", 6: "global", 7: "export",
    8: "start", 9: "element", 10: "code", 11: "data",
    12: "data_count",
}

EXTERNAL_KINDS = {0: "function", 1: "table", 2: "memory", 3: "global"}
MUTABILITY = {0: "const", 1: "mutable"}

MAX_TYPE_COUNT = 32_768

# ---------------------------------------------------------------------------
# LEB128 codec (matches wasm_type_system::{encode,decode}_{u,s}leb128)
# ---------------------------------------------------------------------------

def validator_encode_uleb128(value: int) -> List[int]:
    out = []
    v = value & 0xFFFFFFFFFFFFFFFF
    while True:
        byte = v & 0x7F
        v >>= 7
        if v != 0:
            out.append(byte | 0x80)
        else:
            out.append(byte)
            return out

def validator_decode_uleb128(data: bytes) -> Tuple[int, int]:
    result = 0
    shift = 0
    for i, b in enumerate(data):
        result |= (b & 0x7F) << shift
        if (b & 0x80) == 0:
            return result, i + 1
        shift += 7
        if shift >= 64:
            raise ValueError("uleb128 overflow")
    raise ValueError("uleb128 truncated")

def validator_encode_sleb128(value: int) -> List[int]:
    out = []
    more = True
    v = value
    while more:
        byte = v & 0x7F
        v >>= 7
        sign = byte & 0x40
        if (v == 0 and sign == 0) or (v == -1 and sign != 0):
            more = False
            out.append(byte)
        else:
            out.append(byte | 0x80)
    return out

def validator_decode_sleb128(data: bytes) -> Tuple[int, int]:
    result = 0
    shift = 0
    for i, b in enumerate(data):
        result |= (b & 0x7F) << shift
        shift += 7
        if (b & 0x80) == 0:
            if shift < 64 and (b & 0x40):
                result |= -(1 << shift)
            return result, i + 1
        if shift >= 64:
            raise ValueError("sleb128 overflow")
    raise ValueError("sleb128 truncated")

# ---------------------------------------------------------------------------
# Module header / valtype / section id / extern kind / mutability
# ---------------------------------------------------------------------------

def validator_parse_module_header(data: bytes) -> Dict[str, Any]:
    if len(data) < 8:
        return {"ok": False, "error": "too_short"}
    magic = data[0:4]
    version = data[4:8]
    if magic != WASM_MAGIC:
        return {"ok": False, "error": "bad_magic", "magic": list(magic)}
    if version != WASM_VERSION:
        return {"ok": False, "error": "bad_version", "version": list(version)}
    return {"ok": True, "magic": list(magic), "version": list(version)}

def validator_value_type_from_byte(b: int) -> Dict[str, Any]:
    if b in VALUE_TYPES:
        name = VALUE_TYPES[b]
        return {
            "ok": True, "name": name, "byte": b,
            "is_numeric": b in NUMERIC_VT,
            "is_reference": b in REFERENCE_VT,
        }
    return {"ok": False}

def validator_section_id_from_byte(b: int) -> Dict[str, Any]:
    if b in SECTION_IDS:
        return {"ok": True, "id": b, "name": SECTION_IDS[b]}
    return {"ok": False}

def validator_external_kind_from_byte(b: int) -> Dict[str, Any]:
    if b in EXTERNAL_KINDS:
        return {"ok": True, "kind": EXTERNAL_KINDS[b]}
    return {"ok": False}

def validator_mutability_from_byte(b: int) -> Dict[str, Any]:
    if b in MUTABILITY:
        return {"ok": True, "mutability": MUTABILITY[b]}
    return {"ok": False}

# ---------------------------------------------------------------------------
# Limits / FuncType / GlobalType / TableType / MemoryType
# ---------------------------------------------------------------------------

def validator_decode_limits(data: bytes) -> Dict[str, Any]:
    if len(data) < 2:
        return {"ok": False, "error": "too_short"}
    kind = data[0]
    minv, n1 = validator_decode_uleb128(data[1:])
    consumed = 1 + n1
    if kind == 0x00:
        return {"ok": True, "min": minv, "max": None, "size": consumed}
    if kind == 0x01:
        maxv, n2 = validator_decode_uleb128(data[1 + n1:])
        return {"ok": True, "min": minv, "max": maxv, "size": consumed + n2}
    return {"ok": False, "error": "bad_kind", "kind": kind}

def _decode_vt_vec(data: bytes) -> Tuple[List[str], int]:
    count, n = validator_decode_uleb128(data)
    if count > MAX_TYPE_COUNT:
        raise ValueError("type vec too large")
    types = []
    off = n
    for _ in range(count):
        b = data[off]
        if b not in VALUE_TYPES:
            raise ValueError(f"bad valtype 0x{b:02x}")
        types.append(VALUE_TYPES[b])
        off += 1
    return types, off

def validator_decode_func_type(data: bytes) -> Dict[str, Any]:
    if not data or data[0] != 0x60:
        return {"ok": False, "error": "missing_0x60"}
    try:
        params, p_off = _decode_vt_vec(data[1:])
        results, r_off = _decode_vt_vec(data[1 + p_off:])
    except (ValueError, IndexError) as e:
        return {"ok": False, "error": str(e)}
    size = 1 + p_off + r_off
    return {
        "ok": True, "params": params, "results": results,
        "arity": [len(params), len(results)], "size": size,
    }

def validator_decode_global_type(data: bytes) -> Dict[str, Any]:
    if len(data) < 2:
        return {"ok": False, "error": "too_short"}
    ct = data[0]
    mut = data[1]
    if ct not in VALUE_TYPES or mut not in MUTABILITY:
        return {"ok": False}
    return {
        "ok": True,
        "content_type": VALUE_TYPES[ct],
        "mutability": MUTABILITY[mut],
        "size": 2,
    }

def validator_decode_table_type(data: bytes) -> Dict[str, Any]:
    if not data:
        return {"ok": False, "error": "too_short"}
    et = data[0]
    if et not in REFERENCE_VT:
        return {"ok": False, "error": "bad_elem_type"}
    lim = validator_decode_limits(data[1:])
    if not lim.get("ok"):
        return {"ok": False, "error": "bad_limits"}
    return {
        "ok": True,
        "element_type": VALUE_TYPES[et],
        "limits": {"min": lim["min"], "max": lim["max"]},
        "size": 1 + lim["size"],
    }

def validator_decode_memory_type(data: bytes) -> Dict[str, Any]:
    lim = validator_decode_limits(data)
    if not lim.get("ok"):
        return {"ok": False}
    return {"ok": True, "limits": {"min": lim["min"], "max": lim["max"]}, "size": lim["size"]}

# ---------------------------------------------------------------------------
# Minimal disassembler — a representative subset of opcodes
# ---------------------------------------------------------------------------

# (mnemonic, immediate spec, flags)
# imm spec: list of 'u' (uleb), 's' (sleb32/64), 'f32', 'f64', 'byte',
#           'memarg' (two ulebs), 'brtable'
SIMPLE_OPCODES = {
    0x00: ("unreachable", [], ["BARRIER"]),
    0x01: ("nop", [], []),
    0x02: ("block", ["byte"], []),
    0x03: ("loop", ["byte"], []),
    0x04: ("if", ["byte"], ["BRANCH", "CONDITIONAL"]),
    0x05: ("else", [], ["BRANCH"]),
    0x0B: ("end", [], []),
    0x0C: ("br", ["u"], ["BRANCH"]),
    0x0D: ("br_if", ["u"], ["BRANCH", "CONDITIONAL"]),
    0x0E: ("br_table", ["brtable"], ["BRANCH", "INDIRECT"]),
    0x0F: ("return", [], ["RET"]),
    0x10: ("call", ["u"], ["CALL"]),
    0x11: ("call_indirect", ["u", "u"], ["CALL", "INDIRECT"]),
    0x1A: ("drop", [], []),
    0x1B: ("select", [], []),
    0x20: ("local.get", ["u"], []),
    0x21: ("local.set", ["u"], []),
    0x22: ("local.tee", ["u"], []),
    0x23: ("global.get", ["u"], []),
    0x24: ("global.set", ["u"], []),
    0x28: ("i32.load", ["memarg"], ["READ_MEM"]),
    0x29: ("i64.load", ["memarg"], ["READ_MEM"]),
    0x2A: ("f32.load", ["memarg"], ["READ_MEM"]),
    0x2B: ("f64.load", ["memarg"], ["READ_MEM"]),
    0x36: ("i32.store", ["memarg"], ["WRITE_MEM"]),
    0x37: ("i64.store", ["memarg"], ["WRITE_MEM"]),
    0x38: ("f32.store", ["memarg"], ["WRITE_MEM"]),
    0x39: ("f64.store", ["memarg"], ["WRITE_MEM"]),
    0x41: ("i32.const", ["s"], []),
    0x42: ("i64.const", ["s"], []),
    0x43: ("f32.const", ["f32"], []),
    0x44: ("f64.const", ["f64"], []),
    0x6A: ("i32.add", [], []),
    0x6B: ("i32.sub", [], []),
    0x6C: ("i32.mul", [], []),
}

def validator_disassemble(address: int, data: bytes) -> Dict[str, Any]:
    if not data:
        return {"ok": False, "error": "empty"}
    opcode = data[0]
    if opcode not in SIMPLE_OPCODES:
        return {"ok": False, "error": f"unknown_opcode_0x{opcode:02x}"}
    mnemonic, imm_spec, flags = SIMPLE_OPCODES[opcode]
    off = 1
    operands: List[Any] = []
    try:
        for spec in imm_spec:
            if spec == "u":
                v, n = validator_decode_uleb128(data[off:])
                operands.append(v)
                off += n
            elif spec == "s":
                v, n = validator_decode_sleb128(data[off:])
                operands.append(v)
                off += n
            elif spec == "byte":
                operands.append(data[off])
                off += 1
            elif spec == "f32":
                operands.append(struct.unpack("<f", data[off:off + 4])[0])
                off += 4
            elif spec == "f64":
                operands.append(struct.unpack("<d", data[off:off + 8])[0])
                off += 8
            elif spec == "memarg":
                a, n1 = validator_decode_uleb128(data[off:])
                o, n2 = validator_decode_uleb128(data[off + n1:])
                operands.append({"align": a, "offset": o})
                off += n1 + n2
            elif spec == "brtable":
                count, n = validator_decode_uleb128(data[off:])
                if count > 65_536:
                    return {"ok": False, "error": "brtable_too_large"}
                off += n
                targets = []
                for _ in range(count + 1):  # n labels + default
                    v, k = validator_decode_uleb128(data[off:])
                    targets.append(v)
                    off += k
                operands.append(targets)
    except (ValueError, IndexError, struct.error) as e:
        return {"ok": False, "error": f"decode_failed: {e}"}
    return {
        "ok": True,
        "address": address,
        "mnemonic": mnemonic,
        "operands": operands,
        "size": off,
        "flags": flags,
        "bytes": list(data[:off]),
    }

# ---------------------------------------------------------------------------
# Dispatcher
# ---------------------------------------------------------------------------

DISPATCH = {
    "encode_uleb128": lambda i: validator_encode_uleb128(i["value"]),
    "decode_uleb128": lambda i: validator_decode_uleb128(bytes(i["bytes"])),
    "encode_sleb128": lambda i: validator_encode_sleb128(i["value"]),
    "decode_sleb128": lambda i: validator_decode_sleb128(bytes(i["bytes"])),
    "parse_module_header": lambda i: validator_parse_module_header(bytes(i["bytes"])),
    "value_type_from_byte": lambda i: validator_value_type_from_byte(i["byte"]),
    "section_id_from_byte": lambda i: validator_section_id_from_byte(i["byte"]),
    "external_kind_from_byte": lambda i: validator_external_kind_from_byte(i["byte"]),
    "mutability_from_byte": lambda i: validator_mutability_from_byte(i["byte"]),
    "decode_limits": lambda i: validator_decode_limits(bytes(i["bytes"])),
    "decode_func_type": lambda i: validator_decode_func_type(bytes(i["bytes"])),
    "decode_global_type": lambda i: validator_decode_global_type(bytes(i["bytes"])),
    "decode_table_type": lambda i: validator_decode_table_type(bytes(i["bytes"])),
    "decode_memory_type": lambda i: validator_decode_memory_type(bytes(i["bytes"])),
    "disassemble": lambda i: validator_disassemble(i.get("address", 0), bytes(i["bytes"])),
}

def main() -> None:
    raw = sys.stdin.read().strip()
    if raw:
        req = json.loads(raw)
        fn = req["function"]
        out = DISPATCH[fn](req.get("input", {}))
        print(json.dumps({"function": fn, "output": out}, default=list))
        return
    # Fixed self-tests
    tests = [
        ("parse_module_header", {"bytes": list(WASM_MAGIC + WASM_VERSION)}),
        ("parse_module_header", {"bytes": [0, 0, 0, 0, 1, 0, 0, 0]}),
        ("value_type_from_byte", {"byte": 0x7F}),
        ("value_type_from_byte", {"byte": 0x6F}),
        ("section_id_from_byte", {"byte": 10}),
        ("decode_uleb128", {"bytes": [0xE5, 0x8E, 0x26]}),  # 624485
        ("encode_uleb128", {"value": 624485}),
        ("decode_sleb128", {"bytes": [0xC0, 0xBB, 0x78]}),  # -123456
        ("decode_func_type",
         {"bytes": [0x60, 0x02, 0x7F, 0x7F, 0x01, 0x7F]}),
        ("decode_limits", {"bytes": [0x00, 0x01]}),
        ("decode_limits", {"bytes": [0x01, 0x01, 0x10]}),
        ("decode_global_type", {"bytes": [0x7F, 0x01]}),
        ("decode_table_type", {"bytes": [0x70, 0x00, 0x01]}),
        ("disassemble", {"address": 0, "bytes": [0x41, 0xE5, 0x8E, 0x26]}),  # i32.const 624485
        ("disassemble", {"address": 0, "bytes": [0x10, 0x05]}),              # call 5
        ("disassemble", {"address": 0, "bytes": [0x28, 0x02, 0x10]}),        # i32.load
        ("disassemble", {"address": 0, "bytes": [0x0F]}),                    # return
    ]
    results = []
    for fn, inp in tests:
        try:
            out = DISPATCH[fn](inp)
        except Exception as e:  # pragma: no cover - defensive
            out = {"error": str(e)}
        results.append({"function": fn, "input": inp, "output": out})
    print(json.dumps(results, indent=2, default=list))

if __name__ == "__main__":
    main()
