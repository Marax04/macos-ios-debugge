#!/usr/bin/env python3
"""
Standalone validator for rustre-arch-cil crate.

Implements ECMA-335 Partition III CIL decoding logic in pure Python (stdlib only).
No imports of the Rust crate, no MCP calls.

Each validator_<name>(input) -> output corresponds to a testable function of the crate.

Usage:
    echo '{"fn": "decode", "bytes": [0x00]}' | python rustre-arch-cil.py
    python rustre-arch-cil.py            # runs main() with fixed test vectors
"""

import json
import sys
import struct
from typing import Optional, Tuple, List, Dict, Any


# ---------------------------------------------------------------------------
# ECMA-335 Partition III — single-byte opcode table (subset, sufficient for tests)
# (mnemonic, operand_size_bytes, flags)
# flags: BRANCH=1, CALL=2, RET=4, COND=8, BARRIER=16
# operand_size: -1 = switch (variable), -2 = none, otherwise size in bytes
# ---------------------------------------------------------------------------
F_BRANCH = 1
F_CALL = 2
F_RET = 4
F_COND = 8
F_BARRIER = 16

ONE_BYTE = {
    0x00: ("nop", 0, 0),
    0x01: ("break", 0, F_BARRIER),
    0x02: ("ldarg.0", 0, 0),
    0x03: ("ldarg.1", 0, 0),
    0x04: ("ldarg.2", 0, 0),
    0x05: ("ldarg.3", 0, 0),
    0x06: ("ldloc.0", 0, 0),
    0x07: ("ldloc.1", 0, 0),
    0x08: ("ldloc.2", 0, 0),
    0x09: ("ldloc.3", 0, 0),
    0x0A: ("stloc.0", 0, 0),
    0x0B: ("stloc.1", 0, 0),
    0x0C: ("stloc.2", 0, 0),
    0x0D: ("stloc.3", 0, 0),
    0x0E: ("ldarg.s", 1, 0),
    0x0F: ("ldarga.s", 1, 0),
    0x10: ("starg.s", 1, 0),
    0x11: ("ldloc.s", 1, 0),
    0x12: ("ldloca.s", 1, 0),
    0x13: ("stloc.s", 1, 0),
    0x14: ("ldnull", 0, 0),
    0x15: ("ldc.i4.m1", 0, 0),
    0x16: ("ldc.i4.0", 0, 0),
    0x17: ("ldc.i4.1", 0, 0),
    0x18: ("ldc.i4.2", 0, 0),
    0x19: ("ldc.i4.3", 0, 0),
    0x1A: ("ldc.i4.4", 0, 0),
    0x1B: ("ldc.i4.5", 0, 0),
    0x1C: ("ldc.i4.6", 0, 0),
    0x1D: ("ldc.i4.7", 0, 0),
    0x1E: ("ldc.i4.8", 0, 0),
    0x1F: ("ldc.i4.s", 1, 0),
    0x20: ("ldc.i4", 4, 0),
    0x21: ("ldc.i8", 8, 0),
    0x22: ("ldc.r4", 4, 0),
    0x23: ("ldc.r8", 8, 0),
    0x25: ("dup", 0, 0),
    0x26: ("pop", 0, 0),
    0x27: ("jmp", 4, F_BRANCH),
    0x28: ("call", 4, F_CALL),
    0x29: ("calli", 4, F_CALL),
    0x2A: ("ret", 0, F_RET),
    0x2B: ("br.s", 1, F_BRANCH),
    0x2C: ("brfalse.s", 1, F_BRANCH | F_COND),
    0x2D: ("brtrue.s", 1, F_BRANCH | F_COND),
    0x2E: ("beq.s", 1, F_BRANCH | F_COND),
    0x2F: ("bge.s", 1, F_BRANCH | F_COND),
    0x30: ("bgt.s", 1, F_BRANCH | F_COND),
    0x31: ("ble.s", 1, F_BRANCH | F_COND),
    0x32: ("blt.s", 1, F_BRANCH | F_COND),
    0x33: ("bne.un.s", 1, F_BRANCH | F_COND),
    0x37: ("bgt.un.s", 1, F_BRANCH | F_COND),
    0x38: ("br", 4, F_BRANCH),
    0x39: ("brfalse", 4, F_BRANCH | F_COND),
    0x3A: ("brtrue", 4, F_BRANCH | F_COND),
    0x3B: ("beq", 4, F_BRANCH | F_COND),
    0x3C: ("bge", 4, F_BRANCH | F_COND),
    0x3D: ("bgt", 4, F_BRANCH | F_COND),
    0x3E: ("ble", 4, F_BRANCH | F_COND),
    0x3F: ("blt", 4, F_BRANCH | F_COND),
    0x45: ("switch", -1, F_BRANCH | F_COND),
    0x58: ("add", 0, 0),
    0x59: ("sub", 0, 0),
    0x5A: ("mul", 0, 0),
    0x5B: ("div", 0, 0),
    0x5D: ("rem", 0, 0),
    0x5F: ("and", 0, 0),
    0x60: ("or", 0, 0),
    0x61: ("xor", 0, 0),
    0x62: ("shl", 0, 0),
    0x63: ("shr", 0, 0),
    0x65: ("neg", 0, 0),
    0x66: ("not", 0, 0),
    0x6F: ("callvirt", 4, F_CALL),
    0x72: ("ldstr", 4, 0),
    0x73: ("newobj", 4, F_CALL),
    0x7B: ("ldfld", 4, 0),
    0x7D: ("stfld", 4, 0),
    0xDD: ("leave", 4, F_BRANCH),
    0xDE: ("leave.s", 1, F_BRANCH),
}

# 0xFE-prefixed (two-byte) opcodes subset
FE_BYTE = {
    0x01: ("ceq", 0, 0),
    0x02: ("cgt", 0, 0),
    0x03: ("cgt.un", 0, 0),
    0x04: ("clt", 0, 0),
    0x05: ("clt.un", 0, 0),
    0x06: ("ldftn", 4, 0),
    0x09: ("ldarg", 2, 0),
    0x0A: ("ldarga", 2, 0),
    0x0B: ("starg", 2, 0),
    0x0C: ("ldloc", 2, 0),
    0x0D: ("ldloca", 2, 0),
    0x0E: ("stloc", 2, 0),
    0x14: ("endfilter", 0, F_BARRIER),
    0x16: ("initobj", 4, 0),
    0x1A: ("rethrow", 0, F_BARRIER),
}


# ---------------------------------------------------------------------------
# Validators
# ---------------------------------------------------------------------------

def validator_lookup_cil_opcode(byte1: int) -> Optional[Dict[str, Any]]:
    """Mirror lookup_cil_opcode."""
    e = ONE_BYTE.get(byte1)
    if e is None:
        return None
    return {"mnemonic": e[0], "operand_size": e[1], "flags": e[2]}


def validator_lookup_cil_fe_opcode(byte2: int) -> Optional[Dict[str, Any]]:
    """Mirror lookup_cil_fe_opcode."""
    e = FE_BYTE.get(byte2)
    if e is None:
        return None
    return {"mnemonic": e[0], "operand_size": e[1], "flags": e[2]}


def validator_decode(data: bytes) -> Dict[str, Any]:
    """Mirror CilInstr::decode. Returns dict with mnemonic, size, flags, or error."""
    if len(data) < 1:
        return {"error": "Truncated"}
    b0 = data[0]
    if b0 == 0xFE:
        if len(data) < 2:
            return {"error": "Truncated"}
        e = FE_BYTE.get(data[1])
        if e is None:
            return {"error": "UnknownPrefixedOpcode", "byte": data[1]}
        mne, opsz, flags = e
        total = 2 + (opsz if opsz >= 0 else 0)
        if len(data) < total:
            return {"error": "Truncated"}
        return {"mnemonic": mne, "size": total, "flags": flags, "prefixed": True}
    e = ONE_BYTE.get(b0)
    if e is None:
        return {"error": "UnknownOpcode", "byte": b0}
    mne, opsz, flags = e
    if opsz == -1:
        # switch: 1 + 4 (n) + n*4
        if len(data) < 5:
            return {"error": "Truncated"}
        n = struct.unpack_from("<I", data, 1)[0]
        total = 1 + 4 + n * 4
        if len(data) < total:
            return {"error": "Truncated"}
        return {"mnemonic": mne, "size": total, "flags": flags, "switch_n": n}
    total = 1 + opsz
    if len(data) < total:
        return {"error": "Truncated"}
    return {"mnemonic": mne, "size": total, "flags": flags}


def validator_decode_compressed_uint(data: bytes) -> Dict[str, Any]:
    """ECMA-335 II.23.2 compressed unsigned integer."""
    if len(data) < 1:
        return {"error": "Truncated"}
    b0 = data[0]
    if (b0 & 0x80) == 0:
        return {"value": b0, "consumed": 1}
    if (b0 & 0xC0) == 0x80:
        if len(data) < 2:
            return {"error": "Truncated"}
        return {"value": ((b0 & 0x3F) << 8) | data[1], "consumed": 2}
    if (b0 & 0xE0) == 0xC0:
        if len(data) < 4:
            return {"error": "Truncated"}
        return {
            "value": ((b0 & 0x1F) << 24) | (data[1] << 16) | (data[2] << 8) | data[3],
            "consumed": 4,
        }
    return {"error": "InvalidCompressed"}


def validator_decode_compressed_int(data: bytes) -> Dict[str, Any]:
    """ECMA-335 II.23.2 compressed signed integer (rotate-right encoding)."""
    u = validator_decode_compressed_uint(data)
    if "error" in u:
        return u
    val = u["value"]
    consumed = u["consumed"]
    # sign bit is the LSB; rotate right by 1 across the appropriate width
    if consumed == 1:
        width = 7
    elif consumed == 2:
        width = 14
    else:
        width = 29
    sign = val & 1
    val >>= 1
    if sign:
        val -= 1 << (width - 1)
    return {"value": val, "consumed": consumed}


def validator_cil_max_local_slot(code: bytes) -> int:
    """Max local variable index referenced in a method body."""
    i = 0
    mx = -1
    while i < len(code):
        d = validator_decode(code[i:])
        if "error" in d:
            break
        mne = d["mnemonic"]
        sz = d["size"]
        # short locals
        if mne == "ldloc.0" or mne == "stloc.0":
            mx = max(mx, 0)
        elif mne == "ldloc.1" or mne == "stloc.1":
            mx = max(mx, 1)
        elif mne == "ldloc.2" or mne == "stloc.2":
            mx = max(mx, 2)
        elif mne == "ldloc.3" or mne == "stloc.3":
            mx = max(mx, 3)
        elif mne in ("ldloc.s", "ldloca.s", "stloc.s"):
            mx = max(mx, code[i + 1])
        elif mne in ("ldloc", "ldloca", "stloc"):
            # 0xFE-prefixed, 2-byte operand
            idx = struct.unpack_from("<H", code, i + 2)[0]
            mx = max(mx, idx)
        i += sz
    return max(mx, 0)


def _i32(x: int) -> int:
    x &= 0xFFFFFFFF
    if x & 0x80000000:
        x -= 0x100000000
    return x


def validator_cil_fold_i32(mne: str, a: int, b: int) -> Optional[int]:
    """Constant fold i32 binary op with .NET/Rust wrapping semantics."""
    a = _i32(a); b = _i32(b)
    if mne == "add": return _i32(a + b)
    if mne == "sub": return _i32(a - b)
    if mne == "mul": return _i32(a * b)
    if mne == "div":
        if b == 0: return None
        if a == -2**31 and b == -1: return None
        # truncate toward zero
        q = abs(a) // abs(b)
        if (a < 0) ^ (b < 0): q = -q
        return _i32(q)
    if mne == "and": return _i32(a & b)
    if mne == "or":  return _i32(a | b)
    if mne == "xor": return _i32(a ^ b)
    if mne == "shl": return _i32(a << (b & 31))
    if mne == "shr":
        # arithmetic shift right
        return _i32(a >> (b & 31))
    return None


def validator_cil_fold_unary_i32(mne: str, a: int) -> Optional[int]:
    a = _i32(a)
    if mne == "neg": return _i32(-a)
    if mne == "not": return _i32(~a)
    return None


def validator_stack_effect_of(mne: str) -> Optional[Dict[str, int]]:
    """Stack pop/push per ECMA-335 III for common opcodes."""
    table = {
        "nop":      (0, 0),
        "dup":      (0, 1),  # net +1 -> pop 0 push 1? actually dup: pop 1 push 2
        "pop":      (1, 0),
        "ret":      (0, 0),  # caller-dependent; treat as 0 for delta-of-void
        "add":      (2, 1),
        "sub":      (2, 1),
        "mul":      (2, 1),
        "div":      (2, 1),
        "and":      (2, 1),
        "or":       (2, 1),
        "xor":      (2, 1),
        "shl":      (2, 1),
        "shr":      (2, 1),
        "neg":      (1, 1),
        "not":      (1, 1),
        "ceq":      (2, 1),
        "cgt":      (2, 1),
        "clt":      (2, 1),
        "ldnull":   (0, 1),
        "ldc.i4.0": (0, 1),
        "ldc.i4.1": (0, 1),
        "ldc.i4":   (0, 1),
        "ldc.i4.s": (0, 1),
        "ldloc.0":  (0, 1),
        "stloc.0":  (1, 0),
        "br":       (0, 0),
        "br.s":     (0, 0),
        "brfalse":  (1, 0),
        "brtrue":   (1, 0),
    }
    # special-case dup correctly: pop 1, push 2
    if mne == "dup":
        return {"pop": 1, "push": 2}
    if mne not in table:
        return None
    p, q = table[mne]
    return {"pop": p, "push": q}


def validator_cil_net_stack_delta(mne: str) -> Optional[int]:
    e = validator_stack_effect_of(mne)
    if e is None:
        return None
    return e["push"] - e["pop"]


def validator_cil_find_blocks(code: bytes) -> List[Dict[str, int]]:
    """Linear scan: leaders are offset 0, every branch target, and every instr after a branch/ret."""
    # 1) decode all instructions and collect offsets + branch targets
    instrs = []
    i = 0
    leaders = {0}
    while i < len(code):
        d = validator_decode(code[i:])
        if "error" in d:
            break
        sz = d["size"]
        flags = d["flags"]
        mne = d["mnemonic"]
        instrs.append((i, sz, flags, mne))
        # leaders: target + next
        if flags & F_BRANCH or flags & F_RET:
            nxt = i + sz
            if nxt < len(code):
                leaders.add(nxt)
            # branch target
            if flags & F_BRANCH and mne != "ret":
                # short branch (1B signed) or 4B signed
                op_sz = sz - 1
                if op_sz == 1:
                    off = struct.unpack_from("<b", code, i + 1)[0]
                    leaders.add(nxt + off)
                elif op_sz == 4:
                    off = struct.unpack_from("<i", code, i + 1)[0]
                    leaders.add(nxt + off)
        i += sz
    sorted_leaders = sorted(l for l in leaders if 0 <= l < len(code))
    blocks = []
    for idx, start in enumerate(sorted_leaders):
        end = sorted_leaders[idx + 1] if idx + 1 < len(sorted_leaders) else len(code)
        blocks.append({"start": start, "end": end})
    return blocks


def validator_linear_disassemble_total(code: bytes) -> Dict[str, Any]:
    """Sum-of-sizes must equal len(code) when the body is clean."""
    i = 0
    n = 0
    while i < len(code):
        d = validator_decode(code[i:])
        if "error" in d:
            return {"error": d["error"], "consumed": i, "count": n}
        i += d["size"]
        n += 1
    return {"consumed": i, "count": n, "total": len(code), "ok": i == len(code)}


def validator_get_branch_target(pc: int, code: bytes) -> Optional[int]:
    """Resolve branch target = next_addr + signed offset."""
    d = validator_decode(code)
    if "error" in d:
        return None
    flags = d["flags"]
    if not (flags & F_BRANCH):
        return None
    sz = d["size"]
    op_sz = sz - 1
    if op_sz == 1:
        off = struct.unpack_from("<b", code, 1)[0]
    elif op_sz == 4:
        off = struct.unpack_from("<i", code, 1)[0]
    else:
        return None
    return pc + sz + off


def validator_type_size_in_bytes(cor_element_type: int) -> Optional[int]:
    """ECMA-335 II.23.1.16 CorElementType -> size (primitive types)."""
    T = {
        0x02: 1,  # BOOLEAN
        0x03: 2,  # CHAR
        0x04: 1,  # I1
        0x05: 1,  # U1
        0x06: 2,  # I2
        0x07: 2,  # U2
        0x08: 4,  # I4
        0x09: 4,  # U4
        0x0A: 8,  # I8
        0x0B: 8,  # U8
        0x0C: 4,  # R4
        0x0D: 8,  # R8
    }
    return T.get(cor_element_type)


# ---------------------------------------------------------------------------
# Entry
# ---------------------------------------------------------------------------

DISPATCH = {
    "lookup_cil_opcode": lambda a: validator_lookup_cil_opcode(a["byte"]),
    "lookup_cil_fe_opcode": lambda a: validator_lookup_cil_fe_opcode(a["byte"]),
    "decode": lambda a: validator_decode(bytes(a["bytes"])),
    "decode_compressed_uint": lambda a: validator_decode_compressed_uint(bytes(a["bytes"])),
    "decode_compressed_int": lambda a: validator_decode_compressed_int(bytes(a["bytes"])),
    "cil_max_local_slot": lambda a: validator_cil_max_local_slot(bytes(a["bytes"])),
    "cil_fold_i32": lambda a: validator_cil_fold_i32(a["mne"], a["a"], a["b"]),
    "cil_fold_unary_i32": lambda a: validator_cil_fold_unary_i32(a["mne"], a["a"]),
    "stack_effect_of": lambda a: validator_stack_effect_of(a["mne"]),
    "cil_net_stack_delta": lambda a: validator_cil_net_stack_delta(a["mne"]),
    "cil_find_blocks": lambda a: validator_cil_find_blocks(bytes(a["bytes"])),
    "linear_disassemble_total": lambda a: validator_linear_disassemble_total(bytes(a["bytes"])),
    "get_branch_target": lambda a: validator_get_branch_target(a["pc"], bytes(a["bytes"])),
    "type_size_in_bytes": lambda a: validator_type_size_in_bytes(a["t"]),
}


def main() -> None:
    # If stdin has data, treat as single JSON request
    if not sys.stdin.isatty():
        try:
            req = json.load(sys.stdin)
        except Exception:
            req = None
        if req and "fn" in req:
            fn = req["fn"]
            if fn not in DISPATCH:
                print(json.dumps({"error": f"unknown fn {fn}"}))
                return
            out = DISPATCH[fn](req)
            print(json.dumps(out))
            return

    # Otherwise, run a self-test sweep with fixed vectors
    results: Dict[str, Any] = {}

    results["decode_nop"] = validator_decode(bytes([0x00]))
    results["decode_ret"] = validator_decode(bytes([0x2A]))
    results["decode_ldc_i4"] = validator_decode(bytes([0x20, 0x2A, 0x00, 0x00, 0x00]))
    results["decode_ceq"] = validator_decode(bytes([0xFE, 0x01]))
    results["decode_br_s"] = validator_decode(bytes([0x2B, 0x05]))
    results["decode_truncated"] = validator_decode(bytes([0x20, 0x01]))
    results["decode_unknown"] = validator_decode(bytes([0xA5]))

    # compressed integers — ECMA boundaries
    results["cu_0"] = validator_decode_compressed_uint(bytes([0x00]))
    results["cu_7F"] = validator_decode_compressed_uint(bytes([0x7F]))
    results["cu_80"] = validator_decode_compressed_uint(bytes([0x80, 0x80]))
    results["cu_3FFF"] = validator_decode_compressed_uint(bytes([0xBF, 0xFF]))
    results["cu_4000"] = validator_decode_compressed_uint(bytes([0xC0, 0x00, 0x40, 0x00]))

    # folding
    results["fold_add"] = validator_cil_fold_i32("add", 2, 3)
    results["fold_xor"] = validator_cil_fold_i32("xor", 0xFF, 0x0F)
    results["fold_neg"] = validator_cil_fold_unary_i32("neg", 5)
    results["fold_not"] = validator_cil_fold_unary_i32("not", 0)

    # stack effects
    results["se_add"] = validator_stack_effect_of("add")
    results["se_dup"] = validator_stack_effect_of("dup")
    results["delta_pop"] = validator_cil_net_stack_delta("pop")

    # locals
    # body: ldloc.s 7, stloc.s 3, ret
    body = bytes([0x11, 0x07, 0x13, 0x03, 0x2A])
    results["max_local"] = validator_cil_max_local_slot(body)
    results["linear_total"] = validator_linear_disassemble_total(body)

    # blocks: ldc.i4.0; brfalse.s +1; nop; ret
    cfg = bytes([0x16, 0x2C, 0x01, 0x00, 0x2A])
    results["blocks"] = validator_cil_find_blocks(cfg)

    # branch target
    results["branch_tgt"] = validator_get_branch_target(0x100, bytes([0x2B, 0x05]))

    # type sizes
    results["sz_i4"] = validator_type_size_in_bytes(0x08)
    results["sz_r8"] = validator_type_size_in_bytes(0x0D)

    print(json.dumps(results, indent=2))


if __name__ == "__main__":
    main()
