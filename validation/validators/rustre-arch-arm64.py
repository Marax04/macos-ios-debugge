#!/usr/bin/env python3
"""
Standalone Python validator for the `rustre-arch-arm64` crate.

Implements reference logic for ARM64/AArch64 decoding helpers using only
Python stdlib + optional capstone (auto-installed) — no Rust crate imports,
no MCP calls. Each `validator_<name>` function mirrors a public function
of the crate and can be cross-checked against its Rust counterpart.

Usage:
    echo '{"fn":"a64_b_target","args":{"pc":0,"word":2483027969}}' | python rustre-arch-arm64.py
    python rustre-arch-arm64.py                          # runs main() self-tests
"""
from __future__ import annotations

import json
import struct
import subprocess
import sys
from typing import Any


# --------------------------------------------------------------------------- #
# optional dependency: capstone (used as ground truth for disassemble)
# --------------------------------------------------------------------------- #
def _ensure_capstone():
    try:
        import capstone  # noqa: F401
        return True
    except ImportError:
        try:
            subprocess.check_call(
                [sys.executable, "-m", "pip", "install", "--quiet", "capstone"]
            )
            import capstone  # noqa: F401
            return True
        except Exception:
            return False


# --------------------------------------------------------------------------- #
# bit helpers
# --------------------------------------------------------------------------- #
def _sext(value: int, bits: int) -> int:
    """Sign-extend `value` from `bits` width to a Python int."""
    sign = 1 << (bits - 1)
    return (value & (sign - 1)) - (value & sign)


def _u64(x: int) -> int:
    return x & 0xFFFF_FFFF_FFFF_FFFF


# --------------------------------------------------------------------------- #
# Branch offset / target decoders
# --------------------------------------------------------------------------- #
def validator_a64_b_offset(word: int) -> int:
    """Sign-extended 26-bit immediate * 4 (for B/BL)."""
    imm26 = word & 0x03FF_FFFF
    return _sext(imm26, 26) * 4


def validator_a64_b_target(pc: int, word: int) -> int:
    return _u64(pc + validator_a64_b_offset(word))


def validator_a64_b19_offset(word: int) -> int:
    """Sign-extended 19-bit immediate * 4 (B.cond / CBZ / CBNZ).
    imm19 lives at bits [23:5]."""
    imm19 = (word >> 5) & 0x7_FFFF
    return _sext(imm19, 19) * 4


def validator_a64_b14_offset(word: int) -> int:
    """Sign-extended 14-bit immediate * 4 (TBZ / TBNZ).
    imm14 lives at bits [18:5]."""
    imm14 = (word >> 5) & 0x3FFF
    return _sext(imm14, 14) * 4


# --------------------------------------------------------------------------- #
# Opcode mask checks
# --------------------------------------------------------------------------- #
def validator_is_b(word: int) -> bool:
    # B  : 0 0 0 1 0 1 | imm26    -> top 6 bits = 0b000101
    return ((word >> 26) & 0x3F) == 0b000101


def validator_is_bl(word: int) -> bool:
    # BL : 1 0 0 1 0 1 | imm26    -> top 6 bits = 0b100101
    return ((word >> 26) & 0x3F) == 0b100101


def validator_is_cbz(word: int) -> bool:
    # CBZ: sf 0110100 | imm19 Rt  -> bits[30:24] = 0b0110100, bit24=0
    return ((word >> 24) & 0x7F) == 0b0110100


def validator_is_cbnz(word: int) -> bool:
    return ((word >> 24) & 0x7F) == 0b0110101


def validator_is_ret(word: int) -> bool:
    # RET: 1101011 0 0 10 11111 0000 0 0 Rn 00000
    # canonical RET (Rn=X30) is 0xD65F03C0; mask top 22 bits + low bits
    return (word & 0xFFFF_FC1F) == 0xD65F_0000


# --------------------------------------------------------------------------- #
# Immediate extractors
# --------------------------------------------------------------------------- #
def validator_a64_add_imm(word: int) -> dict:
    """ADD/SUB (immediate). Returns dict(imm12, shift)."""
    imm12 = (word >> 10) & 0xFFF
    sh = (word >> 22) & 0x1
    return {"imm12": imm12, "shift": 12 if sh else 0}


def validator_a64_add_imm_value(word: int) -> int:
    d = validator_a64_add_imm(word)
    return d["imm12"] << d["shift"]


def validator_a64_mov_imm(word: int) -> dict:
    """MOVZ/MOVK/MOVN: imm16 at [20:5], hw at [22:21]."""
    imm16 = (word >> 5) & 0xFFFF
    hw = (word >> 21) & 0x3
    return {"imm16": imm16, "shift": hw * 16}


def validator_a64_movz_value(word: int) -> int:
    d = validator_a64_mov_imm(word)
    return d["imm16"] << d["shift"]


def validator_a64_ls_uoff(word: int, size: int) -> int:
    """LDR/STR unsigned offset (imm12) scaled by access size in bytes."""
    imm12 = (word >> 10) & 0xFFF
    return imm12 * size


# --------------------------------------------------------------------------- #
# NZCV flag computation
# --------------------------------------------------------------------------- #
def _nzcv(result64: int, n_flag_bit: int, c: bool, v: bool) -> dict:
    return {
        "n": bool((result64 >> 63) & 1) if n_flag_bit is None else bool(n_flag_bit),
        "z": result64 == 0,
        "c": c,
        "v": v,
    }


def validator_add64_nzcv(a: int, b: int) -> dict:
    a &= 0xFFFF_FFFF_FFFF_FFFF
    b &= 0xFFFF_FFFF_FFFF_FFFF
    raw = a + b
    res = raw & 0xFFFF_FFFF_FFFF_FFFF
    c = raw > 0xFFFF_FFFF_FFFF_FFFF
    sa = (a >> 63) & 1
    sb = (b >> 63) & 1
    sr = (res >> 63) & 1
    v = (sa == sb) and (sr != sa)
    return {"n": bool(sr), "z": res == 0, "c": c, "v": v, "result": res}


def validator_sub64_nzcv(a: int, b: int) -> dict:
    """ARM SUB sets C = NOT borrow ; i.e. C = (a >= b) unsigned."""
    a &= 0xFFFF_FFFF_FFFF_FFFF
    b &= 0xFFFF_FFFF_FFFF_FFFF
    res = (a - b) & 0xFFFF_FFFF_FFFF_FFFF
    c = a >= b
    sa = (a >> 63) & 1
    sb = (b >> 63) & 1
    sr = (res >> 63) & 1
    v = (sa != sb) and (sr != sa)
    return {"n": bool(sr), "z": res == 0, "c": c, "v": v, "result": res}


# --------------------------------------------------------------------------- #
# Pointer authentication / tagging helpers
# --------------------------------------------------------------------------- #
def validator_get_ptr_tag(ptr: int) -> int:
    return (ptr >> 56) & 0xFF


def validator_set_ptr_tag(ptr: int, tag: int) -> int:
    return (ptr & 0x00FF_FFFF_FFFF_FFFF) | ((tag & 0xFF) << 56)


def validator_strip_ptr_tag(ptr: int) -> int:
    return ptr & 0x00FF_FFFF_FFFF_FFFF


def validator_canonical_address(va: int) -> int:
    """Sign-extend bit 55 across bits 56..63."""
    va &= 0xFFFF_FFFF_FFFF_FFFF
    if (va >> 55) & 1:
        return va | 0xFF00_0000_0000_0000
    return va & 0x00FF_FFFF_FFFF_FFFF


def validator_pac_strip_mask(va_bits: int) -> int:
    """Mask that keeps only the low `va_bits` bits."""
    return (1 << va_bits) - 1


def validator_pac_strip_pointer(ptr: int, va_bits: int) -> int:
    return ptr & validator_pac_strip_mask(va_bits)


# --------------------------------------------------------------------------- #
# Page / alignment helpers
# --------------------------------------------------------------------------- #
def validator_page_base_4k(addr: int) -> int:
    return addr & ~0xFFF & 0xFFFF_FFFF_FFFF_FFFF


def validator_page_offset_4k(addr: int) -> int:
    return addr & 0xFFF


def validator_page_base_64k(addr: int) -> int:
    return addr & ~0xFFFF & 0xFFFF_FFFF_FFFF_FFFF


def validator_page_offset_64k(addr: int) -> int:
    return addr & 0xFFFF


def validator_align_up(val: int, align: int) -> int:
    return (val + align - 1) & ~(align - 1)


def validator_align_down(val: int, align: int) -> int:
    return val & ~(align - 1)


# --------------------------------------------------------------------------- #
# AAPCS64 register roles
# --------------------------------------------------------------------------- #
def validator_aapcs64_role(n: int) -> str:
    if 0 <= n <= 7:
        return "Argument"
    if n == 8:
        return "IndirectResult"
    if 9 <= n <= 15:
        return "CallerSaved"
    if n == 16 or n == 17:
        return "IntraProcedureCall"  # IP0/IP1
    if n == 18:
        return "Platform"
    if 19 <= n <= 28:
        return "CalleeSaved"
    if n == 29:
        return "FramePointer"
    if n == 30:
        return "LinkRegister"
    return "Unknown"


def validator_aapcs64_fp_role(n: int) -> str:
    if 0 <= n <= 7:
        return "Argument"
    if 8 <= n <= 15:
        return "CallerSavedOrTemp"  # V8..V15 low 64 bits callee-saved
    if 16 <= n <= 31:
        return "CallerSaved"
    return "Unknown"


# --------------------------------------------------------------------------- #
# Logical immediate decoder (ARM ARM DecodeBitMasks for immediate variant)
# --------------------------------------------------------------------------- #
def validator_decode_logical_imm(n: int, immr: int, imms: int, reg_size: int):
    """Reference implementation of ARM's DecodeBitMasks for logical-immediate.
    Returns the 64- or 32-bit mask value (Python int) or None if invalid."""
    # length of bitfield
    combined = (n << 6) | ((~imms) & 0x3F)
    # find highest set bit position
    length = -1
    for i in range(6, -1, -1):
        if (combined >> i) & 1:
            length = i
            break
    if length < 1:
        return None
    if reg_size == 32 and n == 1:
        return None
    size = 1 << length
    levels = size - 1
    s = imms & levels
    r = immr & levels
    if s == levels:
        return None
    diff = (s - r) & levels
    welem = (1 << (s + 1)) - 1
    # ROR welem by r within size-bit field
    welem &= (1 << size) - 1
    rotated = ((welem >> r) | (welem << (size - r))) & ((1 << size) - 1)
    # replicate to reg_size
    out = 0
    for i in range(0, reg_size, size):
        out |= rotated << i
    out &= (1 << reg_size) - 1
    return out


# --------------------------------------------------------------------------- #
# PAC fixed-form encodings (ARM ARM)
# --------------------------------------------------------------------------- #
def validator_encode_xpaci(rd: int) -> int:
    # XPACI Rd  : 1101_1010_1100_0001_0100_0111_111d_dddd
    return 0xDAC1_43E0 | (rd & 0x1F)


def validator_encode_retaa() -> int:
    # RETAA : 1101_0110_0101_1111_0000_1011_1111_1111
    return 0xD65F_0BFF


def validator_encode_pacia(rd: int, rn: int) -> int:
    # PACIA Rd, Rn : 1101_1010_1100_0001_0000_00nn_nnnd_dddd
    return 0xDAC1_0000 | ((rn & 0x1F) << 5) | (rd & 0x1F)


def validator_encode_autia(rd: int, rn: int) -> int:
    # AUTIA Rd, Rn : 1101_1010_1100_0001_0001_00nn_nnnd_dddd
    return 0xDAC1_1000 | ((rn & 0x1F) << 5) | (rd & 0x1F)


# --------------------------------------------------------------------------- #
# Category classifier (mnemonic -> category)
# --------------------------------------------------------------------------- #
_CATEGORY_TABLE = {
    "add": "DataProcessing", "sub": "DataProcessing", "mov": "DataProcessing",
    "movz": "DataProcessing", "movk": "DataProcessing", "movn": "DataProcessing",
    "and": "DataProcessing", "orr": "DataProcessing", "eor": "DataProcessing",
    "lsl": "DataProcessing", "lsr": "DataProcessing", "asr": "DataProcessing",
    "ldr": "LoadStore", "str": "LoadStore", "ldp": "LoadStore", "stp": "LoadStore",
    "ldrb": "LoadStore", "strb": "LoadStore", "ldrh": "LoadStore", "strh": "LoadStore",
    "b": "Branch", "bl": "Branch", "br": "Branch", "blr": "Branch",
    "ret": "Branch", "cbz": "Branch", "cbnz": "Branch", "tbz": "Branch", "tbnz": "Branch",
    "fadd": "FloatSimd", "fmul": "FloatSimd", "fmov": "FloatSimd",
    "msr": "System", "mrs": "System", "svc": "System", "hvc": "System",
    "dmb": "Barrier", "dsb": "Barrier", "isb": "Barrier",
    "ldxr": "AtomicMemory", "stxr": "AtomicMemory",
    "ldaxr": "AtomicMemory", "stlxr": "AtomicMemory",
    "casa": "AtomicMemory", "swp": "AtomicMemory",
}


def validator_classify_mnemonic(mnemonic: str) -> str:
    return _CATEGORY_TABLE.get(mnemonic.lower(), "Miscellaneous")


# --------------------------------------------------------------------------- #
# Linear disassembler (count + addresses)
# --------------------------------------------------------------------------- #
def validator_linear_disasm_count(byte_len: int) -> int:
    return byte_len // 4


def validator_linear_disasm_addresses(base: int, byte_len: int) -> list:
    return [base + 4 * i for i in range(byte_len // 4)]


# --------------------------------------------------------------------------- #
# Disassemble (Capstone ground truth)
# --------------------------------------------------------------------------- #
def validator_disassemble(addr: int, word: int) -> dict:
    """Disassemble a single 4-byte A64 word using Capstone as ground truth."""
    if not _ensure_capstone():
        return {"error": "capstone unavailable"}
    from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
    md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
    data = struct.pack("<I", word & 0xFFFF_FFFF)
    for i in md.disasm(data, addr):
        return {
            "address": i.address,
            "mnemonic": i.mnemonic,
            "operands": i.op_str,
            "size": i.size,
            "bytes": list(i.bytes),
        }
    return {"error": "undecodable"}


# --------------------------------------------------------------------------- #
# Dispatcher
# --------------------------------------------------------------------------- #
_DISPATCH = {
    "a64_b_offset": lambda a: validator_a64_b_offset(a["word"]),
    "a64_b_target": lambda a: validator_a64_b_target(a["pc"], a["word"]),
    "a64_b19_offset": lambda a: validator_a64_b19_offset(a["word"]),
    "a64_b14_offset": lambda a: validator_a64_b14_offset(a["word"]),
    "is_b": lambda a: validator_is_b(a["word"]),
    "is_bl": lambda a: validator_is_bl(a["word"]),
    "is_cbz": lambda a: validator_is_cbz(a["word"]),
    "is_cbnz": lambda a: validator_is_cbnz(a["word"]),
    "is_ret": lambda a: validator_is_ret(a["word"]),
    "a64_add_imm": lambda a: validator_a64_add_imm(a["word"]),
    "a64_add_imm_value": lambda a: validator_a64_add_imm_value(a["word"]),
    "a64_mov_imm": lambda a: validator_a64_mov_imm(a["word"]),
    "a64_movz_value": lambda a: validator_a64_movz_value(a["word"]),
    "a64_ls_uoff": lambda a: validator_a64_ls_uoff(a["word"], a["size"]),
    "add64_nzcv": lambda a: validator_add64_nzcv(a["a"], a["b"]),
    "sub64_nzcv": lambda a: validator_sub64_nzcv(a["a"], a["b"]),
    "get_ptr_tag": lambda a: validator_get_ptr_tag(a["ptr"]),
    "set_ptr_tag": lambda a: validator_set_ptr_tag(a["ptr"], a["tag"]),
    "strip_ptr_tag": lambda a: validator_strip_ptr_tag(a["ptr"]),
    "canonical_address": lambda a: validator_canonical_address(a["va"]),
    "pac_strip_mask": lambda a: validator_pac_strip_mask(a["va_bits"]),
    "pac_strip_pointer": lambda a: validator_pac_strip_pointer(a["ptr"], a["va_bits"]),
    "page_base_4k": lambda a: validator_page_base_4k(a["addr"]),
    "page_offset_4k": lambda a: validator_page_offset_4k(a["addr"]),
    "page_base_64k": lambda a: validator_page_base_64k(a["addr"]),
    "page_offset_64k": lambda a: validator_page_offset_64k(a["addr"]),
    "align_up": lambda a: validator_align_up(a["val"], a["align"]),
    "align_down": lambda a: validator_align_down(a["val"], a["align"]),
    "aapcs64_role": lambda a: validator_aapcs64_role(a["n"]),
    "aapcs64_fp_role": lambda a: validator_aapcs64_fp_role(a["n"]),
    "decode_logical_imm": lambda a: validator_decode_logical_imm(
        a["n"], a["immr"], a["imms"], a["reg_size"]
    ),
    "encode_xpaci": lambda a: validator_encode_xpaci(a["rd"]),
    "encode_retaa": lambda a: validator_encode_retaa(),
    "encode_pacia": lambda a: validator_encode_pacia(a["rd"], a["rn"]),
    "encode_autia": lambda a: validator_encode_autia(a["rd"], a["rn"]),
    "classify_mnemonic": lambda a: validator_classify_mnemonic(a["mnemonic"]),
    "linear_disasm_count": lambda a: validator_linear_disasm_count(a["byte_len"]),
    "linear_disasm_addresses": lambda a: validator_linear_disasm_addresses(
        a["base"], a["byte_len"]
    ),
    "disassemble": lambda a: validator_disassemble(a["addr"], a["word"]),
}


# --------------------------------------------------------------------------- #
# Self-tests
# --------------------------------------------------------------------------- #
def main() -> int:
    results: list[dict[str, Any]] = []

    # NOP = 0xD503201F   RET = 0xD65F03C0   BL +4 = 0x94000001
    assert validator_is_ret(0xD65F03C0) is True
    assert validator_is_bl(0x94000001) is True
    assert validator_is_b(0x14000001) is True

    # BL +4 -> target from pc 0x1000 = 0x1004
    assert validator_a64_b_target(0x1000, 0x94000001) == 0x1004
    # B  -4 (back) : imm26 = 0x3FFFFFF -> -1 word
    assert validator_a64_b_offset(0x17FFFFFF) == -4

    # MOVZ X0, #0x1234   -> 0xD2824680
    assert validator_a64_movz_value(0xD2824680) == 0x1234

    # ADD X0, X0, #0x10  -> 0x91004000  (sh=0, imm12=0x10)
    assert validator_a64_add_imm_value(0x91004000) == 0x10

    # NZCV: 0+0 = Z set, others clear
    r = validator_add64_nzcv(0, 0)
    assert r["z"] and not r["n"] and not r["c"] and not r["v"]
    # 0xFFFF.. + 1 -> carry, zero
    r = validator_add64_nzcv(0xFFFFFFFFFFFFFFFF, 1)
    assert r["c"] and r["z"]
    # sub: 1-1 = z, c=1 (no borrow)
    r = validator_sub64_nzcv(1, 1)
    assert r["z"] and r["c"]

    # PAC tagging round-trip
    p = 0x00007FFFAABBCCDD
    tagged = validator_set_ptr_tag(p, 0xAB)
    assert validator_get_ptr_tag(tagged) == 0xAB
    assert validator_strip_ptr_tag(tagged) == p

    # Page helpers
    assert validator_page_base_4k(0x1234) == 0x1000
    assert validator_page_offset_4k(0x1234) == 0x234
    assert validator_align_up(0x1001, 0x1000) == 0x2000
    assert validator_align_down(0x1FFF, 0x1000) == 0x1000

    # AAPCS64
    assert validator_aapcs64_role(0) == "Argument"
    assert validator_aapcs64_role(8) == "IndirectResult"
    assert validator_aapcs64_role(29) == "FramePointer"
    assert validator_aapcs64_role(30) == "LinkRegister"

    # Logical-imm: N=1, immr=0, imms=0 -> mask 0x1 replicated -> 0x1
    v = validator_decode_logical_imm(1, 0, 0, 64)
    assert v == 1

    # PAC encodings
    assert validator_encode_retaa() == 0xD65F0BFF
    assert validator_encode_xpaci(0) == 0xDAC143E0

    # Category classifier
    assert validator_classify_mnemonic("add") == "DataProcessing"
    assert validator_classify_mnemonic("ldr") == "LoadStore"
    assert validator_classify_mnemonic("ret") == "Branch"
    assert validator_classify_mnemonic("dmb") == "Barrier"
    assert validator_classify_mnemonic("ldxr") == "AtomicMemory"

    # Linear disasm
    assert validator_linear_disasm_count(16) == 4
    assert validator_linear_disasm_addresses(0x1000, 16) == [0x1000, 0x1004, 0x1008, 0x100C]

    # Capstone (optional) — verify NOP & RET round-trip if available
    d = validator_disassemble(0x1000, 0xD503201F)
    if "mnemonic" in d:
        assert d["mnemonic"] == "nop"

    results.append({"self_tests": "passed"})
    print(json.dumps(results, indent=2))
    return 0


if __name__ == "__main__":
    # JSON-on-stdin dispatch mode
    if not sys.stdin.isatty():
        try:
            payload = sys.stdin.read().strip()
            if payload:
                req = json.loads(payload)
                fn = req.get("fn")
                args = req.get("args", {}) or {}
                if fn not in _DISPATCH:
                    print(json.dumps({"error": f"unknown fn: {fn}"}))
                    sys.exit(1)
                out = _DISPATCH[fn](args)
                print(json.dumps({"fn": fn, "result": out}))
                sys.exit(0)
        except Exception as e:
            print(json.dumps({"error": str(e)}))
            sys.exit(1)
    sys.exit(main())
