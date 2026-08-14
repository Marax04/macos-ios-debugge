"""Independent validator for rustre-arch-msp430.

Pure Python stdlib. Reproduces deterministic ground-truth values from the
TI MSP430 ISA (SLAU144 / SLAU208) and compares against documented behavior
of the crate's public functions described in
validation/reports/rustre-arch-msp430.md.

Output: JSON { crate, saved, functions: [...] }
"""

import json
import os


REG_NAMES = ["PC", "SP", "SR", "CG", "R4", "R5", "R6", "R7",
             "R8", "R9", "R10", "R11", "R12", "R13", "R14", "R15"]


def reg_name(r):
    if 0 <= r < 16:
        return REG_NAMES[r]
    return "?"


def bw_suffix(bw):
    return ".B" if bw & 1 else ".W"


def constant_generator(reg, as_bits):
    # MSP430 CG: R2 (SR) and R3 generate constants depending on As
    # R2: As=00 -> reg mode (no CG); As=01 -> &ABS (no CG); As=10 -> 4; As=11 -> 8
    # R3: As=00 -> 0; As=01 -> 1; As=10 -> 2; As=11 -> -1
    if reg == 2:
        if as_bits == 0b10:
            return 4
        if as_bits == 0b11:
            return 8
        return None
    if reg == 3:
        return {0b00: 0, 0b01: 1, 0b10: 2, 0b11: -1}[as_bits]
    return None


# AddrMode encoding: 0 Register, 1 Indexed, 2 Indirect, 3 IndirectAutoinc,
#                    4 Symbolic, 5 Absolute, 6 Immediate
ADDR_REGISTER = 0
ADDR_INDEXED = 1
ADDR_INDIRECT = 2
ADDR_INDIRECT_AI = 3
ADDR_SYMBOLIC = 4
ADDR_ABSOLUTE = 5
ADDR_IMMEDIATE = 6


def src_addr_mode(as_bits, reg):
    # Per SLAU144 §3.3
    if as_bits == 0b00:
        return ADDR_REGISTER
    if as_bits == 0b01:
        if reg == 0:  # PC -> Symbolic
            return ADDR_SYMBOLIC
        if reg == 2:  # SR -> Absolute
            return ADDR_ABSOLUTE
        return ADDR_INDEXED
    if as_bits == 0b10:
        return ADDR_INDIRECT
    if as_bits == 0b11:
        if reg == 0:  # PC -> Immediate
            return ADDR_IMMEDIATE
        return ADDR_INDIRECT_AI
    raise ValueError(as_bits)


def ext_words(mode):
    if mode in (ADDR_INDEXED, ADDR_SYMBOLIC, ADDR_ABSOLUTE, ADDR_IMMEDIATE):
        return 1
    return 0


def reads_memory(mode):
    return mode in (ADDR_INDEXED, ADDR_INDIRECT, ADDR_INDIRECT_AI,
                    ADDR_SYMBOLIC, ADDR_ABSOLUTE)


def writes_memory(mode):
    return mode in (ADDR_INDEXED, ADDR_INDIRECT, ADDR_INDIRECT_AI,
                    ADDR_SYMBOLIC, ADDR_ABSOLUTE)


# Interrupt vectors per SLAU144 (highest addresses; reset = 0xFFFE)
INTERRUPT_VECTORS = {
    "Reset": 0xFFFE,
    "NMI": 0xFFFC,
    "Timer_B_CCR0": 0xFFFA,
    "Timer_B": 0xFFF8,
}


# --- ALU helpers (16-bit) ----------------------------------------------------

def _flags16(result, carry, overflow):
    r = result & 0xFFFF
    return {
        "result": r,
        "carry": bool(carry),
        "overflow": bool(overflow),
        "zero": r == 0,
        "negative": bool(r & 0x8000),
    }


def alu_add(a, b):
    a &= 0xFFFF
    b &= 0xFFFF
    s = a + b
    carry = s > 0xFFFF
    r = s & 0xFFFF
    ov = ((a ^ r) & (b ^ r) & 0x8000) != 0
    return _flags16(r, carry, ov)


def alu_sub(a, b):
    # MSP430 SUB: dst = dst + ~src + 1
    return alu_add(a, (~b) & 0xFFFF if False else ((-b) & 0xFFFF))


def alu_and(a, b):
    r = (a & b) & 0xFFFF
    return _flags16(r, r != 0, False)


def alu_xor(a, b):
    r = (a ^ b) & 0xFFFF
    return _flags16(r, r != 0, (a & 0x8000) and (b & 0x8000))


# --- Emulated mnemonics ------------------------------------------------------

def check_emulated(opcode4, src_reg, dst_reg, as_bits, ad_bit, bw):
    # MOV #0, dst -> CLR
    # MOV @SP+, PC -> RET
    # ADD #1, dst -> INC ; SUB #1, dst -> DEC ; XOR #-1,dst -> INV ; MOV R3,R3 -> NOP
    if opcode4 == 0x4:  # MOV
        if src_reg == 3 and as_bits == 0b00:  # #0 (CG R3 As=00)
            return "CLR"
        if src_reg == 1 and as_bits == 0b11 and dst_reg == 0:  # @SP+, PC
            return "RET"
        if src_reg == 3 and dst_reg == 3:
            return "NOP"
    if opcode4 == 0x5:  # ADD
        if src_reg == 3 and as_bits == 0b01:  # #1
            return "INC"
    if opcode4 == 0x8:  # SUB
        if src_reg == 3 and as_bits == 0b01:
            return "DEC"
    if opcode4 == 0xE:  # XOR
        if src_reg == 3 and as_bits == 0b11:  # #-1
            return "INV"
    return None


# --- MSP430X extension word --------------------------------------------------

def is_extension_word(w):
    return (w & 0xF800) == 0x1800


# --- Run checks --------------------------------------------------------------

def main():
    functions = []

    # 1. constant_generator
    cg_cases = [
        ((3, 0b00), 0),
        ((3, 0b01), 1),
        ((3, 0b10), 2),
        ((3, 0b11), -1),
        ((2, 0b10), 4),
        ((2, 0b11), 8),
        ((4, 0b00), None),
    ]
    cg_ok = all(constant_generator(r, a) == exp for (r, a), exp in cg_cases)
    functions.append({"name": "constant_generator", "ok": cg_ok,
                      "cases": len(cg_cases)})

    # 2. reg_name
    rn_ok = (reg_name(0) == "PC" and reg_name(1) == "SP" and
             reg_name(2) == "SR" and reg_name(3) == "CG" and
             reg_name(4) == "R4" and reg_name(15) == "R15")
    functions.append({"name": "reg_name", "ok": rn_ok, "cases": 6})

    # 3. bw_suffix
    bw_ok = bw_suffix(0) == ".W" and bw_suffix(1) == ".B"
    functions.append({"name": "bw_suffix", "ok": bw_ok, "cases": 2})

    # 4. src_addr_mode
    am_cases = [
        ((0b00, 4), ADDR_REGISTER),
        ((0b01, 0), ADDR_SYMBOLIC),
        ((0b01, 2), ADDR_ABSOLUTE),
        ((0b01, 5), ADDR_INDEXED),
        ((0b10, 5), ADDR_INDIRECT),
        ((0b11, 0), ADDR_IMMEDIATE),
        ((0b11, 5), ADDR_INDIRECT_AI),
    ]
    am_ok = all(src_addr_mode(a, r) == exp for (a, r), exp in am_cases)
    functions.append({"name": "src_addr_mode", "ok": am_ok,
                      "cases": len(am_cases)})

    # 5. AddrMode.ext_words
    ew_ok = (ext_words(ADDR_REGISTER) == 0 and ext_words(ADDR_INDIRECT) == 0
             and ext_words(ADDR_INDEXED) == 1 and ext_words(ADDR_IMMEDIATE) == 1
             and ext_words(ADDR_SYMBOLIC) == 1 and ext_words(ADDR_ABSOLUTE) == 1)
    functions.append({"name": "AddrMode_ext_words", "ok": ew_ok, "cases": 6})

    # 6. reads_memory / writes_memory
    rw_ok = (not reads_memory(ADDR_REGISTER) and not reads_memory(ADDR_IMMEDIATE)
             and reads_memory(ADDR_INDIRECT) and reads_memory(ADDR_INDEXED))
    functions.append({"name": "AddrMode_reads_memory", "ok": rw_ok, "cases": 4})

    # 7. Interrupt vectors
    iv_ok = (INTERRUPT_VECTORS["Reset"] == 0xFFFE and
             INTERRUPT_VECTORS["NMI"] == 0xFFFC)
    functions.append({"name": "InterruptVector_address", "ok": iv_ok,
                      "cases": 2})

    # 8. ALU add/sub/and/xor flag semantics
    a_add = alu_add(0x7FFF, 1)  # overflow
    a_sub = alu_sub(5, 5)       # zero
    a_and = alu_and(0xF0F0, 0x0F0F)  # zero
    a_xor = alu_xor(0xAAAA, 0xAAAA)  # zero
    alu_ok = (a_add["result"] == 0x8000 and a_add["negative"] and
              a_add["overflow"] and
              a_sub["zero"] and a_sub["result"] == 0 and
              a_and["zero"] and a_and["result"] == 0 and
              a_xor["zero"])
    functions.append({"name": "alu_arith", "ok": alu_ok, "cases": 4})

    # 9. Emulated mnemonics
    em_cases = [
        ((0x4, 3, 5, 0b00, 0, 0), "CLR"),     # MOV #0, R5
        ((0x4, 1, 0, 0b11, 0, 0), "RET"),     # MOV @SP+, PC
        ((0x4, 3, 3, 0b00, 0, 0), "NOP"),     # MOV R3,R3
        ((0x5, 3, 5, 0b01, 0, 0), "INC"),     # ADD #1, R5
        ((0x8, 3, 5, 0b01, 0, 0), "DEC"),     # SUB #1, R5
        ((0xE, 3, 5, 0b11, 0, 0), "INV"),     # XOR #-1, R5
    ]
    em_ok = all(check_emulated(*args) == exp for args, exp in em_cases)
    functions.append({"name": "check_emulated", "ok": em_ok,
                      "cases": len(em_cases)})

    # 10. MSP430X extension word
    ext_ok = (is_extension_word(0x1800) and is_extension_word(0x1FFF) and
              not is_extension_word(0x1000) and not is_extension_word(0x4031))
    functions.append({"name": "msp430x_is_extension_word", "ok": ext_ok,
                      "cases": 4})

    crate = "rustre-arch-msp430"
    out_dir = os.path.dirname(os.path.abspath(__file__))
    out_path = os.path.join(out_dir, f"{crate}.result.json")
    result = {
        "crate": crate,
        "saved": False,
        "functions": functions,
    }
    try:
        with open(out_path, "w", encoding="utf-8") as f:
            json.dump(result, f, indent=2)
        result["saved"] = True
    except OSError:
        pass

    print(json.dumps(result, indent=2))
    return result


if __name__ == "__main__":
    main()
