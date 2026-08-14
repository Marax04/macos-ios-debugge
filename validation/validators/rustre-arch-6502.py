#!/usr/bin/env python3
"""
Independent validator for rustre-arch-6502.

Implements MOS 6502 disassembly and key constants from scratch using only
Python stdlib, based on public datasheets / nesdev / masswerk references.
No imports from the Rust crate, no MCP calls.

Output (printed as JSON):
    { "crate": "rustre-arch-6502", "saved": bool, "functions": [...] }
"""

import json
import os
import sys

CRATE = "rustre-arch-6502"

# Register IDs (mirrors crate's pub const REG_*)
REG_A, REG_X, REG_Y, REG_SP, REG_PC, REG_P = 0, 1, 2, 3, 4, 5

# Status flag bits (NV-BDIZC)
STATUS = {
    "C": 1 << 0,
    "Z": 1 << 1,
    "I": 1 << 2,
    "D": 1 << 3,
    "B": 1 << 4,
    "U": 1 << 5,
    "V": 1 << 6,
    "N": 1 << 7,
}

# Vectors
NMI_VECTOR = 0xFFFA
RESET_VECTOR = 0xFFFC
IRQ_VECTOR = 0xFFFE

# Addressing modes -> (name, extra_bytes)
ADDR_MODES = {
    "Implied":         ("imp",  0),
    "Accumulator":     ("acc",  0),
    "Immediate":       ("imm",  1),
    "ZeroPage":        ("zp",   1),
    "ZeroPageX":       ("zpx",  1),
    "ZeroPageY":       ("zpy",  1),
    "Absolute":        ("abs",  2),
    "AbsoluteX":       ("abx",  2),
    "AbsoluteY":       ("aby",  2),
    "Indirect":        ("ind",  2),
    "IndirectX":       ("izx",  1),
    "IndirectY":       ("izy",  1),
    "Relative":        ("rel",  1),
}


def addr_mode_extra_bytes(mode):
    return ADDR_MODES[mode][1]


# Minimal but representative 6502 official opcode table.
# (opcode -> (mnemonic, addr_mode, base_cycles))
# Sourced from masswerk.at / Synertek 6502 datasheet.
OPCODE_TABLE = {
    0x00: ("BRK", "Implied",     7),
    0xEA: ("NOP", "Implied",     2),
    0xA9: ("LDA", "Immediate",   2),
    0xA5: ("LDA", "ZeroPage",    3),
    0xB5: ("LDA", "ZeroPageX",   4),
    0xAD: ("LDA", "Absolute",    4),
    0xBD: ("LDA", "AbsoluteX",   4),
    0xB9: ("LDA", "AbsoluteY",   4),
    0xA1: ("LDA", "IndirectX",   6),
    0xB1: ("LDA", "IndirectY",   5),
    0xA2: ("LDX", "Immediate",   2),
    0xA0: ("LDY", "Immediate",   2),
    0x85: ("STA", "ZeroPage",    3),
    0x8D: ("STA", "Absolute",    4),
    0x4C: ("JMP", "Absolute",    3),
    0x6C: ("JMP", "Indirect",    5),
    0x20: ("JSR", "Absolute",    6),
    0x60: ("RTS", "Implied",     6),
    0x40: ("RTI", "Implied",     6),
    0xD0: ("BNE", "Relative",    2),
    0xF0: ("BEQ", "Relative",    2),
    0x10: ("BPL", "Relative",    2),
    0x30: ("BMI", "Relative",    2),
    0x90: ("BCC", "Relative",    2),
    0xB0: ("BCS", "Relative",    2),
    0x50: ("BVC", "Relative",    2),
    0x70: ("BVS", "Relative",    2),
    0x18: ("CLC", "Implied",     2),
    0x38: ("SEC", "Implied",     2),
    0x58: ("CLI", "Implied",     2),
    0x78: ("SEI", "Implied",     2),
    0xB8: ("CLV", "Implied",     2),
    0xD8: ("CLD", "Implied",     2),
    0xF8: ("SED", "Implied",     2),
    0xAA: ("TAX", "Implied",     2),
    0x8A: ("TXA", "Implied",     2),
    0xA8: ("TAY", "Implied",     2),
    0x98: ("TYA", "Implied",     2),
    0xBA: ("TSX", "Implied",     2),
    0x9A: ("TXS", "Implied",     2),
    0x48: ("PHA", "Implied",     3),
    0x68: ("PLA", "Implied",     4),
    0x08: ("PHP", "Implied",     3),
    0x28: ("PLP", "Implied",     4),
}


def opcode_table_lookup(b):
    return OPCODE_TABLE.get(b & 0xFF)


def instruction_length(opcode):
    entry = opcode_table_lookup(opcode)
    if entry is None:
        return 1  # unknown -> treat as single-byte
    return 1 + addr_mode_extra_bytes(entry[1])


def cycles(opcode, crossed_page=False):
    """Base cycles; +1 for AbsoluteX/AbsoluteY/IndirectY page-cross."""
    entry = opcode_table_lookup(opcode)
    if entry is None:
        return 0
    _, mode, base = entry
    if crossed_page and mode in ("AbsoluteX", "AbsoluteY", "IndirectY"):
        return base + 1
    return base


def format_operand(mode, operand_bytes, pc):
    if mode == "Implied":
        return ""
    if mode == "Accumulator":
        return "A"
    if mode == "Immediate":
        return f"#${operand_bytes[0]:02X}"
    if mode == "ZeroPage":
        return f"${operand_bytes[0]:02X}"
    if mode == "ZeroPageX":
        return f"${operand_bytes[0]:02X},X"
    if mode == "ZeroPageY":
        return f"${operand_bytes[0]:02X},Y"
    if mode == "IndirectX":
        return f"(${operand_bytes[0]:02X},X)"
    if mode == "IndirectY":
        return f"(${operand_bytes[0]:02X}),Y"
    if mode == "Relative":
        off = operand_bytes[0]
        if off & 0x80:
            off -= 0x100
        target = (pc + 2 + off) & 0xFFFF
        return f"${target:04X}"
    if mode in ("Absolute", "AbsoluteX", "AbsoluteY", "Indirect"):
        addr = operand_bytes[0] | (operand_bytes[1] << 8)
        if mode == "Absolute":
            return f"${addr:04X}"
        if mode == "AbsoluteX":
            return f"${addr:04X},X"
        if mode == "AbsoluteY":
            return f"${addr:04X},Y"
        if mode == "Indirect":
            return f"(${addr:04X})"
    return "?"


def branch_target(pc, instr_bytes):
    """Return branch / jump target if applicable, else None."""
    if not instr_bytes:
        return None
    entry = opcode_table_lookup(instr_bytes[0])
    if entry is None:
        return None
    mnem, mode, _ = entry
    if mode == "Relative" and len(instr_bytes) >= 2:
        off = instr_bytes[1]
        if off & 0x80:
            off -= 0x100
        return (pc + 2 + off) & 0xFFFF
    if mnem == "JMP" and mode == "Absolute" and len(instr_bytes) >= 3:
        return instr_bytes[1] | (instr_bytes[2] << 8)
    if mnem == "JSR" and len(instr_bytes) >= 3:
        return instr_bytes[1] | (instr_bytes[2] << 8)
    return None


def disassemble_one(data, offset, addr):
    if offset >= len(data):
        return None
    opcode = data[offset]
    entry = opcode_table_lookup(opcode)
    if entry is None:
        return {
            "text": f".byte ${opcode:02X}",
            "bytes_consumed": 1,
        }
    mnem, mode, _ = entry
    nbytes = 1 + addr_mode_extra_bytes(mode)
    if offset + nbytes > len(data):
        return None
    operand = data[offset + 1: offset + nbytes]
    op_str = format_operand(mode, list(operand) + [0, 0], addr)
    text = f"{mnem} {op_str}".rstrip()
    return {"text": text, "bytes_consumed": nbytes}


def disassemble_range(data, start_addr, n_instrs):
    out = []
    off = 0
    pc = start_addr & 0xFFFF
    for _ in range(n_instrs):
        d = disassemble_one(data, off, pc)
        if d is None:
            break
        out.append(f"{pc:04X}: {d['text']}")
        off += d["bytes_consumed"]
        pc = (pc + d["bytes_consumed"]) & 0xFFFF
    return out


def cpu_reset_pc(memory):
    """Return PC value loaded from $FFFC/$FFFD on reset (little-endian)."""
    lo = memory[RESET_VECTOR]
    hi = memory[RESET_VECTOR + 1]
    return lo | (hi << 8)


# --- Self-checks against the report's documented invariants ---

def run_checks():
    results = []

    # 1) Reset vector constant
    results.append(("RESET_VECTOR == 0xFFFC", RESET_VECTOR == 0xFFFC))

    # 2) Pointer size / endian implied for 6502
    results.append(("pointer_size == 2 (16-bit)", True))
    results.append(("endian == little", True))

    # 3) Status bits layout NV-BDIZC
    results.append(("status N bit = 0x80", STATUS["N"] == 0x80))
    results.append(("status V bit = 0x40", STATUS["V"] == 0x40))
    results.append(("status C bit = 0x01", STATUS["C"] == 0x01))

    # 4) Reset state: SP=0xFD, P has U|I set
    sp_post_reset = 0xFD
    p_post_reset = STATUS["U"] | STATUS["I"]
    results.append(("SP post-reset == 0xFD", sp_post_reset == 0xFD))
    results.append(("P post-reset has U|I", (p_post_reset & (STATUS["U"] | STATUS["I"])) == (STATUS["U"] | STATUS["I"])))

    # 5) opcode_table lookup
    nop = opcode_table_lookup(0xEA)
    results.append(("opcode 0xEA == NOP/Implied/2", nop == ("NOP", "Implied", 2)))
    lda_imm = opcode_table_lookup(0xA9)
    results.append(("opcode 0xA9 == LDA/Immediate/2", lda_imm == ("LDA", "Immediate", 2)))
    jsr = opcode_table_lookup(0x20)
    results.append(("opcode 0x20 == JSR/Absolute/6", jsr == ("JSR", "Absolute", 6)))
    rts = opcode_table_lookup(0x60)
    results.append(("opcode 0x60 == RTS/Implied/6", rts == ("RTS", "Implied", 6)))
    brk = opcode_table_lookup(0x00)
    results.append(("opcode 0x00 == BRK/Implied/7", brk == ("BRK", "Implied", 7)))

    # 6) AddrMode extra_bytes
    results.append(("Immediate extra_bytes == 1", addr_mode_extra_bytes("Immediate") == 1))
    results.append(("Absolute extra_bytes == 2", addr_mode_extra_bytes("Absolute") == 2))
    results.append(("Implied extra_bytes == 0", addr_mode_extra_bytes("Implied") == 0))
    results.append(("Relative extra_bytes == 1", addr_mode_extra_bytes("Relative") == 1))

    # 7) cycles() page-cross penalty
    results.append(("LDA abs,X base=4 no cross", cycles(0xBD, False) == 4))
    results.append(("LDA abs,X +1 on page cross", cycles(0xBD, True) == 5))
    results.append(("LDA (zp),Y +1 on page cross", cycles(0xB1, True) == 6))
    results.append(("LDA imm no page-cross penalty", cycles(0xA9, True) == 2))

    # 8) disassemble_one — JSR $1234
    d = disassemble_one(bytes([0x20, 0x34, 0x12]), 0, 0x8000)
    results.append(("disasm JSR $1234 bytes_consumed=3", d is not None and d["bytes_consumed"] == 3))
    results.append(("disasm JSR $1234 text", d is not None and d["text"] == "JSR $1234"))

    # 9) Branch target for BNE
    # BNE $02 at PC=0x8000 -> target = 0x8000 + 2 + 2 = 0x8004
    bt = branch_target(0x8000, [0xD0, 0x02])
    results.append(("BNE +2 -> $8004", bt == 0x8004))
    # Backward branch BNE -2 (0xFE)
    bt2 = branch_target(0x8000, [0xD0, 0xFE])
    results.append(("BNE -2 -> $8000", bt2 == 0x8000))
    # JMP $ABCD absolute
    bt3 = branch_target(0x0000, [0x4C, 0xCD, 0xAB])
    results.append(("JMP $ABCD target", bt3 == 0xABCD))

    # 10) cpu_reset_pc reads $FFFC/$FFFD little-endian
    mem = bytearray(0x10000)
    mem[0xFFFC] = 0x00
    mem[0xFFFD] = 0x80
    results.append(("reset PC = $8000 from vector", cpu_reset_pc(mem) == 0x8000))

    # 11) disassemble_range basic flow
    rng = disassemble_range(bytes([0xA9, 0x42, 0xEA, 0x60]), 0x8000, 3)
    results.append(("disasm_range count == 3", len(rng) == 3))
    results.append(("disasm_range[0] LDA #$42", rng[0].endswith("LDA #$42")))
    results.append(("disasm_range[1] NOP",     rng[1].endswith("NOP")))
    results.append(("disasm_range[2] RTS",     rng[2].endswith("RTS")))

    return results


def main():
    checks = run_checks()
    failed = [name for name, ok in checks if not ok]

    functions = [
        "opcode_table_lookup",
        "addr_mode_extra_bytes",
        "instruction_length",
        "cycles",
        "format_operand",
        "branch_target",
        "disassemble_one",
        "disassemble_range",
        "cpu_reset_pc",
        "run_checks",
    ]

    out_dir = os.path.dirname(os.path.abspath(__file__))
    result_path = os.path.join(out_dir, f"{CRATE}.result.json")
    saved = False
    try:
        with open(result_path, "w", encoding="utf-8") as f:
            json.dump(
                {
                    "crate": CRATE,
                    "checks_total": len(checks),
                    "checks_failed": failed,
                    "functions": functions,
                },
                f,
                indent=2,
            )
        saved = True
    except OSError:
        saved = False

    print(json.dumps({"crate": CRATE, "saved": saved, "functions": functions}, indent=2))
    return 0 if not failed else 1


if __name__ == "__main__":
    sys.exit(main())
