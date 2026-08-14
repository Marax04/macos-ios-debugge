#!/usr/bin/env python3
"""Independent validator for rustre-arch-mips.

Reimplements pure-math / table-lookup behavior of the crate in Python so
that crate outputs can be compared against an independent reference.

Usage:
    echo '{"fn":"branch_target_i","args":{"address":0x1000,"simm16":-4}}' | \
        python rustre-arch-mips.py

If no stdin is provided, main() runs a fixed test corpus.
"""
import json
import sys
import struct
import subprocess

# ---- optional deps --------------------------------------------------------
def _ensure(mod, pip_name=None):
    try:
        return __import__(mod)
    except ImportError:
        subprocess.run([sys.executable, "-m", "pip", "install", "-q",
                        pip_name or mod], check=False)
        try:
            return __import__(mod)
        except ImportError:
            return None

capstone = _ensure("capstone")

# ---- constants ------------------------------------------------------------
GPR_O32 = [
    "$zero", "$at", "$v0", "$v1", "$a0", "$a1", "$a2", "$a3",
    "$t0",   "$t1", "$t2", "$t3", "$t4", "$t5", "$t6", "$t7",
    "$s0",   "$s1", "$s2", "$s3", "$s4", "$s5", "$s6", "$s7",
    "$t8",   "$t9", "$k0", "$k1", "$gp", "$sp", "$fp", "$ra",
]

# Role per O32 ABI: zero, at, return($v0/$v1), arg($a0-$a3),
# temp($t0-$t9), saved($s0-$s7), kernel($k0/$k1), gp, sp, fp, ra
def _role_o32(idx):
    if idx == 0:   return "Zero"
    if idx == 1:   return "At"
    if idx in (2,3):       return "Return"
    if 4 <= idx <= 7:      return "Arg"
    if 8 <= idx <= 15 or idx in (24,25): return "Temp"
    if 16 <= idx <= 23:    return "Saved"
    if idx in (26,27):     return "Kernel"
    if idx == 28:  return "Gp"
    if idx == 29:  return "Sp"
    if idx == 30:  return "Fp"
    if idx == 31:  return "Ra"
    return None

def _role_n64(idx):
    # N64: $a0-$a7 args (4..11), $t4-$t7 temps (12..15), $s0-$s7 saved,
    # $t8/$t9 temp, rest same as O32.
    if idx == 0: return "Zero"
    if idx == 1: return "At"
    if idx in (2,3): return "Return"
    if 4 <= idx <= 11: return "Arg"
    if 12 <= idx <= 15 or idx in (24,25): return "Temp"
    if 16 <= idx <= 23: return "Saved"
    if idx in (26,27): return "Kernel"
    if idx == 28: return "Gp"
    if idx == 29: return "Sp"
    if idx == 30: return "Fp"
    if idx == 31: return "Ra"
    return None

EXC_NAMES = {
    0: "Int", 1: "Mod", 2: "TLBL", 3: "TLBS", 4: "AdEL", 5: "AdES",
    6: "IBE", 7: "DBE", 8: "Sys", 9: "Bp", 10: "RI", 11: "CpU",
    12: "Ov", 13: "Tr", 15: "FPE",
}

# ---- bit utils ------------------------------------------------------------
def _u32(v): return v & 0xFFFFFFFF
def _u64(v): return v & 0xFFFFFFFFFFFFFFFF

# ---- validators -----------------------------------------------------------
def validator_swap32(x):
    x = _u32(x)
    return int.from_bytes(x.to_bytes(4, "big"), "little")

def validator_swap16(x):
    x = x & 0xFFFF
    return int.from_bytes(x.to_bytes(2, "big"), "little")

def validator_read_be32(b, off=0):
    if off + 4 > len(b): return None
    return int.from_bytes(bytes(b[off:off+4]), "big")

def validator_read_le32(b, off=0):
    if off + 4 > len(b): return None
    return int.from_bytes(bytes(b[off:off+4]), "little")

def validator_write_be32(word, off=0, size=4):
    buf = bytearray(size)
    buf[off:off+4] = _u32(word).to_bytes(4, "big")
    return list(buf)

def validator_write_le32(word, off=0, size=4):
    buf = bytearray(size)
    buf[off:off+4] = _u32(word).to_bytes(4, "little")
    return list(buf)

def validator_branch_target_i(address, simm16):
    # sign-extend 16-bit
    simm16 &= 0xFFFF
    if simm16 & 0x8000: simm16 -= 0x10000
    return _u64(address + 4 + (simm16 << 2))

def validator_branch_target_j(address, target26):
    target26 &= 0x03FFFFFF
    return _u64(((address + 4) & 0xFFFFFFFFF0000000) | (target26 << 2))

def validator_gpr(idx):
    if 0 <= idx < 32: return GPR_O32[idx]
    return None

def validator_gpr_role_o32(idx): return _role_o32(idx)
def validator_gpr_role_n64(idx): return _role_n64(idx)

# --- segment / virt_to_phys ---
KSEG0 = 0x80000000
KSEG1 = 0xA0000000
KSEG2 = 0xC0000000
KSEG3 = 0xE0000000

def validator_segment_name(vaddr):
    v = vaddr & 0xFFFFFFFF
    if v < 0x80000000: return "useg"
    if v < 0xA0000000: return "kseg0"
    if v < 0xC0000000: return "kseg1"
    if v < 0xE0000000: return "kseg2"
    return "kseg3"

def validator_virt_to_phys(vaddr):
    v = vaddr & 0xFFFFFFFF
    if 0x80000000 <= v < 0xA0000000: return v - 0x80000000
    if 0xA0000000 <= v < 0xC0000000: return v - 0xA0000000
    if v < 0x80000000: return None  # USEG needs TLB
    return None  # KSEG2/3 needs TLB

def validator_phys_to_kseg0(p): return _u32(p + KSEG0)
def validator_phys_to_kseg1(p): return _u32(p + KSEG1)

# --- COP0 ---
def validator_exc_name(code):  return EXC_NAMES.get(code & 0x1F)
def validator_exc_code(cause): return (cause >> 2) & 0x1F
def validator_is_kernel_mode(status):
    # KSU bits [4:3]; supervisor/user EXL=bit1, ERL=bit2
    ksu = (status >> 3) & 0x3
    exl = (status >> 1) & 0x1
    erl = (status >> 2) & 0x1
    return ksu == 0 or exl == 1 or erl == 1
def validator_in_delay_slot(cause): return bool((cause >> 31) & 1)

# --- encoders ---
def _rtype(op, rs, rt, rd, sa, funct):
    return _u32((op<<26)|((rs&31)<<21)|((rt&31)<<16)|((rd&31)<<11)|((sa&31)<<6)|(funct&0x3F))
def _itype(op, rs, rt, imm):
    return _u32((op<<26)|((rs&31)<<21)|((rt&31)<<16)|(imm&0xFFFF))
def _jtype(op, target26):
    return _u32((op<<26)|(target26 & 0x03FFFFFF))

def validator_encode_rtype(op,rs,rt,rd,sa,funct): return _rtype(op,rs,rt,rd,sa,funct)
def validator_encode_itype(op,rs,rt,imm): return _itype(op,rs,rt,imm)
def validator_encode_jtype(op,target26): return _jtype(op,target26)

def validator_encode_nop():         return 0
def validator_encode_addu(rd,rs,rt):return _rtype(0,rs,rt,rd,0,0x21)
def validator_encode_subu(rd,rs,rt):return _rtype(0,rs,rt,rd,0,0x23)
def validator_encode_and(rd,rs,rt): return _rtype(0,rs,rt,rd,0,0x24)
def validator_encode_or(rd,rs,rt):  return _rtype(0,rs,rt,rd,0,0x25)
def validator_encode_xor(rd,rs,rt): return _rtype(0,rs,rt,rd,0,0x26)
def validator_encode_nor(rd,rs,rt): return _rtype(0,rs,rt,rd,0,0x27)
def validator_encode_slt(rd,rs,rt): return _rtype(0,rs,rt,rd,0,0x2A)
def validator_encode_sltu(rd,rs,rt):return _rtype(0,rs,rt,rd,0,0x2B)
def validator_encode_mult(rs,rt):   return _rtype(0,rs,rt,0,0,0x18)
def validator_encode_div(rs,rt):    return _rtype(0,rs,rt,0,0,0x1A)
def validator_encode_mfhi(rd):      return _rtype(0,0,0,rd,0,0x10)
def validator_encode_mflo(rd):      return _rtype(0,0,0,rd,0,0x12)
def validator_encode_jr(rs):        return _rtype(0,rs,0,0,0,0x08)
def validator_encode_jalr(rd,rs):   return _rtype(0,rs,0,rd,0,0x09)
def validator_encode_syscall():     return 0x0000000C
def validator_encode_jal(target_word):     return _jtype(3, target_word)
def validator_encode_j(target_word):       return _jtype(2, target_word)
def validator_encode_lui(rt,imm):   return _itype(0x0F,0,rt,imm)
def validator_encode_addiu(rt,rs,imm):return _itype(0x09,rs,rt,imm)
def validator_encode_lw(rt,base,off): return _itype(0x23,base,rt,off)
def validator_encode_sw(rt,base,off): return _itype(0x2B,base,rt,off)
def validator_encode_beq(rs,rt,off): return _itype(0x04,rs,rt,off)
def validator_encode_bne(rs,rt,off): return _itype(0x05,rs,rt,off)

# --- decoder via capstone ---
def validator_decode_word(word, addr=0, endian="little"):
    if capstone is None: return {"error":"capstone-missing"}
    md = capstone.Cs(capstone.CS_ARCH_MIPS,
                     capstone.CS_MODE_MIPS32 |
                     (capstone.CS_MODE_BIG_ENDIAN if endian=="big"
                      else capstone.CS_MODE_LITTLE_ENDIAN))
    raw = _u32(word).to_bytes(4, endian)
    for i in md.disasm(raw, addr):
        return {"mnemonic": i.mnemonic, "op_str": i.op_str, "address": i.address}
    return None

# --- prologue / delay-slot heuristics ---
def validator_detect_mips_prologue(instr_words):
    # Look for addiu $sp,$sp,-N as first instr
    if not instr_words: return None
    w = _u32(instr_words[0])
    op = (w>>26)&0x3F; rs=(w>>21)&31; rt=(w>>16)&31; imm=w&0xFFFF
    if op == 0x09 and rs == 29 and rt == 29:
        if imm & 0x8000: imm -= 0x10000
        if imm < 0: return -imm
    return None

DELAY_SLOT_OPS = {2,3,4,5,6,7}  # j,jal,beq,bne,blez,bgtz primary opcodes
def validator_has_delay_slot(word):
    w = _u32(word); op = (w>>26)&0x3F
    if op in DELAY_SLOT_OPS: return True
    if op == 0:  # SPECIAL: jr/jalr
        funct = w & 0x3F
        return funct in (0x08, 0x09)
    if op == 1:  # REGIMM bltz/bgez etc
        return True
    return False

# ---- dispatch -------------------------------------------------------------
FUNCTIONS = {
    "swap32": validator_swap32,
    "swap16": validator_swap16,
    "read_be32": validator_read_be32,
    "read_le32": validator_read_le32,
    "write_be32": validator_write_be32,
    "write_le32": validator_write_le32,
    "branch_target_i": validator_branch_target_i,
    "branch_target_j": validator_branch_target_j,
    "gpr": validator_gpr,
    "gpr_role_o32": validator_gpr_role_o32,
    "gpr_role_n64": validator_gpr_role_n64,
    "segment_name": validator_segment_name,
    "virt_to_phys": validator_virt_to_phys,
    "phys_to_kseg0": validator_phys_to_kseg0,
    "phys_to_kseg1": validator_phys_to_kseg1,
    "exc_name": validator_exc_name,
    "exc_code": validator_exc_code,
    "is_kernel_mode": validator_is_kernel_mode,
    "in_delay_slot": validator_in_delay_slot,
    "encode_rtype": validator_encode_rtype,
    "encode_itype": validator_encode_itype,
    "encode_jtype": validator_encode_jtype,
    "encode_nop": validator_encode_nop,
    "encode_addu": validator_encode_addu,
    "encode_subu": validator_encode_subu,
    "encode_and": validator_encode_and,
    "encode_or": validator_encode_or,
    "encode_xor": validator_encode_xor,
    "encode_nor": validator_encode_nor,
    "encode_slt": validator_encode_slt,
    "encode_sltu": validator_encode_sltu,
    "encode_mult": validator_encode_mult,
    "encode_div": validator_encode_div,
    "encode_mfhi": validator_encode_mfhi,
    "encode_mflo": validator_encode_mflo,
    "encode_jr": validator_encode_jr,
    "encode_jalr": validator_encode_jalr,
    "encode_syscall": validator_encode_syscall,
    "encode_jal": validator_encode_jal,
    "encode_j": validator_encode_j,
    "encode_lui": validator_encode_lui,
    "encode_addiu": validator_encode_addiu,
    "encode_lw": validator_encode_lw,
    "encode_sw": validator_encode_sw,
    "encode_beq": validator_encode_beq,
    "encode_bne": validator_encode_bne,
    "decode_word": validator_decode_word,
    "detect_mips_prologue": validator_detect_mips_prologue,
    "has_delay_slot": validator_has_delay_slot,
}

def dispatch(name, args):
    fn = FUNCTIONS[name]
    if isinstance(args, dict): return fn(**args)
    if isinstance(args, list): return fn(*args)
    return fn(args)

def main():
    data = sys.stdin.read().strip() if not sys.stdin.isatty() else ""
    if data:
        req = json.loads(data)
        out = dispatch(req["fn"], req.get("args", {}))
        print(json.dumps({"result": out}, default=lambda o: list(o) if isinstance(o,(bytes,bytearray)) else o))
        return
    # fixed self-test corpus
    samples = [
        ("swap32", [0xAABBCCDD]),
        ("branch_target_i", {"address": 0x1000, "simm16": -4}),
        ("branch_target_j", {"address": 0x1000, "target26": 0x100}),
        ("gpr", [29]),
        ("gpr_role_o32", [4]),
        ("segment_name", [0x80001234]),
        ("virt_to_phys", [0x80001234]),
        ("exc_name", [8]),
        ("encode_nop", []),
        ("encode_addu", {"rd":8,"rs":9,"rt":10}),
        ("encode_addiu", {"rt":29,"rs":29,"imm":0xFFE0}),  # addiu $sp,$sp,-32
        ("detect_mips_prologue", [[0x27BDFFE0]]),
        ("has_delay_slot", [0x08000000]),  # j
    ]
    results = {}
    for name, a in samples:
        try: results[name] = dispatch(name, a)
        except Exception as e: results[name] = f"ERR:{e}"
    print(json.dumps(results, indent=2))

if __name__ == "__main__":
    main()
