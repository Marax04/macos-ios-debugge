#!/usr/bin/env python3
"""Independent validator for rustre-arch-sparc.

Reimplements pure-math / table-lookup behavior of the crate in Python so
that crate outputs can be compared against an independent reference.

Reference: SPARC V8 Architecture Manual + V9 Manual.
SPARC instructions are 32-bit big-endian words.

Usage:
    echo '{"fn":"encode_nop","args":[]}' | python rustre-arch-sparc.py
"""
import json
import sys
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

# ---- bit utils ------------------------------------------------------------
def _u32(v): return v & 0xFFFFFFFF
def _u64(v): return v & 0xFFFFFFFFFFFFFFFF
def _mask(v, bits): return v & ((1 << bits) - 1)
def _sext(v, bits):
    v &= (1 << bits) - 1
    if v & (1 << (bits - 1)): v -= (1 << bits)
    return v


# ---- register names (SPARC V8) -------------------------------------------
# r0..r7   = %g0..%g7 (globals)
# r8..r15  = %o0..%o7 (outs); %o6 = %sp, %o7 = ret-addr link
# r16..r23 = %l0..%l7 (locals)
# r24..r31 = %i0..%i7 (ins); %i6 = %fp, %i7 = caller ret addr
def validator_reg_name(r):
    r &= 0x1F
    if r < 8:  return f"%g{r}"
    if r < 16:
        i = r - 8
        if i == 6: return "%sp"
        if i == 7: return "%o7"
        return f"%o{i}"
    if r < 24: return f"%l{r - 16}"
    i = r - 24
    if i == 6: return "%fp"
    if i == 7: return "%i7"
    return f"%i{i}"


def validator_freg_name(r):
    r &= 0x1F
    return f"%f{r}"


# ---- Encoders (SPARC V8) --------------------------------------------------
# Format 1 (CALL): op=01 (1), disp30
# Format 2 (SETHI/Branch): op=00 (0), rd[29:25], op2[24:22], imm22 / disp22
# Format 3 (ALU/Mem): op=10 or 11, rd[29:25], op3[24:19], rs1[18:14], i, ...

def validator_encode_call(disp):
    # disp is byte displacement; encoded as disp30 = (disp >> 2)
    disp30 = (disp >> 2) & 0x3FFFFFFF
    return _u32((0b01 << 30) | disp30)


def validator_encode_sethi(rd, imm22):
    # op=00, rd, op2=100 (SETHI), imm22
    return _u32((0b00 << 30) | ((rd & 0x1F) << 25) | (0b100 << 22) | (imm22 & 0x3FFFFF))


def validator_encode_nop():
    # NOP = sethi 0, %g0
    return validator_encode_sethi(0, 0)


def _enc_fmt3_reg(op, op3, rs1, rs2, rd):
    return _u32((op << 30) | ((rd & 0x1F) << 25) | ((op3 & 0x3F) << 19)
                | ((rs1 & 0x1F) << 14) | (0 << 13) | (rs2 & 0x1F))


def _enc_fmt3_imm(op, op3, rs1, simm13, rd):
    return _u32((op << 30) | ((rd & 0x1F) << 25) | ((op3 & 0x3F) << 19)
                | ((rs1 & 0x1F) << 14) | (1 << 13) | (simm13 & 0x1FFF))


def validator_encode_alu_reg(op3, rs1, rs2, rd):
    return _enc_fmt3_reg(0b10, op3, rs1, rs2, rd)


def validator_encode_alu_imm(op3, rs1, simm13, rd):
    return _enc_fmt3_imm(0b10, op3, rs1, simm13, rd)


def validator_encode_load(op3, rs1, simm13, rd):
    # Loads use op=11
    return _enc_fmt3_imm(0b11, op3, rs1, simm13, rd)


def validator_encode_store(op3, rs1, simm13, rd):
    return _enc_fmt3_imm(0b11, op3, rs1, simm13, rd)


def validator_encode_bicc(cond, annul, disp):
    # op=00, a(1) bit at 29, cond[28:25], op2=010 (Bicc), disp22
    # disp is byte displacement => disp22 = disp >> 2
    disp22 = (disp >> 2) & 0x3FFFFF
    a = 1 if annul else 0
    return _u32((0 << 30) | (a << 29) | ((cond & 0xF) << 25)
                | (0b010 << 22) | disp22)


def validator_encode_jmpl(rs1, simm13, rd):
    # JMPL: op=10, op3=0x38
    return _enc_fmt3_imm(0b10, 0x38, rs1, simm13, rd)


# Synthetic / pseudo
def validator_synth_mov_reg(rs, rd):
    # mov rs,rd  ==  or %g0, rs, rd ; op3=0x02
    return validator_encode_alu_reg(0x02, 0, rs, rd)


def validator_synth_mov_imm(simm13, rd):
    return validator_encode_alu_imm(0x02, 0, simm13, rd)


def validator_synth_clr(rd):
    # clr rd == or %g0, %g0, rd
    return validator_encode_alu_reg(0x02, 0, 0, rd)


def validator_synth_nop():
    return validator_encode_nop()


def validator_is_nop(word):
    return _u32(word) == validator_encode_nop()


def validator_build_return_seq():
    # jmpl %i7+8, %g0 ; restore
    # jmpl with rs1=%i7 (31), simm13=8, rd=%g0
    jmpl = validator_encode_jmpl(31, 8, 0)
    # restore = restore %g0,%g0,%g0 : op3=0x3D, op=10
    restore = validator_encode_alu_reg(0x3D, 0, 0, 0)
    return [jmpl, restore]


def validator_build_epilogue():
    return validator_build_return_seq()


def validator_build_prologue(framesize):
    # save %sp, -framesize, %sp : op3=0x3C
    # framesize must fit simm13
    neg = (-framesize) & 0x1FFF
    return validator_encode_alu_imm(0x3C, 14, neg, 14)  # rs1=%sp(14? no - sp=r14)
    # Note: %sp = r14 (o6). Yes correct.


def validator_is_save(word):
    w = _u32(word)
    op = (w >> 30) & 0x3
    op3 = (w >> 19) & 0x3F
    return op == 0b10 and op3 == 0x3C


def validator_is_restore(word):
    w = _u32(word)
    op = (w >> 30) & 0x3
    op3 = (w >> 19) & 0x3F
    return op == 0b10 and op3 == 0x3D


# ---- Branch target extraction ---------------------------------------------
def validator_branch_target_bicc(pc, word):
    w = _u32(word)
    op = (w >> 30) & 0x3
    op2 = (w >> 22) & 0x7
    if op != 0 or op2 != 0b010:
        return None
    disp22 = w & 0x3FFFFF
    disp = _sext(disp22, 22) << 2
    return _u64(pc + disp)


def validator_branch_target_call(pc, word):
    w = _u32(word)
    op = (w >> 30) & 0x3
    if op != 0b01:
        return None
    disp30 = w & 0x3FFFFFFF
    disp = _sext(disp30, 30) << 2
    return _u64(pc + disp)


# ---- Register windows -----------------------------------------------------
def validator_total_physical_regs(nwindows):
    # 8 globals + 16 * nwindows (each window has 8 locals + 8 ins shared with prev outs)
    return 8 + 16 * nwindows


# ---- Calling convention / leaf detection ---------------------------------
def validator_classify_leaf(words):
    # Leaf = no save/restore, no call
    has_save = False
    has_call = False
    for w in words:
        w = _u32(w)
        op = (w >> 30) & 0x3
        if op == 0b01:
            has_call = True
        if validator_is_save(w):
            has_save = True
    if not has_save and not has_call:
        return "Leaf"
    if has_save:
        return "NonLeaf"
    return "LeafWithCall"


# ---- Trap tables ----------------------------------------------------------
SPARC_V8_TRAPS = {
    0x00: "reset",
    0x01: "instruction_access_exception",
    0x02: "illegal_instruction",
    0x03: "privileged_instruction",
    0x04: "fp_disabled",
    0x05: "window_overflow",
    0x06: "window_underflow",
    0x07: "mem_address_not_aligned",
    0x08: "fp_exception",
    0x09: "data_access_exception",
    0x0A: "tag_overflow",
    0x80: "trap_instruction",  # ta 0
}

SPARC_V9_EXTRA = {
    0x24: "clean_window",
    0x28: "division_by_zero",
    0x34: "mem_address_not_aligned",
    0x60: "interrupt_vector",
}


def validator_lookup_v8_trap(tt):
    return SPARC_V8_TRAPS.get(tt & 0xFF)


def validator_lookup_v9_trap(tt):
    tt &= 0xFF
    if tt in SPARC_V9_EXTRA:
        return SPARC_V9_EXTRA[tt]
    return SPARC_V8_TRAPS.get(tt)


def validator_trap_name(tt):
    return validator_lookup_v8_trap(tt)


def validator_trap_name_v9(tt):
    return validator_lookup_v9_trap(tt)


# ---- Condition codes (Bicc) ----------------------------------------------
SPARC_COND = {
    0x0: "bn",  0x1: "be",  0x2: "ble", 0x3: "bl",
    0x4: "bleu",0x5: "bcs", 0x6: "bneg",0x7: "bvs",
    0x8: "ba",  0x9: "bne", 0xA: "bg",  0xB: "bge",
    0xC: "bgu", 0xD: "bcc", 0xE: "bpos",0xF: "bvc",
}


def validator_lookup_condition(c):
    return SPARC_COND.get(c & 0xF)


# ---- ASI (some common) ----------------------------------------------------
SPARC_ASI = {
    0x04: "ASI_NUCLEUS",
    0x0C: "ASI_NUCLEUS_LITTLE",
    0x10: "ASI_AS_IF_USER_PRIMARY",
    0x11: "ASI_AS_IF_USER_SECONDARY",
    0x80: "ASI_PRIMARY",
    0x81: "ASI_SECONDARY",
    0x88: "ASI_PRIMARY_LITTLE",
    0x89: "ASI_SECONDARY_LITTLE",
}


def validator_lookup_asi(a):
    return SPARC_ASI.get(a & 0xFF)


# ---- Decoder via capstone -------------------------------------------------
def validator_decode_word(word, addr=0):
    if capstone is None:
        return {"error": "capstone-missing"}
    md = capstone.Cs(capstone.CS_ARCH_SPARC,
                     capstone.CS_MODE_BIG_ENDIAN)
    raw = _u32(word).to_bytes(4, "big")
    for i in md.disasm(raw, addr):
        return {"mnemonic": i.mnemonic, "op_str": i.op_str, "address": i.address}
    return None


# ---- Delay-slot semantics -------------------------------------------------
def validator_has_delay_slot(word):
    w = _u32(word)
    op = (w >> 30) & 0x3
    if op == 0b01:  # CALL
        return True
    if op == 0b00:
        op2 = (w >> 22) & 0x7
        if op2 in (0b010, 0b110, 0b111):  # Bicc, FBfcc, CBccc
            return True
        return False
    if op == 0b10:
        op3 = (w >> 19) & 0x3F
        # JMPL, RETT
        if op3 in (0x38, 0x39):
            return True
    return False


# ---- dispatch -------------------------------------------------------------
FUNCTIONS = {
    "reg_name": validator_reg_name,
    "freg_name": validator_freg_name,
    "encode_call": validator_encode_call,
    "encode_sethi": validator_encode_sethi,
    "encode_nop": validator_encode_nop,
    "encode_alu_reg": validator_encode_alu_reg,
    "encode_alu_imm": validator_encode_alu_imm,
    "encode_load": validator_encode_load,
    "encode_store": validator_encode_store,
    "encode_bicc": validator_encode_bicc,
    "encode_jmpl": validator_encode_jmpl,
    "synth_mov_reg": validator_synth_mov_reg,
    "synth_mov_imm": validator_synth_mov_imm,
    "synth_clr": validator_synth_clr,
    "synth_nop": validator_synth_nop,
    "is_nop": validator_is_nop,
    "build_return_seq": validator_build_return_seq,
    "build_epilogue": validator_build_epilogue,
    "build_prologue": validator_build_prologue,
    "is_save": validator_is_save,
    "is_restore": validator_is_restore,
    "branch_target_bicc": validator_branch_target_bicc,
    "branch_target_call": validator_branch_target_call,
    "total_physical_regs": validator_total_physical_regs,
    "classify_leaf": validator_classify_leaf,
    "lookup_v8_trap": validator_lookup_v8_trap,
    "lookup_v9_trap": validator_lookup_v9_trap,
    "trap_name": validator_trap_name,
    "trap_name_v9": validator_trap_name_v9,
    "lookup_condition": validator_lookup_condition,
    "lookup_asi": validator_lookup_asi,
    "decode_word": validator_decode_word,
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
        print(json.dumps({"result": out},
                         default=lambda o: list(o) if isinstance(o, (bytes, bytearray)) else o))
        return
    samples = [
        ("encode_nop", []),
        ("is_nop", [0x01000000]),
        ("encode_call", [0x1000]),
        ("encode_sethi", {"rd": 1, "imm22": 0x12345}),
        ("encode_bicc", {"cond": 0x8, "annul": False, "disp": 0x100}),  # ba
        ("encode_jmpl", {"rs1": 31, "simm13": 8, "rd": 0}),
        ("synth_mov_reg", {"rs": 8, "rd": 9}),
        ("synth_clr", [8]),
        ("build_return_seq", []),
        ("build_prologue", [96]),
        ("is_save", [validator_build_prologue(96)]),
        ("reg_name", [14]),
        ("reg_name", [30]),
        ("freg_name", [5]),
        ("branch_target_call", [0x1000, validator_encode_call(0x40)]),
        ("total_physical_regs", [8]),
        ("classify_leaf", [[validator_encode_nop()]]),
        ("lookup_v8_trap", [0x05]),
        ("lookup_v9_trap", [0x24]),
        ("lookup_condition", [0x8]),
        ("lookup_asi", [0x80]),
        ("has_delay_slot", [validator_encode_call(0x10)]),
    ]
    results = {}
    for name, a in samples:
        try:
            results[name] = dispatch(name, a)
        except Exception as e:
            results[name] = f"ERR:{e}"
    print(json.dumps(results, indent=2, default=str))


if __name__ == "__main__":
    main()
