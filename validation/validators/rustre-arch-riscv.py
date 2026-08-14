#!/usr/bin/env python3
"""
Standalone validator for the rustre-arch-riscv crate.

Implements reference logic in pure Python (no Rust import, no MCP) for the
testable functions described in
validation/reports/rustre-arch-riscv.md.

Usage:
    echo '{"fn": "rv_brev8_32", "input": 305419896}' | python rustre-arch-riscv.py
    python rustre-arch-riscv.py            # runs main() self-test
"""

import json
import sys
import struct


# ---------------------------------------------------------------------------
# Pure bit ops
# ---------------------------------------------------------------------------

def validator_rv_brev8_32(val: int) -> int:
    """Zbkb brev8: bit-reverse each byte of a u32."""
    val &= 0xFFFFFFFF
    out = 0
    for i in range(4):
        b = (val >> (8 * i)) & 0xFF
        rb = int(f"{b:08b}"[::-1], 2)
        out |= rb << (8 * i)
    return out & 0xFFFFFFFF


def validator_rv_c_classify(hw: int) -> str:
    """Classify a 16-bit halfword as RVC quadrant / not-compressed."""
    hw &= 0xFFFF
    low2 = hw & 0b11
    if low2 == 0b11:
        return "not-compressed"
    return f"quadrant{low2}"


def validator_rv_fp_rm_str(rm: int) -> str:
    table = {0: "rne", 1: "rtz", 2: "rdn", 3: "rup", 4: "rmm", 7: "dyn"}
    return table.get(rm & 0x7, "reserved")


def validator_rv_fclass_bit_name(bit: int) -> str:
    names = [
        "-inf", "-normal", "-subnormal", "-zero",
        "+zero", "+subnormal", "+normal", "+inf",
        "snan", "qnan",
    ]
    if 0 <= bit < len(names):
        return names[bit]
    return "invalid"


def validator_mcause_decode(cause: int, xlen: int = 64):
    """Split mcause into (is_interrupt, code, name)."""
    msb = 1 << (xlen - 1)
    is_int = bool(cause & msb)
    code = cause & (msb - 1)
    exc_names = {
        0: "instruction address misaligned",
        1: "instruction access fault",
        2: "illegal instruction",
        3: "breakpoint",
        4: "load address misaligned",
        5: "load access fault",
        6: "store/amo address misaligned",
        7: "store/amo access fault",
        8: "environment call from u-mode",
        9: "environment call from s-mode",
        11: "environment call from m-mode",
        12: "instruction page fault",
        13: "load page fault",
        15: "store/amo page fault",
    }
    int_names = {
        1: "supervisor software interrupt",
        3: "machine software interrupt",
        5: "supervisor timer interrupt",
        7: "machine timer interrupt",
        9: "supervisor external interrupt",
        11: "machine external interrupt",
    }
    name = (int_names if is_int else exc_names).get(code, "unknown")
    return {"is_interrupt": is_int, "code": code, "name": name}


# ---------------------------------------------------------------------------
# Tables (subsets sufficient for spec-grounded checks)
# ---------------------------------------------------------------------------

CSR_TABLE = {
    0x001: ("fflags",     "URW", "user"),
    0x002: ("frm",        "URW", "user"),
    0x003: ("fcsr",       "URW", "user"),
    0xC00: ("cycle",      "URO", "user"),
    0xC01: ("time",       "URO", "user"),
    0xC02: ("instret",    "URO", "user"),
    0x100: ("sstatus",    "SRW", "supervisor"),
    0x104: ("sie",        "SRW", "supervisor"),
    0x105: ("stvec",      "SRW", "supervisor"),
    0x140: ("sscratch",   "SRW", "supervisor"),
    0x141: ("sepc",       "SRW", "supervisor"),
    0x142: ("scause",     "SRW", "supervisor"),
    0x143: ("stval",      "SRW", "supervisor"),
    0x144: ("sip",        "SRW", "supervisor"),
    0x180: ("satp",       "SRW", "supervisor"),
    0x300: ("mstatus",    "MRW", "machine"),
    0x301: ("misa",       "MRW", "machine"),
    0x304: ("mie",        "MRW", "machine"),
    0x305: ("mtvec",      "MRW", "machine"),
    0x340: ("mscratch",   "MRW", "machine"),
    0x341: ("mepc",       "MRW", "machine"),
    0x342: ("mcause",     "MRW", "machine"),
    0x343: ("mtval",      "MRW", "machine"),
    0x344: ("mip",        "MRW", "machine"),
    0xF11: ("mvendorid",  "MRO", "machine"),
    0xF12: ("marchid",    "MRO", "machine"),
    0xF13: ("mimpid",     "MRO", "machine"),
    0xF14: ("mhartid",    "MRO", "machine"),
}


def validator_rv_csr_ext_lookup(addr: int):
    addr &= 0xFFFF
    if addr in CSR_TABLE:
        name, access, priv = CSR_TABLE[addr]
        return {"addr": addr, "name": name, "access": access, "privilege": priv}
    return None


def validator_csr_name(addr: int) -> str:
    e = validator_rv_csr_ext_lookup(addr)
    return e["name"] if e else f"csr_{addr:03x}"


# SBI base extension (eid=0x10) — SBI v1.0 spec
SBI_TABLE = {
    (0x10, 0): "sbi_get_spec_version",
    (0x10, 1): "sbi_get_impl_id",
    (0x10, 2): "sbi_get_impl_version",
    (0x10, 3): "sbi_probe_extension",
    (0x10, 4): "sbi_get_mvendorid",
    (0x10, 5): "sbi_get_marchid",
    (0x10, 6): "sbi_get_mimpid",
    (0x54494D45, 0): "sbi_set_timer",       # TIME
    (0x735049, 0): "sbi_send_ipi",          # sPI
    (0x52464E43, 0): "sbi_remote_fence_i",  # RFNC
    (0x53525354, 0): "sbi_system_reset",    # SRST
}


def validator_sbi_lookup(eid: int, fid: int):
    name = SBI_TABLE.get((eid, fid))
    if name:
        return {"eid": eid, "fid": fid, "name": name}
    return None


# Linux RISC-V (generic) syscall numbers — subset
SYSCALL_TABLE = {
    17:  "getcwd",
    35:  "unlinkat",
    48:  "faccessat",
    56:  "openat",
    57:  "close",
    62:  "lseek",
    63:  "read",
    64:  "write",
    78:  "readlinkat",
    93:  "exit",
    94:  "exit_group",
    96:  "set_tid_address",
    113: "clock_gettime",
    134: "rt_sigaction",
    172: "getpid",
    214: "brk",
    215: "munmap",
    222: "mmap",
    226: "mprotect",
}


def validator_rv_syscall_lookup(nr: int):
    name = SYSCALL_TABLE.get(nr)
    if name:
        return {"nr": nr, "name": name}
    return None


# QEMU virt platform MMIO map (hw/riscv/virt.c)
QEMU_VIRT_REGIONS = [
    (0x00001000, 0x00012000, "mrom/debug"),
    (0x00100000, 0x00101000, "test"),
    (0x00101000, 0x00102000, "rtc"),
    (0x02000000, 0x02010000, "clint"),
    (0x0C000000, 0x10000000, "plic"),
    (0x10000000, 0x10000100, "uart0"),
    (0x10001000, 0x10002000, "virtio"),
    (0x30000000, 0x40000000, "pcie-ecam"),
    (0x40000000, 0x80000000, "pcie-mmio"),
    (0x80000000, 0x100000000, "dram"),
]


def validator_rv_qemu_region_lookup(addr: int):
    for lo, hi, name in QEMU_VIRT_REGIONS:
        if lo <= addr < hi:
            return {"base": lo, "size": hi - lo, "name": name}
    return None


# ABI registers (psABI)
ABI_REGS = {
    "zero": (0,  "zero",       False),
    "ra":   (1,  "return-addr", False),  # caller-saved
    "sp":   (2,  "stack-ptr",  True),    # callee-saved
    "gp":   (3,  "global-ptr", False),
    "tp":   (4,  "thread-ptr", False),
    "t0":   (5,  "temp",       False),
    "t1":   (6,  "temp",       False),
    "t2":   (7,  "temp",       False),
    "s0":   (8,  "saved",      True),
    "s1":   (9,  "saved",      True),
    "a0":   (10, "arg/ret",    False),
    "a1":   (11, "arg/ret",    False),
    "a2":   (12, "arg",        False),
    "a3":   (13, "arg",        False),
    "a4":   (14, "arg",        False),
    "a5":   (15, "arg",        False),
    "a6":   (16, "arg",        False),
    "a7":   (17, "arg",        False),
    "s2":   (18, "saved",      True),
    "s3":   (19, "saved",      True),
    "s4":   (20, "saved",      True),
    "s5":   (21, "saved",      True),
    "s6":   (22, "saved",      True),
    "s7":   (23, "saved",      True),
    "s8":   (24, "saved",      True),
    "s9":   (25, "saved",      True),
    "s10":  (26, "saved",      True),
    "s11":  (27, "saved",      True),
    "t3":   (28, "temp",       False),
    "t4":   (29, "temp",       False),
    "t5":   (30, "temp",       False),
    "t6":   (31, "temp",       False),
}


def validator_rv_abi_reg_lookup(name: str):
    e = ABI_REGS.get(name)
    if e:
        idx, role, callee = e
        return {"name": name, "x": idx, "role": role, "callee_saved": callee}
    return None


def validator_rv_arg_regs():
    return [validator_rv_abi_reg_lookup(f"a{i}") for i in range(8)]


def validator_rv_fp_arg_regs():
    return [{"name": f"fa{i}", "f": i + 10, "role": "fp-arg"} for i in range(8)]


def validator_rv_callee_saved_regs():
    return [validator_rv_abi_reg_lookup(n)
            for n, v in ABI_REGS.items() if v[2]]


# ---------------------------------------------------------------------------
# Simple prologue detector (subset: addi sp,sp,-imm; sd rs2,off(sp))
# ---------------------------------------------------------------------------

def _sext(val, bits):
    sign = 1 << (bits - 1)
    return (val & (sign - 1)) - (val & sign)


def validator_rv_detect_prologue(words):
    """
    Given list of 32-bit words, detect:
      - frame_size from `addi sp,sp,-imm`
      - spills: list of {reg, offset} from `sd rsX, off(sp)` (RV64, funct3=011)
    """
    frame_size = None
    spills = []
    for w in words:
        w &= 0xFFFFFFFF
        opcode = w & 0x7F
        rd = (w >> 7) & 0x1F
        funct3 = (w >> 12) & 0x7
        rs1 = (w >> 15) & 0x1F
        rs2 = (w >> 20) & 0x1F
        # addi sp,sp,imm : opcode=0x13 funct3=0 rd=2 rs1=2
        if opcode == 0x13 and funct3 == 0 and rd == 2 and rs1 == 2:
            imm = _sext((w >> 20) & 0xFFF, 12)
            if imm < 0 and frame_size is None:
                frame_size = -imm
            continue
        # store: opcode=0x23, rs1=sp(2). funct3 0=sb 1=sh 2=sw 3=sd
        if opcode == 0x23 and rs1 == 2 and funct3 in (2, 3):
            imm11_5 = (w >> 25) & 0x7F
            imm4_0 = (w >> 7) & 0x1F
            off = _sext((imm11_5 << 5) | imm4_0, 12)
            spills.append({"reg": rs2, "offset": off,
                           "width": 8 if funct3 == 3 else 4})
    return {"frame_size": frame_size, "spills": spills}


# ---------------------------------------------------------------------------
# Dispatch + self-test
# ---------------------------------------------------------------------------

DISPATCH = {
    "rv_brev8_32":          lambda i: validator_rv_brev8_32(i),
    "rv_c_classify":        lambda i: validator_rv_c_classify(i),
    "rv_fp_rm_str":         lambda i: validator_rv_fp_rm_str(i),
    "rv_fclass_bit_name":   lambda i: validator_rv_fclass_bit_name(i),
    "mcause_decode":        lambda i: validator_mcause_decode(i["cause"], i.get("xlen", 64)),
    "rv_csr_ext_lookup":    lambda i: validator_rv_csr_ext_lookup(i),
    "csr_name":             lambda i: validator_csr_name(i),
    "sbi_lookup":           lambda i: validator_sbi_lookup(i["eid"], i["fid"]),
    "rv_syscall_lookup":    lambda i: validator_rv_syscall_lookup(i),
    "rv_qemu_region_lookup": lambda i: validator_rv_qemu_region_lookup(i),
    "rv_abi_reg_lookup":    lambda i: validator_rv_abi_reg_lookup(i),
    "rv_arg_regs":          lambda i: validator_rv_arg_regs(),
    "rv_fp_arg_regs":       lambda i: validator_rv_fp_arg_regs(),
    "rv_callee_saved_regs": lambda i: validator_rv_callee_saved_regs(),
    "rv_detect_prologue":   lambda i: validator_rv_detect_prologue(i),
}


def main():
    if not sys.stdin.isatty():
        try:
            req = json.load(sys.stdin)
            fn = req["fn"]
            out = DISPATCH[fn](req.get("input"))
            print(json.dumps({"fn": fn, "output": out}, indent=2))
            return
        except Exception as e:
            print(json.dumps({"error": str(e)}))
            return

    # Self-test with fixed inputs
    results = {}
    results["rv_brev8_32(0x12345678)"] = hex(validator_rv_brev8_32(0x12345678))
    results["rv_c_classify(0x0001)"]   = validator_rv_c_classify(0x0001)  # quadrant1 (c.nop ...)
    results["rv_c_classify(0x0013)"]   = validator_rv_c_classify(0x0013)  # not-compressed
    results["rv_fp_rm_str(0)"]         = validator_rv_fp_rm_str(0)
    results["rv_fp_rm_str(7)"]         = validator_rv_fp_rm_str(7)
    results["rv_fclass_bit_name(8)"]   = validator_rv_fclass_bit_name(8)
    results["mcause_decode(2,64)"]     = validator_mcause_decode(2, 64)
    results["mcause_decode(int_msb|7)"] = validator_mcause_decode((1 << 63) | 7, 64)
    results["csr 0x300"]               = validator_rv_csr_ext_lookup(0x300)
    results["csr 0xC00"]               = validator_rv_csr_ext_lookup(0xC00)
    results["sbi(0x10,0)"]             = validator_sbi_lookup(0x10, 0)
    results["syscall 64"]              = validator_rv_syscall_lookup(64)
    results["qemu @0x10000000"]        = validator_rv_qemu_region_lookup(0x10000000)
    results["qemu @0x02000000"]        = validator_rv_qemu_region_lookup(0x02000000)
    results["abi sp"]                  = validator_rv_abi_reg_lookup("sp")
    results["abi a0"]                  = validator_rv_abi_reg_lookup("a0")
    results["arg_regs count"]          = len(validator_rv_arg_regs())
    results["callee_saved count"]      = len(validator_rv_callee_saved_regs())

    # Prologue: addi sp,sp,-32 ; sd ra,24(sp) ; sd s0,16(sp)
    # addi sp,sp,-32 = 0xfe010113
    # sd ra,24(sp)   = 0x00113c23
    # sd s0,16(sp)   = 0x00813823
    words = [0xfe010113, 0x00113c23, 0x00813823]
    results["prologue"] = validator_rv_detect_prologue(words)

    print(json.dumps(results, indent=2, default=str))


if __name__ == "__main__":
    main()
