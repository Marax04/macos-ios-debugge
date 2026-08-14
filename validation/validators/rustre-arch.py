#!/usr/bin/env python3
"""Independent Python validator for rustre-arch crate.

Validates pure-logic functions described in reports/rustre-arch.md:
- detect_arch_from_bytes (ELF/PE/Mach-O dispatch)
- detect_from_elf
- detect_from_pe
- detect_from_macho
- LiftContext push overflow cap (4096)
- InstrStats branch_density
- ArchMetadata fixed_width / variable_width

Stdlib only. No imports from the Rust crate, no MCP calls.
"""

import json
import struct
import sys


# ---------------------------------------------------------------- detection

def detect_from_elf(data):
    if len(data) < 20 or data[:4] != b"\x7fELF":
        return None
    ei_class = data[4]   # 1=32, 2=64
    ei_data = data[5]    # 1=LE, 2=BE
    if ei_data == 1:
        e_machine = data[18] | (data[19] << 8)
    elif ei_data == 2:
        e_machine = (data[18] << 8) | data[19]
    else:
        return None
    table = {
        3: "x86",
        62: "x86_64",
        40: "arm",
        183: "arm64",
        8: "mips",
        20: "ppc",
        21: "ppc64",
        2: "sparc",
        18: "sparc64",
        220: "msp430",
        83: "avr",
    }
    if e_machine == 243:
        return "riscv64" if ei_class == 2 else "riscv32"
    return table.get(e_machine)


def detect_from_pe(data):
    if len(data) < 0x40 or data[:2] != b"MZ":
        return None
    pe_off = struct.unpack_from("<I", data, 0x3C)[0]
    if pe_off + 6 > len(data):
        return None
    if data[pe_off:pe_off + 4] != b"PE\x00\x00":
        return None
    machine = struct.unpack_from("<H", data, pe_off + 4)[0]
    table = {
        0x014c: "x86",
        0x8664: "x86_64",
        0x01c0: "arm",
        0xaa64: "arm64",
        0x01f0: "ppc",
        0x0162: "mips",
    }
    return table.get(machine)


def detect_from_macho(data):
    if len(data) < 8:
        return None
    magic = data[:4]
    if magic in (b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf"):
        cputype = struct.unpack_from(">I", data, 4)[0]
    elif magic in (b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe"):
        cputype = struct.unpack_from("<I", data, 4)[0]
    else:
        return None
    table = {
        7: "x86",
        0x01000007: "x86_64",
        12: "arm",
        0x0100000c: "arm64",
        18: "ppc",
        0x01000012: "ppc64",
    }
    return table.get(cputype)


def detect_arch_from_bytes(data):
    if not data or len(data) < 4:
        return None
    if data[:4] == b"\x7fELF":
        return detect_from_elf(data)
    if data[:2] == b"MZ":
        return detect_from_pe(data)
    if data[:4] in (b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf",
                    b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe"):
        return detect_from_macho(data)
    return None


# ---------------------------------------------------------------- LiftContext

class LiftContext:
    MAX_DEPTH = 4096
    MAX_WARN = 4096

    def __init__(self):
        self.depth = 0
        self.temps = {}
        self.warnings = []

    def push(self):
        if self.depth >= self.MAX_DEPTH:
            raise OverflowError("StackOverflow")
        self.depth += 1

    def pop(self):
        if self.depth > 0:
            self.depth -= 1

    def set_temp(self, name, value):
        self.temps[name] = value & 0xFFFFFFFFFFFFFFFF

    def get_temp(self, name):
        return self.temps.get(name)

    def warn(self, msg):
        if len(self.warnings) < self.MAX_WARN:
            self.warnings.append(msg)

    def has_warnings(self):
        return bool(self.warnings)


# ---------------------------------------------------------------- ArchMetadata

class ArchMetadata:
    def __init__(self, description, min_instr_size, max_instr_size,
                 variable_length, nop_bytes):
        self.description = description
        self.min_instr_size = min_instr_size
        self.max_instr_size = max_instr_size
        self.variable_length = variable_length
        self.nop_bytes = nop_bytes

    @classmethod
    def fixed_width(cls, instr_size, nop, description):
        return cls(description, instr_size, instr_size, False, list(nop))

    @classmethod
    def variable_width(cls, mn, mx, nop, description):
        return cls(description, mn, mx, True, list(nop))


# ---------------------------------------------------------------- InstrStats

class InstrStats:
    def __init__(self):
        self.total = 0
        self.branches = 0
        self.calls = 0
        self.returns = 0
        self.conditionals = 0
        self.memory_ops = 0

    def feed(self, instr):
        self.total += 1
        flags = instr.get("flags", set()) if isinstance(instr, dict) else set()
        if "branch" in flags:
            self.branches += 1
        if "call" in flags:
            self.calls += 1
        if "return" in flags:
            self.returns += 1
        if "conditional" in flags:
            self.conditionals += 1
        if "memory" in flags:
            self.memory_ops += 1

    def branch_density(self):
        if self.total == 0:
            return 0.0
        return self.branches / self.total


# ---------------------------------------------------------------- self-tests

def run_tests():
    results = []

    def check(name, cond, detail=""):
        results.append({"name": name, "ok": bool(cond), "detail": detail})

    # ELF x86_64
    elf64 = bytearray(64)
    elf64[0:4] = b"\x7fELF"
    elf64[4] = 2  # 64-bit
    elf64[5] = 1  # LE
    struct.pack_into("<H", elf64, 18, 62)
    check("detect_elf_x86_64", detect_from_elf(bytes(elf64)) == "x86_64")

    # ELF arm64 BE encoding test (still LE EI_DATA)
    elf_arm64 = bytearray(64)
    elf_arm64[0:4] = b"\x7fELF"
    elf_arm64[4] = 2
    elf_arm64[5] = 1
    struct.pack_into("<H", elf_arm64, 18, 183)
    check("detect_elf_arm64", detect_from_elf(bytes(elf_arm64)) == "arm64")

    # ELF riscv64
    elf_rv = bytearray(64)
    elf_rv[0:4] = b"\x7fELF"
    elf_rv[4] = 2
    elf_rv[5] = 1
    struct.pack_into("<H", elf_rv, 18, 243)
    check("detect_elf_riscv64", detect_from_elf(bytes(elf_rv)) == "riscv64")

    # ELF riscv32
    elf_rv[4] = 1
    check("detect_elf_riscv32", detect_from_elf(bytes(elf_rv)) == "riscv32")

    # PE x86_64
    pe = bytearray(0x100)
    pe[0:2] = b"MZ"
    struct.pack_into("<I", pe, 0x3C, 0x80)
    pe[0x80:0x84] = b"PE\x00\x00"
    struct.pack_into("<H", pe, 0x84, 0x8664)
    check("detect_pe_x86_64", detect_from_pe(bytes(pe)) == "x86_64")

    # Mach-O 64 LE arm64
    macho = bytearray(32)
    macho[0:4] = b"\xcf\xfa\xed\xfe"
    struct.pack_into("<I", macho, 4, 0x0100000c)
    check("detect_macho_arm64", detect_from_macho(bytes(macho)) == "arm64")

    # Mach-O BE 32 ppc
    macho_be = bytearray(32)
    macho_be[0:4] = b"\xfe\xed\xfa\xce"
    struct.pack_into(">I", macho_be, 4, 18)
    check("detect_macho_ppc", detect_from_macho(bytes(macho_be)) == "ppc")

    # dispatch
    check("dispatch_elf", detect_arch_from_bytes(bytes(elf64)) == "x86_64")
    check("dispatch_pe", detect_arch_from_bytes(bytes(pe)) == "x86_64")
    check("dispatch_macho", detect_arch_from_bytes(bytes(macho)) == "arm64")
    check("dispatch_unknown", detect_arch_from_bytes(b"\x00\x00\x00\x00") is None)

    # LiftContext overflow
    ctx = LiftContext()
    overflowed = False
    try:
        for _ in range(LiftContext.MAX_DEPTH):
            ctx.push()
        try:
            ctx.push()
        except OverflowError:
            overflowed = True
    except Exception:
        overflowed = False
    check("lift_overflow_at_4096", overflowed and ctx.depth == 4096)

    # pop saturating
    c2 = LiftContext()
    c2.pop()
    c2.pop()
    check("lift_pop_saturates", c2.depth == 0)

    # warn cap
    c3 = LiftContext()
    for i in range(LiftContext.MAX_WARN + 10):
        c3.warn("w")
    check("lift_warn_cap_4096", len(c3.warnings) == LiftContext.MAX_WARN)

    # ArchMetadata
    m = ArchMetadata.fixed_width(4, b"\x00\x00\x00\x00", "arm64")
    check("meta_fixed", m.min_instr_size == 4 and m.max_instr_size == 4
          and m.variable_length is False)
    mv = ArchMetadata.variable_width(1, 15, b"\x90", "x86")
    check("meta_variable", mv.min_instr_size == 1 and mv.max_instr_size == 15
          and mv.variable_length is True)

    # InstrStats branch density
    st = InstrStats()
    st.feed({"flags": {"branch"}})
    st.feed({"flags": set()})
    st.feed({"flags": {"branch", "conditional"}})
    st.feed({"flags": {"call"}})
    check("stats_total", st.total == 4)
    check("stats_branches", st.branches == 2)
    check("stats_density", abs(st.branch_density() - 0.5) < 1e-9)
    check("stats_empty_density", InstrStats().branch_density() == 0.0)

    return results


def main():
    results = run_tests()
    saved = all(r["ok"] for r in results)
    out = {
        "crate": "rustre-arch",
        "saved": saved,
        "functions": results,
    }
    print(json.dumps(out, indent=2))
    return 0 if saved else 1


if __name__ == "__main__":
    sys.exit(main())
