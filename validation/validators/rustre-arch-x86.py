#!/usr/bin/env python3
"""
Standalone validator for the rustre-arch-x86 crate.

Reimplements (with independent libraries) the externally-verifiable ground
truth used to check the Rust crate:
 - x86 disassembly (mnemonic / length / operands)        -> capstone
 - LLIL/lift length consistency                          -> capstone (length only)
 - branch target resolution (CALL rel32 / Jcc rel8/32)   -> manual pc + len + disp
 - LinearDisassembler iteration count / sum-of-lengths   -> capstone
 - constants (pointer_size / endian / name / bits)       -> pure Python
 - register tables for 16/32/64 bit                      -> static tables
 - decode_one_iced None/Some semantics                   -> capstone try-decode

No Rust crate import, no MCP calls. stdlib + capstone only.

Usage:
  echo '{"fn":"disassemble","bits":64,"address":0,"bytes":"90"}' | python rustre-arch-x86.py
  python rustre-arch-x86.py            # runs main() self-test on fixed inputs
"""

import json
import struct
import subprocess
import sys


def _ensure(pkg, import_name=None):
    name = import_name or pkg
    try:
        return __import__(name)
    except ImportError:
        subprocess.check_call(
            [sys.executable, "-m", "pip", "install", "--quiet", pkg]
        )
        return __import__(name)


capstone = _ensure("capstone")
from capstone import (  # noqa: E402
    Cs,
    CS_ARCH_X86,
    CS_MODE_16,
    CS_MODE_32,
    CS_MODE_64,
    CS_OPT_SYNTAX_ATT,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _hex_to_bytes(s):
    if isinstance(s, (bytes, bytearray)):
        return bytes(s)
    s = s.replace(" ", "").replace(",", "").replace("0x", "")
    return bytes.fromhex(s)


def _cs_for(bits, att=True):
    mode = {16: CS_MODE_16, 32: CS_MODE_32, 64: CS_MODE_64}[bits]
    md = Cs(CS_ARCH_X86, mode)
    if att:
        md.syntax = CS_OPT_SYNTAX_ATT
    md.detail = True
    return md


# ---------------------------------------------------------------------------
# Per-function validators
# ---------------------------------------------------------------------------

def validator_bits(inp):
    """X86Arch::bits — trivial constant per constructor."""
    ctor = inp["ctor"]  # "new_16bit" | "new_32bit" | "new_64bit"
    return {"bits": {"new_16bit": 16, "new_32bit": 32, "new_64bit": 64}[ctor]}


def validator_pointer_size(inp):
    return {"pointer_size": {16: 2, 32: 4, 64: 8}[inp["bits"]]}


def validator_endian(inp):
    return {"endian": "little"}


def validator_name(inp):
    return {"name": {16: "x86_16", 32: "x86_32", 64: "x86_64"}[inp["bits"]]}


def validator_disassemble(inp):
    """X86Arch::disassemble — decode ONE instruction at `address`."""
    bits = inp.get("bits", 64)
    address = inp.get("address", 0)
    data = _hex_to_bytes(inp["bytes"])
    md = _cs_for(bits, att=True)
    for ins in md.disasm(data, address):
        return {
            "address": ins.address,
            "length": ins.size,
            "mnemonic": ins.mnemonic,
            "operands": ins.op_str,
            "bytes": ins.bytes.hex(),
        }
    return {"error": "invalid encoding"}


def validator_lift_length(inp):
    """X86Arch::lift — only the (length,) part is independently verifiable here."""
    res = validator_disassemble(inp)
    return {"length": res.get("length")}


def validator_get_branches(inp):
    """X86Arch::get_branches — compute static near-target = pc + len + disp."""
    bits = inp.get("bits", 64)
    address = inp.get("address", 0)
    data = _hex_to_bytes(inp["bytes"])
    md = _cs_for(bits, att=True)
    branches = []
    for ins in md.disasm(data, address):
        m = ins.mnemonic
        if m == "call" or m.startswith("j") or m == "loop" or m.startswith("loop"):
            # capstone exposes the immediate operand as ins.op_str (an int address
            # for direct near branches), but to stay independent of cs decoding
            # of the target, recompute from raw bytes for the common encodings.
            b = ins.bytes
            target = None
            if len(b) == 5 and b[0] == 0xE8:  # CALL rel32
                disp = struct.unpack("<i", b[1:5])[0]
                target = ins.address + 5 + disp
            elif len(b) == 5 and b[0] == 0xE9:  # JMP rel32
                disp = struct.unpack("<i", b[1:5])[0]
                target = ins.address + 5 + disp
            elif len(b) == 2 and b[0] == 0xEB:  # JMP rel8
                disp = struct.unpack("<b", b[1:2])[0]
                target = ins.address + 2 + disp
            elif len(b) == 2 and 0x70 <= b[0] <= 0x7F:  # Jcc rel8
                disp = struct.unpack("<b", b[1:2])[0]
                target = ins.address + 2 + disp
            elif len(b) == 6 and b[0] == 0x0F and 0x80 <= b[1] <= 0x8F:  # Jcc rel32
                disp = struct.unpack("<i", b[2:6])[0]
                target = ins.address + 6 + disp
            branches.append({"mnemonic": m, "target": target, "len": ins.size})
        break  # single instruction
    return {"branches": branches}


def validator_linear_disassemble(inp):
    """LinearDisassembler iteration over a byte blob."""
    bits = inp.get("bits", 64)
    base = inp.get("base", 0)
    data = _hex_to_bytes(inp["bytes"])
    md = _cs_for(bits, att=True)
    count = 0
    total_len = 0
    last_addr = base
    for ins in md.disasm(data, base):
        count += 1
        total_len += ins.size
        last_addr = ins.address + ins.size
    return {
        "count": count,
        "sum_of_lengths": total_len,
        "is_done": total_len == len(data),
        "final_offset": total_len,
        "final_address": last_addr,
    }


def validator_decode_one_iced(inp):
    """X86LiftAdapter::decode_one_iced — Some(_) iff bytes decode."""
    bits = inp.get("bits", 64)
    data = _hex_to_bytes(inp.get("bytes", ""))
    if len(data) == 0:
        return {"some": False}
    md = _cs_for(bits, att=True)
    for ins in md.disasm(data, inp.get("ip", 0)):
        return {"some": True, "length": ins.size, "mnemonic": ins.mnemonic}
    return {"some": False}


# Register tables (canonical). Counts only need to match.
_REGS_64 = (
    ["rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp",
     "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15",
     "rip", "rflags",
     "cs", "ds", "es", "fs", "gs", "ss"]
    + [f"xmm{i}" for i in range(16)]
    + [f"ymm{i}" for i in range(16)]
)

_REGS_32 = (
    ["eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp",
     "eip", "eflags",
     "cs", "ds", "es", "fs", "gs", "ss"]
    + [f"xmm{i}" for i in range(8)]
)

_REGS_16 = [
    "ax", "bx", "cx", "dx", "si", "di", "bp", "sp",
    "ip", "flags",
    "cs", "ds", "es", "ss",
]


def validator_registers(inp):
    bits = inp["bits"]
    table = {16: _REGS_16, 32: _REGS_32, 64: _REGS_64}[bits]
    return {
        "count": len(table),
        "has_rax": "rax" in table,
        "has_rip": "rip" in table,
        "has_rsp": "rsp" in table,
        "registers": table,
    }


def validator_calling_conventions(inp):
    """Empty for 16-bit; non-empty for 32/64."""
    bits = inp["bits"]
    if bits == 16:
        return {"conventions": []}
    if bits == 32:
        return {"conventions": ["cdecl", "stdcall", "fastcall", "thiscall"]}
    return {"conventions": ["sysv64", "win64"]}


# ---------------------------------------------------------------------------
# Dispatcher
# ---------------------------------------------------------------------------

DISPATCH = {
    "bits": validator_bits,
    "pointer_size": validator_pointer_size,
    "endian": validator_endian,
    "name": validator_name,
    "disassemble": validator_disassemble,
    "lift_length": validator_lift_length,
    "get_branches": validator_get_branches,
    "linear_disassemble": validator_linear_disassemble,
    "decode_one_iced": validator_decode_one_iced,
    "registers": validator_registers,
    "calling_conventions": validator_calling_conventions,
}


def dispatch(payload):
    fn = payload.get("fn")
    if fn not in DISPATCH:
        return {"error": f"unknown fn: {fn}", "available": list(DISPATCH)}
    return DISPATCH[fn](payload)


# ---------------------------------------------------------------------------
# main / self-test
# ---------------------------------------------------------------------------

def main():
    # If stdin has JSON, use it; otherwise run fixed self-tests.
    data = sys.stdin.read() if not sys.stdin.isatty() else ""
    if data.strip():
        payload = json.loads(data)
        print(json.dumps(dispatch(payload), indent=2))
        return

    fixtures = [
        {"fn": "bits", "ctor": "new_64bit"},
        {"fn": "pointer_size", "bits": 64},
        {"fn": "endian", "bits": 64},
        {"fn": "name", "bits": 64},
        # 0x90 -> nop, len 1
        {"fn": "disassemble", "bits": 64, "address": 0x1000, "bytes": "90"},
        # 0x48 0x89 0xC3 -> mov rbx, rax (AT&T: mov %rax, %rbx), len 3
        {"fn": "disassemble", "bits": 64, "address": 0x1000, "bytes": "4889C3"},
        # 0xC3 -> ret
        {"fn": "disassemble", "bits": 64, "address": 0x1000, "bytes": "C3"},
        # CALL rel32 from 0x1000 with disp=+0x10 -> target 0x1015
        {"fn": "get_branches", "bits": 64, "address": 0x1000,
         "bytes": "E810000000"},
        # JMP rel8 from 0x2000 with disp=-2 -> target 0x2000
        {"fn": "get_branches", "bits": 64, "address": 0x2000, "bytes": "EBFE"},
        # Linear: nop; mov rbx,rax; ret  => 1 + 3 + 1 = 5 bytes, 3 instrs
        {"fn": "linear_disassemble", "bits": 64, "base": 0x1000,
         "bytes": "904889C3C3"},
        # decode_one_iced positive / negative
        {"fn": "decode_one_iced", "bits": 64, "ip": 0, "bytes": "90"},
        {"fn": "decode_one_iced", "bits": 64, "ip": 0, "bytes": ""},
        # Register tables
        {"fn": "registers", "bits": 64},
        {"fn": "registers", "bits": 32},
        {"fn": "registers", "bits": 16},
        # Calling conventions
        {"fn": "calling_conventions", "bits": 16},
        {"fn": "calling_conventions", "bits": 32},
        {"fn": "calling_conventions", "bits": 64},
    ]

    results = []
    for f in fixtures:
        results.append({"input": f, "output": dispatch(f)})
    print(json.dumps(results, indent=2))


if __name__ == "__main__":
    main()
