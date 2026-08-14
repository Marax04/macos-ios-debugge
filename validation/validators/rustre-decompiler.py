#!/usr/bin/env python3
"""
Independent validator for rustre-decompiler crate.

Reimplements (in pure Python with stdlib + optional capstone/pefile) the
externally-testable functions of the crate, so outputs can be diff'd against
the Rust crate's behavior.

Usage:
    python rustre-decompiler.py            # runs main() self-tests, prints JSON
    echo '{"fn":"register_width_bytes","input":"rax"}' | python rustre-decompiler.py --stdin
"""
from __future__ import annotations

import json
import re
import struct
import subprocess
import sys
from typing import Any


# ---------------------------------------------------------------------------
# Optional dependency bootstrap
# ---------------------------------------------------------------------------
def _try_import(mod: str, pip_name: str | None = None):
    try:
        return __import__(mod)
    except ImportError:
        try:
            subprocess.check_call(
                [sys.executable, "-m", "pip", "install", "--quiet", pip_name or mod]
            )
            return __import__(mod)
        except Exception:
            return None


pefile = _try_import("pefile")
capstone = _try_import("capstone")


# ---------------------------------------------------------------------------
# Tier A: pure functions
# ---------------------------------------------------------------------------

# Intel SDM x86 register width table
_REG_WIDTH = {
    # 64-bit
    **{r: 8 for r in [
        "rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp",
        "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15",
        "rip",
    ]},
    # 32-bit
    **{r: 4 for r in [
        "eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp",
        "r8d", "r9d", "r10d", "r11d", "r12d", "r13d", "r14d", "r15d",
        "eip",
    ]},
    # 16-bit
    **{r: 2 for r in [
        "ax", "bx", "cx", "dx", "si", "di", "bp", "sp",
        "r8w", "r9w", "r10w", "r11w", "r12w", "r13w", "r14w", "r15w",
        "ip", "cs", "ds", "es", "fs", "gs", "ss",
    ]},
    # 8-bit
    **{r: 1 for r in [
        "al", "bl", "cl", "dl", "ah", "bh", "ch", "dh",
        "sil", "dil", "bpl", "spl",
        "r8b", "r9b", "r10b", "r11b", "r12b", "r13b", "r14b", "r15b",
    ]},
    # SSE/AVX
    **{f"xmm{i}": 16 for i in range(32)},
    **{f"ymm{i}": 32 for i in range(32)},
    **{f"zmm{i}": 64 for i in range(32)},
}

# Canonical (64-bit parent) map
_CANONICAL = {
    "eax": "rax", "ax": "rax", "al": "rax", "ah": "rax",
    "ebx": "rbx", "bx": "rbx", "bl": "rbx", "bh": "rbx",
    "ecx": "rcx", "cx": "rcx", "cl": "rcx", "ch": "rcx",
    "edx": "rdx", "dx": "rdx", "dl": "rdx", "dh": "rdx",
    "esi": "rsi", "si": "rsi", "sil": "rsi",
    "edi": "rdi", "di": "rdi", "dil": "rdi",
    "ebp": "rbp", "bp": "rbp", "bpl": "rbp",
    "esp": "rsp", "sp": "rsp", "spl": "rsp",
}
for i in range(8, 16):
    for suf, parent in [("d", f"r{i}"), ("w", f"r{i}"), ("b", f"r{i}")]:
        _CANONICAL[f"r{i}{suf}"] = parent


def validator_register_width_bytes(reg: str) -> int | None:
    return _REG_WIDTH.get(reg.lower().strip())


def validator_register_canonical(reg: str) -> str:
    r = reg.lower().strip()
    return _CANONICAL.get(r, r)


_PTR_WIDTH = {
    "byte": 1, "word": 2, "dword": 4, "qword": 8,
    "xmmword": 16, "ymmword": 32, "zmmword": 64, "tbyte": 10,
}


def validator_width_hint_from_instr(mnemonic: str, operands: str) -> int | None:
    """Look for 'X ptr [...]' hint or infer from register operand."""
    m = re.search(r"\b(byte|word|dword|qword|xmmword|ymmword|zmmword|tbyte)\s+ptr\b",
                  operands.lower())
    if m:
        return _PTR_WIDTH[m.group(1)]
    # Fallback: width of first register operand
    for tok in re.split(r"[,\s\[\]]+", operands.lower()):
        w = _REG_WIDTH.get(tok)
        if w:
            return w
    # Mnemonic hint
    mn = mnemonic.lower()
    if mn in ("movsb", "stosb", "cmpsb", "lodsb"):
        return 1
    if mn in ("movsw", "stosw", "cmpsw", "lodsw"):
        return 2
    if mn in ("movsd", "stosd", "cmpsd", "lodsd"):
        return 4
    if mn in ("movsq", "stosq", "cmpsq", "lodsq"):
        return 8
    return None


_C_KEYWORDS = {
    "auto", "break", "case", "char", "const", "continue", "default", "do",
    "double", "else", "enum", "extern", "float", "for", "goto", "if", "inline",
    "int", "long", "register", "restrict", "return", "short", "signed",
    "sizeof", "static", "struct", "switch", "typedef", "union", "unsigned",
    "void", "volatile", "while", "_Bool", "_Complex", "_Imaginary",
    "_Alignas", "_Alignof", "_Atomic", "_Generic", "_Noreturn",
    "_Static_assert", "_Thread_local",
}


def validator_is_c_keyword(name: str) -> bool:
    return name in _C_KEYWORDS


def validator_arch_from_str(s: str) -> str:
    s = s.lower().strip()
    table = {
        "x86": "X86", "x86_64": "X86_64", "x64": "X86_64", "amd64": "X86_64",
        "i386": "X86", "i686": "X86",
        "arm": "Arm", "arm64": "Aarch64", "aarch64": "Aarch64",
        "mips": "Mips", "riscv": "RiscV", "wasm": "Wasm",
    }
    return table.get(s, "Unknown")


_MEM_RE = re.compile(
    r"\[\s*(?P<base>[a-z][a-z0-9]*)?"
    r"(?:\s*\+\s*(?P<index>[a-z][a-z0-9]*)(?:\s*\*\s*(?P<scale>\d+))?)?"
    r"(?:\s*(?P<sign>[+\-])\s*(?P<disp>0x[0-9a-f]+|\d+))?\s*\]",
    re.IGNORECASE,
)


def validator_parse_mem_operands(operands: str) -> list[dict]:
    """Parse '[base + index*scale +/- disp]' fragments."""
    out = []
    for m in _MEM_RE.finditer(operands):
        disp = 0
        if m.group("disp"):
            d = int(m.group("disp"), 0)
            disp = -d if m.group("sign") == "-" else d
        out.append({
            "base": (m.group("base") or "").lower() or None,
            "index": (m.group("index") or "").lower() or None,
            "scale": int(m.group("scale")) if m.group("scale") else 1,
            "disp": disp,
        })
    return out


# ---------------------------------------------------------------------------
# Tier B: binary-grounded
# ---------------------------------------------------------------------------

def validator_load_binary(path: str) -> dict:
    """Return {arch, bits, base, sections:[...]} for a PE."""
    if pefile is None:
        return {"error": "pefile not available"}
    pe = pefile.PE(path, fast_load=True)
    machine = pe.FILE_HEADER.Machine
    arch = "X86_64" if machine == 0x8664 else ("X86" if machine == 0x14c else hex(machine))
    bits = 64 if machine == 0x8664 else 32
    base = pe.OPTIONAL_HEADER.ImageBase
    sections = [{
        "name": s.Name.rstrip(b"\x00").decode("latin1", "replace"),
        "va": base + s.VirtualAddress,
        "vsize": s.Misc_VirtualSize,
        "rsize": s.SizeOfRawData,
    } for s in pe.sections]
    return {"arch": arch, "bits": bits, "base": base, "sections": sections,
            "section_count": len(sections)}


def validator_slice_at_va(path: str, va: int, length: int = 16) -> dict:
    if pefile is None:
        return {"error": "pefile not available"}
    pe = pefile.PE(path, fast_load=True)
    base = pe.OPTIONAL_HEADER.ImageBase
    rva = va - base
    try:
        off = pe.get_offset_from_rva(rva)
    except Exception as e:
        return {"mapped": False, "error": str(e)}
    data = pe.__data__[off:off + length]
    return {"mapped": True, "file_offset": off, "bytes_hex": data.hex()}


def validator_disassemble_function_x86(bytes_hex: str, ip: int, bits: int = 64,
                                       max_instr: int = 64) -> list[dict]:
    if capstone is None:
        return [{"error": "capstone not available"}]
    mode = {16: capstone.CS_MODE_16, 32: capstone.CS_MODE_32,
            64: capstone.CS_MODE_64}[bits]
    md = capstone.Cs(capstone.CS_ARCH_X86, mode)
    data = bytes.fromhex(bytes_hex)
    out = []
    for i, ins in enumerate(md.disasm(data, ip)):
        out.append({
            "ip": ins.address, "size": ins.size,
            "mnemonic": ins.mnemonic, "op_str": ins.op_str,
            "bytes": ins.bytes.hex(),
        })
        if ins.mnemonic in ("ret", "retn", "retf", "hlt"):
            break
        if i + 1 >= max_instr:
            break
    return out


def validator_analyze_stack_frame(instructions: list[dict]) -> dict:
    """Detect sub rsp, N prologue + saved regs from a disasm list."""
    locals_size = 0
    saved = []
    for ins in instructions[:16]:
        mn = ins.get("mnemonic", "")
        op = ins.get("op_str", "")
        if mn == "push":
            saved.append(op.strip())
        elif mn == "sub" and "rsp" in op:
            m = re.search(r"(0x[0-9a-fA-F]+|\d+)\s*$", op)
            if m:
                locals_size = int(m.group(1), 0)
                break
        elif mn == "mov" and "rbp" in op and "rsp" in op:
            continue
        else:
            break
    return {"locals_size": locals_size, "saved_regs": saved}


_ALLOC_NAMES = {"malloc", "calloc", "realloc", "HeapAlloc", "VirtualAlloc",
                "LocalAlloc", "GlobalAlloc", "_malloc", "operator new",
                "RtlAllocateHeap", "mi_malloc", "je_malloc"}


def validator_detect_heap_bases(instructions: list[dict]) -> list[dict]:
    out = []
    for i, ins in enumerate(instructions):
        if ins.get("mnemonic") != "call":
            continue
        op = ins.get("op_str", "")
        for name in _ALLOC_NAMES:
            if name in op:
                out.append({"idx": i, "name": name})
                break
    return out


def validator_render_c_signature(sig: dict, name: str) -> str:
    ret = sig.get("return_type", "void")
    args = sig.get("args", [])
    if not args:
        arg_s = "void"
    else:
        arg_s = ", ".join(f"{a.get('ty','int')} {a.get('name', f'a{i}')}"
                          for i, a in enumerate(args))
    return f"{ret} {name}({arg_s})"


# ---------------------------------------------------------------------------
# Dispatcher
# ---------------------------------------------------------------------------
DISPATCH = {
    "register_width_bytes": lambda i: validator_register_width_bytes(i),
    "register_canonical": lambda i: validator_register_canonical(i),
    "width_hint_from_instr": lambda i: validator_width_hint_from_instr(
        i["mnemonic"], i["operands"]),
    "is_c_keyword": lambda i: validator_is_c_keyword(i),
    "arch_from_str": lambda i: validator_arch_from_str(i),
    "parse_mem_operands": lambda i: validator_parse_mem_operands(i),
    "load_binary": lambda i: validator_load_binary(i),
    "slice_at_va": lambda i: validator_slice_at_va(i["path"], i["va"],
                                                   i.get("length", 16)),
    "disassemble_function_x86": lambda i: validator_disassemble_function_x86(
        i["bytes_hex"], i["ip"], i.get("bits", 64), i.get("max_instr", 64)),
    "analyze_stack_frame": lambda i: validator_analyze_stack_frame(i),
    "detect_heap_bases": lambda i: validator_detect_heap_bases(i),
    "render_c_signature": lambda i: validator_render_c_signature(i["sig"], i["name"]),
}


def main() -> int:
    if "--stdin" in sys.argv:
        req = json.loads(sys.stdin.read())
        fn = req["fn"]
        result = DISPATCH[fn](req["input"])
        print(json.dumps({"fn": fn, "result": result}))
        return 0

    # Self-tests with fixed inputs
    tests = {
        "register_width_bytes(rax)": validator_register_width_bytes("rax"),
        "register_width_bytes(eax)": validator_register_width_bytes("eax"),
        "register_width_bytes(al)":  validator_register_width_bytes("al"),
        "register_canonical(eax)":   validator_register_canonical("eax"),
        "register_canonical(r9d)":   validator_register_canonical("r9d"),
        "width_hint(mov, dword ptr [rbp-4])":
            validator_width_hint_from_instr("mov", "dword ptr [rbp-4], eax"),
        "is_c_keyword(return)": validator_is_c_keyword("return"),
        "is_c_keyword(foo)":    validator_is_c_keyword("foo"),
        "arch_from_str(x86_64)": validator_arch_from_str("x86_64"),
        "parse_mem(rbp-0x10)":
            validator_parse_mem_operands("qword ptr [rbp - 0x10]"),
        "parse_mem(rax+rcx*4+8)":
            validator_parse_mem_operands("[rax + rcx*4 + 8]"),
        "disasm(55 48 89 e5 c3)":
            validator_disassemble_function_x86("554889e5c3", 0x1000, 64),
        "render_sig":
            validator_render_c_signature(
                {"return_type": "int", "args": [{"ty": "int", "name": "x"}]},
                "foo"),
        "analyze_stack_frame(push rbp;sub rsp,0x20)":
            validator_analyze_stack_frame([
                {"mnemonic": "push", "op_str": "rbp"},
                {"mnemonic": "mov",  "op_str": "rbp, rsp"},
                {"mnemonic": "sub",  "op_str": "rsp, 0x20"},
            ]),
        "detect_heap_bases(call malloc)":
            validator_detect_heap_bases([
                {"mnemonic": "call", "op_str": "malloc"},
                {"mnemonic": "mov",  "op_str": "rax, rdi"},
            ]),
    }
    print(json.dumps(tests, indent=2, default=str))
    return 0


if __name__ == "__main__":
    sys.exit(main())
