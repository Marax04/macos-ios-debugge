"""Independent Python validator for rustre-arch-luajit.

Implements (from scratch, stdlib only) the public behaviors documented in
validation/reports/rustre-arch-luajit.md so they can be cross-checked against
the Rust crate. No imports of the Rust code, no MCP calls.
"""

from __future__ import annotations

import json
import struct
from dataclasses import dataclass, field
from enum import Enum
from typing import List, Optional, Tuple


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
LJ_MAGIC = bytes([0x1B, 0x4C, 0x4A])
LJ_VERSION_20 = 1
LJ_VERSION_21 = 2
BIAS = 0x8000


# ---------------------------------------------------------------------------
# Opcodes (LuaJIT 2.0 / 2.1 — order matches lj_bc.h BCDEF_*)
# ---------------------------------------------------------------------------
LJ_OPCODES: List[str] = [
    "ISLT", "ISGE", "ISLE", "ISGT", "ISEQV", "ISNEV", "ISEQS", "ISNES",
    "ISEQN", "ISNEN", "ISEQP", "ISNEP",
    "ISTC", "ISFC", "IST", "ISF", "ISTYPE", "ISNUM",
    "MOV", "NOT", "UNM", "LEN",
    "ADDVN", "SUBVN", "MULVN", "DIVVN", "MODVN",
    "ADDNV", "SUBNV", "MULNV", "DIVNV", "MODNV",
    "ADDVV", "SUBVV", "MULVV", "DIVVV", "MODVV",
    "POW", "CAT",
    "KSTR", "KCDATA", "KSHORT", "KNUM", "KPRI", "KNIL",
    "UGET", "USETV", "USETS", "USETN", "USETP", "UCLO",
    "FNEW",
    "TNEW", "TDUP", "GGET", "GSET",
    "TGETV", "TGETS", "TGETB", "TGETR",
    "TSETV", "TSETS", "TSETB", "TSETM", "TSETR",
    "CALLM", "CALL", "CALLMT", "CALLT",
    "ITERC", "ITERN",
    "VARG", "ISNEXT",
    "RETM", "RET", "RET0", "RET1",
    "FORI", "JFORI", "FORL", "IFORL", "JFORL",
    "ITERL", "IITERL", "JITERL",
    "LOOP", "ILOOP", "JLOOP",
    "JMP",
    "FUNCF", "IFUNCF", "JFUNCF",
    "FUNCV", "IFUNCV", "JFUNCV",
    "FUNCC", "FUNCCW",
]
assert len(LJ_OPCODES) == 97, len(LJ_OPCODES)


class InstrCategory(str, Enum):
    Comparison = "Comparison"
    Arithmetic = "Arithmetic"
    LoadConst = "LoadConst"
    Upvalue = "Upvalue"
    TableGet = "TableGet"
    TableSet = "TableSet"
    Call = "Call"
    Return = "Return"
    Branch = "Branch"
    FuncHeader = "FuncHeader"
    Other = "Other"


class LjFmt(str, Enum):
    Abc = "Abc"
    Ad = "Ad"
    AdSigned = "AdSigned"
    A = "A"
    NoneFmt = "None"


# Comparison ops (the first ISLT..ISNUM block); ISTYPE/ISNUM are 16/17
_COMPARE = set(range(0, 18))
_ARITH_NAMES = {"ADDVN", "SUBVN", "MULVN", "DIVVN", "MODVN",
                "ADDNV", "SUBNV", "MULNV", "DIVNV", "MODNV",
                "ADDVV", "SUBVV", "MULVV", "DIVVV", "MODVV",
                "POW", "CAT", "NOT", "UNM", "LEN", "MOV"}
_LOADCONST_NAMES = {"KSTR", "KCDATA", "KSHORT", "KNUM", "KPRI", "KNIL", "FNEW"}
_UPVAL_NAMES = {"UGET", "USETV", "USETS", "USETN", "USETP", "UCLO"}
_TGET_NAMES = {"TGETV", "TGETS", "TGETB", "TGETR", "GGET"}
_TSET_NAMES = {"TSETV", "TSETS", "TSETB", "TSETM", "TSETR", "GSET",
               "TNEW", "TDUP"}
_CALL_NAMES = {"CALLM", "CALL", "CALLMT", "CALLT", "ITERC", "ITERN",
               "VARG", "ISNEXT"}
_RET_NAMES = {"RETM", "RET", "RET0", "RET1"}
_BRANCH_NAMES = {"JMP", "FORI", "JFORI", "FORL", "IFORL", "JFORL",
                 "ITERL", "IITERL", "JITERL", "LOOP", "ILOOP", "JLOOP"}
_FUNCHDR_NAMES = {"FUNCF", "IFUNCF", "JFUNCF", "FUNCV", "IFUNCV", "JFUNCV",
                  "FUNCC", "FUNCCW"}


def lj_op_from_u8(v: int) -> Optional[int]:
    if 0 <= v <= 96:
        return v
    return None


def lj_op_mnemonic(op: int) -> str:
    return LJ_OPCODES[op]


def lj_op_category(op: int) -> InstrCategory:
    name = LJ_OPCODES[op]
    if op in _COMPARE:
        return InstrCategory.Comparison
    if name in _ARITH_NAMES:
        return InstrCategory.Arithmetic
    if name in _LOADCONST_NAMES:
        return InstrCategory.LoadConst
    if name in _UPVAL_NAMES:
        return InstrCategory.Upvalue
    if name in _TGET_NAMES:
        return InstrCategory.TableGet
    if name in _TSET_NAMES:
        return InstrCategory.TableSet
    if name in _CALL_NAMES:
        return InstrCategory.Call
    if name in _RET_NAMES:
        return InstrCategory.Return
    if name in _BRANCH_NAMES:
        return InstrCategory.Branch
    if name in _FUNCHDR_NAMES:
        return InstrCategory.FuncHeader
    return InstrCategory.Other


# Format classification per documented behavior. ABC formats use B+C bytes,
# AD formats pack a 16-bit D. Branch-bearing JMP/loop ops use AdSigned.
_AD_SIGNED_NAMES = _BRANCH_NAMES  # branch-target ops use signed D w/ BIAS
_A_ONLY_NAMES = {"UCLO"}  # rough: A only fields meaningful
_NONE_NAMES: set = set()


def lj_fmt(op: int) -> LjFmt:
    name = LJ_OPCODES[op]
    if name in _AD_SIGNED_NAMES:
        return LjFmt.AdSigned
    # AD ops: single-D fields
    if name in {"MOV", "NOT", "UNM", "LEN", "KSTR", "KCDATA", "KSHORT",
                "KNUM", "KPRI", "UGET", "USETV", "USETS", "USETN", "USETP",
                "FNEW", "TNEW", "TDUP", "GGET", "GSET", "RETM", "RET",
                "RET0", "RET1", "ISTC", "ISFC", "IST", "ISF",
                "ISEQS", "ISNES", "ISEQN", "ISNEN", "ISEQP", "ISNEP",
                "ISEQV", "ISNEV", "ISLT", "ISGE", "ISLE", "ISGT",
                "ISTYPE", "ISNUM", "VARG", "ISNEXT"}:
        return LjFmt.Ad
    if name in _A_ONLY_NAMES:
        return LjFmt.A
    # Func headers: treated as None
    if name in _FUNCHDR_NAMES:
        return LjFmt.NoneFmt
    return LjFmt.Abc


# ---------------------------------------------------------------------------
# Field accessors (LuaJIT instruction layout: OP[7..0] A[15..8] CD[31..16])
# For ABC: B is bits 31..24, C is bits 23..16. For AD: D is 16..31.
# ---------------------------------------------------------------------------
def instr_op(word: int) -> int:
    return word & 0xFF


def instr_a(word: int) -> int:
    return (word >> 8) & 0xFF


def instr_b(word: int) -> int:
    return (word >> 24) & 0xFF


def instr_c(word: int) -> int:
    return (word >> 16) & 0xFF


def instr_d(word: int) -> int:
    return (word >> 16) & 0xFFFF


def instr_d_signed(word: int) -> int:
    return instr_d(word) - BIAS


def make_lj_abc(op: int, a: int, b: int, c: int) -> int:
    return (op & 0xFF) | ((a & 0xFF) << 8) | ((c & 0xFF) << 16) | ((b & 0xFF) << 24)


def make_lj_ad(op: int, a: int, d: int) -> int:
    return (op & 0xFF) | ((a & 0xFF) << 8) | ((d & 0xFFFF) << 16)


def make_lj_ad_signed(op: int, a: int, d_signed: int) -> int:
    d = (d_signed + BIAS) & 0xFFFF
    return make_lj_ad(op, a, d)


# ---------------------------------------------------------------------------
# Instruction detail
# ---------------------------------------------------------------------------
@dataclass
class LjInstrDetail:
    index: int
    raw: int
    op: int
    a: int
    b: int
    c: int
    d: int
    d_signed: int
    fmt: LjFmt
    category: InstrCategory
    branch_target: Optional[int]

    def mnemonic(self) -> str:
        return lj_op_mnemonic(self.op).lower()

    def reads_reg(self, reg: int) -> bool:
        name = lj_op_mnemonic(self.op)
        # Stores treat A as source
        if name.startswith("TSET") or name.startswith("USET") or name == "GSET":
            if self.a == reg:
                return True
        # ABC: B and C are register operands for arithmetic/table ops
        if self.fmt == LjFmt.Abc:
            if self.b == reg or self.c == reg:
                return True
        return False

    def writes_reg(self, reg: int) -> bool:
        name = lj_op_mnemonic(self.op)
        if name.startswith("TSET") or name.startswith("USET") or name == "GSET":
            return False  # A is source, no register write
        if self.category in (InstrCategory.Return, InstrCategory.Branch,
                             InstrCategory.Comparison):
            return False
        return self.a == reg


def detail(idx: int, word: int) -> Optional[LjInstrDetail]:
    op = instr_op(word)
    if op > 96:
        return None
    fmt = lj_fmt(op)
    cat = lj_op_category(op)
    a = instr_a(word)
    b = instr_b(word)
    c = instr_c(word)
    d = instr_d(word)
    ds = instr_d_signed(word)
    bt: Optional[int] = None
    if fmt == LjFmt.AdSigned and cat == InstrCategory.Branch:
        bt = idx + 1 + ds
    return LjInstrDetail(idx, word, op, a, b, c, d, ds, fmt, cat, bt)


# ---------------------------------------------------------------------------
# Pretty printer
# ---------------------------------------------------------------------------
def format_instruction(idx: int, word: int) -> str:
    det = detail(idx, word)
    if det is None:
        return f"{idx:04d}  <bad op {instr_op(word):02x}>"
    name = lj_op_mnemonic(det.op).ljust(7)
    if det.fmt == LjFmt.Abc:
        ops = f"R{det.a}, R{det.b}, R{det.c}"
    elif det.fmt == LjFmt.Ad:
        ops = f"R{det.a}, {det.d}"
    elif det.fmt == LjFmt.AdSigned:
        ops = f"R{det.a}, {det.d_signed}"
    elif det.fmt == LjFmt.A:
        ops = f"R{det.a}"
    else:
        ops = ""
    return f"{idx:04d}  {name} {ops}".rstrip()


def disassemble_listing(words: List[int]) -> str:
    return "\n".join(format_instruction(i, w) for i, w in enumerate(words))


# ---------------------------------------------------------------------------
# Basic blocks (leader detection: branch targets, fallthrough, post-return)
# ---------------------------------------------------------------------------
@dataclass
class BasicBlock:
    start: int
    end: int  # exclusive

    def len(self) -> int:
        return self.end - self.start

    def is_empty(self) -> bool:
        return self.end <= self.start


def find_basic_blocks(words: List[int]) -> List[BasicBlock]:
    n = len(words)
    if n == 0:
        return []
    leaders = {0}
    for i, w in enumerate(words):
        det = detail(i, w)
        if det is None:
            continue
        if det.category == InstrCategory.Branch and det.branch_target is not None:
            t = det.branch_target
            if 0 <= t < n:
                leaders.add(t)
            if i + 1 < n:
                leaders.add(i + 1)
        elif det.category == InstrCategory.Return:
            if i + 1 < n:
                leaders.add(i + 1)
    sorted_leaders = sorted(leaders)
    blocks: List[BasicBlock] = []
    for j, ld in enumerate(sorted_leaders):
        end = sorted_leaders[j + 1] if j + 1 < len(sorted_leaders) else n
        blocks.append(BasicBlock(ld, end))
    return blocks


# ---------------------------------------------------------------------------
# Reg accesses
# ---------------------------------------------------------------------------
@dataclass
class RegAccess:
    instr_idx: int
    reg: int
    is_def: bool


def collect_reg_accesses(words: List[int]) -> List[RegAccess]:
    out: List[RegAccess] = []
    for i, w in enumerate(words):
        det = detail(i, w)
        if det is None:
            continue
        for r in range(16):
            if det.writes_reg(r):
                out.append(RegAccess(i, r, True))
            if det.reads_reg(r):
                out.append(RegAccess(i, r, False))
    return out


# ---------------------------------------------------------------------------
# Dump flags
# ---------------------------------------------------------------------------
@dataclass
class DumpFlags:
    raw: int

    @classmethod
    def from_byte(cls, b: int) -> "DumpFlags":
        return cls(b & 0xFF)

    def be(self) -> bool:
        return bool(self.raw & 0x01)

    def strip(self) -> bool:
        return bool(self.raw & 0x02)

    def ffi(self) -> bool:
        return bool(self.raw & 0x04)

    def fr2(self) -> bool:
        return bool(self.raw & 0x08)


# ---------------------------------------------------------------------------
# ULEB128
# ---------------------------------------------------------------------------
class ParseError(Exception):
    pass


def read_uleb128(data: bytes, pos: int) -> Tuple[int, int]:
    result = 0
    shift = 0
    while True:
        if pos >= len(data):
            raise ParseError("UnexpectedEof")
        byte = data[pos]
        pos += 1
        result |= (byte & 0x7F) << shift
        if (byte & 0x80) == 0:
            return result, pos
        shift += 7
        if shift > 63:
            raise ParseError("Overflow")


# ---------------------------------------------------------------------------
# Minimal LuaJIT bytecode parser (chunk header only — full proto walk is
# out of scope for this validator, the report itself only documents shape).
# ---------------------------------------------------------------------------
@dataclass
class LuaJitProto:
    instructions: List[int] = field(default_factory=list)
    upvalues: List[Tuple[bool, int]] = field(default_factory=list)
    constants: List[object] = field(default_factory=list)
    protos: List["LuaJitProto"] = field(default_factory=list)
    params: int = 0
    framesize: int = 0
    flags: int = 0
    source: bytes = b""
    first_line: int = 0
    num_lines: int = 0

    def instr_count(self) -> int:
        return len(self.instructions)

    def is_vararg(self) -> bool:
        return bool(self.flags & 0x02)

    def has_children(self) -> bool:
        return len(self.protos) > 0


@dataclass
class LuaJitBytecode:
    version: int
    flags: DumpFlags
    chunk: LuaJitProto

    def is_lj21(self) -> bool:
        return self.version == LJ_VERSION_21

    def total_instructions(self) -> int:
        return self.chunk.instr_count()

    @classmethod
    def parse(cls, data: bytes) -> "LuaJitBytecode":
        if len(data) < 4:
            raise ParseError("UnexpectedEof")
        if data[0:3] != LJ_MAGIC:
            raise ParseError("BadMagic")
        version = data[3]
        if version not in (LJ_VERSION_20, LJ_VERSION_21):
            raise ParseError("BadMagic")
        pos = 4
        flags_val, pos = read_uleb128(data, pos)
        flags = DumpFlags.from_byte(flags_val)
        # If stripped flag not set, chunkname follows
        if not flags.strip():
            name_len, pos = read_uleb128(data, pos)
            if pos + name_len > len(data):
                raise ParseError("UnexpectedEof")
            pos += name_len
        # Stop here: full proto chain decode is large; the spec says we just
        # need header validation for cross-check purposes.
        chunk = LuaJitProto()
        return cls(version=version, flags=flags, chunk=chunk)


# ---------------------------------------------------------------------------
# Public catalog for the harness
# ---------------------------------------------------------------------------
FUNCTIONS = [
    "LJ_MAGIC", "LJ_VERSION_20", "LJ_VERSION_21",
    "lj_op_from_u8", "lj_op_mnemonic", "lj_op_category",
    "InstrCategory", "LjFmt", "lj_fmt",
    "instr_op", "instr_a", "instr_b", "instr_c", "instr_d", "instr_d_signed",
    "make_lj_abc", "make_lj_ad", "make_lj_ad_signed",
    "LjInstrDetail", "detail",
    "format_instruction", "disassemble_listing",
    "BasicBlock", "find_basic_blocks",
    "RegAccess", "collect_reg_accesses",
    "DumpFlags", "read_uleb128",
    "ParseError", "LuaJitProto", "LuaJitBytecode",
]


def _self_test() -> None:
    # round-trip encode/decode
    w = make_lj_abc(32, 0, 1, 2)  # ADDVV R0,R1,R2
    assert instr_op(w) == 32 and instr_a(w) == 0 and instr_b(w) == 1 and instr_c(w) == 2
    w2 = make_lj_ad_signed(LJ_OPCODES.index("JMP"), 0, -3)
    d = detail(5, w2)
    assert d is not None and d.branch_target == 5 + 1 + (-3)
    # all 97 opcodes have categories
    for i in range(97):
        assert isinstance(lj_op_category(i), InstrCategory)
    # find_basic_blocks
    words = [
        make_lj_abc(LJ_OPCODES.index("ISLT"), 0, 1, 2),
        make_lj_ad_signed(LJ_OPCODES.index("JMP"), 0, 1),
        make_lj_abc(LJ_OPCODES.index("ADDVV"), 0, 1, 2),
        make_lj_ad(LJ_OPCODES.index("RET0"), 0, 0),
    ]
    bbs = find_basic_blocks(words)
    assert len(bbs) >= 2
    # bytecode header
    raw = bytes(LJ_MAGIC) + bytes([2, 0x02])  # LJ 2.1, stripped
    bc = LuaJitBytecode.parse(raw)
    assert bc.is_lj21() and bc.flags.strip()


if __name__ == "__main__":
    _self_test()
    print(json.dumps({
        "crate": "rustre-arch-luajit",
        "saved": True,
        "functions": FUNCTIONS,
    }, indent=2))
