"""Independent validator for rustre-debug-windows based on the report analysis.

Reimplements (in pure Python stdlib) the platform-independent pure-logic
surfaces of the crate:

  * MemoryRegionInfo  -> rwx / committed / protect_name / to_memory_map
  * DebugEventDecoder -> exception/exit/dll/thread decoders + exception_name
  * Wow64Context      -> trap_flag get/set, to_register_set
  * pattern parser    -> "48 8B ? ? 90 CC"-style AOB parser

These are testable without the Win32 Debug API. Everything driven by Win32
(WindowsDebugger trait impl, ReadProcessMemory etc.) requires Windows + a live
target and is out of scope for a stdlib validator.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional, Tuple


# ---------------------------------------------------------------------------
# Win32 constants (mirror lib.rs exports)
# ---------------------------------------------------------------------------

PAGE_NOACCESS           = 0x01
PAGE_READONLY           = 0x02
PAGE_READWRITE          = 0x04
PAGE_WRITECOPY          = 0x08
PAGE_EXECUTE            = 0x10
PAGE_EXECUTE_READ       = 0x20
PAGE_EXECUTE_READWRITE  = 0x40
PAGE_EXECUTE_WRITECOPY  = 0x80
PAGE_GUARD              = 0x100

MEM_COMMIT  = 0x1000
MEM_RESERVE = 0x2000
MEM_FREE    = 0x10000
MEM_IMAGE   = 0x1000000
MEM_MAPPED  = 0x40000
MEM_PRIVATE = 0x20000

EXCEPTION_ACCESS_VIOLATION       = 0xC0000005
EXCEPTION_BREAKPOINT             = 0x80000003
EXCEPTION_SINGLE_STEP            = 0x80000004
EXCEPTION_STACK_OVERFLOW         = 0xC00000FD
EXCEPTION_ARRAY_BOUNDS_EXCEEDED  = 0xC000008C
EXCEPTION_DATATYPE_MISALIGNMENT  = 0x80000002
EXCEPTION_FLT_DIVIDE_BY_ZERO     = 0xC000008E
EXCEPTION_INT_DIVIDE_BY_ZERO     = 0xC0000094
EXCEPTION_INT_OVERFLOW           = 0xC0000095
EXCEPTION_ILLEGAL_INSTRUCTION    = 0xC000001D
EXCEPTION_PRIV_INSTRUCTION       = 0xC0000096
EXCEPTION_IN_PAGE_ERROR          = 0xC0000006
EXCEPTION_GUARD_PAGE             = 0x80000001
EXCEPTION_INVALID_HANDLE         = 0xC0000008
EXCEPTION_NONCONTINUABLE         = 0xC0000025


# ---------------------------------------------------------------------------
# Neutral types (mirrors rustre_debug shape)
# ---------------------------------------------------------------------------

@dataclass
class MemoryMap:
    base: int
    size: int
    readable: bool
    writable: bool
    executable: bool
    name: Optional[str] = None


@dataclass
class RegisterSet:
    pc: int = 0
    sp: int = 0
    fp: int = 0
    # x64 named registers
    rax: int = 0
    rcx: int = 0
    rdx: int = 0
    rbx: int = 0
    rsp: int = 0
    rbp: int = 0
    rsi: int = 0
    rdi: int = 0
    r8: int = 0
    r9: int = 0
    r10: int = 0
    r11: int = 0
    r12: int = 0
    r13: int = 0
    r14: int = 0
    r15: int = 0
    rip: int = 0
    rflags: int = 0
    # 32-bit (wow64) named registers
    eax: int = 0
    ecx: int = 0
    edx: int = 0
    ebx: int = 0
    esp: int = 0
    ebp: int = 0
    esi: int = 0
    edi: int = 0
    eip: int = 0
    eflags: int = 0
    dr0: int = 0
    dr1: int = 0
    dr2: int = 0
    dr3: int = 0
    dr6: int = 0
    dr7: int = 0


# StopReason as tagged dict-style values
def _sr(kind: str, **kw) -> dict:
    d = {"kind": kind}
    d.update(kw)
    return d


# ---------------------------------------------------------------------------
# MemoryRegionInfo
# ---------------------------------------------------------------------------

# protections that grant read access
_READ_MASK = (
    PAGE_READONLY | PAGE_READWRITE | PAGE_WRITECOPY
    | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY
)
# protections that grant write access
_WRITE_MASK = (
    PAGE_READWRITE | PAGE_WRITECOPY
    | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY
)
# protections that grant execute access
_EXEC_MASK = (
    PAGE_EXECUTE | PAGE_EXECUTE_READ
    | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY
)


@dataclass
class MemoryRegionInfo:
    base: int
    size: int
    state: int
    protect: int
    type_: int

    def _effective(self) -> int:
        # PAGE_GUARD bit is stripped for naming/effective-protection purposes.
        return self.protect & ~PAGE_GUARD

    def is_committed(self) -> bool:
        return self.state == MEM_COMMIT

    def is_readable(self) -> bool:
        if not self.is_committed():
            return False
        eff = self._effective()
        if eff == PAGE_NOACCESS:
            return False
        return (eff & _READ_MASK) != 0

    def is_writable(self) -> bool:
        if not self.is_committed():
            return False
        return (self._effective() & _WRITE_MASK) != 0

    def is_executable(self) -> bool:
        if not self.is_committed():
            return False
        return (self._effective() & _EXEC_MASK) != 0

    def protect_name(self) -> str:
        eff = self._effective()
        return {
            PAGE_NOACCESS:           "PAGE_NOACCESS",
            PAGE_READONLY:           "PAGE_READONLY",
            PAGE_READWRITE:          "PAGE_READWRITE",
            PAGE_WRITECOPY:          "PAGE_WRITECOPY",
            PAGE_EXECUTE:            "PAGE_EXECUTE",
            PAGE_EXECUTE_READ:       "PAGE_EXECUTE_READ",
            PAGE_EXECUTE_READWRITE:  "PAGE_EXECUTE_READWRITE",
            PAGE_EXECUTE_WRITECOPY:  "PAGE_EXECUTE_WRITECOPY",
        }.get(eff, "PAGE_UNKNOWN")

    def to_memory_map(self) -> MemoryMap:
        return MemoryMap(
            base=self.base,
            size=self.size,
            readable=self.is_readable(),
            writable=self.is_writable(),
            executable=self.is_executable(),
            name=None,
        )


def is_committed(state: int) -> bool:
    return state == MEM_COMMIT


# ---------------------------------------------------------------------------
# DebugEventDecoder
# ---------------------------------------------------------------------------

_EXC_NAMES = {
    EXCEPTION_ACCESS_VIOLATION:      "EXCEPTION_ACCESS_VIOLATION",
    EXCEPTION_BREAKPOINT:            "EXCEPTION_BREAKPOINT",
    EXCEPTION_SINGLE_STEP:           "EXCEPTION_SINGLE_STEP",
    EXCEPTION_STACK_OVERFLOW:        "EXCEPTION_STACK_OVERFLOW",
    EXCEPTION_ARRAY_BOUNDS_EXCEEDED: "EXCEPTION_ARRAY_BOUNDS_EXCEEDED",
    EXCEPTION_DATATYPE_MISALIGNMENT: "EXCEPTION_DATATYPE_MISALIGNMENT",
    EXCEPTION_FLT_DIVIDE_BY_ZERO:    "EXCEPTION_FLT_DIVIDE_BY_ZERO",
    EXCEPTION_INT_DIVIDE_BY_ZERO:    "EXCEPTION_INT_DIVIDE_BY_ZERO",
    EXCEPTION_INT_OVERFLOW:          "EXCEPTION_INT_OVERFLOW",
    EXCEPTION_ILLEGAL_INSTRUCTION:   "EXCEPTION_ILLEGAL_INSTRUCTION",
    EXCEPTION_PRIV_INSTRUCTION:      "EXCEPTION_PRIV_INSTRUCTION",
    EXCEPTION_IN_PAGE_ERROR:         "EXCEPTION_IN_PAGE_ERROR",
    EXCEPTION_GUARD_PAGE:            "EXCEPTION_GUARD_PAGE",
    EXCEPTION_INVALID_HANDLE:        "EXCEPTION_INVALID_HANDLE",
    EXCEPTION_NONCONTINUABLE:        "EXCEPTION_NONCONTINUABLE",
}


class DebugEventDecoder:
    @staticmethod
    def exception_name(code: int) -> str:
        return _EXC_NAMES.get(code & 0xFFFFFFFF, "UNKNOWN_EXCEPTION")

    @staticmethod
    def decode_exception(code: int, address: int, is_first_chance: bool,
                         pid: int, tid: int) -> dict:
        code &= 0xFFFFFFFF
        if code == EXCEPTION_BREAKPOINT:
            return _sr("Breakpoint", address=address, pid=pid, tid=tid)
        if code == EXCEPTION_SINGLE_STEP:
            return _sr("SingleStep", address=address, pid=pid, tid=tid)
        if code == EXCEPTION_ACCESS_VIOLATION:
            return _sr("AccessViolation", address=address,
                       first_chance=is_first_chance, pid=pid, tid=tid)
        return _sr("Exception", code=code,
                   name=DebugEventDecoder.exception_name(code),
                   address=address, first_chance=is_first_chance,
                   pid=pid, tid=tid)

    @staticmethod
    def decode_exit_process(exit_code: int, pid: int, tid: int) -> dict:
        return _sr("ProcessExit", exit_code=exit_code, pid=pid, tid=tid)

    @staticmethod
    def decode_load_dll(base: int, path: Optional[str], pid: int, tid: int) -> dict:
        return _sr("LibraryLoad", base=base, path=path, pid=pid, tid=tid)

    @staticmethod
    def decode_unload_dll(base: int, pid: int, tid: int) -> dict:
        return _sr("LibraryUnload", base=base, pid=pid, tid=tid)

    @staticmethod
    def decode_create_thread(tid: int, pid: int) -> dict:
        return _sr("ThreadCreate", pid=pid, tid=tid)

    @staticmethod
    def decode_exit_thread(tid: int, exit_code: int, pid: int) -> dict:
        return _sr("ThreadExit", pid=pid, tid=tid, exit_code=exit_code)


# ---------------------------------------------------------------------------
# Wow64Context
# ---------------------------------------------------------------------------

_TF_BIT = 1 << 8  # EFLAGS.TF


@dataclass
class Wow64Context:
    context_flags: int = 0
    dr0: int = 0
    dr1: int = 0
    dr2: int = 0
    dr3: int = 0
    dr6: int = 0
    dr7: int = 0
    eax: int = 0
    ecx: int = 0
    edx: int = 0
    ebx: int = 0
    esp: int = 0
    ebp: int = 0
    esi: int = 0
    edi: int = 0
    eip: int = 0
    eflags: int = 0

    def trap_flag(self) -> bool:
        return (self.eflags & _TF_BIT) != 0

    def set_trap_flag(self, on: bool) -> None:
        if on:
            self.eflags |= _TF_BIT
        else:
            self.eflags &= ~_TF_BIT & 0xFFFFFFFF

    def to_register_set(self) -> RegisterSet:
        rs = RegisterSet()
        rs.eax = self.eax
        rs.ecx = self.ecx
        rs.edx = self.edx
        rs.ebx = self.ebx
        rs.esp = self.esp
        rs.ebp = self.ebp
        rs.esi = self.esi
        rs.edi = self.edi
        rs.eip = self.eip
        rs.eflags = self.eflags
        rs.dr0 = self.dr0
        rs.dr1 = self.dr1
        rs.dr2 = self.dr2
        rs.dr3 = self.dr3
        rs.dr6 = self.dr6
        rs.dr7 = self.dr7
        # neutral pc/sp/fp populated from 32-bit regs (zero-extended)
        rs.pc = self.eip & 0xFFFFFFFF
        rs.sp = self.esp & 0xFFFFFFFF
        rs.fp = self.ebp & 0xFFFFFFFF
        return rs


# ---------------------------------------------------------------------------
# Pattern parser  ("48 8B ? ? 90 CC" -> (bytes, mask))
# ---------------------------------------------------------------------------

def parse_pattern(s: str) -> Optional[Tuple[List[int], List[bool]]]:
    """Parse a hex AOB pattern. Returns (bytes, mask) where mask[i] is True
    iff bytes[i] must match exactly. '?' or '??' are wildcards.
    Returns None on syntactic error.
    """
    out_bytes: List[int] = []
    out_mask: List[bool] = []
    tokens = s.split()
    if not tokens:
        return None
    for tok in tokens:
        if tok in ("?", "??"):
            out_bytes.append(0)
            out_mask.append(False)
            continue
        if len(tok) != 2:
            return None
        # Allow single '?' inside a 2-char token? rustre style is whole-token wildcard.
        try:
            v = int(tok, 16)
        except ValueError:
            return None
        if not (0 <= v <= 0xFF):
            return None
        out_bytes.append(v)
        out_mask.append(True)
    return out_bytes, out_mask


def pattern_match(haystack: bytes, pattern: str) -> Optional[int]:
    parsed = parse_pattern(pattern)
    if parsed is None:
        return None
    pb, pm = parsed
    n = len(pb)
    if n == 0 or len(haystack) < n:
        return None
    for i in range(len(haystack) - n + 1):
        ok = True
        for j in range(n):
            if pm[j] and haystack[i + j] != pb[j]:
                ok = False
                break
        if ok:
            return i
    return None


# ---------------------------------------------------------------------------
# Self-tests
# ---------------------------------------------------------------------------

def _self_test() -> None:
    # --- MemoryRegionInfo ---
    r = MemoryRegionInfo(base=0x1000, size=0x1000, state=MEM_COMMIT,
                         protect=PAGE_EXECUTE_READ, type_=MEM_IMAGE)
    assert r.is_committed()
    assert r.is_readable()
    assert not r.is_writable()
    assert r.is_executable()
    assert r.protect_name() == "PAGE_EXECUTE_READ"
    mm = r.to_memory_map()
    assert mm.base == 0x1000 and mm.size == 0x1000
    assert mm.readable and mm.executable and not mm.writable

    # PAGE_GUARD must be stripped for effective protection
    rg = MemoryRegionInfo(0, 0x1000, MEM_COMMIT,
                          PAGE_READWRITE | PAGE_GUARD, MEM_PRIVATE)
    assert rg.protect_name() == "PAGE_READWRITE"
    assert rg.is_readable() and rg.is_writable() and not rg.is_executable()

    # NOACCESS / reserved-only -> nothing
    rn = MemoryRegionInfo(0, 0x1000, MEM_COMMIT, PAGE_NOACCESS, MEM_PRIVATE)
    assert not rn.is_readable() and not rn.is_writable() and not rn.is_executable()
    assert rn.protect_name() == "PAGE_NOACCESS"

    rr = MemoryRegionInfo(0, 0x1000, MEM_RESERVE, PAGE_READWRITE, MEM_PRIVATE)
    assert not rr.is_committed()
    assert not rr.is_readable() and not rr.is_writable()

    assert is_committed(MEM_COMMIT) and not is_committed(MEM_RESERVE)

    # --- DebugEventDecoder ---
    d = DebugEventDecoder
    bp = d.decode_exception(EXCEPTION_BREAKPOINT, 0xdead, True, 1, 2)
    assert bp["kind"] == "Breakpoint" and bp["address"] == 0xdead
    ss = d.decode_exception(EXCEPTION_SINGLE_STEP, 0xbeef, True, 1, 2)
    assert ss["kind"] == "SingleStep"
    av = d.decode_exception(EXCEPTION_ACCESS_VIOLATION, 0x41, False, 1, 2)
    assert av["kind"] == "AccessViolation" and av["first_chance"] is False
    ex = d.decode_exception(EXCEPTION_ILLEGAL_INSTRUCTION, 0x10, True, 1, 2)
    assert ex["kind"] == "Exception"
    assert ex["name"] == "EXCEPTION_ILLEGAL_INSTRUCTION"
    assert d.exception_name(EXCEPTION_STACK_OVERFLOW) == "EXCEPTION_STACK_OVERFLOW"
    assert d.exception_name(0xDEADBEEF) == "UNKNOWN_EXCEPTION"

    pe = d.decode_exit_process(7, 100, 200)
    assert pe == {"kind": "ProcessExit", "exit_code": 7, "pid": 100, "tid": 200}
    ld = d.decode_load_dll(0x7ff000, "kernel32.dll", 1, 2)
    assert ld["kind"] == "LibraryLoad" and ld["path"] == "kernel32.dll"
    ul = d.decode_unload_dll(0x7ff000, 1, 2)
    assert ul["kind"] == "LibraryUnload"
    tc = d.decode_create_thread(9, 1)
    assert tc == {"kind": "ThreadCreate", "pid": 1, "tid": 9}
    te = d.decode_exit_thread(9, 0, 1)
    assert te["kind"] == "ThreadExit" and te["exit_code"] == 0

    # --- Wow64Context ---
    w = Wow64Context(eip=0x1234, esp=0x2000, ebp=0x2100, eflags=0)
    assert not w.trap_flag()
    w.set_trap_flag(True)
    assert w.trap_flag()
    assert (w.eflags & _TF_BIT) != 0
    w.set_trap_flag(False)
    assert not w.trap_flag()
    rs = w.to_register_set()
    assert rs.pc == 0x1234 and rs.sp == 0x2000 and rs.fp == 0x2100
    assert rs.eip == 0x1234

    # --- pattern parser ---
    parsed = parse_pattern("48 8B ? ? 90 CC")
    assert parsed is not None
    pb, pm = parsed
    assert pb == [0x48, 0x8B, 0, 0, 0x90, 0xCC]
    assert pm == [True, True, False, False, True, True]

    assert parse_pattern("") is None
    assert parse_pattern("ZZ") is None
    assert parse_pattern("1") is None  # odd length

    hay = bytes.fromhex("90 90 48 8B 11 22 90 CC 00")
    idx = pattern_match(hay, "48 8B ? ? 90 CC")
    assert idx == 2, idx
    assert pattern_match(hay, "DE AD BE EF") is None


if __name__ == "__main__":
    _self_test()
    print("rustre-debug-windows validator: OK")
