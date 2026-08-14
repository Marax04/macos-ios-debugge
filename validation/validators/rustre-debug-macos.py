#!/usr/bin/env python3
"""Independent Python re-implementation of selected pure-data helpers from
the `rustre-debug-macos` crate, based on the analysis report.

Covers:
  - BreakpointManager
  - MacosRegisterSet (x86_64 / arm64 register-name -> index)
  - MacosArch enum
  - Mach-O magic constants, CpuType, MachoFileType
"""

from __future__ import annotations
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional


# ---------------------------------------------------------------------------
# BreakpointManager
# ---------------------------------------------------------------------------
class BreakpointManager:
    def __init__(self) -> None:
        self.breakpoints: Dict[int, int] = {}

    def insert(self, addr: int, original_byte: int) -> None:
        self.breakpoints[addr] = original_byte & 0xFF

    def remove(self, addr: int) -> Optional[int]:
        return self.breakpoints.pop(addr, None)

    def contains(self, addr: int) -> bool:
        return addr in self.breakpoints

    def all(self) -> List[int]:
        return list(self.breakpoints.keys())


# ---------------------------------------------------------------------------
# MacosArch
# ---------------------------------------------------------------------------
class MacosArch(Enum):
    X86_64 = "x86_64"
    Arm64 = "arm64"


# ---------------------------------------------------------------------------
# MacosProcess
# ---------------------------------------------------------------------------
@dataclass
class MacosProcess:
    pid: int
    task_port: int = 0
    thread_ports: List[int] = field(default_factory=list)


# ---------------------------------------------------------------------------
# MacosRegisterSet
# ---------------------------------------------------------------------------
class MacosRegisterSet:
    _X86_64 = {
        "rax": 0, "rbx": 1, "rcx": 2, "rdx": 3,
        "rdi": 4, "rsi": 5, "rbp": 6, "rsp": 7,
        "r8": 8, "r9": 9, "r10": 10, "r11": 11,
        "r12": 12, "r13": 13, "r14": 14, "r15": 15,
        "rip": 16, "rflags": 17,
        "cs": 18, "fs": 19, "gs": 20,
    }

    @staticmethod
    def x86_64_index(name: str) -> Optional[int]:
        return MacosRegisterSet._X86_64.get(name)

    @staticmethod
    def arm64_index(name: str) -> Optional[int]:
        if name.startswith("x"):
            try:
                n = int(name[1:])
            except ValueError:
                n = -1
            if 0 <= n <= 28:
                return n
            if n == 29:
                return 29
            if n == 30:
                return 30
        if name == "fp":
            return 29
        if name == "lr":
            return 30
        if name == "sp":
            return 31
        if name == "pc":
            return 32
        if name == "cpsr":
            return 33
        return None


# ---------------------------------------------------------------------------
# Mach-O constants
# ---------------------------------------------------------------------------
class macho_magic:
    MH_MAGIC = 0xFEEDFACE
    MH_CIGAM = 0xCEFAEDFE
    MH_MAGIC_64 = 0xFEEDFACF
    MH_CIGAM_64 = 0xCFFAEDFE
    FAT_MAGIC = 0xCAFEBABE
    FAT_CIGAM = 0xBEBAFECA


class CpuType(Enum):
    I386 = "i386"
    X86_64 = "x86_64"
    Arm = "arm"
    Arm64 = "arm64"
    Ppc = "ppc"
    Ppc64 = "ppc64"
    Unknown = "unknown"

    @staticmethod
    def from_u32(v: int) -> "CpuType":
        v &= 0xFFFFFFFF
        return {
            0x00000007: CpuType.I386,
            0x01000007: CpuType.X86_64,
            0x0000000C: CpuType.Arm,
            0x0100000C: CpuType.Arm64,
            0x00000012: CpuType.Ppc,
            0x01000012: CpuType.Ppc64,
        }.get(v, CpuType.Unknown)

    def name(self) -> str:
        return self.value


class MachoFileType(Enum):
    Execute = "execute"
    DyLib = "dylib"
    Bundle = "bundle"
    DyLinker = "dylinker"
    Core = "core"
    Object = "object"
    Unknown = "unknown"

    @staticmethod
    def from_u32(v: int) -> "MachoFileType":
        return {
            1: MachoFileType.Object,
            2: MachoFileType.Execute,
            4: MachoFileType.Core,
            6: MachoFileType.DyLib,
            7: MachoFileType.DyLinker,
            8: MachoFileType.Bundle,
        }.get(v, MachoFileType.Unknown)

    def name(self) -> str:
        return self.value


@dataclass
class MachoHeader:
    magic: int
    cpu_type: CpuType
    cpu_subtype: int
    file_type: MachoFileType
    n_cmds: int
    size_of_cmds: int
    flags: int
    is_64: bool


# ---------------------------------------------------------------------------
# MacosDebugger stub (non-macOS path semantics)
# ---------------------------------------------------------------------------
class MacosDebugger:
    NAME = "macos-mach"
    SUPPORTED_ARCHS = ["x86_64", "arm64"]

    def __init__(self) -> None:
        self._attached = False
        self._pid: Optional[int] = None

    def name(self) -> str:
        return self.NAME

    def supported_architectures(self) -> List[str]:
        return list(self.SUPPORTED_ARCHS)

    def is_attached(self) -> bool:
        return self._attached

    def target_pid(self) -> Optional[int]:
        return self._pid


if __name__ == "__main__":
    # basic smoke checks
    bm = BreakpointManager()
    bm.insert(0x1000, 0x90)
    assert bm.contains(0x1000)
    assert bm.remove(0x1000) == 0x90
    assert MacosRegisterSet.x86_64_index("rip") == 16
    assert MacosRegisterSet.arm64_index("pc") == 32
    assert MacosRegisterSet.arm64_index("x5") == 5
    assert CpuType.from_u32(0x0100000C) == CpuType.Arm64
    assert MachoFileType.from_u32(2) == MachoFileType.Execute
    print("ok")
