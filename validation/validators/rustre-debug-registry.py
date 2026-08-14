"""Independent validator for rustre-debug-registry.

Models the expected behavior described in the analysis report:
- A single `all()` factory returning a Vec<Box<dyn Debugger>> with 8 backends.
- Each backend exposes a distinct `name()`.
- No state, no I/O, pure construction.
"""

from abc import ABC, abstractmethod
from typing import List


class Debugger(ABC):
    @abstractmethod
    def name(self) -> str: ...
    @abstractmethod
    def supported_architectures(self) -> List[str]: ...


class FridaDebugger(Debugger):
    def name(self): return "frida"
    def supported_architectures(self): return ["x86", "x86_64", "arm", "arm64", "aarch64", "mips"]


class GdbDebugger(Debugger):
    def name(self): return "gdb-rsp"
    def supported_architectures(self): return [
        "x86", "x86_64", "arm", "arm64", "aarch64", "mips", "mips64",
        "powerpc", "powerpc64", "riscv", "riscv64", "s390", "sparc",
        "sparc64", "m68k", "avr", "msp430",
    ]


class KgdbDebugger(Debugger):
    def name(self): return "kgdb"
    def supported_architectures(self): return ["x86_64", "arm64", "arm", "mips"]


class LinuxDebugger(Debugger):
    def name(self): return "linux-ptrace"
    def supported_architectures(self): return ["x86_64", "x86"]


class MacosDebugger(Debugger):
    def name(self): return "macos-mach"
    def supported_architectures(self): return ["x86_64", "arm64"]


class UnicornDebugger(Debugger):
    def name(self): return "unicorn"
    def supported_architectures(self): return ["x86_64", "x86_32", "arm", "arm64", "mips", "mips64", "riscv32", "riscv64"]


class WindbgDebugger(Debugger):
    def name(self): return "windbg"
    def supported_architectures(self): return ["x86_64", "x86", "arm64"]


class WindowsDebugger(Debugger):
    def name(self): return "windows-debug-api"
    def supported_architectures(self): return ["x86_64", "x86"]


def all_debuggers() -> List[Debugger]:
    """Factory: returns one fresh instance of each known backend."""
    return [
        FridaDebugger(),
        GdbDebugger(),
        KgdbDebugger(),
        LinuxDebugger(),
        MacosDebugger(),
        UnicornDebugger(),
        WindbgDebugger(),
        WindowsDebugger(),
    ]


def _validate():
    v = all_debuggers()
    assert len(v) == 8, f"expected 8 backends, got {len(v)}"
    names = [d.name() for d in v]
    assert len(set(names)) == 8, f"backend names not distinct: {names}"
    expected = {"frida", "gdb-rsp", "kgdb", "linux-ptrace", "macos-mach", "unicorn", "windbg", "windows-debug-api"}
    assert set(names) == expected, f"unexpected names: {set(names) ^ expected}"
    # fresh instances each call
    v2 = all_debuggers()
    assert v is not v2 and all(a is not b for a, b in zip(v, v2)), "must return fresh instances"
    for d in v:
        archs = d.supported_architectures()
        assert isinstance(archs, list) and archs, f"{d.name()} has no architectures"
    print(f"OK: {len(v)} backends — {names}")


if __name__ == "__main__":
    _validate()
