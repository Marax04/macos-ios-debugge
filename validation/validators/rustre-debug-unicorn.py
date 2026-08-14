"""Independent Python validator for rustre-debug-unicorn.

Reimplements the documented behaviour (per reports/rustre-debug-unicorn.md)
using only the Python stdlib. Pure simulation: PC advances by an arch stride,
no real CPU semantics. Memory and registers are honest stores.
"""

from __future__ import annotations

import threading
import unittest
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Tuple


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------

class UnicornDbgError(Exception):
    pass


class EmulationError(UnicornDbgError): pass
class InvalidArch(UnicornDbgError): pass
class MemMapError(UnicornDbgError): pass
class HookError(UnicornDbgError): pass
class DebugError(UnicornDbgError): pass
class Unsupported(UnicornDbgError): pass


# ---------------------------------------------------------------------------
# Architectures
# ---------------------------------------------------------------------------

class UnicornArch(Enum):
    X86_64 = "x86_64"
    X86_32 = "x86_32"
    Arm = "arm"
    Arm64 = "arm64"
    Mips = "mips"
    Mips64 = "mips64"
    Riscv32 = "riscv32"
    Riscv64 = "riscv64"

    def __str__(self) -> str:
        return self.value

    def stride(self) -> int:
        # 1 for x86, 4 otherwise
        if self in (UnicornArch.X86_64, UnicornArch.X86_32):
            return 1
        return 4

    def pc_register(self) -> str:
        return {
            UnicornArch.X86_64: "rip",
            UnicornArch.X86_32: "eip",
        }.get(self, "pc")


SUPPORTED_ARCH_STRINGS = [str(a) for a in UnicornArch]


# ---------------------------------------------------------------------------
# Memory regions / hooks
# ---------------------------------------------------------------------------

MAX_MEM = 256 * (1024 ** 4)  # 256 TiB
PAGE_SIZE = 0x1000


@dataclass
class MemRegion:
    addr: int
    size: int
    perms: int  # bit0=R, bit1=W, bit2=X

    def readable(self) -> bool: return bool(self.perms & 1)
    def writable(self) -> bool: return bool(self.perms & 2)
    def executable(self) -> bool: return bool(self.perms & 4)

    def end(self) -> int:
        # saturating add
        e = self.addr + self.size
        return min(e, 2**64 - 1)

    def contains(self, addr: int) -> bool:
        return self.addr <= addr < self.end()


class HookType(Enum):
    Code = "Code"
    MemRead = "MemRead"
    MemWrite = "MemWrite"
    MemInvalid = "MemInvalid"
    Interrupt = "Interrupt"

    def __str__(self): return self.value


@dataclass
class HookRecord:
    hook_id: int
    hook_type: HookType
    address: int
    size: int = 0

    def __str__(self):
        return f"HookRecord(id={self.hook_id}, type={self.hook_type}, addr=0x{self.address:x})"


# ---------------------------------------------------------------------------
# Debug session
# ---------------------------------------------------------------------------

@dataclass
class Breakpoint:
    addr: int
    enabled: bool = True


@dataclass
class DebugSession:
    pid: Optional[int] = None
    running: bool = False
    breakpoints: Dict[int, Breakpoint] = field(default_factory=dict)
    modules: List = field(default_factory=list)


# ---------------------------------------------------------------------------
# UnicornDebugger (v1)
# ---------------------------------------------------------------------------

class UnicornDebugger:
    def __init__(self, arch: UnicornArch = UnicornArch.X86_64):
        self._arch = arch
        self._max_steps: int = 0
        self._step_count: int = 0
        self._session = DebugSession()
        self._mem_regions: List[MemRegion] = []
        self._memory: Dict[int, bytearray] = {}  # keyed by region base
        self._hooks: List[HookRecord] = []
        self._next_hook_id: int = 1
        self._registers: Dict[str, int] = self._default_regs()
        self._lock = threading.RLock()

    # config -----------------------------------------------------------------
    def arch(self) -> UnicornArch:
        return self._arch

    def set_max_steps(self, n: int) -> None:
        self._max_steps = n

    def step_count(self) -> int:
        return self._step_count

    def debug_session(self) -> DebugSession:
        return self._session

    def _default_regs(self) -> Dict[str, int]:
        if self._arch == UnicornArch.X86_64:
            return {"rip": 0x401000, "rsp": 0x7fff_ffff_f000}
        if self._arch == UnicornArch.X86_32:
            return {"eip": 0x401000, "esp": 0x7fff_f000}
        return {"pc": 0x401000, "sp": 0x7fff_f000}

    # memory / hooks ---------------------------------------------------------
    def map_memory(self, addr: int, size: int, perms: int) -> None:
        if size == 0:
            raise MemMapError("zero size")
        if size > MAX_MEM:
            raise MemMapError("size > 256 TiB")
        end = min(addr + size, 2**64 - 1)
        for r in self._mem_regions:
            r_end = r.end()
            if not (end <= r.addr or addr >= r_end):
                raise MemMapError(f"overlap with region 0x{r.addr:x}")
        region = MemRegion(addr, size, perms)
        self._mem_regions.append(region)
        self._memory[addr] = bytearray(size)

    def write_memory_direct(self, addr: int, data: bytes) -> None:
        region = self._find_region(addr)
        if region is None:
            raise MemMapError(f"address 0x{addr:x} not mapped")
        page_end = ((addr // PAGE_SIZE) + 1) * PAGE_SIZE
        if addr + len(data) > page_end:
            raise MemMapError("write crosses page end")
        buf = self._memory[region.addr]
        off = addr - region.addr
        buf[off:off + len(data)] = data

    def add_hook(self, hook_type: HookType, addr: int) -> int:
        hid = self._next_hook_id
        self._next_hook_id += 1
        self._hooks.append(HookRecord(hid, hook_type, addr))
        return hid

    def mem_regions(self) -> List[MemRegion]:
        return list(self._mem_regions)

    def installed_hooks(self) -> List[HookRecord]:
        return list(self._hooks)

    def _find_region(self, addr: int) -> Optional[MemRegion]:
        for r in self._mem_regions:
            if r.contains(addr):
                return r
        return None

    # emulation --------------------------------------------------------------
    def emulate(self, begin: int, until: int, steps: int) -> int:
        if not self._session.running:
            raise EmulationError("not attached")
        if begin == until:
            raise EmulationError("begin == until")
        pc = begin
        stride = self._arch.stride()
        count = 0
        while pc != until and count < steps:
            if self._max_steps and self._step_count >= self._max_steps:
                break
            pc += stride
            count += 1
            self._step_count += 1
        self._registers[self._arch.pc_register()] = pc
        return pc

    # attach/detach ----------------------------------------------------------
    def attach(self, pid: int) -> None:
        if self._session.running:
            raise DebugError("already running")
        self._session.pid = pid
        self._session.running = True

    def detach(self) -> None:
        if not self._session.running:
            raise DebugError("not attached")
        self._session.pid = None
        self._session.running = False

    def kill(self) -> None:
        self._session.pid = None
        self._session.running = False

    def is_attached(self) -> bool:
        return self._session.running

    def target_pid(self) -> Optional[int]:
        return self._session.pid

    def launch(self, *_args, **_kw):
        raise Unsupported("unicorn emulates images; use attach")

    def name(self) -> str:
        return "unicorn"

    def supported_architectures(self) -> List[str]:
        return list(SUPPORTED_ARCH_STRINGS)

    # registers --------------------------------------------------------------
    def get_registers(self) -> Dict[str, int]:
        with self._lock:
            return dict(self._registers)

    def set_registers(self, regs: Dict[str, int]) -> None:
        with self._lock:
            self._registers.update(regs)

    def get_register(self, name: str) -> Optional[int]:
        with self._lock:
            return self._registers.get(name)

    def set_register(self, name: str, value: int) -> None:
        with self._lock:
            self._registers[name] = value

    # memory r/w -------------------------------------------------------------
    def read_memory(self, addr: int, length: int) -> bytes:
        region = self._find_region(addr)
        if region is None:
            raise MemMapError("unmapped")
        page_end = ((addr // PAGE_SIZE) + 1) * PAGE_SIZE
        clamp = min(addr + length, page_end, region.end())
        n = max(0, clamp - addr)
        off = addr - region.addr
        return bytes(self._memory[region.addr][off:off + n])

    def write_memory(self, addr: int, data: bytes) -> None:
        region = self._find_region(addr)
        if region is None:
            raise MemMapError("unmapped")
        off = addr - region.addr
        self._memory[region.addr][off:off + len(data)] = data

    def memory_maps(self) -> List[Tuple[str, MemRegion]]:
        return [(f"uc_{r.addr:x}", r) for r in self._mem_regions]

    # breakpoints ------------------------------------------------------------
    def set_breakpoint(self, addr: int) -> None:
        if addr in self._session.breakpoints:
            raise DebugError("duplicate breakpoint")
        self._session.breakpoints[addr] = Breakpoint(addr, True)

    def remove_breakpoint(self, addr: int) -> None:
        self._session.breakpoints.pop(addr, None)

    def enable_breakpoint(self, addr: int) -> None:
        if addr in self._session.breakpoints:
            self._session.breakpoints[addr].enabled = True

    def disable_breakpoint(self, addr: int) -> None:
        if addr in self._session.breakpoints:
            self._session.breakpoints[addr].enabled = False

    def breakpoints(self) -> List[Breakpoint]:
        return list(self._session.breakpoints.values())

    # threads / control ------------------------------------------------------
    def threads(self) -> List[int]:
        return [1]

    def current_thread(self) -> int:
        return 1

    def pause(self) -> None:
        if not self._session.running:
            raise DebugError("not attached")

    def single_step(self, _tid: int = 1) -> Dict:
        stride = self._arch.stride()
        reg = self._arch.pc_register()
        self._registers[reg] = self._registers.get(reg, 0) + stride
        return {"event": "SingleStep", "pc": self._registers[reg]}

    def step_over(self, tid: int = 1) -> Dict:
        return self.single_step(tid)

    def step_out(self, tid: int = 1) -> Dict:
        return self.single_step(tid)

    def continue_execution(self) -> Dict:
        reg = self._arch.pc_register()
        return {"event": "SingleStep", "pc": self._registers.get(reg, 0)}

    def backtrace(self, _tid: int = 1) -> List[Dict]:
        reg = self._arch.pc_register()
        sp_reg = "rsp" if self._arch == UnicornArch.X86_64 else ("esp" if self._arch == UnicornArch.X86_32 else "sp")
        return [{"pc": self._registers.get(reg, 0), "sp": self._registers.get(sp_reg, 0)}]

    def modules(self) -> List:
        return list(self._session.modules)


# ---------------------------------------------------------------------------
# v2 spec-compliant API
# ---------------------------------------------------------------------------

class UnicornError(Exception): pass
class MemNotMapped(UnicornError): pass
class RegNotFound(UnicornError): pass
class EmulationFailed(UnicornError): pass
class V2HookError(UnicornError): pass


class V2Arch(Enum):
    X86 = "X86"
    X86_64 = "X86_64"
    Arm = "Arm"
    Arm64 = "Arm64"
    Mips = "Mips"
    Sparc = "Sparc"

    def pointer_size(self) -> int:
        return 8 if self in (V2Arch.X86_64, V2Arch.Arm64) else 4


class V2Mode(Enum):
    Mode16 = "Mode16"
    Mode32 = "Mode32"
    Mode64 = "Mode64"
    Thumb = "Thumb"
    LittleEndian = "LittleEndian"
    BigEndian = "BigEndian"


class V2HookType(Enum):
    Code = "Code"
    MemRead = "MemRead"
    MemWrite = "MemWrite"
    Block = "Block"
    Interrupt = "Interrupt"
    Invalid = "Invalid"


@dataclass
class UnicornConfig:
    arch: V2Arch
    mode: V2Mode
    stack_size: int = 0x10000
    timeout_ms: int = 0

    @staticmethod
    def x86_64() -> "UnicornConfig":
        return UnicornConfig(V2Arch.X86_64, V2Mode.Mode64)

    @staticmethod
    def arm64() -> "UnicornConfig":
        return UnicornConfig(V2Arch.Arm64, V2Mode.LittleEndian)

    @staticmethod
    def arm_thumb() -> "UnicornConfig":
        return UnicornConfig(V2Arch.Arm, V2Mode.Thumb)


@dataclass
class EmulatorHook:
    id: int
    hook_type: V2HookType
    address: int
    size: int
    callback_desc: str


@dataclass
class EmulationResult:
    instructions: int
    mem_reads: int
    mem_writes: int
    exit_addr: int
    error: Optional[str] = None

    def success(self) -> bool:
        return self.error is None


class UnicornDebuggerV2:
    def __init__(self, config: UnicornConfig):
        self.config = config
        self.memory: Dict[int, bytearray] = {}
        self.registers: Dict[str, int] = {}
        self.hooks: List[EmulatorHook] = []
        self.next_hook_id: int = 1

    def map_memory(self, base: int, data: bytes) -> None:
        self.memory[base] = bytearray(data)

    def set_reg(self, name: str, value: int) -> None:
        self.registers[name] = value

    def get_reg(self, name: str) -> int:
        if name not in self.registers:
            raise RegNotFound(name)
        return self.registers[name]

    def read_memory(self, addr: int, size: int) -> Optional[bytes]:
        for base, buf in self.memory.items():
            if base <= addr < base + len(buf):
                off = addr - base
                return bytes(buf[off:off + size])
        return None

    def add_hook(self, hook_type: V2HookType, desc: str) -> int:
        hid = self.next_hook_id
        self.next_hook_id += 1
        self.hooks.append(EmulatorHook(hid, hook_type, 0, 0, desc))
        return hid

    def hook_count(self) -> int:
        return len(self.hooks)

    def emulate(self, start: int, end: int) -> EmulationResult:
        if start == end:
            return EmulationResult(0, 0, 0, start, error="start == end")
        stride = 1 if self.config.arch in (V2Arch.X86, V2Arch.X86_64) else 4
        pc = start
        count = 0
        cap = 10_000
        while pc != end and count < cap:
            pc += stride
            count += 1
        return EmulationResult(count, 0, 0, pc)


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestUnicornDebugger(unittest.TestCase):
    def test_default_arch(self):
        d = UnicornDebugger()
        self.assertEqual(d.arch(), UnicornArch.X86_64)
        self.assertEqual(d.name(), "unicorn")
        self.assertEqual(len(d.supported_architectures()), 8)

    def test_arch_display(self):
        self.assertEqual(str(UnicornArch.X86_64), "x86_64")
        self.assertEqual(str(UnicornArch.Arm64), "arm64")

    def test_attach_detach_kill(self):
        d = UnicornDebugger()
        self.assertFalse(d.is_attached())
        d.attach(1234)
        self.assertTrue(d.is_attached())
        self.assertEqual(d.target_pid(), 1234)
        with self.assertRaises(DebugError):
            d.attach(2)
        d.detach()
        self.assertFalse(d.is_attached())
        with self.assertRaises(DebugError):
            d.detach()
        d.kill()  # idempotent

    def test_launch_unsupported(self):
        with self.assertRaises(Unsupported):
            UnicornDebugger().launch()

    def test_map_memory(self):
        d = UnicornDebugger()
        d.map_memory(0x1000, 0x1000, 7)
        self.assertEqual(len(d.mem_regions()), 1)
        with self.assertRaises(MemMapError):
            d.map_memory(0x2000, 0, 7)
        with self.assertRaises(MemMapError):
            d.map_memory(0x1800, 0x1000, 7)  # overlap
        with self.assertRaises(MemMapError):
            d.map_memory(0x100000, MAX_MEM + 1, 7)

    def test_write_direct(self):
        d = UnicornDebugger()
        d.map_memory(0x1000, 0x2000, 7)
        d.write_memory_direct(0x1000, b"\x90\x90\x90")
        self.assertEqual(d.read_memory(0x1000, 3), b"\x90\x90\x90")
        with self.assertRaises(MemMapError):
            d.write_memory_direct(0x9000, b"x")
        # cross page end
        with self.assertRaises(MemMapError):
            d.write_memory_direct(0x1FFE, b"\x00\x00\x00\x00")

    def test_emulate(self):
        d = UnicornDebugger()
        with self.assertRaises(EmulationError):
            d.emulate(0, 10, 5)  # not attached
        d.attach(1)
        with self.assertRaises(EmulationError):
            d.emulate(0x1000, 0x1000, 5)
        pc = d.emulate(0x1000, 0x1010, 100)
        self.assertEqual(pc, 0x1010)
        # Arm stride 4
        d2 = UnicornDebugger(UnicornArch.Arm64)
        d2.attach(1)
        pc = d2.emulate(0x0, 0x10, 100)
        self.assertEqual(pc, 0x10)

    def test_hook_ids(self):
        d = UnicornDebugger()
        a = d.add_hook(HookType.Code, 0x1000)
        b = d.add_hook(HookType.MemRead, 0x2000)
        self.assertEqual(a, 1)
        self.assertEqual(b, 2)
        self.assertEqual(len(d.installed_hooks()), 2)

    def test_registers(self):
        d = UnicornDebugger()
        self.assertEqual(d.get_register("rip"), 0x401000)
        d.set_register("rax", 0xdead)
        self.assertEqual(d.get_register("rax"), 0xdead)
        d.set_registers({"rbx": 1, "rcx": 2})
        regs = d.get_registers()
        self.assertEqual(regs["rbx"], 1)

    def test_single_step_stride(self):
        d = UnicornDebugger(UnicornArch.X86_64)
        d.set_register("rip", 0x1000)
        d.single_step()
        self.assertEqual(d.get_register("rip"), 0x1001)
        d2 = UnicornDebugger(UnicornArch.Mips)
        d2.set_register("pc", 0x1000)
        d2.single_step()
        self.assertEqual(d2.get_register("pc"), 0x1004)

    def test_breakpoints(self):
        d = UnicornDebugger()
        d.set_breakpoint(0x1000)
        with self.assertRaises(DebugError):
            d.set_breakpoint(0x1000)
        self.assertEqual(len(d.breakpoints()), 1)
        d.disable_breakpoint(0x1000)
        self.assertFalse(d.breakpoints()[0].enabled)
        d.enable_breakpoint(0x1000)
        self.assertTrue(d.breakpoints()[0].enabled)
        d.remove_breakpoint(0x1000)
        self.assertEqual(len(d.breakpoints()), 0)

    def test_backtrace(self):
        d = UnicornDebugger()
        bt = d.backtrace()
        self.assertEqual(len(bt), 1)
        self.assertEqual(bt[0]["pc"], 0x401000)

    def test_memregion_perms(self):
        r = MemRegion(0, 0x1000, 7)
        self.assertTrue(r.readable())
        self.assertTrue(r.writable())
        self.assertTrue(r.executable())
        r2 = MemRegion(0, 0x1000, 1)
        self.assertTrue(r2.readable())
        self.assertFalse(r2.writable())

    def test_hooktype_display(self):
        self.assertEqual(str(HookType.Code), "Code")

    def test_threads(self):
        d = UnicornDebugger()
        self.assertEqual(d.threads(), [1])
        self.assertEqual(d.current_thread(), 1)

    def test_memory_maps(self):
        d = UnicornDebugger()
        d.map_memory(0x1000, 0x1000, 7)
        mm = d.memory_maps()
        self.assertEqual(mm[0][0], "uc_1000")


class TestV2Api(unittest.TestCase):
    def test_pointer_size(self):
        self.assertEqual(V2Arch.X86_64.pointer_size(), 8)
        self.assertEqual(V2Arch.X86.pointer_size(), 4)

    def test_presets(self):
        c = UnicornConfig.x86_64()
        self.assertEqual(c.arch, V2Arch.X86_64)
        self.assertEqual(UnicornConfig.arm_thumb().mode, V2Mode.Thumb)

    def test_map_and_read(self):
        d = UnicornDebuggerV2(UnicornConfig.x86_64())
        d.map_memory(0x1000, b"\x90\x90\xc3")
        self.assertEqual(d.read_memory(0x1000, 3), b"\x90\x90\xc3")
        self.assertIsNone(d.read_memory(0x9999, 1))

    def test_regs(self):
        d = UnicornDebuggerV2(UnicornConfig.x86_64())
        d.set_reg("rax", 42)
        self.assertEqual(d.get_reg("rax"), 42)
        with self.assertRaises(RegNotFound):
            d.get_reg("xyz")

    def test_hook(self):
        d = UnicornDebuggerV2(UnicornConfig.x86_64())
        h = d.add_hook(V2HookType.Code, "test")
        self.assertEqual(h, 1)
        self.assertEqual(d.hook_count(), 1)

    def test_emulate(self):
        d = UnicornDebuggerV2(UnicornConfig.x86_64())
        r = d.emulate(0x1000, 0x1000)
        self.assertFalse(r.success())
        r = d.emulate(0x1000, 0x1005)
        self.assertTrue(r.success())
        self.assertEqual(r.instructions, 5)
        # arm stride 4
        d2 = UnicornDebuggerV2(UnicornConfig.arm64())
        r2 = d2.emulate(0, 0x10)
        self.assertEqual(r2.instructions, 4)


if __name__ == "__main__":
    unittest.main(verbosity=2)
