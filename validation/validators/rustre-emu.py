"""Independent Python validator skeleton mirroring rustre-emu's public surface.

Based on validation/reports/rustre-emu.md. Stdlib only. Provides classes,
enums and function signatures that mirror the Rust crate's public API so that
behavioral / structural comparisons can be wired up by the harness.
"""

from __future__ import annotations

import enum
import struct
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Tuple, Any


# ---------------------------------------------------------------------------
# lib.rs core
# ---------------------------------------------------------------------------

class EmulatorArch(enum.Enum):
    X86 = "x86"
    X86_64 = "x86_64"
    ARM = "arm"
    THUMB = "thumb"
    ARM64 = "arm64"
    MIPS = "mips"
    MIPSEL = "mipsel"


class OsType(enum.Enum):
    LINUX = "linux"
    WINDOWS = "windows"
    MACOS = "macos"
    NONE = "none"


class ExitReason(enum.Enum):
    HALT = "halt"
    HOOK_STOP = "hook_stop"
    INVALID_INSN = "invalid_insn"
    MEM_FAULT = "mem_fault"
    SYSCALL = "syscall"
    STEP_LIMIT = "step_limit"
    BREAKPOINT = "breakpoint"


class HookKind(enum.Enum):
    CODE = "code"
    MEM_READ = "mem_read"
    MEM_WRITE = "mem_write"
    SYSCALL = "syscall"
    BLOCK = "block"


class HookAction(enum.Enum):
    CONTINUE = "continue"
    STOP = "stop"
    SKIP = "skip"


@dataclass
class HookHandle:
    id: int


@dataclass
class SnapshotId:
    id: int


@dataclass
class MemRegion:
    base: int
    size: int
    perm: int  # bit 0=R, 1=W, 2=X


class EmulatorError(Exception):
    pass


@dataclass
class MemAccess:
    addr: int
    size: int
    is_write: bool
    value: int = 0


@dataclass
class SyscallEntry:
    num: int
    args: List[int] = field(default_factory=list)
    ret: int = 0


@dataclass
class ExecutionResult:
    reason: ExitReason
    pc: int
    steps: int
    mem_accesses: List[MemAccess] = field(default_factory=list)
    syscalls: List[SyscallEntry] = field(default_factory=list)


@dataclass
class CpuState:
    pc: int = 0
    regs: Dict[str, int] = field(default_factory=dict)


@dataclass
class RegisterFile:
    regs: Dict[str, int] = field(default_factory=dict)

    def get(self, name: str) -> int:
        return self.regs.get(name, 0)

    def set(self, name: str, value: int) -> None:
        self.regs[name] = value & 0xFFFFFFFFFFFFFFFF


@dataclass
class FlatMemory:
    pages: Dict[int, bytearray] = field(default_factory=dict)
    PAGE: int = 0x1000

    def read(self, addr: int, size: int) -> bytes:
        out = bytearray()
        for i in range(size):
            page = (addr + i) // self.PAGE
            off = (addr + i) % self.PAGE
            buf = self.pages.get(page, bytearray(self.PAGE))
            out.append(buf[off])
        return bytes(out)

    def write(self, addr: int, data: bytes) -> None:
        for i, b in enumerate(data):
            page = (addr + i) // self.PAGE
            off = (addr + i) % self.PAGE
            if page not in self.pages:
                self.pages[page] = bytearray(self.PAGE)
            self.pages[page][off] = b


class Emulator:
    """Base interface mirroring trait Emulator."""

    def read_reg(self, name: str) -> int: raise NotImplementedError
    def write_reg(self, name: str, value: int) -> None: raise NotImplementedError
    def read_mem(self, addr: int, size: int) -> bytes: raise NotImplementedError
    def write_mem(self, addr: int, data: bytes) -> None: raise NotImplementedError
    def map_region(self, region: MemRegion) -> None: raise NotImplementedError
    def step(self) -> ExitReason: raise NotImplementedError
    def run(self, max_steps: int = 1_000_000) -> ExecutionResult: raise NotImplementedError
    def add_hook(self, kind: HookKind, cb: Callable) -> HookHandle: raise NotImplementedError
    def remove_hook(self, h: HookHandle) -> None: raise NotImplementedError
    def snapshot(self) -> SnapshotId: raise NotImplementedError
    def restore(self, sid: SnapshotId) -> None: raise NotImplementedError


class EmulatorBackend:
    name: str = ""
    arch: EmulatorArch = EmulatorArch.X86

    def create(self) -> Emulator:
        raise NotImplementedError


class EmulatorRegistry:
    def __init__(self) -> None:
        self._backends: Dict[str, EmulatorBackend] = {}

    def register(self, backend: EmulatorBackend) -> None:
        self._backends[backend.name] = backend

    def find(self, name: str) -> Optional[EmulatorBackend]:
        return self._backends.get(name)

    def by_arch(self, arch: EmulatorArch) -> List[EmulatorBackend]:
        return [b for b in self._backends.values() if b.arch == arch]


class SimpleInterpreter(Emulator):
    """Minimal x86-ish reference interpreter."""

    def __init__(self) -> None:
        self.regs = RegisterFile()
        self.mem = FlatMemory()
        self.pc = 0
        self._hooks: Dict[int, Tuple[HookKind, Callable]] = {}
        self._next_hook = 1
        self._snaps: Dict[int, Tuple[Dict[str, int], Dict[int, bytes]]] = {}
        self._next_snap = 1
        self.halted = False

    def read_reg(self, name: str) -> int:
        if name == "pc":
            return self.pc
        return self.regs.get(name)

    def write_reg(self, name: str, value: int) -> None:
        if name == "pc":
            self.pc = value & 0xFFFFFFFFFFFFFFFF
        else:
            self.regs.set(name, value)

    def read_mem(self, addr: int, size: int) -> bytes:
        return self.mem.read(addr, size)

    def write_mem(self, addr: int, data: bytes) -> None:
        self.mem.write(addr, data)

    def map_region(self, region: MemRegion) -> None:
        # eager-allocate pages
        for p in range(region.base // self.mem.PAGE,
                       (region.base + region.size + self.mem.PAGE - 1) // self.mem.PAGE):
            self.mem.pages.setdefault(p, bytearray(self.mem.PAGE))

    def step(self) -> ExitReason:
        if self.halted:
            return ExitReason.HALT
        op = self.mem.read(self.pc, 1)[0]
        # Minimal opcodes: 0x90 NOP, 0xF4 HLT, 0xB8 mov eax,imm32
        if op == 0x90:
            self.pc += 1
            return ExitReason.HALT if False else ExitReason.STEP_LIMIT
        if op == 0xF4:
            self.halted = True
            self.pc += 1
            return ExitReason.HALT
        if op == 0xB8:
            imm = struct.unpack("<I", self.mem.read(self.pc + 1, 4))[0]
            self.regs.set("eax", imm)
            self.pc += 5
            return ExitReason.STEP_LIMIT
        return ExitReason.INVALID_INSN

    def run(self, max_steps: int = 1_000_000) -> ExecutionResult:
        steps = 0
        while steps < max_steps and not self.halted:
            r = self.step()
            steps += 1
            if r in (ExitReason.HALT, ExitReason.INVALID_INSN, ExitReason.MEM_FAULT,
                     ExitReason.HOOK_STOP, ExitReason.BREAKPOINT):
                return ExecutionResult(reason=r, pc=self.pc, steps=steps)
        return ExecutionResult(reason=ExitReason.STEP_LIMIT, pc=self.pc, steps=steps)

    def add_hook(self, kind: HookKind, cb: Callable) -> HookHandle:
        hid = self._next_hook
        self._next_hook += 1
        self._hooks[hid] = (kind, cb)
        return HookHandle(hid)

    def remove_hook(self, h: HookHandle) -> None:
        self._hooks.pop(h.id, None)

    def snapshot(self) -> SnapshotId:
        sid = self._next_snap
        self._next_snap += 1
        self._snaps[sid] = (dict(self.regs.regs), {k: bytes(v) for k, v in self.mem.pages.items()})
        return SnapshotId(sid)

    def restore(self, sid: SnapshotId) -> None:
        regs, pages = self._snaps[sid.id]
        self.regs.regs = dict(regs)
        self.mem.pages = {k: bytearray(v) for k, v in pages.items()}


class EmulatorFactory:
    @staticmethod
    def simple() -> SimpleInterpreter:
        return SimpleInterpreter()

    @staticmethod
    def for_arch(arch: EmulatorArch) -> Emulator:
        if arch in (EmulatorArch.ARM, EmulatorArch.THUMB):
            return ArmThumbInterpreter()
        if arch == EmulatorArch.MIPS:
            return Mips32Interpreter()
        if arch == EmulatorArch.MIPSEL:
            return Mips32ElInterpreter(Mips32Interpreter())
        return SimpleInterpreter()


# Trace / stats / coverage ---------------------------------------------------

@dataclass
class TraceEntry:
    pc: int
    insn: bytes = b""


@dataclass
class Trace:
    entries: List[TraceEntry] = field(default_factory=list)

    def push(self, e: TraceEntry) -> None:
        self.entries.append(e)


@dataclass
class InsnTrace:
    entries: List[TraceEntry] = field(default_factory=list)


@dataclass
class EmuStats:
    insns: int = 0
    branches: int = 0
    mem_reads: int = 0
    mem_writes: int = 0
    syscalls: int = 0


@dataclass
class CoverageMap:
    blocks: Dict[int, int] = field(default_factory=dict)

    def hit(self, addr: int) -> None:
        self.blocks[addr] = self.blocks.get(addr, 0) + 1


@dataclass
class EmuCoverageTracker:
    cov: CoverageMap = field(default_factory=CoverageMap)


@dataclass
class CoverageCollector:
    cov: CoverageMap = field(default_factory=CoverageMap)


@dataclass
class MemoryDumper:
    dumps: List[Tuple[int, bytes]] = field(default_factory=list)

    def dump(self, addr: int, data: bytes) -> None:
        self.dumps.append((addr, data))


class CoverageEmu:
    def __init__(self, inner: Emulator) -> None:
        self.inner = inner
        self.tracker = EmuCoverageTracker()

    def step(self) -> ExitReason:
        self.tracker.cov.hit(self.inner.read_reg("pc"))
        return self.inner.step()


# IO / MMIO / IRQ ------------------------------------------------------------

class IoPortHandler:
    def read(self, port: int, size: int) -> int: raise NotImplementedError
    def write(self, port: int, size: int, value: int) -> None: raise NotImplementedError


@dataclass
class IoPortMap:
    handlers: Dict[int, IoPortHandler] = field(default_factory=dict)

    def register(self, port: int, h: IoPortHandler) -> None:
        self.handlers[port] = h


class MmioDevice:
    def read(self, off: int, size: int) -> int: raise NotImplementedError
    def write(self, off: int, size: int, val: int) -> None: raise NotImplementedError


@dataclass
class MmioRegion:
    base: int
    size: int
    device: Optional[MmioDevice] = None


@dataclass
class MmioMap:
    regions: List[MmioRegion] = field(default_factory=list)

    def add(self, r: MmioRegion) -> None:
        self.regions.append(r)

    def find(self, addr: int) -> Optional[MmioRegion]:
        for r in self.regions:
            if r.base <= addr < r.base + r.size:
                return r
        return None


@dataclass
class InterruptVector:
    num: int
    handler: int  # address


@dataclass
class InterruptController:
    vectors: Dict[int, InterruptVector] = field(default_factory=dict)
    pending: List[int] = field(default_factory=list)

    def raise_irq(self, num: int) -> None:
        self.pending.append(num)


class ExceptionKind(enum.Enum):
    DIVIDE_BY_ZERO = "divide_by_zero"
    PAGE_FAULT = "page_fault"
    INVALID_OP = "invalid_op"
    BREAKPOINT = "breakpoint"


@dataclass
class CpuException:
    kind: ExceptionKind
    pc: int


class EmulatedDevice:
    def name(self) -> str: raise NotImplementedError


class NullDevice(EmulatedDevice):
    def name(self) -> str:
        return "null"


# Snapshots / sessions / hook manager ---------------------------------------

@dataclass
class EmuSnapshot:
    sid: SnapshotId
    regs: Dict[str, int]
    mem_pages: Dict[int, bytes]


@dataclass
class SnapshotManager:
    snapshots: Dict[int, EmuSnapshot] = field(default_factory=dict)
    _next: int = 1

    def save(self, emu: SimpleInterpreter) -> SnapshotId:
        sid = SnapshotId(self._next)
        self._next += 1
        self.snapshots[sid.id] = EmuSnapshot(
            sid,
            dict(emu.regs.regs),
            {k: bytes(v) for k, v in emu.mem.pages.items()},
        )
        return sid


@dataclass
class EmuCheckpointManager:
    checkpoints: List[SnapshotId] = field(default_factory=list)


@dataclass
class EmuHookManager:
    hooks: Dict[int, Tuple[HookKind, Callable]] = field(default_factory=dict)
    _next: int = 1

    def add(self, kind: HookKind, cb: Callable) -> HookHandle:
        hid = self._next
        self._next += 1
        self.hooks[hid] = (kind, cb)
        return HookHandle(hid)

    def remove(self, h: HookHandle) -> None:
        self.hooks.pop(h.id, None)


@dataclass
class EmuSession:
    emu: Optional[Emulator] = None
    trace: Trace = field(default_factory=Trace)
    hooks: EmuHookManager = field(default_factory=EmuHookManager)


# ---------------------------------------------------------------------------
# arm_interpreter.rs
# ---------------------------------------------------------------------------

@dataclass
class ArmRegFile:
    r: List[int] = field(default_factory=lambda: [0] * 16)
    cpsr: int = 0


class ArmThumbInterpreter(Emulator):
    def __init__(self) -> None:
        self.regs = ArmRegFile()
        self.mem = FlatMemory()
        self.thumb = False

    def read_reg(self, name: str) -> int:
        if name == "pc":
            return self.regs.r[15]
        if name == "cpsr":
            return self.regs.cpsr
        if name.startswith("r"):
            return self.regs.r[int(name[1:])]
        return 0

    def write_reg(self, name: str, value: int) -> None:
        v = value & 0xFFFFFFFF
        if name == "pc":
            self.regs.r[15] = v
        elif name == "cpsr":
            self.regs.cpsr = v
        elif name.startswith("r"):
            self.regs.r[int(name[1:])] = v

    def read_mem(self, addr: int, size: int) -> bytes:
        return self.mem.read(addr, size)

    def write_mem(self, addr: int, data: bytes) -> None:
        self.mem.write(addr, data)

    def map_region(self, region: MemRegion) -> None: pass
    def step(self) -> ExitReason: return ExitReason.HALT
    def run(self, max_steps: int = 1_000_000) -> ExecutionResult:
        return ExecutionResult(ExitReason.HALT, self.regs.r[15], 0)
    def add_hook(self, kind, cb) -> HookHandle: return HookHandle(0)
    def remove_hook(self, h) -> None: pass
    def snapshot(self) -> SnapshotId: return SnapshotId(0)
    def restore(self, sid) -> None: pass


# ---------------------------------------------------------------------------
# mips_interpreter.rs
# ---------------------------------------------------------------------------

@dataclass
class MipsRegFile:
    gpr: List[int] = field(default_factory=lambda: [0] * 32)
    pc: int = 0
    hi: int = 0
    lo: int = 0


class Mips32Interpreter(Emulator):
    def __init__(self) -> None:
        self.regs = MipsRegFile()
        self.mem = FlatMemory()
        self.big_endian = True

    def read_reg(self, name: str) -> int:
        if name == "pc": return self.regs.pc
        if name == "hi": return self.regs.hi
        if name == "lo": return self.regs.lo
        if name.startswith("r"): return self.regs.gpr[int(name[1:])]
        return 0

    def write_reg(self, name: str, value: int) -> None:
        v = value & 0xFFFFFFFF
        if name == "pc": self.regs.pc = v
        elif name == "hi": self.regs.hi = v
        elif name == "lo": self.regs.lo = v
        elif name.startswith("r"): self.regs.gpr[int(name[1:])] = v

    def read_mem(self, addr: int, size: int) -> bytes: return self.mem.read(addr, size)
    def write_mem(self, addr: int, data: bytes) -> None: self.mem.write(addr, data)
    def map_region(self, region: MemRegion) -> None: pass
    def step(self) -> ExitReason: return ExitReason.HALT
    def run(self, max_steps=1_000_000) -> ExecutionResult:
        return ExecutionResult(ExitReason.HALT, self.regs.pc, 0)
    def add_hook(self, kind, cb) -> HookHandle: return HookHandle(0)
    def remove_hook(self, h) -> None: pass
    def snapshot(self) -> SnapshotId: return SnapshotId(0)
    def restore(self, sid) -> None: pass


class Mips32ElInterpreter:
    def __init__(self, inner: Mips32Interpreter) -> None:
        self.inner = inner
        self.inner.big_endian = False


def encode_rtype(opcode: int, rs: int, rt: int, rd: int, shamt: int, funct: int) -> int:
    return ((opcode & 0x3F) << 26) | ((rs & 0x1F) << 21) | ((rt & 0x1F) << 16) \
        | ((rd & 0x1F) << 11) | ((shamt & 0x1F) << 6) | (funct & 0x3F)


def encode_itype(opcode: int, rs: int, rt: int, imm: int) -> int:
    return ((opcode & 0x3F) << 26) | ((rs & 0x1F) << 21) | ((rt & 0x1F) << 16) | (imm & 0xFFFF)


def encode_jtype(opcode: int, target: int) -> int:
    return ((opcode & 0x3F) << 26) | (target & 0x03FFFFFF)


# ---------------------------------------------------------------------------
# jit_compiler.rs
# ---------------------------------------------------------------------------

class IlOp(enum.Enum):
    NOP = "nop"
    MOV = "mov"
    ADD = "add"
    SUB = "sub"
    MUL = "mul"
    LOAD = "load"
    STORE = "store"
    BR = "br"
    CALL = "call"
    RET = "ret"
    CMP = "cmp"


@dataclass
class JitBlock:
    start_pc: int
    ops: List[Tuple[IlOp, Tuple[Any, ...]]] = field(default_factory=list)
    compiled: bool = False


@dataclass
class JitCache:
    blocks: Dict[int, JitBlock] = field(default_factory=dict)

    def get(self, pc: int) -> Optional[JitBlock]: return self.blocks.get(pc)
    def insert(self, b: JitBlock) -> None: self.blocks[b.start_pc] = b


@dataclass
class JitStats:
    compiled: int = 0
    executed: int = 0
    cache_hits: int = 0
    cache_misses: int = 0


class JitCodegen:
    def emit(self, block: JitBlock) -> None:
        block.compiled = True


@dataclass
class DirectDispatch:
    table: Dict[int, JitBlock] = field(default_factory=dict)


@dataclass
class IndirectDispatch:
    targets: List[int] = field(default_factory=list)


class JitCompiler:
    def __init__(self) -> None:
        self.cache = JitCache()
        self.stats = JitStats()
        self.codegen = JitCodegen()

    def compile_block(self, pc: int, ops: List[Tuple[IlOp, Tuple[Any, ...]]]) -> JitBlock:
        b = JitBlock(pc, ops)
        self.codegen.emit(b)
        self.cache.insert(b)
        self.stats.compiled += 1
        return b

    def execute(self, pc: int, emu: Emulator) -> Optional[int]:
        b = self.cache.get(pc)
        if b is None:
            self.stats.cache_misses += 1
            return None
        self.stats.cache_hits += 1
        self.stats.executed += 1
        # interpreter over IL
        for op, args in b.ops:
            if op == IlOp.RET:
                return emu.read_reg("eax")
        return None


# ---------------------------------------------------------------------------
# structured_execution.rs
# ---------------------------------------------------------------------------

class StructuredEmuError(enum.Enum):
    BAD_ARG = "bad_arg"
    TIMEOUT = "timeout"
    CRASH = "crash"
    UNSUPPORTED_CC = "unsupported_cc"


class CallingConvention(enum.Enum):
    SYSTEM_V = "system_v"
    MS_X64 = "ms_x64"
    CDECL = "cdecl"
    STDCALL = "stdcall"
    FASTCALL = "fastcall"
    AAPCS = "aapcs"


@dataclass
class EmuValue:
    kind: str  # "int", "ptr", "bytes", "cstr", "struct"
    value: Any


@dataclass
class MemSnapshot:
    pages: Dict[int, bytes] = field(default_factory=dict)


@dataclass
class MemoryDiff:
    changed: Dict[int, Tuple[bytes, bytes]] = field(default_factory=dict)


@dataclass
class ExecTraceEntry:
    pc: int
    insn: bytes = b""


@dataclass
class ExecTrace:
    entries: List[ExecTraceEntry] = field(default_factory=list)


@dataclass
class LoopDetector:
    visits: Dict[int, int] = field(default_factory=dict)
    threshold: int = 1024

    def visit(self, pc: int) -> bool:
        self.visits[pc] = self.visits.get(pc, 0) + 1
        return self.visits[pc] > self.threshold


@dataclass
class EmuMemory:
    flat: FlatMemory = field(default_factory=FlatMemory)


@dataclass
class FunctionCallResult:
    ret: EmuValue
    mem_diff: MemoryDiff
    trace: ExecTrace
    ok: bool = True


class FunctionEmulator:
    def __init__(self, emu: Emulator, cc: CallingConvention = CallingConvention.SYSTEM_V) -> None:
        self.emu = emu
        self.cc = cc

    def call(self, addr: int, args: List[EmuValue]) -> FunctionCallResult:
        # Skeleton: marshal args according to CC, run, capture diff
        return FunctionCallResult(
            ret=EmuValue("int", 0),
            mem_diff=MemoryDiff(),
            trace=ExecTrace(),
        )


class StringEmulator:
    def __init__(self, emu: Emulator) -> None:
        self.emu = emu

    def strlen(self, addr: int) -> int:
        n = 0
        while True:
            b = self.emu.read_mem(addr + n, 1)
            if not b or b[0] == 0:
                return n
            n += 1
            if n > 1 << 20:
                return n


class TracingEmulator:
    def __init__(self, inner: Emulator) -> None:
        self.inner = inner
        self.trace = ExecTrace()

    def step(self) -> ExitReason:
        self.trace.entries.append(ExecTraceEntry(self.inner.read_reg("pc")))
        return self.inner.step()


# ---------------------------------------------------------------------------
# os_emulation.rs
# ---------------------------------------------------------------------------

class FdKind(enum.Enum):
    FILE = "file"
    SOCKET = "socket"
    PIPE = "pipe"
    STDIN = "stdin"
    STDOUT = "stdout"
    STDERR = "stderr"


@dataclass
class FdTable:
    fds: Dict[int, FdKind] = field(default_factory=lambda: {0: FdKind.STDIN, 1: FdKind.STDOUT, 2: FdKind.STDERR})
    _next: int = 3

    def open(self, kind: FdKind) -> int:
        fd = self._next
        self._next += 1
        self.fds[fd] = kind
        return fd

    def close(self, fd: int) -> bool:
        return self.fds.pop(fd, None) is not None


@dataclass
class BumpAllocator:
    base: int = 0x10000000
    pos: int = 0x10000000

    def alloc(self, n: int) -> int:
        a = self.pos
        self.pos += n
        return a


@dataclass
class OsProcess:
    pid: int = 1
    fds: FdTable = field(default_factory=FdTable)
    alloc: BumpAllocator = field(default_factory=BumpAllocator)


@dataclass
class SyscallResult:
    ok: bool
    value: int = 0
    errno: int = 0


class OsEmulator:
    def dispatch(self, emu: Emulator, num: int, args: List[int]) -> SyscallResult:
        raise NotImplementedError


class LinuxX86_64Emulator(OsEmulator):
    def __init__(self) -> None:
        self.process = OsProcess()

    def dispatch(self, emu: Emulator, num: int, args: List[int]) -> SyscallResult:
        # 0=read, 1=write, 60=exit
        if num == 60:
            return SyscallResult(True, args[0] if args else 0)
        return SyscallResult(True, 0)


class WindowsX86_64Stub(OsEmulator):
    def dispatch(self, emu: Emulator, num: int, args: List[int]) -> SyscallResult:
        return SyscallResult(False, errno=1)  # ENOSYS


@dataclass
class OsEmuSession:
    os: Optional[OsEmulator] = None
    trace: List[SyscallEntry] = field(default_factory=list)


def read_cstring(emu: Emulator, addr: int) -> str:
    out = bytearray()
    i = 0
    while True:
        b = emu.read_mem(addr + i, 1)
        if not b or b[0] == 0:
            break
        out.append(b[0])
        i += 1
        if i > 1 << 20:
            break
    return out.decode("utf-8", errors="replace")


# ---------------------------------------------------------------------------
# os_syscall_model.rs
# ---------------------------------------------------------------------------

class SyscallError(enum.Enum):
    UNKNOWN = "unknown"
    PERMISSION = "permission"
    BAD_FD = "bad_fd"
    NO_MEM = "no_mem"
    INTERRUPTED = "interrupted"


class SyscallOs(enum.Enum):
    LINUX = "linux"
    WINDOWS = "windows"
    MACOS = "macos"


class SyscallGroup(enum.Enum):
    FILE_IO = "file_io"
    NETWORK = "network"
    PROCESS = "process"
    MEMORY = "memory"
    IPC = "ipc"
    TIME = "time"
    SIGNAL = "signal"
    OTHER = "other"


@dataclass
class SyscallInfo:
    number: int
    name: str
    os: SyscallOs
    group: SyscallGroup
    arg_count: int = 0


@dataclass
class SyscallArguments:
    args: List[int] = field(default_factory=list)


@dataclass
class SyscallDispatch:
    table: Dict[Tuple[SyscallOs, int], SyscallInfo] = field(default_factory=dict)

    def register(self, info: SyscallInfo) -> None:
        self.table[(info.os, info.number)] = info

    def lookup(self, os_: SyscallOs, num: int) -> Optional[SyscallInfo]:
        return self.table.get((os_, num))


class LinuxSyscalls:
    pass


class WindowsSyscalls:
    pass


class MacOsSyscalls:
    pass


@dataclass
class SyscallEmulator:
    dispatch: SyscallDispatch = field(default_factory=SyscallDispatch)


@dataclass
class SyscallTrace:
    events: List[SyscallEntry] = field(default_factory=list)


@dataclass
class OsSyscallModel:
    os: SyscallOs = SyscallOs.LINUX
    dispatch: SyscallDispatch = field(default_factory=SyscallDispatch)


@dataclass
class SyscallFilter:
    allow: List[int] = field(default_factory=list)
    deny: List[int] = field(default_factory=list)

    def allows(self, num: int) -> bool:
        if num in self.deny: return False
        if not self.allow: return True
        return num in self.allow


@dataclass
class SyscallStats:
    counts: Dict[int, int] = field(default_factory=dict)

    def record(self, num: int) -> None:
        self.counts[num] = self.counts.get(num, 0) + 1


@dataclass
class SyscallConvention:
    arg_regs: List[str]
    ret_reg: str
    num_reg: str


@dataclass
class SyscallInterception:
    handler: Callable


@dataclass
class SyscallInterceptor:
    intercepts: Dict[int, SyscallInterception] = field(default_factory=dict)


@dataclass
class SyscallPatternDetector:
    patterns: List[List[int]] = field(default_factory=list)

    def detect(self, seq: List[int]) -> List[int]:
        hits = []
        for i, pat in enumerate(self.patterns):
            if any(seq[j:j + len(pat)] == pat for j in range(len(seq) - len(pat) + 1)):
                hits.append(i)
        return hits


_LINUX_GROUPS = {
    "read": SyscallGroup.FILE_IO, "write": SyscallGroup.FILE_IO,
    "open": SyscallGroup.FILE_IO, "close": SyscallGroup.FILE_IO,
    "socket": SyscallGroup.NETWORK, "connect": SyscallGroup.NETWORK,
    "fork": SyscallGroup.PROCESS, "execve": SyscallGroup.PROCESS,
    "exit": SyscallGroup.PROCESS, "mmap": SyscallGroup.MEMORY,
    "munmap": SyscallGroup.MEMORY, "brk": SyscallGroup.MEMORY,
    "kill": SyscallGroup.SIGNAL, "time": SyscallGroup.TIME,
    "pipe": SyscallGroup.IPC,
}


def linux_syscall_group(name: str) -> SyscallGroup:
    return _LINUX_GROUPS.get(name, SyscallGroup.OTHER)


# ---------------------------------------------------------------------------
# syscall_emulation.rs (lower-level)
# ---------------------------------------------------------------------------

@dataclass
class RegisterContext:
    regs: Dict[str, int] = field(default_factory=dict)


@dataclass
class SyscallEvent:
    num: int
    name: str = ""
    args: List[int] = field(default_factory=list)
    ret: int = 0
    error: Optional[str] = None


@dataclass
class VirtualFile:
    path: str
    data: bytearray = field(default_factory=bytearray)
    pos: int = 0


@dataclass
class VirtualFs:
    files: Dict[str, VirtualFile] = field(default_factory=dict)

    def open(self, path: str) -> VirtualFile:
        if path not in self.files:
            self.files[path] = VirtualFile(path)
        return self.files[path]


@dataclass
class MemoryRegion:
    base: int
    size: int
    perm: int


@dataclass
class MmapRequest:
    addr: int
    size: int
    prot: int
    flags: int


@dataclass
class VirtualMemory:
    regions: List[MemoryRegion] = field(default_factory=list)

    def mmap(self, req: MmapRequest) -> int:
        self.regions.append(MemoryRegion(req.addr, req.size, req.prot))
        return req.addr


def format_trace(events: List[SyscallEvent]) -> str:
    return "\n".join(f"{e.num} {e.name}({', '.join(map(str, e.args))}) = {e.ret}" for e in events)


def syscall_histogram(events: List[SyscallEvent]) -> Dict[str, int]:
    out: Dict[str, int] = {}
    for e in events:
        key = e.name or str(e.num)
        out[key] = out.get(key, 0) + 1
    return out


def error_syscalls(events: List[SyscallEvent]) -> List[SyscallEvent]:
    return [e for e in events if e.error is not None]


def attempted_privilege_escalation(events: List[SyscallEvent]) -> bool:
    names = {e.name for e in events}
    return bool(names & {"setuid", "setgid", "setresuid", "capset"})


# ---------------------------------------------------------------------------
# taint_emulation.rs
# ---------------------------------------------------------------------------

TaintLabel = int


@dataclass
class TaintSource:
    label: TaintLabel
    name: str
    origin: str = ""


@dataclass
class MemTaintMap:
    labels: Dict[int, TaintLabel] = field(default_factory=dict)

    def set(self, addr: int, label: TaintLabel) -> None: self.labels[addr] = label
    def get(self, addr: int) -> TaintLabel: return self.labels.get(addr, 0)
    def clear(self, addr: int) -> None: self.labels.pop(addr, None)


@dataclass
class RegTaintMap:
    labels: Dict[str, TaintLabel] = field(default_factory=dict)

    def set(self, name: str, label: TaintLabel) -> None: self.labels[name] = label
    def get(self, name: str) -> TaintLabel: return self.labels.get(name, 0)


class TaintEvent(enum.Enum):
    SOURCE = "source"
    PROPAGATE = "propagate"
    SINK = "sink"
    CLEAR = "clear"


class TaintPropagationFlags:
    REG_TO_REG = 1
    REG_TO_MEM = 2
    MEM_TO_REG = 4
    ARITH = 8
    POINTER = 16


class TaintDetectionFlags:
    CONTROL_FLOW = 1
    SYSCALL_ARG = 2
    INDIRECT_READ = 4
    INDIRECT_WRITE = 8


class TaintPolicyFlags:
    STRICT = 1
    LAZY = 2
    SHADOW_STACK = 4


@dataclass
class TaintPolicy:
    propagation: int = TaintPropagationFlags.REG_TO_REG | TaintPropagationFlags.MEM_TO_REG | TaintPropagationFlags.REG_TO_MEM
    detection: int = TaintDetectionFlags.SYSCALL_ARG
    flags: int = TaintPolicyFlags.LAZY


@dataclass
class TaintEmulator:
    emu: Optional[Emulator] = None
    policy: TaintPolicy = field(default_factory=TaintPolicy)
    regs: RegTaintMap = field(default_factory=RegTaintMap)
    mem: MemTaintMap = field(default_factory=MemTaintMap)
    events: List[Tuple[TaintEvent, Any]] = field(default_factory=list)
    sources: List[TaintSource] = field(default_factory=list)

    def add_source(self, src: TaintSource) -> None:
        self.sources.append(src)
        self.events.append((TaintEvent.SOURCE, src.label))


@dataclass
class TaintSummary:
    tainted_regs: int = 0
    tainted_mem_bytes: int = 0


@dataclass
class TaintReport:
    summary: TaintSummary = field(default_factory=TaintSummary)
    events: List[Tuple[TaintEvent, Any]] = field(default_factory=list)


# ---------------------------------------------------------------------------
# heap_emulator.rs
# ---------------------------------------------------------------------------

class HeapError(enum.Enum):
    OOM = "oom"
    INVALID_FREE = "invalid_free"
    DOUBLE_FREE = "double_free"
    OOB = "oob"
    USE_AFTER_FREE = "uaf"


class BlockState(enum.Enum):
    FREE = "free"
    ALLOCATED = "allocated"
    QUARANTINED = "quarantined"


class HeapEventType(enum.Enum):
    ALLOC = "alloc"
    FREE = "free"
    REALLOC = "realloc"
    CORRUPTION = "corruption"


class HeapErrorKind(enum.Enum):
    UAF = "uaf"
    DOUBLE_FREE = "double_free"
    OOB_READ = "oob_read"
    OOB_WRITE = "oob_write"
    INVALID_FREE = "invalid_free"


class CanaryKind(enum.Enum):
    FRONT = "front"
    BACK = "back"
    BOTH = "both"


@dataclass
class HeapBlock:
    addr: int
    size: int
    state: BlockState = BlockState.ALLOCATED
    canary: int = 0xDEADBEEF


@dataclass
class HeapEvent:
    kind: HeapEventType
    addr: int
    size: int = 0


@dataclass
class HeapState:
    blocks: Dict[int, HeapBlock] = field(default_factory=dict)
    events: List[HeapEvent] = field(default_factory=list)


@dataclass
class CanaryViolation:
    addr: int
    expected: int
    found: int


@dataclass
class CanaryManager:
    canaries: Dict[int, int] = field(default_factory=dict)
    violations: List[CanaryViolation] = field(default_factory=list)

    def set(self, addr: int, value: int) -> None: self.canaries[addr] = value
    def check(self, addr: int, found: int) -> bool:
        exp = self.canaries.get(addr, found)
        if exp != found:
            self.violations.append(CanaryViolation(addr, exp, found))
            return False
        return True


@dataclass
class ChunkAllocator:
    next_addr: int = 0x20000000
    align: int = 16

    def alloc(self, size: int) -> int:
        a = (self.next_addr + self.align - 1) & ~(self.align - 1)
        self.next_addr = a + size
        return a


@dataclass
class HeapEmulator:
    state: HeapState = field(default_factory=HeapState)
    allocator: ChunkAllocator = field(default_factory=ChunkAllocator)
    canaries: CanaryManager = field(default_factory=CanaryManager)
    errors: List[Tuple[HeapErrorKind, int]] = field(default_factory=list)

    def malloc(self, size: int) -> int:
        addr = self.allocator.alloc(size)
        self.state.blocks[addr] = HeapBlock(addr, size, BlockState.ALLOCATED)
        self.state.events.append(HeapEvent(HeapEventType.ALLOC, addr, size))
        return addr

    def free(self, addr: int) -> Optional[HeapError]:
        b = self.state.blocks.get(addr)
        if b is None:
            self.errors.append((HeapErrorKind.INVALID_FREE, addr))
            return HeapError.INVALID_FREE
        if b.state == BlockState.FREE:
            self.errors.append((HeapErrorKind.DOUBLE_FREE, addr))
            return HeapError.DOUBLE_FREE
        b.state = BlockState.FREE
        self.state.events.append(HeapEvent(HeapEventType.FREE, addr, b.size))
        return None


@dataclass
class HeapVulnerabilityReport:
    findings: List[Tuple[HeapErrorKind, int]] = field(default_factory=list)


def visualise_heap(emulator: HeapEmulator, width: int) -> str:
    lines = []
    for addr, b in sorted(emulator.state.blocks.items()):
        ch = "A" if b.state == BlockState.ALLOCATED else "F"
        bar = ch * max(1, min(width, b.size // 16))
        lines.append(f"{addr:#x} [{bar}] {b.size}")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# fuzzing_integration.rs
# ---------------------------------------------------------------------------

@dataclass
class CorpusEntry:
    data: bytes
    coverage: int = 0
    parent: Optional[int] = None


@dataclass
class Corpus:
    entries: List[CorpusEntry] = field(default_factory=list)

    def add(self, e: CorpusEntry) -> None: self.entries.append(e)


@dataclass
class FuzzCoverage:
    blocks: Dict[int, int] = field(default_factory=dict)

    def merge(self, other: "FuzzCoverage") -> int:
        new = 0
        for k, v in other.blocks.items():
            if k not in self.blocks:
                new += 1
            self.blocks[k] = self.blocks.get(k, 0) + v
        return new


InputInjector = Callable[[Emulator, bytes], None]


@dataclass
class FuzzRunResult:
    crashed: bool = False
    new_coverage: int = 0
    exit_reason: ExitReason = ExitReason.HALT


class Rng:
    def __init__(self, seed: int) -> None:
        self.state = seed & 0xFFFFFFFFFFFFFFFF

    def next_u64(self) -> int:
        x = self.state
        x ^= (x << 13) & 0xFFFFFFFFFFFFFFFF
        x ^= (x >> 7) & 0xFFFFFFFFFFFFFFFF
        x ^= (x << 17) & 0xFFFFFFFFFFFFFFFF
        self.state = x & 0xFFFFFFFFFFFFFFFF
        return self.state

    def below(self, n: int) -> int:
        return self.next_u64() % n if n else 0


class MutationKind(enum.Enum):
    BITFLIP = "bitflip"
    BYTEFLIP = "byteflip"
    ARITH = "arith"
    INSERT = "insert"
    DELETE = "delete"
    SPLICE = "splice"
    DICT = "dict"


@dataclass
class Mutator:
    rng: Rng

    def mutate(self, data: bytes) -> bytes:
        if not data:
            return b"\x00"
        out = bytearray(data)
        i = self.rng.below(len(out))
        bit = self.rng.below(8)
        out[i] ^= 1 << bit
        return bytes(out)


@dataclass
class FuzzStats:
    execs: int = 0
    crashes: int = 0
    unique_crashes: int = 0
    new_paths: int = 0


@dataclass
class FuzzSession:
    corpus: Corpus = field(default_factory=Corpus)
    coverage: FuzzCoverage = field(default_factory=FuzzCoverage)
    stats: FuzzStats = field(default_factory=FuzzStats)


@dataclass
class CoverageGuidedFuzzer:
    session: FuzzSession = field(default_factory=FuzzSession)
    mutator: Optional[Mutator] = None
    injector: Optional[InputInjector] = None

    def run_one(self, emu: Emulator, data: bytes) -> FuzzRunResult:
        if self.injector:
            self.injector(emu, data)
        res = emu.run(max_steps=10_000)
        self.session.stats.execs += 1
        crashed = res.reason in (ExitReason.INVALID_INSN, ExitReason.MEM_FAULT)
        if crashed:
            self.session.stats.crashes += 1
        return FuzzRunResult(crashed=crashed, exit_reason=res.reason)


# ---------------------------------------------------------------------------
# library_stub.rs
# ---------------------------------------------------------------------------

class StubError(enum.Enum):
    NOT_IMPLEMENTED = "not_implemented"
    BAD_ARGS = "bad_args"
    INTERNAL = "internal"


class SideEffect(enum.Enum):
    NONE = "none"
    WRITE_MEM = "write_mem"
    ALLOC = "alloc"
    FREE = "free"
    IO = "io"
    REGISTRY = "registry"


@dataclass
class StubArgs:
    args: List[Any] = field(default_factory=list)


@dataclass
class StubReturn:
    value: int = 0
    side_effects: List[SideEffect] = field(default_factory=list)


@dataclass
class StubLogEntry:
    function: str
    args: StubArgs
    ret: StubReturn


@dataclass
class VirtualRegistry:
    keys: Dict[str, str] = field(default_factory=dict)

    def set(self, key: str, value: str) -> None: self.keys[key] = value
    def get(self, key: str) -> Optional[str]: return self.keys.get(key)


STUBBED_FUNCTIONS: Tuple[str, ...] = (
    "strlen", "strcpy", "strncpy", "strcat", "strcmp", "memcpy", "memset", "memcmp",
    "malloc", "calloc", "realloc", "free",
    "printf", "puts", "fprintf", "scanf",
    "fopen", "fclose", "fread", "fwrite", "fseek",
    "GetProcAddress", "LoadLibraryA", "LoadLibraryW",
    "VirtualAlloc", "VirtualFree", "HeapAlloc", "HeapFree",
    "CreateFileA", "CreateFileW", "ReadFile", "WriteFile", "CloseHandle",
    "RegOpenKeyExA", "RegQueryValueExA", "RegSetValueExA", "RegCloseKey",
)


_STUB_MODULE = {
    "GetProcAddress": "kernel32",
    "LoadLibraryA": "kernel32",
    "LoadLibraryW": "kernel32",
    "VirtualAlloc": "kernel32",
    "VirtualFree": "kernel32",
    "HeapAlloc": "kernel32",
    "HeapFree": "kernel32",
    "CreateFileA": "kernel32",
    "CreateFileW": "kernel32",
    "ReadFile": "kernel32",
    "WriteFile": "kernel32",
    "CloseHandle": "kernel32",
    "RegOpenKeyExA": "advapi32",
    "RegQueryValueExA": "advapi32",
    "RegSetValueExA": "advapi32",
    "RegCloseKey": "advapi32",
}


def is_stubbed(function: str) -> bool:
    return function in STUBBED_FUNCTIONS


def stub_module(function: str) -> str:
    return _STUB_MODULE.get(function, "libc")


@dataclass
class LibraryStubEngine:
    log: List[StubLogEntry] = field(default_factory=list)
    registry: VirtualRegistry = field(default_factory=VirtualRegistry)

    def call(self, name: str, args: StubArgs) -> StubReturn:
        if not is_stubbed(name):
            raise EmulatorError(f"not stubbed: {name}")
        ret = StubReturn(value=0)
        self.log.append(StubLogEntry(name, args, ret))
        return ret


# ---------------------------------------------------------------------------
# emu_device_model.rs
# ---------------------------------------------------------------------------

class DeviceKind(enum.Enum):
    NULL = "null"
    RAM = "ram"
    ROM = "rom"
    UART = "uart"
    TIMER = "timer"


class EmuDevice:
    kind: DeviceKind = DeviceKind.NULL

    def read(self, off: int, size: int) -> int: return 0
    def write(self, off: int, size: int, val: int) -> None: pass


class RamDevice(EmuDevice):
    kind = DeviceKind.RAM

    def __init__(self, size: int) -> None:
        self.buf = bytearray(size)

    def read(self, off: int, size: int) -> int:
        return int.from_bytes(self.buf[off:off + size], "little")

    def write(self, off: int, size: int, val: int) -> None:
        self.buf[off:off + size] = val.to_bytes(size, "little")


class RomDevice(EmuDevice):
    kind = DeviceKind.ROM

    def __init__(self, data: bytes) -> None:
        self.buf = bytes(data)

    def read(self, off: int, size: int) -> int:
        return int.from_bytes(self.buf[off:off + size], "little")

    def write(self, off: int, size: int, val: int) -> None:
        # ROM ignores writes
        pass


class UartDevice(EmuDevice):
    kind = DeviceKind.UART

    def __init__(self) -> None:
        self.tx: List[int] = []
        self.rx: List[int] = []

    def read(self, off: int, size: int) -> int:
        return self.rx.pop(0) if self.rx else 0

    def write(self, off: int, size: int, val: int) -> None:
        self.tx.append(val & 0xFF)


class TimerDevice(EmuDevice):
    kind = DeviceKind.TIMER

    def __init__(self) -> None:
        self.ticks = 0

    def read(self, off: int, size: int) -> int:
        return self.ticks & ((1 << (size * 8)) - 1)

    def write(self, off: int, size: int, val: int) -> None:
        self.ticks = val


@dataclass
class EmuDeviceModel:
    devices: List[Tuple[int, int, EmuDevice]] = field(default_factory=list)

    def attach(self, base: int, size: int, dev: EmuDevice) -> None:
        self.devices.append((base, size, dev))

    def route(self, addr: int) -> Optional[Tuple[int, EmuDevice]]:
        for base, size, dev in self.devices:
            if base <= addr < base + size:
                return addr - base, dev
        return None


# ---------------------------------------------------------------------------
# emu_interrupt_controller.rs
# ---------------------------------------------------------------------------

class InterruptState(enum.Enum):
    IDLE = "idle"
    PENDING = "pending"
    ACTIVE = "active"
    MASKED = "masked"


class InterruptTrigger(enum.Enum):
    LEVEL = "level"
    EDGE = "edge"


class IrqEventKind(enum.Enum):
    RAISE = "raise"
    ACK = "ack"
    MASK = "mask"
    UNMASK = "unmask"


@dataclass
class InterruptLine:
    num: int
    state: InterruptState = InterruptState.IDLE
    trigger: InterruptTrigger = InterruptTrigger.LEVEL
    priority: int = 0


@dataclass
class IrqEvent:
    kind: IrqEventKind
    line: int


@dataclass
class EmuInterruptController:
    lines: Dict[int, InterruptLine] = field(default_factory=dict)
    events: List[IrqEvent] = field(default_factory=list)

    def add_line(self, line: InterruptLine) -> None:
        self.lines[line.num] = line

    def raise_irq(self, num: int) -> None:
        ln = self.lines.get(num)
        if ln and ln.state != InterruptState.MASKED:
            ln.state = InterruptState.PENDING
            self.events.append(IrqEvent(IrqEventKind.RAISE, num))

    def ack(self, num: int) -> None:
        ln = self.lines.get(num)
        if ln:
            ln.state = InterruptState.IDLE
            self.events.append(IrqEvent(IrqEventKind.ACK, num))


# ---------------------------------------------------------------------------
# emu_execution_statistics.rs
# ---------------------------------------------------------------------------

@dataclass
class InsnCount:
    by_mnemonic: Dict[str, int] = field(default_factory=dict)
    total: int = 0

    def add(self, mnemonic: str) -> None:
        self.by_mnemonic[mnemonic] = self.by_mnemonic.get(mnemonic, 0) + 1
        self.total += 1


@dataclass
class BranchStats:
    taken: int = 0
    not_taken: int = 0
    indirect: int = 0


@dataclass
class MemAccessStats:
    reads: int = 0
    writes: int = 0
    bytes_read: int = 0
    bytes_written: int = 0


@dataclass
class StatsReport:
    insns: InsnCount = field(default_factory=InsnCount)
    branches: BranchStats = field(default_factory=BranchStats)
    mem: MemAccessStats = field(default_factory=MemAccessStats)


@dataclass
class EmuExecutionStatistics:
    report: StatsReport = field(default_factory=StatsReport)
    loop_detector: LoopDetector = field(default_factory=LoopDetector)

    def on_insn(self, pc: int, mnemonic: str) -> None:
        self.report.insns.add(mnemonic)
        self.loop_detector.visit(pc)

    def on_mem(self, is_write: bool, size: int) -> None:
        if is_write:
            self.report.mem.writes += 1
            self.report.mem.bytes_written += size
        else:
            self.report.mem.reads += 1
            self.report.mem.bytes_read += size


# ---------------------------------------------------------------------------
# backends_registry.rs
# ---------------------------------------------------------------------------

@dataclass
class BackendDescriptor:
    name: str
    arch: EmulatorArch
    description: str = ""


_ALL_BACKENDS: Tuple[BackendDescriptor, ...] = (
    BackendDescriptor("simple", EmulatorArch.X86, "Minimal x86 interpreter"),
    BackendDescriptor("arm", EmulatorArch.ARM, "ARM/Thumb interpreter"),
    BackendDescriptor("thumb", EmulatorArch.THUMB, "Thumb interpreter"),
    BackendDescriptor("mips32", EmulatorArch.MIPS, "MIPS32 BE interpreter"),
    BackendDescriptor("mips32el", EmulatorArch.MIPSEL, "MIPS32 LE interpreter"),
)


def all_backends() -> Tuple[BackendDescriptor, ...]:
    return _ALL_BACKENDS


def find_backend(name: str) -> Optional[BackendDescriptor]:
    for b in _ALL_BACKENDS:
        if b.name == name:
            return b
    return None


# ---------------------------------------------------------------------------
# mem_provider.rs
# ---------------------------------------------------------------------------

@dataclass
class MemProviderDescriptor:
    name: str
    description: str = ""


_ALL_PROVIDERS: Tuple[MemProviderDescriptor, ...] = (
    MemProviderDescriptor("virtual", "Page-based virtual memory"),
    MemProviderDescriptor("composite", "Layered composite memory"),
)


class EmuVirtualMemoryProvider(FlatMemory):
    pass


@dataclass
class EmuCompositeMemoryProvider:
    layers: List[FlatMemory] = field(default_factory=list)

    def read(self, addr: int, size: int) -> bytes:
        for layer in reversed(self.layers):
            try:
                return layer.read(addr, size)
            except Exception:
                continue
        return b"\x00" * size

    def write(self, addr: int, data: bytes) -> None:
        if not self.layers:
            self.layers.append(FlatMemory())
        self.layers[-1].write(addr, data)


def new_virtual() -> EmuVirtualMemoryProvider:
    return EmuVirtualMemoryProvider()


def new_composite() -> EmuCompositeMemoryProvider:
    return EmuCompositeMemoryProvider()


def find_provider(name: str) -> Optional[MemProviderDescriptor]:
    for p in _ALL_PROVIDERS:
        if p.name == name:
            return p
    return None


# ---------------------------------------------------------------------------
# Self-test
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    emu = SimpleInterpreter()
    emu.map_region(MemRegion(0, 0x1000, 0b111))
    # mov eax, 0x41; hlt
    emu.write_mem(0, bytes([0xB8, 0x41, 0x00, 0x00, 0x00, 0xF4]))
    res = emu.run()
    assert emu.read_reg("eax") == 0x41, emu.read_reg("eax")
    assert res.reason == ExitReason.HALT

    heap = HeapEmulator()
    a = heap.malloc(64)
    heap.free(a)
    assert heap.free(a) == HeapError.DOUBLE_FREE

    assert linux_syscall_group("read") == SyscallGroup.FILE_IO
    assert is_stubbed("malloc")
    assert stub_module("LoadLibraryA") == "kernel32"
    assert encode_itype(0x23, 1, 2, 0x100) == ((0x23 << 26) | (1 << 21) | (2 << 16) | 0x100)
    print("rustre-emu.py self-test OK")
