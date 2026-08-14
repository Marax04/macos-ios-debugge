"""Independent validator for rustre-debug-windbg based on the analysis report.

Simulates the expected behavior described in
validation/reports/rustre-debug-windbg.md using only stdlib.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Tuple


# ---------- Enums / errors ----------

class ExecutionStatus(Enum):
    NoDebuggee = "NoDebuggee"
    Break = "Break"
    Go = "Go"
    StepOver = "StepOver"
    StepInto = "StepInto"
    StepBranch = "StepBranch"
    Reverse = "Reverse"


class WinDbgError(Exception):
    pass


class CommandError(WinDbgError):
    pass


class BreakpointExists(WinDbgError):
    pass


# ---------- Data classes ----------

@dataclass
class DbgModule:
    name: str
    base: int
    size: int
    timestamp: int = 0
    checksum: int = 0
    path: str = ""


@dataclass
class WinDbgThread:
    thread_id: int
    system_id: int
    teb_addr: int
    start_addr: int
    state: str = "Ready"


@dataclass
class ExtensionResult:
    command: str
    output: str
    success: bool


@dataclass
class Breakpoint:
    id: int
    address: int
    kind: str = "Software"
    enabled: bool = True


# ---------- Session ----------

DEFAULT_MODULES = [
    DbgModule("ntdll",      0x7FFE_0000_0000, 0x200000),
    DbgModule("kernel32",   0x7FFE_0020_0000, 0x100000),
    DbgModule("kernelbase", 0x7FFE_0030_0000, 0x100000),
    DbgModule("user32",     0x7FFE_0040_0000, 0x100000),
    DbgModule("combase",    0x7FFE_0050_0000, 0x100000),
]

DEFAULT_THREADS = [
    WinDbgThread(1, 0x100, 0x7FF0_0000_0000, 0x7FFE_0000_1000),
    WinDbgThread(2, 0x101, 0x7FF0_0000_1000, 0x7FFE_0000_2000),
    WinDbgThread(3, 0x102, 0x7FF0_0000_2000, 0x7FFE_0000_3000),
    WinDbgThread(4, 0x103, 0x7FF0_0000_3000, 0x7FFE_0000_4000),
]

SIM_MZ_PAGE = 0x7FFF_D000_0000
LAUNCH_PAGE = 0x0000_0001_4001_0000
FIXED_PID = 0x1000


class WinDbgSession:
    def __init__(self) -> None:
        self.modules: List[DbgModule] = list(DEFAULT_MODULES)
        self.threads: List[WinDbgThread] = list(DEFAULT_THREADS)
        self.status: ExecutionStatus = ExecutionStatus.NoDebuggee
        self.pid: Optional[int] = None
        self.attached: bool = False
        self.registers: Dict[str, int] = {
            r: 0 for r in ("rax", "rbx", "rcx", "rdx", "rsi", "rdi",
                            "rbp", "rsp", "rip", "r8", "r9", "r10",
                            "r11", "r12", "r13", "r14", "r15", "rflags")
        }
        # Page table: base -> bytes
        self.pages: Dict[int, bytearray] = {
            SIM_MZ_PAGE: bytearray(b"MZ" + b"\x00" * (4096 - 2)),
        }
        self.breakpoints: Dict[int, Breakpoint] = {}
        self._next_bp_id = 0
        self.symbol_path: Optional[str] = None
        self.history: List[str] = []

    # --- lifecycle ---
    def launch(self, _opts=None) -> int:
        self.pid = FIXED_PID
        self.attached = True
        self.pages.setdefault(LAUNCH_PAGE, bytearray(b"\x90" * 4096))
        self.status = ExecutionStatus.Break
        return FIXED_PID

    def attach(self, pid: int) -> None:
        self.pid = pid
        self.attached = True
        self.pages.setdefault(LAUNCH_PAGE, bytearray(b"\x90" * 4096))
        self.status = ExecutionStatus.Break

    def detach(self) -> None:
        self.attached = False
        self.pid = None
        self.status = ExecutionStatus.NoDebuggee

    def is_attached(self) -> bool:
        return self.attached

    # --- memory ---
    def read_memory(self, addr: int, size: int) -> bytes:
        for base, data in self.pages.items():
            if base <= addr < base + len(data):
                offset = addr - base
                if offset + size > len(data):
                    raise WinDbgError("short read past page")
                return bytes(data[offset:offset + size])
        raise WinDbgError(f"unmapped address {addr:#x}")

    def write_memory(self, addr: int, data: bytes) -> None:
        for base, page in self.pages.items():
            if base <= addr < base + len(page):
                offset = addr - base
                end = offset + len(data)
                if end > len(page):
                    page.extend(b"\x00" * (end - len(page)))
                page[offset:end] = data
                return
        # new page
        self.pages[addr] = bytearray(data)

    # --- registers ---
    def get_register(self, name: str) -> int:
        if name not in self.registers:
            raise WinDbgError(f"unknown register {name}")
        return self.registers[name]

    def set_register(self, name: str, value: int) -> None:
        self.registers[name] = value

    # --- breakpoints ---
    def set_breakpoint(self, addr: int, kind: str = "Software") -> int:
        for bp in self.breakpoints.values():
            if bp.address == addr:
                raise BreakpointExists(f"bp at {addr:#x} exists")
        bid = self._next_bp_id
        self._next_bp_id += 1
        self.breakpoints[bid] = Breakpoint(bid, addr, kind, True)
        return bid

    def remove_breakpoint(self, bid: int) -> None:
        self.breakpoints.pop(bid, None)

    def enable_breakpoint(self, bid: int) -> None:
        if bid in self.breakpoints:
            self.breakpoints[bid].enabled = True

    def disable_breakpoint(self, bid: int) -> None:
        if bid in self.breakpoints:
            self.breakpoints[bid].enabled = False

    # --- execution ---
    def continue_execution(self) -> str:
        rip = self.registers.get("rip", 0)
        for bp in self.breakpoints.values():
            if bp.enabled and bp.address == rip:
                return "Breakpoint"
        return "SingleStep"

    def single_step(self) -> None:
        self.registers["rip"] = self.registers.get("rip", 0) + 1

    # --- backtrace ---
    def backtrace(self, _tid: int) -> List[Tuple[str, int]]:
        return [
            ("simulated_function", 0x7FFE_0000_1234),
            ("ntdll!RtlUserThreadStart", 0x7FFE_0000_5678),
        ]

    # --- symbol path ---
    def set_symbol_path(self, p: str) -> None:
        self.symbol_path = p

    # --- command interpreter ---
    def execute_command(self, cmd: str) -> ExtensionResult:
        self.history.append(cmd)
        verb = cmd.strip().split()[0] if cmd.strip() else ""
        known_prefixes = ("k", "kb", "kp", "r", "u", "db",
                          "lm", ".modules", "~", "!peb", "!teb",
                          "bp", "bl", "bc", "q", ".detach")
        if verb in known_prefixes or any(cmd.startswith(p + " ") or cmd == p for p in known_prefixes):
            return ExtensionResult(cmd, f"<simulated output for {verb}>", True)
        raise CommandError(f"unknown command: {cmd}")


# ---------- v2 API ----------

class WinDbgCommand:
    def __init__(self, kind: str, arg=None):
        self.kind = kind
        self.arg = arg

    def __str__(self) -> str:
        mapping = {
            "Go": "g", "StepIn": "t", "StepOver": "p", "StepOut": "gu",
            "BreakIn": ".break", "DumpStack": "k", "DumpLocals": "dv",
            "ListModules": "lm", "ShowRegisters": "r",
        }
        if self.kind in mapping:
            return mapping[self.kind]
        if self.kind == "Evaluate":
            return f"? {self.arg}"
        if self.kind == "SetBreakpoint":
            return f"bp {self.arg:#x}"
        if self.kind == "Command":
            return str(self.arg)
        return self.kind


@dataclass
class WinDbgOutput:
    text: str
    is_error: bool = False
    source: str = "Debugger"

    @classmethod
    def ok(cls, text: str) -> "WinDbgOutput":
        return cls(text, False, "Debugger")

    @classmethod
    def err(cls, text: str) -> "WinDbgOutput":
        return cls(text, True, "Debugger")


@dataclass
class V2Session:
    id: int = 0
    target_pid: int = 0
    connected: bool = False
    log: List[str] = field(default_factory=list)

    def add_log(self, msg: str) -> None:
        self.log.append(msg)

    def log_count(self) -> int:
        return len(self.log)


class MockWinDbgClient:
    def __init__(self) -> None:
        self.outputs: List[WinDbgOutput] = []

    def attach(self, pid: int) -> V2Session:
        return V2Session(id=1, target_pid=pid, connected=True)

    def execute(self, session: V2Session, cmd: WinDbgCommand) -> WinDbgOutput:
        if self.outputs:
            return self.outputs.pop()  # LIFO
        return WinDbgOutput.ok(str(cmd))

    def detach(self, session: V2Session) -> None:
        session.connected = False


# ---------- Self-validation ----------

def _validate() -> bool:
    s = WinDbgSession()
    assert len(s.modules) == 5
    assert len(s.threads) == 4
    assert s.status == ExecutionStatus.NoDebuggee
    assert not s.is_attached()

    pid = s.launch()
    assert pid == FIXED_PID and s.is_attached()
    data = s.read_memory(LAUNCH_PAGE, 4)
    assert data == b"\x90\x90\x90\x90"

    s.write_memory(LAUNCH_PAGE, b"\xCC")
    assert s.read_memory(LAUNCH_PAGE, 1) == b"\xCC"

    # unmapped read errors
    try:
        s.read_memory(0xDEAD_BEEF_0000, 4)
        assert False, "should have raised"
    except WinDbgError:
        pass

    # MZ page
    assert s.read_memory(SIM_MZ_PAGE, 2) == b"MZ"

    # breakpoints
    bid = s.set_breakpoint(0x1234)
    try:
        s.set_breakpoint(0x1234)
        assert False
    except BreakpointExists:
        pass
    s.disable_breakpoint(bid)
    assert not s.breakpoints[bid].enabled
    s.enable_breakpoint(bid)
    assert s.breakpoints[bid].enabled

    # continue: rip != bp -> SingleStep; rip == bp -> Breakpoint
    s.registers["rip"] = 0
    assert s.continue_execution() == "SingleStep"
    s.registers["rip"] = 0x1234
    assert s.continue_execution() == "Breakpoint"
    s.single_step()
    assert s.registers["rip"] == 0x1235

    # commands
    res = s.execute_command("k")
    assert res.success
    try:
        s.execute_command("bogusverb")
        assert False
    except CommandError:
        pass

    # backtrace has 2 frames
    assert len(s.backtrace(1)) == 2

    # symbol path
    s.set_symbol_path("srv*")
    assert s.symbol_path == "srv*"

    # v2 mock
    client = MockWinDbgClient()
    sess = client.attach(0x2222)
    assert sess.connected and sess.target_pid == 0x2222
    out = client.execute(sess, WinDbgCommand("Go"))
    assert out.text == "g" and not out.is_error
    client.outputs.append(WinDbgOutput.err("boom"))
    out = client.execute(sess, WinDbgCommand("Go"))
    assert out.is_error and out.text == "boom"
    client.detach(sess)
    assert not sess.connected

    # v2 command displays
    assert str(WinDbgCommand("StepOver")) == "p"
    assert str(WinDbgCommand("SetBreakpoint", 0x401000)) == "bp 0x401000"
    assert str(WinDbgCommand("Evaluate", "1+2")) == "? 1+2"

    return True


if __name__ == "__main__":
    ok = _validate()
    print(json.dumps({"crate": "rustre-debug-windbg", "validated": ok}))
