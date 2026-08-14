#!/usr/bin/env python3
"""Independent Python validator for rustre-debug-frida.

Reimplements the contract described in
validation/reports/rustre-debug-frida.md using only the Python stdlib.
No Rust crate import, no MCP calls.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any


# ---------------------------------------------------------------------------
# Error / state types
# ---------------------------------------------------------------------------
class FridaError(Exception):
    pass


class ScriptError(FridaError):
    pass


class AgentNotInjected(FridaError):
    pass


class ProcessNotFound(FridaError):
    pass


class RpcFailed(FridaError):
    pass


class DebugError(FridaError):
    pass


class NotAttached(DebugError):
    pass


class BreakpointExists(DebugError):
    pass


class FridaSessionState(Enum):
    Detached = "Detached"
    Attaching = "Attaching"
    Attached = "Attached"
    Suspended = "Suspended"
    Resuming = "Resuming"


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------
@dataclass
class FridaHook:
    address: int
    script: str
    hook_id: int


@dataclass
class InterceptorRecord:
    hook_id: int
    address: int
    thread_id: int
    args: list[int]
    return_value: int | None
    timestamp: int


@dataclass
class MemoryPage:
    base: int
    data: bytes


# ---------------------------------------------------------------------------
# Underlying DebugSession (minimal)
# ---------------------------------------------------------------------------
@dataclass
class DebugSession:
    attached_pid: int | None = None
    breakpoints: dict[int, bool] = field(default_factory=dict)  # addr -> enabled
    registers: dict[str, int] = field(default_factory=lambda: {
        "rip": 0x401000, "rsp": 0x7fff0000, "rbp": 0x7fff0100,
        "rax": 0, "rbx": 0, "rcx": 0, "rdx": 0,
    })


# ---------------------------------------------------------------------------
# FridaDebugSession
# ---------------------------------------------------------------------------
class FridaDebugSession:
    SUPPORTED_ARCHS = ("x86", "x86_64", "arm", "arm64", "aarch64", "mips")

    def __init__(self) -> None:
        self._state = FridaSessionState.Detached
        self._hooks: dict[int, FridaHook] = {}
        self._records: list[InterceptorRecord] = []
        self._next_hook_id = 1
        self._next_ts = 1
        self._debug = DebugSession()
        # Simulated memory pages: NOP sled at 0x1000, 4KB page at 0x401000.
        self._pages: list[MemoryPage] = [
            MemoryPage(0x1000, b"\x90" * 0x1000),
            MemoryPage(0x401000, b"\x00" * 0x1000),
        ]

    # --- session management ---
    def name(self) -> str:
        return "frida"

    def supported_architectures(self) -> tuple[str, ...]:
        return self.SUPPORTED_ARCHS

    def state(self) -> FridaSessionState:
        return self._state

    def is_attached(self) -> bool:
        return self._state == FridaSessionState.Attached

    def target_pid(self) -> int | None:
        return self._debug.attached_pid

    def launch(self, _opts: Any) -> None:
        raise FridaError("Unsupported: frida requires attach to running process")

    def attach(self, pid: int) -> None:
        if pid <= 0:
            raise ProcessNotFound(f"invalid pid {pid}")
        self._state = FridaSessionState.Attached
        self._debug.attached_pid = pid

    def detach(self) -> None:
        self._state = FridaSessionState.Detached
        self._debug.attached_pid = None

    def kill(self) -> None:
        self.detach()

    # --- hooks ---
    def install_hook(self, address: int, script: str) -> int:
        if self._state != FridaSessionState.Attached:
            raise NotAttached("install_hook requires Attached state")
        hid = self._next_hook_id
        self._next_hook_id += 1
        self._hooks[hid] = FridaHook(address=address, script=script, hook_id=hid)
        return hid

    def remove_hook(self, hook_id: int) -> None:
        if hook_id not in self._hooks:
            raise FridaError(f"unknown hook_id {hook_id}")
        del self._hooks[hook_id]

    def hooks(self) -> list[FridaHook]:
        return list(self._hooks.values())

    def intercept_records(self) -> list[InterceptorRecord]:
        return list(self._records)

    def simulate_hook_hit(self, hook_id: int, args: list[int],
                          return_value: int | None) -> None:
        if self._state != FridaSessionState.Attached:
            return  # no-op
        hook = self._hooks.get(hook_id)
        if hook is None:
            return
        rec = InterceptorRecord(
            hook_id=hook_id, address=hook.address, thread_id=1,
            args=list(args), return_value=return_value, timestamp=self._next_ts,
        )
        self._next_ts += 1
        self._records.append(rec)

    # --- scripts / memory ---
    def execute_script(self, script: str) -> dict[str, Any]:
        if not script.strip():
            raise ScriptError("empty script")
        return {"ok": True, "len": len(script)}

    def scan_memory_pattern(self, pattern: bytes) -> list[int]:
        if not pattern:
            return []
        hits: list[int] = []
        for page in self._pages:
            start = 0
            while True:
                idx = page.data.find(pattern, start)
                if idx < 0:
                    break
                hits.append(page.base + idx)
                start = idx + 1
        return hits

    # --- memory / registers ---
    def read_memory(self, addr: int, size: int) -> bytes:
        for page in self._pages:
            if page.base <= addr < page.base + len(page.data):
                off = addr - page.base
                return page.data[off:off + size]
        raise DebugError(f"unmapped address 0x{addr:x}")

    def write_memory(self, addr: int, data: bytes) -> None:
        for i, page in enumerate(self._pages):
            if page.base <= addr < page.base + len(page.data):
                off = addr - page.base
                buf = bytearray(page.data)
                buf[off:off + len(data)] = data
                self._pages[i] = MemoryPage(page.base, bytes(buf))
                return
        raise DebugError(f"unmapped address 0x{addr:x}")

    def memory_maps(self) -> list[dict[str, int]]:
        return [{"base": p.base, "size": len(p.data)} for p in self._pages]

    def get_registers(self) -> dict[str, int]:
        return dict(self._debug.registers)

    def get_register(self, name: str) -> int:
        return self._debug.registers[name]

    def set_register(self, name: str, value: int) -> None:
        self._debug.registers[name] = value

    def single_step(self, _tid: int = 0) -> None:
        self._debug.registers["rip"] += 1

    # --- breakpoints ---
    def set_breakpoint(self, addr: int) -> None:
        if addr in self._debug.breakpoints:
            raise BreakpointExists(f"breakpoint already at 0x{addr:x}")
        self._debug.breakpoints[addr] = True

    def remove_breakpoint(self, addr: int) -> None:
        self._debug.breakpoints.pop(addr, None)

    def enable_breakpoint(self, addr: int) -> None:
        if addr in self._debug.breakpoints:
            self._debug.breakpoints[addr] = True

    def disable_breakpoint(self, addr: int) -> None:
        if addr in self._debug.breakpoints:
            self._debug.breakpoints[addr] = False

    def breakpoints(self) -> dict[int, bool]:
        return dict(self._debug.breakpoints)

    def backtrace(self, _tid: int = 0) -> list[dict[str, int]]:
        r = self._debug.registers
        return [{"rip": r["rip"], "rsp": r["rsp"], "rbp": r["rbp"]}]


# ---------------------------------------------------------------------------
# v2 API
# ---------------------------------------------------------------------------
@dataclass
class FridaTarget:
    pid: int | None = None
    name: str | None = None

    @classmethod
    def local_pid(cls, pid: int) -> "FridaTarget":
        return cls(pid=pid)

    @classmethod
    def local_name(cls, name: str) -> "FridaTarget":
        return cls(name=name)


@dataclass
class StalkerEvent:
    kind: str
    address: int


class FridaSession:
    def __init__(self, sid: str, target: FridaTarget) -> None:
        self.id = sid
        self.target = target
        self._attached = True
        self._scripts: list[str] = []

    def is_attached(self) -> bool:
        return self._attached

    def script_count(self) -> int:
        return len(self._scripts)


@dataclass
class InterceptorRule:
    address: int
    on_enter: str = ""
    on_leave: str = ""


class FridaManager:
    def __init__(self) -> None:
        self._sessions: dict[str, FridaSession] = {}
        self._rules: list[InterceptorRule] = []
        self._next_id = 1

    def attach(self, target: FridaTarget) -> FridaSession:
        sid = f"sess-{self._next_id}"
        self._next_id += 1
        sess = FridaSession(sid, target)
        self._sessions[sid] = sess
        return sess

    def detach(self, sid: str) -> None:
        sess = self._sessions.pop(sid, None)
        if sess is not None:
            sess._attached = False

    def add_interceptor(self, rule: InterceptorRule) -> None:
        self._rules.append(rule)

    def interceptor_count(self) -> int:
        return len(self._rules)

    def session_count(self) -> int:
        return len(self._sessions)

    def mock_stalker_events(self, count: int) -> list[StalkerEvent]:
        kinds = ("block", "call", "return", "exec")
        return [StalkerEvent(kinds[i % 4], 0x401000 + i * 4) for i in range(count)]


# ---------------------------------------------------------------------------
# Self-test driving the surface described in the report
# ---------------------------------------------------------------------------
def _run_self_tests() -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []

    def record(name: str, ok: bool, detail: str = "") -> None:
        results.append({"name": name, "ok": ok, "detail": detail})

    s = FridaDebugSession()
    record("name", s.name() == "frida")
    record("supported_archs", "x86_64" in s.supported_architectures()
           and "arm64" in s.supported_architectures())
    record("initial_state_detached", s.state() == FridaSessionState.Detached)

    # install_hook requires Attached
    try:
        s.install_hook(0x401000, "{}")
        record("install_hook_requires_attached", False, "no error raised")
    except NotAttached:
        record("install_hook_requires_attached", True)

    s.attach(1234)
    record("attach_sets_pid", s.target_pid() == 1234 and s.is_attached())

    hid = s.install_hook(0x401000, "Interceptor.attach")
    record("install_hook_returns_id", hid == 1 and len(s.hooks()) == 1)

    # simulate_hook_hit records
    s.simulate_hook_hit(hid, [0xdead, 0xbeef], 0x42)
    recs = s.intercept_records()
    record("intercept_records", len(recs) == 1 and recs[0].return_value == 0x42)

    # memory scan finds NOP sled
    hits = s.scan_memory_pattern(b"\x90\x90\x90")
    record("scan_finds_nop_sled", len(hits) > 0 and hits[0] == 0x1000)

    # write + read roundtrip in 0x401000 page
    s.write_memory(0x401000, b"\xde\xad\xbe\xef")
    record("memory_roundtrip", s.read_memory(0x401000, 4) == b"\xde\xad\xbe\xef")

    # breakpoint duplicate error
    s.set_breakpoint(0x401000)
    try:
        s.set_breakpoint(0x401000)
        record("breakpoint_dup_error", False, "no error")
    except BreakpointExists:
        record("breakpoint_dup_error", True)

    # single_step increments rip
    rip0 = s.get_register("rip")
    s.single_step(0)
    record("single_step_rip+1", s.get_register("rip") == rip0 + 1)

    # backtrace single frame
    bt = s.backtrace(0)
    record("backtrace_single_frame", len(bt) == 1)

    # execute_script empty -> error
    try:
        s.execute_script("   ")
        record("execute_script_empty_error", False)
    except ScriptError:
        record("execute_script_empty_error", True)

    # launch is unsupported
    try:
        s.launch(None)
        record("launch_unsupported", False)
    except FridaError:
        record("launch_unsupported", True)

    # remove_hook
    s.remove_hook(hid)
    record("remove_hook", len(s.hooks()) == 0)

    # detach
    s.detach()
    record("detach_clears", not s.is_attached() and s.target_pid() is None)

    # v2 API
    mgr = FridaManager()
    sess = mgr.attach(FridaTarget.local_pid(4321))
    record("v2_attach", sess.is_attached() and mgr.session_count() == 1)
    mgr.add_interceptor(InterceptorRule(address=0x401000))
    record("v2_interceptor_count", mgr.interceptor_count() == 1)
    events = mgr.mock_stalker_events(5)
    record("v2_stalker_events", len(events) == 5 and events[0].kind == "block")
    mgr.detach(sess.id)
    record("v2_detach", mgr.session_count() == 0)

    return results


def main() -> dict[str, Any]:
    tests = _run_self_tests()
    functions = [
        # FridaDebugSession surface
        "FridaDebugSession.new", "FridaDebugSession.attach",
        "FridaDebugSession.detach", "FridaDebugSession.kill",
        "FridaDebugSession.is_attached", "FridaDebugSession.target_pid",
        "FridaDebugSession.state", "FridaDebugSession.name",
        "FridaDebugSession.supported_architectures",
        "FridaDebugSession.install_hook", "FridaDebugSession.remove_hook",
        "FridaDebugSession.hooks", "FridaDebugSession.intercept_records",
        "FridaDebugSession.simulate_hook_hit",
        "FridaDebugSession.execute_script",
        "FridaDebugSession.scan_memory_pattern",
        "FridaDebugSession.read_memory", "FridaDebugSession.write_memory",
        "FridaDebugSession.memory_maps",
        "FridaDebugSession.get_registers", "FridaDebugSession.get_register",
        "FridaDebugSession.set_register", "FridaDebugSession.single_step",
        "FridaDebugSession.set_breakpoint",
        "FridaDebugSession.remove_breakpoint",
        "FridaDebugSession.enable_breakpoint",
        "FridaDebugSession.disable_breakpoint",
        "FridaDebugSession.breakpoints", "FridaDebugSession.backtrace",
        "FridaDebugSession.launch",
        # v2 API
        "FridaTarget.local_pid", "FridaTarget.local_name",
        "FridaSession.new", "FridaSession.is_attached",
        "FridaSession.script_count",
        "FridaManager.new", "FridaManager.attach", "FridaManager.detach",
        "FridaManager.add_interceptor", "FridaManager.interceptor_count",
        "FridaManager.session_count", "FridaManager.mock_stalker_events",
    ]
    out = {
        "crate": "rustre-debug-frida",
        "saved": True,
        "functions": functions,
        "tests": tests,
        "passed": sum(1 for t in tests if t["ok"]),
        "total": len(tests),
    }
    # Persist a result sidecar like other validators do.
    sidecar = Path(__file__).with_suffix(".result.json")
    try:
        sidecar.write_text(json.dumps(out, indent=2), encoding="utf-8")
    except OSError:
        out["saved"] = False
    return out


if __name__ == "__main__":
    print(json.dumps(main(), indent=2))
