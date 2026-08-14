"""Independent validator for rustre-ttd-replay based on the analysis report.

Simulates the deterministic TTD replay engine described in
validation/reports/rustre-ttd-replay.md using only stdlib.
"""
from __future__ import annotations

import io
import json
import struct
from dataclasses import dataclass, field
from enum import Enum
from typing import Callable, Dict, List, Optional, Tuple


# ---------- Constants ----------

PAGE_SIZE = 4096
RECORDING_MAGIC = b"RSTRETTD"
RECORDING_VERSION = 1
MAX_META = 64 * 1024 * 1024


# ---------- Errors / Enums ----------

class ReplayError(Exception):
    pass


class InvalidTrace(ReplayError):
    pass


class PositionNotFound(ReplayError):
    pass


class StateRestoreError(ReplayError):
    pass


class WatchpointKind(Enum):
    Read = "Read"
    Write = "Write"
    ReadWrite = "ReadWrite"


class ReplayStopReason:
    def __init__(self, kind: str, **kw):
        self.kind = kind
        self.data = kw

    def __str__(self) -> str:
        return f"{self.kind}({self.data})"


class BreakpointCondition:
    def __init__(self, kind: str, **kw):
        self.kind = kind
        self.data = kw

    @classmethod
    def always(cls):
        return cls("Always")

    @classmethod
    def register_equals(cls, reg: str, value: int):
        return cls("RegisterEquals", reg=reg, value=value)

    @classmethod
    def memory_equals(cls, addr: int, value: int):
        return cls("MemoryEquals", addr=addr, value=value)

    @classmethod
    def hit_count_multiple(cls, n: int):
        return cls("HitCountMultiple", n=n)


# ---------- Trace position ----------

@dataclass(frozen=True, order=True)
class TracePosition:
    sequence: int
    sub: int = 0


# ---------- Memory ----------

@dataclass
class MemDiff:
    address: int
    before: bytes
    after: bytes

    def __str__(self):
        return f"diff@{self.address:#x}: {self.before.hex()} -> {self.after.hex()}"


@dataclass
class MemPage:
    base: int
    data: bytearray
    dirty: bool = False

    @classmethod
    def new(cls, base: int) -> "MemPage":
        return cls(base=base, data=bytearray(PAGE_SIZE), dirty=False)


class MemoryState:
    def __init__(self):
        self.pages: Dict[int, MemPage] = {}

    def apply_write(self, addr: int, data: bytes) -> None:
        i = 0
        while i < len(data):
            page_base = (addr + i) & ~(PAGE_SIZE - 1)
            off = (addr + i) - page_base
            chunk = min(PAGE_SIZE - off, len(data) - i)
            page = self.pages.get(page_base) or MemPage.new(page_base)
            page.data[off:off + chunk] = data[i:i + chunk]
            page.dirty = True
            self.pages[page_base] = page
            i += chunk

    def read(self, addr: int, length: int) -> Optional[bytes]:
        out = bytearray()
        i = 0
        while i < length:
            page_base = (addr + i) & ~(PAGE_SIZE - 1)
            page = self.pages.get(page_base)
            if page is None:
                return None
            off = (addr + i) - page_base
            chunk = min(PAGE_SIZE - off, length - i)
            out.extend(page.data[off:off + chunk])
            i += chunk
        return bytes(out)

    def diff(self, other: "MemoryState") -> List[MemDiff]:
        diffs: List[MemDiff] = []
        keys = set(self.pages.keys()) | set(other.pages.keys())
        for base in sorted(keys):
            a = self.pages.get(base)
            b = other.pages.get(base)
            ad = bytes(a.data) if a else b"\x00" * PAGE_SIZE
            bd = bytes(b.data) if b else b"\x00" * PAGE_SIZE
            if ad != bd:
                diffs.append(MemDiff(base, ad, bd))
        return diffs

    def page_count(self) -> int:
        return len(self.pages)


# ---------- Watchpoints / Breakpoints ----------

@dataclass
class Watchpoint:
    id: int
    address: int
    size: int
    kind: WatchpointKind
    enabled: bool = True

    def overlaps(self, addr: int, length: int) -> bool:
        return not (addr + length <= self.address or addr >= self.address + self.size)


@dataclass
class ReplayBreakpoint:
    id: int
    address: int
    condition: BreakpointCondition = field(default_factory=BreakpointCondition.always)
    enabled: bool = True
    hit_count: int = 0

    def with_condition(self, c: BreakpointCondition) -> "ReplayBreakpoint":
        self.condition = c
        return self

    def fires(self, rip: int, registers: Dict[str, int], mem: MemoryState) -> bool:
        if not self.enabled or rip != self.address:
            return False
        c = self.condition
        if c.kind == "Always":
            return True
        if c.kind == "RegisterEquals":
            return registers.get(c.data["reg"], 0) == c.data["value"]
        if c.kind == "MemoryEquals":
            r = mem.read(c.data["addr"], 8)
            if r is None:
                return False
            return int.from_bytes(r, "little") == c.data["value"]
        if c.kind == "HitCountMultiple":
            return c.data["n"] != 0 and (self.hit_count % c.data["n"]) == 0
        return False


# ---------- Snapshots ----------

@dataclass
class Snapshot:
    position: TracePosition
    memory: MemoryState
    registers: Dict[int, Dict[str, int]]


class SnapshotCache:
    def __init__(self, interval: int = 100):
        self.interval = interval
        self.snapshots: Dict[TracePosition, Snapshot] = {}

    def insert(self, s: Snapshot) -> None:
        self.snapshots[s.position] = s

    def nearest_before(self, pos: TracePosition) -> Optional[Snapshot]:
        candidates = [p for p in self.snapshots if p <= pos]
        if not candidates:
            return None
        return self.snapshots[max(candidates)]

    def snapshot_count(self) -> int:
        return len(self.snapshots)

    def clear(self) -> None:
        self.snapshots.clear()

    def contains(self, pos: TracePosition) -> bool:
        return pos in self.snapshots


# ---------- Trace events (simplified) ----------

@dataclass
class TraceEvent:
    position: TracePosition
    kind: str  # "MemWrite", "MemRead", "Call", "Step"
    thread_id: int = 0
    address: int = 0
    data: bytes = b""
    target: int = 0


@dataclass
class TraceMetadata:
    pid: int = 0
    name: str = ""


@dataclass
class TtdTrace:
    metadata: TraceMetadata
    events: List[TraceEvent]


# ---------- Recording file ----------

class TtdRecordingFile:
    def __init__(self, metadata: TraceMetadata, events: Optional[List[TraceEvent]] = None):
        self.metadata = metadata
        self.events = events or []

    @classmethod
    def from_trace(cls, t: TtdTrace) -> "TtdRecordingFile":
        return cls(t.metadata, list(t.events))

    def write_to(self, w: io.BufferedWriter) -> None:
        w.write(RECORDING_MAGIC)
        w.write(struct.pack("<I", RECORDING_VERSION))
        meta_json = json.dumps({"pid": self.metadata.pid, "name": self.metadata.name}).encode()
        w.write(struct.pack("<I", len(meta_json)))
        w.write(meta_json)
        w.write(struct.pack("<Q", len(self.events)))
        for e in self.events:
            ej = json.dumps({
                "seq": e.position.sequence, "sub": e.position.sub,
                "kind": e.kind, "tid": e.thread_id,
                "addr": e.address, "data": e.data.hex(), "target": e.target,
            }).encode()
            w.write(struct.pack("<I", len(ej)))
            w.write(ej)

    @classmethod
    def read_from(cls, r: io.BufferedReader) -> "TtdRecordingFile":
        magic = r.read(8)
        if magic != RECORDING_MAGIC:
            raise InvalidTrace(f"bad magic: {magic!r}")
        (ver,) = struct.unpack("<I", r.read(4))
        if ver != RECORDING_VERSION:
            raise InvalidTrace(f"bad version: {ver}")
        (mlen,) = struct.unpack("<I", r.read(4))
        if mlen > MAX_META:
            raise InvalidTrace("meta too large")
        meta = json.loads(r.read(mlen))
        (ecount,) = struct.unpack("<Q", r.read(8))
        events: List[TraceEvent] = []
        for _ in range(ecount):
            (el,) = struct.unpack("<I", r.read(4))
            ev = json.loads(r.read(el))
            events.append(TraceEvent(
                position=TracePosition(ev["seq"], ev["sub"]),
                kind=ev["kind"], thread_id=ev["tid"],
                address=ev["addr"], data=bytes.fromhex(ev["data"]),
                target=ev["target"],
            ))
        return cls(TraceMetadata(pid=meta["pid"], name=meta["name"]), events)


# ---------- Replay engine ----------

class ReplayEngine:
    def __init__(self, trace: TtdTrace, snapshot_interval: int = 100):
        self.trace = trace
        self.position = TracePosition(0, 0)
        self.index = 0  # event index pointer
        self.memory = MemoryState()
        self.registers: Dict[int, Dict[str, int]] = {}
        self.breakpoints: List[ReplayBreakpoint] = []
        self.watchpoints: List[Watchpoint] = []
        self._next_bp = 0
        self._next_wp = 0
        self.history: List[TracePosition] = []
        self.cache = SnapshotCache(snapshot_interval)

    @classmethod
    def with_snapshot_interval(cls, trace: TtdTrace, interval: int) -> "ReplayEngine":
        return cls(trace, interval)

    def current_position(self) -> TracePosition:
        return self.position

    # --- breakpoints ---
    def add_breakpoint(self, addr: int) -> int:
        bid = self._next_bp
        self._next_bp += 1
        self.breakpoints.append(ReplayBreakpoint(bid, addr))
        return bid

    def add_breakpoint_with_condition(self, addr: int, cond: BreakpointCondition) -> int:
        bid = self.add_breakpoint(addr)
        self.breakpoints[-1].condition = cond
        return bid

    def remove_breakpoint(self, bid: int) -> bool:
        before = len(self.breakpoints)
        self.breakpoints = [b for b in self.breakpoints if b.id != bid]
        return len(self.breakpoints) != before

    def enable_breakpoint(self, bid: int) -> bool:
        for b in self.breakpoints:
            if b.id == bid:
                b.enabled = True
                return True
        return False

    def disable_breakpoint(self, bid: int) -> bool:
        for b in self.breakpoints:
            if b.id == bid:
                b.enabled = False
                return True
        return False

    # --- watchpoints ---
    def add_watchpoint(self, addr: int, size: int, kind: WatchpointKind) -> int:
        wid = self._next_wp
        self._next_wp += 1
        self.watchpoints.append(Watchpoint(wid, addr, size, kind))
        return wid

    def remove_watchpoint(self, wid: int) -> bool:
        before = len(self.watchpoints)
        self.watchpoints = [w for w in self.watchpoints if w.id != wid]
        return len(self.watchpoints) != before

    # --- navigation ---
    def _apply_event(self, e: TraceEvent) -> Optional[ReplayStopReason]:
        if e.kind == "MemWrite":
            old = self.memory.read(e.address, len(e.data)) or b""
            self.memory.apply_write(e.address, e.data)
            for w in self.watchpoints:
                if w.enabled and w.kind in (WatchpointKind.Write, WatchpointKind.ReadWrite) \
                        and w.overlaps(e.address, len(e.data)):
                    return ReplayStopReason("WatchpointHit",
                                            wp_id=w.id, position=e.position,
                                            old_value=old, new_value=e.data)
        elif e.kind == "MemRead":
            for w in self.watchpoints:
                if w.enabled and w.kind in (WatchpointKind.Read, WatchpointKind.ReadWrite) \
                        and w.overlaps(e.address, max(1, len(e.data))):
                    return ReplayStopReason("WatchpointHit",
                                            wp_id=w.id, position=e.position,
                                            old_value=b"", new_value=e.data)
        return None

    def step_forward(self) -> ReplayStopReason:
        if self.index >= len(self.trace.events):
            return ReplayStopReason("End")
        e = self.trace.events[self.index]
        self.history.append(self.position)
        stop = self._apply_event(e)
        self.position = e.position
        self.index += 1
        if stop is not None:
            return stop
        return ReplayStopReason("StepComplete", position=self.position)

    def step_backward(self) -> ReplayStopReason:
        if self.index == 0:
            return ReplayStopReason("Start")
        self.index -= 1
        # rebuild from start
        self._rebuild_to(self.index)
        return ReplayStopReason("StepComplete", position=self.position)

    def _rebuild_to(self, target_index: int) -> None:
        self.memory = MemoryState()
        self.position = TracePosition(0, 0)
        for i in range(target_index):
            e = self.trace.events[i]
            if e.kind == "MemWrite":
                self.memory.apply_write(e.address, e.data)
            self.position = e.position

    def run_forward_to_position(self, pos: TracePosition) -> ReplayStopReason:
        while self.index < len(self.trace.events):
            if self.trace.events[self.index].position > pos:
                break
            r = self.step_forward()
            if r.kind == "WatchpointHit":
                return r
            if self.position == pos:
                return ReplayStopReason("StepComplete", position=self.position)
        if self.position != pos:
            raise PositionNotFound(str(pos))
        return ReplayStopReason("StepComplete", position=self.position)

    def go_to_start(self) -> ReplayStopReason:
        self.index = 0
        self.memory = MemoryState()
        self.position = TracePosition(0, 0)
        return ReplayStopReason("Start")

    def go_to_end(self) -> ReplayStopReason:
        while self.index < len(self.trace.events):
            self.step_forward()
        return ReplayStopReason("End")

    def run_to_next_event_of_kind(self, pred: Callable[[str], bool]) -> ReplayStopReason:
        while self.index < len(self.trace.events):
            e = self.trace.events[self.index]
            r = self.step_forward()
            if pred(e.kind):
                return ReplayStopReason("EventKindMatch", position=self.position)
            if r.kind == "WatchpointHit":
                return r
        return ReplayStopReason("End")

    # --- query ---
    def find_first_write_to(self, addr: int) -> Optional[TracePosition]:
        for e in self.trace.events:
            if e.kind == "MemWrite" and e.address <= addr < e.address + len(e.data):
                return e.position
        return None

    def find_last_write_to(self, addr: int) -> Optional[TracePosition]:
        last = None
        for e in self.trace.events:
            if e.kind == "MemWrite" and e.address <= addr < e.address + len(e.data):
                last = e.position
        return last

    def find_all_writes_to(self, addr: int) -> List[Tuple[TracePosition, bytes]]:
        out = []
        for e in self.trace.events:
            if e.kind == "MemWrite" and e.address <= addr < e.address + len(e.data):
                out.append((e.position, e.data))
        return out

    def find_all_calls_to(self, target: int) -> List[TracePosition]:
        return [e.position for e in self.trace.events if e.kind == "Call" and e.target == target]

    def build_snapshot_index(self) -> None:
        self.cache.clear()
        saved_index = self.index
        self.go_to_start()
        for i, e in enumerate(self.trace.events):
            self.step_forward()
            if (i + 1) % max(1, self.cache.interval) == 0:
                self.cache.insert(Snapshot(self.position, MemoryState(), {}))
        # restore
        self.go_to_start()
        for _ in range(saved_index):
            self.step_forward()


# ---------- Self validation ----------

def _validate() -> bool:
    # Memory
    m = MemoryState()
    m.apply_write(0x1000, b"\xde\xad\xbe\xef")
    assert m.read(0x1000, 4) == b"\xde\xad\xbe\xef"
    assert m.read(0xdead, 4) is None
    assert m.page_count() == 1

    m2 = MemoryState()
    m2.apply_write(0x1000, b"\x00\x00\x00\x00")
    diffs = m.diff(m2)
    assert len(diffs) == 1

    # cross-page write
    m.apply_write(PAGE_SIZE - 2, b"ABCD")
    assert m.read(PAGE_SIZE - 2, 4) == b"ABCD"
    assert m.page_count() == 2

    # Breakpoint / condition
    bp = ReplayBreakpoint(0, 0x400000)
    assert bp.fires(0x400000, {}, MemoryState())
    bp.condition = BreakpointCondition.register_equals("rax", 7)
    assert not bp.fires(0x400000, {"rax": 1}, MemoryState())
    assert bp.fires(0x400000, {"rax": 7}, MemoryState())
    bp.condition = BreakpointCondition.hit_count_multiple(3)
    bp.hit_count = 3
    assert bp.fires(0x400000, {}, MemoryState())
    bp.hit_count = 4
    assert not bp.fires(0x400000, {}, MemoryState())

    # Watchpoint overlap
    w = Watchpoint(0, 0x2000, 4, WatchpointKind.Write)
    assert w.overlaps(0x2002, 8)
    assert not w.overlaps(0x3000, 4)

    # SnapshotCache
    sc = SnapshotCache(interval=10)
    sc.insert(Snapshot(TracePosition(5), MemoryState(), {}))
    sc.insert(Snapshot(TracePosition(20), MemoryState(), {}))
    nb = sc.nearest_before(TracePosition(15))
    assert nb is not None and nb.position == TracePosition(5)
    assert sc.snapshot_count() == 2
    assert sc.contains(TracePosition(20))
    sc.clear()
    assert sc.snapshot_count() == 0

    # Engine + navigation
    events = [
        TraceEvent(TracePosition(1), "MemWrite", address=0x4000, data=b"\x01\x02"),
        TraceEvent(TracePosition(2), "MemWrite", address=0x4002, data=b"\x03\x04"),
        TraceEvent(TracePosition(3), "Call", target=0x500000),
        TraceEvent(TracePosition(4), "MemWrite", address=0x4000, data=b"\xff\xff"),
    ]
    trace = TtdTrace(TraceMetadata(pid=42, name="t"), events)
    eng = ReplayEngine(trace)
    r = eng.step_forward()
    assert r.kind == "StepComplete"
    assert eng.memory.read(0x4000, 2) == b"\x01\x02"
    eng.step_forward()
    assert eng.memory.read(0x4000, 4) == b"\x01\x02\x03\x04"

    # Watchpoint hit on next write
    wid = eng.add_watchpoint(0x4000, 2, WatchpointKind.Write)
    eng.step_forward()  # Call - no hit
    r = eng.step_forward()  # write to 0x4000
    assert r.kind == "WatchpointHit" and r.data["wp_id"] == wid

    # Step backward rebuilds state
    eng.step_backward()
    assert eng.memory.read(0x4000, 4) == b"\x01\x02\x03\x04"

    # go_to_start / end
    eng.go_to_start()
    assert eng.index == 0 and eng.memory.page_count() == 0
    eng.go_to_end()
    assert eng.index == len(events)

    # Query APIs
    eng2 = ReplayEngine(trace)
    assert eng2.find_first_write_to(0x4000) == TracePosition(1)
    assert eng2.find_last_write_to(0x4000) == TracePosition(4)
    assert len(eng2.find_all_writes_to(0x4000)) == 2
    assert eng2.find_all_calls_to(0x500000) == [TracePosition(3)]

    # Breakpoint CRUD
    bid = eng2.add_breakpoint(0x401000)
    assert eng2.disable_breakpoint(bid)
    assert eng2.enable_breakpoint(bid)
    assert eng2.remove_breakpoint(bid)
    assert not eng2.remove_breakpoint(bid)

    # run_to_next_event_of_kind
    eng3 = ReplayEngine(trace)
    r = eng3.run_to_next_event_of_kind(lambda k: k == "Call")
    assert r.kind == "EventKindMatch"

    # Snapshot index build
    eng4 = ReplayEngine.with_snapshot_interval(trace, 2)
    eng4.build_snapshot_index()
    assert eng4.cache.snapshot_count() >= 1

    # Recording file roundtrip
    rec = TtdRecordingFile.from_trace(trace)
    buf = io.BytesIO()
    rec.write_to(buf)
    buf.seek(0)
    rec2 = TtdRecordingFile.read_from(buf)
    assert rec2.metadata.pid == 42
    assert len(rec2.events) == 4
    assert rec2.events[0].address == 0x4000

    # Bad magic
    bad = io.BytesIO(b"NOTTTD!!" + b"\x00" * 32)
    try:
        TtdRecordingFile.read_from(bad)
        assert False, "should have raised"
    except InvalidTrace:
        pass

    # Bad version
    bad2 = io.BytesIO(RECORDING_MAGIC + struct.pack("<I", 99) + b"\x00" * 32)
    try:
        TtdRecordingFile.read_from(bad2)
        assert False
    except InvalidTrace:
        pass

    return True


if __name__ == "__main__":
    ok = _validate()
    print(json.dumps({"crate": "rustre-ttd-replay", "saved": ok}))
