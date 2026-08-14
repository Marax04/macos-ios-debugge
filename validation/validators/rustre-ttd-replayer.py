"""Independent validator for rustre-ttd-replayer crate.

Reimplements pure-logic primitives described in
validation/reports/rustre-ttd-replayer.md using only Python stdlib.
"""

import json
import os
from collections import defaultdict
from typing import Optional, List, Dict, Tuple


# ---------- Constants ----------
DEFAULT_SNAPSHOT_INTERVAL = 256
MAX_MEM_WRITES_PER_EVENT = 1024
REPLAY_PAGE_SIZE = 4096

TRACE_MAGIC = 0x0052_554E_0044_5454
SUPPORTED_VERSION_MAJOR = 2
HEADER_SIZE = 128
FRAME_SIZE = 32

KIND_SYSCALL_ENTRY = 1
KIND_SYSCALL_EXIT = 2
KIND_SIGNAL = 3
KIND_SNAPSHOT = 4
KIND_MODULE_LOAD = 5
KIND_END = 6


# ---------- MemWriteRecord ----------
class MemWriteRecord:
    def __init__(self, addr: int, data: bytes):
        self.addr = addr & 0xFFFFFFFFFFFFFFFF
        self.data = bytes(data)

    def size(self) -> int:
        return len(self.data)

    def end_addr(self) -> int:
        return self.addr + self.size()

    def overlaps(self, addr: int, size: int) -> bool:
        return not (addr + size <= self.addr or addr >= self.end_addr())

    def bytes_in_range(self, addr: int, size: int) -> bytes:
        if not self.overlaps(addr, size):
            return b""
        start = max(addr, self.addr)
        end = min(addr + size, self.end_addr())
        return self.data[start - self.addr:end - self.addr]

    def __str__(self):
        return f"write @0x{self.addr:x} ({self.size()} bytes)"


# ---------- TraceEvent ----------
class TraceEvent:
    def __init__(self, kind: str, **kw):
        self.kind = kind
        self.fields = kw

    def tick(self) -> int:
        return self.fields["tick"]

    def kind_name(self) -> str:
        return self.kind

    def has_mem_writes(self) -> bool:
        return self.kind == "SyscallExit" and bool(self.fields.get("mem_writes"))

    def mem_writes(self) -> List[MemWriteRecord]:
        return self.fields.get("mem_writes", [])

    def syscall_nr(self) -> Optional[int]:
        if self.kind == "SyscallEntry":
            return self.fields["nr"]
        return None

    def __str__(self):
        return f"{self.kind}@{self.tick()}"


def SyscallEntry(tick, nr, args):
    return TraceEvent("SyscallEntry", tick=tick, nr=nr, args=list(args))


def SyscallExit(tick, retval, mem_writes):
    return TraceEvent("SyscallExit", tick=tick, retval=retval, mem_writes=list(mem_writes))


def SignalDelivered(tick, signal, pc):
    return TraceEvent("SignalDelivered", tick=tick, signal=signal, pc=pc)


# ---------- TraceSnapshot ----------
class TraceSnapshot:
    def __init__(self, tick: int):
        self.tick = tick
        self.regs: Dict[str, int] = {}
        self.mem_pages: Dict[int, bytes] = {}

    def set_reg(self, name: str, value: int):
        self.regs[name] = value & 0xFFFFFFFFFFFFFFFF

    def get_reg(self, name: str) -> Optional[int]:
        return self.regs.get(name)

    def write_mem(self, addr: int, data: bytes):
        # Page-aligned storage
        page = addr & ~(REPLAY_PAGE_SIZE - 1)
        self.mem_pages[page] = bytes(data)

    def read_mem(self, addr: int, size: int) -> Optional[bytes]:
        page = addr & ~(REPLAY_PAGE_SIZE - 1)
        data = self.mem_pages.get(page)
        if data is None:
            return None
        off = addr - page
        if off + size > len(data):
            return None
        return data[off:off + size]

    def page_count(self) -> int:
        return len(self.mem_pages)

    def memory_footprint(self) -> int:
        return sum(len(p) for p in self.mem_pages.values())


# ---------- TtdTrace ----------
class TtdTrace:
    def __init__(self):
        self.events: List[TraceEvent] = []
        self.snapshots: List[TraceSnapshot] = []
        self.tick_index: List[int] = []

    @classmethod
    def from_parts(cls, events, snapshots):
        t = cls()
        t.events = list(events)
        t.snapshots = list(snapshots)
        t.rebuild_tick_index()
        return t

    def push_event(self, ev: TraceEvent):
        self.events.append(ev)
        self.tick_index.append(ev.tick())

    def push_snapshot(self, snap: TraceSnapshot):
        self.snapshots.append(snap)

    def rebuild_tick_index(self):
        self.tick_index = [e.tick() for e in self.events]

    def max_tick(self) -> Optional[int]:
        return max(self.tick_index) if self.tick_index else None

    def min_tick(self) -> Optional[int]:
        return min(self.tick_index) if self.tick_index else None

    def first_event_at_or_after(self, target: int) -> Optional[int]:
        for i, t in enumerate(self.tick_index):
            if t >= target:
                return i
        return None

    def last_event_at_or_before(self, target: int) -> Optional[int]:
        idx = None
        for i, t in enumerate(self.tick_index):
            if t <= target:
                idx = i
            else:
                break
        return idx

    def nearest_snapshot_before(self, target: int) -> Optional[TraceSnapshot]:
        best = None
        for s in self.snapshots:
            if s.tick <= target and (best is None or s.tick > best.tick):
                best = s
        return best

    def events_in_range(self, frm: int, to: int):
        return [e for e in self.events if frm <= e.tick() <= to]

    def event_counts(self) -> Dict[str, int]:
        out: Dict[str, int] = defaultdict(int)
        for e in self.events:
            out[e.kind_name()] += 1
        return dict(out)

    def all_writes_touching(self, addr: int, size: int) -> List[Tuple[int, MemWriteRecord]]:
        out = []
        for e in self.events:
            if e.has_mem_writes():
                for w in e.mem_writes():
                    if w.overlaps(addr, size):
                        out.append((e.tick(), w))
        return out

    def is_empty(self) -> bool:
        return not self.events

    def len(self) -> int:
        return len(self.events)


# ---------- ReplayState ----------
class ReplayState:
    def __init__(self):
        self.regs: Dict[str, int] = {}
        self.mem: Dict[int, int] = {}  # byte-addressed

    def load_snapshot(self, snap: TraceSnapshot):
        self.regs = dict(snap.regs)
        self.mem.clear()
        for page, data in snap.mem_pages.items():
            for i, b in enumerate(data):
                self.mem[page + i] = b

    def reg(self, name: str) -> int:
        return self.regs.get(name, 0)

    def set_reg(self, name: str, value: int):
        self.regs[name] = value & 0xFFFFFFFFFFFFFFFF

    def apply_write(self, w: MemWriteRecord):
        for i, b in enumerate(w.data):
            self.mem[w.addr + i] = b

    def read(self, addr: int, size: int) -> Optional[bytes]:
        out = bytearray()
        for i in range(size):
            b = self.mem.get(addr + i)
            if b is None:
                return None
            out.append(b)
        return bytes(out)

    def footprint(self) -> int:
        return len(self.mem)

    def program_counter(self) -> Optional[int]:
        for k in ("pc", "rip", "eip"):
            if k in self.regs:
                return self.regs[k]
        return None


# ---------- TtdReplayer ----------
class TtdReplayer:
    def __init__(self, trace: TtdTrace):
        self.trace = trace
        self.current_tick = 0
        self.state = ReplayState()

    def goto(self, target_tick: int) -> None:
        max_t = self.trace.max_tick() or 0
        if target_tick > max_t:
            raise ValueError(f"TickOutOfRange({target_tick},{max_t})")
        snap = self.trace.nearest_snapshot_before(target_tick)
        if snap is None:
            self.state = ReplayState()
        else:
            self.state.load_snapshot(snap)
        # apply events up to target
        for e in self.trace.events:
            if e.tick() > target_tick:
                break
            if snap and e.tick() <= snap.tick:
                continue
            if e.has_mem_writes():
                for w in e.mem_writes():
                    self.state.apply_write(w)
        self.current_tick = target_tick

    def step_forward(self) -> TraceEvent:
        idx = self.trace.first_event_at_or_after(self.current_tick + 1)
        if idx is None:
            raise ValueError("AtEnd")
        ev = self.trace.events[idx]
        if ev.has_mem_writes():
            for w in ev.mem_writes():
                self.state.apply_write(w)
        self.current_tick = ev.tick()
        return ev

    def step_backward(self) -> TraceEvent:
        if self.current_tick == 0:
            raise ValueError("AtStart")
        target = self.current_tick - 1
        self.goto(target)
        idx = self.trace.last_event_at_or_before(target)
        if idx is None:
            raise ValueError("AtStart")
        return self.trace.events[idx]

    def find_all_writes_to(self, addr: int, size: int) -> List[Tuple[int, bytes]]:
        return [(t, w.bytes_in_range(addr, size))
                for t, w in self.trace.all_writes_touching(addr, size)]

    def read_memory_at_tick(self, tick: int, addr: int, size: int) -> bytes:
        self.goto(tick)
        r = self.state.read(addr, size)
        if r is None:
            raise ValueError(f"AddressNotMapped({addr},{tick})")
        return r

    def find_last_write_before(self, addr: int, tick: int) -> Optional[Tuple[int, bytes]]:
        candidates = [(t, w) for t, w in self.trace.all_writes_touching(addr, 1) if t < tick]
        if not candidates:
            return None
        t, w = max(candidates, key=lambda x: x[0])
        return (t, w.bytes_in_range(addr, 1))

    def find_last_write_range_before(self, addr, size, tick) -> Optional[Tuple[int, bytes]]:
        candidates = [(t, w) for t, w in self.trace.all_writes_touching(addr, size) if t < tick]
        if not candidates:
            return None
        t, w = max(candidates, key=lambda x: x[0])
        return (t, w.bytes_in_range(addr, size))

    def pc(self) -> Optional[int]:
        return self.state.program_counter()

    def at_end(self) -> bool:
        m = self.trace.max_tick()
        return m is not None and self.current_tick >= m

    def at_start(self) -> bool:
        return self.current_tick == 0

    def reset(self):
        self.current_tick = 0
        self.state = ReplayState()

    def remaining_events(self) -> int:
        return sum(1 for t in self.trace.tick_index if t > self.current_tick)


# ---------- TtdQuery ----------
def parse_query(text: str) -> dict:
    parts = text.strip().split()
    if not parts:
        raise ValueError("QueryParse(empty)")
    cmd = parts[0]
    CAP = 256 * 1024 * 1024
    if cmd == "read_mem":
        tick = int(parts[1]); addr = int(parts[2], 16); size = int(parts[3])
        if size > CAP:
            raise ValueError("QueryParse(size cap)")
        return {"op": "ReadMem", "tick": tick, "addr": addr, "size": size}
    if cmd == "find_writes":
        addr = int(parts[1], 16); size = int(parts[2])
        if size > CAP:
            raise ValueError("QueryParse(size cap)")
        return {"op": "FindWrites", "addr": addr, "size": size}
    if cmd == "last_write":
        return {"op": "LastWrite", "addr": int(parts[1], 16), "tick": int(parts[2])}
    if cmd == "list_syscalls":
        nr = int(parts[1]) if len(parts) > 1 else None
        return {"op": "ListSyscalls", "nr": nr}
    if cmd == "list_signals":
        return {"op": "ListSignals"}
    if cmd == "read_reg":
        return {"op": "ReadReg", "tick": int(parts[1]), "reg": parts[2]}
    if cmd == "count_events":
        return {"op": "CountEvents", "kind": parts[1]}
    if cmd == "root_cause":
        return {"op": "RootCause", "crash_tick": int(parts[1]), "crash_addr": int(parts[2], 16)}
    if cmd == "max_tick":
        return {"op": "MaxTick"}
    if cmd == "min_tick":
        return {"op": "MinTick"}
    raise ValueError(f"QueryParse({cmd})")


# ---------- Root cause ----------
def find_root_cause(replayer: TtdReplayer, crash_tick: int, crash_addr: int) -> dict:
    chain = []
    lw = replayer.find_last_write_before(crash_addr, crash_tick)
    if lw:
        chain.append({"tick": lw[0], "description": "last write to crash_addr", "addr": crash_addr})
        # preceding syscall
        for e in reversed(replayer.trace.events):
            if e.tick() < lw[0] and e.kind == "SyscallEntry":
                chain.append({"tick": e.tick(), "description": f"syscall nr={e.syscall_nr()}"})
                break
        # preceding signal
        for e in reversed(replayer.trace.events):
            if e.tick() < lw[0] and e.kind == "SignalDelivered":
                chain.append({"tick": e.tick(), "description": f"signal {e.fields['signal']}"})
                break
    confidence = min(1.0, 0.25 * len(chain))
    return {
        "crash_tick": crash_tick,
        "crash_addr": crash_addr,
        "chain": chain,
        "summary": f"{len(chain)} causal steps",
        "confidence": confidence,
    }


# ---------- TraceStats ----------
def compute_stats(trace: TtdTrace) -> dict:
    syscall_freq: Dict[int, int] = defaultdict(int)
    entries = exits_ = signals = total_bytes = 0
    unique_addrs = set()
    for e in trace.events:
        if e.kind == "SyscallEntry":
            entries += 1
            syscall_freq[e.fields["nr"]] += 1
        elif e.kind == "SyscallExit":
            exits_ += 1
            for w in e.mem_writes():
                total_bytes += w.size()
                unique_addrs.add(w.addr)
        elif e.kind == "SignalDelivered":
            signals += 1
    return {
        "total_events": len(trace.events),
        "syscall_entries": entries,
        "syscall_exits": exits_,
        "signals": signals,
        "total_bytes_written": total_bytes,
        "unique_write_addrs": len(unique_addrs),
        "min_tick": trace.min_tick(),
        "max_tick": trace.max_tick(),
        "snapshot_count": len(trace.snapshots),
        "syscall_freq": dict(syscall_freq),
    }


# ---------- TraceBuilder ----------
class TraceBuilder:
    def __init__(self, snapshot_interval: int):
        self._interval = snapshot_interval
        self._tick = 0
        self.trace = TtdTrace()

    def syscall_entry(self, nr, args) -> int:
        t = self._tick
        self.trace.push_event(SyscallEntry(t, nr, args))
        self._tick += 1
        return t

    def syscall_exit(self, retval, mem_writes) -> int:
        t = self._tick
        self.trace.push_event(SyscallExit(t, retval, mem_writes))
        self._tick += 1
        return t

    def signal(self, signal, pc) -> int:
        t = self._tick
        self.trace.push_event(SignalDelivered(t, signal, pc))
        self._tick += 1
        return t

    def snapshot(self, regs, mem_pages):
        snap = TraceSnapshot(self._tick)
        snap.regs = dict(regs)
        snap.mem_pages = dict(mem_pages)
        self.trace.push_snapshot(snap)

    def build(self) -> TtdTrace:
        return self.trace

    def snapshot_interval(self) -> int:
        return self._interval

    def next_tick_is_snapshot_boundary(self) -> bool:
        return self._tick % self._interval == 0


# ---------- Validation functions ----------
def fn_constants():
    return {
        "DEFAULT_SNAPSHOT_INTERVAL": DEFAULT_SNAPSHOT_INTERVAL,
        "MAX_MEM_WRITES_PER_EVENT": MAX_MEM_WRITES_PER_EVENT,
        "REPLAY_PAGE_SIZE": REPLAY_PAGE_SIZE,
        "TRACE_MAGIC": TRACE_MAGIC,
        "TRACE_MAGIC_hex": f"0x{TRACE_MAGIC:016x}",
        "SUPPORTED_VERSION_MAJOR": SUPPORTED_VERSION_MAJOR,
        "HEADER_SIZE": HEADER_SIZE,
        "FRAME_SIZE": FRAME_SIZE,
        "kind_tags": {
            "SYSCALL_ENTRY": KIND_SYSCALL_ENTRY,
            "SYSCALL_EXIT": KIND_SYSCALL_EXIT,
            "SIGNAL": KIND_SIGNAL,
            "SNAPSHOT": KIND_SNAPSHOT,
            "MODULE_LOAD": KIND_MODULE_LOAD,
            "END": KIND_END,
        },
    }


def fn_mem_write_record():
    w = MemWriteRecord(0x1000, b"\x11\x22\x33\x44")
    return {
        "size": w.size(),
        "end_addr": w.end_addr(),
        "overlaps_in": w.overlaps(0x1002, 4),
        "overlaps_before": w.overlaps(0x0FF0, 4),
        "overlaps_after": w.overlaps(0x2000, 4),
        "slice_mid": w.bytes_in_range(0x1001, 2).hex(),
        "display": str(w),
    }


def fn_trace_event():
    e1 = SyscallEntry(10, 60, [1, 2, 3, 4, 5, 6])
    e2 = SyscallExit(11, 0, [MemWriteRecord(0x2000, b"\xaa\xbb")])
    e3 = SignalDelivered(12, 11, 0x4000)
    return {
        "entry": {"tick": e1.tick(), "kind": e1.kind_name(), "nr": e1.syscall_nr()},
        "exit_has_writes": e2.has_mem_writes(),
        "exit_n_writes": len(e2.mem_writes()),
        "signal_kind": e3.kind_name(),
    }


def fn_snapshot_and_state():
    s = TraceSnapshot(100)
    s.set_reg("rip", 0x401000)
    s.write_mem(0x1000, b"\x01\x02\x03\x04")
    st = ReplayState()
    st.load_snapshot(s)
    return {
        "snap_pages": s.page_count(),
        "snap_footprint": s.memory_footprint(),
        "state_pc": st.program_counter(),
        "state_read": st.read(0x1000, 4).hex(),
        "state_read_partial": st.read(0x1002, 2).hex(),
        "state_read_oob": st.read(0x9999, 1),
    }


def fn_trace_basic():
    b = TraceBuilder(DEFAULT_SNAPSHOT_INTERVAL)
    b.syscall_entry(60, [1, 0, 0, 0, 0, 0])
    b.syscall_exit(0, [MemWriteRecord(0x1000, b"AAAA")])
    b.syscall_entry(1, [2, 0, 0, 0, 0, 0])
    b.signal(11, 0x4000)
    t = b.build()
    return {
        "len": t.len(),
        "min": t.min_tick(),
        "max": t.max_tick(),
        "counts": t.event_counts(),
        "is_empty": t.is_empty(),
        "first_at_or_after_2": t.first_event_at_or_after(2),
        "last_at_or_before_2": t.last_event_at_or_before(2),
        "in_range_1_3": len(t.events_in_range(1, 3)),
        "writes_touch_0x1001": len(t.all_writes_touching(0x1001, 1)),
    }


def fn_replayer():
    b = TraceBuilder(DEFAULT_SNAPSHOT_INTERVAL)
    b.syscall_exit(0, [MemWriteRecord(0x2000, b"\x11\x22\x33\x44")])
    b.syscall_exit(0, [MemWriteRecord(0x2000, b"\xAA\xBB\xCC\xDD")])
    b.syscall_entry(60, [0, 0, 0, 0, 0, 0])
    t = b.build()
    r = TtdReplayer(t)
    r.goto(0)
    after0 = r.state.read(0x2000, 4)
    r.goto(1)
    after1 = r.state.read(0x2000, 4)
    last = r.find_last_write_before(0x2000, 2)
    all_w = r.find_all_writes_to(0x2000, 4)
    return {
        "after_tick0": after0.hex() if after0 else None,
        "after_tick1": after1.hex() if after1 else None,
        "remaining_from_0": (r.reset(), r.remaining_events())[1],
        "last_before_t2_tick": last[0] if last else None,
        "n_writes_to_addr": len(all_w),
        "at_start_after_reset": r.at_start(),
    }


def fn_query_parse():
    examples = [
        "read_mem 100 0x1000 16",
        "find_writes 0x2000 4",
        "last_write 0x3000 50",
        "list_syscalls",
        "list_syscalls 60",
        "list_signals",
        "read_reg 10 rip",
        "count_events SyscallEntry",
        "root_cause 100 0xdeadbeef",
        "max_tick",
        "min_tick",
    ]
    parsed = [parse_query(s) for s in examples]
    bad = None
    try:
        parse_query("read_mem 0 0x0 999999999999")
    except Exception as e:
        bad = str(e)
    return {"parsed": parsed, "size_cap_err": bad}


def fn_root_cause():
    b = TraceBuilder(DEFAULT_SNAPSHOT_INTERVAL)
    b.signal(11, 0x4000)
    b.syscall_entry(60, [0, 0, 0, 0, 0, 0])
    b.syscall_exit(0, [MemWriteRecord(0xDEAD0000, b"\x00\x00\x00\x00")])
    b.syscall_entry(1, [0, 0, 0, 0, 0, 0])  # crash next
    t = b.build()
    r = TtdReplayer(t)
    rep = find_root_cause(r, crash_tick=3, crash_addr=0xDEAD0000)
    return rep


def fn_stats():
    b = TraceBuilder(DEFAULT_SNAPSHOT_INTERVAL)
    b.syscall_entry(60, [0] * 6)
    b.syscall_exit(0, [MemWriteRecord(0x1000, b"AAAA"), MemWriteRecord(0x2000, b"BB")])
    b.syscall_entry(1, [0] * 6)
    b.syscall_exit(0, [])
    b.signal(11, 0x4000)
    t = b.build()
    return compute_stats(t)


def fn_error_variants():
    return {
        "ReplayError": [
            "TickOutOfRange", "NoSnapshot", "AddressNotMapped", "ReadOverflow",
            "AtStart", "AtEnd", "QueryParse", "QueryExec", "MalformedTrace", "Internal",
        ],
        "QueryValue": [
            "Int", "SignedInt", "Bytes", "WriteList", "EventList", "Text", "Null",
        ],
        "QueryAst": [
            "ReadMem", "FindWrites", "LastWrite", "ListSyscalls", "ListSignals",
            "ReadReg", "CountEvents", "RootCause", "MaxTick", "MinTick",
        ],
        "TraceLoader": [
            "LoadError", "TraceArch", "ModuleEntry", "TraceHeader",
            "PositionIndex", "LoadOptions", "LoadResult",
        ],
    }


def fn_modules():
    return {
        "modules": [
            "api_call_tracker", "memory_diff_viewer", "memory_reconstructor",
            "register_timeline", "replay_engine", "replay_stats",
            "differential_replay", "snapshot_manager", "replay_scheduler",
            "trace_diff", "ttd_call_recorder", "ttd_memory_provider",
            "ttd_trace_loader", "ttd_database", "position_engine",
            "replay_controller", "timeline",
        ]
    }


FUNCTIONS = [
    ("constants", fn_constants),
    ("mem_write_record", fn_mem_write_record),
    ("trace_event", fn_trace_event),
    ("snapshot_and_state", fn_snapshot_and_state),
    ("trace_basic", fn_trace_basic),
    ("replayer", fn_replayer),
    ("query_parse", fn_query_parse),
    ("root_cause", fn_root_cause),
    ("stats", fn_stats),
    ("error_variants", fn_error_variants),
    ("modules", fn_modules),
]


def main():
    results = []
    for name, fn in FUNCTIONS:
        try:
            results.append({"name": name, "ok": True, "result": fn()})
        except Exception as e:
            results.append({"name": name, "ok": False, "error": str(e)})
    out = {"crate": "rustre-ttd-replayer", "saved": True, "functions": results}
    out_path = os.path.join(
        os.path.dirname(os.path.abspath(__file__)),
        "rustre-ttd-replayer.result.json",
    )
    try:
        with open(out_path, "w", encoding="utf-8") as f:
            json.dump(out, f, indent=2, default=str)
    except Exception:
        out["saved"] = False
    print(json.dumps(out, indent=2, default=str))


if __name__ == "__main__":
    main()
