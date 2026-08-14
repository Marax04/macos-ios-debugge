"""Independent Python reimplementation of rustre-fuzz-sanitizers logic.

Pure stdlib. Mirrors the behavior described in
validation/reports/rustre-fuzz-sanitizers.md: shadow memory (MSan),
heap tracking (ASan), UBSan predicates, sanitizer log parsing,
severity classification, crash dedup, and a coverage map.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Set, Tuple


# ---------- Enums ----------

class SanitizerKind(str, Enum):
    MemoryUninit = "MemoryUninit"
    HeapOverflow = "HeapOverflow"
    UseAfterFree = "UseAfterFree"
    DoubleFree = "DoubleFree"
    NullDeref = "NullDeref"
    IntOverflow = "IntOverflow"
    Misaligned = "Misaligned"
    DivByZero = "DivByZero"
    HeapUnderflow = "HeapUnderflow"


class ArithOp(str, Enum):
    Add = "Add"
    Sub = "Sub"
    Mul = "Mul"


class SanitizerTool(str, Enum):
    ASan = "ASan"
    MSan = "MSan"
    UBSan = "UBSan"
    LSan = "LSan"
    TSan = "TSan"
    Unknown = "Unknown"


class AccessType(str, Enum):
    Read = "Read"
    Write = "Write"


class CrashSeverity(int, Enum):
    Info = 0
    Low = 1
    Medium = 2
    High = 3
    Critical = 4


# ---------- Reports ----------

@dataclass
class SanitizerReport:
    kind: SanitizerKind
    message: str
    stack_trace: List[int] = field(default_factory=list)


@dataclass
class ParsedStackFrame:
    index: int = 0
    address: int = 0
    function: str = ""
    file: str = ""
    line: int = 0
    column: int = 0

    @staticmethod
    def empty(index: int) -> "ParsedStackFrame":
        return ParsedStackFrame(index=index)

    def display(self) -> str:
        return f"#{self.index} 0x{self.address:x} in {self.function} {self.file}:{self.line}"


@dataclass
class ParsedCrashReport:
    tool: SanitizerTool = SanitizerTool.Unknown
    error_type: str = ""
    access_type: Optional[AccessType] = None
    access_size: Optional[int] = None
    address: Optional[int] = None
    thread: Optional[int] = None
    stack_frames: List[ParsedStackFrame] = field(default_factory=list)
    allocation_frames: List[ParsedStackFrame] = field(default_factory=list)
    deallocation_frames: List[ParsedStackFrame] = field(default_factory=list)
    raw_text: str = ""
    severity: CrashSeverity = CrashSeverity.Medium

    def summary(self) -> str:
        parts = [self.tool.value, self.error_type or "unknown"]
        if self.access_type is not None:
            parts.append(self.access_type.value)
        if self.address is not None:
            parts.append(f"0x{self.address:x}")
        return " ".join(parts)

    def top_function(self) -> Optional[str]:
        if self.stack_frames:
            return self.stack_frames[0].function or None
        return None


# ---------- Shadow memory / MSan ----------

PAGE_SIZE = 256


class ShadowMemory:
    def __init__(self) -> None:
        self.bits: Dict[int, bytearray] = {}

    def _page(self, addr: int) -> Tuple[int, int]:
        return addr // PAGE_SIZE, addr % PAGE_SIZE

    def _ensure(self, page: int) -> bytearray:
        b = self.bits.get(page)
        if b is None:
            b = bytearray(PAGE_SIZE // 8)
            self.bits[page] = b
        return b

    def _set(self, addr: int, defined: bool) -> None:
        page, off = self._page(addr)
        b = self._ensure(page)
        byte_i, bit_i = off // 8, off % 8
        if defined:
            b[byte_i] |= (1 << bit_i)
        else:
            b[byte_i] &= ~(1 << bit_i) & 0xFF

    def _get(self, addr: int) -> bool:
        page, off = self._page(addr)
        b = self.bits.get(page)
        if b is None:
            return False
        byte_i, bit_i = off // 8, off % 8
        return bool(b[byte_i] & (1 << bit_i))

    def mark_defined(self, addr: int, length: int) -> None:
        for i in range(length):
            self._set(addr + i, True)

    def mark_undefined(self, addr: int, length: int) -> None:
        for i in range(length):
            self._set(addr + i, False)

    def check_defined(self, addr: int, length: int) -> bool:
        return all(self._get(addr + i) for i in range(length))


class MemorySanitizer:
    def __init__(self) -> None:
        self.shadow = ShadowMemory()

    def mark_defined(self, addr: int, length: int) -> None:
        self.shadow.mark_defined(addr, length)

    def mark_undefined(self, addr: int, length: int) -> None:
        self.shadow.mark_undefined(addr, length)

    def check(self, addr: int, length: int) -> Optional[SanitizerReport]:
        if not self.shadow.check_defined(addr, length):
            return SanitizerReport(
                SanitizerKind.MemoryUninit,
                f"use of uninitialized memory at 0x{addr:x}+{length}",
                [],
            )
        return None


# ---------- Heap tracking / ASan ----------

@dataclass
class Allocation:
    addr: int
    size: int
    freed: bool = False
    freed_at: Optional[int] = None


class SanitizerResult:
    class Clean:
        pass

    @dataclass
    class HeapOverflow:
        addr: int
        size: int
        alloc_base: int
        alloc_size: int

    @dataclass
    class UseAfterFree:
        addr: int
        freed_at: int

    @dataclass
    class DoubleFree:
        addr: int

    @dataclass
    class HeapUnderflow:
        addr: int


class HeapTracking:
    def __init__(self) -> None:
        self.allocations: Dict[int, Allocation] = {}
        self.freed: Dict[int, Allocation] = {}
        self.quarantine: List[int] = []
        self._tick = 0

    def track_alloc(self, addr: int, size: int) -> None:
        self.allocations[addr] = Allocation(addr=addr, size=size)

    def track_free(self, addr: int):
        if addr in self.freed:
            return SanitizerResult.DoubleFree(addr=addr)
        alloc = self.allocations.pop(addr, None)
        if alloc is None:
            return SanitizerResult.DoubleFree(addr=addr)
        self._tick += 1
        alloc.freed = True
        alloc.freed_at = self._tick
        self.freed[addr] = alloc
        self.quarantine.append(addr)
        return SanitizerResult.Clean()

    def check_heap_access(self, addr: int, size: int):
        # check live allocations for containment / overflow
        for base, alloc in self.allocations.items():
            end = base + alloc.size
            if base <= addr < end:
                if addr + size > end:
                    return SanitizerResult.HeapOverflow(
                        addr=addr, size=size,
                        alloc_base=base, alloc_size=alloc.size,
                    )
                return SanitizerResult.Clean()
            # underflow: access right before allocation
            if addr < base and addr + size > base:
                return SanitizerResult.HeapUnderflow(addr=addr)
        # check freed
        for base, alloc in self.freed.items():
            end = base + alloc.size
            if base <= addr < end:
                return SanitizerResult.UseAfterFree(
                    addr=addr, freed_at=alloc.freed_at or 0,
                )
        return SanitizerResult.Clean()


class AddressSanitizer:
    def __init__(self) -> None:
        self.heap = HeapTracking()

    def track_alloc(self, addr: int, size: int) -> None:
        self.heap.track_alloc(addr, size)

    def track_free(self, addr: int) -> Optional[SanitizerReport]:
        r = self.heap.track_free(addr)
        if isinstance(r, SanitizerResult.DoubleFree):
            return SanitizerReport(SanitizerKind.DoubleFree, f"double-free at 0x{addr:x}", [])
        return None

    def check(self, addr: int, size: int) -> Optional[SanitizerReport]:
        r = self.heap.check_heap_access(addr, size)
        if isinstance(r, SanitizerResult.HeapOverflow):
            return SanitizerReport(SanitizerKind.HeapOverflow,
                                   f"heap-buffer-overflow at 0x{addr:x}", [])
        if isinstance(r, SanitizerResult.UseAfterFree):
            return SanitizerReport(SanitizerKind.UseAfterFree,
                                   f"use-after-free at 0x{addr:x}", [])
        if isinstance(r, SanitizerResult.HeapUnderflow):
            return SanitizerReport(SanitizerKind.HeapUnderflow,
                                   f"heap-underflow at 0x{addr:x}", [])
        return None


# ---------- UBSan ----------

I64_MIN = -(1 << 63)
I64_MAX = (1 << 63) - 1


class UbSanitizer:
    def __init__(self) -> None:
        pass

    @staticmethod
    def check_signed_overflow(a: int, b: int, op: ArithOp) -> bool:
        if op == ArithOp.Add:
            r = a + b
        elif op == ArithOp.Sub:
            r = a - b
        else:
            r = a * b
        return not (I64_MIN <= r <= I64_MAX)

    @staticmethod
    def check_null_deref(ptr: int) -> bool:
        return ptr == 0

    @staticmethod
    def check_misaligned(addr: int, alignment: int) -> bool:
        # non-power-of-two alignment -> treated as always aligned
        if alignment == 0 or (alignment & (alignment - 1)) != 0:
            return False
        return (addr % alignment) != 0

    @staticmethod
    def check_division(divisor: int) -> bool:
        return divisor == 0

    def checked_add(self, a: int, b: int):
        if self.check_signed_overflow(a, b, ArithOp.Add):
            return SanitizerReport(SanitizerKind.IntOverflow, f"signed add overflow {a}+{b}", [])
        return a + b

    def checked_mul(self, a: int, b: int):
        if self.check_signed_overflow(a, b, ArithOp.Mul):
            return SanitizerReport(SanitizerKind.IntOverflow, f"signed mul overflow {a}*{b}", [])
        return a * b

    def check_access(self, ptr: int, alignment: int) -> Optional[SanitizerReport]:
        if self.check_null_deref(ptr):
            return SanitizerReport(SanitizerKind.NullDeref, "null pointer dereference", [])
        if self.check_misaligned(ptr, alignment):
            return SanitizerReport(SanitizerKind.Misaligned,
                                   f"misaligned access at 0x{ptr:x} align={alignment}", [])
        return None


# ---------- Severity ----------

def classify_crash_severity(error_type: str) -> CrashSeverity:
    et = error_type.lower().strip()
    high = {
        "heap-buffer-overflow", "global-buffer-overflow", "stack-buffer-overflow",
        "double-free", "stack-overflow", "bad-free", "alloc-dealloc-mismatch",
    }
    critical = {"use-after-free", "heap-use-after-free"}
    low = {
        "integer-overflow", "undefined-behavior",
        "initialization-order-fiasco", "odr-violation",
    }
    info = {"memory-leak", "leak"}
    if et in critical:
        return CrashSeverity.Critical
    if et in high:
        return CrashSeverity.High
    if et in low:
        return CrashSeverity.Low
    if et in info:
        return CrashSeverity.Info
    return CrashSeverity.Medium


# ---------- Log parser ----------

MAX_LINES = 1_000_000


def parse_hex_u64(s: str) -> Optional[int]:
    s = s.strip()
    if s.startswith(("0x", "0X")):
        s = s[2:]
    if not s:
        return None
    try:
        return int(s, 16)
    except ValueError:
        return None


_HEADER_RE = re.compile(r"==\d+==ERROR:\s*(\S+)Sanitizer:\s*(\S+)", re.IGNORECASE)
_ACCESS_RE = re.compile(
    r"(READ|WRITE)\s+of size\s+(\d+)\s+at\s+(0x[0-9a-fA-F]+)", re.IGNORECASE
)
_THREAD_RE = re.compile(r"thread\s+T?(\d+)", re.IGNORECASE)
_FRAME_RE = re.compile(
    r"#(\d+)\s+(0x[0-9a-fA-F]+)\s+in\s+(\S+)(?:\s+([^\s].*?))?$"
)
_FRAME_LOC_RE = re.compile(r"(.+?):(\d+)(?::(\d+))?$")


def _parse_tool(tool_str: str) -> SanitizerTool:
    t = tool_str.lower()
    if t.startswith("address"):
        return SanitizerTool.ASan
    if t.startswith("memory"):
        return SanitizerTool.MSan
    if t.startswith("undefinedbehavior") or t.startswith("ub"):
        return SanitizerTool.UBSan
    if t.startswith("leak"):
        return SanitizerTool.LSan
    if t.startswith("thread"):
        return SanitizerTool.TSan
    return SanitizerTool.Unknown


def _parse_frame(line: str) -> Optional[ParsedStackFrame]:
    m = _FRAME_RE.search(line.strip())
    if not m:
        return None
    idx = int(m.group(1))
    addr = parse_hex_u64(m.group(2)) or 0
    func = m.group(3) or ""
    tail = (m.group(4) or "").strip()
    fname, lineno, col = "", 0, 0
    if tail:
        # Tail may contain "file:line:col" possibly with windows drive.
        lm = _FRAME_LOC_RE.match(tail)
        if lm:
            fname = lm.group(1)
            try:
                lineno = int(lm.group(2))
            except ValueError:
                lineno = 0
            if lm.group(3):
                try:
                    col = int(lm.group(3))
                except ValueError:
                    col = 0
        else:
            fname = tail
    return ParsedStackFrame(
        index=idx, address=addr, function=func,
        file=fname, line=lineno, column=col,
    )


class SanitizerLogParser:
    @classmethod
    def parse(cls, text: str) -> ParsedCrashReport:
        reports = cls.parse_all(text)
        if reports:
            return reports[0]
        return ParsedCrashReport(raw_text=text)

    @classmethod
    def parse_all(cls, text: str) -> List[ParsedCrashReport]:
        lines = text.splitlines()
        if len(lines) > MAX_LINES:
            lines = lines[:MAX_LINES]

        # Split on header lines.
        chunks: List[List[str]] = []
        current: List[str] = []
        for ln in lines:
            if _HEADER_RE.search(ln):
                if current:
                    chunks.append(current)
                current = [ln]
            else:
                if current:
                    current.append(ln)
        if current:
            chunks.append(current)

        out: List[ParsedCrashReport] = []
        for chunk in chunks:
            out.append(cls._parse_chunk(chunk))
        return out

    @staticmethod
    def _parse_chunk(lines: List[str]) -> ParsedCrashReport:
        raw = "\n".join(lines)
        rep = ParsedCrashReport(raw_text=raw)
        # Header
        for ln in lines:
            m = _HEADER_RE.search(ln)
            if m:
                rep.tool = _parse_tool(m.group(1))
                rep.error_type = m.group(2).rstrip(":,.")
                break
        # Access info + thread
        for ln in lines:
            am = _ACCESS_RE.search(ln)
            if am and rep.access_type is None:
                rep.access_type = (AccessType.Read
                                   if am.group(1).upper() == "READ"
                                   else AccessType.Write)
                try:
                    rep.access_size = int(am.group(2))
                except ValueError:
                    pass
                rep.address = parse_hex_u64(am.group(3))
            tm = _THREAD_RE.search(ln)
            if tm and rep.thread is None:
                try:
                    rep.thread = int(tm.group(1))
                except ValueError:
                    pass

        # Frame sections: crash, allocation (after "allocated by"),
        # deallocation (after "freed by").
        section = "crash"
        for ln in lines:
            low = ln.lower()
            if "freed by thread" in low or "previously freed by" in low:
                section = "dealloc"
                continue
            if "allocated by thread" in low:
                section = "alloc"
                continue
            fr = _parse_frame(ln)
            if fr is None:
                continue
            if section == "alloc":
                rep.allocation_frames.append(fr)
            elif section == "dealloc":
                rep.deallocation_frames.append(fr)
            else:
                rep.stack_frames.append(fr)

        rep.severity = classify_crash_severity(rep.error_type)
        return rep


# ---------- Crash deduplication ----------

_OFFSET_RE = re.compile(r"\+0x[0-9a-fA-F]+")


@dataclass
class DeduplicatedCrash:
    representative: ParsedCrashReport
    duplicate_count: int = 1
    all_addresses: List[int] = field(default_factory=list)

    def is_recurring(self) -> bool:
        return self.duplicate_count > 1


@dataclass
class CrashDeduplicator:
    stack_depth: int = 5
    ignore_addresses: bool = True
    ignore_offsets: bool = True

    def dedup_key(self, report: ParsedCrashReport) -> str:
        parts = [report.error_type]
        if not self.ignore_addresses:
            if report.access_type is not None:
                parts.append(report.access_type.value)
            if report.access_size is not None:
                parts.append(str(report.access_size))
        else:
            if report.access_type is not None:
                parts.append(report.access_type.value)
        for fr in report.stack_frames[: self.stack_depth]:
            fn = fr.function
            if self.ignore_offsets:
                fn = _OFFSET_RE.sub("", fn)
            parts.append(fn)
        return "|".join(parts)

    def are_duplicates(self, a: ParsedCrashReport, b: ParsedCrashReport) -> bool:
        return self.dedup_key(a) == self.dedup_key(b)

    def deduplicate(self, reports: List[ParsedCrashReport]) -> List[DeduplicatedCrash]:
        order: List[str] = []
        groups: Dict[str, DeduplicatedCrash] = {}
        for r in reports:
            k = self.dedup_key(r)
            if k not in groups:
                groups[k] = DeduplicatedCrash(representative=r, duplicate_count=1,
                                              all_addresses=[r.address] if r.address is not None else [])
                order.append(k)
            else:
                g = groups[k]
                g.duplicate_count += 1
                if r.address is not None:
                    g.all_addresses.append(r.address)
        return [groups[k] for k in order]


# ---------- Coverage map ----------

@dataclass
class CoverageMap:
    edges: Dict[Tuple[int, int], int] = field(default_factory=dict)
    blocks: Dict[int, int] = field(default_factory=dict)

    def record_edge(self, frm: int, to: int) -> None:
        self.edges[(frm, to)] = self.edges.get((frm, to), 0) + 1

    def record_block(self, pc: int) -> None:
        self.blocks[pc] = self.blocks.get(pc, 0) + 1

    def merge(self, other: "CoverageMap") -> None:
        for k, v in other.edges.items():
            self.edges[k] = self.edges.get(k, 0) + v
        for k, v in other.blocks.items():
            self.blocks[k] = self.blocks.get(k, 0) + v

    def total_edges(self) -> int:
        return len(self.edges)

    def total_blocks(self) -> int:
        return len(self.blocks)

    def new_edges_since(self, baseline: "CoverageMap") -> int:
        base: Set[Tuple[int, int]] = set(baseline.edges.keys())
        return sum(1 for k in self.edges if k not in base)

    def coverage_ratio(self, total_known: int) -> float:
        if total_known <= 0:
            return 0.0
        r = len(self.edges) / total_known
        if r < 0.0:
            return 0.0
        if r > 1.0:
            return 1.0
        return r


# ---------- Self-test ----------

def _self_test() -> None:
    # ShadowMemory / MSan
    sm = ShadowMemory()
    assert not sm.check_defined(0x1000, 4)
    sm.mark_defined(0x1000, 4)
    assert sm.check_defined(0x1000, 4)
    sm.mark_undefined(0x1002, 1)
    assert not sm.check_defined(0x1000, 4)

    msan = MemorySanitizer()
    assert msan.check(0x2000, 8) is not None
    msan.mark_defined(0x2000, 8)
    assert msan.check(0x2000, 8) is None

    # ASan
    asan = AddressSanitizer()
    asan.track_alloc(0x4000, 16)
    assert asan.check(0x4000, 8) is None
    r = asan.check(0x400C, 8)  # overflow
    assert r is not None and r.kind == SanitizerKind.HeapOverflow
    assert asan.track_free(0x4000) is None
    r = asan.check(0x4000, 1)
    assert r is not None and r.kind == SanitizerKind.UseAfterFree
    r = asan.track_free(0x4000)
    assert r is not None and r.kind == SanitizerKind.DoubleFree

    # UBSan
    ub = UbSanitizer()
    assert ub.check_signed_overflow(I64_MAX, 1, ArithOp.Add)
    assert not ub.check_signed_overflow(1, 2, ArithOp.Add)
    assert ub.check_null_deref(0)
    assert not ub.check_null_deref(1)
    assert ub.check_misaligned(0x1001, 4)
    assert not ub.check_misaligned(0x1000, 4)
    assert not ub.check_misaligned(0x1001, 3)  # non-pow2 -> ok
    assert ub.check_division(0)
    assert isinstance(ub.checked_add(I64_MAX, 1), SanitizerReport)
    assert ub.checked_add(1, 2) == 3
    assert ub.check_access(0, 4) is not None
    assert ub.check_access(0x1000, 4) is None
    assert ub.check_access(0x1001, 4) is not None

    # Severity
    assert classify_crash_severity("heap-use-after-free") == CrashSeverity.Critical
    assert classify_crash_severity("heap-buffer-overflow") == CrashSeverity.High
    assert classify_crash_severity("memory-leak") == CrashSeverity.Info
    assert classify_crash_severity("integer-overflow") == CrashSeverity.Low
    assert classify_crash_severity("weird-thing") == CrashSeverity.Medium

    # Log parser
    log = """==1234==ERROR: AddressSanitizer: heap-buffer-overflow on address 0xdeadbeef
READ of size 4 at 0xdeadbeef thread T0
    #0 0x401000 in foo /src/a.c:10:5
    #1 0x401100 in main /src/a.c:20
allocated by thread T0 here:
    #0 0x400000 in malloc /src/m.c:1
"""
    parsed = SanitizerLogParser.parse(log)
    assert parsed.tool == SanitizerTool.ASan
    assert parsed.error_type == "heap-buffer-overflow"
    assert parsed.access_type == AccessType.Read
    assert parsed.access_size == 4
    assert parsed.address == 0xdeadbeef
    assert parsed.thread == 0
    assert len(parsed.stack_frames) == 2
    assert parsed.stack_frames[0].function == "foo"
    assert len(parsed.allocation_frames) == 1
    assert parsed.severity == CrashSeverity.High
    assert parsed.top_function() == "foo"
    assert "ASan" in parsed.summary()

    # parse_hex_u64
    assert parse_hex_u64("0xff") == 255
    assert parse_hex_u64("0X10") == 16
    assert parse_hex_u64("garbage") is None

    # Dedup
    log2 = log + "\n" + log.replace("0xdeadbeef", "0xcafebabe")
    reports = SanitizerLogParser.parse_all(log2)
    assert len(reports) == 2
    dd = CrashDeduplicator()
    out = dd.deduplicate(reports)
    assert len(out) == 1
    assert out[0].duplicate_count == 2
    assert out[0].is_recurring()

    # Coverage
    cm = CoverageMap()
    cm.record_edge(1, 2)
    cm.record_edge(1, 2)
    cm.record_edge(2, 3)
    cm.record_block(1)
    assert cm.total_edges() == 2
    assert cm.total_blocks() == 1
    base = CoverageMap()
    base.record_edge(1, 2)
    assert cm.new_edges_since(base) == 1
    assert 0.0 <= cm.coverage_ratio(10) <= 1.0
    assert cm.coverage_ratio(1) == 1.0
    assert cm.coverage_ratio(0) == 0.0

    # Frame display
    f = ParsedStackFrame(index=0, address=0x401000, function="foo",
                         file="/src/a.c", line=10)
    assert f.display() == "#0 0x401000 in foo /src/a.c:10"

    # Empty parse
    empty = SanitizerLogParser.parse("nothing here")
    assert empty.tool == SanitizerTool.Unknown


if __name__ == "__main__":
    _self_test()
    print("OK")
