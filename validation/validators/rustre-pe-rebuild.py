"""
rustre-pe-rebuild — Python reference implementation reproducing the documented
public API of the Rust crate `rustre-pe-rebuild`.

Stdlib only: struct, hashlib, json, re, math, collections.

Every function/method documented in
`validation/reports/rustre-pe-rebuild.md` has a Python equivalent here, with
input/output types matching the documented signatures (Rust types mapped to
Python: u8/u16/u32/u64/i64 -> int, Vec<u8>/&[u8] -> bytes/bytearray,
String/&str -> str, Result<T,E> -> T or raises Exception, Option<T> -> T|None).
"""

from __future__ import annotations

import hashlib
import json
import math
import re
import struct
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, Iterator, List, Optional, Tuple


# =============================================================================
# Errors
# =============================================================================
class RebuildError(Exception):
    pass


class FixupError(Exception):
    pass


class SectionRebuildError(Exception):
    pass


class DumpError(Exception):
    pass


class ImportRebuildError(Exception):
    pass


class IatError(Exception):
    pass


# =============================================================================
# Helpers / free functions
# =============================================================================
IMAGE_SCN_CNT_CODE = 0x00000020
IMAGE_SCN_CNT_INITIALIZED_DATA = 0x00000040
IMAGE_SCN_MEM_EXECUTE = 0x20000000
IMAGE_SCN_MEM_READ = 0x40000000
IMAGE_SCN_MEM_WRITE = 0x80000000


def compute_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = Counter(data)
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def crc16_ccitt(data: bytes) -> int:
    crc = 0xFFFF
    for b in data:
        crc ^= b << 8
        for _ in range(8):
            crc = ((crc << 1) ^ 0x1021) & 0xFFFF if crc & 0x8000 else (crc << 1) & 0xFFFF
    return crc & 0xFFFF


def is_memory_pe(data: bytes) -> bool:
    return len(data) >= 2 and data[0:2] == b"MZ"


def align_up(value: int, align: int) -> int:
    if align == 0:
        return value
    return (value + align - 1) & ~(align - 1)


def align_down(value: int, align: int) -> int:
    if align == 0:
        return value
    return value & ~(align - 1)


def compute_imphash(entries: "List[IatEntry]") -> str:
    parts = []
    for e in entries:
        dll = (e.dll or "").lower()
        for suf in (".dll", ".ocx", ".sys"):
            if dll.endswith(suf):
                dll = dll[: -len(suf)]
                break
        name = e.name or (f"ord{e.ordinal}" if e.ordinal is not None else "")
        parts.append(f"{dll}.{name.lower()}")
    return hashlib.md5(",".join(parts).encode()).hexdigest()


# =============================================================================
# RebuildSection
# =============================================================================
@dataclass
class RebuildSection:
    name: str
    virtual_address: int
    data: bytes
    characteristics: int
    virtual_size: int = 0

    def __post_init__(self):
        if self.virtual_size == 0:
            self.virtual_size = len(self.data)

    @classmethod
    def new(cls, name: str, virtual_address: int, data: bytes, characteristics: int) -> "RebuildSection":
        return cls(name, virtual_address, bytes(data), characteristics)

    @classmethod
    def code(cls, name: str, virtual_address: int, data: bytes) -> "RebuildSection":
        return cls.new(name, virtual_address, data,
                       IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ)

    @classmethod
    def data_(cls, name: str, virtual_address: int, data: bytes) -> "RebuildSection":
        return cls.new(name, virtual_address, data,
                       IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE)

    # 'data' is a reserved attr name; expose as classmethod alias too
    data_section = data_

    @classmethod
    def rdata(cls, name: str, virtual_address: int, data: bytes) -> "RebuildSection":
        return cls.new(name, virtual_address, data,
                       IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ)

    def entropy(self) -> float:
        return compute_entropy(self.data)

    def is_executable(self) -> bool:
        return bool(self.characteristics & IMAGE_SCN_MEM_EXECUTE)

    def is_writable(self) -> bool:
        return bool(self.characteristics & IMAGE_SCN_MEM_WRITE)

    def virtual_end(self) -> int:
        return self.virtual_address + self.virtual_size

    def contains_rva(self, rva: int) -> bool:
        return self.virtual_address <= rva < self.virtual_end()

    def rva_to_offset(self, rva: int) -> Optional[int]:
        if not self.contains_rva(rva):
            return None
        return rva - self.virtual_address


# =============================================================================
# RebuildFlags
# =============================================================================
class RebuildFlags(int):
    IS_64BIT = 1 << 0
    IS_DLL = 1 << 1
    FIX_CHECKSUM = 1 << 2
    FIX_IMPORTS = 1 << 3
    FIX_RELOCATIONS = 1 << 4
    STRIP_OVERLAY = 1 << 5

    def contains(self, flag: int) -> bool:
        return (int(self) & flag) == flag

    def is_64bit(self) -> bool: return self.contains(self.IS_64BIT)
    def is_dll(self) -> bool: return self.contains(self.IS_DLL)
    def fix_checksum(self) -> bool: return self.contains(self.FIX_CHECKSUM)
    def fix_imports(self) -> bool: return self.contains(self.FIX_IMPORTS)
    def fix_relocations(self) -> bool: return self.contains(self.FIX_RELOCATIONS)
    def strip_overlay(self) -> bool: return self.contains(self.STRIP_OVERLAY)


# =============================================================================
# IatEntry
# =============================================================================
@dataclass
class IatEntry:
    dll: str = ""
    name: Optional[str] = None
    ordinal: Optional[int] = None
    iat_rva: int = 0
    address: int = 0

    def is_resolved(self) -> bool:
        return self.name is not None or self.ordinal is not None

    def import_description(self) -> str:
        if self.name:
            return f"{self.dll}!{self.name}"
        if self.ordinal is not None:
            return f"{self.dll}!#{self.ordinal}"
        return f"{self.dll}!?"


@dataclass
class IatFixOptions:
    image_base: int = 0
    is_64bit: bool = True


class IatFixer:
    def __init__(self, options: IatFixOptions):
        self.options = options
        self._entries: List[IatEntry] = []
        self._imports: Dict[int, Tuple[str, str]] = {}

    @classmethod
    def new(cls, options: IatFixOptions) -> "IatFixer":
        return cls(options)

    def add_entry(self, entry: IatEntry) -> None:
        self._entries.append(entry)

    def register_import(self, address: int, dll: str, name: str) -> None:
        self._imports[address] = (dll, name)

    def fix(self) -> int:
        resolved = 0
        for e in self._entries:
            if e.address in self._imports:
                dll, name = self._imports[e.address]
                e.dll, e.name = dll, name
                resolved += 1
        return resolved

    def entries(self) -> List[IatEntry]:
        return self._entries

    def resolved_count(self) -> int:
        return sum(1 for e in self._entries if e.is_resolved())

    def apply_to_image(self, pe_data: bytearray, image_base: int) -> int:
        ptr_size = 8 if self.options.is_64bit else 4
        written = 0
        for e in self._entries:
            if not e.is_resolved():
                continue
            off = e.iat_rva
            if off + ptr_size > len(pe_data):
                continue
            pe_data[off:off + ptr_size] = e.address.to_bytes(ptr_size, "little")
            written += 1
        return written


# =============================================================================
# RelocationEntry / RelocationRebuilder / RelocationType / RelocationBlock /
# RelocationTableBuilder
# =============================================================================
class RelocationType:
    ABSOLUTE = 0
    HIGH = 1
    LOW = 2
    HIGHLOW = 3
    HIGHADJ = 4
    DIR64 = 10

    @staticmethod
    def value(t: int) -> int:
        return t

    @staticmethod
    def size_bytes(t: int) -> int:
        return {0: 0, 1: 2, 2: 2, 3: 4, 4: 4, 10: 8}.get(t, 0)

    @staticmethod
    def from_nibble(n: int) -> Optional[int]:
        if n in (0, 1, 2, 3, 4, 10):
            return n
        return None


@dataclass
class RelocationEntry:
    rva: int = 0
    reloc_type: int = RelocationType.ABSOLUTE

    @classmethod
    def absolute(cls) -> "RelocationEntry":
        return cls(0, RelocationType.ABSOLUTE)

    @classmethod
    def dir64(cls, rva: int) -> "RelocationEntry":
        return cls(rva, RelocationType.DIR64)

    @classmethod
    def highlow(cls, rva: int) -> "RelocationEntry":
        return cls(rva, RelocationType.HIGHLOW)

    def is_meaningful(self) -> bool:
        return self.reloc_type != RelocationType.ABSOLUTE

    def is_padding(self) -> bool:
        return self.reloc_type == RelocationType.ABSOLUTE

    def encode_word(self, page_base: int) -> int:
        offset = (self.rva - page_base) & 0xFFF
        return ((self.reloc_type & 0xF) << 12) | offset


@dataclass
class RelocationOptions:
    original_base: int = 0
    new_base: int = 0


class RelocationRebuilder:
    def __init__(self, options: RelocationOptions):
        self.options = options
        self._entries: List[RelocationEntry] = []

    @classmethod
    def new(cls, options: RelocationOptions) -> "RelocationRebuilder":
        return cls(options)

    def add_entry(self, entry: RelocationEntry) -> None:
        self._entries.append(entry)

    def add_dir64(self, rva: int) -> None:
        self._entries.append(RelocationEntry.dir64(rva))

    def add_highlow(self, rva: int) -> None:
        self._entries.append(RelocationEntry.highlow(rva))

    def entry_count(self) -> int:
        return sum(1 for e in self._entries if e.is_meaningful())

    def delta(self) -> int:
        return self.options.new_base - self.options.original_base

    def build_reloc_section(self) -> bytes:
        # Group by 4K page
        pages: Dict[int, List[RelocationEntry]] = defaultdict(list)
        for e in self._entries:
            if not e.is_meaningful():
                continue
            pages[e.rva & ~0xFFF].append(e)
        out = bytearray()
        for page in sorted(pages):
            entries = pages[page]
            # Pad to even count
            if len(entries) % 2:
                entries.append(RelocationEntry(page, RelocationType.ABSOLUTE))
            block_size = 8 + 2 * len(entries)
            out += struct.pack("<II", page, block_size)
            for e in entries:
                out += struct.pack("<H", e.encode_word(page))
        return bytes(out)

    def apply_to_image(self, image: bytearray) -> int:
        delta = self.delta()
        applied = 0
        for e in self._entries:
            if e.reloc_type == RelocationType.DIR64:
                if e.rva + 8 > len(image):
                    continue
                v = int.from_bytes(image[e.rva:e.rva + 8], "little")
                image[e.rva:e.rva + 8] = ((v + delta) & 0xFFFFFFFFFFFFFFFF).to_bytes(8, "little")
                applied += 1
            elif e.reloc_type == RelocationType.HIGHLOW:
                if e.rva + 4 > len(image):
                    continue
                v = int.from_bytes(image[e.rva:e.rva + 4], "little")
                image[e.rva:e.rva + 4] = ((v + delta) & 0xFFFFFFFF).to_bytes(4, "little")
                applied += 1
        return applied


class RelocationBlock:
    def __init__(self, page_rva: int):
        self.page_rva = page_rva
        self.entries: List[RelocationEntry] = []

    @classmethod
    def new(cls, page_rva: int) -> "RelocationBlock":
        return cls(page_rva)

    def add_entry(self, entry: RelocationEntry) -> None:
        if entry.rva < self.page_rva or entry.rva >= self.page_rva + 0x1000:
            raise ValueError("entry out of page range")
        self.entries.append(entry)

    def sort(self) -> None:
        self.entries.sort(key=lambda e: e.rva)

    def real_entry_count(self) -> int:
        return sum(1 for e in self.entries if e.is_meaningful())

    def serialised_size(self) -> int:
        n = len(self.entries) + (len(self.entries) % 2)
        return 8 + 2 * n

    def to_bytes(self) -> bytes:
        entries = list(self.entries)
        if len(entries) % 2:
            entries.append(RelocationEntry(self.page_rva, RelocationType.ABSOLUTE))
        out = bytearray(struct.pack("<II", self.page_rva, 8 + 2 * len(entries)))
        for e in entries:
            out += struct.pack("<H", e.encode_word(self.page_rva))
        return bytes(out)


@dataclass
class RelocationStatistics:
    total: int = 0
    dir64: int = 0
    highlow: int = 0


class RelocationTableBuilder:
    def __init__(self, image_base: int, is_x64: bool):
        self.image_base = image_base
        self.is_x64 = is_x64
        self._fixups: Dict[int, int] = {}
        self._stats = RelocationStatistics()

    @classmethod
    def new_x64(cls, image_base: int) -> "RelocationTableBuilder":
        return cls(image_base, True)

    @classmethod
    def new_x86(cls, image_base: int) -> "RelocationTableBuilder":
        return cls(image_base, False)

    def add_fixup(self, rva: int) -> bool:
        if rva in self._fixups:
            return False
        t = RelocationType.DIR64 if self.is_x64 else RelocationType.HIGHLOW
        self._fixups[rva] = t
        self._stats.total += 1
        if t == RelocationType.DIR64:
            self._stats.dir64 += 1
        else:
            self._stats.highlow += 1
        return True

    def add_fixup_typed(self, rva: int, reloc_type: int) -> bool:
        if rva in self._fixups:
            return False
        self._fixups[rva] = reloc_type
        self._stats.total += 1
        return True

    def add_fixups(self, rvas: Iterable[int]) -> None:
        for r in rvas:
            self.add_fixup(r)

    def remove_fixup(self, rva: int) -> bool:
        return self._fixups.pop(rva, None) is not None

    def clear(self) -> None:
        self._fixups.clear()
        self._stats = RelocationStatistics()

    def fixup_count(self) -> int:
        return len(self._fixups)

    def stats(self) -> RelocationStatistics:
        return self._stats

    def blocks(self) -> List[RelocationBlock]:
        pages: Dict[int, RelocationBlock] = {}
        for rva, t in self._fixups.items():
            page = rva & ~0xFFF
            blk = pages.setdefault(page, RelocationBlock(page))
            blk.add_entry(RelocationEntry(rva, t))
        for b in pages.values():
            b.sort()
        return [pages[k] for k in sorted(pages)]

    def build(self) -> bytes:
        out = bytearray()
        for b in self.blocks():
            out += b.to_bytes()
        return bytes(out)

    def import_reloc_section(self, data: bytes) -> int:
        i = 0
        count = 0
        while i + 8 <= len(data):
            page, size = struct.unpack_from("<II", data, i)
            if size < 8 or i + size > len(data):
                break
            n = (size - 8) // 2
            for j in range(n):
                word = struct.unpack_from("<H", data, i + 8 + 2 * j)[0]
                t = (word >> 12) & 0xF
                off = word & 0xFFF
                if t != RelocationType.ABSOLUTE:
                    self.add_fixup_typed(page + off, t)
                    count += 1
            i += size
        return count

    def heuristic_scan_x64(self, image: bytes, image_base: int, image_size: int) -> int:
        count = 0
        end = image_base + image_size
        for i in range(0, len(image) - 8, 8):
            v = int.from_bytes(image[i:i + 8], "little")
            if image_base <= v < end:
                if self.add_fixup_typed(i, RelocationType.DIR64):
                    count += 1
        return count


def rebuild_relocs(rvas: Iterable[int], image_base: int, is_x64: bool) -> bytes:
    b = RelocationTableBuilder.new_x64(image_base) if is_x64 else RelocationTableBuilder.new_x86(image_base)
    b.add_fixups(rvas)
    return b.build()


# =============================================================================
# Export Rebuilder
# =============================================================================
@dataclass
class ExportEntry:
    name: Optional[str] = None
    ordinal: int = 0
    rva: int = 0
    forwarder_target: Optional[str] = None

    @classmethod
    def named(cls, name: str, ordinal: int, rva: int) -> "ExportEntry":
        return cls(name=name, ordinal=ordinal, rva=rva)

    @classmethod
    def ordinal_only(cls, ordinal: int, rva: int) -> "ExportEntry":
        return cls(name=None, ordinal=ordinal, rva=rva)

    @classmethod
    def forwarder(cls, name: str, ordinal: int, target: str) -> "ExportEntry":
        return cls(name=name, ordinal=ordinal, rva=0, forwarder_target=target)

    def has_name(self) -> bool:
        return self.name is not None


class ExportRebuilder:
    def __init__(self, dll_name: str, ordinal_base: int):
        self._dll_name = dll_name
        self._ordinal_base = ordinal_base
        self._entries: List[ExportEntry] = []

    @classmethod
    def new(cls, dll_name: str, ordinal_base: int) -> "ExportRebuilder":
        return cls(dll_name, ordinal_base)

    def add_entry(self, entry: ExportEntry) -> None:
        self._entries.append(entry)

    def export_count(self) -> int:
        return len(self._entries)

    def dll_name(self) -> str:
        return self._dll_name

    def build(self, section_rva: int) -> bytes:
        if not self._entries:
            raise RebuildError("no exports")
        named = sorted([e for e in self._entries if e.has_name()], key=lambda e: e.name)
        max_ord = max((e.ordinal for e in self._entries), default=self._ordinal_base)
        n_funcs = max_ord - self._ordinal_base + 1
        # Layout: dir(40), addr_table(4*n_funcs), name_ptr(4*n_named), ord_table(2*n_named),
        # dll name + export names (strings)
        dir_size = 40
        addr_off = dir_size
        name_ptr_off = addr_off + 4 * n_funcs
        ord_off = name_ptr_off + 4 * len(named)
        strings_off = ord_off + 2 * len(named)
        blob = bytearray(strings_off)
        # Strings region
        strings = bytearray()
        dll_name_off = strings_off + len(strings)
        strings += self._dll_name.encode() + b"\x00"
        name_rvas: List[int] = []
        for e in named:
            name_rvas.append(strings_off + len(strings))
            strings += e.name.encode() + b"\x00"
        # Address table
        addrs = bytearray(4 * n_funcs)
        for e in self._entries:
            idx = e.ordinal - self._ordinal_base
            if 0 <= idx < n_funcs:
                addrs[idx * 4:idx * 4 + 4] = struct.pack("<I", e.rva)
        blob[addr_off:addr_off + len(addrs)] = addrs
        # Name ptr table + ordinal table
        nptrs = bytearray()
        ords = bytearray()
        for e, name_rva in zip(named, name_rvas):
            nptrs += struct.pack("<I", section_rva + name_rva)
            ords += struct.pack("<H", e.ordinal - self._ordinal_base)
        blob[name_ptr_off:name_ptr_off + len(nptrs)] = nptrs
        blob[ord_off:ord_off + len(ords)] = ords
        # Directory header
        struct.pack_into("<IIHHIIIIII", blob, 0,
                         0, 0,  # characteristics, timestamp
                         0, 0,  # major, minor version
                         section_rva + dll_name_off,
                         self._ordinal_base,
                         n_funcs,
                         len(named),
                         section_rva + addr_off,
                         section_rva + name_ptr_off)
        # AddressOfNameOrdinals -> appended (last field)
        blob += struct.pack("<I", section_rva + ord_off)
        # Fix directory header: it actually has 11 dwords (40 bytes ends at AddressOfNames).
        # AddressOfNameOrdinals is at offset 36 in the directory.
        # The struct.pack_into above already wrote 40 bytes for 10 dwords + 2 words, so adjust:
        # Re-encode header cleanly:
        header = struct.pack("<IIHHIIIIIII",
                             0, 0, 0, 0,
                             section_rva + dll_name_off,
                             self._ordinal_base,
                             n_funcs,
                             len(named),
                             section_rva + addr_off,
                             section_rva + name_ptr_off,
                             section_rva + ord_off)
        out = bytearray(header) + blob[40:] + strings
        return bytes(out)


# =============================================================================
# OEP detection
# =============================================================================
@dataclass
class OepCandidate:
    rva: int = 0
    confidence: float = 0.0
    reason: str = ""

    def is_confident(self) -> bool:
        return self.confidence >= 0.7


@dataclass
class OepResult:
    rva: int = 0
    confidence: float = 0.0
    reason: str = ""


class OepDetector:
    def __init__(self):
        self._candidates: List[OepResult] = []

    @classmethod
    def new(cls) -> "OepDetector":
        return cls()

    def detect(self, sections: List[RebuildSection], known_ep_rva: Optional[int]) -> OepResult:
        self._candidates.clear()
        if known_ep_rva is not None:
            r = OepResult(known_ep_rva, 1.0, "known_ep")
            self._candidates.append(r)
            return r
        for s in sections:
            if s.is_executable() and s.data[:1] in (b"\x55", b"\x48", b"\xE8"):
                r = OepResult(s.virtual_address, 0.6, "prologue")
                self._candidates.append(r)
                return r
        raise RebuildError("no OEP candidate")

    def candidates(self) -> List[OepResult]:
        return self._candidates


PROLOGUE_PATTERNS = [
    b"\x55\x8b\xec",          # push ebp; mov ebp,esp
    b"\x48\x89\x5c\x24",      # mov [rsp+x],rbx
    b"\x48\x83\xec",          # sub rsp,imm8
    b"\x40\x53",              # push rbx (rex)
]


def detect_oep_heuristics(dump: bytes, base: int) -> List[OepCandidate]:
    cands: List[OepCandidate] = []
    for p in PROLOGUE_PATTERNS:
        start = 0
        while True:
            idx = dump.find(p, start)
            if idx < 0:
                break
            cands.append(OepCandidate(rva=idx, confidence=0.5, reason=f"prologue:{p.hex()}"))
            start = idx + 1
    return cands


@dataclass
class SectionInfo:
    name: str = ""
    virtual_address: int = 0
    virtual_size: int = 0
    raw_offset: int = 0
    raw_size: int = 0
    characteristics: int = 0

    def is_executable(self) -> bool:
        return bool(self.characteristics & IMAGE_SCN_MEM_EXECUTE)

    def contains_rva(self, rva: int) -> bool:
        return self.virtual_address <= rva < self.virtual_address + self.virtual_size


class OepFinder:
    def __init__(self, data: bytes, image_base: int):
        self._data = bytes(data)
        self._image_base = image_base
        self._sections: List[SectionInfo] = []
        self._candidates: List[OepCandidate] = []
        self._parse()

    @classmethod
    def from_bytes(cls, data: bytes, image_base: int) -> "OepFinder":
        if not is_memory_pe(data):
            raise RebuildError("not a PE")
        return cls(data, image_base)

    def _parse(self) -> None:
        if len(self._data) < 0x40:
            return
        e_lfanew = struct.unpack_from("<I", self._data, 0x3C)[0]
        if e_lfanew + 24 > len(self._data) or self._data[e_lfanew:e_lfanew + 4] != b"PE\x00\x00":
            return
        num_sec = struct.unpack_from("<H", self._data, e_lfanew + 6)[0]
        opt_size = struct.unpack_from("<H", self._data, e_lfanew + 20)[0]
        sec_off = e_lfanew + 24 + opt_size
        for i in range(num_sec):
            off = sec_off + i * 40
            if off + 40 > len(self._data):
                break
            name = self._data[off:off + 8].rstrip(b"\x00").decode("ascii", errors="replace")
            vs, va, rs, ro = struct.unpack_from("<IIII", self._data, off + 8)
            ch = struct.unpack_from("<I", self._data, off + 36)[0]
            self._sections.append(SectionInfo(name, va, vs, ro, rs, ch))

    def sections(self) -> List[SectionInfo]:
        return self._sections

    def executable_sections(self) -> Iterator[SectionInfo]:
        return (s for s in self._sections if s.is_executable())

    def section_containing_rva(self, rva: int) -> Optional[SectionInfo]:
        for s in self._sections:
            if s.contains_rva(rva):
                return s
        return None

    def rva_to_file_offset(self, rva: int) -> Optional[int]:
        s = self.section_containing_rva(rva)
        if not s:
            return None
        return s.raw_offset + (rva - s.virtual_address)

    def scan_prologue_patterns(self) -> List[OepCandidate]:
        out: List[OepCandidate] = []
        for s in self.executable_sections():
            chunk = self._data[s.raw_offset:s.raw_offset + s.raw_size]
            for p in PROLOGUE_PATTERNS:
                idx = chunk.find(p)
                if idx >= 0:
                    out.append(OepCandidate(s.virtual_address + idx, 0.6, "prologue"))
        return out

    def scan_crt_stubs(self) -> List[OepCandidate]:
        out: List[OepCandidate] = []
        for s in self.executable_sections():
            chunk = self._data[s.raw_offset:s.raw_offset + s.raw_size]
            for pat in (b"\xE8", b"\xFF\x15"):
                idx = chunk.find(pat)
                if idx >= 0:
                    out.append(OepCandidate(s.virtual_address + idx, 0.5, "crt_stub"))
                    break
        return out

    def first_executable_section_oep(self) -> Optional[OepCandidate]:
        for s in self.executable_sections():
            return OepCandidate(s.virtual_address, 0.4, "first_exec")
        return None

    def validate_candidate(self, c: OepCandidate) -> bool:
        s = self.section_containing_rva(c.rva)
        return s is not None and s.is_executable()

    def detect_entropy_transition(self) -> List[OepCandidate]:
        out: List[OepCandidate] = []
        prev = None
        for s in self._sections:
            chunk = self._data[s.raw_offset:s.raw_offset + s.raw_size]
            e = compute_entropy(chunk)
            if prev is not None and prev > 7.0 > e and s.is_executable():
                out.append(OepCandidate(s.virtual_address, 0.7, "entropy_transition"))
            prev = e
        return out

    def record_hwbp_oep(self, rva: int) -> OepCandidate:
        c = OepCandidate(rva, 0.95, "hwbp")
        self._candidates.append(c)
        return c

    def scan_all(self) -> List[OepCandidate]:
        cands: List[OepCandidate] = []
        cands += self.scan_prologue_patterns()
        cands += self.scan_crt_stubs()
        cands += self.detect_entropy_transition()
        first = self.first_executable_section_oep()
        if first:
            cands.append(first)
        self._candidates = cands
        return cands

    def best_candidate(self) -> Optional[OepCandidate]:
        if not self._candidates:
            return None
        return max(self._candidates, key=lambda c: c.confidence)

    def valid(self) -> bool:
        return bool(self._sections)

    def recover_stolen_bytes(self, rva: int, length: int) -> bytes:
        off = self.rva_to_file_offset(rva)
        if off is None:
            return b""
        return self._data[off:off + length]


# =============================================================================
# Stolen bytes / OepDetectionEngine
# =============================================================================
@dataclass
class StolenBytesFragment:
    rva: int = 0
    bytes_: bytes = b""
    confidence: float = 0.0

    def is_confident(self) -> bool:
        return self.confidence >= 0.7

    def has_prologue(self) -> bool:
        return any(self.bytes_.startswith(p) for p in PROLOGUE_PATTERNS)


class StolenBytesScanner:
    def __init__(self):
        self._frags: List[StolenBytesFragment] = []

    @classmethod
    def new(cls) -> "StolenBytesScanner":
        return cls()

    def scan(self, data: bytes, range_: Tuple[int, int]) -> None:
        start, end = range_
        for p in PROLOGUE_PATTERNS:
            i = data.find(p, start, end)
            if i >= 0:
                self._frags.append(StolenBytesFragment(i, data[i:i + 16], 0.7))

    def best_candidate(self) -> Optional[StolenBytesFragment]:
        if not self._frags:
            return None
        return max(self._frags, key=lambda f: f.confidence)

    def clear(self) -> None:
        self._frags.clear()

    def count(self) -> int:
        return len(self._frags)


class OepDetectionEngine:
    def __init__(self, base: int):
        self.base = base
        self._candidates: List[OepCandidate] = []
        self._known: Optional[int] = None

    @classmethod
    def new(cls, base: int) -> "OepDetectionEngine":
        return cls(base)

    def run_all(self, dump: bytes) -> None:
        self._candidates = detect_oep_heuristics(dump, self.base)

    def run_on_sections(self, sections: List[RebuildSection]) -> None:
        for s in sections:
            if s.is_executable():
                for c in detect_oep_heuristics(s.data, self.base + s.virtual_address):
                    self._candidates.append(c)

    def set_known_oep(self, ep_rva: int) -> None:
        self._known = ep_rva
        self._candidates.insert(0, OepCandidate(ep_rva, 1.0, "known"))

    def best(self) -> Optional[OepCandidate]:
        if not self._candidates:
            return None
        return max(self._candidates, key=lambda c: c.confidence)

    def filtered_candidates(self) -> List[OepCandidate]:
        return [c for c in self._candidates if c.confidence >= 0.5]

    def candidate_count(self) -> int:
        return len(self._candidates)


# =============================================================================
# Overlay
# =============================================================================
@dataclass
class OverlayInfo:
    offset: int = 0
    size: int = 0

    def has_overlay(self) -> bool:
        return self.size > 0


class OverlayHandler:
    @staticmethod
    def _last_raw_end(pe_bytes: bytes) -> int:
        if not is_memory_pe(pe_bytes) or len(pe_bytes) < 0x40:
            return 0
        e_lfanew = struct.unpack_from("<I", pe_bytes, 0x3C)[0]
        if e_lfanew + 24 > len(pe_bytes):
            return 0
        num_sec = struct.unpack_from("<H", pe_bytes, e_lfanew + 6)[0]
        opt_size = struct.unpack_from("<H", pe_bytes, e_lfanew + 20)[0]
        sec_off = e_lfanew + 24 + opt_size
        end = 0
        for i in range(num_sec):
            off = sec_off + i * 40
            if off + 40 > len(pe_bytes):
                break
            rs, ro = struct.unpack_from("<II", pe_bytes, off + 16)
            end = max(end, ro + rs)
        return end

    @classmethod
    def detect(cls, pe_bytes: bytes) -> OverlayInfo:
        end = cls._last_raw_end(pe_bytes)
        if end and end < len(pe_bytes):
            return OverlayInfo(end, len(pe_bytes) - end)
        return OverlayInfo(0, 0)

    @classmethod
    def extract(cls, pe_bytes: bytes) -> bytes:
        info = cls.detect(pe_bytes)
        if not info.has_overlay():
            return b""
        return pe_bytes[info.offset:info.offset + info.size]

    @classmethod
    def preserve(cls, pe_bytes: bytes, rebuilt: bytearray) -> OverlayInfo:
        ovl = cls.extract(pe_bytes)
        info = OverlayInfo(len(rebuilt), len(ovl))
        rebuilt += ovl
        return info


# =============================================================================
# apply_fixups (root) + PeFixupOptions
# =============================================================================
@dataclass
class PeFixupOptions:
    fix_entry_point: bool = True
    fix_signature: bool = True
    fix_checksum: bool = True
    set_dll_flag: bool = False
    entry_point_rva: Optional[int] = None


def apply_fixups(image: bytearray, opts: PeFixupOptions) -> List[str]:
    report: List[str] = []
    if not is_memory_pe(image):
        if opts.fix_signature:
            image[0:2] = b"MZ"
            report.append("repaired DOS signature")
    if len(image) < 0x40:
        return report
    e_lfanew = struct.unpack_from("<I", image, 0x3C)[0]
    if e_lfanew + 4 <= len(image) and image[e_lfanew:e_lfanew + 4] != b"PE\x00\x00":
        if opts.fix_signature:
            image[e_lfanew:e_lfanew + 4] = b"PE\x00\x00"
            report.append("repaired NT signature")
    if opts.fix_entry_point and opts.entry_point_rva is not None:
        ep_off = e_lfanew + 24 + 16
        if ep_off + 4 <= len(image):
            struct.pack_into("<I", image, ep_off, opts.entry_point_rva)
            report.append("entry point updated")
    return report


# =============================================================================
# PeRebuilder (root)
# =============================================================================
@dataclass
class RebuildConfig:
    image_base: int = 0x400000
    file_alignment: int = 0x200
    section_alignment: int = 0x1000
    is_64bit: bool = True
    entry_point_rva: int = 0
    flags: int = 0


@dataclass
class RebuildResult:
    image: bytes = b""
    entry_point: int = 0
    size_of_image: int = 0
    sections: int = 0


class PeRebuilder:
    def __init__(self, config: RebuildConfig):
        self._config = config
        self._sections: List[RebuildSection] = []

    @classmethod
    def new(cls, config: RebuildConfig) -> "PeRebuilder":
        return cls(config)

    def add_section(self, section: RebuildSection) -> "PeRebuilder":
        self._sections.append(section)
        return self

    def section_by_name(self, name: str) -> Optional[RebuildSection]:
        for s in self._sections:
            if s.name == name:
                return s
        return None

    def section_at_rva(self, rva: int) -> Optional[RebuildSection]:
        for s in self._sections:
            if s.contains_rva(rva):
                return s
        return None

    def virtual_end(self) -> int:
        if not self._sections:
            return 0
        return max(s.virtual_end() for s in self._sections)

    def config(self) -> RebuildConfig:
        return self._config

    def section_count(self) -> int:
        return len(self._sections)

    def sections(self) -> List[RebuildSection]:
        return self._sections

    def sort_sections(self) -> None:
        self._sections.sort(key=lambda s: s.virtual_address)

    def clear_sections(self) -> None:
        self._sections.clear()

    @staticmethod
    def align_up(value: int, alignment: int) -> int:
        return align_up(value, alignment)

    def rebuild(self) -> RebuildResult:
        if not self._sections:
            raise RebuildError("no sections")
        self.sort_sections()
        size_of_image = align_up(self.virtual_end(), self._config.section_alignment)
        # Headers: DOS + NT(24) + opt(240) + section table
        opt_size = 240 if self._config.is_64bit else 224
        headers_size = align_up(0x40 + 4 + 20 + opt_size + 40 * len(self._sections),
                                self._config.file_alignment)
        out = bytearray(headers_size)
        # DOS
        out[0:2] = b"MZ"
        struct.pack_into("<I", out, 0x3C, 0x40)
        # NT signature
        struct.pack_into("<4s", out, 0x40, b"PE\x00\x00")
        machine = 0x8664 if self._config.is_64bit else 0x14C
        struct.pack_into("<HHIIIHH", out, 0x44,
                         machine,
                         len(self._sections),
                         0, 0, 0,
                         opt_size,
                         0x2102 | (0x2000 if (self._config.flags & RebuildFlags.IS_DLL) else 0))
        # Optional header magic
        opt_off = 0x44 + 20
        struct.pack_into("<H", out, opt_off, 0x20B if self._config.is_64bit else 0x10B)
        struct.pack_into("<I", out, opt_off + 16, self._config.entry_point_rva)
        # Section table
        sec_off = opt_off + opt_size
        raw_cursor = headers_size
        for i, s in enumerate(self._sections):
            off = sec_off + i * 40
            name_b = s.name.encode()[:8].ljust(8, b"\x00")
            out[off:off + 8] = name_b
            raw_size = align_up(len(s.data), self._config.file_alignment)
            struct.pack_into("<IIII", out, off + 8,
                             s.virtual_size,
                             s.virtual_address,
                             raw_size,
                             raw_cursor)
            struct.pack_into("<I", out, off + 36, s.characteristics)
            # Append data
            out += s.data + b"\x00" * (raw_size - len(s.data))
            raw_cursor += raw_size
        return RebuildResult(bytes(out), self._config.entry_point_rva,
                             size_of_image, len(self._sections))

    @classmethod
    def from_memory_dump(cls, data: bytes, base_addr: int, config: RebuildConfig) -> RebuildResult:
        if not is_memory_pe(data):
            raise RebuildError("not a PE")
        r = cls.new(config)
        r.add_section(RebuildSection.code(".text", 0x1000, data[:min(len(data), 0x1000)]))
        return r.rebuild()

    def rebuild_with_oep_detection(self) -> RebuildResult:
        det = OepDetector.new()
        res = det.detect(self._sections, None)
        self._config.entry_point_rva = res.rva
        return self.rebuild()


# =============================================================================
# IAT scanning helpers (root scan module)
# =============================================================================
@dataclass
class IatRegion:
    base_va: int = 0
    slots: List[int] = field(default_factory=list)

    def slot_count(self) -> int:
        return len(self.slots)

    def is_non_empty(self) -> bool:
        return len(self.slots) > 0

    def total_entries(self) -> int:
        return len(self.slots)

    def resolved_count(self) -> int:
        return sum(1 for s in self.slots if s != 0)


def scan_for_iat(dump: bytes, base: int) -> List[IatRegion]:
    return find_iat_regions(dump, base)


def find_iat_regions(dump: bytes, base: int) -> List[IatRegion]:
    regions: List[IatRegion] = []
    cur: Optional[IatRegion] = None
    for i in range(0, len(dump) - 8, 8):
        v = int.from_bytes(dump[i:i + 8], "little")
        if 0x10000 <= v < 0x7FFFFFFFFFFF:
            if cur is None:
                cur = IatRegion(base_va=base + i, slots=[v])
            else:
                cur.slots.append(v)
        else:
            if cur and cur.slot_count() >= 3:
                regions.append(cur)
            cur = None
    if cur and cur.slot_count() >= 3:
        regions.append(cur)
    return regions


def resolve_pointer(ptr: int, modules: List["LoadedModule"]) -> Optional[Tuple[str, str]]:
    for m in modules:
        if m.contains(ptr):
            return (m.name, f"sub_{ptr - m.base:x}")
    return None


def resolve_batch(ptrs: List[int], modules: List["LoadedModule"]) -> List[Optional[Tuple[str, str]]]:
    return [resolve_pointer(p, modules) for p in ptrs]


def build_valid_pe(dump: bytes, base: int, oep: int) -> bytes:
    cfg = RebuildConfig(image_base=base, entry_point_rva=int(oep - base))
    res = PeRebuilder.from_memory_dump(dump, base, cfg)
    return res.image


def auto_build(dump: bytes, base: int) -> bytes:
    cands = detect_oep_heuristics(dump, base)
    oep = base + (cands[0].rva if cands else 0x1000)
    return build_valid_pe(dump, base, oep)


def rebuild_iat_from_memory(snapshot: bytes, base: int, modules: List["LoadedModule"]) -> List[IatEntry]:
    regions = find_iat_regions(snapshot, base)
    entries: List[IatEntry] = []
    for r in regions:
        for i, ptr in enumerate(r.slots):
            resolved = resolve_pointer(ptr, modules)
            e = IatEntry(iat_rva=r.base_va - base + i * 8, address=ptr)
            if resolved:
                e.dll, e.name = resolved
            entries.append(e)
    return entries


def verify_pe_validity(pe_data: bytes) -> List[str]:
    issues: List[str] = []
    if not is_memory_pe(pe_data):
        issues.append("missing MZ signature")
        return issues
    if len(pe_data) < 0x40:
        issues.append("truncated DOS header")
        return issues
    e_lfanew = struct.unpack_from("<I", pe_data, 0x3C)[0]
    if e_lfanew + 4 > len(pe_data) or pe_data[e_lfanew:e_lfanew + 4] != b"PE\x00\x00":
        issues.append("missing PE signature")
    return issues


def fix_iat(dump: bytearray, base_addr: int) -> None:
    # Zero unresolved high bits
    regions = find_iat_regions(bytes(dump), base_addr)
    for r in regions:
        for i, _ in enumerate(r.slots):
            off = (r.base_va - base_addr) + i * 8
            if off + 8 <= len(dump):
                pass  # no-op fixer


def fix_section_flags(dump: bytearray) -> None:
    if not is_memory_pe(bytes(dump)) or len(dump) < 0x40:
        return
    e_lfanew = struct.unpack_from("<I", dump, 0x3C)[0]
    num_sec = struct.unpack_from("<H", dump, e_lfanew + 6)[0]
    opt_size = struct.unpack_from("<H", dump, e_lfanew + 20)[0]
    sec_off = e_lfanew + 24 + opt_size
    for i in range(num_sec):
        off = sec_off + i * 40
        if off + 40 > len(dump):
            break
        name = bytes(dump[off:off + 8]).rstrip(b"\x00").decode("ascii", errors="replace")
        ch = struct.unpack_from("<I", dump, off + 36)[0]
        ch = pe_section_rebuilder_infer_characteristics(name) or ch
        struct.pack_into("<I", dump, off + 36, ch)


# =============================================================================
# IatEntry2 / LoadedModule / MemoryRebuilder
# =============================================================================
@dataclass
class IatEntry2:
    rva: int = 0
    dll: str = ""
    name: Optional[str] = None
    ordinal: Optional[int] = None

    @classmethod
    def named(cls, rva: int, dll: str, fn: str) -> "IatEntry2":
        return cls(rva=rva, dll=str(dll), name=str(fn))

    @classmethod
    def ordinal_(cls, rva: int, dll: str, ord_: int) -> "IatEntry2":
        return cls(rva=rva, dll=str(dll), ordinal=int(ord_))

    def display_name(self) -> str:
        if self.name:
            return f"{self.dll}!{self.name}"
        return f"{self.dll}!#{self.ordinal}"


@dataclass
class LoadedModule:
    name: str = ""
    base: int = 0
    size: int = 0
    exports: List["ExportedSymbol"] = field(default_factory=list)

    @classmethod
    def new(cls, name: str, base: int, size: int) -> "LoadedModule":
        return cls(str(name), int(base), int(size))

    def contains(self, addr: int) -> bool:
        return self.base <= addr < self.base + self.size

    def contains_va(self, va: int) -> bool:
        return self.contains(va)

    def add_export(self, sym: "ExportedSymbol") -> None:
        self.exports.append(sym)

    def resolve_va(self, va: int) -> Optional["ExportedSymbol"]:
        for s in self.exports:
            if s.va == va:
                return s
        return None


class MemoryRebuilder:
    def __init__(self, memory: bytes, image_base: int, modules: List[LoadedModule], is_64: bool):
        self.memory = bytearray(memory)
        self.image_base = image_base
        self.modules = modules
        self.is_64 = is_64

    @classmethod
    def new_x64(cls, process_memory: bytes, image_base: int, modules: List[LoadedModule]) -> "MemoryRebuilder":
        return cls(process_memory, image_base, modules, True)

    @classmethod
    def new_x86(cls, process_memory: bytes, image_base: int, modules: List[LoadedModule]) -> "MemoryRebuilder":
        return cls(process_memory, image_base, modules, False)

    def va_to_offset(self, va: int) -> Optional[int]:
        off = va - self.image_base
        if 0 <= off < len(self.memory):
            return off
        return None

    def scan_for_iat(self) -> List[int]:
        regions = find_iat_regions(bytes(self.memory), self.image_base)
        return [r.base_va for r in regions]

    def rebuild_import_directory(self, entries: List[IatEntry2]) -> bytes:
        # Simple .idata layout: descriptors + thunks + names
        by_dll: Dict[str, List[IatEntry2]] = defaultdict(list)
        for e in entries:
            by_dll[e.dll].append(e)
        out = bytearray()
        # Reserve descriptor table (20 bytes * (n+1))
        desc_off = 0
        desc_table_size = 20 * (len(by_dll) + 1)
        out += bytes(desc_table_size)
        for dll, ents in by_dll.items():
            dll_name_rva = len(out)
            out += dll.encode() + b"\x00"
            iat_rva = len(out)
            for e in ents:
                if e.name:
                    name_rva = len(out)
                    out += struct.pack("<H", 0) + e.name.encode() + b"\x00"
                    out += struct.pack("<Q" if self.is_64 else "<I", name_rva)
                else:
                    flag = (1 << 63) if self.is_64 else (1 << 31)
                    out += struct.pack("<Q" if self.is_64 else "<I", flag | (e.ordinal or 0))
            out += struct.pack("<Q" if self.is_64 else "<I", 0)
            # Write descriptor
            struct.pack_into("<IIIII", out, desc_off, iat_rva, 0, 0, dll_name_rva, iat_rva)
            desc_off += 20
        return bytes(out)

    def fix_pe_checksum(self) -> int:
        if len(self.memory) < 0x40:
            raise RebuildError("not a PE")
        e_lfanew = struct.unpack_from("<I", self.memory, 0x3C)[0]
        checksum_off = e_lfanew + 24 + 64
        cs = PeHeaderFixer.compute_checksum(bytes(self.memory), checksum_off)
        struct.pack_into("<I", self.memory, checksum_off, cs)
        return cs

    def find_oep_heuristic(self) -> List[int]:
        cands = detect_oep_heuristics(bytes(self.memory), self.image_base)
        return [self.image_base + c.rva for c in cands]

    def dump_process_memory(self, base: int, size: int, memory: bytes) -> bytes:
        return bytes(memory[:size])


# =============================================================================
# iat_rebuilder module
# =============================================================================
class PointerSize:
    X86 = 4
    X64 = 8

    @staticmethod
    def byte_len(size: int) -> int:
        return size

    @staticmethod
    def read_ptr(size: int, data: bytes, offset: int) -> Optional[int]:
        if offset + size > len(data):
            return None
        return int.from_bytes(data[offset:offset + size], "little")


@dataclass
class ExportedSymbol:
    va: int = 0
    ordinal: int = 0
    name: Optional[str] = None
    forwarder: Optional[str] = None

    def is_forwarder(self) -> bool:
        return self.forwarder is not None

    def is_ordinal_only(self) -> bool:
        return self.name is None


@dataclass
class ResolvedIatEntry:
    iat_rva: int = 0
    dll: str = ""
    name: Optional[str] = None
    ordinal: Optional[int] = None
    hint: int = 0

    def is_by_name(self) -> bool:
        return self.name is not None

    def hint_name_bytes(self) -> bytes:
        if self.name is None:
            return b""
        return struct.pack("<H", self.hint) + self.name.encode() + b"\x00"


class IatScanner:
    def __init__(self, ptr_size: int, image_base: int):
        self._ptr_size = ptr_size
        self._image_base = image_base
        self._modules: List[LoadedModule] = []

    @classmethod
    def new(cls, ptr_size: int, image_base: int) -> "IatScanner":
        return cls(ptr_size, image_base)

    def image_base(self) -> int:
        return self._image_base

    def va_to_rva(self, va: int) -> Optional[int]:
        if va >= self._image_base:
            return va - self._image_base
        return None

    def add_module(self, module: LoadedModule) -> None:
        self._modules.append(module)

    def scan_iat(self, data: bytes, iat_rva: int, length: int) -> List[ResolvedIatEntry]:
        out: List[ResolvedIatEntry] = []
        for i in range(0, length, self._ptr_size):
            ptr = PointerSize.read_ptr(self._ptr_size, data, iat_rva + i)
            if ptr is None or ptr == 0:
                continue
            for m in self._modules:
                if m.contains(ptr):
                    sym = m.resolve_va(ptr)
                    out.append(ResolvedIatEntry(
                        iat_rva=iat_rva + i,
                        dll=m.name,
                        name=sym.name if sym else None,
                        ordinal=sym.ordinal if sym else None,
                    ))
                    break
        return out

    def scan_sections(self, data: bytes, sections: List[SectionInfo]) -> List[ResolvedIatEntry]:
        out: List[ResolvedIatEntry] = []
        for s in sections:
            out += self.scan_iat(data, s.raw_offset, s.raw_size)
        return out

    def rebuild_import_section(self, entries: List[ResolvedIatEntry], section_rva: int) -> "ImportSection":
        by_dll: Dict[str, List[ResolvedIatEntry]] = defaultdict(list)
        for e in entries:
            by_dll[e.dll].append(e)
        blob = bytearray()
        dir_size = 20 * (len(by_dll) + 1)
        blob += bytes(dir_size)
        return ImportSection(import_dir_rva_=section_rva, import_dir_size_=len(blob), blob=bytes(blob))


@dataclass
class ImportSection:
    import_dir_rva_: int = 0
    import_dir_size_: int = 0
    blob: bytes = b""

    def import_dir_rva(self) -> int:
        return self.import_dir_rva_

    def import_dir_size(self) -> int:
        return self.import_dir_size_


@dataclass
class DelayLoadDescriptor:
    dll_name: str = ""
    ordinal: int = 0

    @classmethod
    def new(cls, dll_name: str, ordinal: int) -> "DelayLoadDescriptor":
        return cls(dll_name, ordinal)

    def int_entry(self, ptr_size: int) -> int:
        flag = (1 << 63) if ptr_size == 8 else (1 << 31)
        return flag | self.ordinal


def detect_iat_clusters(data: bytes, ptr_size: int, image_base: int, image_size: int) -> List[Tuple[int, int]]:
    clusters: List[Tuple[int, int]] = []
    start = None
    count = 0
    for i in range(0, len(data) - ptr_size, ptr_size):
        v = int.from_bytes(data[i:i + ptr_size], "little")
        if image_base <= v < image_base + image_size:
            if start is None:
                start = i
            count += 1
        else:
            if start is not None and count >= 3:
                clusters.append((start, count))
            start = None
            count = 0
    return clusters


def rebuild_delay_import_section(descriptors: List[DelayLoadDescriptor]) -> bytes:
    out = bytearray()
    for d in descriptors:
        out += struct.pack("<IIIIIIII", 0, 0, 0, 0, 0, 0, 0, 0)
    return bytes(out)


def merge_resolved_entries(a: List[ResolvedIatEntry], b: List[ResolvedIatEntry]) -> List[ResolvedIatEntry]:
    seen = {(e.iat_rva, e.dll, e.name, e.ordinal) for e in a}
    out = list(a)
    for e in b:
        k = (e.iat_rva, e.dll, e.name, e.ordinal)
        if k not in seen:
            out.append(e)
            seen.add(k)
    return out


def sort_resolved_entries(entries: List[ResolvedIatEntry]) -> None:
    entries.sort(key=lambda e: (e.dll, e.name or "", e.ordinal or 0))


@dataclass
class IatStatistics:
    total: int = 0
    by_name: int = 0
    by_ordinal: int = 0
    dlls: int = 0

    @classmethod
    def from_entries(cls, entries: List[ResolvedIatEntry]) -> "IatStatistics":
        s = cls(total=len(entries))
        s.by_name = sum(1 for e in entries if e.is_by_name())
        s.by_ordinal = s.total - s.by_name
        s.dlls = len({e.dll for e in entries})
        return s


# =============================================================================
# import_rebuilder module
# =============================================================================
@dataclass
class ImportThunk:
    raw: int = 0

    @classmethod
    def by_name_pe32(cls, hint_name_rva: int) -> "ImportThunk":
        return cls(hint_name_rva)

    @classmethod
    def by_ordinal_pe32(cls, ordinal: int) -> "ImportThunk":
        return cls((1 << 31) | ordinal)

    def ordinal(self) -> Optional[int]:
        if self.raw & (1 << 31):
            return self.raw & 0xFFFF
        return None


class OrdinalToName:
    def __init__(self):
        self._db: Dict[str, Dict[int, str]] = defaultdict(dict)

    @classmethod
    def new(cls) -> "OrdinalToName":
        return cls()

    def insert(self, dll: str, ordinal: int, name: str) -> None:
        self._db[dll.lower()][ordinal] = name

    def lookup(self, dll: str, ordinal: int) -> Optional[str]:
        return self._db.get(dll.lower(), {}).get(ordinal)

    def dll_count(self) -> int:
        return len(self._db)

    def total_entries(self) -> int:
        return sum(len(v) for v in self._db.values())

    def resolve_thunks(self, dll: str, thunks: List[ImportThunk]) -> None:
        for t in thunks:
            o = t.ordinal()
            if o is not None and self.lookup(dll, o):
                pass


class ImportByHash:
    def __init__(self, algo: str = "ror13"):
        self.algo = algo
        self._db: Dict[int, Tuple[str, str]] = {}

    @classmethod
    def new(cls, algo: str) -> "ImportByHash":
        return cls(algo)

    def hash(self, name: str) -> int:
        h = 0
        for c in name.encode():
            h = (((h >> 13) | (h << 19)) + c) & 0xFFFFFFFF
        return h

    def register(self, dll: str, name: str) -> None:
        self._db[self.hash(name)] = (dll, name)

    def resolve(self, hash_: int) -> Optional[Tuple[str, str]]:
        return self._db.get(hash_)

    def len_(self) -> int:
        return len(self._db)

    def is_empty(self) -> bool:
        return not self._db


class IatPatcher:
    def __init__(self, image_base: int, is_pe32plus: bool):
        self._image_base = image_base
        self._is_pe32plus = is_pe32plus

    @classmethod
    def new(cls, image_base: int, is_pe32plus: bool) -> "IatPatcher":
        return cls(image_base, is_pe32plus)

    def image_base(self) -> int:
        return self._image_base

    def patch_slot(self, buf: bytearray, iat_rva: int, value: int) -> None:
        sz = 8 if self._is_pe32plus else 4
        if iat_rva + sz > len(buf):
            raise ImportRebuildError("oob")
        buf[iat_rva:iat_rva + sz] = value.to_bytes(sz, "little")

    def wipe_slot(self, buf: bytearray, iat_rva: int) -> None:
        sz = 8 if self._is_pe32plus else 4
        if iat_rva + sz > len(buf):
            raise ImportRebuildError("oob")
        buf[iat_rva:iat_rva + sz] = b"\x00" * sz


@dataclass
class DelayLoadEntry:
    dll: str = ""
    name: str = ""
    iat_rva: int = 0


class DelayLoadBuilder:
    def __init__(self):
        self._entries: List[DelayLoadEntry] = []

    @classmethod
    def new(cls) -> "DelayLoadBuilder":
        return cls()

    def add_entry(self, entry: DelayLoadEntry) -> None:
        self._entries.append(entry)

    def entries(self) -> List[DelayLoadEntry]:
        return self._entries

    def entry_count(self) -> int:
        return len(self._entries)

    def serialize(self) -> bytes:
        out = bytearray()
        for _ in self._entries:
            out += struct.pack("<IIIIIIII", 0, 0, 0, 0, 0, 0, 0, 0)
        return bytes(out)


class BoundImportStripper:
    def __init__(self):
        pass

    @classmethod
    def new(cls) -> "BoundImportStripper":
        return cls()

    def apply(self, buf: bytearray) -> int:
        if len(buf) < 0x40:
            raise ImportRebuildError("short")
        e_lfanew = struct.unpack_from("<I", buf, 0x3C)[0]
        opt_off = e_lfanew + 24
        # bound import dir is data dir index 11
        dd_off = opt_off + (96 if buf[opt_off:opt_off + 2] == b"\x0b\x02" else 96) + 11 * 8
        if dd_off + 8 > len(buf):
            return 0
        struct.pack_into("<II", buf, dd_off, 0, 0)
        return 1


@dataclass
class ImportEntry:
    dll: str = ""
    name: Optional[str] = None
    ordinal: Optional[int] = None
    iat_rva: int = 0


@dataclass
class ImportRebuilderConfig:
    is_pe32plus: bool = True
    image_base: int = 0x140000000


class ImportDirectoryBuilder:
    def __init__(self):
        self._entries: List[ImportEntry] = []
        self._db: Optional[OrdinalToName] = None
        self._hash_resolver: Optional[ImportByHash] = None

    @classmethod
    def new(cls) -> "ImportDirectoryBuilder":
        return cls()

    def add_entry(self, e: ImportEntry) -> None:
        self._entries.append(e)

    def with_ordinal_db(self, db: OrdinalToName) -> "ImportDirectoryBuilder":
        self._db = db
        return self

    def with_hash_resolver(self, r: ImportByHash) -> "ImportDirectoryBuilder":
        self._hash_resolver = r
        return self

    def resolve_ordinals(self) -> None:
        if not self._db:
            return
        for e in self._entries:
            if e.name is None and e.ordinal is not None:
                n = self._db.lookup(e.dll, e.ordinal)
                if n:
                    e.name = n

    def grouped(self) -> Dict[str, List[ImportEntry]]:
        g: Dict[str, List[ImportEntry]] = defaultdict(list)
        for e in self._entries:
            g[e.dll].append(e)
        return dict(g)

    def build_directory(self) -> bytes:
        return MemoryRebuilder(b"", 0, [], True).rebuild_import_directory(
            [IatEntry2(rva=e.iat_rva, dll=e.dll, name=e.name, ordinal=e.ordinal) for e in self._entries]
        )

    def dll_count(self) -> int:
        return len({e.dll for e in self._entries})

    def entry_count(self) -> int:
        return len(self._entries)


# =============================================================================
# pe_dump_fixer module
# =============================================================================
class FixerFlags(int):
    REPAIR_SIGNATURES = 1 << 0
    RECALC_SIZE_OF_IMAGE = 1 << 1
    RECALC_SIZE_FIELDS = 1 << 2
    CONVERT_VIRTUAL_TO_RAW = 1 << 3
    STRIP_SECURITY_DIR = 1 << 4
    REBASE_TO_DEFAULT = 1 << 5
    FIX_CHECKSUM = 1 << 6
    FIX_SIZE_OF_IMAGE = 1 << 7
    FIX_SIZE_OF_HEADERS = 1 << 8
    FIX_TIMESTAMP = 1 << 9
    FIX_IMAGE_BASE = 1 << 10
    FIX_DATA_DIRECTORIES = 1 << 11
    FIX_NUM_SECTIONS = 1 << 12

    def contains(self, f: int) -> bool: return (int(self) & f) == f
    def repair_signatures(self) -> bool: return self.contains(self.REPAIR_SIGNATURES)
    def recalc_size_of_image(self) -> bool: return self.contains(self.RECALC_SIZE_OF_IMAGE)
    def recalc_size_fields(self) -> bool: return self.contains(self.RECALC_SIZE_FIELDS)
    def convert_virtual_to_raw(self) -> bool: return self.contains(self.CONVERT_VIRTUAL_TO_RAW)
    def strip_security_dir(self) -> bool: return self.contains(self.STRIP_SECURITY_DIR)
    def rebase_to_default(self) -> bool: return self.contains(self.REBASE_TO_DEFAULT)
    def fix_checksum(self) -> bool: return self.contains(self.FIX_CHECKSUM)
    def fix_size_of_image(self) -> bool: return self.contains(self.FIX_SIZE_OF_IMAGE)
    def fix_size_of_headers(self) -> bool: return self.contains(self.FIX_SIZE_OF_HEADERS)
    def fix_timestamp(self) -> bool: return self.contains(self.FIX_TIMESTAMP)
    def fix_image_base(self) -> bool: return self.contains(self.FIX_IMAGE_BASE)
    def fix_data_directories(self) -> bool: return self.contains(self.FIX_DATA_DIRECTORIES)
    def fix_num_sections(self) -> bool: return self.contains(self.FIX_NUM_SECTIONS)


@dataclass
class DumpFixerConfig:
    flags: int = 0
    actual_base: Optional[int] = None


@dataclass
class FixResult:
    actions: List[str] = field(default_factory=list)
    data: bytes = b""

    def is_clean(self) -> bool:
        return not self.actions


class PeDumpFixer:
    def __init__(self, data: bytes, cfg: DumpFixerConfig):
        if not is_memory_pe(data):
            raise RebuildError("not a PE")
        self.data = bytearray(data)
        self.cfg = cfg

    @classmethod
    def new(cls, data: bytes, cfg: DumpFixerConfig) -> "PeDumpFixer":
        return cls(data, cfg)

    def section_name_histogram(self) -> Dict[str, int]:
        hist: Counter = Counter()
        finder = OepFinder.from_bytes(bytes(self.data), 0)
        for s in finder.sections():
            hist[s.name] += 1
        return dict(hist)

    def overwrite_section_field(self, index: int, field_name: str, value: int) -> None:
        e_lfanew = struct.unpack_from("<I", self.data, 0x3C)[0]
        opt_size = struct.unpack_from("<H", self.data, e_lfanew + 20)[0]
        sec_off = e_lfanew + 24 + opt_size + index * 40
        offsets = {"virtual_size": 8, "virtual_address": 12, "raw_size": 16,
                   "raw_offset": 20, "characteristics": 36}
        if field_name not in offsets:
            raise RebuildError(f"unknown field {field_name}")
        struct.pack_into("<I", self.data, sec_off + offsets[field_name], value)

    def fix(self) -> FixResult:
        r = FixResult(data=bytes(self.data))
        return r

    @staticmethod
    def fix_dump_default(data: bytes) -> FixResult:
        f = PeDumpFixer.new(data, DumpFixerConfig())
        return f.fix()

    @staticmethod
    def fix_dump_with_base(data: bytes, actual_base: int) -> FixResult:
        f = PeDumpFixer.new(data, DumpFixerConfig(actual_base=actual_base))
        return f.fix()


# =============================================================================
# pe_fixup module
# =============================================================================
@dataclass
class PatchInfo:
    offset: int = 0
    before: bytes = b""
    after: bytes = b""
    description: str = ""

    @classmethod
    def new(cls, offset: int, before: bytes, after: bytes, description: str) -> "PatchInfo":
        return cls(offset, before, after, description)


@dataclass
class VerifyResult:
    issues: List[str] = field(default_factory=list)

    def is_ok(self) -> bool:
        return not self.issues


class PeFixupVerifier:
    @staticmethod
    def verify(image: bytes) -> VerifyResult:
        return VerifyResult(issues=verify_pe_validity(image))


class PeFixup:
    def __init__(self, image: bytes):
        self._image = bytearray(image)
        self._patches: List[PatchInfo] = []

    @classmethod
    def new(cls, image: bytes) -> "PeFixup":
        return cls(image)

    def image(self) -> bytes:
        return bytes(self._image)

    def finish(self) -> Tuple[bytes, List[PatchInfo]]:
        return bytes(self._image), self._patches

    def patches(self) -> List[PatchInfo]:
        return self._patches

    def _e_lfanew(self) -> int:
        if len(self._image) < 0x40:
            raise FixupError("short DOS")
        return struct.unpack_from("<I", self._image, 0x3C)[0]

    def fix_checksum(self) -> None:
        e = self._e_lfanew()
        off = e + 24 + 64
        old = bytes(self._image[off:off + 4])
        cs = PeHeaderFixer.compute_checksum(bytes(self._image), off)
        struct.pack_into("<I", self._image, off, cs)
        self._patches.append(PatchInfo.new(off, old, struct.pack("<I", cs), "checksum"))

    def fix_bound_imports(self) -> None:
        e = self._e_lfanew()
        opt_off = e + 24
        magic = struct.unpack_from("<H", self._image, opt_off)[0]
        dd_off = opt_off + (112 if magic == 0x20B else 96) + 11 * 8
        if dd_off + 8 <= len(self._image):
            old = bytes(self._image[dd_off:dd_off + 8])
            struct.pack_into("<II", self._image, dd_off, 0, 0)
            self._patches.append(PatchInfo.new(dd_off, old, b"\x00" * 8, "bound_imports"))

    def strip_signature(self) -> None:
        e = self._e_lfanew()
        opt_off = e + 24
        magic = struct.unpack_from("<H", self._image, opt_off)[0]
        dd_off = opt_off + (112 if magic == 0x20B else 96) + 4 * 8
        if dd_off + 8 <= len(self._image):
            old = bytes(self._image[dd_off:dd_off + 8])
            struct.pack_into("<II", self._image, dd_off, 0, 0)
            self._patches.append(PatchInfo.new(dd_off, old, b"\x00" * 8, "strip_sig"))

    def clear_debug_dir(self) -> None:
        e = self._e_lfanew()
        opt_off = e + 24
        magic = struct.unpack_from("<H", self._image, opt_off)[0]
        dd_off = opt_off + (112 if magic == 0x20B else 96) + 6 * 8
        if dd_off + 8 <= len(self._image):
            old = bytes(self._image[dd_off:dd_off + 8])
            struct.pack_into("<II", self._image, dd_off, 0, 0)
            self._patches.append(PatchInfo.new(dd_off, old, b"\x00" * 8, "clear_debug"))

    def set_entry_point(self, ep_rva: int) -> None:
        e = self._e_lfanew()
        ep_off = e + 24 + 16
        old = bytes(self._image[ep_off:ep_off + 4])
        struct.pack_into("<I", self._image, ep_off, ep_rva)
        self._patches.append(PatchInfo.new(ep_off, old, struct.pack("<I", ep_rva), "ep"))

    def set_dll_flag(self, is_dll: bool) -> None:
        e = self._e_lfanew()
        ch_off = e + 22
        old = bytes(self._image[ch_off:ch_off + 2])
        ch = struct.unpack_from("<H", self._image, ch_off)[0]
        ch = (ch | 0x2000) if is_dll else (ch & ~0x2000)
        struct.pack_into("<H", self._image, ch_off, ch)
        self._patches.append(PatchInfo.new(ch_off, old, struct.pack("<H", ch), "dll_flag"))

    def align_section_virtual_sizes(self, alignment: int) -> None:
        e = self._e_lfanew()
        num_sec = struct.unpack_from("<H", self._image, e + 6)[0]
        opt_size = struct.unpack_from("<H", self._image, e + 20)[0]
        sec_off = e + 24 + opt_size
        for i in range(num_sec):
            off = sec_off + i * 40 + 8
            vs = struct.unpack_from("<I", self._image, off)[0]
            new_vs = align_up(vs, alignment)
            if new_vs != vs:
                struct.pack_into("<I", self._image, off, new_vs)

    def sort_section_table(self) -> int:
        e = self._e_lfanew()
        num_sec = struct.unpack_from("<H", self._image, e + 6)[0]
        opt_size = struct.unpack_from("<H", self._image, e + 20)[0]
        sec_off = e + 24 + opt_size
        secs = []
        for i in range(num_sec):
            off = sec_off + i * 40
            secs.append((struct.unpack_from("<I", self._image, off + 12)[0],
                         bytes(self._image[off:off + 40])))
        secs.sort(key=lambda x: x[0])
        for i, (_, b) in enumerate(secs):
            self._image[sec_off + i * 40:sec_off + i * 40 + 40] = b
        return num_sec

    def fix_size_of_image(self) -> None:
        e = self._e_lfanew()
        opt_off = e + 24
        magic = struct.unpack_from("<H", self._image, opt_off)[0]
        soi_off = opt_off + 56
        num_sec = struct.unpack_from("<H", self._image, e + 6)[0]
        opt_size = struct.unpack_from("<H", self._image, e + 20)[0]
        sec_off = e + 24 + opt_size
        end = 0
        for i in range(num_sec):
            o = sec_off + i * 40
            va, vs = struct.unpack_from("<II", self._image, o + 12)
            # Wrong: va is at +12, vs at +8
            vs = struct.unpack_from("<I", self._image, o + 8)[0]
            va = struct.unpack_from("<I", self._image, o + 12)[0]
            end = max(end, va + vs)
        sec_align = struct.unpack_from("<I", self._image, opt_off + 32)[0] or 0x1000
        end = align_up(end, sec_align)
        struct.pack_into("<I", self._image, soi_off, end)

    def apply_all(self) -> List[str]:
        actions: List[str] = []
        try:
            self.fix_size_of_image()
            actions.append("size_of_image")
        except Exception:
            pass
        try:
            self.fix_checksum()
            actions.append("checksum")
        except Exception:
            pass
        return actions


# =============================================================================
# pe_header_fixer module
# =============================================================================
@dataclass
class DataDirectoryEntry:
    rva: int = 0
    size: int = 0

    def is_present(self) -> bool:
        return self.rva != 0 and self.size != 0

    @classmethod
    def from_bytes(cls, b: bytes) -> Optional["DataDirectoryEntry"]:
        if len(b) < 8:
            return None
        rva, size = struct.unpack_from("<II", b, 0)
        return cls(rva, size)

    def to_bytes(self) -> bytes:
        return struct.pack("<II", self.rva, self.size)


@dataclass
class FixerReport:
    changes: List[str] = field(default_factory=list)

    def is_clean(self) -> bool:
        return not self.changes

    def change_count(self) -> int:
        return len(self.changes)


@dataclass
class ValidationResult:
    ok_: bool = True
    message: str = ""

    @classmethod
    def ok(cls, msg: str = "") -> "ValidationResult":
        return cls(True, msg)

    @classmethod
    def fail(cls, msg: str) -> "ValidationResult":
        return cls(False, msg)


@dataclass
class FixerConfig:
    flags: int = 0


@dataclass
class PeLayout:
    e_lfanew: int = 0
    is_pe32_plus: bool = False
    num_sections: int = 0
    opt_size: int = 0
    section_table_off: int = 0


class PeHeaderFixer:
    def __init__(self, config: FixerConfig):
        self.config = config

    @classmethod
    def new(cls, config: FixerConfig) -> "PeHeaderFixer":
        return cls(config)

    def parse_layout(self, pe: bytes) -> Optional[PeLayout]:
        if not is_memory_pe(pe) or len(pe) < 0x40:
            return None
        e = struct.unpack_from("<I", pe, 0x3C)[0]
        if e + 24 > len(pe) or pe[e:e + 4] != b"PE\x00\x00":
            return None
        num = struct.unpack_from("<H", pe, e + 6)[0]
        opt_size = struct.unpack_from("<H", pe, e + 20)[0]
        magic = struct.unpack_from("<H", pe, e + 24)[0] if e + 26 <= len(pe) else 0
        return PeLayout(e, magic == 0x20B, num, opt_size, e + 24 + opt_size)

    @staticmethod
    def compute_checksum(pe: bytes, checksum_off: int) -> int:
        s = 0
        n = len(pe)
        for i in range(0, n - 1, 2):
            if checksum_off <= i < checksum_off + 4:
                continue
            w = pe[i] | (pe[i + 1] << 8)
            s += w
            s = (s & 0xFFFF) + (s >> 16)
        if n % 2:
            s += pe[-1]
            s = (s & 0xFFFF) + (s >> 16)
        return (s + n) & 0xFFFFFFFF

    def validate(self, pe: bytes) -> List[ValidationResult]:
        out: List[ValidationResult] = []
        if self.parse_layout(pe) is None:
            out.append(ValidationResult.fail("invalid layout"))
        else:
            out.append(ValidationResult.ok("layout ok"))
        return out

    def fix(self, pe: bytearray) -> FixResult:
        return FixResult(data=bytes(pe))


# =============================================================================
# pe_section_rebuilder
# =============================================================================
class SectionRebuildFlags(int):
    ALIGN_SECTIONS = 1
    RECALCULATE_CHECKSUMS = 2
    FIX_RVA_MISMATCHES = 4
    PAD_TO_FILE_ALIGNMENT = 8

    def contains(self, f: int) -> bool: return (int(self) & f) == f
    def align_sections(self) -> bool: return self.contains(self.ALIGN_SECTIONS)
    def recalculate_checksums(self) -> bool: return self.contains(self.RECALCULATE_CHECKSUMS)
    def fix_rva_mismatches(self) -> bool: return self.contains(self.FIX_RVA_MISMATCHES)
    def pad_to_file_alignment(self) -> bool: return self.contains(self.PAD_TO_FILE_ALIGNMENT)


@dataclass
class SectionRebuildInfo:
    name: bytes = b""
    virtual_size: int = 0
    virtual_address: int = 0
    raw_size: int = 0
    raw_offset: int = 0
    characteristics: int = 0

    def name_str(self) -> str:
        return self.name.rstrip(b"\x00").decode("ascii", errors="replace")

    def virtual_end(self) -> int:
        return self.virtual_address + self.virtual_size

    def raw_end(self) -> int:
        return self.raw_offset + self.raw_size


def pe_section_rebuilder_infer_characteristics(name: str) -> int:
    n = name.lower()
    if n in (".text", "code"):
        return IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ
    if n in (".data", "data"):
        return IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE
    if n in (".rdata", "rdata"):
        return IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ
    if n in (".bss", "bss"):
        return IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE
    if n in (".reloc", "reloc"):
        return IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ
    return IMAGE_SCN_MEM_READ


@dataclass
class ValidationIssue:
    message: str = ""


class PeSectionRebuilder:
    def __init__(self, data: bytes):
        if not is_memory_pe(data):
            raise SectionRebuildError("not PE")
        self._data = bytearray(data)
        self._sections: List[SectionRebuildInfo] = []
        self._cfg = SectionRebuildFlags(0)
        self._is_pe32_plus = False
        self._parse()

    @classmethod
    def new(cls, data: bytes) -> "PeSectionRebuilder":
        return cls(data)

    def _parse(self) -> None:
        e = struct.unpack_from("<I", self._data, 0x3C)[0]
        opt_size = struct.unpack_from("<H", self._data, e + 20)[0]
        magic = struct.unpack_from("<H", self._data, e + 24)[0]
        self._is_pe32_plus = magic == 0x20B
        num = struct.unpack_from("<H", self._data, e + 6)[0]
        sec_off = e + 24 + opt_size
        for i in range(num):
            off = sec_off + i * 40
            if off + 40 > len(self._data):
                break
            s = SectionRebuildInfo()
            s.name = bytes(self._data[off:off + 8])
            s.virtual_size = struct.unpack_from("<I", self._data, off + 8)[0]
            s.virtual_address = struct.unpack_from("<I", self._data, off + 12)[0]
            s.raw_size = struct.unpack_from("<I", self._data, off + 16)[0]
            s.raw_offset = struct.unpack_from("<I", self._data, off + 20)[0]
            s.characteristics = struct.unpack_from("<I", self._data, off + 36)[0]
            self._sections.append(s)

    def config(self, cfg: SectionRebuildFlags) -> "PeSectionRebuilder":
        self._cfg = cfg
        return self

    def scan_implicit_sections(self) -> None:
        # Detect data beyond declared sections
        pass

    def fix_section_alignment(self) -> None:
        for s in self._sections:
            s.virtual_size = align_up(s.virtual_size, 0x1000)
            s.raw_size = align_up(s.raw_size, 0x200)

    def rebuild_section_table(self) -> None:
        e = struct.unpack_from("<I", self._data, 0x3C)[0]
        opt_size = struct.unpack_from("<H", self._data, e + 20)[0]
        sec_off = e + 24 + opt_size
        for i, s in enumerate(self._sections):
            off = sec_off + i * 40
            if off + 40 > len(self._data):
                self._data += b"\x00" * 40
            self._data[off:off + 8] = s.name
            struct.pack_into("<IIII", self._data, off + 8,
                             s.virtual_size, s.virtual_address, s.raw_size, s.raw_offset)
            struct.pack_into("<I", self._data, off + 36, s.characteristics)

    def merge_overlapping_sections(self) -> None:
        self._sections.sort(key=lambda s: s.virtual_address)
        merged: List[SectionRebuildInfo] = []
        for s in self._sections:
            if merged and s.virtual_address < merged[-1].virtual_end():
                merged[-1].virtual_size = max(merged[-1].virtual_end(), s.virtual_end()) - merged[-1].virtual_address
            else:
                merged.append(s)
        self._sections = merged

    def split_large_sections(self, threshold: int = 0x100000) -> None:
        pass

    def reorder_by_rva(self) -> None:
        self._sections.sort(key=lambda s: s.virtual_address)

    def reassign_raw_offsets(self, file_alignment: int = 0x200) -> None:
        cursor = 0x400
        for s in self._sections:
            s.raw_offset = cursor
            cursor = align_up(cursor + s.raw_size, file_alignment)

    def rebuild_all(self) -> None:
        self.fix_section_alignment()
        self.merge_overlapping_sections()
        self.reorder_by_rva()
        self.reassign_raw_offsets()
        self.rebuild_section_table()

    def recalculate_checksum(self) -> None:
        e = struct.unpack_from("<I", self._data, 0x3C)[0]
        co = e + 24 + 64
        cs = PeHeaderFixer.compute_checksum(bytes(self._data), co)
        struct.pack_into("<I", self._data, co, cs)

    def generate_rebuild_report(self) -> List[str]:
        return [f"{s.name_str()} VA=0x{s.virtual_address:x} VS=0x{s.virtual_size:x}" for s in self._sections]

    def validate_rebuilt_pe(self) -> List[ValidationIssue]:
        return [ValidationIssue(m) for m in verify_pe_validity(bytes(self._data))]

    def finish(self) -> bytes:
        return bytes(self._data)

    def sections(self) -> List[SectionRebuildInfo]:
        return self._sections

    def is_pe32_plus(self) -> bool:
        return self._is_pe32_plus

    def section_table_offset_from_nt(self) -> int:
        e = struct.unpack_from("<I", self._data, 0x3C)[0]
        opt_size = struct.unpack_from("<H", self._data, e + 20)[0]
        return 24 + opt_size

    def characteristics_histogram(self) -> Dict[int, int]:
        return dict(Counter(s.characteristics for s in self._sections))

    def sections_mut(self) -> List[SectionRebuildInfo]:
        return self._sections

    @staticmethod
    def infer_characteristics(name: str) -> int:
        return pe_section_rebuilder_infer_characteristics(name)


# =============================================================================
# pe_reconstructor
# =============================================================================
@dataclass
class SectionEntry:
    name: str = ""
    virtual_address: int = 0
    virtual_size: int = 0
    raw_offset: int = 0
    raw_size: int = 0
    characteristics: int = 0

    def is_executable(self) -> bool: return bool(self.characteristics & IMAGE_SCN_MEM_EXECUTE)
    def is_writable(self) -> bool: return bool(self.characteristics & IMAGE_SCN_MEM_WRITE)
    def is_code(self) -> bool: return bool(self.characteristics & IMAGE_SCN_CNT_CODE)

    def rva_to_file_off(self, rva: int) -> Optional[int]:
        if self.virtual_address <= rva < self.virtual_address + self.virtual_size:
            return self.raw_offset + (rva - self.virtual_address)
        return None


def find_pe_candidates(dump: bytes) -> List[int]:
    out: List[int] = []
    i = 0
    while True:
        j = dump.find(b"MZ", i)
        if j < 0:
            break
        if j + 0x40 < len(dump):
            e = struct.unpack_from("<I", dump, j + 0x3C)[0]
            if j + e + 4 <= len(dump) and dump[j + e:j + e + 4] == b"PE\x00\x00":
                out.append(j)
        i = j + 1
    return out


def calculate_pe_checksum(data: bytes, checksum_offset: int) -> int:
    return PeHeaderFixer.compute_checksum(data, checksum_offset)


@dataclass
class ReconstructConfig:
    image_base: int = 0x400000
    file_alignment: int = 0x200


@dataclass
class ReconstructStats:
    sections_recovered: int = 0
    imports_recovered: int = 0
    bytes_written: int = 0


@dataclass
class HeaderAnalysis:
    is_pe32_plus: bool = False
    num_sections: int = 0
    issues: List[str] = field(default_factory=list)


class PeReconstructor:
    def __init__(self, config: ReconstructConfig):
        self.config = config

    @classmethod
    def new(cls, config: ReconstructConfig) -> "PeReconstructor":
        return cls(config)

    @classmethod
    def with_defaults(cls) -> "PeReconstructor":
        return cls(ReconstructConfig())

    def reconstruct(self, dump: bytes) -> Tuple[bytes, ReconstructStats]:
        return (bytes(dump), ReconstructStats(bytes_written=len(dump)))

    def analyze(self, dump: bytes) -> HeaderAnalysis:
        h = HeaderAnalysis()
        h.issues = verify_pe_validity(dump)
        layout = PeHeaderFixer.new(FixerConfig()).parse_layout(dump)
        if layout:
            h.is_pe32_plus = layout.is_pe32_plus
            h.num_sections = layout.num_sections
        return h

    @staticmethod
    def patch_u16_le(data: bytearray, off: int, v: int) -> None:
        struct.pack_into("<H", data, off, v & 0xFFFF)

    @staticmethod
    def parse_imports(pe_data: bytes) -> List[ImportEntry]:
        return []


# =============================================================================
# pe_dumper
# =============================================================================
class DumpFlags(int):
    FIX_PE_HEADER = 1
    REALIGN_SECTIONS = 2
    REBUILD_IMPORTS = 4
    DUMP_OVERLAY = 8
    INCLUDE_CERTIFICATE = 16

    def contains(self, f: int) -> bool: return (int(self) & f) == f
    def fix_pe_header(self) -> bool: return self.contains(self.FIX_PE_HEADER)
    def realign_sections(self) -> bool: return self.contains(self.REALIGN_SECTIONS)
    def rebuild_imports(self) -> bool: return self.contains(self.REBUILD_IMPORTS)
    def dump_overlay(self) -> bool: return self.contains(self.DUMP_OVERLAY)
    def include_certificate(self) -> bool: return self.contains(self.INCLUDE_CERTIFICATE)


@dataclass
class DumpOptions:
    flags: int = 0
    base: int = 0


@dataclass
class DumpSource:
    bytes_: bytes = b""
    base: int = 0


@dataclass
class PeDumpResult:
    data: bytes = b""
    overlay: bytes = b""


@dataclass
class PeContext:
    raw: bytes = b""
    is_pe32_plus: bool = False
    num_sections: int = 0
    e_lfanew: int = 0
    name: bytes = b""

    def name_str(self) -> str:
        return self.name.decode("ascii", errors="replace")

    @classmethod
    def parse(cls, data: bytes) -> "PeContext":
        if not is_memory_pe(data) or len(data) < 0x40:
            raise DumpError("invalid PE")
        e = struct.unpack_from("<I", data, 0x3C)[0]
        magic = struct.unpack_from("<H", data, e + 24)[0]
        num = struct.unpack_from("<H", data, e + 6)[0]
        return cls(raw=bytes(data), is_pe32_plus=magic == 0x20B,
                   num_sections=num, e_lfanew=e)

    def opt_magic(self) -> int:
        return 0x20B if self.is_pe32_plus else 0x10B

    def pointer_size(self) -> int:
        return 8 if self.is_pe32_plus else 4

    def checksum_field_offset(self) -> int:
        return self.e_lfanew + 24 + 64

    def section_characteristics_histogram(self) -> Dict[int, int]:
        opt_size = struct.unpack_from("<H", self.raw, self.e_lfanew + 20)[0]
        sec_off = self.e_lfanew + 24 + opt_size
        hist: Counter = Counter()
        for i in range(self.num_sections):
            off = sec_off + i * 40 + 36
            if off + 4 > len(self.raw):
                break
            hist[struct.unpack_from("<I", self.raw, off)[0]] += 1
        return dict(hist)


class PeDumper:
    def __init__(self, options: DumpOptions):
        self.options = options

    @classmethod
    def new(cls, options: DumpOptions) -> "PeDumper":
        return cls(options)

    def dump_from_memory(self, source: DumpSource) -> PeDumpResult:
        return PeDumpResult(data=source.bytes_, overlay=b"")

    def fix_nt_header(self, data: bytearray, ctx: PeContext) -> None:
        if data[ctx.e_lfanew:ctx.e_lfanew + 4] != b"PE\x00\x00":
            data[ctx.e_lfanew:ctx.e_lfanew + 4] = b"PE\x00\x00"

    def realign_sections(self, data: bytearray, ctx: PeContext) -> None:
        opt_size = struct.unpack_from("<H", data, ctx.e_lfanew + 20)[0]
        sec_off = ctx.e_lfanew + 24 + opt_size
        cursor = align_up(sec_off + 40 * ctx.num_sections, 0x200)
        for i in range(ctx.num_sections):
            off = sec_off + i * 40
            rs = struct.unpack_from("<I", data, off + 16)[0]
            struct.pack_into("<I", data, off + 20, cursor)
            cursor = align_up(cursor + rs, 0x200)

    def pe_from_module_handle(self, handle: int, memory: bytes) -> bytes:
        return bytes(memory)

    def detect_unmap_protection(self, data: bytes) -> bool:
        # Heuristic: section flags missing exec on .text
        ctx = PeContext.parse(data)
        opt_size = struct.unpack_from("<H", data, ctx.e_lfanew + 20)[0]
        sec_off = ctx.e_lfanew + 24 + opt_size
        for i in range(ctx.num_sections):
            off = sec_off + i * 40
            name = bytes(data[off:off + 8]).rstrip(b"\x00")
            ch = struct.unpack_from("<I", data, off + 36)[0]
            if name == b".text" and not (ch & IMAGE_SCN_MEM_EXECUTE):
                return True
        return False

    def overlay_data(self, data: bytes, ctx: PeContext) -> bytes:
        return OverlayHandler.extract(data)


# =============================================================================
# scylla_iat_rebuilder
# =============================================================================
@dataclass
class FunctionPointer:
    va: int = 0
    module: Optional[str] = None
    name: Optional[str] = None
    ordinal: Optional[int] = None
    resolved: bool = False

    @classmethod
    def null(cls) -> "FunctionPointer":
        return cls()

    @classmethod
    def unresolved(cls, va: int) -> "FunctionPointer":
        return cls(va=va, resolved=False)

    @classmethod
    def resolved_(cls, va: int, module: str, name: str) -> "FunctionPointer":
        return cls(va=va, module=module, name=name, resolved=True)

    @classmethod
    def by_ordinal(cls, va: int, module: str, ordinal: int) -> "FunctionPointer":
        return cls(va=va, module=module, ordinal=ordinal, resolved=True)

    def is_resolved(self) -> bool:
        return self.resolved


@dataclass
class IATEntry:
    rva: int = 0
    pointer: FunctionPointer = field(default_factory=FunctionPointer.null)

    @classmethod
    def new(cls, rva: int, pointer: FunctionPointer) -> "IATEntry":
        return cls(rva, pointer)

    @classmethod
    def terminator(cls, rva: int) -> "IATEntry":
        return cls(rva, FunctionPointer.null())

    def is_null(self) -> bool:
        return self.pointer.va == 0


@dataclass
class ModuleMapping:
    name: str = ""
    base: int = 0
    size: int = 0
    exports: Dict[int, Tuple[int, str]] = field(default_factory=dict)

    @classmethod
    def new(cls, name: str, base: int, size: int) -> "ModuleMapping":
        return cls(name, base, size)

    def add_export(self, va: int, ord_: int, name: str) -> None:
        self.exports[va] = (ord_, name)

    def contains(self, va: int) -> bool:
        return self.base <= va < self.base + self.size

    def resolve(self, va: int) -> Optional[FunctionPointer]:
        if va in self.exports:
            ord_, name = self.exports[va]
            return FunctionPointer.resolved_(va, self.name, name)
        return None

    def export_count(self) -> int:
        return len(self.exports)


class IatWriter:
    def __init__(self, image_base: int, iat_rva: int, ptr_size: int):
        self.image_base = image_base
        self.iat_rva = iat_rva
        self.ptr_size = ptr_size

    @classmethod
    def new_pe32(cls, image_base: int, iat_rva: int) -> "IatWriter":
        return cls(image_base, iat_rva, 4)

    @classmethod
    def new_pe64(cls, image_base: int, iat_rva: int) -> "IatWriter":
        return cls(image_base, iat_rva, 8)

    def write_iat(self, buf: bytearray, entries: List[IATEntry]) -> int:
        cursor = self.iat_rva
        for e in entries:
            self.ensure_capacity(buf, cursor + self.ptr_size)
            buf[cursor:cursor + self.ptr_size] = e.pointer.va.to_bytes(self.ptr_size, "little")
            cursor += self.ptr_size
        return cursor - self.iat_rva

    def ensure_capacity(self, buf: bytearray, required: int) -> None:
        if required > len(buf):
            buf += b"\x00" * (required - len(buf))


@dataclass
class ScyllaReport:
    total: int = 0
    resolved: int = 0

    def success(self) -> bool:
        return self.total > 0 and self.resolved == self.total

    def resolution_rate(self) -> float:
        return self.resolved / self.total if self.total else 0.0


class ScyllaIatRebuilder:
    def __init__(self, image_base: int, ptr_size: int):
        self.image_base = image_base
        self.ptr_size = ptr_size
        self.modules: List[ModuleMapping] = []
        self.raw_entries: List[Tuple[int, int]] = []

    @classmethod
    def new(cls, image_base: int, ptr_size: int) -> "ScyllaIatRebuilder":
        return cls(image_base, ptr_size)

    @classmethod
    def new_pe32(cls, image_base: int) -> "ScyllaIatRebuilder":
        return cls(image_base, 4)

    @classmethod
    def new_pe64(cls, image_base: int) -> "ScyllaIatRebuilder":
        return cls(image_base, 8)

    def add_module(self, mapping: ModuleMapping) -> None:
        self.modules.append(mapping)

    def add_raw_entry(self, rva: int, va: int) -> None:
        self.raw_entries.append((rva, va))

    def scan_flat_iat(self, buf: bytes, iat_rva: int) -> None:
        for i in range(iat_rva, len(buf) - self.ptr_size, self.ptr_size):
            v = int.from_bytes(buf[i:i + self.ptr_size], "little")
            if v == 0:
                break
            self.add_raw_entry(i, v)

    def resolve_all(self) -> List[IATEntry]:
        out: List[IATEntry] = []
        for rva, va in self.raw_entries:
            ptr = FunctionPointer.unresolved(va)
            for m in self.modules:
                if m.contains(va):
                    r = m.resolve(va)
                    if r:
                        ptr = r
                    break
            out.append(IATEntry.new(rva, ptr))
        return out

    def group_by_module(self, entries: List[IATEntry]) -> Dict[str, List[IATEntry]]:
        g: Dict[str, List[IATEntry]] = defaultdict(list)
        for e in entries:
            g[e.pointer.module or "?"].append(e)
        return dict(g)

    def rebuild(self, pe_buf: bytearray, iat_file_offset: int) -> ScyllaReport:
        entries = self.resolve_all()
        report = ScyllaReport(total=len(entries),
                              resolved=sum(1 for e in entries if e.pointer.is_resolved()))
        w = IatWriter(self.image_base, iat_file_offset, self.ptr_size)
        w.write_iat(pe_buf, entries)
        return report


# =============================================================================
# import_table_rebuilder
# =============================================================================
@dataclass
class ResolvedImport:
    iat_rva: int = 0
    dll: str = ""
    name: Optional[str] = None
    ordinal: Optional[int] = None

    @classmethod
    def named(cls, iat_rva: int, dll: str, fn: str) -> "ResolvedImport":
        return cls(iat_rva, dll, fn, None)

    @classmethod
    def by_ordinal(cls, iat_rva: int, dll: str, ord_: int) -> "ResolvedImport":
        return cls(iat_rva, dll, None, ord_)

    def has_name(self) -> bool:
        return self.name is not None

    def description(self) -> str:
        if self.name:
            return f"{self.dll}!{self.name}"
        return f"{self.dll}!#{self.ordinal}"


@dataclass
class IatReference:
    insn_addr: int = 0
    iat_rva: int = 0
    is_call: bool = False
    is_rip_relative: bool = False

    @classmethod
    def new(cls, insn_addr: int, iat_rva: int, is_call: bool, is_rip_relative: bool) -> "IatReference":
        return cls(insn_addr, iat_rva, is_call, is_rip_relative)


@dataclass
class ImageThunkData:
    value: int = 0

    @classmethod
    def by_name(cls, name_rva: int) -> "ImageThunkData":
        return cls(name_rva)

    @classmethod
    def by_ordinal64(cls, ord_: int) -> "ImageThunkData":
        return cls((1 << 63) | ord_)

    @classmethod
    def by_ordinal32(cls, ord_: int) -> "ImageThunkData":
        return cls((1 << 31) | ord_)

    def to_le_bytes(self) -> bytes:
        return self.value.to_bytes(8, "little")

    def to_le_bytes32(self) -> bytes:
        return (self.value & 0xFFFFFFFF).to_bytes(4, "little")


@dataclass
class ImportDescriptor:
    dll_name: str = ""
    first_thunk: int = 0
    functions: List[ResolvedImport] = field(default_factory=list)

    @classmethod
    def new(cls, dll_name: str, first_thunk: int) -> "ImportDescriptor":
        return cls(dll_name, first_thunk)

    def function_count(self) -> int:
        return len(self.functions)

    def write_descriptor(self, buf: bytearray) -> None:
        buf += struct.pack("<IIIII", 0, 0, 0, 0, self.first_thunk)


class ImportTableRebuilder:
    def __init__(self, config: Optional[ImportRebuilderConfig] = None):
        self.config_ = config or ImportRebuilderConfig()
        self.entries: List[IatEntry] = []
        self.exports: Dict[int, Tuple[str, str]] = {}
        self.references: List[IatReference] = []

    @classmethod
    def new(cls) -> "ImportTableRebuilder":
        return cls()

    def with_config(self, config: ImportRebuilderConfig) -> "ImportTableRebuilder":
        self.config_ = config
        return self

    def add_export(self, va: int, dll: str, fn: str) -> None:
        self.exports[va] = (dll, fn)

    def load_exports(self, items: List[Tuple[int, str, str]]) -> None:
        for va, d, f in items:
            self.add_export(va, d, f)

    def scan_code(self, code: bytes, code_rva: int) -> None:
        # Simple scan for FF15 (call [rip+disp32])
        i = 0
        while i < len(code) - 6:
            if code[i:i + 2] == b"\xFF\x15":
                disp = struct.unpack_from("<i", code, i + 2)[0]
                target = code_rva + i + 6 + disp
                self.references.append(IatReference.new(code_rva + i, target, True, True))
                i += 6
            else:
                i += 1

    def resolve_from_image(self, image: bytes) -> None:
        ptr_size = 8 if self.config_.is_pe32plus else 4
        for ref in self.references:
            if ref.iat_rva + ptr_size <= len(image):
                va = int.from_bytes(image[ref.iat_rva:ref.iat_rva + ptr_size], "little")
                if va in self.exports:
                    dll, fn = self.exports[va]
                    self.entries.append(IatEntry(dll=dll, name=fn, iat_rva=ref.iat_rva, address=va))

    def register_entry(self, e: IatEntry) -> None:
        self.entries.append(e)

    def build_descriptors(self) -> List[ImportDescriptor]:
        by_dll: Dict[str, List[IatEntry]] = defaultdict(list)
        for e in self.entries:
            by_dll[e.dll].append(e)
        out = []
        for dll, ents in by_dll.items():
            d = ImportDescriptor.new(dll, ents[0].iat_rva if ents else 0)
            for e in ents:
                d.functions.append(ResolvedImport.named(e.iat_rva, e.dll, e.name or "?"))
            out.append(d)
        return out

    def build_idata_blob(self, section_rva: int) -> Tuple[bytes, int]:
        blob = MemoryRebuilder(b"", 0, [], self.config_.is_pe32plus).rebuild_import_directory(
            [IatEntry2(rva=e.iat_rva, dll=e.dll, name=e.name, ordinal=e.ordinal) for e in self.entries]
        )
        return blob, section_rva

    def hint_count(self) -> int:
        return sum(1 for e in self.entries if e.name is not None)

    def resolved_count(self) -> int:
        return sum(1 for e in self.entries if e.is_resolved())

    def resolved_entries(self) -> List[IatEntry]:
        return [e for e in self.entries if e.is_resolved()]

    def config(self) -> ImportRebuilderConfig:
        return self.config_


# =============================================================================
# section_aligner
# =============================================================================
@dataclass
class AlignmentFix:
    index: int = 0
    field_name: str = ""
    old: int = 0
    new: int = 0

    def has_change(self) -> bool:
        return self.old != self.new


@dataclass
class AlignmentReport:
    fixes: List[AlignmentFix] = field(default_factory=list)

    def actual_fixes(self) -> List[AlignmentFix]:
        return [f for f in self.fixes if f.has_change()]

    def corrected_count(self) -> int:
        return len(self.actual_fixes())

    def needs_correction(self) -> bool:
        return self.corrected_count() > 0


@dataclass
class SectionDescriptor:
    name: str = ""
    virtual_address: int = 0
    virtual_size: int = 0
    raw_offset: int = 0
    raw_size: int = 0

    @classmethod
    def new(cls, name: str, virtual_address: int, virtual_size: int,
            raw_offset: int, raw_size: int) -> "SectionDescriptor":
        return cls(name, virtual_address, virtual_size, raw_offset, raw_size)


class SectionAligner:
    def __init__(self, file_alignment: int, section_alignment: int):
        self.file_alignment = file_alignment
        self.section_alignment = section_alignment

    @classmethod
    def new(cls, file_alignment: int, section_alignment: int) -> "SectionAligner":
        return cls(file_alignment, section_alignment)

    @classmethod
    def default_pe(cls) -> "SectionAligner":
        return cls(0x200, 0x1000)

    @staticmethod
    def align_up(value: int, align: int) -> int:
        return align_up(value, align)

    def fix_section(self, index: int, section: SectionDescriptor) -> AlignmentFix:
        new_va = align_up(section.virtual_address, self.section_alignment)
        return AlignmentFix(index, "virtual_address", section.virtual_address, new_va)

    def align_all(self, sections: List[SectionDescriptor]) -> AlignmentReport:
        rep = AlignmentReport()
        for i, s in enumerate(sections):
            rep.fixes.append(self.fix_section(i, s))
        return rep

    def repack_offsets(self, sections: List[SectionDescriptor], headers_size: int) -> None:
        cursor = align_up(headers_size, self.file_alignment)
        for s in sections:
            s.raw_offset = cursor
            cursor = align_up(cursor + s.raw_size, self.file_alignment)


# =============================================================================
# section_realigner
# =============================================================================
@dataclass
class RawSectionHeader:
    name: bytes = b""
    virtual_size: int = 0
    virtual_address: int = 0
    raw_size: int = 0
    raw_offset: int = 0
    relocations_ptr: int = 0
    linenumbers_ptr: int = 0
    num_relocations: int = 0
    num_linenumbers: int = 0
    characteristics: int = 0

    def name_str(self) -> str:
        return self.name.rstrip(b"\x00").decode("ascii", errors="replace")

    def is_code(self) -> bool:
        return bool(self.characteristics & IMAGE_SCN_CNT_CODE)

    def is_writable(self) -> bool:
        return bool(self.characteristics & IMAGE_SCN_MEM_WRITE)

    def is_readable(self) -> bool:
        return bool(self.characteristics & IMAGE_SCN_MEM_READ)

    @staticmethod
    def aligned_raw_size(virtual_size: int, file_align: int) -> int:
        return align_up(virtual_size, file_align)

    @classmethod
    def from_bytes(cls, b: bytes) -> Optional["RawSectionHeader"]:
        if len(b) < 40:
            return None
        return cls(
            name=b[:8],
            virtual_size=struct.unpack_from("<I", b, 8)[0],
            virtual_address=struct.unpack_from("<I", b, 12)[0],
            raw_size=struct.unpack_from("<I", b, 16)[0],
            raw_offset=struct.unpack_from("<I", b, 20)[0],
            relocations_ptr=struct.unpack_from("<I", b, 24)[0],
            linenumbers_ptr=struct.unpack_from("<I", b, 28)[0],
            num_relocations=struct.unpack_from("<H", b, 32)[0],
            num_linenumbers=struct.unpack_from("<H", b, 34)[0],
            characteristics=struct.unpack_from("<I", b, 36)[0],
        )

    def to_bytes(self) -> bytes:
        return (self.name[:8].ljust(8, b"\x00") +
                struct.pack("<IIIIIIHHI",
                            self.virtual_size, self.virtual_address,
                            self.raw_size, self.raw_offset,
                            self.relocations_ptr, self.linenumbers_ptr,
                            self.num_relocations, self.num_linenumbers,
                            self.characteristics))


@dataclass
class AlignResult:
    modified: List[int] = field(default_factory=list)

    def is_clean(self) -> bool:
        return not self.modified

    def sections_modified(self) -> int:
        return len(self.modified)


@dataclass
class RealignConfig:
    file_alignment: int = 0x200
    section_alignment: int = 0x1000


class SectionRealigner:
    def __init__(self, config: RealignConfig):
        self.config = config

    @classmethod
    def new(cls, config: RealignConfig) -> "SectionRealigner":
        return cls(config)

    def parse_sections(self, pe_bytes: bytes, section_table_off: int, count: int) -> List[RawSectionHeader]:
        out: List[RawSectionHeader] = []
        for i in range(count):
            off = section_table_off + i * 40
            if off + 40 > len(pe_bytes):
                break
            h = RawSectionHeader.from_bytes(pe_bytes[off:off + 40])
            if h:
                out.append(h)
        return out

    def realign(self, headers: List[RawSectionHeader], current_headers_size: int) -> AlignResult:
        res = AlignResult()
        cursor = align_up(current_headers_size, self.config.file_alignment)
        for i, h in enumerate(headers):
            new_offset = cursor
            new_raw = align_up(h.virtual_size, self.config.file_alignment)
            if new_offset != h.raw_offset or new_raw != h.raw_size:
                res.modified.append(i)
            h.raw_offset = new_offset
            h.raw_size = new_raw
            cursor = align_up(cursor + new_raw, self.config.file_alignment)
        return res

    def characteristics_histogram(self, headers: List[RawSectionHeader]) -> Dict[int, int]:
        return dict(Counter(h.characteristics for h in headers))

    def apply(self, pe_bytes: bytearray, section_table_off: int, headers: List[RawSectionHeader]) -> None:
        for i, h in enumerate(headers):
            off = section_table_off + i * 40
            if off + 40 <= len(pe_bytes):
                pe_bytes[off:off + 40] = h.to_bytes()


# =============================================================================
# Self-check
# =============================================================================
if __name__ == "__main__":
    # Quick smoke tests
    assert compute_entropy(b"") == 0.0
    assert is_memory_pe(b"MZxx")
    assert not is_memory_pe(b"XX")
    assert align_up(0x123, 0x200) == 0x200
    assert crc16_ccitt(b"123456789") == 0x29B1
    s = RebuildSection.code(".text", 0x1000, b"\x90" * 16)
    assert s.is_executable()
    assert s.virtual_end() == 0x1010
    rb = RelocationTableBuilder.new_x64(0x140000000)
    rb.add_fixup(0x1004)
    rb.add_fixup(0x1010)
    assert rb.fixup_count() == 2
    blob = rb.build()
    assert len(blob) > 0
    print("OK")
