#!/usr/bin/env python3
"""Independent Python validators for rustre-fuzz primitives.

Reimplements (in pure stdlib) a subset of the documented behaviors so we can
cross-check Rust outputs. Each validator is a pure function operating on
bytes/lists; no I/O, no external deps.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterable, List, Optional, Tuple


# ---------------------------------------------------------------------------
# Hash: FNV-1a 64-bit
# ---------------------------------------------------------------------------

FNV1A_OFFSET = 0xCBF29CE484222325
FNV1A_PRIME = 0x100000001B3
U64_MASK = 0xFFFFFFFFFFFFFFFF


def fnv1a(data: bytes) -> int:
    h = FNV1A_OFFSET
    for b in data:
        h ^= b
        h = (h * FNV1A_PRIME) & U64_MASK
    return h


# ---------------------------------------------------------------------------
# FuzzRng: xorshift64
# ---------------------------------------------------------------------------

class FuzzRng:
    def __init__(self, seed: int) -> None:
        if seed == 0:
            seed = 0xDEADBEEFCAFEBABE
        self.state = seed & U64_MASK

    def next_u64(self) -> int:
        x = self.state
        x ^= (x << 13) & U64_MASK
        x ^= (x >> 7) & U64_MASK
        x ^= (x << 17) & U64_MASK
        self.state = x & U64_MASK
        return self.state

    def next_usize(self, n: int) -> int:
        if n == 0:
            return 0
        return self.next_u64() % n

    def next_u8(self) -> int:
        return self.next_u64() & 0xFF

    def one_in(self, n: int) -> bool:
        if n == 0:
            return False
        return self.next_usize(n) == 0


# ---------------------------------------------------------------------------
# CoverageMap: AFL-style bitmap
# ---------------------------------------------------------------------------

class CoverageMap:
    def __init__(self, size: int) -> None:
        self.size = size
        self.edges = bytearray(size)
        self._cumulative = 0

    def update(self, trace: bytes) -> int:
        """XOR-style novel-bit detection; saturating per-edge counter at 255.

        Returns number of edges that became newly non-zero.
        """
        new_bits = 0
        for i, b in enumerate(trace):
            if i >= self.size or b == 0:
                continue
            prev = self.edges[i]
            if prev == 0:
                new_bits += 1
            total = prev + b
            self.edges[i] = 255 if total > 255 else total
        self._cumulative += new_bits
        return new_bits

    def merge(self, other: "CoverageMap") -> int:
        new_bits = 0
        for i in range(min(self.size, other.size)):
            o = other.edges[i]
            if o == 0:
                continue
            prev = self.edges[i]
            if prev == 0 and o != 0:
                new_bits += 1
            total = prev + o
            self.edges[i] = 255 if total > 255 else total
        self._cumulative += new_bits
        return new_bits

    def total_bits_set(self) -> int:
        return sum(1 for e in self.edges if e != 0)

    def cumulative_bits_set(self) -> int:
        return self._cumulative

    def is_empty(self) -> bool:
        return self.total_bits_set() == 0

    def edge_hit_count(self, idx: int) -> int:
        return self.edges[idx] if 0 <= idx < self.size else 0

    def active_edges(self) -> List[Tuple[int, int]]:
        return [(i, e) for i, e in enumerate(self.edges) if e != 0]

    def hash(self) -> int:
        return fnv1a(bytes(self.edges))

    def reset(self) -> None:
        self.edges = bytearray(self.size)
        self._cumulative = 0


# ---------------------------------------------------------------------------
# FuzzInput
# ---------------------------------------------------------------------------

@dataclass
class FuzzInput:
    id: int
    data: bytes
    parent: Optional[int] = None
    generation: int = 0
    origin: Optional[str] = None

    def derive(self, new_id: int, new_data: bytes,
               origin: Optional[str] = None) -> "FuzzInput":
        return FuzzInput(
            id=new_id,
            data=bytes(new_data),
            parent=self.id,
            generation=self.generation + 1,
            origin=origin if origin is not None else self.origin,
        )

    def data_hash(self) -> int:
        return fnv1a(self.data)

    def len_(self) -> int:
        return len(self.data)

    def is_empty(self) -> bool:
        return len(self.data) == 0


# ---------------------------------------------------------------------------
# Dictionary loader (text format)
# ---------------------------------------------------------------------------

def _parse_hex_block(payload: str) -> bytes:
    cleaned = payload.replace(" ", "").replace("\t", "")
    if len(cleaned) % 2 != 0:
        raise ValueError("hex block length must be even")
    return bytes.fromhex(cleaned)


def load_dictionary_from_text(text: str) -> List[bytes]:
    """Mirrors `Dictionary::load_from_text` semantics.

    Supports:
      - lines beginning with `#` are comments
      - blank lines ignored
      - `"quoted"` literal strings (UTF-8 bytes)
      - `x"de ad be ef"` hex blocks
      - bare tokens
    """
    out: List[bytes] = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith('x"') and line.endswith('"') and len(line) >= 3:
            out.append(_parse_hex_block(line[2:-1]))
        elif line.startswith('"') and line.endswith('"') and len(line) >= 2:
            out.append(line[1:-1].encode("utf-8"))
        else:
            out.append(line.encode("utf-8"))
    return out


# ---------------------------------------------------------------------------
# InputQueue: round-robin with favored over-sampling (every 3rd call)
# ---------------------------------------------------------------------------

class InputQueue:
    def __init__(self) -> None:
        self._all: List[FuzzInput] = []
        self._favored: List[int] = []  # indices into _all
        self._cursor = 0
        self._fav_cursor = 0
        self._call_count = 0
        self._next_id_val = 0

    def next_id(self) -> int:
        i = self._next_id_val
        self._next_id_val += 1
        return i

    def add(self, inp: FuzzInput, is_interesting: bool) -> None:
        idx = len(self._all)
        self._all.append(inp)
        if is_interesting:
            self._favored.append(idx)

    def remove(self, fid: int) -> bool:
        for i, e in enumerate(self._all):
            if e.id == fid:
                self._all.pop(i)
                self._favored = [j if j < i else j - 1
                                 for j in self._favored if j != i]
                return True
        return False

    def is_empty(self) -> bool:
        return not self._all

    def len_(self) -> int:
        return len(self._all)

    def favored_count(self) -> int:
        return len(self._favored)

    def clear(self) -> None:
        self._all.clear()
        self._favored.clear()
        self._cursor = 0
        self._fav_cursor = 0
        self._call_count = 0

    def select_cursor(self) -> int:
        return self._cursor

    def select(self) -> FuzzInput:
        if not self._all:
            raise IndexError("select on empty queue")
        self._call_count += 1
        if self._call_count % 3 == 0 and self._favored:
            idx = self._favored[self._fav_cursor % len(self._favored)]
            self._fav_cursor += 1
            return self._all[idx]
        e = self._all[self._cursor % len(self._all)]
        self._cursor = (self._cursor + 1) % max(1, len(self._all))
        return e


# ---------------------------------------------------------------------------
# Corpus: dedup by coverage hash; prune retains roots
# ---------------------------------------------------------------------------

@dataclass
class CorpusMeta:
    coverage_hash: int
    coverage_bits: int
    execution_time_us: int
    selections: int = 0

    def record_selection(self) -> None:
        self.selections += 1


@dataclass
class CorpusEntry:
    input: FuzzInput
    meta: CorpusMeta


class Corpus:
    def __init__(self) -> None:
        self.entries: List[CorpusEntry] = []
        self._cov_hashes: set = set()
        self.crashes: List[FuzzInput] = []

    def add_input(self, inp: FuzzInput, meta: CorpusMeta) -> bool:
        if meta.coverage_hash in self._cov_hashes:
            return False
        self._cov_hashes.add(meta.coverage_hash)
        self.entries.append(CorpusEntry(inp, meta))
        return True

    def add_crash(self, inp: FuzzInput) -> None:
        self.crashes.append(inp)

    def __len__(self) -> int:
        return len(self.entries)

    def is_empty(self) -> bool:
        return not self.entries

    def unique_coverage_hashes(self) -> int:
        return len(self._cov_hashes)

    def get_entry(self, fid: int) -> Optional[CorpusEntry]:
        for e in self.entries:
            if e.input.id == fid:
                return e
        return None

    def prune(self, min_coverage_bits: int) -> int:
        kept: List[CorpusEntry] = []
        removed = 0
        for e in self.entries:
            is_root = e.input.parent is None
            if is_root or e.meta.coverage_bits >= min_coverage_bits:
                kept.append(e)
            else:
                self._cov_hashes.discard(e.meta.coverage_hash)
                removed += 1
        self.entries = kept
        return removed

    def sorted_by_coverage(self) -> List[FuzzInput]:
        ordered = sorted(self.entries,
                         key=lambda e: e.meta.coverage_bits,
                         reverse=True)
        return [e.input for e in ordered]


# ---------------------------------------------------------------------------
# CrashDeduplicator
# ---------------------------------------------------------------------------

@dataclass
class CrashRecord:
    id: int
    input: bytes
    signal: int
    fault_addr: int
    coverage_hash: int
    stack_hash: Optional[int] = None
    count: int = 1

    def set_stack_hash(self, stack: Iterable[int]) -> None:
        h = FNV1A_OFFSET
        for frame in stack:
            for i in range(8):
                h ^= (frame >> (i * 8)) & 0xFF
                h = (h * FNV1A_PRIME) & U64_MASK
        self.stack_hash = h

    def increment(self) -> None:
        self.count += 1

    def dedup_key(self) -> int:
        return self.stack_hash if self.stack_hash is not None else self.coverage_hash


class CrashDeduplicator:
    def __init__(self) -> None:
        self._by_key: dict = {}
        self._next_id = 0

    def submit(self, input_bytes: bytes, signal: int,
               fault_addr: int, cov_hash: int,
               stack: Optional[List[int]] = None) -> bool:
        rec = CrashRecord(self._next_id, bytes(input_bytes),
                          signal, fault_addr, cov_hash)
        if stack is not None:
            rec.set_stack_hash(stack)
        key = rec.dedup_key()
        if key in self._by_key:
            self._by_key[key].increment()
            return False
        self._next_id += 1
        self._by_key[key] = rec
        return True

    def unique_count(self) -> int:
        return len(self._by_key)

    def all_crashes(self) -> List[CrashRecord]:
        return list(self._by_key.values())

    def most_common(self) -> Optional[CrashRecord]:
        if not self._by_key:
            return None
        return max(self._by_key.values(), key=lambda r: r.count)

    def clear(self) -> None:
        self._by_key.clear()


# ---------------------------------------------------------------------------
# Self-test
# ---------------------------------------------------------------------------

def _selftest() -> None:
    # FNV-1a known vector: empty -> offset basis
    assert fnv1a(b"") == FNV1A_OFFSET
    # Deterministic xorshift
    r1, r2 = FuzzRng(1), FuzzRng(1)
    for _ in range(50):
        assert r1.next_u64() == r2.next_u64()
    # Seed 0 remap
    a = FuzzRng(0).next_u64()
    b = FuzzRng(0xDEADBEEFCAFEBABE).next_u64()
    assert a == b
    # CoverageMap basics
    cm = CoverageMap(16)
    assert cm.is_empty()
    new = cm.update(b"\x00\x01\x00\x02" + b"\x00" * 12)
    assert new == 2
    assert cm.total_bits_set() == 2
    assert cm.update(b"\x00\x01\x00\x02" + b"\x00" * 12) == 0
    # Saturation
    cm2 = CoverageMap(4)
    cm2.update(b"\xff\x00\x00\x00")
    cm2.update(b"\x05\x00\x00\x00")
    assert cm2.edge_hit_count(0) == 255
    # FuzzInput derive
    a = FuzzInput(id=1, data=b"hi")
    c = a.derive(2, b"hey")
    assert c.parent == 1 and c.generation == 1
    # Dictionary
    text = '# c\nfoo\n"bar"\nx"de ad"\n'
    toks = load_dictionary_from_text(text)
    assert toks == [b"foo", b"bar", b"\xde\xad"]
    # InputQueue round-robin + favored
    q = InputQueue()
    for i in range(3):
        q.add(FuzzInput(id=i, data=bytes([i])), is_interesting=(i == 0))
    seq = [q.select().id for _ in range(6)]
    # every 3rd call -> favored (id=0); others round-robin starting at 0
    assert seq[2] == 0 and seq[5] == 0
    # Corpus dedup + prune retains root
    corp = Corpus()
    root = FuzzInput(id=10, data=b"r")
    child = FuzzInput(id=11, data=b"c", parent=10, generation=1)
    assert corp.add_input(root, CorpusMeta(0xAA, 1, 100))
    assert corp.add_input(child, CorpusMeta(0xBB, 0, 100))
    assert not corp.add_input(FuzzInput(id=12, data=b"d"),
                              CorpusMeta(0xAA, 5, 100))
    removed = corp.prune(min_coverage_bits=2)
    assert removed == 1
    assert any(e.input.id == 10 for e in corp.entries)
    # CrashDeduplicator
    cd = CrashDeduplicator()
    assert cd.submit(b"a", 11, 0x1000, 0xDEAD, stack=[1, 2, 3])
    assert not cd.submit(b"b", 11, 0x1000, 0xDEAD, stack=[1, 2, 3])
    assert cd.unique_count() == 1
    assert cd.most_common().count == 2
    print("rustre-fuzz validators: OK")


if __name__ == "__main__":
    _selftest()
