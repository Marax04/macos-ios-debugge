#!/usr/bin/env python3
"""Independent Python reimplementation of rustre-diff core algorithms.

Mirrors the behavior described in validation/reports/rustre-diff.md:
- FNV-1a 64-bit hashing
- LCS-based byte similarity (capped 512 B/side, coverage-scaled)
- Byte-histogram Bhattacharyya similarity
- N-gram Jaccard similarity (n<=8, input<=4096 B)
- Combined byte similarity (0.6 hist + 0.4 4-gram jaccard)
- FuncFingerprint similarity (0.7 LCS + 0.3 size ratio, identical-hash short-circuit)
- DiffEngine two-pass matching (hash-identical, then greedy similarity)
- diff_by_name / diff_exports deterministic outputs
"""

from dataclasses import dataclass, field
from typing import Optional, Dict, List, Tuple
from enum import Enum

FNV_OFFSET = 0xcbf29ce484222325
FNV_PRIME = 0x100000001b3
MASK64 = (1 << 64) - 1


def simple_hash(data: bytes) -> int:
    h = FNV_OFFSET
    for b in data:
        h ^= b
        h = (h * FNV_PRIME) & MASK64
    return h


def _lcs_len(a: bytes, b: bytes) -> int:
    if not a or not b:
        return 0
    la, lb = len(a), len(b)
    prev = [0] * (lb + 1)
    cur = [0] * (lb + 1)
    for i in range(1, la + 1):
        ai = a[i - 1]
        for j in range(1, lb + 1):
            if ai == b[j - 1]:
                cur[j] = prev[j - 1] + 1
            else:
                cur[j] = prev[j] if prev[j] >= cur[j - 1] else cur[j - 1]
        prev, cur = cur, prev
        for j in range(lb + 1):
            cur[j] = 0
    return prev[lb]


def lcs_similarity(a: bytes, b: bytes) -> float:
    if not a and not b:
        return 1.0
    if not a or not b:
        return 0.0
    CAP = 512
    a_t = a[:CAP]
    b_t = b[:CAP]
    lcs = _lcs_len(a_t, b_t)
    denom = max(len(a_t), len(b_t))
    base = lcs / denom if denom else 0.0
    # coverage scaling: avoid inflated similarity on truncation
    coverage = min(len(a_t), len(b_t)) / max(len(a), len(b))
    score = base * coverage
    if score < 0.0:
        return 0.0
    if score > 1.0:
        return 1.0
    return score


def byte_histogram_similarity(a: bytes, b: bytes) -> float:
    if not a and not b:
        return 1.0
    if not a or not b:
        return 0.0
    ha = [0] * 256
    hb = [0] * 256
    for x in a:
        ha[x] += 1
    for x in b:
        hb[x] += 1
    la = len(a)
    lb = len(b)
    # Bhattacharyya coefficient
    import math
    bc = 0.0
    for i in range(256):
        if ha[i] and hb[i]:
            bc += math.sqrt((ha[i] / la) * (hb[i] / lb))
    if bc < 0.0:
        return 0.0
    if bc > 1.0:
        return 1.0
    return bc


def ngram_jaccard_similarity(a: bytes, b: bytes, n: int) -> float:
    if not a and not b:
        return 1.0
    if not a or not b:
        return 0.0
    if n < 1:
        n = 1
    if n > 8:
        n = 8
    CAP = 4096
    a_t = a[:CAP]
    b_t = b[:CAP]
    if len(a_t) < n or len(b_t) < n:
        return 0.0
    sa = set(a_t[i:i + n] for i in range(len(a_t) - n + 1))
    sb = set(b_t[i:i + n] for i in range(len(b_t) - n + 1))
    inter = len(sa & sb)
    union = len(sa | sb)
    if union == 0:
        return 0.0
    return inter / union


def combined_byte_similarity(a: bytes, b: bytes) -> float:
    return 0.6 * byte_histogram_similarity(a, b) + 0.4 * ngram_jaccard_similarity(a, b, 4)


@dataclass
class FuncFingerprint:
    address: int
    name: str
    size: int
    hash: int
    bytes_: bytes = b""
    call_count: int = 0
    block_count: int = 0
    edge_count: int = 0

    @classmethod
    def new(cls, address: int, name: str, data: bytes) -> "FuncFingerprint":
        return cls(address=address, name=name, size=len(data),
                   hash=simple_hash(data), bytes_=data)

    def similarity(self, other: "FuncFingerprint") -> float:
        if self.hash == other.hash:
            return 1.0
        lcs = lcs_similarity(self.bytes_, other.bytes_)
        if self.size == 0 and other.size == 0:
            size_ratio = 1.0
        elif self.size == 0 or other.size == 0:
            size_ratio = 0.0
        else:
            size_ratio = min(self.size, other.size) / max(self.size, other.size)
        return 0.7 * lcs + 0.3 * size_ratio

    def __str__(self) -> str:
        return f"{self.name}@0x{self.address:X} sz={self.size}"


class MatchKind(Enum):
    Identical = "Identical"
    Similar = "Similar"
    Added = "Added"
    Removed = "Removed"
    Renamed = "Renamed"


@dataclass
class FuncMatch:
    primary: Optional[FuncFingerprint]
    secondary: Optional[FuncFingerprint]
    kind: MatchKind
    similarity: float
    confidence: int

    @classmethod
    def identical(cls, a, b):
        return cls(a, b, MatchKind.Identical, 1.0, 100)

    @classmethod
    def similar(cls, a, b, sim):
        return cls(a, b, MatchKind.Similar, sim, int(sim * 100))

    @classmethod
    def renamed(cls, a, b, sim):
        return cls(a, b, MatchKind.Renamed, sim, int(sim * 100))

    @classmethod
    def added(cls, b):
        return cls(None, b, MatchKind.Added, 0.0, 100)

    @classmethod
    def removed(cls, a):
        return cls(a, None, MatchKind.Removed, 0.0, 100)

    def is_changed(self) -> bool:
        return self.kind != MatchKind.Identical


@dataclass
class BinaryDiff:
    name_a: str
    name_b: str
    matches: List[FuncMatch] = field(default_factory=list)
    total_functions_a: int = 0
    total_functions_b: int = 0
    diff_time_ms: int = 0

    def identical_count(self) -> int:
        return sum(1 for m in self.matches if m.kind == MatchKind.Identical)

    def added_count(self) -> int:
        return sum(1 for m in self.matches if m.kind == MatchKind.Added)

    def removed_count(self) -> int:
        return sum(1 for m in self.matches if m.kind == MatchKind.Removed)

    def changed_count(self) -> int:
        return sum(1 for m in self.matches
                   if m.kind in (MatchKind.Similar, MatchKind.Renamed))

    def similarity_ratio(self) -> float:
        paired = [m for m in self.matches
                  if m.primary is not None and m.secondary is not None]
        if not paired:
            return 0.0
        return sum(m.similarity for m in paired) / len(paired)


class DiffError(Exception):
    pass


@dataclass
class DiffEngine:
    similarity_threshold: float = 0.6

    def diff(self, funcs_a: List[FuncFingerprint],
             funcs_b: List[FuncFingerprint],
             name_a: str, name_b: str) -> BinaryDiff:
        if not funcs_a and not funcs_b:
            raise DiffError("EmptyInput: both inputs empty")

        out = BinaryDiff(name_a=name_a, name_b=name_b,
                         total_functions_a=len(funcs_a),
                         total_functions_b=len(funcs_b))

        # Pass 1: identical-hash pairing.
        b_by_hash: Dict[int, List[int]] = {}
        for i, fb in enumerate(funcs_b):
            b_by_hash.setdefault(fb.hash, []).append(i)
        used_b = set()
        unmatched_a: List[FuncFingerprint] = []
        for fa in funcs_a:
            bucket = b_by_hash.get(fa.hash, [])
            picked = None
            for idx in bucket:
                if idx not in used_b:
                    picked = idx
                    break
            if picked is not None:
                used_b.add(picked)
                out.matches.append(FuncMatch.identical(fa, funcs_b[picked]))
            else:
                unmatched_a.append(fa)

        # Pass 2: greedy similarity for the residue.
        remaining_b = [i for i in range(len(funcs_b)) if i not in used_b]
        for fa in unmatched_a:
            best_idx = -1
            best_sim = self.similarity_threshold
            for idx in remaining_b:
                sim = fa.similarity(funcs_b[idx])
                if sim >= best_sim:
                    best_sim = sim
                    best_idx = idx
            if best_idx >= 0:
                fb = funcs_b[best_idx]
                remaining_b.remove(best_idx)
                if best_sim > 0.9 and fa.name != fb.name:
                    out.matches.append(FuncMatch.renamed(fa, fb, best_sim))
                else:
                    out.matches.append(FuncMatch.similar(fa, fb, best_sim))
            else:
                out.matches.append(FuncMatch.removed(fa))

        for idx in remaining_b:
            out.matches.append(FuncMatch.added(funcs_b[idx]))

        return out


class ChangeType:
    @staticmethod
    def added(): return ("Added", None)
    @staticmethod
    def removed(): return ("Removed", None)
    @staticmethod
    def modified(sim): return ("Modified", sim)
    @staticmethod
    def unchanged(): return ("Unchanged", None)


@dataclass
class FunctionDiff:
    addr_a: Optional[int]
    addr_b: Optional[int]
    name_a: Optional[str]
    name_b: Optional[str]
    similarity: float
    change_type: Tuple[str, Optional[float]]

    def display_name(self) -> str:
        return self.name_a or self.name_b or "<unknown>"


@dataclass
class NamedBinaryDiff:
    functions: List[FunctionDiff] = field(default_factory=list)
    overall_similarity: float = 0.0

    def added_count(self):
        return sum(1 for f in self.functions if f.change_type[0] == "Added")

    def removed_count(self):
        return sum(1 for f in self.functions if f.change_type[0] == "Removed")

    def modified_count(self):
        return sum(1 for f in self.functions if f.change_type[0] == "Modified")

    def unchanged_count(self):
        return sum(1 for f in self.functions if f.change_type[0] == "Unchanged")


def diff_by_name(map_a: Dict[str, bytes],
                 map_b: Dict[str, bytes]) -> NamedBinaryDiff:
    out = NamedBinaryDiff()
    keys = set(map_a) | set(map_b)
    sims = []
    for k in keys:
        a = map_a.get(k)
        b = map_b.get(k)
        if a is not None and b is not None:
            sim = combined_byte_similarity(a, b)
            sims.append(sim)
            if sim >= 0.999999:
                ct = ChangeType.unchanged()
            else:
                ct = ChangeType.modified(sim)
            out.functions.append(FunctionDiff(None, None, k, k, sim, ct))
        elif a is not None:
            out.functions.append(FunctionDiff(None, None, k, None, 0.0,
                                              ChangeType.removed()))
        else:
            out.functions.append(FunctionDiff(None, None, None, k, 0.0,
                                              ChangeType.added()))

    order = {"Unchanged": 0, "Modified": 1, "Removed": 2, "Added": 3}

    def sort_key(f: FunctionDiff):
        cat = f.change_type[0]
        # Modified desc by similarity, others by name.
        if cat == "Modified":
            return (order[cat], -f.similarity, f.display_name())
        return (order[cat], 0.0, f.display_name())

    out.functions.sort(key=sort_key)

    paired = max(1, len(set(map_a) & set(map_b)))
    union = max(1, len(keys))
    coverage = len(set(map_a) & set(map_b)) / union
    mean_sim = sum(sims) / paired if sims else 0.0
    out.overall_similarity = mean_sim * coverage
    return out


@dataclass
class ExportEntry:
    ordinal: int
    address: int
    name: Optional[str] = None

    def key(self) -> str:
        return self.name if self.name else f"@{self.ordinal}"


@dataclass
class ExportDiff:
    removed: List[ExportEntry] = field(default_factory=list)
    added: List[ExportEntry] = field(default_factory=list)
    moved: List[Tuple[ExportEntry, ExportEntry]] = field(default_factory=list)
    unchanged: List[ExportEntry] = field(default_factory=list)

    def is_clean(self) -> bool:
        return not (self.removed or self.added or self.moved)


def diff_exports(a: List[ExportEntry], b: List[ExportEntry]) -> ExportDiff:
    out = ExportDiff()
    by_a = {e.key(): e for e in a}
    by_b = {e.key(): e for e in b}
    for k in sorted(set(by_a) | set(by_b)):
        ea = by_a.get(k)
        eb = by_b.get(k)
        if ea is not None and eb is not None:
            if ea.address != eb.address:
                out.moved.append((ea, eb))
            else:
                out.unchanged.append(ea)
        elif ea is not None:
            out.removed.append(ea)
        else:
            out.added.append(eb)
    return out


# ---------------------------------------------------------------------------
# Smoke tests when run directly.
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    assert simple_hash(b"") == FNV_OFFSET
    assert lcs_similarity(b"", b"") == 1.0
    assert lcs_similarity(b"abc", b"") == 0.0
    assert abs(lcs_similarity(b"abcd", b"abcd") - 1.0) < 1e-9
    assert byte_histogram_similarity(b"aaaa", b"aaaa") > 0.999
    assert ngram_jaccard_similarity(b"abcd", b"abcd", 2) == 1.0

    f1 = FuncFingerprint.new(0x1000, "foo", b"\x90" * 32)
    f2 = FuncFingerprint.new(0x2000, "foo", b"\x90" * 32)
    assert f1.similarity(f2) == 1.0

    f3 = FuncFingerprint.new(0x3000, "bar", b"\x90" * 30 + b"\xCC\xCC")
    assert 0.0 < f1.similarity(f3) < 1.0

    eng = DiffEngine()
    diff = eng.diff([f1, f3], [f2], "a", "b")
    assert diff.identical_count() == 1
    assert diff.removed_count() == 1

    try:
        eng.diff([], [], "a", "b")
        raise SystemExit("expected EmptyInput")
    except DiffError:
        pass

    nd = diff_by_name({"x": b"hello", "y": b"abc"},
                      {"x": b"hello", "z": b"qqq"})
    assert nd.unchanged_count() == 1
    assert nd.added_count() == 1
    assert nd.removed_count() == 1

    ed = diff_exports(
        [ExportEntry(1, 0x100, "foo"), ExportEntry(2, 0x200, "bar")],
        [ExportEntry(1, 0x100, "foo"), ExportEntry(2, 0x999, "bar")],
    )
    assert len(ed.moved) == 1
    assert len(ed.unchanged) == 1
    assert not ed.is_clean()

    print("rustre-diff.py: smoke OK")
