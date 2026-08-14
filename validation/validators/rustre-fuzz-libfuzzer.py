"""Independent validator for rustre-fuzz-libfuzzer.

Implements ground-truth reference behavior in pure Python (stdlib only) for
cross-checking the Rust crate `rustre-fuzz-libfuzzer`. No imports of the Rust
crate and no MCP calls.

Covers:
- numeric `cast::*` helpers (saturating / lossless conversions)
- deterministic RNG (xorshift64*-style)
- mutator plugins: ByteFlip, BitFlip, Insert, Delete, Splice, DictEntry,
  Arithmetic, InterestingValue, ChunkCopy, MutatorChain
- coverage feedback / edge tracking
- crash hashing / dedup
- crash triage (severity classification)
- corpus management (selection, shrinking)
- libfuzzer corpus file naming (sha1)
"""
from __future__ import annotations

import hashlib
import math
import struct
from typing import Any, Dict, List, Optional, Sequence, Tuple


# =============================================================================
# cast::* helpers
# =============================================================================

U8_MAX = 0xFF
U16_MAX = 0xFFFF
U32_MAX = 0xFFFF_FFFF
U64_MAX = 0xFFFF_FFFF_FFFF_FFFF
I32_MAX = 0x7FFF_FFFF


def u64_to_f64(x: int) -> float:
    return float(x & U64_MAX)


def usize_to_f64(x: int) -> float:
    return float(max(0, x))


def i64_to_f64(x: int) -> float:
    return float(x)


def u32_to_f64(x: int) -> float:
    return float(x & U32_MAX)


def u64_to_usize(x: int) -> int:
    # On 64-bit platforms usize == u64
    return x & U64_MAX


def u64_to_u32(x: int) -> int:
    return min(x & U64_MAX, U32_MAX)


def u64_to_u16(x: int) -> int:
    return min(x & U64_MAX, U16_MAX)


def u64_to_u8(x: int) -> int:
    return min(x & U64_MAX, U8_MAX)


def u128_to_u64(x: int) -> int:
    return min(x, U64_MAX)


def usize_to_u32(x: int) -> int:
    return min(max(0, x), U32_MAX)


def usize_to_u16(x: int) -> int:
    return min(max(0, x), U16_MAX)


def usize_to_u8(x: int) -> int:
    return min(max(0, x), U8_MAX)


def usize_to_i32(x: int) -> int:
    return min(max(0, x), I32_MAX)


# =============================================================================
# Deterministic RNG (xorshift64*)
# =============================================================================

class Rng:
    def __init__(self, seed: int = 0xDEAD_BEEF_CAFE_BABE) -> None:
        self.state = seed & U64_MAX
        if self.state == 0:
            self.state = 0x1
        self.calls = 0

    def next_u64(self) -> int:
        x = self.state
        x ^= (x << 13) & U64_MAX
        x ^= (x >> 7) & U64_MAX
        x ^= (x << 17) & U64_MAX
        self.state = x & U64_MAX
        self.calls += 1
        return self.state

    def gen_range(self, lo: int, hi: int) -> int:
        # half-open [lo, hi)
        if hi <= lo:
            return lo
        return lo + (self.next_u64() % (hi - lo))

    def choice(self, seq: Sequence[Any]) -> Any:
        if not seq:
            raise ValueError("empty sequence")
        return seq[self.next_u64() % len(seq)]


# =============================================================================
# Mutator plugins
# =============================================================================

INTERESTING_U8 = [0, 1, 0x7F, 0x80, 0xFF]
INTERESTING_U16 = [0, 1, 0x7FFF, 0x8000, 0xFFFF]
INTERESTING_U32 = [0, 1, 0x7FFF_FFFF, 0x8000_0000, 0xFFFF_FFFF]


def byte_flip(buf: bytes, rng: Rng) -> bytes:
    if not buf:
        return buf
    out = bytearray(buf)
    idx = rng.gen_range(0, len(out))
    out[idx] = (out[idx] ^ 0xFF) & 0xFF
    return bytes(out)


def bit_flip(buf: bytes, rng: Rng) -> bytes:
    if not buf:
        return buf
    out = bytearray(buf)
    idx = rng.gen_range(0, len(out))
    bit = rng.gen_range(0, 8)
    out[idx] ^= (1 << bit) & 0xFF
    return bytes(out)


def insert_mut(buf: bytes, rng: Rng, max_len: int = 65536) -> bytes:
    if len(buf) >= max_len:
        return buf
    idx = rng.gen_range(0, len(buf) + 1)
    val = rng.gen_range(0, 256)
    return bytes(buf[:idx]) + bytes([val]) + bytes(buf[idx:])


def delete_mut(buf: bytes, rng: Rng) -> bytes:
    if not buf:
        return buf
    idx = rng.gen_range(0, len(buf))
    return bytes(buf[:idx]) + bytes(buf[idx + 1:])


def splice_mut(a: bytes, b: bytes, rng: Rng) -> bytes:
    if not a or not b:
        return a
    cut_a = rng.gen_range(0, len(a))
    cut_b = rng.gen_range(0, len(b))
    return bytes(a[:cut_a]) + bytes(b[cut_b:])


def dict_entry_mut(buf: bytes, rng: Rng, dictionary: Sequence[bytes]) -> bytes:
    if not dictionary:
        return buf
    entry = dictionary[rng.gen_range(0, len(dictionary))]
    idx = rng.gen_range(0, len(buf) + 1) if buf else 0
    return bytes(buf[:idx]) + bytes(entry) + bytes(buf[idx:])


def arithmetic_mut(buf: bytes, rng: Rng) -> bytes:
    if not buf:
        return buf
    out = bytearray(buf)
    idx = rng.gen_range(0, len(out))
    delta = rng.gen_range(0, 70) - 35  # [-35, 35)
    out[idx] = (out[idx] + delta) & 0xFF
    return bytes(out)


def interesting_value_mut(buf: bytes, rng: Rng) -> bytes:
    if not buf:
        return buf
    out = bytearray(buf)
    idx = rng.gen_range(0, len(out))
    val = INTERESTING_U8[rng.gen_range(0, len(INTERESTING_U8))]
    out[idx] = val & 0xFF
    return bytes(out)


def chunk_copy_mut(buf: bytes, rng: Rng) -> bytes:
    if len(buf) < 2:
        return buf
    src = rng.gen_range(0, len(buf))
    dst = rng.gen_range(0, len(buf))
    length = rng.gen_range(1, min(16, len(buf) - max(src, dst) + 1) + 1)
    out = bytearray(buf)
    chunk = bytes(buf[src:src + length])
    out[dst:dst + len(chunk)] = chunk
    return bytes(out[:len(buf)])


def mutator_chain(buf: bytes, rng: Rng, plugins: Sequence[str],
                  dictionary: Optional[Sequence[bytes]] = None) -> bytes:
    cur = buf
    for name in plugins:
        if name == "ByteFlip":
            cur = byte_flip(cur, rng)
        elif name == "BitFlip":
            cur = bit_flip(cur, rng)
        elif name == "Insert":
            cur = insert_mut(cur, rng)
        elif name == "Delete":
            cur = delete_mut(cur, rng)
        elif name == "Arithmetic":
            cur = arithmetic_mut(cur, rng)
        elif name == "InterestingValue":
            cur = interesting_value_mut(cur, rng)
        elif name == "ChunkCopy":
            cur = chunk_copy_mut(cur, rng)
        elif name == "DictEntry":
            cur = dict_entry_mut(cur, rng, dictionary or [])
        else:
            raise ValueError(f"unknown plugin {name}")
    return cur


# =============================================================================
# Coverage feedback / edge tracking
# =============================================================================

class CoverageFeedback:
    def __init__(self, edge_count: int = 65536) -> None:
        self.edges = [0] * edge_count
        self.virgin = [True] * edge_count

    def record(self, edges_hit: Sequence[int]) -> bool:
        """Return True if any new edge was hit."""
        new = False
        for e in edges_hit:
            e_idx = e % len(self.edges)
            if self.virgin[e_idx]:
                self.virgin[e_idx] = False
                new = True
            self.edges[e_idx] += 1
        return new

    def total_edges(self) -> int:
        return sum(1 for v in self.virgin if not v)


# =============================================================================
# Crash dedup / triage
# =============================================================================

def crash_hash(stack: Sequence[str], top_n: int = 5) -> str:
    """Hash top-N stack frames for dedup."""
    blob = "\n".join(stack[:top_n]).encode("utf-8")
    return hashlib.sha256(blob).hexdigest()


def triage_crash(signal: str, stack: Sequence[str]) -> Dict[str, Any]:
    """Classify crash severity.

    Returns dict with: kind, severity ("critical"|"high"|"medium"|"low"),
    exploitable (bool).
    """
    sig = signal.upper()
    joined = " ".join(stack).lower()
    if sig in ("SIGSEGV", "SIGBUS") and ("write" in joined or "memcpy" in joined or "strcpy" in joined):
        return {"kind": "memory-corruption", "severity": "critical", "exploitable": True}
    if sig == "SIGSEGV":
        return {"kind": "null-deref-or-oob", "severity": "high", "exploitable": False}
    if sig == "SIGABRT" and "assert" in joined:
        return {"kind": "assertion", "severity": "medium", "exploitable": False}
    if sig == "SIGABRT":
        return {"kind": "abort", "severity": "medium", "exploitable": False}
    if sig == "SIGFPE":
        return {"kind": "fp-exception", "severity": "low", "exploitable": False}
    if sig in ("SIGALRM", "TIMEOUT"):
        return {"kind": "timeout", "severity": "low", "exploitable": False}
    return {"kind": "unknown", "severity": "low", "exploitable": False}


def dedup_crashes(crashes: Sequence[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """crashes: [{"stack":[...], "signal":...}, ...] -> uniques."""
    seen = {}
    for c in crashes:
        h = crash_hash(c.get("stack", []))
        if h not in seen:
            seen[h] = c
    return list(seen.values())


# =============================================================================
# Corpus management
# =============================================================================

def libfuzzer_corpus_name(data: bytes) -> str:
    """libFuzzer canonical filename = sha1(content) hex."""
    return hashlib.sha1(data).hexdigest()


class CorpusEntry:
    __slots__ = ("data", "coverage", "size")

    def __init__(self, data: bytes, coverage: Sequence[int]) -> None:
        self.data = bytes(data)
        self.coverage = set(coverage)
        self.size = len(self.data)


class CorpusManager:
    def __init__(self) -> None:
        self.entries: List[CorpusEntry] = []
        self._global_edges: set = set()

    def add(self, data: bytes, coverage: Sequence[int]) -> bool:
        """Add if it covers a new edge. Returns True if added."""
        cov = set(coverage)
        if cov - self._global_edges:
            self.entries.append(CorpusEntry(data, cov))
            self._global_edges |= cov
            return True
        return False

    def shrink(self) -> List[CorpusEntry]:
        """Greedy set cover: pick minimal entries covering all edges, prefer
        smaller inputs."""
        needed = set(self._global_edges)
        candidates = sorted(self.entries, key=lambda e: (-len(e.coverage), e.size))
        kept: List[CorpusEntry] = []
        for e in candidates:
            if e.coverage & needed:
                kept.append(e)
                needed -= e.coverage
                if not needed:
                    break
        self.entries = kept
        return kept

    def total_coverage(self) -> int:
        return len(self._global_edges)


# =============================================================================
# Validators (mirrors of pub fn surface used by harness)
# =============================================================================

def validator_cast(input: Dict[str, Any]) -> Dict[str, Any]:
    """input: {"fn": "<name>", "x": <int>}"""
    name = input["fn"]
    x = input["x"]
    fns = {
        "u64_to_f64": u64_to_f64, "usize_to_f64": usize_to_f64,
        "i64_to_f64": i64_to_f64, "u32_to_f64": u32_to_f64,
        "u64_to_usize": u64_to_usize, "u64_to_u32": u64_to_u32,
        "u64_to_u16": u64_to_u16, "u64_to_u8": u64_to_u8,
        "u128_to_u64": u128_to_u64, "usize_to_u32": usize_to_u32,
        "usize_to_u16": usize_to_u16, "usize_to_u8": usize_to_u8,
        "usize_to_i32": usize_to_i32,
    }
    return {"result": fns[name](x)}


def validator_rng(input: Dict[str, Any]) -> Dict[str, Any]:
    rng = Rng(input.get("seed", 0xDEAD_BEEF_CAFE_BABE))
    n = input.get("n", 8)
    return {"values": [rng.next_u64() for _ in range(n)]}


def validator_mutate(input: Dict[str, Any]) -> Dict[str, Any]:
    rng = Rng(input.get("seed", 1))
    buf = bytes.fromhex(input["data_hex"])
    plugins = input.get("plugins", ["ByteFlip"])
    dictionary = [bytes.fromhex(h) for h in input.get("dict_hex", [])]
    out = mutator_chain(buf, rng, plugins, dictionary)
    return {"data_hex": out.hex(), "len": len(out)}


def validator_coverage(input: Dict[str, Any]) -> Dict[str, Any]:
    cov = CoverageFeedback(input.get("edge_count", 4096))
    any_new = False
    for batch in input["batches"]:
        any_new |= cov.record(batch)
    return {"total_edges": cov.total_edges(), "any_new": any_new}


def validator_triage(input: Dict[str, Any]) -> Dict[str, Any]:
    return triage_crash(input["signal"], input.get("stack", []))


def validator_dedup(input: Dict[str, Any]) -> Dict[str, Any]:
    out = dedup_crashes(input["crashes"])
    return {"unique": len(out), "hashes": [crash_hash(c.get("stack", [])) for c in out]}


def validator_corpus_name(input: Dict[str, Any]) -> Dict[str, Any]:
    return {"name": libfuzzer_corpus_name(bytes.fromhex(input["data_hex"]))}


def validator_corpus_manager(input: Dict[str, Any]) -> Dict[str, Any]:
    cm = CorpusManager()
    added = 0
    for item in input["inputs"]:
        if cm.add(bytes.fromhex(item["data_hex"]), item["coverage"]):
            added += 1
    if input.get("shrink"):
        cm.shrink()
    return {
        "added": added,
        "kept": len(cm.entries),
        "total_coverage": cm.total_coverage(),
    }


VALIDATORS = {
    "cast": validator_cast,
    "rng": validator_rng,
    "mutate": validator_mutate,
    "coverage": validator_coverage,
    "triage": validator_triage,
    "dedup": validator_dedup,
    "corpus_name": validator_corpus_name,
    "corpus_manager": validator_corpus_manager,
}


if __name__ == "__main__":
    import json, sys
    if len(sys.argv) < 2:
        print(json.dumps({"validators": list(VALIDATORS)}))
        sys.exit(0)
    name = sys.argv[1]
    payload = json.loads(sys.stdin.read() or "{}")
    print(json.dumps(VALIDATORS[name](payload)))
