"""Independent validator for rustre-fuzz-afl crate.

Reimplements pure-logic primitives described in
validation/reports/rustre-fuzz-afl.md using only Python stdlib.
Covers AFL coverage-map bucket classification, virgin-bits diffing,
similarity metrics, fnv1a hashing, deterministic mutation stages,
and greedy minimal covering set.
"""

import json
from typing import List, Tuple


AFL_MAP_SIZE = 65536
STAGE_INPUT_MAX_BYTES = 4096

INTERESTING_8 = [-128, -1, 0, 1, 16, 32, 64, 100, 127]
INTERESTING_16 = INTERESTING_8 + [-32768, -129, 128, 255, 256, 512, 1000, 1024, 4096, 32767]
INTERESTING_32 = INTERESTING_16 + [-2147483648, -100663046, -32769, 32768, 65535, 65536, 100663045, 2147483647]


# ---------- coverage bucket classifier (AFL log2-style) ----------
def cov_classify_count(c: int) -> int:
    c &= 0xFF
    if c == 0:
        return 0
    if c == 1:
        return 1
    if c == 2:
        return 2
    if c == 3:
        return 4
    if 4 <= c <= 7:
        return 8
    if 8 <= c <= 15:
        return 16
    if 16 <= c <= 31:
        return 32
    if 32 <= c <= 127:
        return 64
    return 128


def has_new_coverage(virgin: List[int], trace: List[int]) -> bool:
    for v, t in zip(virgin, trace):
        if t and (v & t) != 0:
            return True
    return False


def update_virgin(virgin: List[int], trace: List[int]) -> List[int]:
    return [v & (~t & 0xFF) for v, t in zip(virgin, trace)]


# ---------- similarity ----------
def hamming_distance(a: bytes, b: bytes) -> int:
    n = min(len(a), len(b))
    d = abs(len(a) - len(b)) * 8
    for i in range(n):
        d += bin(a[i] ^ b[i]).count("1")
    return d


def jaccard_similarity(a: List[int], b: List[int]) -> float:
    sa = set(i for i, v in enumerate(a) if v)
    sb = set(i for i, v in enumerate(b) if v)
    if not sa and not sb:
        return 1.0
    return len(sa & sb) / len(sa | sb)


# ---------- fnv1a (shared primitive from rustre-fuzz) ----------
def fnv1a_64(data: bytes) -> int:
    h = 0xcbf29ce484222325
    for byte in data:
        h ^= byte
        h = (h * 0x100000001b3) & 0xFFFFFFFFFFFFFFFF
    return h


# ---------- deterministic stages ----------
def stage_bit_flip_1(input_bytes: bytes) -> List[bytes]:
    out = []
    data = input_bytes[:STAGE_INPUT_MAX_BYTES]
    for bit in range(len(data) * 8):
        b = bytearray(data)
        b[bit // 8] ^= 1 << (bit % 8)
        out.append(bytes(b))
    return out


def stage_byte_flip_1(input_bytes: bytes) -> List[bytes]:
    out = []
    data = input_bytes[:STAGE_INPUT_MAX_BYTES]
    for i in range(len(data)):
        b = bytearray(data)
        b[i] ^= 0xFF
        out.append(bytes(b))
    return out


def stage_arith_8(input_bytes: bytes) -> List[bytes]:
    out = []
    data = input_bytes[:STAGE_INPUT_MAX_BYTES]
    for i in range(len(data)):
        for delta in range(-35, 36):
            if delta == 0:
                continue
            b = bytearray(data)
            b[i] = (b[i] + delta) & 0xFF
            out.append(bytes(b))
    return out


def stage_interesting_8(input_bytes: bytes) -> List[bytes]:
    out = []
    data = input_bytes[:STAGE_INPUT_MAX_BYTES]
    for i in range(len(data)):
        for v in INTERESTING_8:
            b = bytearray(data)
            b[i] = v & 0xFF
            out.append(bytes(b))
    return out


def stage_splice(a: bytes, b: bytes) -> bytes:
    if not a or not b:
        return a
    split = min(len(a), len(b)) // 2
    return a[:split] + b[split:]


# ---------- minimal covering set (greedy set-cover) ----------
def minimal_covering_set(inputs: List[bytes], coverage: List[List[int]]) -> List[int]:
    universe = set()
    for cov in coverage:
        universe.update(cov)
    selected = []
    covered = set()
    available = list(range(len(inputs)))
    while covered != universe and available:
        best_i, best_gain = -1, -1
        for idx in available:
            gain = len(set(coverage[idx]) - covered)
            if gain > best_gain:
                best_gain, best_i = gain, idx
        if best_gain <= 0:
            break
        selected.append(best_i)
        covered.update(coverage[best_i])
        available.remove(best_i)
    return selected


# ---------- validators ----------
def fn_constants():
    return {
        "AFL_MAP_SIZE": AFL_MAP_SIZE,
        "BITMAP_SIZE": 1 << 16,
        "STAGE_INPUT_MAX_BYTES": STAGE_INPUT_MAX_BYTES,
        "INTERESTING_8_len": len(INTERESTING_8),
        "INTERESTING_16_len": len(INTERESTING_16),
        "INTERESTING_32_len": len(INTERESTING_32),
    }


def fn_cov_classify_count():
    return {str(c): cov_classify_count(c) for c in [0, 1, 2, 3, 4, 7, 8, 15, 16, 31, 32, 127, 128, 255]}


def fn_has_new_coverage():
    virgin = [0xFF] * 8
    trace_no_new = [0] * 8
    trace_new = [0, 1, 0, 0, 0, 0, 0, 0]
    virgin2 = update_virgin(virgin, trace_new)
    return {
        "virgin_vs_empty": has_new_coverage(virgin, trace_no_new),
        "virgin_vs_new": has_new_coverage(virgin, trace_new),
        "after_update": has_new_coverage(virgin2, trace_new),
        "virgin_updated": virgin2,
    }


def fn_similarity():
    return {
        "hamming_equal": hamming_distance(b"abc", b"abc"),
        "hamming_diff": hamming_distance(b"abc", b"abd"),
        "hamming_lendiff": hamming_distance(b"abc", b"abcd"),
        "jaccard_equal": jaccard_similarity([1, 1, 0, 1], [1, 1, 0, 1]),
        "jaccard_disjoint": jaccard_similarity([1, 0, 0, 0], [0, 1, 0, 0]),
        "jaccard_empty": jaccard_similarity([0, 0], [0, 0]),
    }


def fn_fnv1a():
    return {
        "empty": fnv1a_64(b""),
        "a": fnv1a_64(b"a"),
        "foobar": fnv1a_64(b"foobar"),
    }


def fn_stage_bit_flip_1():
    out = stage_bit_flip_1(b"AB")
    return {"count": len(out), "first_hex": out[0].hex(), "last_hex": out[-1].hex()}


def fn_stage_byte_flip_1():
    out = stage_byte_flip_1(b"AB")
    return {"count": len(out), "results_hex": [o.hex() for o in out]}


def fn_stage_arith_8():
    out = stage_arith_8(b"\x00")
    return {"count": len(out), "expected_per_byte": 70}


def fn_stage_interesting_8():
    out = stage_interesting_8(b"\x00")
    return {"count": len(out), "values_set": sorted({o[0] for o in out})}


def fn_stage_splice():
    return {
        "splice": stage_splice(b"AAAA", b"BBBB").hex(),
        "splice_empty": stage_splice(b"", b"BBBB").hex(),
    }


def fn_minimal_covering_set():
    inputs = [b"a", b"b", b"c", b"d"]
    coverage = [[1, 2, 3], [3, 4], [1, 4], [5]]
    sel = minimal_covering_set(inputs, coverage)
    return {"selected": sel, "selected_count": len(sel)}


FUNCTIONS = [
    ("constants", fn_constants),
    ("cov_classify_count", fn_cov_classify_count),
    ("has_new_coverage", fn_has_new_coverage),
    ("similarity", fn_similarity),
    ("fnv1a", fn_fnv1a),
    ("stage_bit_flip_1", fn_stage_bit_flip_1),
    ("stage_byte_flip_1", fn_stage_byte_flip_1),
    ("stage_arith_8", fn_stage_arith_8),
    ("stage_interesting_8", fn_stage_interesting_8),
    ("stage_splice", fn_stage_splice),
    ("minimal_covering_set", fn_minimal_covering_set),
]


def main():
    results = []
    for name, fn in FUNCTIONS:
        try:
            results.append({"name": name, "ok": True, "result": fn()})
        except Exception as e:
            results.append({"name": name, "ok": False, "error": str(e)})
    out = {"crate": "rustre-fuzz-afl", "saved": True, "functions": results}
    print(json.dumps(out, indent=2, default=str))


if __name__ == "__main__":
    main()
