#!/usr/bin/env python3
"""
Standalone validator for rustre-hex crate.

Reimplements core hex-buffer / analysis logic in pure Python to act as
ground truth. No Rust import, no MCP calls.

Usage:
    echo '{"fn":"xor_range","data":"deadbeef","key":"ff"}' | python rustre-hex.py
    python rustre-hex.py            # runs self-tests
"""

import json
import math
import re
import struct
import sys
from collections import Counter


# ---------- helpers ----------

def _b(x):
    """Accept hex string or list[int] -> bytes."""
    if isinstance(x, (bytes, bytearray)):
        return bytes(x)
    if isinstance(x, list):
        return bytes(x)
    if isinstance(x, str):
        return bytes.fromhex(x)
    raise TypeError(f"cannot coerce {type(x)} to bytes")


# ---------- pure analysis ----------

def validator_byte_statistics(data):
    data = _b(data)
    if not data:
        return {"count": 0, "min": None, "max": None, "mean": 0.0,
                "median": 0.0, "stddev": 0.0, "entropy": 0.0,
                "unique": 0, "mode": None, "mode_freq": 0}
    n = len(data)
    counts = Counter(data)
    mean = sum(data) / n
    var = sum((b - mean) ** 2 for b in data) / n
    stddev = math.sqrt(var)
    sd = sorted(data)
    if n % 2:
        median = float(sd[n // 2])
    else:
        median = (sd[n // 2 - 1] + sd[n // 2]) / 2
    entropy = 0.0
    for c in counts.values():
        p = c / n
        entropy -= p * math.log2(p)
    mode, mode_freq = counts.most_common(1)[0]
    return {"count": n, "min": min(data), "max": max(data),
            "mean": mean, "median": median, "stddev": stddev,
            "entropy": entropy, "unique": len(counts),
            "mode": mode, "mode_freq": mode_freq}


def validator_histogram(data):
    data = _b(data)
    h = [0] * 256
    for b in data:
        h[b] += 1
    return h


def validator_histogram_top_n(data, n):
    h = validator_histogram(data)
    pairs = [(i, c) for i, c in enumerate(h) if c > 0]
    pairs.sort(key=lambda p: (-p[1], p[0]))
    return pairs[:n]


def validator_entropy_blocks(data, block_size):
    data = _b(data)
    out = []
    for i in range(0, len(data), block_size):
        block = data[i:i + block_size]
        if not block:
            continue
        counts = Counter(block)
        n = len(block)
        e = 0.0
        for c in counts.values():
            p = c / n
            e -= p * math.log2(p)
        out.append(e)
    return out


def validator_shannon_entropy(data):
    data = _b(data)
    if not data:
        return 0.0
    counts = Counter(data)
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


# ---------- typed reads ----------

_TYPE_FMTS = {
    "u8": "<B", "i8": "<b",
    "u16le": "<H", "u16be": ">H", "i16le": "<h", "i16be": ">h",
    "u32le": "<I", "u32be": ">I", "i32le": "<i", "i32be": ">i",
    "u64le": "<Q", "u64be": ">Q", "i64le": "<q", "i64be": ">q",
    "f32le": "<f", "f32be": ">f",
    "f64le": "<d", "f64be": ">d",
}


def validator_read_typed(data, offset, dtype, n=None):
    data = _b(data)
    if dtype in _TYPE_FMTS:
        fmt = _TYPE_FMTS[dtype]
        size = struct.calcsize(fmt)
        return struct.unpack(fmt, data[offset:offset + size])[0]
    if dtype == "bytes":
        return list(data[offset:offset + n])
    if dtype == "cstr":
        end = data.find(b"\x00", offset)
        if end < 0:
            end = len(data)
        return data[offset:end].decode("utf-8", errors="replace")
    if dtype == "utf16le":
        raw = data[offset:offset + n * 2]
        return raw.decode("utf-16-le", errors="replace")
    raise ValueError(f"unknown dtype {dtype}")


# ---------- bitwise / arithmetic transforms ----------

def _apply_range(data, start, end, fn):
    data = bytearray(_b(data))
    for i in range(start, min(end, len(data))):
        data[i] = fn(data[i], i - start) & 0xFF
    return bytes(data)


def validator_xor_range(data, start, end, key):
    key = _b(key)
    if not key:
        return _b(data)
    return _apply_range(data, start, end, lambda b, i: b ^ key[i % len(key)])


def validator_and_range(data, start, end, key):
    key = _b(key)
    return _apply_range(data, start, end, lambda b, i: b & key[i % len(key)])


def validator_or_range(data, start, end, key):
    key = _b(key)
    return _apply_range(data, start, end, lambda b, i: b | key[i % len(key)])


def validator_not_range(data, start, end):
    return _apply_range(data, start, end, lambda b, i: ~b)


def validator_add_range(data, start, end, addend):
    return _apply_range(data, start, end, lambda b, i: b + addend)


def validator_negate_range(data, start, end):
    return _apply_range(data, start, end, lambda b, i: (-b) & 0xFF)


# ---------- block ops ----------

def validator_fill(data, start, end, pattern):
    pattern = _b(pattern)
    data = bytearray(_b(data))
    if not pattern:
        return bytes(data)
    for i in range(start, min(end, len(data))):
        data[i] = pattern[(i - start) % len(pattern)]
    return bytes(data)


def validator_reverse_range(data, start, end):
    data = bytearray(_b(data))
    end = min(end, len(data))
    data[start:end] = data[start:end][::-1]
    return bytes(data)


def validator_shift_left(data, start, end, amount, fill_byte):
    data = bytearray(_b(data))
    end = min(end, len(data))
    seg = bytes(data[start:end])
    n = len(seg)
    amount = min(amount, n)
    new = seg[amount:] + bytes([fill_byte]) * amount
    data[start:end] = new
    return bytes(data)


def validator_shift_right(data, start, end, amount, fill_byte):
    data = bytearray(_b(data))
    end = min(end, len(data))
    seg = bytes(data[start:end])
    n = len(seg)
    amount = min(amount, n)
    new = bytes([fill_byte]) * amount + seg[:n - amount]
    data[start:end] = new
    return bytes(data)


def validator_rotate_left(data, start, end, amount):
    data = bytearray(_b(data))
    end = min(end, len(data))
    seg = bytes(data[start:end])
    n = len(seg)
    if n == 0:
        return bytes(data)
    amount %= n
    data[start:end] = seg[amount:] + seg[:amount]
    return bytes(data)


def validator_rotate_right(data, start, end, amount):
    data = bytearray(_b(data))
    end = min(end, len(data))
    seg = bytes(data[start:end])
    n = len(seg)
    if n == 0:
        return bytes(data)
    amount %= n
    data[start:end] = seg[n - amount:] + seg[:n - amount]
    return bytes(data)


# ---------- search ----------

def validator_search(data, pattern):
    data = _b(data)
    pattern = _b(pattern)
    if not pattern:
        return []
    out = []
    i = 0
    while True:
        j = data.find(pattern, i)
        if j < 0:
            break
        out.append(j)
        i = j + 1
    return out


def validator_search_regex(data, pattern):
    data = _b(data)
    pat = re.compile(pattern.encode() if isinstance(pattern, str) else pattern, re.DOTALL)
    return [m.start() for m in pat.finditer(data)]


def validator_find_string(data, s, encoding):
    enc_map = {"utf8": "utf-8", "utf16le": "utf-16-le",
               "utf16be": "utf-16-be", "ascii": "ascii", "latin1": "latin-1"}
    needle = s.encode(enc_map[encoding.lower()])
    return validator_search(data, needle)


def validator_find_hex_pattern(data, pattern):
    """Pattern like 'DE AD ? ? EF' with ?/?? as wildcards."""
    data = _b(data)
    tokens = pattern.replace("??", "?").split()
    mask = []
    needle = []
    for t in tokens:
        if t == "?":
            mask.append(None)
            needle.append(0)
        else:
            mask.append(int(t, 16))
            needle.append(int(t, 16))
    out = []
    n = len(mask)
    for i in range(0, len(data) - n + 1):
        ok = True
        for k in range(n):
            if mask[k] is not None and data[i + k] != mask[k]:
                ok = False
                break
        if ok:
            out.append(i)
    return out


# ---------- diff ----------

def validator_diff_compare_slices(left, right):
    left = _b(left)
    right = _b(right)
    n = min(len(left), len(right))
    regions = []
    i = 0
    while i < n:
        if left[i] != right[i]:
            j = i
            while j < n and left[j] != right[j]:
                j += 1
            regions.append({"offset": i, "len": j - i,
                            "left": list(left[i:j]), "right": list(right[i:j])})
            i = j
        else:
            i += 1
    if len(left) != len(right):
        offs = min(len(left), len(right))
        regions.append({"offset": offs,
                        "len": abs(len(left) - len(right)),
                        "left": list(left[offs:]),
                        "right": list(right[offs:])})
    return regions


# ---------- address mapping ----------

def validator_virtual_address(base, offset):
    return base + offset


def validator_offset_for_va(base, va, buf_len):
    if va < base:
        return None
    off = va - base
    return off if off < buf_len else None


# ---------- HexBuffer mirror (undo/redo round-trip) ----------

class HexBufferMirror:
    def __init__(self, data):
        self.data = bytearray(_b(data))
        self.undo_stack = []
        self.redo_stack = []

    def write(self, off, b):
        b = _b(b)
        old = bytes(self.data[off:off + len(b)])
        self.undo_stack.append(("write", off, old))
        self.data[off:off + len(b)] = b
        self.redo_stack.clear()

    def insert(self, off, b):
        b = _b(b)
        self.undo_stack.append(("insert", off, len(b)))
        self.data[off:off] = b
        self.redo_stack.clear()

    def delete(self, off, length):
        old = bytes(self.data[off:off + length])
        self.undo_stack.append(("delete", off, old))
        del self.data[off:off + length]
        self.redo_stack.clear()

    def undo(self):
        if not self.undo_stack:
            return False
        op = self.undo_stack.pop()
        kind = op[0]
        if kind == "write":
            _, off, old = op
            self.data[off:off + len(old)] = old
        elif kind == "insert":
            _, off, n = op
            del self.data[off:off + n]
        elif kind == "delete":
            _, off, old = op
            self.data[off:off] = old
        self.redo_stack.append(op)
        return True


def validator_undo_roundtrip(initial, edits):
    """edits: [['write',off,'hex'], ['insert',off,'hex'], ['delete',off,len], ...]"""
    buf = HexBufferMirror(initial)
    s0 = bytes(buf.data)
    for e in edits:
        op = e[0]
        if op == "write":
            buf.write(e[1], e[2])
        elif op == "insert":
            buf.insert(e[1], e[2])
        elif op == "delete":
            buf.delete(e[1], e[2])
    while buf.undo():
        pass
    return bytes(buf.data) == s0


# ---------- dispatch ----------

DISPATCH = {
    "byte_statistics": lambda i: validator_byte_statistics(i["data"]),
    "histogram": lambda i: validator_histogram(i["data"]),
    "histogram_top_n": lambda i: validator_histogram_top_n(i["data"], i["n"]),
    "entropy_blocks": lambda i: validator_entropy_blocks(i["data"], i["block_size"]),
    "shannon_entropy": lambda i: validator_shannon_entropy(i["data"]),
    "read_typed": lambda i: validator_read_typed(i["data"], i["offset"], i["dtype"], i.get("n")),
    "xor_range": lambda i: validator_xor_range(i["data"], i["start"], i["end"], i["key"]).hex(),
    "and_range": lambda i: validator_and_range(i["data"], i["start"], i["end"], i["key"]).hex(),
    "or_range": lambda i: validator_or_range(i["data"], i["start"], i["end"], i["key"]).hex(),
    "not_range": lambda i: validator_not_range(i["data"], i["start"], i["end"]).hex(),
    "add_range": lambda i: validator_add_range(i["data"], i["start"], i["end"], i["addend"]).hex(),
    "negate_range": lambda i: validator_negate_range(i["data"], i["start"], i["end"]).hex(),
    "fill": lambda i: validator_fill(i["data"], i["start"], i["end"], i["pattern"]).hex(),
    "reverse_range": lambda i: validator_reverse_range(i["data"], i["start"], i["end"]).hex(),
    "shift_left": lambda i: validator_shift_left(i["data"], i["start"], i["end"], i["amount"], i["fill"]).hex(),
    "shift_right": lambda i: validator_shift_right(i["data"], i["start"], i["end"], i["amount"], i["fill"]).hex(),
    "rotate_left": lambda i: validator_rotate_left(i["data"], i["start"], i["end"], i["amount"]).hex(),
    "rotate_right": lambda i: validator_rotate_right(i["data"], i["start"], i["end"], i["amount"]).hex(),
    "search": lambda i: validator_search(i["data"], i["pattern"]),
    "search_regex": lambda i: validator_search_regex(i["data"], i["pattern"]),
    "find_string": lambda i: validator_find_string(i["data"], i["s"], i["encoding"]),
    "find_hex_pattern": lambda i: validator_find_hex_pattern(i["data"], i["pattern"]),
    "diff_compare_slices": lambda i: validator_diff_compare_slices(i["left"], i["right"]),
    "virtual_address": lambda i: validator_virtual_address(i["base"], i["offset"]),
    "offset_for_va": lambda i: validator_offset_for_va(i["base"], i["va"], i["buf_len"]),
    "undo_roundtrip": lambda i: validator_undo_roundtrip(i["initial"], i["edits"]),
}


def main():
    if not sys.stdin.isatty():
        try:
            raw = sys.stdin.read()
            if raw.strip():
                req = json.loads(raw)
                fn = req["fn"]
                out = DISPATCH[fn](req)
                print(json.dumps({"ok": True, "fn": fn, "out": out}))
                return
        except Exception as e:
            print(json.dumps({"ok": False, "error": str(e)}))
            return

    # Self-tests
    results = {}
    data = bytes(range(256)) * 4
    results["byte_statistics"] = validator_byte_statistics(data)
    results["histogram_sum"] = sum(validator_histogram(data))
    results["entropy_full"] = validator_shannon_entropy(data)
    results["xor"] = validator_xor_range(b"\xde\xad\xbe\xef", 0, 4, b"\xff").hex()
    results["read_u32le"] = validator_read_typed(b"\x01\x00\x00\x00", 0, "u32le")
    results["search"] = validator_search(b"abcabcabc", b"abc")
    results["hex_pattern"] = validator_find_hex_pattern(b"\xde\xad\x00\x00\xef\xde\xad\xff\xff\xef", "DE AD ? ? EF")
    results["diff"] = validator_diff_compare_slices(b"abcdef", b"abXdYf")
    results["undo_rt"] = validator_undo_roundtrip(b"\x00\x01\x02\x03",
                                                  [["write", 1, "ff"], ["insert", 0, "aa"], ["delete", 2, 1]])
    results["rotate_left"] = validator_rotate_left(b"\x01\x02\x03\x04", 0, 4, 1).hex()
    print(json.dumps(results, indent=2, default=str))


if __name__ == "__main__":
    main()
