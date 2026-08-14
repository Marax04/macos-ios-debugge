#!/usr/bin/env python3
"""Independent Python validator for rustre-hex-pattern crate behavior.

Implements (stdlib only) the public semantics documented in
validation/reports/rustre-hex-pattern.md and exercises them with tests.
"""
from __future__ import annotations

import json
import re
import sqlite3
import sys
import unittest
from dataclasses import dataclass, field
from typing import List, Optional, Tuple


# ---------------------------------------------------------------------------
# PatternByte
# ---------------------------------------------------------------------------

class PatternByte:
    __slots__ = ("kind", "value", "high", "low")

    EXACT = "exact"
    WILDCARD = "wildcard"
    NIBBLE = "nibble"

    def __init__(self, kind, value=0, high=None, low=None):
        self.kind = kind
        self.value = value
        self.high = high
        self.low = low

    @classmethod
    def exact(cls, b: int):
        return cls(cls.EXACT, value=b & 0xFF)

    @classmethod
    def wildcard(cls):
        return cls(cls.WILDCARD)

    @classmethod
    def nibble(cls, high: Optional[int], low: Optional[int]):
        return cls(cls.NIBBLE, high=high, low=low)

    def is_wildcard(self) -> bool:
        return self.kind == self.WILDCARD

    def matches(self, byte: int) -> bool:
        byte &= 0xFF
        if self.kind == self.EXACT:
            return byte == self.value
        if self.kind == self.WILDCARD:
            return True
        # nibble
        ok = True
        if self.high is not None:
            ok = ok and ((byte >> 4) & 0xF) == (self.high & 0xF)
        if self.low is not None:
            ok = ok and (byte & 0xF) == (self.low & 0xF)
        return ok

    def mask_byte(self) -> int:
        if self.kind == self.EXACT:
            return 0xFF
        if self.kind == self.WILDCARD:
            return 0x00
        m = 0
        if self.high is not None:
            m |= 0xF0
        if self.low is not None:
            m |= 0x0F
        return m

    def value_byte(self) -> int:
        if self.kind == self.EXACT:
            return self.value
        if self.kind == self.WILDCARD:
            return 0
        v = 0
        if self.high is not None:
            v |= (self.high & 0xF) << 4
        if self.low is not None:
            v |= (self.low & 0xF)
        return v


# ---------------------------------------------------------------------------
# Pattern
# ---------------------------------------------------------------------------

class PatternError(Exception):
    pass


@dataclass
class NamedCapture:
    name: str
    start: int
    length: int


@dataclass
class CaptureResult:
    name: str
    offset: int
    bytes_: bytes


def _hexval(ch: str) -> Optional[int]:
    if '0' <= ch <= '9':
        return ord(ch) - ord('0')
    c = ch.lower()
    if 'a' <= c <= 'f':
        return ord(c) - ord('a') + 10
    return None


@dataclass
class Pattern:
    bytes: List[PatternByte] = field(default_factory=list)
    name: Optional[str] = None
    tags: List[str] = field(default_factory=list)
    captures: List[NamedCapture] = field(default_factory=list)
    comment: str = ""

    @classmethod
    def parse(cls, s: str) -> "Pattern":
        toks = s.split()
        if not toks:
            raise PatternError("Empty")
        out: List[PatternByte] = []
        for t in toks:
            if t == "??" or t == "?":
                out.append(PatternByte.wildcard())
                continue
            if len(t) == 1:
                # single hex digit -> high nibble
                d = _hexval(t)
                if d is None:
                    raise PatternError(f"Parse token={t}")
                out.append(PatternByte.nibble(high=d, low=None))
                continue
            if len(t) == 2:
                h_ch, l_ch = t[0], t[1]
                h = _hexval(h_ch) if h_ch != '?' else None
                l = _hexval(l_ch) if l_ch != '?' else None
                if h_ch != '?' and h is None:
                    raise PatternError(f"Parse token={t}")
                if l_ch != '?' and l is None:
                    raise PatternError(f"Parse token={t}")
                if h_ch == '?' and l_ch == '?':
                    out.append(PatternByte.wildcard())
                elif h is not None and l is not None:
                    out.append(PatternByte.exact((h << 4) | l))
                else:
                    out.append(PatternByte.nibble(high=h, low=l))
                continue
            raise PatternError(f"Parse token={t}")
        return cls(bytes=out)

    def with_name(self, n: str) -> "Pattern":
        self.name = n
        return self

    def with_tag(self, t: str) -> "Pattern":
        self.tags.append(t)
        return self

    def with_comment(self, c: str) -> "Pattern":
        self.comment = c
        return self

    def with_capture(self, name: str, start: int, length: int) -> "Pattern":
        self.captures.append(NamedCapture(name, start, length))
        return self

    def len(self) -> int:
        return len(self.bytes)

    def is_empty(self) -> bool:
        return not self.bytes

    def exact_count(self) -> int:
        return sum(1 for b in self.bytes if b.kind == PatternByte.EXACT)

    def wildcard_count(self) -> int:
        return sum(1 for b in self.bytes if b.is_wildcard())

    def specificity(self) -> float:
        n = self.len()
        return 0.0 if n == 0 else self.exact_count() / n

    def matches(self, data: bytes, offset: int) -> bool:
        if offset + self.len() > len(data):
            return False
        for i, pb in enumerate(self.bytes):
            if not pb.matches(data[offset + i]):
                return False
        return True

    def search(self, data: bytes) -> List[int]:
        out = []
        n = self.len()
        if n == 0 or len(data) < n:
            return out
        for i in range(0, len(data) - n + 1):
            if self.matches(data, i):
                out.append(i)
        return out

    def search_with_captures(self, data: bytes) -> List[Tuple[int, List[CaptureResult]]]:
        out = []
        for off in self.search(data):
            caps = []
            for c in self.captures:
                if c.start + c.length <= self.len():
                    caps.append(CaptureResult(c.name, off + c.start,
                                              bytes(data[off + c.start: off + c.start + c.length])))
            out.append((off, caps))
        return out

    def to_bytes(self) -> Optional[bytes]:
        if any(b.kind != PatternByte.EXACT for b in self.bytes):
            return None
        return bytes(b.value for b in self.bytes)

    def to_simd_form(self) -> Tuple[bytes, bytes]:
        return bytes(b.value_byte() for b in self.bytes), bytes(b.mask_byte() for b in self.bytes)

    def to_hex_string(self) -> str:
        out = []
        for b in self.bytes:
            if b.kind == PatternByte.EXACT:
                out.append(f"{b.value:02X}")
            elif b.is_wildcard():
                out.append("??")
            else:
                h = f"{b.high:X}" if b.high is not None else "?"
                l = f"{b.low:X}" if b.low is not None else "?"
                out.append(h + l)
        return " ".join(out)


# ---------------------------------------------------------------------------
# AlternationPattern
# ---------------------------------------------------------------------------

@dataclass
class AlternationPattern:
    alternatives: List[Pattern]
    name: Optional[str] = None

    @classmethod
    def parse(cls, s: str) -> "AlternationPattern":
        parts = [p.strip() for p in s.split("|")]
        if not parts:
            raise PatternError("Empty")
        return cls(alternatives=[Pattern.parse(p) for p in parts])

    def matches(self, data: bytes, off: int) -> bool:
        return any(p.matches(data, off) for p in self.alternatives)

    def search(self, data: bytes) -> List[int]:
        offs = set()
        for p in self.alternatives:
            for o in p.search(data):
                offs.add(o)
        return sorted(offs)

    def len(self) -> int:
        return len(self.alternatives)

    def is_empty(self) -> bool:
        return not self.alternatives


# ---------------------------------------------------------------------------
# CompiledPattern / MaskedPattern
# ---------------------------------------------------------------------------

@dataclass
class CompiledPattern:
    values: bytes
    masks: bytes

    @classmethod
    def compile(cls, p: Pattern) -> "CompiledPattern":
        v, m = p.to_simd_form()
        return cls(v, m)

    def matches(self, data: bytes, off: int) -> bool:
        n = len(self.values)
        if off + n > len(data):
            return False
        for i in range(n):
            if (data[off + i] & self.masks[i]) != (self.values[i] & self.masks[i]):
                return False
        return True

    def search(self, data: bytes) -> List[int]:
        out = []
        n = len(self.values)
        if n == 0 or len(data) < n:
            return out
        for i in range(0, len(data) - n + 1):
            if self.matches(data, i):
                out.append(i)
        return out


@dataclass
class MaskedPattern:
    bytes_: bytes
    mask: bytes
    name: Optional[str] = None

    def __post_init__(self):
        if len(self.bytes_) != len(self.mask):
            raise PatternError("length mismatch")

    @classmethod
    def from_pattern(cls, p: Pattern) -> "MaskedPattern":
        v, m = p.to_simd_form()
        return cls(v, m)

    def matches(self, data: bytes, off: int) -> bool:
        n = len(self.bytes_)
        if off + n > len(data):
            return False
        for i in range(n):
            if (data[off + i] & self.mask[i]) != (self.bytes_[i] & self.mask[i]):
                return False
        return True

    def search(self, data: bytes) -> List[int]:
        out = []
        n = len(self.bytes_)
        if n == 0 or len(data) < n:
            return out
        for i in range(0, len(data) - n + 1):
            if self.matches(data, i):
                out.append(i)
        return out

    def len(self) -> int:
        return len(self.bytes_)

    def is_empty(self) -> bool:
        return not self.bytes_


# ---------------------------------------------------------------------------
# CRC-16/IBM (poly 0x8005 reversed 0xA001, init 0, refin/refout true)
# ---------------------------------------------------------------------------

def crc16_ibm(data: bytes) -> int:
    crc = 0
    for b in data:
        crc ^= b
        for _ in range(8):
            if crc & 1:
                crc = (crc >> 1) ^ 0xA001
            else:
                crc >>= 1
    return crc & 0xFFFF


# ---------------------------------------------------------------------------
# SignaturePattern (FLIRT-like)
# ---------------------------------------------------------------------------

@dataclass
class SignaturePattern:
    name: str
    prologue: Pattern
    crc16: int
    crc_len: int
    func_len: int
    module_name: Optional[str] = None

    def with_module(self, m: str) -> "SignaturePattern":
        self.module_name = m
        return self

    def matches(self, data: bytes, off: int) -> bool:
        if not self.prologue.matches(data, off):
            return False
        start = off + self.prologue.len()
        end = start + self.crc_len
        if end > len(data):
            return False
        return crc16_ibm(data[start:end]) == self.crc16

    def search(self, data: bytes) -> List[int]:
        return [o for o in self.prologue.search(data) if self.matches(data, o)]


# ---------------------------------------------------------------------------
# Pattern JSON / IDA .pat exporter
# ---------------------------------------------------------------------------

def pattern_to_json_dict(p: Pattern) -> dict:
    return {
        "bytes": [_pb_to_dict(b) for b in p.bytes],
        "name": p.name,
        "tags": p.tags,
        "captures": [{"name": c.name, "start": c.start, "len": c.length} for c in p.captures],
        "comment": p.comment,
    }


def _pb_to_dict(b: PatternByte) -> dict:
    if b.kind == PatternByte.EXACT:
        return {"Exact": b.value}
    if b.is_wildcard():
        return {"Wildcard": True}
    return {"Nibble": {"high": b.high, "low": b.low}}


def export_json(patterns: List[Pattern]) -> str:
    return json.dumps([pattern_to_json_dict(p) for p in patterns], indent=2)


def export_ida_pat(patterns: List[Pattern]) -> str:
    lines = []
    for p in patterns:
        nm = p.name if p.name else ""
        lines.append(f"{p.to_hex_string()} {nm}".rstrip())
    return "\n".join(lines) + "\n"


def import_ida_pat(text: str) -> List[Pattern]:
    out = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        toks = line.split()
        # the last token is name if it doesn't look like a pattern token
        name = None
        if toks and not _is_pattern_token(toks[-1]):
            name = toks[-1]
            toks = toks[:-1]
        if not toks:
            continue
        p = Pattern.parse(" ".join(toks))
        if name:
            p.name = name
        out.append(p)
    return out


def _is_pattern_token(t: str) -> bool:
    if t in ("?", "??"):
        return True
    if len(t) == 1:
        return _hexval(t) is not None
    if len(t) == 2:
        a, b = t
        return (a == '?' or _hexval(a) is not None) and (b == '?' or _hexval(b) is not None)
    return False


# ---------------------------------------------------------------------------
# PatternDatabase (SQLite, in-memory supported)
# ---------------------------------------------------------------------------

_SCHEMA = """
CREATE TABLE IF NOT EXISTS patterns(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT,
    pattern TEXT NOT NULL,
    tags TEXT,
    comment TEXT
);
"""


class PatternDatabase:
    def __init__(self, conn):
        self.conn = conn
        self.conn.execute(_SCHEMA)
        self.conn.commit()

    @classmethod
    def open(cls, path: str) -> "PatternDatabase":
        return cls(sqlite3.connect(path))

    @classmethod
    def open_in_memory(cls) -> "PatternDatabase":
        return cls(sqlite3.connect(":memory:"))

    def insert(self, p: Pattern) -> int:
        cur = self.conn.execute(
            "INSERT INTO patterns(name,pattern,tags,comment) VALUES(?,?,?,?)",
            (p.name, json.dumps([_pb_to_dict(b) for b in p.bytes]),
             ",".join(p.tags), p.comment),
        )
        self.conn.commit()
        return cur.lastrowid

    @staticmethod
    def _escape_like(s: str) -> str:
        return s.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")

    def _row_to_pattern(self, row) -> Pattern:
        name, pat_json, tags, comment = row
        bs = []
        for d in json.loads(pat_json):
            if "Exact" in d:
                bs.append(PatternByte.exact(d["Exact"]))
            elif "Wildcard" in d:
                bs.append(PatternByte.wildcard())
            else:
                n = d["Nibble"]
                bs.append(PatternByte.nibble(n.get("high"), n.get("low")))
        p = Pattern(bytes=bs, name=name,
                    tags=[t for t in (tags or "").split(",") if t],
                    comment=comment or "")
        return p

    def search_by_name(self, name: str) -> List[Pattern]:
        like = f"%{self._escape_like(name)}%"
        cur = self.conn.execute(
            "SELECT name,pattern,tags,comment FROM patterns WHERE name LIKE ? ESCAPE '\\'",
            (like,))
        return [self._row_to_pattern(r) for r in cur.fetchall()]

    def search_by_tag(self, tag: str) -> List[Pattern]:
        like = f"%{self._escape_like(tag)}%"
        cur = self.conn.execute(
            "SELECT name,pattern,tags,comment FROM patterns WHERE tags LIKE ? ESCAPE '\\'",
            (like,))
        return [self._row_to_pattern(r) for r in cur.fetchall()]

    def delete(self, id_: int) -> None:
        self.conn.execute("DELETE FROM patterns WHERE id=?", (id_,))
        self.conn.commit()

    def count(self) -> int:
        cur = self.conn.execute("SELECT COUNT(*) FROM patterns")
        return cur.fetchone()[0]


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestPatternByte(unittest.TestCase):
    def test_exact(self):
        b = PatternByte.exact(0xAB)
        self.assertTrue(b.matches(0xAB))
        self.assertFalse(b.matches(0xAC))
        self.assertEqual(b.mask_byte(), 0xFF)
        self.assertEqual(b.value_byte(), 0xAB)

    def test_wildcard(self):
        b = PatternByte.wildcard()
        self.assertTrue(b.matches(0))
        self.assertTrue(b.matches(0xFF))
        self.assertTrue(b.is_wildcard())
        self.assertEqual(b.mask_byte(), 0x00)

    def test_nibble_high(self):
        b = PatternByte.nibble(high=0xA, low=None)
        self.assertTrue(b.matches(0xA0))
        self.assertTrue(b.matches(0xAF))
        self.assertFalse(b.matches(0xB0))
        self.assertEqual(b.mask_byte(), 0xF0)

    def test_nibble_low(self):
        b = PatternByte.nibble(high=None, low=0x3)
        self.assertTrue(b.matches(0x13))
        self.assertTrue(b.matches(0xF3))
        self.assertFalse(b.matches(0xF4))
        self.assertEqual(b.mask_byte(), 0x0F)


class TestPatternParse(unittest.TestCase):
    def test_empty(self):
        with self.assertRaises(PatternError):
            Pattern.parse("   ")

    def test_tokens(self):
        p = Pattern.parse("DE AD ?? ?F A?")
        self.assertEqual(p.len(), 5)
        self.assertEqual(p.bytes[0].kind, PatternByte.EXACT)
        self.assertEqual(p.bytes[0].value, 0xDE)
        self.assertTrue(p.bytes[2].is_wildcard())
        self.assertEqual(p.bytes[3].kind, PatternByte.NIBBLE)
        self.assertIsNone(p.bytes[3].high)
        self.assertEqual(p.bytes[3].low, 0xF)
        self.assertEqual(p.bytes[4].high, 0xA)
        self.assertIsNone(p.bytes[4].low)

    def test_single_digit_high_nibble(self):
        p = Pattern.parse("D")
        self.assertEqual(p.bytes[0].kind, PatternByte.NIBBLE)
        self.assertEqual(p.bytes[0].high, 0xD)
        self.assertIsNone(p.bytes[0].low)
        self.assertTrue(p.bytes[0].matches(0xD0))
        self.assertTrue(p.bytes[0].matches(0xDF))
        self.assertFalse(p.bytes[0].matches(0xE0))

    def test_single_question(self):
        p = Pattern.parse("?")
        self.assertTrue(p.bytes[0].is_wildcard())


class TestPatternSearch(unittest.TestCase):
    def test_exact_search(self):
        p = Pattern.parse("DE AD BE EF")
        data = b"\x00\xDE\xAD\xBE\xEF\x99\xDE\xAD\xBE\xEF"
        self.assertEqual(p.search(data), [1, 6])

    def test_wildcard_search(self):
        p = Pattern.parse("DE ?? BE EF")
        data = b"\xDE\x11\xBE\xEF\xDE\x22\xBE\xEF"
        self.assertEqual(p.search(data), [0, 4])

    def test_no_match(self):
        p = Pattern.parse("AA BB")
        self.assertEqual(p.search(b"\x00\x01\x02"), [])

    def test_to_bytes(self):
        self.assertEqual(Pattern.parse("DE AD").to_bytes(), b"\xDE\xAD")
        self.assertIsNone(Pattern.parse("DE ??").to_bytes())

    def test_to_simd_form(self):
        v, m = Pattern.parse("DE ?? A?").to_simd_form()
        self.assertEqual(v, b"\xDE\x00\xA0")
        self.assertEqual(m, b"\xFF\x00\xF0")

    def test_specificity(self):
        p = Pattern.parse("DE AD ?? ??")
        self.assertAlmostEqual(p.specificity(), 0.5)

    def test_to_hex_string(self):
        self.assertEqual(Pattern.parse("DE AD ?? ?F").to_hex_string(),
                         "DE AD ?? ?F")

    def test_captures(self):
        p = Pattern.parse("DE AD ?? ??").with_capture("tail", 2, 2)
        data = b"\xDE\xAD\x11\x22\xDE\xAD\x33\x44"
        res = p.search_with_captures(data)
        self.assertEqual(len(res), 2)
        self.assertEqual(res[0][1][0].bytes_, b"\x11\x22")
        self.assertEqual(res[1][1][0].bytes_, b"\x33\x44")


class TestAlternation(unittest.TestCase):
    def test_parse_and_search(self):
        a = AlternationPattern.parse("AA BB | CC DD")
        data = b"\xAA\xBB\x00\xCC\xDD\xAA\xBB"
        self.assertEqual(a.search(data), [0, 3, 5])
        self.assertTrue(a.matches(data, 0))
        self.assertTrue(a.matches(data, 3))
        self.assertFalse(a.matches(data, 2))


class TestCompiledMasked(unittest.TestCase):
    def test_compiled(self):
        p = Pattern.parse("DE ?? BE EF")
        c = CompiledPattern.compile(p)
        data = b"\xDE\xAA\xBE\xEF\xDE\x55\xBE\xEF"
        self.assertEqual(c.search(data), [0, 4])

    def test_masked_from_pattern(self):
        p = Pattern.parse("A? ?B")
        m = MaskedPattern.from_pattern(p)
        self.assertTrue(m.matches(b"\xA5\x3B", 0))
        self.assertFalse(m.matches(b"\xB5\x3B", 0))
        self.assertFalse(m.matches(b"\xA5\x3C", 0))

    def test_masked_length_check(self):
        with self.assertRaises(PatternError):
            MaskedPattern(b"\x00\x01", b"\xFF")


class TestCRC16IBM(unittest.TestCase):
    def test_known(self):
        # CRC-16/ARC ("123456789") -> 0xBB3D
        self.assertEqual(crc16_ibm(b"123456789"), 0xBB3D)

    def test_empty(self):
        self.assertEqual(crc16_ibm(b""), 0)


class TestSignaturePattern(unittest.TestCase):
    def test_match(self):
        prologue = Pattern.parse("55 8B EC")
        body = b"\xAA\xBB\xCC\xDD"
        crc = crc16_ibm(body)
        sig = SignaturePattern("f", prologue, crc, len(body), 32)
        data = b"\x00" + b"\x55\x8B\xEC" + body + b"\x00"
        self.assertEqual(sig.search(data), [1])
        # corrupt body -> no match
        bad = b"\x00" + b"\x55\x8B\xEC" + b"\xAA\xBB\xCC\x00" + b"\x00"
        self.assertEqual(sig.search(bad), [])


class TestExporters(unittest.TestCase):
    def test_ida_pat_roundtrip_exact(self):
        ps = [Pattern.parse("DE AD BE EF").with_name("magic"),
              Pattern.parse("CA FE").with_name("cafe")]
        text = export_ida_pat(ps)
        loaded = import_ida_pat(text)
        self.assertEqual(len(loaded), 2)
        self.assertEqual(loaded[0].to_hex_string(), "DE AD BE EF")
        self.assertEqual(loaded[0].name, "magic")
        self.assertEqual(loaded[1].name, "cafe")

    def test_ida_pat_skip_comments(self):
        text = "# comment line\n\nDE AD foo\n"
        loaded = import_ida_pat(text)
        self.assertEqual(len(loaded), 1)
        self.assertEqual(loaded[0].name, "foo")

    def test_export_json_parses(self):
        ps = [Pattern.parse("DE ??").with_name("n").with_tag("t")]
        js = export_json(ps)
        data = json.loads(js)
        self.assertEqual(data[0]["name"], "n")
        self.assertEqual(data[0]["tags"], ["t"])
        self.assertEqual(data[0]["bytes"][0], {"Exact": 0xDE})
        self.assertEqual(data[0]["bytes"][1], {"Wildcard": True})


class TestPatternDatabase(unittest.TestCase):
    def test_in_memory_crud(self):
        db = PatternDatabase.open_in_memory()
        self.assertEqual(db.count(), 0)
        p = Pattern.parse("DE AD ??").with_name("hdr").with_tag("magic")
        id_ = db.insert(p)
        self.assertGreater(id_, 0)
        self.assertEqual(db.count(), 1)
        rs = db.search_by_name("hd")
        self.assertEqual(len(rs), 1)
        self.assertEqual(rs[0].name, "hdr")
        rs2 = db.search_by_tag("magic")
        self.assertEqual(len(rs2), 1)
        db.delete(id_)
        self.assertEqual(db.count(), 0)

    def test_like_escape(self):
        db = PatternDatabase.open_in_memory()
        db.insert(Pattern.parse("AA").with_name("plain"))
        db.insert(Pattern.parse("BB").with_name("100%_real"))
        # querying literal '%' must not match 'plain'
        rs = db.search_by_name("%")
        self.assertEqual(len(rs), 1)
        self.assertEqual(rs[0].name, "100%_real")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    unittest.main(verbosity=2)
