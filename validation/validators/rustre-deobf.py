"""rustre-deobf — Python reference reproducing the documented public API.

Stdlib only (struct, hashlib, json, re). For each function in the report, a
Python equivalent accepting the same inputs and returning the same output types.
"""
from __future__ import annotations

import json
import hashlib
import re
import struct
import math
from collections import Counter, defaultdict
from typing import Any, Callable, Dict, List, Optional, Set, Tuple


# ============================================================
# casts.rs
# ============================================================
def usize_to_f64(x: int) -> float: return float(x & 0xFFFFFFFFFFFFFFFF)
def usize_to_f32(x: int) -> float: return float(x & 0xFFFFFFFFFFFFFFFF)
def u64_to_f64(x: int) -> float: return float(x & 0xFFFFFFFFFFFFFFFF)
def u64_to_f32(x: int) -> float: return float(x & 0xFFFFFFFFFFFFFFFF)
def f64_to_u32(x: float) -> int:
    if x != x: return 0
    if x <= 0: return 0
    if x >= 0xFFFFFFFF: return 0xFFFFFFFF
    return int(x) & 0xFFFFFFFF
def u128_to_u64(x: int) -> int: return x & 0xFFFFFFFFFFFFFFFF
def usize_to_u32(x: int) -> int: return x & 0xFFFFFFFF
def usize_to_u8(x: int) -> int: return x & 0xFF


# ============================================================
# Common errors / types
# ============================================================
class DeobfError(Exception): pass
class ReportError(Exception): pass
class PassManagerError(Exception): pass


# ============================================================
# lib.rs — Pipeline / Patch / Context
# ============================================================
class DeobfPass:
    name = "pass"
    def run(self, ctx): return TransformResult()


class DeobfPassSet:
    @staticmethod
    def all() -> List[DeobfPass]: return []


class Patch:
    def __init__(self, offset: int = 0, data: Optional[bytes] = None, metadata: Optional[dict] = None):
        self.offset = offset
        self.data = bytes(data or b"")
        self.metadata = dict(metadata or {})

    @classmethod
    def new(cls, offset: int = 0, data: Optional[bytes] = None, metadata: Optional[dict] = None) -> "Patch":
        return cls(offset, data, metadata)

    def apply(self, data: bytearray) -> None:
        if self.offset + len(self.data) > len(data):
            raise DeobfError("patch out of range")
        data[self.offset:self.offset + len(self.data)] = self.data


class SegmentMapping:
    def __init__(self, va: int = 0, file_offset: int = 0, size: int = 0):
        self.va = va
        self.file_offset = file_offset
        self.size = size


class DeobfContext:
    def __init__(self, binary: bytes):
        self.binary = bytearray(binary)
        self.patches: List[Patch] = []
        self.segments: List[SegmentMapping] = []
        self.meta: Dict[str, Any] = {}

    @classmethod
    def new(cls, binary: bytes) -> "DeobfContext": return cls(binary)

    def va_to_file_offset(self, va: int) -> Optional[int]:
        for s in self.segments:
            if s.va <= va < s.va + s.size:
                return s.file_offset + (va - s.va)
        return None

    def add_segment(self, mapping: SegmentMapping) -> None:
        self.segments.append(mapping)

    def apply_patches(self) -> bytes:
        data = bytearray(self.binary)
        for p in self.patches:
            p.apply(data)
        return bytes(data)

    def set_meta(self, key: str, value: Any) -> None:
        self.meta[key] = value

    def get_meta(self, key: str) -> Optional[Any]:
        return self.meta.get(key)


class TransformResult:
    def __init__(self, category: str = "", description: str = "", bytes_changed: int = 0):
        self.category = category
        self.description = description
        self.bytes_changed = bytes_changed


class PipelineResult:
    def __init__(self):
        self.results: List[Any] = []
        self.failures: List[Any] = []

    def merge(self, other: "PipelineResult") -> None:
        self.results.extend(other.results)
        self.failures.extend(other.failures)

    def record(self, pass_result: Any) -> None:
        self.results.append(pass_result)

    def results_by_confidence(self) -> List[Any]:
        return sorted(self.results, key=lambda r: getattr(r, "confidence", 0.0), reverse=True)

    def summary(self) -> str:
        return f"{len(self.results)} results, {len(self.failures)} failures"


class DeobfOptions:
    def __init__(self, **kw): self.options = dict(kw)


class DeobfPipelineResult:
    def __init__(self): self.passes: List[Any] = []


class DeobfPipeline:
    def __init__(self, options: Optional[DeobfOptions] = None):
        self.passes: List[DeobfPass] = []
        self.options = options or DeobfOptions()

    @classmethod
    def new(cls) -> "DeobfPipeline": return cls()
    @classmethod
    def with_options(cls, options: DeobfOptions) -> "DeobfPipeline": return cls(options)

    def add_pass(self, p: DeobfPass) -> None: self.passes.append(p)
    def add_pass_arc(self, p: DeobfPass) -> None: self.passes.append(p)
    def pass_count(self) -> int: return len(self.passes)

    def run_all(self, ctx: DeobfContext) -> PipelineResult:
        res = PipelineResult()
        for p in self.passes:
            res.record(p.run(ctx))
        return res

    def run(self, ctx: DeobfContext) -> DeobfPipelineResult:
        r = DeobfPipelineResult()
        for p in self.passes:
            r.passes.append(p.run(ctx))
        return r


# ============================================================
# Pattern matching
# ============================================================
class PatternMatch:
    def __init__(self, name: str, offset: int):
        self.name = name
        self.offset = offset


class PatternScanner:
    def __init__(self):
        self.patterns: List[Tuple[str, bytes, Optional[bytes]]] = []

    def add_pattern(self, name: str, pattern: bytes) -> None:
        self.patterns.append((name, bytes(pattern), None))

    def add_masked_pattern(self, name: str, pattern: bytes, mask: bytes) -> None:
        self.patterns.append((name, bytes(pattern), bytes(mask)))

    def scan(self, data: bytes) -> List[PatternMatch]:
        out: List[PatternMatch] = []
        for name, pat, mask in self.patterns:
            if mask is None:
                i = data.find(pat)
                while i != -1:
                    out.append(PatternMatch(name, i))
                    i = data.find(pat, i + 1)
            else:
                plen = len(pat)
                for i in range(len(data) - plen + 1):
                    if all((data[i + j] & mask[j]) == (pat[j] & mask[j]) for j in range(plen)):
                        out.append(PatternMatch(name, i))
        return out


# ============================================================
# Crypto helpers
# ============================================================
def entropy(data: bytes) -> float:
    if not data: return 0.0
    counts = Counter(data)
    n = len(data)
    h = 0.0
    for c in counts.values():
        p = c / n
        h -= p * math.log2(p)
    return h


def decrypt_constant(data: bytes, key: int) -> bytes:
    return bytes(b ^ (key & 0xFF) for b in data)


def recover_single_byte_key(data: bytes) -> Tuple[int, bytes]:
    best_key, best_score, best_out = 0, -1.0, b""
    for k in range(256):
        out = decrypt_constant(data, k)
        score = sum(1 for b in out if 32 <= b < 127 or b in (9, 10, 13))
        if score > best_score:
            best_score, best_key, best_out = score, k, out
    return best_key, best_out


def decrypt_cyclic(data: bytes, key: bytes) -> bytes:
    if not key: return bytes(data)
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))


def decrypt_rolling(data: bytes, initial_key: int) -> bytes:
    out = bytearray()
    k = initial_key & 0xFF
    for b in data:
        out.append(b ^ k)
        k = (k + b) & 0xFF
    return bytes(out)


def rol(byte: int, n: int) -> int:
    byte &= 0xFF
    n &= 7
    return ((byte << n) | (byte >> (8 - n))) & 0xFF if n else byte


def ror(byte: int, n: int) -> int:
    byte &= 0xFF
    n &= 7
    return ((byte >> n) | (byte << (8 - n))) & 0xFF if n else byte


def decrypt_rol(data: bytes, rotation: int) -> bytes:
    return bytes(rol(b, rotation) for b in data)


def decrypt_ror(data: bytes, rotation: int) -> bytes:
    return bytes(ror(b, rotation) for b in data)


def recover_rotation(data: bytes) -> Tuple[int, bool, bytes]:
    best = (0, False, bytes(data))
    best_score = -1
    for is_left in (True, False):
        for r in range(1, 8):
            out = decrypt_rol(data, r) if is_left else decrypt_ror(data, r)
            score = sum(1 for b in out if 32 <= b < 127)
            if score > best_score:
                best_score = score
                best = (r, is_left, out)
    return best


def most_frequent_byte(data: bytes) -> int:
    if not data: return 0
    return Counter(data).most_common(1)[0][0]


def build_substitution_table(data: bytes, assumed_plaintext: int) -> bytes:
    table = bytearray(range(256))
    if data:
        mfb = most_frequent_byte(data)
        table[mfb] = assumed_plaintext & 0xFF
    return bytes(table)


def apply_table(data: bytes, table: bytes) -> bytes:
    return bytes(table[b] for b in data)


class Base64Find:
    def __init__(self, offset: int, text: str, decoded: bytes):
        self.offset = offset
        self.text = text
        self.decoded = decoded


class Base64:
    _RE = re.compile(rb"[A-Za-z0-9+/]{8,}={0,2}")

    @staticmethod
    def decode(input_str: str) -> Optional[bytes]:
        import base64 as _b64
        try:
            return _b64.b64decode(input_str, validate=True)
        except Exception:
            return None

    @staticmethod
    def find_all(data: bytes) -> List[Base64Find]:
        out: List[Base64Find] = []
        for m in Base64._RE.finditer(data):
            txt = m.group(0).decode("ascii", "ignore")
            dec = Base64.decode(txt)
            if dec is not None:
                out.append(Base64Find(m.start(), txt, dec))
        return out


class DecryptedString:
    def __init__(self, offset: int, key: Any, plaintext: bytes):
        self.offset = offset
        self.key = key
        self.plaintext = plaintext


def _is_printable_run(data: bytes, min_length: int) -> bool:
    return len(data) >= min_length and all(32 <= b < 127 or b in (9, 10, 13) for b in data)


def try_xor_constant(data: bytes, min_length: int) -> List[DecryptedString]:
    out: List[DecryptedString] = []
    for k in range(1, 256):
        dec = decrypt_constant(data, k)
        run = bytearray()
        start = 0
        for i, b in enumerate(dec):
            if 32 <= b < 127:
                if not run:
                    start = i
                run.append(b)
            else:
                if len(run) >= min_length:
                    out.append(DecryptedString(start, k, bytes(run)))
                run = bytearray()
        if len(run) >= min_length:
            out.append(DecryptedString(start, k, bytes(run)))
    return out


def try_xor_rolling(data: bytes, min_length: int) -> List[DecryptedString]:
    out: List[DecryptedString] = []
    for k in range(256):
        dec = decrypt_rolling(data, k)
        if _is_printable_run(dec, min_length):
            out.append(DecryptedString(0, k, dec))
    return out


# ============================================================
# Registries
# ============================================================
class Registry:
    def __init__(self):
        self._passes: Dict[str, DeobfPass] = {}

    @classmethod
    def new(cls) -> "Registry": return cls()

    def register(self, pass_: DeobfPass) -> Optional[DeobfPass]:
        prev = self._passes.get(pass_.name)
        self._passes[pass_.name] = pass_
        return prev

    def get(self, name: str) -> Optional[DeobfPass]: return self._passes.get(name)
    def len(self) -> int: return len(self._passes)
    def is_empty(self) -> bool: return not self._passes
    def names(self) -> List[str]: return list(self._passes.keys())

    def run_selection(self, names: List[str], ctx: DeobfContext) -> PipelineResult:
        res = PipelineResult()
        for n in names:
            p = self._passes.get(n)
            if p: res.record(p.run(ctx))
        return res


# ============================================================
# Report / ObfuscationProfile
# ============================================================
class ObfuscationType:
    XOR = "XOR"; RC4 = "RC4"; CHACHA = "CHACHA"; PACKED = "PACKED"; CFG_FLATTENING = "CFG_FLATTENING"


class DeobfReport:
    def __init__(self, binary_name: str = "", binary_size_bytes: int = 0):
        self.binary_name = binary_name
        self.binary_size_bytes = binary_size_bytes
        self.passes: List["PassSummary"] = []
        self.transforms: List[TransformResult] = []
        self.notes: List[str] = []
        self.warnings: List[str] = []
        self.findings: List["Finding"] = []
        self.hash: Optional[str] = None
        self.metadata: Dict[str, Any] = {}

    @classmethod
    def new(cls, binary_name: str, binary_size_bytes: int) -> "DeobfReport":
        return cls(binary_name, binary_size_bytes)

    @classmethod
    def from_pipeline(cls, pr: PipelineResult) -> "DeobfReport":
        rep = cls()
        for r in pr.results:
            if isinstance(r, TransformResult):
                rep.transforms.append(r)
        return rep

    def log_transform(self, t: TransformResult) -> None:
        self.transforms.append(t)

    def applied_count(self) -> int: return len(self.transforms)

    def set_hash(self, sha256: str) -> None: self.hash = sha256
    def add_pass(self, summary: "PassSummary") -> None: self.passes.append(summary)
    def add_note(self, note: str) -> None: self.notes.append(note)
    def add_warning(self, w: str) -> None: self.warnings.append(w)
    def executed_passes(self) -> List["PassSummary"]: return [p for p in self.passes if not p.skipped]
    def failed_passes(self) -> List["PassSummary"]: return [p for p in self.passes if p.failed]
    def skipped_passes(self) -> List["PassSummary"]: return [p for p in self.passes if p.skipped]
    def score_improvement(self) -> float: return 0.0
    def export(self, format: str) -> str:
        if format == "json": return self.to_json()
        if format == "html": return self.to_html()
        return self.summary_line()

    @property
    def total_finding_bytes(self) -> int:
        return sum(getattr(f, "bytes", 0) for f in self.findings)

    @property
    def high_severity_count(self) -> int:
        return sum(1 for f in self.findings if getattr(f, "severity", 0) >= 7)

    def findings_by_severity(self, min_sev: int) -> List["Finding"]:
        return [f for f in self.findings if getattr(f, "severity", 0) >= min_sev]

    def findings_by_confidence(self) -> List["Finding"]:
        return sorted(self.findings, key=lambda f: getattr(f, "confidence", 0.0), reverse=True)

    def total_findings(self) -> int: return len(self.findings)

    def to_json(self) -> str:
        try:
            return json.dumps({"binary": self.binary_name, "passes": len(self.passes), "findings": len(self.findings)})
        except Exception as e:
            raise ReportError(str(e))

    def to_json_pretty(self) -> str:
        return json.dumps({"binary": self.binary_name, "passes": len(self.passes)}, indent=2)

    def to_html(self) -> str:
        return f"<html><body><h1>{self.binary_name}</h1></body></html>"

    def summary_line(self) -> str:
        return f"{self.binary_name}: {len(self.passes)} passes, {len(self.findings)} findings"


class ObfuscationProfile:
    def __init__(self, binary_name: str):
        self.binary_name = binary_name
        self.obfuscations: List[Tuple[str, float]] = []

    @classmethod
    def new(cls, binary_name: str) -> "ObfuscationProfile": return cls(binary_name)

    def add_obfuscation(self, ty: str, confidence: float) -> None:
        self.obfuscations.append((ty, confidence))

    def summary(self) -> str:
        return f"{self.binary_name}: {len(self.obfuscations)} techniques"


# ============================================================
# RC4 / ChaCha / checksums
# ============================================================
class Rc4:
    @staticmethod
    def ksa(key: bytes) -> bytes:
        s = list(range(256))
        j = 0
        klen = len(key) or 1
        for i in range(256):
            j = (j + s[i] + (key[i % klen] if key else 0)) & 0xFF
            s[i], s[j] = s[j], s[i]
        return bytes(s)

    @staticmethod
    def prga(s: bytes, length: int) -> bytes:
        s = list(s)
        i = j = 0
        out = bytearray()
        for _ in range(length):
            i = (i + 1) & 0xFF
            j = (j + s[i]) & 0xFF
            s[i], s[j] = s[j], s[i]
            out.append(s[(s[i] + s[j]) & 0xFF])
        return bytes(out)

    @staticmethod
    def decrypt(data: bytes, key: bytes) -> bytes:
        ks = Rc4.prga(Rc4.ksa(key), len(data))
        return bytes(a ^ b for a, b in zip(data, ks))

    @staticmethod
    def brute_force_short_key(data: bytes) -> Tuple[bytes, bytes]:
        best_key, best_out, best_score = b"\x00", b"", -1
        for k in range(256):
            key = bytes([k])
            out = Rc4.decrypt(data, key)
            score = sum(1 for b in out if 32 <= b < 127)
            if score > best_score:
                best_score, best_key, best_out = score, key, out
        return best_key, best_out


class ChaCha20:
    @staticmethod
    def _qr(state, a, b, c, d):
        state[a] = (state[a] + state[b]) & 0xFFFFFFFF
        state[d] ^= state[a]; state[d] = ((state[d] << 16) | (state[d] >> 16)) & 0xFFFFFFFF
        state[c] = (state[c] + state[d]) & 0xFFFFFFFF
        state[b] ^= state[c]; state[b] = ((state[b] << 12) | (state[b] >> 20)) & 0xFFFFFFFF
        state[a] = (state[a] + state[b]) & 0xFFFFFFFF
        state[d] ^= state[a]; state[d] = ((state[d] << 8) | (state[d] >> 24)) & 0xFFFFFFFF
        state[c] = (state[c] + state[d]) & 0xFFFFFFFF
        state[b] ^= state[c]; state[b] = ((state[b] << 7) | (state[b] >> 25)) & 0xFFFFFFFF

    @staticmethod
    def block(key: bytes, nonce: bytes, counter: int) -> bytes:
        if len(key) != 32 or len(nonce) != 12:
            raise DeobfError("invalid key/nonce length")
        consts = b"expand 32-byte k"
        state = list(struct.unpack("<4I", consts)) + list(struct.unpack("<8I", key)) + [counter & 0xFFFFFFFF] + list(struct.unpack("<3I", nonce))
        working = list(state)
        for _ in range(10):
            ChaCha20._qr(working, 0, 4, 8, 12)
            ChaCha20._qr(working, 1, 5, 9, 13)
            ChaCha20._qr(working, 2, 6, 10, 14)
            ChaCha20._qr(working, 3, 7, 11, 15)
            ChaCha20._qr(working, 0, 5, 10, 15)
            ChaCha20._qr(working, 1, 6, 11, 12)
            ChaCha20._qr(working, 2, 7, 8, 13)
            ChaCha20._qr(working, 3, 4, 9, 14)
        out = bytearray()
        for i in range(16):
            out += struct.pack("<I", (working[i] + state[i]) & 0xFFFFFFFF)
        return bytes(out)

    @staticmethod
    def crypt(data: bytes, key: bytes, nonce: bytes) -> bytes:
        out = bytearray()
        counter = 0
        for i in range(0, len(data), 64):
            ks = ChaCha20.block(key, nonce, counter)
            chunk = data[i:i + 64]
            out += bytes(a ^ b for a, b in zip(chunk, ks))
            counter += 1
        return bytes(out)


class Crc32:
    _TABLE: List[int] = []

    @staticmethod
    def _build():
        t = []
        for i in range(256):
            c = i
            for _ in range(8):
                c = (c >> 1) ^ 0xEDB88320 if c & 1 else c >> 1
            t.append(c)
        Crc32._TABLE = t

    @staticmethod
    def checksum(data: bytes) -> int:
        if not Crc32._TABLE: Crc32._build()
        c = 0xFFFFFFFF
        t = Crc32._TABLE
        for b in data:
            c = t[(c ^ b) & 0xFF] ^ (c >> 8)
        return c ^ 0xFFFFFFFF


class Adler32:
    @staticmethod
    def checksum(data: bytes) -> int:
        a, b = 1, 0
        for byte in data:
            a = (a + byte) % 65521
            b = (b + a) % 65521
        return ((b << 16) | a) & 0xFFFFFFFF


class Fletcher32:
    @staticmethod
    def checksum_table(data: bytes) -> int:
        s1 = s2 = 0
        for i in range(0, len(data) - 1, 2):
            w = data[i] | (data[i + 1] << 8)
            s1 = (s1 + w) % 65535
            s2 = (s2 + s1) % 65535
        return ((s2 << 16) | s1) & 0xFFFFFFFF


# ============================================================
# Entropy / Section / PatchSet / HexDumper / NopSled
# ============================================================
class EntropyRegion:
    def __init__(self, offset: int, length: int, value: float):
        self.offset = offset
        self.length = length
        self.value = value


class EntropyScanner:
    def __init__(self, window: int = 256):
        self.window = window

    @classmethod
    def new(cls) -> "EntropyScanner": return cls()

    def scan(self, data: bytes) -> List[EntropyRegion]:
        out = []
        for i in range(0, len(data), self.window):
            chunk = data[i:i + self.window]
            out.append(EntropyRegion(i, len(chunk), entropy(chunk)))
        return out

    def max_entropy_region(self, data: bytes) -> Optional[EntropyRegion]:
        regs = self.scan(data)
        return max(regs, key=lambda r: r.value) if regs else None


class Section:
    def __init__(self, name: str, va: int, data: bytes):
        self.name = name
        self.va = va
        self.data = bytes(data)

    @classmethod
    def new(cls, name: str, va: int, data: bytes) -> "Section":
        return cls(name, va, data)


class PatchSet:
    def __init__(self):
        self._patches: List[Patch] = []
        self._seen: Set[int] = set()

    @classmethod
    def new(cls) -> "PatchSet": return cls()

    def insert(self, patch: Patch) -> bool:
        if patch.offset in self._seen: return False
        self._seen.add(patch.offset)
        self._patches.append(patch)
        return True

    def patches(self) -> List[Patch]: return list(self._patches)
    def into_patches(self) -> List[Patch]: return list(self._patches)

    def apply_to(self, data: bytes) -> bytes:
        buf = bytearray(data)
        for p in self._patches:
            p.apply(buf)
        return bytes(buf)


class HexDumper:
    def __init__(self): pass
    @classmethod
    def new(cls) -> "HexDumper": return cls()

    def dump(self, data: bytes) -> str:
        lines = []
        for i in range(0, len(data), 16):
            chunk = data[i:i + 16]
            hexpart = " ".join(f"{b:02x}" for b in chunk)
            ascpart = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
            lines.append(f"{i:08x}  {hexpart:<48}  {ascpart}")
        return "\n".join(lines)

    def hex_only(self, data: bytes) -> str:
        return " ".join(f"{b:02x}" for b in data)


class NopSledDetector:
    def __init__(self, min_len: int = 4): self.min_len = min_len
    @classmethod
    def new(cls) -> "NopSledDetector": return cls()

    def find_sleds(self, data: bytes) -> List[Tuple[int, int]]:
        out = []
        i = 0
        while i < len(data):
            if data[i] == 0x90:
                j = i
                while j < len(data) and data[j] == 0x90:
                    j += 1
                if j - i >= self.min_len:
                    out.append((i, j - i))
                i = j
            else:
                i += 1
        return out


# ============================================================
# ArcRegistry
# ============================================================
class ArcRegistry:
    def __init__(self):
        self._passes: Dict[str, DeobfPass] = {}

    @classmethod
    def new(cls) -> "ArcRegistry": return cls()

    def register(self, p: DeobfPass) -> None: self._passes[p.name] = p
    def get(self, name: str) -> Optional[DeobfPass]: return self._passes.get(name)
    def count(self) -> int: return len(self._passes)
    def names(self) -> List[str]: return list(self._passes.keys())

    def build_pipeline(self, names: List[str], options: Optional[DeobfOptions] = None) -> DeobfPipeline:
        pipe = DeobfPipeline.with_options(options or DeobfOptions())
        for n in names:
            p = self._passes.get(n)
            if p: pipe.add_pass(p)
        return pipe


# ============================================================
# Job / PipelineGroup
# ============================================================
class Job:
    def __init__(self, id_: str, pipeline: DeobfPipeline):
        self.id = id_
        self.pipeline = pipeline
        self.patches_applied = 0

    @classmethod
    def new(cls, id_: str, pipeline: DeobfPipeline) -> "Job": return cls(id_, pipeline)

    def run_on(self, ctx: DeobfContext) -> None:
        res = self.pipeline.run_all(ctx)
        self.patches_applied = len(res.results)

    def patches_per_pass(self) -> float:
        n = self.pipeline.pass_count()
        return (self.patches_applied / n) if n else 0.0


class PipelineGroup:
    def __init__(self): self.pipelines: List[DeobfPipeline] = []
    def add_pipeline(self, p: DeobfPipeline) -> None: self.pipelines.append(p)

    def run(self, data: bytes) -> bytes:
        out = bytes(data)
        for p in self.pipelines:
            ctx = DeobfContext.new(out)
            p.run_all(ctx)
            out = ctx.apply_patches()
        return out


# ============================================================
# Heuristic detection
# ============================================================
class Heuristics:
    def __init__(self): self.signatures: List[bytes] = []
    def add_signature(self, sig: bytes) -> None: self.signatures.append(bytes(sig))

    def entropy(self, data: bytes) -> float: return entropy(data)

    def is_likely_obfuscated(self, data: bytes) -> bool:
        return self.entropy(data) > 7.0


class Classifier:
    def __init__(self): self._detections: List[Tuple[str, float]] = []
    @classmethod
    def new(cls) -> "Classifier": return cls()

    def classify(self, data: bytes) -> None:
        h = entropy(data)
        if h > 7.5:
            self._detections.append((ObfuscationType.PACKED, h / 8.0))

    def detections(self) -> List[Tuple[str, float]]: return list(self._detections)

    def most_likely(self) -> Optional[str]:
        if not self._detections: return None
        return max(self._detections, key=lambda d: d[1])[0]


# ============================================================
# Persistence store
# ============================================================
class Store:
    def __init__(self):
        self._patches: Dict[str, List[Patch]] = {}
        self._reports: List[DeobfReport] = []

    @classmethod
    def new(cls) -> "Store": return cls()

    def save_patches(self, binary_id: str, patches: List[Patch]) -> None:
        self._patches[binary_id] = list(patches)

    def save_report(self, report: DeobfReport) -> None:
        self._reports.append(report)

    def patches_for(self, binary_id: str) -> List[Patch]:
        return self._patches.get(binary_id, [])


def run(data: bytes) -> Tuple[bytes, int]:
    """Top-level run: returns (data, pass_count)."""
    return bytes(data), 0


# ============================================================
# cfg_normalizer.rs
# ============================================================
class CfgBlock:
    def __init__(self, offset: int = 0, instrs: Optional[list] = None, label: Optional[str] = None,
                 successors: Optional[List[int]] = None):
        self.offset = offset
        self.instrs = list(instrs or [])
        self.label = label
        self.successors = list(successors or [])

    def with_label(self, label: str) -> "CfgBlock":
        self.label = label
        return self


class NormalizedCfg:
    def __init__(self, blocks: Optional[List[CfgBlock]] = None, entry: int = 0):
        self.blocks = list(blocks or [])
        self.entry = entry

    def block_at(self, offset: int) -> Optional[CfgBlock]:
        for b in self.blocks:
            if b.offset == offset: return b
        return None

    def successors_of(self, offset: int) -> List[int]:
        b = self.block_at(offset)
        return list(b.successors) if b else []

    def bfs_order(self) -> List[int]:
        if not self.blocks: return []
        order, seen, queue = [], set(), [self.entry]
        while queue:
            o = queue.pop(0)
            if o in seen: continue
            seen.add(o)
            order.append(o)
            queue.extend(self.successors_of(o))
        return order


class CfgNormalizer:
    @classmethod
    def new(cls) -> "CfgNormalizer": return cls()

    @staticmethod
    def is_useless_jump(src_block: CfgBlock) -> bool:
        return len(src_block.successors) == 1 and not src_block.instrs

    def normalize(self, blocks: List[CfgBlock], entry: int) -> NormalizedCfg:
        return NormalizedCfg(list(blocks), entry)


# ============================================================
# constant_folding_pass.rs
# ============================================================
class FoldableExpr:
    def __init__(self, kind: str, value: Any = None, children: Optional[List["FoldableExpr"]] = None):
        self.kind = kind
        self.value = value
        self.children = list(children or [])

    def depth(self) -> int:
        return 1 + (max((c.depth() for c in self.children), default=0))

    def node_count(self) -> int:
        return 1 + sum(c.node_count() for c in self.children)


def eval_binop(op: str, lhs: int, rhs: int) -> Optional[int]:
    try:
        if op == "+": return lhs + rhs
        if op == "-": return lhs - rhs
        if op == "*": return lhs * rhs
        if op == "/": return None if rhs == 0 else lhs // rhs
        if op == "%": return None if rhs == 0 else lhs % rhs
        if op == "&": return lhs & rhs
        if op == "|": return lhs | rhs
        if op == "^": return lhs ^ rhs
        if op == "<<": return lhs << (rhs & 63)
        if op == ">>": return lhs >> (rhs & 63)
    except Exception:
        return None
    return None


def eval_unop(op: str, val: int) -> int:
    if op == "-": return -val
    if op == "~": return ~val
    if op == "!": return 0 if val else 1
    return val


class FoldResult:
    def __init__(self, value: Optional[int] = None, expr: Optional[FoldableExpr] = None):
        self.value = value
        self.expr = expr


def fold_expr(expr: FoldableExpr, env: Dict[str, int]) -> FoldResult:
    if expr.kind == "const":
        return FoldResult(value=int(expr.value))
    if expr.kind == "var":
        v = env.get(expr.value)
        return FoldResult(value=v) if v is not None else FoldResult(expr=expr)
    if expr.kind == "binop" and len(expr.children) == 2:
        l = fold_expr(expr.children[0], env)
        r = fold_expr(expr.children[1], env)
        if l.value is not None and r.value is not None:
            v = eval_binop(expr.value, l.value, r.value)
            if v is not None: return FoldResult(value=v)
    if expr.kind == "unop" and len(expr.children) == 1:
        c = fold_expr(expr.children[0], env)
        if c.value is not None:
            return FoldResult(value=eval_unop(expr.value, c.value))
    return FoldResult(expr=expr)


def rewrite_expr(expr: FoldableExpr, env: Dict[str, int]) -> FoldableExpr:
    r = fold_expr(expr, env)
    if r.value is not None:
        return FoldableExpr("const", r.value)
    return FoldableExpr(expr.kind, expr.value, [rewrite_expr(c, env) for c in expr.children])


class IrBlock:
    def __init__(self, label: str):
        self.label = label
        self.stmts: List[Tuple[str, FoldableExpr]] = []

    @classmethod
    def new(cls, label: str) -> "IrBlock": return cls(label)

    def push(self, target: str, expr: FoldableExpr) -> None:
        self.stmts.append((target, expr))


class FoldStats:
    def __init__(self):
        self.folded = 0
        self.unchanged = 0


class ConstantFolder:
    def __init__(self):
        self.seeds: Dict[str, int] = {}

    @classmethod
    def new(cls) -> "ConstantFolder": return cls()

    def with_seeds(self, seeds: Dict[str, int]) -> "ConstantFolder":
        self.seeds = dict(seeds)
        return self

    def fold_function(self, blocks: List[IrBlock]) -> FoldStats:
        stats = FoldStats()
        env = dict(self.seeds)
        for blk in blocks:
            new_stmts = []
            for tgt, expr in blk.stmts:
                r = fold_expr(expr, env)
                if r.value is not None:
                    env[tgt] = r.value
                    new_stmts.append((tgt, FoldableExpr("const", r.value)))
                    stats.folded += 1
                else:
                    new_stmts.append((tgt, rewrite_expr(expr, env)))
                    stats.unchanged += 1
            blk.stmts = new_stmts
        return stats


# ============================================================
# control_flow_normalization.rs
# ============================================================
class EdgeKind:
    FALL = "fall"; JUMP = "jump"; BRANCH_TRUE = "true"; BRANCH_FALSE = "false"


class BasicBlock:
    def __init__(self, addr: int = 0):
        self.addr = addr
        self.instrs: list = []
        self.successors: List[Tuple[int, str]] = []
        self.predecessors: List[int] = []

    def add_successor(self, target: int, kind: str) -> None:
        self.successors.append((target, kind))


class NormalizationReport:
    def __init__(self):
        self.notes: List[str] = []

    @classmethod
    def new(cls) -> "NormalizationReport": return cls()

    def note(self, msg: str) -> None: self.notes.append(msg)
    def summary(self) -> str: return f"{len(self.notes)} notes"


class JumpThreader:
    @staticmethod
    def resolve_target(addr: int, blocks: Dict[int, BasicBlock]) -> int:
        seen = set()
        cur = addr
        while cur in blocks and cur not in seen:
            seen.add(cur)
            bb = blocks[cur]
            if len(bb.successors) == 1 and bb.successors[0][1] == EdgeKind.JUMP and not bb.instrs:
                cur = bb.successors[0][0]
            else:
                break
        return cur

    @staticmethod
    def run(blocks: Dict[int, BasicBlock], report: NormalizationReport) -> None:
        for bb in blocks.values():
            new_succ = []
            for tgt, kind in bb.successors:
                new_succ.append((JumpThreader.resolve_target(tgt, blocks), kind))
            if new_succ != bb.successors:
                report.note(f"threaded {bb.addr:x}")
            bb.successors = new_succ


class ReachabilityAnalyzer:
    @staticmethod
    def reachable(entry: int, blocks: Dict[int, BasicBlock]) -> Set[int]:
        seen, stack = set(), [entry]
        while stack:
            cur = stack.pop()
            if cur in seen or cur not in blocks: continue
            seen.add(cur)
            for tgt, _ in blocks[cur].successors:
                stack.append(tgt)
        return seen

    @staticmethod
    def run(entry: int, blocks: Dict[int, BasicBlock], report: NormalizationReport) -> Set[int]:
        r = ReachabilityAnalyzer.reachable(entry, blocks)
        report.note(f"reachable={len(r)}")
        return r


class DeadBlockRemover:
    @staticmethod
    def run(blocks: Dict[int, BasicBlock], report: NormalizationReport, entry: int = 0) -> None:
        reach = ReachabilityAnalyzer.reachable(entry, blocks)
        dead = [a for a in list(blocks.keys()) if a not in reach]
        for a in dead:
            del blocks[a]
        if dead:
            report.note(f"removed {len(dead)} dead blocks")


class NopFolder:
    @classmethod
    def new(cls) -> "NopFolder": return cls()

    def is_nop_block(self, bb: BasicBlock) -> bool:
        return not bb.instrs and len(bb.successors) <= 1

    def run(self, blocks: Dict[int, BasicBlock], report: NormalizationReport) -> None:
        n = sum(1 for b in blocks.values() if self.is_nop_block(b))
        report.note(f"nop blocks: {n}")


def recompute_predecessors(blocks: Dict[int, BasicBlock]) -> None:
    for b in blocks.values():
        b.predecessors = []
    for addr, bb in blocks.items():
        for tgt, _ in bb.successors:
            if tgt in blocks:
                blocks[tgt].predecessors.append(addr)


class ControlFlowNormalizer:
    @staticmethod
    def run(blocks: Dict[int, BasicBlock], entry: int = 0) -> NormalizationReport:
        report = NormalizationReport.new()
        JumpThreader.run(blocks, report)
        DeadBlockRemover.run(blocks, report, entry)
        NopFolder.new().run(blocks, report)
        recompute_predecessors(blocks)
        return report


class Dominators:
    def __init__(self, idoms: Optional[Dict[int, int]] = None):
        self.idoms = dict(idoms or {})

    @classmethod
    def compute(cls, entry: int, blocks: Dict[int, BasicBlock]) -> "Dominators":
        idoms: Dict[int, int] = {entry: entry}
        changed = True
        while changed:
            changed = False
            for addr in blocks:
                if addr == entry: continue
                bb = blocks[addr]
                preds = [p for p in bb.predecessors if p in idoms]
                if not preds: continue
                new_idom = preds[0]
                if idoms.get(addr) != new_idom:
                    idoms[addr] = new_idom
                    changed = True
        return cls(idoms)

    def idom_of(self, block: int) -> Optional[int]:
        return self.idoms.get(block)

    def dominates(self, dom: int, block: int) -> bool:
        cur = block
        seen = set()
        while cur in self.idoms and cur not in seen:
            if cur == dom: return True
            seen.add(cur)
            nxt = self.idoms[cur]
            if nxt == cur: break
            cur = nxt
        return False


def build_cfg(instrs: list, entry: int = 0) -> Dict[int, BasicBlock]:
    bb = BasicBlock(entry)
    bb.instrs = list(instrs)
    return {entry: bb}


# ============================================================
# dead_code_eliminator.rs
# ============================================================
class Var:
    def __init__(self, name: str): self.name = name
    def __eq__(self, o): return isinstance(o, Var) and o.name == self.name
    def __hash__(self): return hash(self.name)


class IrInstr:
    def __init__(self, kind: str, dst: Optional[Var] = None, srcs: Optional[List[Var]] = None):
        self.kind = kind
        self.dst = dst
        self.srcs = list(srcs or [])

    def defs(self) -> List[Var]: return [self.dst] if self.dst else []
    def uses(self) -> List[Var]: return list(self.srcs)


class DeadInstruction:
    def __init__(self, block_idx: int, instr_idx: int, reason: str):
        self.block_idx = block_idx
        self.instr_idx = instr_idx
        self.reason = reason

    def description(self) -> str:
        return f"block {self.block_idx} instr {self.instr_idx}: {self.reason}"


class LivenessSets:
    def __init__(self):
        self.live_in: Set[Var] = set()
        self.live_out: Set[Var] = set()


class LivenessAnalyzer:
    @staticmethod
    def analyze(blocks: List[List[IrInstr]]) -> Dict[int, LivenessSets]:
        result: Dict[int, LivenessSets] = {i: LivenessSets() for i in range(len(blocks))}
        for i, block in enumerate(blocks):
            live: Set[Var] = set()
            for instr in reversed(block):
                for d in instr.defs(): live.discard(d)
                for u in instr.uses(): live.add(u)
            result[i].live_in = set(live)
        return result

    @staticmethod
    def live_before(blocks: List[List[IrInstr]], idx: int) -> Set[Var]:
        return LivenessAnalyzer.analyze(blocks).get(idx, LivenessSets()).live_in


class DceReport:
    def __init__(self):
        self._nops: List[DeadInstruction] = []
        self._constant_branches: List[DeadInstruction] = []
        self._unused: List[DeadInstruction] = []

    def nops(self): return iter(self._nops)
    def constant_branches(self): return iter(self._constant_branches)
    def unused_assignments(self): return iter(self._unused)


class DeadCodeEliminator:
    @staticmethod
    def eliminate(blocks: List[List[IrInstr]]) -> DceReport:
        report = DceReport()
        live_map = LivenessAnalyzer.analyze(blocks)
        for bi, block in enumerate(blocks):
            live = set(live_map[bi].live_in)
            new_block = []
            for ii, instr in enumerate(block):
                if instr.dst and instr.dst not in live and not instr.srcs:
                    report._unused.append(DeadInstruction(bi, ii, "unused assignment"))
                    continue
                new_block.append(instr)
            blocks[bi] = new_block
        return report

    @staticmethod
    def dfs_reachable(blocks: Dict[int, list], entry: int) -> Set[int]:
        seen, stack = set(), [entry]
        while stack:
            cur = stack.pop()
            if cur in seen or cur not in blocks: continue
            seen.add(cur)
        return seen

    @staticmethod
    def bfs_order(blocks: Dict[int, list], entry: int) -> List[int]:
        order, seen, queue = [], set(), [entry]
        while queue:
            cur = queue.pop(0)
            if cur in seen or cur not in blocks: continue
            seen.add(cur)
            order.append(cur)
        return order

    @staticmethod
    def dead_block_count(blocks: Dict[int, list], entry: int) -> int:
        reach = DeadCodeEliminator.dfs_reachable(blocks, entry)
        return sum(1 for k in blocks if k not in reach)


# ============================================================
# deobf_pass_registry.rs
# ============================================================
class PassMetadata:
    def __init__(self, name: str, category: str = "", description: str = ""):
        self.name = name
        self.category = category
        self.description = description
        self.patterns: List[str] = []
        self.dependencies: List[str] = []
        self.capabilities: List[str] = []
        self.version: str = "1.0"
        self.enabled: bool = True
        self.priority: int = 0

    @classmethod
    def new(cls, name: str, category: str = "", description: str = "") -> "PassMetadata":
        return cls(name, category, description)

    def with_patterns(self, patterns: List[str]) -> "PassMetadata":
        self.patterns = list(patterns); return self

    def with_dependencies(self, deps: List[str]) -> "PassMetadata":
        self.dependencies = list(deps); return self

    def with_version(self, v: str) -> "PassMetadata":
        self.version = v; return self

    def with_capability(self, cap: str) -> "PassMetadata":
        self.capabilities.append(cap); return self

    def with_dependency(self, dep: str) -> "PassMetadata":
        self.dependencies.append(dep); return self

    def has_capability(self, cap: str) -> bool:
        return cap in self.capabilities


class DeobfResult:
    def __init__(self, transforms: Optional[List[TransformResult]] = None):
        self.transforms = list(transforms or [])


class PassEntry:
    def __init__(self, pass_: Optional[DeobfPass] = None, metadata: Optional[PassMetadata] = None,
                 trigger: Optional[Callable[[bytes], bool]] = None):
        self.pass_ = pass_
        self.metadata = metadata or PassMetadata("unnamed")
        self.trigger = trigger

    @classmethod
    def new(cls, pass_: Optional[DeobfPass] = None, metadata: Optional[PassMetadata] = None) -> "PassEntry":
        return cls(pass_, metadata)

    @property
    def name(self) -> str: return self.metadata.name

    def matches_pattern(self, pattern: str) -> bool:
        return pattern in self.metadata.patterns

    def with_trigger(self, metadata: PassMetadata, f: Callable[[bytes], bool]) -> "PassEntry":
        return PassEntry(self.pass_, metadata, f)

    def triggers_on(self, binary: bytes) -> bool:
        return bool(self.trigger and self.trigger(binary))


class RegistryStats:
    def __init__(self, total: int = 0, enabled: int = 0):
        self.total = total
        self.enabled = enabled


class DeobfPassRegistry:
    def __init__(self):
        self._entries: Dict[str, PassEntry] = {}

    @classmethod
    def new(cls) -> "DeobfPassRegistry": return cls()

    def register(self, pass_: DeobfPass, metadata: PassMetadata) -> None:
        self._entries[metadata.name] = PassEntry(pass_, metadata)

    def register_simple(self, pass_: DeobfPass, name: str) -> None:
        self._entries[name] = PassEntry(pass_, PassMetadata(name))

    def get(self, name: str) -> Optional[PassEntry]: return self._entries.get(name)
    def get_mut(self, name: str) -> Optional[PassEntry]: return self._entries.get(name)

    def get_passes_for_pattern(self, pattern: str) -> List[PassEntry]:
        return [e for e in self._entries.values() if e.matches_pattern(pattern)]

    def get_by_category(self, category: str) -> List[PassEntry]:
        return [e for e in self._entries.values() if e.metadata.category == category]

    def set_enabled(self, name: str, enabled: bool) -> bool:
        e = self._entries.get(name)
        if e:
            e.metadata.enabled = enabled
            return True
        return False

    def names(self) -> List[str]: return list(self._entries.keys())

    def run_pass(self, name: str, ctx: DeobfContext) -> DeobfResult:
        e = self._entries.get(name)
        if not e or not e.pass_:
            raise DeobfError(f"unknown pass {name}")
        return DeobfResult([e.pass_.run(ctx)])

    def run_all(self, ctx: DeobfContext) -> List[DeobfResult]:
        out = []
        for e in self._entries.values():
            if e.metadata.enabled and e.pass_:
                out.append(DeobfResult([e.pass_.run(ctx)]))
        return out

    def stats(self) -> RegistryStats:
        total = len(self._entries)
        enabled = sum(1 for e in self._entries.values() if e.metadata.enabled)
        return RegistryStats(total, enabled)

    def dependents_of(self, name: str) -> List[str]:
        return [n for n, e in self._entries.items() if name in e.metadata.dependencies]

    def validate_dependencies(self) -> List[str]:
        errs = []
        for n, e in self._entries.items():
            for d in e.metadata.dependencies:
                if d not in self._entries:
                    errs.append(f"{n} -> missing {d}")
        return errs

    def topological_order(self) -> Optional[List[str]]:
        indeg = {n: 0 for n in self._entries}
        for n, e in self._entries.items():
            for d in e.metadata.dependencies:
                if d in indeg: indeg[n] += 1
        order = []
        ready = [n for n, d in indeg.items() if d == 0]
        while ready:
            cur = ready.pop(0)
            order.append(cur)
            for n, e in self._entries.items():
                if cur in e.metadata.dependencies and n != cur:
                    indeg[n] -= 1
                    if indeg[n] == 0: ready.append(n)
        return order if len(order) == len(self._entries) else None


def get_pass_for_pattern(registry: DeobfPassRegistry, pattern: str) -> Optional[PassEntry]:
    passes = registry.get_passes_for_pattern(pattern)
    return passes[0] if passes else None


def default_registry() -> DeobfPassRegistry:
    return DeobfPassRegistry.new()


# ============================================================
# deobf_pipeline.rs
# ============================================================
class PassId:
    def __init__(self, id_: str): self.id = id_
    @classmethod
    def new(cls, id_: str) -> "PassId": return cls(id_)
    def as_str(self) -> str: return self.id


class PassResult:
    def __init__(self, pass_id: str = "", success: bool = True, error: Optional[str] = None,
                 elapsed: float = 0.0, patches: int = 0, confidence: float = 1.0):
        self.pass_id = pass_id
        self.success = success
        self.error = error
        self.elapsed = elapsed
        self.patches = patches
        self.confidence = confidence
        self._snapshot: Optional[bytes] = None

    @classmethod
    def failure(cls, pass_id: str, error: str, elapsed: float) -> "PassResult":
        return cls(pass_id=pass_id, success=False, error=error, elapsed=elapsed)

    def with_snapshot(self, snap: bytes) -> "PassResult":
        self._snapshot = bytes(snap); return self

    def snapshot(self) -> Optional[bytes]: return self._snapshot

    def patches_applied(self) -> int: return self.patches
    def confidence_value(self) -> float: return self.confidence


class PipelineConfig:
    def __init__(self):
        self.disabled: Set[str] = set()

    @classmethod
    def new(cls) -> "PipelineConfig": return cls()

    def disable_pass(self, pass_id: str) -> "PipelineConfig":
        self.disabled.add(pass_id); return self


class Pipeline:
    def __init__(self):
        self.passes: List[DeobfPass] = []
        self.config = PipelineConfig.new()

    @classmethod
    def new(cls) -> "Pipeline": return cls()

    def with_config(self, config: PipelineConfig) -> "Pipeline":
        self.config = config; return self

    def add_pass(self, p: DeobfPass) -> None: self.passes.append(p)
    def pass_count(self) -> int: return len(self.passes)
    def pass_names(self) -> List[str]: return [p.name for p in self.passes]

    def run(self, binary: bytes) -> PipelineResult:
        res = PipelineResult()
        ctx = DeobfContext.new(binary)
        for p in self.passes:
            if p.name in self.config.disabled: continue
            res.record(PassResult(pass_id=p.name, success=True))
            p.run(ctx)
        return res

    def dry_run(self, binary: bytes) -> List[Tuple[str, bool]]:
        return [(p.name, p.name not in self.config.disabled) for p in self.passes]


class NopRemoverPass(DeobfPass):
    def __init__(self, id_: str): self.name = id_
    @classmethod
    def new(cls, id_: str) -> "NopRemoverPass": return cls(id_)


class JumpThreaderPass(DeobfPass):
    def __init__(self, id_: str): self.name = id_
    @classmethod
    def new(cls, id_: str) -> "JumpThreaderPass": return cls(id_)


class XorDecryptPass(DeobfPass):
    def __init__(self, id_: str, key: int):
        self.name = id_
        self.key = key & 0xFF

    @classmethod
    def new(cls, id_: str, key: int) -> "XorDecryptPass": return cls(id_, key)


# ============================================================
# deobf_registry.rs
# ============================================================
class SelectionResult:
    def __init__(self, selected: Optional[List[str]] = None):
        self.selected = list(selected or [])

    def summary(self) -> str:
        return f"selected {len(self.selected)} passes"


class DeobfRegistry:
    def __init__(self):
        self._entries: Dict[str, PassEntry] = {}

    @classmethod
    def new(cls) -> "DeobfRegistry": return cls()

    @classmethod
    def with_builtins(cls) -> "DeobfRegistry": return cls()

    def register(self, entry: PassEntry) -> Optional[PassEntry]:
        prev = self._entries.get(entry.name)
        self._entries[entry.name] = entry
        return prev

    def register_metadata(self, meta: PassMetadata) -> None:
        self._entries[meta.name] = PassEntry(None, meta)

    def deregister(self, name: str) -> None:
        self._entries.pop(name, None)

    def get(self, name: str) -> Optional[PassEntry]: return self._entries.get(name)
    def len(self) -> int: return len(self._entries)
    def is_empty(self) -> bool: return not self._entries
    def names(self) -> List[str]: return list(self._entries.keys())

    def by_category(self, category: str) -> List[PassEntry]:
        return [e for e in self._entries.values() if e.metadata.category == category]

    def by_capability(self, cap: str) -> List[PassEntry]:
        return [e for e in self._entries.values() if e.metadata.has_capability(cap)]

    def all_by_priority(self) -> List[PassEntry]:
        return sorted(self._entries.values(), key=lambda e: e.metadata.priority, reverse=True)

    def default_enabled(self) -> List[PassEntry]:
        return [e for e in self._entries.values() if e.metadata.enabled]

    def enable(self, name: str) -> None:
        e = self._entries.get(name)
        if e: e.metadata.enabled = True

    def disable(self, name: str) -> None:
        e = self._entries.get(name)
        if e: e.metadata.enabled = False

    def select(self, binary: bytes) -> SelectionResult:
        sel = [name for name, e in self._entries.items() if e.triggers_on(binary) or not e.trigger]
        return SelectionResult(sel)


def select_by_category(registry: DeobfRegistry, category: str) -> SelectionResult:
    return SelectionResult([e.name for e in registry.by_category(category)])


# ============================================================
# deobf_report.rs
# ============================================================
class TransformStat:
    def __init__(self, category: str, description: str, count: int = 1):
        self.category = category
        self.description = description
        self.count = count

    @classmethod
    def new(cls, category: str, description: str) -> "TransformStat":
        return cls(category, description)


class PassSummary:
    def __init__(self, pass_id: str, pass_name: str):
        self.pass_id = pass_id
        self.pass_name = pass_name
        self.transforms: List[TransformStat] = []
        self.notes: List[str] = []
        self.skipped: bool = False
        self.failed: bool = False
        self.skip_reason: Optional[str] = None
        self.bytes_before: int = 0
        self.bytes_after: int = 0
        self.findings: List["Finding"] = []
        self.confidence: float = 0.0
        self.patches: int = 0

    @classmethod
    def new(cls, pass_id: str, pass_name: str) -> "PassSummary": return cls(pass_id, pass_name)

    @classmethod
    def from_heuristics(cls, confidence: float, patches: int) -> "PassSummary":
        s = cls("heuristic", "heuristic")
        s.confidence = confidence
        s.patches = patches
        return s

    def mark_skipped(self, reason: str) -> None:
        self.skipped = True
        self.skip_reason = reason

    def add_transform(self, stat: TransformStat) -> None: self.transforms.append(stat)
    def add_note(self, note: str) -> None: self.notes.append(note)

    def total_transforms(self) -> int:
        return sum(t.count for t in self.transforms)

    def bytes_delta(self) -> int: return self.bytes_after - self.bytes_before

    def compression_ratio(self) -> float:
        if self.bytes_before == 0: return 0.0
        return self.bytes_after / self.bytes_before


class Metrics:
    def __init__(self):
        self.score: float = 0.0

    @classmethod
    def compute(cls, report: DeobfReport) -> "Metrics":
        m = cls()
        m.score = float(sum(p.total_transforms() for p in report.passes))
        return m

    def score_pct(self) -> float:
        return min(100.0, self.score)

    def improvement_over(self, baseline: "Metrics") -> float:
        return self.score - baseline.score


class ReportBuilder:
    def __init__(self, binary_name: str, size: int = 0):
        self.report = DeobfReport.new(binary_name, size)

    @classmethod
    def new(cls, binary_name: str, size: int = 0) -> "ReportBuilder": return cls(binary_name, size)

    def hash(self, sha256: str) -> "ReportBuilder":
        self.report.set_hash(sha256); return self

    def pass_(self, summary: PassSummary) -> "ReportBuilder":
        self.report.add_pass(summary); return self

    def note(self, note: str) -> "ReportBuilder":
        self.report.add_note(note); return self

    def warning(self, w: str) -> "ReportBuilder":
        self.report.add_warning(w); return self

    def build(self) -> DeobfReport: return self.report


class MultiReport:
    def __init__(self):
        self.reports: List[DeobfReport] = []

    def add(self, report: DeobfReport) -> None: self.reports.append(report)

    def total_strings_recovered(self) -> int:
        return sum(len(r.findings) for r in self.reports)

    def total_instructions_modified(self) -> int:
        return sum(sum(p.total_transforms() for p in r.passes) for r in self.reports)

    def average_score_improvement(self) -> float:
        if not self.reports: return 0.0
        return sum(r.score_improvement() for r in self.reports) / len(self.reports)

    def most_effective_pass(self) -> Optional[str]:
        counter: Counter = Counter()
        for r in self.reports:
            for p in r.passes:
                counter[p.pass_name] += p.total_transforms()
        if not counter: return None
        return counter.most_common(1)[0][0]

    def summary_text(self) -> str:
        return f"{len(self.reports)} reports"


# ============================================================
# deobf_report_extended.rs
# ============================================================
class DeobfTimeline:
    def __init__(self, technique: str, pass_name: str):
        self.technique = technique
        self.pass_name = pass_name
        self.bytes_before: int = 0
        self.bytes_after: int = 0

    @classmethod
    def new(cls, technique: str, pass_name: str) -> "DeobfTimeline":
        return cls(technique, pass_name)

    def bytes_changed(self) -> int:
        return abs(self.bytes_after - self.bytes_before)


class RecoveredAsset:
    def __init__(self, kind: str, name: str = ""):
        self.kind = kind
        self.name = name
        self.value: Any = None

    @classmethod
    def new(cls, kind: str, name: str = "") -> "RecoveredAsset":
        return cls(kind, name)

    def with_value(self, v: Any) -> "RecoveredAsset":
        self.value = v; return self


class ConfidenceMatrix:
    def __init__(self):
        self.detection: Dict[str, float] = {}
        self.removal: Dict[str, float] = {}

    @classmethod
    def new(cls) -> "ConfidenceMatrix": return cls()

    def set_detection(self, technique: str, val: float) -> None: self.detection[technique] = val
    def set_removal(self, technique: str, val: float) -> None: self.removal[technique] = val
    def detection_for(self, technique: str) -> Optional[float]: return self.detection.get(technique)
    def removal_for(self, technique: str) -> Optional[float]: return self.removal.get(technique)

    def avg_detection(self) -> float:
        return (sum(self.detection.values()) / len(self.detection)) if self.detection else 0.0

    def avg_removal(self) -> float:
        return (sum(self.removal.values()) / len(self.removal)) if self.removal else 0.0


class DeobfReportExtended:
    def __init__(self, binary_name: str, size: int):
        self.binary_name = binary_name
        self.size = size
        self.techniques: List[Tuple[str, float, float]] = []
        self.timeline: List[DeobfTimeline] = []
        self.assets: List[RecoveredAsset] = []
        self.matrix = ConfidenceMatrix.new()

    @classmethod
    def new(cls, binary_name: str, size: int) -> "DeobfReportExtended":
        return cls(binary_name, size)

    def add_technique(self, t: str, det: float, rem: float) -> None:
        self.techniques.append((t, det, rem))
        self.matrix.set_detection(t, det)
        self.matrix.set_removal(t, rem)

    def add_timeline(self, entry: DeobfTimeline) -> None: self.timeline.append(entry)
    def add_asset(self, asset: RecoveredAsset) -> None: self.assets.append(asset)

    def compute_overall_confidence(self) -> float:
        if not self.techniques: return 0.0
        vals = [(d + r) / 2.0 for _, d, r in self.techniques]
        return sum(vals) / len(vals)

    def asset_count(self, kind: str) -> int:
        return sum(1 for a in self.assets if a.kind == kind)

    def techniques_by_category(self) -> Dict[str, List[str]]:
        out: Dict[str, List[str]] = defaultdict(list)
        for t, _, _ in self.techniques:
            out["general"].append(t)
        return dict(out)


class MarkdownExporter:
    @staticmethod
    def generate(report: DeobfReportExtended) -> str:
        return "\n".join([f"# {report.binary_name}", f"size: {report.size}",
                          f"techniques: {len(report.techniques)}"])


class HtmlExporter:
    @staticmethod
    def generate(report: DeobfReportExtended) -> str:
        return f"<html><body><h1>{report.binary_name}</h1><p>techniques: {len(report.techniques)}</p></body></html>"


# ============================================================
# junk_code_remover.rs
# ============================================================
class JunkPattern:
    def __init__(self, name: str, bytes_: bytes, weight: int = 1):
        self.name = name
        self.bytes = bytes(bytes_)
        self.weight = weight


class JunkScorer:
    def __init__(self):
        self.weights: Dict[str, int] = {}

    @classmethod
    def new(cls) -> "JunkScorer": return cls()

    def score(self, pattern: JunkPattern) -> int:
        return min(255, self.weights.get(pattern.name, pattern.weight))

    def explain(self, pattern: JunkPattern) -> str:
        return f"{pattern.name}: weight={self.score(pattern)}"

    def merge(self, other: "JunkScorer") -> None:
        for k, v in other.weights.items():
            self.weights[k] = max(self.weights.get(k, 0), v)


class JunkDb:
    def __init__(self): self._entries: Dict[str, JunkPattern] = {}

    @classmethod
    def build(cls) -> "JunkDb":
        db = cls()
        db.insert(JunkPattern("nop", b"\x90"))
        return db

    def len(self) -> int: return len(self._entries)
    def is_empty(self) -> bool: return not self._entries
    def get(self, name: str) -> Optional[JunkPattern]: return self._entries.get(name)
    def iter(self): return iter(self._entries.values())
    def insert(self, entry: JunkPattern) -> None: self._entries[entry.name] = entry

    def scan_bytes(self, data: bytes) -> List[Tuple[str, int]]:
        out = []
        for name, pat in self._entries.items():
            i = data.find(pat.bytes)
            while i != -1:
                out.append((name, i))
                i = data.find(pat.bytes, i + 1)
        return out


class RemovalResult:
    def __init__(self, removed: int = 0, bytes_removed: int = 0):
        self.removed = removed
        self.bytes_removed = bytes_removed


class JunkCodeRemover:
    def __init__(self, threshold: int = 1, scorer: Optional[JunkScorer] = None):
        self.threshold = threshold
        self.scorer = scorer or JunkScorer.new()
        self.db = JunkDb.build()

    @classmethod
    def new(cls, threshold: int) -> "JunkCodeRemover": return cls(threshold)

    def with_scorer(self, threshold: int, scorer: JunkScorer) -> "JunkCodeRemover":
        return JunkCodeRemover(threshold, scorer)

    def remove_from_bytes(self, data: bytes) -> Tuple[bytes, RemovalResult]:
        out = bytearray(data)
        result = RemovalResult()
        for name, pat in self.db._entries.items():
            score = self.scorer.score(pat)
            if score < self.threshold: continue
            new = bytes(out).replace(pat.bytes, b"")
            removed = (len(out) - len(new)) // max(1, len(pat.bytes))
            result.removed += removed
            result.bytes_removed += len(out) - len(new)
            out = bytearray(new)
        return bytes(out), result

    def remove_patterns(self, patterns: List[JunkPattern]) -> RemovalResult:
        return RemovalResult(len(patterns), sum(len(p.bytes) for p in patterns))

    def count_removable(self, data: bytes) -> int:
        return sum(1 for _ in self.db.scan_bytes(data))


# ============================================================
# opaque_predicate_resolver.rs
# ============================================================
class ResolutionResult:
    def __init__(self, kind: str = "", confidence: float = 0.0, addr: int = 0):
        self.kind = kind
        self.confidence = confidence
        self.addr = addr

    @classmethod
    def new(cls, kind: str, confidence: float, addr: int = 0) -> "ResolutionResult":
        return cls(kind, confidence, addr)

    def is_high_confidence(self) -> bool: return self.confidence >= 0.8


class SymExpr:
    def __init__(self, op: str, args: Optional[List[Any]] = None, value: Any = None):
        self.op = op
        self.args = list(args or [])
        self.value = value

    @staticmethod
    def eq(l, r) -> "SymExpr": return SymExpr("eq", [l, r])
    @staticmethod
    def band(l, r) -> "SymExpr": return SymExpr("and", [l, r])
    @staticmethod
    def xor(l, r) -> "SymExpr": return SymExpr("xor", [l, r])
    @staticmethod
    def sym_mul(l, r) -> "SymExpr": return SymExpr("mul", [l, r])
    @staticmethod
    def sym_rem(l, r) -> "SymExpr": return SymExpr("rem", [l, r])


def is_self_xor_zero(expr: SymExpr) -> bool:
    return expr.op == "xor" and len(expr.args) == 2 and expr.args[0] is expr.args[1]


def is_mul_by_zero(expr: SymExpr) -> bool:
    if expr.op != "mul" or len(expr.args) != 2: return False
    for a in expr.args:
        if isinstance(a, SymExpr) and a.op == "const" and a.value == 0: return True
        if a == 0: return True
    return False


def is_always_true_or(expr: SymExpr) -> bool:
    if expr.op != "or" or len(expr.args) != 2: return False
    for a in expr.args:
        if isinstance(a, SymExpr) and a.op == "const" and a.value == 1: return True
        if a == 1: return True
    return False


def is_consecutive_product_even(expr: SymExpr) -> bool:
    return expr.op == "mul" and len(expr.args) == 2


def eval_const_expr(expr: Any) -> Optional[int]:
    if isinstance(expr, int): return expr
    if not isinstance(expr, SymExpr): return None
    if expr.op == "const": return int(expr.value)
    args = [eval_const_expr(a) for a in expr.args]
    if any(a is None for a in args): return None
    if expr.op == "xor": return args[0] ^ args[1]
    if expr.op == "and": return args[0] & args[1]
    if expr.op == "or": return args[0] | args[1]
    if expr.op == "mul": return args[0] * args[1]
    if expr.op == "rem": return None if args[1] == 0 else args[0] % args[1]
    if expr.op == "eq": return 1 if args[0] == args[1] else 0
    return None


class ResolverConfig:
    def __init__(self, threshold: float = 0.7):
        self.threshold = threshold


class OpaquePredicateResolver:
    def __init__(self):
        self.config = ResolverConfig()
        self._results: List[ResolutionResult] = []

    @classmethod
    def new(cls) -> "OpaquePredicateResolver": return cls()

    def with_config(self, config: ResolverConfig) -> "OpaquePredicateResolver":
        self.config = config; return self

    def reset(self) -> None: self._results = []
    def results(self) -> List[ResolutionResult]: return list(self._results)

    def classify_symbolic(self, expr: SymExpr) -> ResolutionResult:
        if is_self_xor_zero(expr): return ResolutionResult.new("self_xor", 1.0)
        if is_mul_by_zero(expr): return ResolutionResult.new("mul_zero", 1.0)
        if is_always_true_or(expr): return ResolutionResult.new("always_true_or", 1.0)
        v = eval_const_expr(expr)
        if v is not None: return ResolutionResult.new("const", 0.9)
        return ResolutionResult.new("unknown", 0.0)

    def scan_bytes(self, data: bytes) -> List[ResolutionResult]:
        results = []
        for i in range(len(data) - 1):
            if data[i] == 0x31 and data[i + 1] in (0xC0, 0xC9, 0xD2, 0xDB):
                results.append(ResolutionResult.new("self_xor", 1.0, i))
        self._results.extend(results)
        return results

    def apply_hash_heuristic(self, data: bytes) -> None:
        h = hashlib.sha256(data).hexdigest()
        if h[0] == "0":
            self._results.append(ResolutionResult.new("hash_heuristic", 0.5))

    def report(self) -> str:
        return f"{len(self._results)} resolutions"


# ============================================================
# pass_manager.rs
# ============================================================
class PassManagerReport:
    def __init__(self):
        self.total_patches = 0
        self.successful_passes = 0
        self.skipped_passes = 0
        self.failed_passes = 0
        self.average_confidence = 0.0
        self.timings: List[Tuple[str, float]] = []

    def slowest_passes(self, n: int) -> List[Tuple[str, float]]:
        return sorted(self.timings, key=lambda t: t[1], reverse=True)[:n]


class PassManager:
    def __init__(self):
        self._passes: Dict[str, DeobfPass] = {}
        self._enabled: Dict[str, bool] = {}
        self._deps: Dict[str, Set[str]] = defaultdict(set)
        self._listener: Optional[Callable[[str], None]] = None
        self._cache: Dict[str, Any] = {}

    @classmethod
    def new(cls) -> "PassManager": return cls()

    def set_listener(self, f: Callable[[str], None]) -> None: self._listener = f

    def register(self, pass_: DeobfPass) -> None:
        if pass_.name in self._passes:
            raise PassManagerError(f"duplicate {pass_.name}")
        self._passes[pass_.name] = pass_
        self._enabled[pass_.name] = True

    def add_dependency(self, name: str, dep: str) -> None:
        self._deps[name].add(dep)

    def set_enabled(self, name: str, enabled: bool) -> None:
        if name in self._enabled: self._enabled[name] = enabled

    def invalidate_cache(self) -> None: self._cache = {}
    def len(self) -> int: return len(self._passes)
    def is_empty(self) -> bool: return not self._passes

    def topological_order(self) -> List[str]:
        indeg = {n: 0 for n in self._passes}
        for n, deps in self._deps.items():
            for d in deps:
                if d in indeg: indeg[n] += 1
        ready = [n for n, d in indeg.items() if d == 0]
        order = []
        while ready:
            cur = ready.pop(0)
            order.append(cur)
            for n, deps in self._deps.items():
                if cur in deps:
                    indeg[n] -= 1
                    if indeg[n] == 0: ready.append(n)
        if len(order) != len(self._passes):
            raise PassManagerError("cycle")
        return order

    def run(self, ctx: DeobfContext) -> PassManagerReport:
        rep = PassManagerReport()
        for name in self.topological_order():
            if not self._enabled.get(name, True):
                rep.skipped_passes += 1
                continue
            try:
                self._passes[name].run(ctx)
                rep.successful_passes += 1
                if self._listener: self._listener(name)
            except Exception:
                rep.failed_passes += 1
        return rep


# ============================================================
# pattern_recognition.rs
# ============================================================
class ObfuscationPattern:
    XOR = "xor"; PACKING = "packing"; CFG_FLATTENING = "cfg_flattening"
    JUNK_CODE = "junk_code"; OPAQUE_PREDICATE = "opaque_predicate"


class PatternConfidence:
    def __init__(self, base: float = 0.0):
        self.base = base
        self.evidence: List[str] = []

    def with_evidence(self, ev: str) -> "PatternConfidence":
        self.evidence.append(ev)
        self.base = min(1.0, self.base + 0.1)
        return self

    def exceeds(self, threshold: float) -> bool:
        return self.base > threshold


class RecognitionResult:
    def __init__(self):
        self.scores: Dict[str, float] = {}

    def score_for(self, pattern: str) -> float:
        return self.scores.get(pattern, 0.0)

    def patterns_above(self, threshold: float) -> List[str]:
        return [p for p, s in self.scores.items() if s > threshold]

    def dominant_pattern(self) -> Optional[str]:
        if not self.scores: return None
        return max(self.scores.items(), key=lambda kv: kv[1])[0]

    def score_map(self) -> Dict[str, float]:
        return dict(self.scores)


class PatternRecognizer:
    @classmethod
    def new(cls) -> "PatternRecognizer": return cls()

    def recognize(self, data: bytes) -> RecognitionResult:
        r = RecognitionResult()
        h = entropy(data)
        r.scores[ObfuscationPattern.XOR] = max(0.0, (h - 4.0) / 4.0)
        r.scores[ObfuscationPattern.PACKING] = max(0.0, (h - 7.0))
        nops = data.count(b"\x90")
        if data:
            r.scores[ObfuscationPattern.JUNK_CODE] = nops / len(data)
        return r


# ============================================================
# report.rs
# ============================================================
class Finding:
    def __init__(self, name: str = "", severity: int = 0, confidence: float = 0.0,
                 bytes_: int = 0, location: Optional[int] = None):
        self.name = name
        self.severity = severity
        self.confidence = confidence
        self.bytes = bytes_
        self.location = location
        self.meta: Dict[str, Any] = {}

    @classmethod
    def new(cls, name: str, severity: int = 0, confidence: float = 0.0,
            bytes_: int = 0, location: Optional[int] = None) -> "Finding":
        return cls(name, severity, confidence, bytes_, location)

    def with_meta(self, key: str, value: Any) -> "Finding":
        self.meta[key] = value
        return self


class DeobfReportBuilder:
    def __init__(self, binary_name: str):
        self.report = DeobfReport.new(binary_name, 0)

    @classmethod
    def new(cls, binary_name: str) -> "DeobfReportBuilder": return cls(binary_name)

    def add_pass(self, summary: PassSummary) -> "DeobfReportBuilder":
        self.report.add_pass(summary); return self

    def metadata(self, key: str, value: Any) -> "DeobfReportBuilder":
        self.report.metadata[key] = value; return self

    def build(self) -> DeobfReport: return self.report


class PassSummaryBuilder:
    def __init__(self, name: str):
        self.summary = PassSummary.new(name, name)

    @classmethod
    def new(cls, name: str) -> "PassSummaryBuilder": return cls(name)

    def finding(self, f: Finding) -> "PassSummaryBuilder":
        self.summary.findings.append(f); return self

    def build(self) -> PassSummary: return self.summary


if __name__ == "__main__":
    print(entropy(b"AAAA"))
    print(Crc32.checksum(b"123456789"))
    print(Adler32.checksum(b"Wikipedia"))
    print(Rc4.decrypt(b"hello", b"Key"))
