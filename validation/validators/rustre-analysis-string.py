#!/usr/bin/env python3
"""Independent Python validator for rustre-analysis-string crate.

Reimplements the crate's string scanning, decoding, classification, and
similarity logic with pure stdlib (+ optional jellyfish for similarity)
so results can be cross-checked against the Rust implementation.

Usage:
  echo '{"fn":"scan_ascii","args":{"data_b64":"...","base":0,"min_len":4}}' | \
      python rustre-analysis-string.py
  python rustre-analysis-string.py            # run main() self-tests
"""
from __future__ import annotations

import base64
import binascii
import codecs
import ipaddress
import json
import math
import re
import subprocess
import sys
from collections import Counter
from typing import Any


# ---------------------------------------------------------------------------
# Optional dep: jellyfish for jaro/jaro_winkler. Fall back to pure-python.
# ---------------------------------------------------------------------------
def _ensure(pkg: str) -> Any:
    try:
        return __import__(pkg)
    except ImportError:
        subprocess.check_call(
            [sys.executable, "-m", "pip", "install", "--quiet", pkg]
        )
        return __import__(pkg)


# ---------------------------------------------------------------------------
# Tier A: scanners
# ---------------------------------------------------------------------------
def validator_scan_ascii(data: bytes, base: int = 0, min_len: int = 4) -> list[dict]:
    """Find runs of >=min_len printable ASCII bytes (0x20..0x7e)."""
    pat = re.compile(rb"[\x20-\x7e]{%d,}" % min_len)
    out = []
    for m in pat.finditer(data):
        out.append({
            "address": base + m.start(),
            "length": len(m.group()),
            "encoding": "Ascii",
            "value": m.group().decode("ascii"),
        })
    return out


def validator_scan_utf16_le(data: bytes, base: int = 0, min_len: int = 4) -> list[dict]:
    """Find UTF-16LE runs of >=min_len printable chars terminated/delimited."""
    out = []
    i = 0
    n = len(data) - 1
    while i < n:
        j = i
        buf = []
        while j < n - 1:
            lo, hi = data[j], data[j + 1]
            if hi == 0 and 0x20 <= lo <= 0x7e:
                buf.append(chr(lo))
                j += 2
            else:
                break
        if len(buf) >= min_len:
            out.append({
                "address": base + i,
                "length": len(buf),
                "encoding": "Utf16Le",
                "value": "".join(buf),
            })
            i = j
        else:
            i += 1
    return out


def validator_read_cstring(data: bytes, base: int, addr: int, min_len: int = 1) -> dict | None:
    off = addr - base
    if off < 0 or off >= len(data):
        return None
    end = data.find(b"\x00", off)
    if end == -1:
        return None
    raw = data[off:end]
    if len(raw) < min_len:
        return None
    try:
        s = raw.decode("ascii")
    except UnicodeDecodeError:
        return None
    if not all(0x20 <= b <= 0x7e for b in raw):
        return None
    return {"address": addr, "length": len(raw), "encoding": "Ascii", "value": s}


def validator_scan_pascal_strings(data: bytes, base: int = 0, min_len: int = 4) -> list[dict]:
    out = []
    i = 0
    while i < len(data):
        ln = data[i]
        if ln >= min_len and i + 1 + ln <= len(data):
            raw = data[i + 1 : i + 1 + ln]
            if all(0x20 <= b <= 0x7e for b in raw):
                out.append({
                    "address": base + i + 1,
                    "length": ln,
                    "encoding": "Ascii",
                    "value": raw.decode("ascii"),
                })
                i += 1 + ln
                continue
        i += 1
    return out


# ---------------------------------------------------------------------------
# Heuristics / entropy
# ---------------------------------------------------------------------------
def validator_entropy(s: str) -> float:
    b = s.encode("utf-8")
    if not b:
        return 0.0
    c = Counter(b)
    total = len(b)
    return -sum((n / total) * math.log2(n / total) for n in c.values())


def validator_shannon_entropy(s: str) -> float:
    return validator_entropy(s)


# ---------------------------------------------------------------------------
# XOR / encoding decoders
# ---------------------------------------------------------------------------
def validator_xor_decode_single(data: bytes, key: int) -> bytes:
    return bytes(b ^ key for b in data)


def validator_xor_decode_multibyte(data: bytes, key: bytes) -> bytes:
    if not key:
        return data
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))


def validator_detect_xor_key(data: bytes, threshold: float = 0.70) -> int | None:
    """Find single-byte XOR key making >threshold of bytes printable ASCII."""
    if not data:
        return None
    best_key = None
    best_score = threshold
    for k in range(256):
        dec = validator_xor_decode_single(data, k)
        printable = sum(1 for b in dec if 0x20 <= b <= 0x7e or b in (0x09, 0x0a, 0x0d))
        score = printable / len(dec)
        if score > best_score:
            best_score = score
            best_key = k
    return best_key


def validator_base64_decode(s: str) -> bytes | None:
    try:
        # require valid b64 charset
        if not re.fullmatch(r"[A-Za-z0-9+/=\s]+", s):
            return None
        return base64.b64decode(s, validate=True)
    except (binascii.Error, ValueError):
        return None


def validator_hex_decode(s: str) -> bytes | None:
    s2 = s.strip().replace(" ", "").replace("\n", "")
    if len(s2) % 2 != 0 or not re.fullmatch(r"[0-9a-fA-F]+", s2):
        return None
    return bytes.fromhex(s2)


def validator_rot_byte(b: int, n: int) -> int:
    if 0x41 <= b <= 0x5a:
        return (b - 0x41 + n) % 26 + 0x41
    if 0x61 <= b <= 0x7a:
        return (b - 0x61 + n) % 26 + 0x61
    return b


def validator_rot_decode(s: str, n: int) -> str:
    return "".join(chr(validator_rot_byte(ord(c), n)) for c in s)


def validator_rot13_decode(s: str) -> str:
    return codecs.encode(s, "rot_13")


# ---------------------------------------------------------------------------
# Classification
# ---------------------------------------------------------------------------
_URL_RE = re.compile(r"\bhttps?://[^\s\"'<>]+", re.IGNORECASE)
_IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
_FMT_RE = re.compile(r"%[-+ 0#]?\d*(?:\.\d+)?[hlLjzt]*[diouxXeEfgGaAcspn%]")


def validator_extract_urls(s: str) -> list[str]:
    return _URL_RE.findall(s)


def validator_extract_ips(s: str) -> list[str]:
    out = []
    for m in _IP_RE.findall(s):
        try:
            ipaddress.IPv4Address(m)
            out.append(m)
        except ValueError:
            pass
    return out


def validator_extract_emails(s: str) -> list[str]:
    return _EMAIL_RE.findall(s)


def validator_extract_format_strings(s: str) -> list[str]:
    return _FMT_RE.findall(s)


def validator_parse_ipv4(s: str) -> list[int] | None:
    try:
        ip = ipaddress.IPv4Address(s)
    except ValueError:
        return None
    return list(ip.packed)


def validator_is_private_ipv4(s: str) -> bool:
    try:
        return ipaddress.IPv4Address(s).is_private
    except ValueError:
        return False


def validator_looks_like_base64(s: str) -> bool:
    if len(s) < 4 or len(s) % 4 != 0:
        return False
    return bool(re.fullmatch(r"[A-Za-z0-9+/]+=*", s))


def validator_looks_like_hex(s: str) -> bool:
    return len(s) >= 4 and len(s) % 2 == 0 and bool(re.fullmatch(r"[0-9a-fA-F]+", s))


# ---------------------------------------------------------------------------
# Similarity
# ---------------------------------------------------------------------------
def validator_levenshtein(a: str, b: str) -> int:
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i] + [0] * len(b)
        for j, cb in enumerate(b, 1):
            cur[j] = min(
                prev[j] + 1,
                cur[j - 1] + 1,
                prev[j - 1] + (ca != cb),
            )
        prev = cur
    return prev[-1]


def validator_levenshtein_similarity(a: str, b: str) -> float:
    m = max(len(a), len(b))
    if m == 0:
        return 1.0
    return 1.0 - validator_levenshtein(a, b) / m


def validator_lcs_length(a: str, b: str) -> int:
    if not a or not b:
        return 0
    prev = [0] * (len(b) + 1)
    for ca in a:
        cur = [0] * (len(b) + 1)
        for j, cb in enumerate(b, 1):
            if ca == cb:
                cur[j] = prev[j - 1] + 1
            else:
                cur[j] = max(prev[j], cur[j - 1])
        prev = cur
    return prev[-1]


def validator_lcs_similarity(a: str, b: str) -> float:
    m = max(len(a), len(b))
    if m == 0:
        return 1.0
    return validator_lcs_length(a, b) / m


def validator_ngrams(s: str, n: int) -> list[str]:
    if len(s) < n:
        return []
    return [s[i : i + n] for i in range(len(s) - n + 1)]


def validator_jaccard_ngram(a: str, b: str, n: int) -> float:
    A, B = set(validator_ngrams(a, n)), set(validator_ngrams(b, n))
    if not A and not B:
        return 1.0
    return len(A & B) / len(A | B)


def validator_jaro(a: str, b: str) -> float:
    jf = _ensure("jellyfish")
    return jf.jaro_similarity(a, b)


def validator_jaro_winkler(a: str, b: str) -> float:
    jf = _ensure("jellyfish")
    return jf.jaro_winkler_similarity(a, b)


# ---------------------------------------------------------------------------
# Dispatcher
# ---------------------------------------------------------------------------
FUNCTIONS = {
    "scan_ascii": lambda a: validator_scan_ascii(
        base64.b64decode(a["data_b64"]), a.get("base", 0), a.get("min_len", 4)
    ),
    "scan_utf16_le": lambda a: validator_scan_utf16_le(
        base64.b64decode(a["data_b64"]), a.get("base", 0), a.get("min_len", 4)
    ),
    "read_cstring": lambda a: validator_read_cstring(
        base64.b64decode(a["data_b64"]), a.get("base", 0), a["addr"], a.get("min_len", 1)
    ),
    "scan_pascal_strings": lambda a: validator_scan_pascal_strings(
        base64.b64decode(a["data_b64"]), a.get("base", 0), a.get("min_len", 4)
    ),
    "entropy": lambda a: validator_entropy(a["s"]),
    "shannon_entropy": lambda a: validator_shannon_entropy(a["s"]),
    "xor_decode_single": lambda a: base64.b64encode(
        validator_xor_decode_single(base64.b64decode(a["data_b64"]), a["key"])
    ).decode(),
    "xor_decode_multibyte": lambda a: base64.b64encode(
        validator_xor_decode_multibyte(
            base64.b64decode(a["data_b64"]), bytes(a["key"])
        )
    ).decode(),
    "detect_xor_key": lambda a: validator_detect_xor_key(
        base64.b64decode(a["data_b64"]), a.get("threshold", 0.70)
    ),
    "base64_decode": lambda a: (
        base64.b64encode(validator_base64_decode(a["s"])).decode()
        if validator_base64_decode(a["s"]) is not None
        else None
    ),
    "hex_decode": lambda a: (
        base64.b64encode(validator_hex_decode(a["s"])).decode()
        if validator_hex_decode(a["s"]) is not None
        else None
    ),
    "rot_decode": lambda a: validator_rot_decode(a["s"], a["n"]),
    "rot13_decode": lambda a: validator_rot13_decode(a["s"]),
    "extract_urls": lambda a: validator_extract_urls(a["s"]),
    "extract_ips": lambda a: validator_extract_ips(a["s"]),
    "extract_emails": lambda a: validator_extract_emails(a["s"]),
    "extract_format_strings": lambda a: validator_extract_format_strings(a["s"]),
    "parse_ipv4": lambda a: validator_parse_ipv4(a["s"]),
    "is_private_ipv4": lambda a: validator_is_private_ipv4(a["s"]),
    "looks_like_base64": lambda a: validator_looks_like_base64(a["s"]),
    "looks_like_hex": lambda a: validator_looks_like_hex(a["s"]),
    "levenshtein": lambda a: validator_levenshtein(a["a"], a["b"]),
    "levenshtein_similarity": lambda a: validator_levenshtein_similarity(a["a"], a["b"]),
    "lcs_length": lambda a: validator_lcs_length(a["a"], a["b"]),
    "lcs_similarity": lambda a: validator_lcs_similarity(a["a"], a["b"]),
    "ngrams": lambda a: validator_ngrams(a["s"], a["n"]),
    "jaccard_ngram": lambda a: validator_jaccard_ngram(a["a"], a["b"], a["n"]),
    "jaro": lambda a: validator_jaro(a["a"], a["b"]),
    "jaro_winkler": lambda a: validator_jaro_winkler(a["a"], a["b"]),
}


def main() -> None:
    # If stdin has data, dispatch a single call.
    if not sys.stdin.isatty():
        raw = sys.stdin.read().strip()
        if raw:
            req = json.loads(raw)
            fn = req["fn"]
            if fn not in FUNCTIONS:
                json.dump({"error": f"unknown fn: {fn}"}, sys.stdout)
                return
            try:
                result = FUNCTIONS[fn](req.get("args", {}))
                json.dump({"fn": fn, "result": result}, sys.stdout)
            except Exception as e:  # noqa: BLE001
                json.dump({"fn": fn, "error": str(e)}, sys.stdout)
            return

    # Otherwise run built-in self-tests.
    buf = b"hello\x00world is here\x00\x01\x02foobar1234"
    print("scan_ascii:", validator_scan_ascii(buf, 0x1000, 4))
    print("read_cstring@0x1006:", validator_read_cstring(buf, 0x1000, 0x1006))
    print(
        "scan_utf16_le:",
        validator_scan_utf16_le("hello world".encode("utf-16-le"), 0x2000, 4),
    )
    print("scan_pascal:", validator_scan_pascal_strings(b"\x05hello\x06world!", 0))
    print("entropy('aaaa') =", validator_entropy("aaaa"))
    print("entropy('ab')   =", validator_entropy("ab"))

    key = 0x42
    plain = b"The quick brown fox jumps over the lazy dog 0123456789"
    cipher = validator_xor_decode_single(plain, key)
    print("detect_xor_key:", hex(validator_detect_xor_key(cipher) or 0), "expected", hex(key))

    print("base64_decode('aGVsbG8='):", validator_base64_decode("aGVsbG8="))
    print("hex_decode('deadbeef'):", validator_hex_decode("deadbeef"))
    print("rot13('hello'):", validator_rot13_decode("hello"))
    print("levenshtein('kitten','sitting'):", validator_levenshtein("kitten", "sitting"))
    print("lcs_length('ABCBDAB','BDCAB'):", validator_lcs_length("ABCBDAB", "BDCAB"))
    print("extract_urls:", validator_extract_urls("see https://x.example.com/a and http://y.io"))
    print("extract_ips:", validator_extract_ips("10.0.0.1 and 999.1.1.1 and 8.8.8.8"))
    print("is_private_ipv4('10.0.0.1'):", validator_is_private_ipv4("10.0.0.1"))
    print("jaro_winkler('martha','marhta'):", validator_jaro_winkler("martha", "marhta"))


if __name__ == "__main__":
    main()
