#!/usr/bin/env python3
"""
Independent Python validator for crate `rustre-crypto-id`.

Reimplements the crate's testable functions using only Python stdlib + well-known
crypto libraries (hashlib, zlib). No Rust import, no MCP calls.

Each validator_<name>(input) returns a dict mirroring the expected Rust output
so the test harness can cross-check the Rust crate against an independent oracle.

CLI:
    - `python rustre-crypto-id.py`               -> runs main() with fixed inputs
    - `python rustre-crypto-id.py --stdin`       -> reads JSON from stdin: {func, input}
                                                    returns JSON: {output}
"""
from __future__ import annotations

import hashlib
import json
import math
import os
import struct
import subprocess
import sys
import zlib
from typing import Any


# ---------------------------------------------------------------------------
# Auto-install optional deps
# ---------------------------------------------------------------------------
def _ensure(pkg: str, import_name: str | None = None) -> Any:
    name = import_name or pkg
    try:
        return __import__(name)
    except ImportError:
        subprocess.check_call(
            [sys.executable, "-m", "pip", "install", "--quiet", pkg],
            stdout=subprocess.DEVNULL,
        )
        return __import__(name)


# ---------------------------------------------------------------------------
# Reference crypto constants (independently sourced from FIPS/RFC specs)
# ---------------------------------------------------------------------------

# FIPS 197 — AES Rijndael S-box
AES_SBOX = bytes([
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16,
])

# FIPS 197 — Inverse S-box
AES_INV_SBOX = bytes(_inv := [0]*256)
for i, v in enumerate(AES_SBOX):
    _inv[v] = i
AES_INV_SBOX = bytes(_inv)

# FIPS 180-4 — SHA-256 initial hash values (H0..H7)
SHA256_H = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
]

# FIPS 180-4 — SHA-256 K constants (first 32 bits of cube roots of first 64 primes)
SHA256_K = [
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2,
]

# RFC 3174 — SHA-1 IVs
SHA1_H = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0]

# RFC 1321 — MD5 IVs
MD5_H = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476]

# CRC32 reversed polynomial (ISO-HDLC / IEEE 802.3)
CRC32_POLY = 0xEDB88320


def _u32_be(words: list[int]) -> bytes:
    return b"".join(struct.pack(">I", w) for w in words)


def _u32_le(words: list[int]) -> bytes:
    return b"".join(struct.pack("<I", w) for w in words)


def _build_crc32_table() -> bytes:
    out = bytearray()
    for n in range(256):
        c = n
        for _ in range(8):
            c = (c >> 1) ^ CRC32_POLY if (c & 1) else (c >> 1)
        out += struct.pack("<I", c & 0xFFFFFFFF)
    return bytes(out)


CRC32_TABLE = _build_crc32_table()


# Map of (name, algorithm, bytes) used by BinaryScanner::scan
_SIGNATURES = [
    ("AES-SBOX",       "Aes128",   AES_SBOX),
    ("AES-INV-SBOX",   "Aes128",   AES_INV_SBOX),
    ("SHA256-H",       "Sha256",   _u32_be(SHA256_H)),
    ("SHA256-K",       "Sha256",   _u32_be(SHA256_K)),
    ("SHA1-H",         "Sha1",     _u32_be(SHA1_H)),
    ("MD5-H",          "Md5",      _u32_le(MD5_H)),
    ("CRC32-TABLE",    "Crc32",    CRC32_TABLE),
]


# ---------------------------------------------------------------------------
# Validators
# ---------------------------------------------------------------------------

def validator_shannon_entropy(data: bytes) -> float:
    """Mirror of rustre-crypto-id::shannon_entropy — Shannon entropy in bits/byte."""
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    n = len(data)
    h = 0.0
    for c in counts:
        if c:
            p = c / n
            h -= p * math.log2(p)
    return h


def validator_binary_scanner_scan(data: bytes) -> list[dict]:
    """Mirror of BinaryScanner::scan — linear search for known constants."""
    hits = []
    for name, algo, sig in _SIGNATURES:
        if len(sig) > len(data):
            continue
        # naive search across all offsets
        idx = 0
        while True:
            off = data.find(sig, idx)
            if off < 0:
                break
            # confidence scaled by constant size (saturates around 0.95)
            conf = min(0.95, 0.5 + len(sig) / 2048.0)
            hits.append({
                "offset": off,
                "algorithm": algo,
                "constant_name": name,
                "confidence": conf,
            })
            idx = off + 1
    return hits


def validator_scan_for_aes_sbox(data: bytes) -> list[int]:
    return _find_all(data, AES_SBOX)


def validator_scan_for_sha256_constants(data: bytes) -> list[int]:
    return _find_all(data, _u32_be(SHA256_K))


def validator_scan_for_sha256_init(data: bytes) -> list[int]:
    return _find_all(data, _u32_be(SHA256_H))


def validator_scan_for_sha1_init(data: bytes) -> list[int]:
    return _find_all(data, _u32_be(SHA1_H))


def validator_scan_for_md5_init(data: bytes) -> list[int]:
    return _find_all(data, _u32_le(MD5_H))


def validator_scan_for_crc32_table(data: bytes) -> list[int]:
    return _find_all(data, CRC32_TABLE)


def _find_all(haystack: bytes, needle: bytes) -> list[int]:
    out: list[int] = []
    if not needle or len(needle) > len(haystack):
        return out
    i = 0
    while True:
        off = haystack.find(needle, i)
        if off < 0:
            return out
        out.append(off)
        i = off + 1


def validator_full_scan(data: bytes) -> dict:
    """Mirror of CryptoScanner::full_scan."""
    if len(data) < 4:
        return {"error": "TooShort"}
    hits = validator_binary_scanner_scan(data)
    algorithms_found = sorted({h["algorithm"] for h in hits})
    # find 16/24/32-byte windows with entropy > 0.9 (normalized to [0,1] -> 0.9*8=7.2 bits)
    possible_keys: list[dict] = []
    for klen in (16, 24, 32):
        for off in range(0, len(data) - klen + 1):
            window = data[off:off + klen]
            e = validator_shannon_entropy(window)
            if e > 7.2:  # > 0.9 normalized
                possible_keys.append({"offset": off, "length": klen, "entropy": e})
    return {
        "algorithms_found": algorithms_found,
        "possible_keys_count": len(possible_keys),
        "hits": hits,
    }


def validator_combined_confidence(probs: list[float]) -> float:
    """1 - Π(1-p), clamped to 0.99."""
    prod = 1.0
    for p in probs:
        prod *= (1.0 - p)
    return min(0.99, 1.0 - prod)


def validator_function_scanner_analyze(code: bytes) -> dict:
    """Heuristic opcode counting mirroring FunctionScanner::analyze."""
    xor_count = sum(1 for b in code if b in (0x31, 0x33))
    rol_count = sum(1 for b in code if b == 0xC1)  # approximation
    xchg_count = sum(1 for b in code if b in (0x86, 0x87))
    mul_count = sum(1 for b in code if b == 0xF7)  # approximation
    hits = []
    if xor_count >= 8 and rol_count >= 4:
        hits.append("ChaCha20")
    if xchg_count >= 4:
        hits.append("RC4")
    if mul_count >= 8:
        hits.append("RSA")
    return {
        "xor": xor_count, "rol": rol_count, "xchg": xchg_count, "mul": mul_count,
        "hits": hits,
    }


def validator_builtin_test_vectors() -> dict:
    """Independently verify the BUILTIN_TEST_VECTORS using stdlib."""
    results = {}
    # SHA-256 of ""
    results["sha256_empty"] = hashlib.sha256(b"").hexdigest()
    # SHA-256 of "abc"
    results["sha256_abc"] = hashlib.sha256(b"abc").hexdigest()
    # MD5 of ""
    results["md5_empty"] = hashlib.md5(b"").hexdigest()
    # CRC32 of "hello world"
    results["crc32_hello_world"] = format(zlib.crc32(b"hello world") & 0xFFFFFFFF, "08x")
    # AES-128-ECB FIPS-197 Appx B: key/plaintext/ciphertext (verify constants exist)
    results["aes128_fips197_appxB_known"] = {
        "key":        "000102030405060708090a0b0c0d0e0f",
        "plaintext":  "00112233445566778899aabbccddeeff",
        "ciphertext": "69c4e0d86a7b0430d8cdb78070b4c55a",
    }
    return results


# ---------------------------------------------------------------------------
# Dispatch
# ---------------------------------------------------------------------------

DISPATCH = {
    "shannon_entropy":           lambda i: validator_shannon_entropy(bytes(i)),
    "binary_scanner_scan":       lambda i: validator_binary_scanner_scan(bytes(i)),
    "scan_for_aes_sbox":         lambda i: validator_scan_for_aes_sbox(bytes(i)),
    "scan_for_sha256_constants": lambda i: validator_scan_for_sha256_constants(bytes(i)),
    "scan_for_sha256_init":      lambda i: validator_scan_for_sha256_init(bytes(i)),
    "scan_for_sha1_init":        lambda i: validator_scan_for_sha1_init(bytes(i)),
    "scan_for_md5_init":         lambda i: validator_scan_for_md5_init(bytes(i)),
    "scan_for_crc32_table":      lambda i: validator_scan_for_crc32_table(bytes(i)),
    "full_scan":                 lambda i: validator_full_scan(bytes(i)),
    "combined_confidence":       lambda i: validator_combined_confidence(list(i)),
    "function_scanner_analyze":  lambda i: validator_function_scanner_analyze(bytes(i)),
    "builtin_test_vectors":      lambda i: validator_builtin_test_vectors(),
}


def main_stdin() -> None:
    req = json.loads(sys.stdin.read())
    func = req["func"]
    inp = req.get("input", [])
    if func not in DISPATCH:
        print(json.dumps({"error": f"unknown function {func}"}))
        return
    out = DISPATCH[func](inp)
    print(json.dumps({"output": out}))


def main() -> None:
    # Fixed-input self-test
    rng = os.urandom(4096)
    zeros = bytes(1024)

    # Embed AES S-box at offset 1000 inside random buffer
    buf = bytearray(rng)
    buf[1000:1000 + 256] = AES_SBOX
    buf = bytes(buf)

    report = {
        "shannon_entropy_zeros":   validator_shannon_entropy(zeros),
        "shannon_entropy_random":  validator_shannon_entropy(rng),
        "aes_sbox_at_1000":        validator_scan_for_aes_sbox(buf),
        "binary_scan_aes":         [h for h in validator_binary_scanner_scan(buf)
                                    if h["constant_name"] == "AES-SBOX"],
        "full_scan_too_short":     validator_full_scan(b"\x01\x02\x03"),
        "full_scan_zero_buffer":   {
            "algorithms_found": validator_full_scan(zeros)["algorithms_found"],
            "possible_keys_count": validator_full_scan(zeros)["possible_keys_count"],
        },
        "combined_confidence_two_095": validator_combined_confidence([0.95, 0.95]),
        "builtin_test_vectors":    validator_builtin_test_vectors(),
    }
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    if "--stdin" in sys.argv:
        main_stdin()
    else:
        main()
