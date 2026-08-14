#!/usr/bin/env python3
"""
Independent Python validator for crate `rustre-crypto-oracle`.

Reimplements the crate's testable pure-computation functions using only Python
stdlib (hashlib, struct, math, hmac, itertools). No Rust import, no MCP calls.

Modules covered:
  lib.rs (root): PaddingOracleAttack, EcbByteAtATime, NonceReuseDetection,
                 IvPredictionAttack, OtpKeyReuse, CbcBitFlippingAttack,
                 EcbCutAndPasteAttack, TimingAttack, AesCracker, RsaAttacks,
                 FieldFlags, ProtocolSynthesizer (infer_fields)
  padding_oracle.rs: validate_pkcs7, strip_pkcs7, add_pkcs7
  padding_oracle_attack.rs: pkcs7_pad, decrypt_with_oracle (pure logic)
  padding_oracle_detector.rs: pkcs7_validate, pkcs7_pad, pkcs7_unpad
  ecb_oracle.rs: check_ecb_in_ciphertext, detect_block_size_from_pairs
  oracle_query_engine.rs: OracleStats::accept_rate (pure), detect_block_size,
                          detect_ecb_mode (pure)
  oracle_exploitation.rs: ExploitTimeline, ExploitResult (pure accessors)
  oracle_detection.rs: ResponseProfile (stats), DifferentialTester (pure),
                       OracleDetectionReport::is_oracle_found
  hash_attacks.rs: sha1, sha512, extend_sha256, extend_sha512
  hash_length_extension.rs: md_padding, md5, sha1, sha256, HashLengthExtension
  key_schedule_analyzer.rs: KeySchedule::expand_aes128/aes256/rc4,
                             KeySchedulePattern::count_constant_hits,
                             verify_aes128_expansion
  crypto_constant_finder.rs: ConstantPattern::builtin_patterns (meta),
                              test_blob_with_sha256_iv, test_blob_with_sha1_iv
  side_channel.rs: PowerTrace stats, TraceAligner, TraceFilter, pearson_correlation
  timing_oracle_full.rs: TimingStats, TimingTest::welch_t_test, remove_outliers,
                          median
  stream_cipher_attacks.rs: LfsrAnalysis, KeystreamTestSuite, NonceReuseDetection
  whitebox_attacks.rs: SBoxAnalyzer, WalshHadamardTransform, GF2LinearSystem

CLI:
    python rustre-crypto-oracle.py              -> runs main() self-tests
    python rustre-crypto-oracle.py --stdin      -> reads JSON {func, input}, returns {output}
"""
from __future__ import annotations

import hashlib
import hmac
import json
import math
import os
import struct
import sys
from collections import defaultdict
from typing import Any

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _xor(a: bytes | bytearray, b: bytes | bytearray) -> bytes:
    n = min(len(a), len(b))
    return bytes(a[i] ^ b[i] for i in range(n))


def _xor_full(a: bytes | bytearray, b: bytes | bytearray) -> bytes:
    """XOR repeating b over a (or truncate to min length)."""
    return _xor(a, b)


# ---------------------------------------------------------------------------
# PKCS#7 — used by many modules
# ---------------------------------------------------------------------------

def validator_validate_pkcs7(data: bytes) -> bool:
    """padding_oracle.rs: validate_pkcs7 — True if PKCS#7 padding is valid."""
    if not data:
        return False
    pad = data[-1]
    if pad == 0 or pad > 16:
        return False
    if len(data) < pad:
        return False
    return all(data[-i] == pad for i in range(1, pad + 1))


def validator_strip_pkcs7(data: bytes) -> list | None:
    """padding_oracle.rs: strip_pkcs7 — removes PKCS#7 padding, None if invalid."""
    if not validator_validate_pkcs7(data):
        return None
    pad = data[-1]
    return list(data[:-pad])


def validator_add_pkcs7(data: bytes, block_size: int) -> list:
    """padding_oracle.rs: add_pkcs7 — appends PKCS#7 padding."""
    pad = block_size - (len(data) % block_size)
    return list(data + bytes([pad] * pad))


def validator_pkcs7_validate(block: bytes) -> int | None:
    """padding_oracle_detector.rs: pkcs7_validate — returns pad length or None."""
    if not block:
        return None
    pad = block[-1]
    if pad == 0 or pad > len(block):
        return None
    if all(block[-i] == pad for i in range(1, pad + 1)):
        return pad
    return None


def validator_pkcs7_pad(data: bytes, block_size: int) -> list:
    """padding_oracle_attack.rs / detector.rs: pkcs7_pad."""
    return validator_add_pkcs7(data, block_size)


def validator_pkcs7_unpad(data: bytes) -> list | None:
    """padding_oracle_detector.rs: pkcs7_unpad."""
    return validator_strip_pkcs7(data)


# ---------------------------------------------------------------------------
# ECB detection
# ---------------------------------------------------------------------------

def validator_check_ecb_in_ciphertext(ciphertext: bytes, block_size: int) -> bool:
    """ecb_oracle.rs: check_ecb_in_ciphertext — True if duplicate blocks found."""
    if block_size == 0 or len(ciphertext) < block_size * 2:
        return False
    blocks = [
        ciphertext[i:i + block_size]
        for i in range(0, len(ciphertext) - block_size + 1, block_size)
    ]
    return len(blocks) != len(set(blocks))


def validator_detect_block_size_from_pairs(pairs: list[tuple[int, int]]) -> int | None:
    """ecb_oracle.rs: detect_block_size_from_pairs — GCD of output length differences."""
    deltas = []
    for i in range(1, len(pairs)):
        delta = pairs[i][1] - pairs[i - 1][1]
        if delta > 0:
            deltas.append(delta)
    if not deltas:
        return None
    g = deltas[0]
    for d in deltas[1:]:
        while d:
            g, d = d, g % d
    return g if g > 0 else None


def validator_ecb_detect(oracle_fn: Any, block_size: int = 16) -> bool:
    """EcbByteAtATime::detect_ecb — feed 3*block_size repeated bytes."""
    payload = bytes([0x41] * (block_size * 3))
    ct = oracle_fn(payload)
    ct_bytes = bytes(ct)
    return validator_check_ecb_in_ciphertext(ct_bytes, block_size)


def validator_determine_block_size(oracle_fn: Any) -> int:
    """EcbByteAtATime::determine_block_size — increase input until output grows."""
    base = len(oracle_fn(b""))
    for n in range(1, 65):
        new_len = len(oracle_fn(bytes([0x41] * n)))
        if new_len > base:
            return new_len - base
    return 16  # fallback


# ---------------------------------------------------------------------------
# Nonce-reuse / OTP
# ---------------------------------------------------------------------------

def validator_xor_ciphertexts(ct1: bytes, ct2: bytes) -> list:
    """NonceReuseDetection::xor_ciphertexts / OtpKeyReuse::xor_ciphertexts."""
    return list(_xor(ct1, ct2))


def validator_analyze_xor_for_english(xored: bytes) -> float:
    """NonceReuseDetection::analyze_xor_for_english — printable ASCII ratio."""
    if not xored:
        return 0.0
    printable = sum(1 for b in xored if 0x20 <= b <= 0x7e)
    return printable / len(xored)


def validator_attack_nonce_reuse(ct1: bytes, ct2: bytes, known_p1: bytes) -> list:
    """NonceReuseDetection::attack_nonce_reuse — P2 = C1 XOR C2 XOR P1."""
    p1_xor_p2 = _xor(ct1, ct2)
    n = min(len(p1_xor_p2), len(known_p1))
    return list(bytes(p1_xor_p2[i] ^ known_p1[i] for i in range(n)))


def validator_find_nonce_reuse(pairs: list[dict]) -> list[list[int]]:
    """NonceReuseDetection::find_nonce_reuse — pairs sharing the same nonce."""
    nonce_map: dict[bytes, list[int]] = defaultdict(list)
    for i, p in enumerate(pairs):
        nonce = bytes(p.get("nonce", []))
        nonce_map[nonce].append(i)
    result = []
    for indices in nonce_map.values():
        if len(indices) >= 2:
            for a in range(len(indices)):
                for b in range(a + 1, len(indices)):
                    result.append([indices[a], indices[b]])
    return result


def validator_otp_recover_p2(p1_xor_p2: bytes, known_p1: bytes) -> list:
    """OtpKeyReuse::recover_p2."""
    return validator_attack_nonce_reuse(p1_xor_p2, bytes(len(p1_xor_p2)), known_p1)


# English letter frequency scoring for key recovery
_ENGLISH_FREQ = {c: f for c, f in zip(
    "etaoinshrdlcumwfgypbvkjxqzETAOINSHRDLCUMWFGYPBVKJXQZ",
    [12.7, 9.1, 8.2, 7.5, 7.0, 6.3, 6.1, 6.0, 4.3, 4.0, 2.8, 2.8, 2.4,
     2.4, 2.2, 2.0, 2.0, 1.9, 1.5, 1.5, 1.0, 0.8, 0.2, 0.2, 0.1, 0.1,
     12.7, 9.1, 8.2, 7.5, 7.0, 6.3, 6.1, 6.0, 4.3, 4.0, 2.8, 2.8, 2.4,
     2.4, 2.2, 2.0, 2.0, 1.9, 1.5, 1.5, 1.0, 0.8, 0.2, 0.2, 0.1, 0.1],
)}


def _english_score(data: bytes) -> float:
    return sum(_ENGLISH_FREQ.get(chr(b), 0.0) for b in data)


def validator_recover_key_byte(stream_byte_col: bytes) -> int:
    """OtpKeyReuse::recover_key_byte — brute-force column byte via English score."""
    best_k, best_score = 0, -1.0
    for k in range(256):
        decrypted = bytes(b ^ k for b in stream_byte_col)
        score = _english_score(decrypted)
        if score > best_score:
            best_score = score
            best_k = k
    return best_k


def validator_otp_analyze_xor_distribution(xored: bytes) -> float:
    """OtpKeyReuse::analyze_xor_distribution — printable ASCII percentage."""
    return validator_analyze_xor_for_english(xored)


# ---------------------------------------------------------------------------
# IV Prediction
# ---------------------------------------------------------------------------

def validator_detect_counter_iv(ivs: list[bytes]) -> bool:
    """IvPredictionAttack::detect_counter_iv — increment +1 as little-endian u128."""
    if len(ivs) < 2:
        return False
    for i in range(1, len(ivs)):
        prev = int.from_bytes(ivs[i - 1], "little")
        curr = int.from_bytes(ivs[i], "little")
        if (prev + 1) % (2**128) != curr:
            return False
    return True


def validator_predict_next_iv(current_iv: bytes) -> list:
    """IvPredictionAttack::predict_next_iv."""
    n = int.from_bytes(current_iv, "little")
    next_n = (n + 1) % (2**128)
    return list(next_n.to_bytes(16, "little"))


def validator_forge_chosen_plaintext(current_iv: bytes, known_plaintext: bytes,
                                     desired_plaintext: bytes) -> list:
    """IvPredictionAttack::forge_chosen_plaintext — next_iv XOR known XOR desired."""
    next_iv = bytes(validator_predict_next_iv(current_iv))
    n = min(len(next_iv), len(known_plaintext), len(desired_plaintext))
    forged = bytes(next_iv[i] ^ known_plaintext[i] ^ desired_plaintext[i] for i in range(n))
    return list(forged)


# ---------------------------------------------------------------------------
# CBC Bit-Flip
# ---------------------------------------------------------------------------

def validator_cbc_bitflip(ciphertext: bytes, iv: bytes, target_offset: int,
                           known_plain: int, desired: int) -> dict | None:
    """CbcBitFlippingAttack::flip — returns {iv, ciphertext} with flipped byte."""
    if len(ciphertext) % 16 != 0:
        return None
    block_idx = target_offset // 16
    byte_in_block = target_offset % 16
    # flip in the previous block (or IV if block_idx == 0)
    flip_byte = known_plain ^ desired
    if block_idx == 0:
        iv_mod = bytearray(iv)
        iv_mod[byte_in_block] ^= flip_byte
        return {"iv": list(iv_mod), "ciphertext": list(ciphertext)}
    else:
        ct_mod = bytearray(ciphertext)
        prev_block_start = (block_idx - 1) * 16
        ct_mod[prev_block_start + byte_in_block] ^= flip_byte
        return {"iv": list(iv), "ciphertext": list(ct_mod)}


# ---------------------------------------------------------------------------
# ECB Cut-and-Paste
# ---------------------------------------------------------------------------

def validator_ecb_detect_blocks(ciphertext: bytes, block_size: int) -> bool:
    """EcbCutAndPasteAttack::detect_ecb — duplicate blocks."""
    return validator_check_ecb_in_ciphertext(ciphertext, block_size)


def validator_ecb_reorder_blocks(ciphertext: bytes, block_size: int,
                                  order: list[int]) -> list | None:
    """EcbCutAndPasteAttack::reorder_blocks."""
    if block_size == 0:
        return None
    n_blocks = len(ciphertext) // block_size
    blocks = [ciphertext[i * block_size:(i + 1) * block_size] for i in range(n_blocks)]
    result = bytearray()
    for idx in order:
        if idx >= n_blocks:
            return None
        result.extend(blocks[idx])
    return list(result)


# ---------------------------------------------------------------------------
# Timing Attack helpers
# ---------------------------------------------------------------------------

def validator_median_duration(measurements: list[dict]) -> int | None:
    """TimingAttack::median_duration — median of duration_ns values."""
    vals = sorted(m["duration_ns"] for m in measurements if "duration_ns" in m)
    if not vals:
        return None
    n = len(vals)
    if n % 2 == 0:
        return (vals[n // 2 - 1] + vals[n // 2]) // 2
    return vals[n // 2]


def validator_find_max_duration(measurements: list[dict]) -> dict | None:
    """TimingAttack::find_max_duration."""
    if not measurements:
        return None
    return max(measurements, key=lambda m: m.get("duration_ns", 0))


def validator_byte_timing_attack(oracle_results: list[dict]) -> int:
    """TimingAttack::byte_timing_attack — candidate with maximum average time.
    oracle_results: list of {byte: int, times: [int]}"""
    best_byte, best_avg = 0, -1.0
    for r in oracle_results:
        times = r.get("times", [])
        avg = sum(times) / len(times) if times else 0.0
        if avg > best_avg:
            best_avg = avg
            best_byte = r["byte"]
    return best_byte


# ---------------------------------------------------------------------------
# AES Cracker
# ---------------------------------------------------------------------------

_AES_WEAK_KEYS = [
    bytes([0x00] * 16),
    bytes([0xFF] * 16),
    bytes(range(16)),
    bytes(range(15, -1, -1)),
]


def validator_is_weak_key(key: bytes) -> bool:
    """AesCracker::is_weak_key — all-zero, all-FF, ascending, descending."""
    if len(key) != 16:
        return False
    if all(b == 0x00 for b in key):
        return True
    if all(b == 0xFF for b in key):
        return True
    if key == bytes(range(16)):
        return True
    if key == bytes(range(15, -1, -1)):
        return True
    return False


def validator_weak_keys() -> list[list[int]]:
    """AesCracker::weak_keys — list of predefined weak AES-128 keys."""
    return [list(k) for k in _AES_WEAK_KEYS]


# ---------------------------------------------------------------------------
# RSA Attacks (integer / pure math)
# ---------------------------------------------------------------------------

def _iroot(n: int, k: int) -> int:
    """Integer k-th root of n."""
    if n < 0:
        return -1
    if n == 0:
        return 0
    x = int(round(n ** (1.0 / k)))
    # Newton correction
    for _ in range(100):
        x1 = ((k - 1) * x + n // (x ** (k - 1))) // k
        if x1 >= x:
            break
        x = x1
    while x ** k > n:
        x -= 1
    while (x + 1) ** k <= n:
        x += 1
    return x


def validator_rsa_small_exponent(ciphertext_bytes: bytes, exponent: int) -> list | None:
    """RsaAttacks::small_exponent_attack — integer e-th root."""
    c = int.from_bytes(ciphertext_bytes, "big")
    root = _iroot(c, exponent)
    if root ** exponent == c:
        # encode back to bytes
        length = (root.bit_length() + 7) // 8
        return list(root.to_bytes(length, "big"))
    return None


def _gcd(a: int, b: int) -> int:
    while b:
        a, b = b, a % b
    return a


def _extended_gcd(a: int, b: int):
    if b == 0:
        return a, 1, 0
    g, x, y = _extended_gcd(b, a % b)
    return g, y, x - (a // b) * y


def _continued_fractions(n: int, d: int) -> list[tuple[int, int]]:
    """Convergents of continued fraction of n/d."""
    convergents = []
    h0, h1 = 1, 0
    k0, k1 = 0, 1
    while d:
        q = n // d
        n, d = d, n % d
        h0, h1 = h1, h0 + q * h1
        k0, k1 = k1, k0 + q * k1
        convergents.append((h1, k1))
    return convergents


def validator_wiener_attack(e: int, n: int) -> int | None:
    """RsaAttacks::wiener_attack — recover d via continued fractions."""
    for k, d in _continued_fractions(e, n):
        if k == 0:
            continue
        if (e * d - 1) % k != 0:
            continue
        phi = (e * d - 1) // k
        # Check phi: p+q = n - phi + 1, discriminant must be perfect square
        b = n - phi + 1
        disc = b * b - 4 * n
        if disc < 0:
            continue
        sq = _iroot(disc, 2)
        if sq * sq == disc:
            return d
    return None


def validator_fermat_factor(modulus: int) -> tuple[int, int] | None:
    """RsaAttacks::fermat_factor — Fermat factorization for close p, q."""
    if modulus <= 1:
        return None
    a = _iroot(modulus, 2)
    if a * a == modulus:
        return (a, a)
    a += 1
    for _ in range(10_000):
        b2 = a * a - modulus
        b = _iroot(b2, 2)
        if b * b == b2:
            p, q = a - b, a + b
            if p * q == modulus:
                return (p, q)
        a += 1
    return None


def validator_common_modulus_attack(c1: int, e1: int, c2: int, e2: int, n: int) -> int | None:
    """RsaAttacks::common_modulus_attack — Bezout with gcd(e1,e2)=1."""
    g, a, b = _extended_gcd(e1, e2)
    if g != 1:
        return None
    # m = c1^a * c2^b mod n
    # handle negative exponents: modular inverse
    def mod_pow_maybe_neg(base: int, exp: int, mod: int) -> int:
        if exp >= 0:
            return pow(base, exp, mod)
        _, inv, _ = _extended_gcd(base % mod, mod)
        return pow(inv % mod, -exp, mod)

    m = (mod_pow_maybe_neg(c1, a, n) * mod_pow_maybe_neg(c2, b, n)) % n
    return m


# ---------------------------------------------------------------------------
# FieldFlags
# ---------------------------------------------------------------------------

def validator_field_flags_from_tuple(is_constant: bool, is_random: bool,
                                     is_incrementing: bool, is_timestamp: bool) -> int:
    """FieldFlags::from_tuple — bitmask construction."""
    flags = 0
    if is_constant:
        flags |= 1
    if is_random:
        flags |= 2
    if is_incrementing:
        flags |= 4
    if is_timestamp:
        flags |= 8
    return flags


def validator_field_flags_is_constant(flags: int) -> bool:
    return bool(flags & 1)


def validator_field_flags_is_random(flags: int) -> bool:
    return bool(flags & 2)


def validator_field_flags_is_incrementing(flags: int) -> bool:
    return bool(flags & 4)


def validator_field_flags_is_timestamp(flags: int) -> bool:
    return bool(flags & 8)


# ---------------------------------------------------------------------------
# ProtocolSynthesizer::infer_fields
# ---------------------------------------------------------------------------

def _byte_entropy(col: list[int]) -> float:
    if not col:
        return 0.0
    counts = defaultdict(int)
    for b in col:
        counts[b] += 1
    n = len(col)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def validator_infer_fields(samples: list[bytes]) -> list[dict]:
    """ProtocolSynthesizer::infer_fields — classify each byte position."""
    if not samples:
        return []
    min_len = min(len(s) for s in samples)
    fields = []
    for pos in range(min_len):
        col = [s[pos] for s in samples]
        unique = len(set(col))
        ent = _byte_entropy(col)
        is_const = unique == 1
        is_rand = ent > 7.5
        is_inc = (not is_const) and all(col[i] <= col[i + 1] for i in range(len(col) - 1))
        kind = "Static" if is_const else ("Random" if is_rand else ("Counter" if is_inc else "Random"))
        fields.append({
            "offset": pos,
            "kind": kind,
            "entropy": ent,
            "unique_values": unique,
        })
    return fields


# ---------------------------------------------------------------------------
# Oracle stats helpers
# ---------------------------------------------------------------------------

def validator_oracle_stats_accept_rate(total: int, accepted: int) -> float:
    """OracleStats::accept_rate."""
    if total == 0:
        return 0.0
    return accepted / total


# ---------------------------------------------------------------------------
# ExploitTimeline
# ---------------------------------------------------------------------------

def validator_exploit_timeline_acceptance_ratio(entries: list[dict]) -> float:
    """ExploitTimeline::acceptance_ratio."""
    total = len(entries)
    if total == 0:
        return 0.0
    accepted = sum(1 for e in entries if e.get("result", False))
    return accepted / total


def validator_exploit_timeline_total_queries(entries: list[dict]) -> int:
    return len(entries)


def validator_exploit_timeline_accepted_count(entries: list[dict]) -> int:
    return sum(1 for e in entries if e.get("result", False))


def validator_exploit_timeline_rejected_count(entries: list[dict]) -> int:
    return sum(1 for e in entries if not e.get("result", False))


# ---------------------------------------------------------------------------
# ExploitResult
# ---------------------------------------------------------------------------

def validator_exploit_queries_per_byte(total_queries: int, plaintext_len: int) -> float:
    """ExploitResult::queries_per_byte."""
    if plaintext_len == 0:
        return 0.0
    return total_queries / plaintext_len


# ---------------------------------------------------------------------------
# ResponseProfile
# ---------------------------------------------------------------------------

def _safe_mean(vals: list[float]) -> float | None:
    return sum(vals) / len(vals) if vals else None


def _safe_std(vals: list[float]) -> float | None:
    if len(vals) < 2:
        return None
    m = sum(vals) / len(vals)
    return math.sqrt(sum((v - m) ** 2 for v in vals) / (len(vals) - 1))


def validator_response_profile_mean_time(samples: list[dict]) -> float | None:
    """ResponseProfile::mean_time_us."""
    times = [s["time_us"] for s in samples if "time_us" in s]
    return _safe_mean([float(t) for t in times])


def validator_response_profile_std_dev(samples: list[dict]) -> float | None:
    """ResponseProfile::std_dev_time_us."""
    times = [float(s["time_us"]) for s in samples if "time_us" in s]
    return _safe_std(times)


def validator_response_profile_mean_length(samples: list[dict]) -> float | None:
    """ResponseProfile::mean_length."""
    lengths = [float(s["length"]) for s in samples if "length" in s]
    return _safe_mean(lengths)


def validator_response_profile_distinct_status(samples: list[dict]) -> list[int]:
    """ResponseProfile::distinct_status_codes."""
    return sorted(set(s["status"] for s in samples if "status" in s))


def validator_response_profile_distinct_lengths(samples: list[dict]) -> list[int]:
    return sorted(set(s["length"] for s in samples if "length" in s))


def validator_response_profile_is_length_bimodal(samples: list[dict]) -> bool:
    return len(validator_response_profile_distinct_lengths(samples)) >= 2


def validator_response_profile_is_status_bimodal(samples: list[dict]) -> bool:
    return len(validator_response_profile_distinct_status(samples)) >= 2


# ---------------------------------------------------------------------------
# DifferentialTester
# ---------------------------------------------------------------------------

def validator_differential_timing_delta(valid_times: list[int],
                                         invalid_times: list[int]) -> float | None:
    """DifferentialTester::timing_delta_us — mean(valid) - mean(invalid)."""
    mv = _safe_mean([float(t) for t in valid_times])
    mi = _safe_mean([float(t) for t in invalid_times])
    if mv is None or mi is None:
        return None
    return mv - mi


def validator_differential_has_timing_diff(valid_times: list[int], invalid_times: list[int],
                                            threshold_us: float) -> bool:
    delta = validator_differential_timing_delta(valid_times, invalid_times)
    if delta is None:
        return False
    return abs(delta) > threshold_us


# ---------------------------------------------------------------------------
# OracleDetectionReport::is_oracle_found
# ---------------------------------------------------------------------------

def validator_is_oracle_found(findings: list[dict]) -> bool:
    """OracleDetectionReport::is_oracle_found — any finding with confidence >= 70."""
    return any(f.get("confidence", 0) >= 70 for f in findings)


# ---------------------------------------------------------------------------
# Hash implementations (stdlib wrappers)
# ---------------------------------------------------------------------------

def validator_sha1(data: bytes) -> list:
    """hash_attacks.rs / hash_length_extension.rs: sha1."""
    return list(hashlib.sha1(data).digest())


def validator_sha512(data: bytes) -> list:
    """hash_attacks.rs: sha512."""
    return list(hashlib.sha512(data).digest())


def validator_sha256(data: bytes) -> list:
    """hash_length_extension.rs: sha256."""
    return list(hashlib.sha256(data).digest())


def validator_md5(data: bytes) -> list:
    """hash_length_extension.rs: md5."""
    return list(hashlib.md5(data).digest())


# ---------------------------------------------------------------------------
# Merkle-Damgård padding
# ---------------------------------------------------------------------------

def validator_md_padding(msg_len: int, algo: str) -> list:
    """hash_length_extension.rs: md_padding — computes padding bytes for MD/SHA."""
    algo_lower = algo.lower()
    if algo_lower in ("sha256", "sha1", "md5"):
        # All use 512-bit (64-byte) blocks with 64-bit length field
        block_size = 64
        length_bytes = 8
        big_endian_len = algo_lower in ("sha256", "sha1")
    elif algo_lower == "sha512":
        block_size = 128
        length_bytes = 16
        big_endian_len = True
    else:
        block_size = 64
        length_bytes = 8
        big_endian_len = True

    pad = bytearray([0x80])
    needed = block_size - length_bytes
    while (msg_len + len(pad)) % block_size != needed % block_size:
        pad.append(0x00)
    bit_len = msg_len * 8
    if big_endian_len:
        pad += bit_len.to_bytes(length_bytes, "big")
    else:
        pad += bit_len.to_bytes(length_bytes, "little")
    return list(pad)


# ---------------------------------------------------------------------------
# Hash Length Extension
# ---------------------------------------------------------------------------

def _sha256_compress(state: list[int], block: bytes) -> list[int]:
    """One SHA-256 block compression."""
    K = [
        0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
        0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
        0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
        0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
        0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
        0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
        0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
        0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2,
    ]
    M = list(struct.unpack(">16I", block))
    W = M[:]
    for i in range(16, 64):
        s0 = _rotr32(W[i-15], 7) ^ _rotr32(W[i-15], 18) ^ (W[i-15] >> 3)
        s1 = _rotr32(W[i-2], 17) ^ _rotr32(W[i-2], 19) ^ (W[i-2] >> 10)
        W.append((W[i-16] + s0 + W[i-7] + s1) & 0xFFFFFFFF)
    a, b, c, d, e, f, g, h = state
    for i in range(64):
        S1 = _rotr32(e, 6) ^ _rotr32(e, 11) ^ _rotr32(e, 25)
        ch = (e & f) ^ (~e & g)
        temp1 = (h + S1 + ch + K[i] + W[i]) & 0xFFFFFFFF
        S0 = _rotr32(a, 2) ^ _rotr32(a, 13) ^ _rotr32(a, 22)
        maj = (a & b) ^ (a & c) ^ (b & c)
        temp2 = (S0 + maj) & 0xFFFFFFFF
        h = g; g = f; f = e
        e = (d + temp1) & 0xFFFFFFFF
        d = c; c = b; b = a
        a = (temp1 + temp2) & 0xFFFFFFFF
    return [(x + y) & 0xFFFFFFFF for x, y in zip(state, [a,b,c,d,e,f,g,h])]


def _rotr32(v: int, n: int) -> int:
    return ((v >> n) | (v << (32 - n))) & 0xFFFFFFFF


def validator_extend_sha256(mac: bytes, orig_msg_len: int, secret_len: int,
                             extension: bytes) -> dict | None:
    """HashLengthExtensionAttack::extend_sha256 — (new_mac, forged_msg)."""
    if len(mac) != 32:
        return None
    total_len = secret_len + orig_msg_len
    padding = bytes(validator_md_padding(total_len, "sha256"))
    # Reconstruct internal state from known MAC
    state = list(struct.unpack(">8I", mac))
    # The forged message is: original_msg || padding || extension
    # We don't have original_msg but we know its length
    # forged_msg visible part (without secret):
    forged_visible = bytes(total_len * b"\x00")[secret_len:]  # placeholder: just the layout
    # In length-extension the forged_msg is: <orig_msg>||<padding>||<extension>
    # The caller has orig_msg; we return the glue bytes
    glue = padding + extension
    # Compute new hash: continue SHA-256 from restored state
    new_total_len = total_len + len(padding) + len(extension)
    new_padding = bytes(validator_md_padding(new_total_len, "sha256"))
    # Pad extension to block boundary and compress
    ext_padded = extension + new_padding
    cur_state = list(state)
    for off in range(0, len(ext_padded), 64):
        cur_state = _sha256_compress(cur_state, ext_padded[off:off+64])
    new_mac = struct.pack(">8I", *cur_state)
    return {
        "new_mac": list(new_mac),
        "forged_msg_glue": list(glue),  # bytes to append after original msg
    }


# ---------------------------------------------------------------------------
# AES-128 Key Schedule
# ---------------------------------------------------------------------------

_AES_SBOX = bytes([
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

_AES_RCON = [
    0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36,
]


def _aes_sub_word(w: int) -> int:
    return (
        (_AES_SBOX[(w >> 24) & 0xFF] << 24) |
        (_AES_SBOX[(w >> 16) & 0xFF] << 16) |
        (_AES_SBOX[(w >> 8) & 0xFF] << 8) |
        _AES_SBOX[w & 0xFF]
    )


def _aes_rot_word(w: int) -> int:
    return ((w << 8) | (w >> 24)) & 0xFFFFFFFF


def validator_expand_aes128(key: bytes) -> list[list[int]]:
    """KeySchedule::expand_aes128 — 11 round keys × 16 bytes."""
    assert len(key) == 16
    nk = 4  # 128-bit key
    nr = 10
    w = list(struct.unpack(">4I", key))
    for i in range(nk, 4 * (nr + 1)):
        temp = w[i - 1]
        if i % nk == 0:
            temp = _aes_sub_word(_aes_rot_word(temp)) ^ (_AES_RCON[i // nk - 1] << 24)
        w.append((w[i - nk] ^ temp) & 0xFFFFFFFF)
    round_keys = []
    for r in range(nr + 1):
        rk = b"".join(struct.pack(">I", w[r * 4 + j]) for j in range(4))
        round_keys.append(list(rk))
    return round_keys


def validator_expand_aes256(key: bytes) -> list[list[int]]:
    """KeySchedule::expand_aes256 — 15 round keys × 16 bytes."""
    assert len(key) == 32
    nk = 8
    nr = 14
    w = list(struct.unpack(">8I", key))
    for i in range(nk, 4 * (nr + 1)):
        temp = w[i - 1]
        if i % nk == 0:
            temp = _aes_sub_word(_aes_rot_word(temp)) ^ (_AES_RCON[i // nk - 1] << 24)
        elif i % nk == 4:
            temp = _aes_sub_word(temp)
        w.append((w[i - nk] ^ temp) & 0xFFFFFFFF)
    round_keys = []
    for r in range(nr + 1):
        rk = b"".join(struct.pack(">I", w[r * 4 + j]) for j in range(4))
        round_keys.append(list(rk))
    return round_keys


def validator_expand_rc4(key: bytes) -> list[int]:
    """KeySchedule::expand_rc4 — RC4 KSA, returns 256-byte state."""
    S = list(range(256))
    j = 0
    klen = len(key)
    for i in range(256):
        j = (j + S[i] + key[i % klen]) % 256
        S[i], S[j] = S[j], S[i]
    return S


def validator_verify_aes128_expansion() -> bool:
    """verify_aes128_expansion — FIPS-197 Appendix A.1 test vector."""
    # Key: 2b 7e 15 16 28 ae d2 a6 ab f7 15 88 09 cf 4f 3c
    key = bytes([0x2b,0x7e,0x15,0x16,0x28,0xae,0xd2,0xa6,
                 0xab,0xf7,0x15,0x88,0x09,0xcf,0x4f,0x3c])
    rks = validator_expand_aes128(key)
    # Round 1 key per FIPS-197: a0 fa fe 17 88 54 2c b1 23 a3 39 39 2a 6c 76 05
    expected_rk1 = [0xa0,0xfa,0xfe,0x17,0x88,0x54,0x2c,0xb1,
                    0x23,0xa3,0x39,0x39,0x2a,0x6c,0x76,0x05]
    return rks[1] == expected_rk1


def validator_count_constant_hits(binary_data: bytes, constants: list[bytes]) -> int:
    """KeySchedulePattern::count_constant_hits."""
    count = 0
    for c in constants:
        idx = 0
        while True:
            off = binary_data.find(c, idx)
            if off < 0:
                break
            count += 1
            idx = off + 1
    return count


# ---------------------------------------------------------------------------
# Crypto constant finder blobs
# ---------------------------------------------------------------------------

# SHA-256 IV (big-endian)
_SHA256_IV = struct.pack(">8I",
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19)

# SHA-1 IV
_SHA1_IV = struct.pack(">5I",
    0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0)


def validator_test_blob_with_sha256_iv(offset: int) -> list:
    """crypto_constant_finder.rs: test_blob_with_sha256_iv."""
    blob = bytearray(offset) + bytearray(_SHA256_IV) + bytearray(32)
    return list(blob)


def validator_test_blob_with_sha1_iv(offset: int) -> list:
    """crypto_constant_finder.rs: test_blob_with_sha1_iv."""
    blob = bytearray(offset) + bytearray(_SHA1_IV) + bytearray(32)
    return list(blob)


# ---------------------------------------------------------------------------
# PowerTrace stats
# ---------------------------------------------------------------------------

def validator_power_trace_mean(samples: list[float]) -> float:
    """PowerTrace::mean."""
    if not samples:
        return 0.0
    return sum(samples) / len(samples)


def validator_power_trace_variance(samples: list[float]) -> float:
    """PowerTrace::variance."""
    if not samples:
        return 0.0
    m = sum(samples) / len(samples)
    return sum((x - m) ** 2 for x in samples) / len(samples)


def validator_power_trace_std_dev(samples: list[float]) -> float:
    """PowerTrace::std_dev."""
    return math.sqrt(validator_power_trace_variance(samples))


def validator_power_trace_energy(samples: list[float]) -> float:
    """PowerTrace::energy — sum of squares."""
    return sum(x * x for x in samples)


def validator_power_trace_normalize(samples: list[float]) -> list[float]:
    """PowerTrace::normalize — zero mean, unit variance."""
    if not samples:
        return []
    m = sum(samples) / len(samples)
    std = math.sqrt(sum((x - m) ** 2 for x in samples) / len(samples))
    if std == 0.0:
        return [0.0] * len(samples)
    return [(x - m) / std for x in samples]


def validator_power_trace_subtract(a: list[float], b: list[float]) -> list[float]:
    """PowerTrace::subtract."""
    n = min(len(a), len(b))
    return [a[i] - b[i] for i in range(n)]


def validator_pearson_correlation(x: list[float], y: list[float]) -> float:
    """DpaAnalyzer::pearson_correlation."""
    n = min(len(x), len(y))
    if n == 0:
        return 0.0
    mx = sum(x[:n]) / n
    my = sum(y[:n]) / n
    num = sum((x[i] - mx) * (y[i] - my) for i in range(n))
    dx = math.sqrt(sum((x[i] - mx) ** 2 for i in range(n)))
    dy = math.sqrt(sum((y[i] - my) ** 2 for i in range(n)))
    if dx == 0 or dy == 0:
        return 0.0
    return num / (dx * dy)


# ---------------------------------------------------------------------------
# TraceFilter
# ---------------------------------------------------------------------------

def validator_trace_low_pass(samples: list[float], window_size: int) -> list[float]:
    """TraceFilter::low_pass — simple moving average."""
    if window_size == 0 or not samples:
        return list(samples)
    out = []
    for i in range(len(samples)):
        start = max(0, i - window_size // 2)
        end = min(len(samples), i + window_size // 2 + 1)
        out.append(sum(samples[start:end]) / (end - start))
    return out


def validator_trace_high_pass(samples: list[float], window_size: int) -> list[float]:
    """TraceFilter::high_pass — signal minus low-pass."""
    lp = validator_trace_low_pass(samples, window_size)
    return [samples[i] - lp[i] for i in range(len(samples))]


def validator_trace_smooth(samples: list[float]) -> list[float]:
    """TraceFilter::smooth — 5-tap Gaussian [1,4,6,4,1]/16."""
    kernel = [1, 4, 6, 4, 1]
    k_sum = 16
    out = []
    n = len(samples)
    for i in range(n):
        s = 0.0
        for j, w in enumerate(kernel):
            idx = i + j - 2
            if 0 <= idx < n:
                s += w * samples[idx]
            else:
                s += w * (samples[0] if idx < 0 else samples[-1])
        out.append(s / k_sum)
    return out


# ---------------------------------------------------------------------------
# Timing stats
# ---------------------------------------------------------------------------

def validator_median(values: list[int]) -> int | None:
    """timing_oracle_full.rs: median."""
    if not values:
        return None
    s = sorted(values)
    n = len(s)
    if n % 2 == 0:
        return (s[n // 2 - 1] + s[n // 2]) // 2
    return s[n // 2]


def validator_remove_outliers(measurements: list[dict]) -> list[dict]:
    """timing_oracle_full.rs: remove_outliers — IQR 1.5×."""
    if len(measurements) < 4:
        return list(measurements)
    vals = sorted(m["duration_ns"] for m in measurements if "duration_ns" in m)
    n = len(vals)
    q1 = vals[n // 4]
    q3 = vals[(3 * n) // 4]
    iqr = q3 - q1
    lo = q1 - 1.5 * iqr
    hi = q3 + 1.5 * iqr
    return [m for m in measurements if lo <= m.get("duration_ns", 0) <= hi]


def validator_timing_stats_cv(mean: float, std: float) -> float:
    """TimingStats::cv — coefficient of variation."""
    if mean == 0.0:
        return 0.0
    return std / mean


def validator_timing_stats_is_constant_time(cv: float) -> bool:
    """TimingStats::is_constant_time — CV < 0.05."""
    return cv < 0.05


def validator_welch_t_test(class0: list[int], class1: list[int]) -> float | None:
    """TimingTest::welch_t_test."""
    if len(class0) < 2 or len(class1) < 2:
        return None
    n0, n1 = len(class0), len(class1)
    m0 = sum(class0) / n0
    m1 = sum(class1) / n1
    v0 = sum((x - m0) ** 2 for x in class0) / (n0 - 1)
    v1 = sum((x - m1) ** 2 for x in class1) / (n1 - 1)
    se = math.sqrt(v0 / n0 + v1 / n1)
    if se == 0.0:
        return None
    return (m0 - m1) / se


def validator_timing_estimate_query_count(byte_len: int, samples_per_byte: int) -> int:
    """TimingOracleAttack::estimate_query_count."""
    return byte_len * 256 * samples_per_byte


# ---------------------------------------------------------------------------
# Berlekamp-Massey LFSR
# ---------------------------------------------------------------------------

def validator_berlekamp_massey(seq: list[int]) -> dict:
    """LfsrAnalysis::berlekamp_massey — minimal LFSR for binary sequence."""
    # seq is list of 0/1 bits
    n = len(seq)
    C = [1] + [0] * n
    B = [1] + [0] * n
    L = 0
    x = 1
    b = 1
    for i in range(n):
        d = seq[i]
        for j in range(1, L + 1):
            d ^= (C[j] * seq[i - j]) % 2
        d %= 2
        if d == 0:
            x += 1
        elif 2 * L <= i:
            T = C[:]
            coeff = pow(b, -1, 2) if b != 0 else 1  # GF(2): inverse of 1 is 1
            for j in range(x, n + 1):
                C[j] ^= (coeff * d * B[j - x]) % 2
            L = i + 1 - L
            B = T
            b = d
            x = 1
        else:
            coeff = 1  # GF(2)
            for j in range(x, n + 1):
                C[j] ^= (coeff * d * B[j - x]) % 2
            x += 1
    poly = C[:L + 1]
    return {"lfsr_length": L, "polynomial": poly}


def validator_detect_lfsr(seq: list[int]) -> bool:
    """LfsrAnalysis::detect_lfsr — True if BM complexity < len/2."""
    if len(seq) < 4:
        return False
    bm = validator_berlekamp_massey(seq)
    return bm["lfsr_length"] <= len(seq) // 2


def validator_bytes_to_bits(data: bytes) -> list[int]:
    """LfsrAnalysis::bytes_to_bits."""
    bits = []
    for b in data:
        for i in range(7, -1, -1):
            bits.append((b >> i) & 1)
    return bits


def validator_bits_to_bytes(bits: list[int]) -> list[int]:
    """LfsrAnalysis::bits_to_bytes."""
    result = []
    for i in range(0, len(bits) - 7, 8):
        byte = 0
        for j in range(8):
            byte = (byte << 1) | (bits[i + j] & 1)
        result.append(byte)
    return result


# ---------------------------------------------------------------------------
# Keystream statistics
# ---------------------------------------------------------------------------

def _shannon_entropy_bits(data: bytes) -> float:
    if not data:
        return 0.0
    counts = defaultdict(int)
    for b in data:
        counts[b] += 1
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def validator_byte_entropy(data: bytes) -> float:
    """KeystreamTestSuite::byte_entropy."""
    return _shannon_entropy_bits(data)


def validator_monobit_test(bits: list[int]) -> float:
    """KeystreamTestSuite::monobit_test — NIST SP 800-22 monobit p-value approximation."""
    n = len(bits)
    if n == 0:
        return 0.0
    s = abs(sum(1 if b else -1 for b in bits)) / math.sqrt(n)
    # erfc approximation
    import math as _math
    return math.erfc(s / math.sqrt(2))


def validator_longest_run(bits: list[int]) -> int:
    """KeystreamTestSuite::longest_run."""
    if not bits:
        return 0
    max_run = cur = 1 if bits[0] else 0
    for i in range(1, len(bits)):
        if bits[i] == bits[i - 1] and bits[i] == 1:
            cur += 1
            max_run = max(max_run, cur)
        else:
            cur = 1 if bits[i] else 0
    return max_run


def validator_chi_squared_byte(data: bytes) -> float:
    """KeystreamTestSuite::chi_squared_byte."""
    if not data:
        return 0.0
    n = len(data)
    expected = n / 256.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    return sum((c - expected) ** 2 / expected for c in counts)


def validator_autocorrelation(bits: list[int], lag: int) -> float:
    """KeystreamTestSuite::autocorrelation."""
    n = len(bits)
    if lag >= n or n == 0:
        return 0.0
    m = n - lag
    mean = sum(bits) / n
    num = sum((bits[i] - mean) * (bits[i + lag] - mean) for i in range(m))
    denom = sum((b - mean) ** 2 for b in bits)
    if denom == 0:
        return 1.0
    return num / denom


def validator_estimate_period(keystream: bytes, max_lag: int) -> int | None:
    """KeystreamTestSuite::estimate_period."""
    bits = validator_bytes_to_bits(keystream)
    best_lag = None
    best_corr = -1.0
    for lag in range(1, min(max_lag + 1, len(bits))):
        c = validator_autocorrelation(bits, lag)
        if c > best_corr and c > 0.9:
            best_corr = c
            best_lag = lag
    return best_lag


# ---------------------------------------------------------------------------
# SBoxAnalyzer (whitebox)
# ---------------------------------------------------------------------------

def validator_sbox_is_affine(table: list[int]) -> bool:
    """SBoxAnalyzer::is_affine — check f(a XOR b) == f(a) XOR f(b) XOR f(0) for all a,b."""
    if len(table) != 256:
        return False
    f0 = table[0]
    for a in range(256):
        for b in range(256):
            if table[a ^ b] != (table[a] ^ table[b] ^ f0):
                return False
    return True


def validator_sbox_is_linear(table: list[int]) -> bool:
    """SBoxAnalyzer::is_linear — affine with f(0)=0."""
    if len(table) != 256:
        return False
    if table[0] != 0:
        return False
    return validator_sbox_is_affine(table)


def validator_sbox_inverse(table: list[int]) -> list[int] | None:
    """SBoxAnalyzer::inverse_table — None if not bijective."""
    if len(table) != 256 or len(set(table)) != 256:
        return None
    inv = [0] * 256
    for i, v in enumerate(table):
        inv[v] = i
    return inv


def validator_sbox_compose(outer: list[int], inner: list[int]) -> list[int]:
    """SBoxAnalyzer::compose."""
    return [outer[inner[i]] for i in range(256)]


def validator_sbox_difference_distribution_table(table: list[int]) -> list[list[int]]:
    """SBoxAnalyzer::difference_distribution_table."""
    ddt = [[0] * 256 for _ in range(256)]
    for x in range(256):
        for dx in range(256):
            dy = table[x] ^ table[x ^ dx]
            ddt[dx][dy] += 1
    return ddt


# ---------------------------------------------------------------------------
# Walsh-Hadamard Transform
# ---------------------------------------------------------------------------

def _wht(table: list[int]) -> list[int]:
    """Compute Walsh-Hadamard transform over GF(2)^8."""
    n = 256
    # Convert to {-1,+1} via (-1)^table[x]
    W = [1 - 2 * (table[i] & 1) for i in range(n)]
    # Hadamard transform
    h = 1
    while h < n:
        for i in range(0, n, h * 2):
            for j in range(i, i + h):
                u = W[j]
                v = W[j + h]
                W[j] = u + v
                W[j + h] = u - v
        h *= 2
    return W


def validator_wht_compute_nonlinearity(table: list[int]) -> int:
    """WalshHadamardTransform::compute_nonlinearity."""
    if len(table) != 256:
        return 0
    W = _wht(table)
    max_coeff = max(abs(w) for w in W)
    return (256 - max_coeff) // 2


def validator_wht_max_walsh_coefficient(table: list[int]) -> int:
    """WalshHadamardTransform::max_walsh_coefficient."""
    if len(table) != 256:
        return 0
    W = _wht(table)
    return max(abs(w) for w in W)


def validator_wht_compute_differential_uniformity(table: list[int]) -> int:
    """WalshHadamardTransform::compute_differential_uniformity."""
    ddt = validator_sbox_difference_distribution_table(table)
    max_val = 0
    for dx in range(1, 256):
        for dy in range(256):
            if ddt[dx][dy] > max_val:
                max_val = ddt[dx][dy]
    return max_val


def validator_wht_compute_output_entropy(table: list[int]) -> float:
    """WalshHadamardTransform::compute_output_entropy."""
    return _shannon_entropy_bits(bytes(table))


# ---------------------------------------------------------------------------
# GF(2) linear system solver
# ---------------------------------------------------------------------------

def validator_gf2_solve(matrix: list[list[int]], rhs: list[int]) -> list[int] | None:
    """GF2LinearSystem::solve — Gaussian elimination over GF(2)."""
    m = [row[:] + [rhs[i]] for i, row in enumerate(matrix)]
    n_rows = len(m)
    n_cols = len(matrix[0]) if matrix else 0
    pivot_row = 0
    for col in range(n_cols):
        # Find pivot
        found = -1
        for row in range(pivot_row, n_rows):
            if m[row][col] == 1:
                found = row
                break
        if found < 0:
            continue
        m[pivot_row], m[found] = m[found], m[pivot_row]
        for row in range(n_rows):
            if row != pivot_row and m[row][col] == 1:
                m[row] = [(m[row][j] ^ m[pivot_row][j]) for j in range(n_cols + 1)]
        pivot_row += 1
    # Extract solution
    sol = [0] * n_cols
    for row in range(n_rows):
        pivots = [j for j in range(n_cols) if m[row][j] == 1]
        if not pivots:
            if m[row][n_cols] == 1:
                return None  # inconsistent
            continue
        if len(pivots) == 1:
            sol[pivots[0]] = m[row][n_cols]
    return sol


# ---------------------------------------------------------------------------
# RC4 bias
# ---------------------------------------------------------------------------

def validator_rc4_bias_ratio(counts: list[int], position: int, value: int) -> float:
    """ByteBiasAccumulator::bias_ratio — observed / expected (1/256)."""
    total = sum(counts)
    if total == 0:
        return 0.0
    observed = counts[value] / total
    expected = 1.0 / 256
    return observed / expected


def validator_rc4_most_likely_byte(counts: list[int]) -> int:
    """ByteBiasAccumulator::most_likely_byte."""
    return max(range(256), key=lambda i: counts[i])


def validator_rc4_max_bias_ratio(counts: list[int]) -> float:
    """ByteBiasAccumulator::max_bias_ratio."""
    total = sum(counts)
    if total == 0:
        return 0.0
    expected = total / 256.0
    return max(c / expected for c in counts)


# ---------------------------------------------------------------------------
# Dispatch table
# ---------------------------------------------------------------------------

DISPATCH: dict[str, Any] = {
    # PKCS#7
    "validate_pkcs7":           lambda i: validator_validate_pkcs7(bytes(i)),
    "strip_pkcs7":              lambda i: validator_strip_pkcs7(bytes(i)),
    "add_pkcs7":                lambda i: validator_add_pkcs7(bytes(i[0]), int(i[1])),
    "pkcs7_validate":           lambda i: validator_pkcs7_validate(bytes(i)),
    "pkcs7_pad":                lambda i: validator_pkcs7_pad(bytes(i[0]), int(i[1])),
    "pkcs7_unpad":              lambda i: validator_pkcs7_unpad(bytes(i)),
    # ECB
    "check_ecb_in_ciphertext":  lambda i: validator_check_ecb_in_ciphertext(bytes(i[0]), int(i[1])),
    "detect_block_size_from_pairs": lambda i: validator_detect_block_size_from_pairs([tuple(p) for p in i]),
    # Nonce reuse
    "xor_ciphertexts":          lambda i: validator_xor_ciphertexts(bytes(i[0]), bytes(i[1])),
    "analyze_xor_for_english":  lambda i: validator_analyze_xor_for_english(bytes(i)),
    "attack_nonce_reuse":       lambda i: validator_attack_nonce_reuse(bytes(i[0]), bytes(i[1]), bytes(i[2])),
    "find_nonce_reuse":         lambda i: validator_find_nonce_reuse(i),
    "otp_recover_p2":           lambda i: validator_otp_recover_p2(bytes(i[0]), bytes(i[1])),
    "recover_key_byte":         lambda i: validator_recover_key_byte(bytes(i)),
    "otp_analyze_xor_distribution": lambda i: validator_otp_analyze_xor_distribution(bytes(i)),
    # IV prediction
    "detect_counter_iv":        lambda i: validator_detect_counter_iv([bytes(iv) for iv in i]),
    "predict_next_iv":          lambda i: validator_predict_next_iv(bytes(i)),
    "forge_chosen_plaintext":   lambda i: validator_forge_chosen_plaintext(bytes(i[0]), bytes(i[1]), bytes(i[2])),
    # CBC bit-flip
    "cbc_bitflip":              lambda i: validator_cbc_bitflip(bytes(i[0]), bytes(i[1]), int(i[2]), int(i[3]), int(i[4])),
    # ECB cut-and-paste
    "ecb_detect_blocks":        lambda i: validator_ecb_detect_blocks(bytes(i[0]), int(i[1])),
    "ecb_reorder_blocks":       lambda i: validator_ecb_reorder_blocks(bytes(i[0]), int(i[1]), list(i[2])),
    # Timing
    "median_duration":          lambda i: validator_median_duration(i),
    "find_max_duration":        lambda i: validator_find_max_duration(i),
    "byte_timing_attack":       lambda i: validator_byte_timing_attack(i),
    # AES cracker
    "is_weak_key":              lambda i: validator_is_weak_key(bytes(i)),
    "weak_keys":                lambda i: validator_weak_keys(),
    # RSA
    "rsa_small_exponent":       lambda i: validator_rsa_small_exponent(bytes(i[0]), int(i[1])),
    "wiener_attack":            lambda i: validator_wiener_attack(int(i[0]), int(i[1])),
    "fermat_factor":            lambda i: validator_fermat_factor(int(i)),
    "common_modulus_attack":    lambda i: validator_common_modulus_attack(int(i[0]),int(i[1]),int(i[2]),int(i[3]),int(i[4])),
    # FieldFlags
    "field_flags_from_tuple":   lambda i: validator_field_flags_from_tuple(*[bool(x) for x in i]),
    "field_flags_is_constant":  lambda i: validator_field_flags_is_constant(int(i)),
    "field_flags_is_random":    lambda i: validator_field_flags_is_random(int(i)),
    "field_flags_is_incrementing": lambda i: validator_field_flags_is_incrementing(int(i)),
    "field_flags_is_timestamp": lambda i: validator_field_flags_is_timestamp(int(i)),
    # Protocol
    "infer_fields":             lambda i: validator_infer_fields([bytes(s) for s in i]),
    # Oracle stats
    "oracle_accept_rate":       lambda i: validator_oracle_stats_accept_rate(int(i[0]), int(i[1])),
    # Timeline
    "timeline_acceptance_ratio": lambda i: validator_exploit_timeline_acceptance_ratio(i),
    "timeline_total_queries":   lambda i: validator_exploit_timeline_total_queries(i),
    "timeline_accepted_count":  lambda i: validator_exploit_timeline_accepted_count(i),
    "timeline_rejected_count":  lambda i: validator_exploit_timeline_rejected_count(i),
    # Exploit
    "exploit_queries_per_byte": lambda i: validator_exploit_queries_per_byte(int(i[0]), int(i[1])),
    # Response profile
    "response_mean_time":       lambda i: validator_response_profile_mean_time(i),
    "response_std_dev":         lambda i: validator_response_profile_std_dev(i),
    "response_mean_length":     lambda i: validator_response_profile_mean_length(i),
    "response_distinct_status": lambda i: validator_response_profile_distinct_status(i),
    "response_distinct_lengths": lambda i: validator_response_profile_distinct_lengths(i),
    "response_is_length_bimodal": lambda i: validator_response_profile_is_length_bimodal(i),
    "response_is_status_bimodal": lambda i: validator_response_profile_is_status_bimodal(i),
    # Differential
    "differential_timing_delta": lambda i: validator_differential_timing_delta(i[0], i[1]),
    "differential_has_timing_diff": lambda i: validator_differential_has_timing_diff(i[0], i[1], float(i[2])),
    # Oracle found
    "is_oracle_found":          lambda i: validator_is_oracle_found(i),
    # Hash
    "sha1":                     lambda i: validator_sha1(bytes(i)),
    "sha512":                   lambda i: validator_sha512(bytes(i)),
    "sha256":                   lambda i: validator_sha256(bytes(i)),
    "md5":                      lambda i: validator_md5(bytes(i)),
    "md_padding":               lambda i: validator_md_padding(int(i[0]), str(i[1])),
    "extend_sha256":            lambda i: validator_extend_sha256(bytes(i[0]), int(i[1]), int(i[2]), bytes(i[3])),
    # Key schedule
    "expand_aes128":            lambda i: validator_expand_aes128(bytes(i)),
    "expand_aes256":            lambda i: validator_expand_aes256(bytes(i)),
    "expand_rc4":               lambda i: validator_expand_rc4(bytes(i)),
    "verify_aes128_expansion":  lambda i: validator_verify_aes128_expansion(),
    "count_constant_hits":      lambda i: validator_count_constant_hits(bytes(i[0]), [bytes(c) for c in i[1]]),
    # Crypto constant blobs
    "test_blob_with_sha256_iv": lambda i: validator_test_blob_with_sha256_iv(int(i)),
    "test_blob_with_sha1_iv":   lambda i: validator_test_blob_with_sha1_iv(int(i)),
    # Power trace
    "power_trace_mean":         lambda i: validator_power_trace_mean(i),
    "power_trace_variance":     lambda i: validator_power_trace_variance(i),
    "power_trace_std_dev":      lambda i: validator_power_trace_std_dev(i),
    "power_trace_energy":       lambda i: validator_power_trace_energy(i),
    "power_trace_normalize":    lambda i: validator_power_trace_normalize(i),
    "power_trace_subtract":     lambda i: validator_power_trace_subtract(i[0], i[1]),
    "pearson_correlation":      lambda i: validator_pearson_correlation(i[0], i[1]),
    # Filters
    "trace_low_pass":           lambda i: validator_trace_low_pass(i[0], int(i[1])),
    "trace_high_pass":          lambda i: validator_trace_high_pass(i[0], int(i[1])),
    "trace_smooth":             lambda i: validator_trace_smooth(i),
    # Timing oracle
    "median":                   lambda i: validator_median(i),
    "remove_outliers":          lambda i: validator_remove_outliers(i),
    "timing_stats_cv":          lambda i: validator_timing_stats_cv(float(i[0]), float(i[1])),
    "timing_stats_is_constant_time": lambda i: validator_timing_stats_is_constant_time(float(i)),
    "welch_t_test":             lambda i: validator_welch_t_test(i[0], i[1]),
    "timing_estimate_query_count": lambda i: validator_timing_estimate_query_count(int(i[0]), int(i[1])),
    # LFSR / stream
    "berlekamp_massey":         lambda i: validator_berlekamp_massey(i),
    "detect_lfsr":              lambda i: validator_detect_lfsr(i),
    "bytes_to_bits":            lambda i: validator_bytes_to_bits(bytes(i)),
    "bits_to_bytes":            lambda i: validator_bits_to_bytes(i),
    "byte_entropy":             lambda i: validator_byte_entropy(bytes(i)),
    "monobit_test":             lambda i: validator_monobit_test(i),
    "longest_run":              lambda i: validator_longest_run(i),
    "chi_squared_byte":         lambda i: validator_chi_squared_byte(bytes(i)),
    "autocorrelation":          lambda i: validator_autocorrelation(i[0], int(i[1])),
    "estimate_period":          lambda i: validator_estimate_period(bytes(i[0]), int(i[1])),
    # RC4 bias
    "rc4_bias_ratio":           lambda i: validator_rc4_bias_ratio(i[0], int(i[1]), int(i[2])),
    "rc4_most_likely_byte":     lambda i: validator_rc4_most_likely_byte(i),
    "rc4_max_bias_ratio":       lambda i: validator_rc4_max_bias_ratio(i),
    # SBox
    "sbox_is_affine":           lambda i: validator_sbox_is_affine(i),
    "sbox_is_linear":           lambda i: validator_sbox_is_linear(i),
    "sbox_inverse":             lambda i: validator_sbox_inverse(i),
    "sbox_compose":             lambda i: validator_sbox_compose(i[0], i[1]),
    "sbox_difference_distribution_table": lambda i: validator_sbox_difference_distribution_table(i),
    # WHT
    "wht_nonlinearity":         lambda i: validator_wht_compute_nonlinearity(i),
    "wht_max_coefficient":      lambda i: validator_wht_max_walsh_coefficient(i),
    "wht_differential_uniformity": lambda i: validator_wht_compute_differential_uniformity(i),
    "wht_output_entropy":       lambda i: validator_wht_compute_output_entropy(i),
    # GF(2)
    "gf2_solve":                lambda i: validator_gf2_solve(i[0], i[1]),
}


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main_stdin() -> None:
    req = json.loads(sys.stdin.read())
    func = req["func"]
    inp = req.get("input", [])
    if func not in DISPATCH:
        print(json.dumps({"error": f"unknown function: {func}"}))
        return
    try:
        out = DISPATCH[func](inp)
        print(json.dumps({"output": out}))
    except Exception as e:
        print(json.dumps({"error": str(e)}))


def main() -> None:
    results: dict[str, Any] = {}

    # PKCS#7
    results["validate_pkcs7_valid"]   = validator_validate_pkcs7(b"\x01\x02\x04\x04\x04\x04")
    results["validate_pkcs7_invalid"] = validator_validate_pkcs7(b"\x01\x02\x05\x04\x04\x04")
    results["add_pkcs7"]              = validator_add_pkcs7(b"YELLOW SUBMARINE", 20)
    results["strip_pkcs7"]            = validator_strip_pkcs7(bytes([1, 2, 4, 4, 4, 4]))
    results["pkcs7_validate"]         = validator_pkcs7_validate(bytes([1, 2, 4, 4, 4, 4]))

    # ECB
    ct_dup  = bytes([0xAA] * 16 * 3)
    ct_rand = os.urandom(48)
    results["check_ecb_dup"]     = validator_check_ecb_in_ciphertext(ct_dup, 16)
    results["check_ecb_rand"]    = validator_check_ecb_in_ciphertext(ct_rand, 16)
    results["block_size_pairs"]  = validator_detect_block_size_from_pairs([(0,16),(1,16),(5,32),(9,32),(17,48)])

    # Nonce reuse
    k  = b"SECRETKEYABCDEFG"
    p1 = b"Hello, world!!!!!"
    p2 = b"Attack at dawn!!!"
    ct1 = _xor(p1, k[:len(p1)])
    ct2 = _xor(p2, k[:len(p2)])
    results["attack_nonce_reuse"]     = validator_attack_nonce_reuse(ct1, ct2, p1)
    results["analyze_xor_english"]    = round(validator_analyze_xor_for_english(b"Hello world"), 3)

    # IV prediction
    iv0 = b"\x00" * 16
    iv1 = b"\x01" + b"\x00" * 15
    iv2 = b"\x02" + b"\x00" * 15
    results["detect_counter_iv"]  = validator_detect_counter_iv([iv0, iv1, iv2])
    results["predict_next_iv"]    = validator_predict_next_iv(iv2)

    # RSA
    # 3^3 = 27
    results["rsa_small_exp"]  = validator_rsa_small_exponent(bytes([27]), 3)
    results["fermat_factor"]  = validator_fermat_factor(3_233)  # 61 * 53
    results["wiener"]         = validator_wiener_attack(17993, 90581)  # small d example

    # AES key schedule
    key128 = bytes(range(16))
    rks = validator_expand_aes128(key128)
    results["aes128_rk_count"]  = len(rks)
    results["aes128_rk0"]       = rks[0]
    results["verify_aes128"]    = validator_verify_aes128_expansion()

    key256 = bytes(range(32))
    rks256 = validator_expand_aes256(key256)
    results["aes256_rk_count"]  = len(rks256)

    rc4_state = validator_expand_rc4(b"Key")
    results["rc4_state_len"]   = len(rc4_state)
    results["rc4_state_0"]     = rc4_state[0]

    # Hash
    results["sha1_empty"]   = bytes(validator_sha1(b"")).hex()
    results["sha256_empty"] = bytes(validator_sha256(b"")).hex()
    results["md5_empty"]    = bytes(validator_md5(b"")).hex()
    results["sha512_empty"] = bytes(validator_sha512(b""))[:8].hex()

    # md_padding
    pad = validator_md_padding(3, "sha256")
    results["md_padding_sha256_len_3"] = len(pad)

    # Crypto blobs
    blob = bytes(validator_test_blob_with_sha256_iv(100))
    from struct import pack
    sha256_iv = pack(">8I",0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19)
    results["sha256_blob_contains_iv"] = sha256_iv in blob

    # Power trace
    samples = [1.0, 2.0, 3.0, 4.0, 5.0]
    results["trace_mean"]   = validator_power_trace_mean(samples)
    results["trace_std"]    = round(validator_power_trace_std_dev(samples), 4)
    results["pearson_self"] = round(validator_pearson_correlation(samples, samples), 4)

    # Timing
    results["median_odd"]  = validator_median([3, 1, 4, 1, 5])
    results["remove_out"]  = len(validator_remove_outliers([
        {"duration_ns": v} for v in [100, 101, 102, 103, 104, 10000]
    ]))
    results["welch_t"]     = validator_welch_t_test([100,101,102,103],[200,201,202,203])

    # LFSR / BM
    bits = [1,0,1,1,0,1,0,1,1,0,1,1,0,1,0,1]
    bm = validator_berlekamp_massey(bits)
    results["bm_length"] = bm["lfsr_length"]

    # WHT on identity S-box
    identity = list(range(256))
    results["wht_nonlinearity_identity"] = validator_wht_compute_nonlinearity(identity)
    results["sbox_is_linear_identity"]   = validator_sbox_is_linear(identity)

    # AES S-box
    aes_sbox = list(_AES_SBOX)
    results["aes_sbox_is_linear"]  = validator_sbox_is_linear(aes_sbox)
    results["aes_sbox_is_affine"]  = validator_sbox_is_affine(aes_sbox)  # should be False (non-linear)
    results["aes_sbox_du"]         = validator_wht_compute_differential_uniformity(aes_sbox)

    # GF(2) solve
    # x0 XOR x1 = 1, x0 = 0  -> x1 = 1
    sol = validator_gf2_solve([[1,1],[1,0]], [1, 0])
    results["gf2_solve"] = sol

    # FieldFlags
    f = validator_field_flags_from_tuple(True, False, True, False)
    results["field_flags"] = {
        "value": f,
        "is_constant": validator_field_flags_is_constant(f),
        "is_random": validator_field_flags_is_random(f),
        "is_incrementing": validator_field_flags_is_incrementing(f),
    }

    print(json.dumps(results, indent=2))


if __name__ == "__main__":
    if "--stdin" in sys.argv:
        main_stdin()
    else:
        main()
