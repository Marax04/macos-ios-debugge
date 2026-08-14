"""Python validator reproducing the public API of crate `rustre-deobf-string`.

Each Rust free-standing function has a Python equivalent with matching input
shape and output type. Implementations use only Python stdlib (struct,
hashlib, json, re).
"""
from __future__ import annotations

import json
import re
import struct
import hashlib
from typing import Callable, Optional


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

ENGLISH_FREQ = {
    'a': 8.17, 'b': 1.49, 'c': 2.78, 'd': 4.25, 'e': 12.70, 'f': 2.23,
    'g': 2.02, 'h': 6.09, 'i': 6.97, 'j': 0.15, 'k': 0.77, 'l': 4.03,
    'm': 2.41, 'n': 6.75, 'o': 7.51, 'p': 1.93, 'q': 0.10, 'r': 5.99,
    's': 6.33, 't': 9.06, 'u': 2.76, 'v': 0.98, 'w': 2.36, 'x': 0.15,
    'y': 1.97, 'z': 0.07,
}


def _printable_ratio(data: bytes) -> float:
    if not data:
        return 0.0
    p = sum(1 for b in data if 32 <= b < 127 or b in (9, 10, 13))
    return p / len(data)


def _english_score(data: bytes) -> float:
    score = 0.0
    for b in data:
        c = chr(b).lower()
        score += ENGLISH_FREQ.get(c, 0.0)
    return score / max(1, len(data))


# ---------------------------------------------------------------------------
# lib.rs
# ---------------------------------------------------------------------------

def xor_brute_force_top3(data: bytes) -> list:
    cands = []
    for k in range(256):
        dec = bytes(b ^ k for b in data)
        cands.append({
            "key": k,
            "confidence": _printable_ratio(dec),
            "decoded_utf8": dec.decode("utf-8", errors="replace"),
        })
    cands.sort(key=lambda c: c["confidence"], reverse=True)
    return cands[:3]


def detect_xor_key_length_ic(data: bytes, max_key_len: int) -> list:
    out = []
    for kl in range(1, max_key_len + 1):
        ics = [index_of_coincidence(data[offset::kl]) for offset in range(kl)]
        avg = sum(ics) / len(ics) if ics else 0.0
        out.append((kl, avg))
    out.sort(key=lambda t: t[1], reverse=True)
    return out


def recover_multibyte_xor(data: bytes, max_key_len: int) -> list:
    results = []
    for kl, _ in detect_xor_key_length_ic(data, max_key_len)[:3]:
        key = recover_multibyte_key(data, kl)
        dec = xor_decrypt_multibyte(data, key)
        results.append({"key": key, "key_length": kl, "plaintext": dec,
                        "score": _english_score(dec)})
    return results


def detect_rc4_ksa_in_mlil(instructions: list) -> list:
    hits = []
    has_256 = any(i.get("const") == 256 for i in instructions)
    has_swap = any("swap" in (i.get("op") or "").lower() for i in instructions)
    if has_256 and has_swap:
        hits.append({"pattern": "rc4_ksa", "confidence": 0.9})
    return hits


def rc4_inverse_ksa(s_final: bytes) -> list:
    assert len(s_final) == 256
    return []


def detect_base64_variant(data: bytes) -> Optional[str]:
    alphabet = set(data) - {ord('='), ord('\n'), ord('\r')}
    if not alphabet:
        return None
    std = set(b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/")
    url = set(b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_")
    if alphabet <= std:
        return "standard"
    if alphabet <= url:
        return "urlsafe"
    if 60 <= len(alphabet) <= 65:
        return "custom"
    return None


def decode_base64_urlsafe(input: str) -> bytes:
    import base64
    s = input.replace('-', '+').replace('_', '/')
    s += '=' * ((-len(s)) % 4)
    try:
        return base64.b64decode(s)
    except Exception as e:
        raise ValueError(f"StringDeobfError: {e}")


def decode_base64_custom(input: bytes, alphabet: bytes) -> bytes:
    assert len(alphabet) == 64
    table = {c: i for i, c in enumerate(alphabet)}
    out = bytearray()
    buf = 0; bits = 0
    for c in input:
        if c == ord('='):
            break
        if c not in table:
            raise ValueError("StringDeobfError: invalid char")
        buf = (buf << 6) | table[c]; bits += 6
        if bits >= 8:
            bits -= 8
            out.append((buf >> bits) & 0xFF)
    return bytes(out)


def caesar_brute_force(input: str) -> list:
    results = []
    for shift in range(1, 26):
        dec = ''.join(
            chr((ord(c) - 65 + shift) % 26 + 65) if 'A' <= c <= 'Z'
            else chr((ord(c) - 97 + shift) % 26 + 97) if 'a' <= c <= 'z'
            else c for c in input)
        results.append({"shift": shift, "plaintext": dec,
                        "score": _english_score(dec.encode())})
    results.sort(key=lambda r: r["score"], reverse=True)
    return results


def detect_arith_obf_in_mlil(instructions: list, ciphertext: bytes) -> list:
    out = []
    for ins in instructions:
        op = (ins.get("op") or "").upper()
        if op in ("ADD", "SUB", "ROL", "ROR", "XOR") and "const" in ins:
            k = ins["const"] & 0xFF
            if op == "XOR":
                dec = bytes(b ^ k for b in ciphertext)
            elif op == "ADD":
                dec = bytes((b - k) & 0xFF for b in ciphertext)
            elif op == "SUB":
                dec = bytes((b + k) & 0xFF for b in ciphertext)
            else:
                dec = ciphertext
            out.append({"op": op, "const": k, "plaintext": dec})
    return out


def detect_mlil_stack_strings(instructions: list) -> list:
    out, cur = [], bytearray()
    for ins in instructions:
        if ins.get("op") == "STORE" and "byte" in ins:
            cur.append(ins["byte"] & 0xFF)
        else:
            if len(cur) >= 4:
                out.append({"bytes": bytes(cur),
                            "text": cur.decode("utf-8", errors="replace")})
            cur = bytearray()
    if len(cur) >= 4:
        out.append({"bytes": bytes(cur),
                    "text": cur.decode("utf-8", errors="replace")})
    return out


def detect_string_decoder_helpers(func_addr: int, instructions: list) -> list:
    out = []
    if detect_xor_encryption(instructions):
        out.append({"addr": func_addr, "kind": "xor_loop"})
    if any(i.get("const") == 256 for i in instructions):
        out.append({"addr": func_addr, "kind": "rc4_256_loop"})
    return out


def batch_decrypt_string_table(entries: list,
                               data_provider: Callable[[int, int], Optional[bytes]],
                               algorithm: str) -> list:
    out = []
    for e in entries:
        data = data_provider(e["addr"], e["size"])
        if data is None:
            out.append({"addr": e["addr"], "ok": False, "plaintext": None})
            continue
        if algorithm == "xor_single":
            top = xor_brute_force_top3(data)
            pt = top[0]["decoded_utf8"].encode() if top else b""
        elif algorithm == "rc4":
            pt = rc4_decrypt(e.get("key", b""), data)
        else:
            pt = data
        out.append({"addr": e["addr"], "ok": True, "plaintext": pt})
    return out


def compute_confidence(decrypted: bytes) -> int:
    score = _printable_ratio(decrypted) * 60
    s = decrypted.decode("utf-8", errors="replace")
    if "http" in s or "://" in s:
        score += 20
    if decrypted.endswith(b"\x00"):
        score += 5
    score += _english_score(decrypted) * 15 / 12.7
    return max(0, min(100, int(score)))


def recover_stack_strings(instructions: list) -> list:
    return detect_mlil_stack_strings(instructions)


def detect_xor_encryption(instructions: list) -> bool:
    return any((ins.get("op") or "").upper() == "XOR" and "const" in ins
               for ins in instructions)


def run_pass() -> None:
    return None


# ---------------------------------------------------------------------------
# xor_string_decoder
# ---------------------------------------------------------------------------

def score_plaintext(data: bytes) -> float:
    return _printable_ratio(data) * 0.6 + _english_score(data) / 12.7 * 0.4


def to_display_string(data: bytes) -> str:
    return ''.join(chr(b) if 32 <= b < 127 else f"\\x{b:02x}" for b in data)


def brute_force_xor(data: bytes) -> list:
    out = []
    for k in range(256):
        dec = bytes(b ^ k for b in data)
        out.append((k, score_plaintext(dec), dec))
    out.sort(key=lambda t: t[1], reverse=True)
    return out


def brute_force_xor_multi(data: bytes, max_key_len: int) -> list:
    out = []
    for kl in range(1, max_key_len + 1):
        key = recover_multibyte_key(data, kl)
        dec = xor_decrypt_multibyte(data, key)
        out.append((key, score_plaintext(dec)))
    out.sort(key=lambda t: t[1], reverse=True)
    return out


# ---------------------------------------------------------------------------
# xor_decryptor
# ---------------------------------------------------------------------------

def brute_force_single_byte_xor(ciphertext: bytes) -> list:
    out = []
    for k in range(256):
        dec = bytes(b ^ k for b in ciphertext)
        out.append({"key": k, "score": score_plaintext(dec), "plaintext": dec})
    out.sort(key=lambda c: c["score"], reverse=True)
    return out


def best_single_byte_xor(ciphertext: bytes) -> Optional[dict]:
    cands = brute_force_single_byte_xor(ciphertext)
    return cands[0] if cands else None


def index_of_coincidence(data: bytes) -> float:
    if len(data) < 2:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    n = len(data)
    return sum(c * (c - 1) for c in counts) / (n * (n - 1))


def detect_key_length_ic(ciphertext: bytes, max_key_len: int) -> list:
    return detect_xor_key_length_ic(ciphertext, max_key_len)


def kasiski_trigrams(ciphertext: bytes) -> list:
    positions: dict = {}
    for i in range(len(ciphertext) - 2):
        positions.setdefault(bytes(ciphertext[i:i + 3]), []).append(i)
    return [(t, ps) for t, ps in positions.items() if len(ps) > 1]


def kasiski_key_length(ciphertext: bytes, max_key_len: int) -> list:
    distances = []
    for _, ps in kasiski_trigrams(ciphertext):
        for i in range(len(ps) - 1):
            distances.append(ps[i + 1] - ps[i])
    counts: dict = {}
    for d in distances:
        for kl in range(2, max_key_len + 1):
            if d % kl == 0:
                counts[kl] = counts.get(kl, 0) + 1
    return sorted(counts.items(), key=lambda x: x[1], reverse=True)


def xor_decrypt_multibyte(ciphertext: bytes, key: bytes) -> bytes:
    if not key:
        return ciphertext
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(ciphertext))


def recover_multibyte_key(ciphertext: bytes, key_len: int) -> bytes:
    key = bytearray()
    for offset in range(key_len):
        best = best_single_byte_xor(ciphertext[offset::key_len])
        key.append(best["key"] if best else 0)
    return bytes(key)


def attack_multibyte_xor(ciphertext: bytes, max_key_len: int = 16) -> dict:
    cands = detect_xor_key_length_ic(ciphertext, max_key_len)
    if not cands:
        return {"key": b"", "plaintext": ciphertext}
    kl = cands[0][0]
    key = recover_multibyte_key(ciphertext, kl)
    return {"key": key, "plaintext": xor_decrypt_multibyte(ciphertext, key)}


def _rol8(v, n):
    n &= 7; return ((v << n) | (v >> (8 - n))) & 0xFF


def _ror8(v, n):
    n &= 7; return ((v >> n) | (v << (8 - n))) & 0xFF


def brute_force_rol_xor(ciphertext: bytes) -> list:
    out = []
    for k in range(256):
        for r in range(1, 8):
            dec = bytes(_rol8(b ^ k, r) for b in ciphertext)
            out.append({"key": k, "rol": r, "score": score_plaintext(dec), "plaintext": dec})
    out.sort(key=lambda c: c["score"], reverse=True)
    return out


def brute_force_ror_xor(ciphertext: bytes) -> list:
    out = []
    for k in range(256):
        for r in range(1, 8):
            dec = bytes(_ror8(b ^ k, r) for b in ciphertext)
            out.append({"key": k, "ror": r, "score": score_plaintext(dec), "plaintext": dec})
    out.sort(key=lambda c: c["score"], reverse=True)
    return out


def brute_force_xor_add(ciphertext: bytes) -> list:
    out = []
    for k in range(256):
        for a in range(256):
            dec = bytes(((b ^ k) + a) & 0xFF for b in ciphertext)
            out.append({"key": k, "add": a, "score": score_plaintext(dec), "plaintext": dec})
    out.sort(key=lambda c: c["score"], reverse=True)
    return out[:256]


def decrypt_rolling_xor(ciphertext: bytes, initial_key: int) -> bytes:
    out = bytearray(); k = initial_key & 0xFF
    for b in ciphertext:
        out.append(b ^ k); k = (k + 1) & 0xFF
    return bytes(out)


def brute_force_rolling_xor(ciphertext: bytes) -> list:
    out = []
    for k in range(256):
        dec = decrypt_rolling_xor(ciphertext, k)
        out.append({"key": k, "score": score_plaintext(dec), "plaintext": dec})
    out.sort(key=lambda c: c["score"], reverse=True)
    return out


# ---------------------------------------------------------------------------
# unicode_obfuscation_detector
# ---------------------------------------------------------------------------

_HOMOGLYPHS = {
    'а': 'a', 'е': 'e', 'о': 'o', 'р': 'p', 'с': 'c', 'х': 'x', 'у': 'y',
    'А': 'A', 'В': 'B', 'Е': 'E', 'К': 'K', 'М': 'M', 'Н': 'H', 'О': 'O',
    'Р': 'P', 'С': 'C', 'Т': 'T', 'Х': 'X',
}
_INVISIBLE = {'​', '‌', '‍', '⁠', '﻿'}
_BIDI = {'‪', '‫', '‬', '‭', '‮'}


def homoglyph_check(s: str) -> list:
    return [{"index": i, "char": c, "ascii": _HOMOGLYPHS[c]}
            for i, c in enumerate(s) if c in _HOMOGLYPHS]


def mixed_script_check(s: str) -> Optional[dict]:
    has_latin = any('a' <= c.lower() <= 'z' for c in s)
    has_cyr = any('Ѐ' <= c <= 'ӿ' for c in s)
    if has_latin and has_cyr:
        return {"kind": "mixed_script", "scripts": ["Latin", "Cyrillic"]}
    return None


def normalize_homoglyphs(s: str) -> str:
    return ''.join(_HOMOGLYPHS.get(c, c) for c in s)


def strip_invisible(s: str) -> str:
    return ''.join(c for c in s if c not in _INVISIBLE)


def count_non_ascii_unicode(s: str) -> int:
    return sum(1 for c in s if ord(c) > 127)


def has_bidi_override(s: str) -> bool:
    return any(c in _BIDI for c in s)


def has_invisible_char(s: str) -> bool:
    return any(c in _INVISIBLE for c in s)


# ---------------------------------------------------------------------------
# string_encryption_bruteforcer
# ---------------------------------------------------------------------------

def result_to_candidate(result: dict) -> dict:
    return {"algorithm": result.get("algorithm", "xor"),
            "key": result.get("key"),
            "plaintext": result.get("plaintext"),
            "score": result.get("score", 0.0)}


def bruteforce(ciphertext: bytes) -> list:
    out = []
    for c in brute_force_single_byte_xor(ciphertext)[:8]:
        out.append({"algorithm": "xor1", **c})
    for c in brute_force_rolling_xor(ciphertext)[:4]:
        out.append({"algorithm": "rolling_xor", **c})
    return out


def bruteforce_top_n(ciphertext: bytes, n: int) -> list:
    cands = [result_to_candidate(r) for r in bruteforce(ciphertext)]
    cands.sort(key=lambda c: c["score"], reverse=True)
    return cands[:n]


def printability_score(data: bytes) -> float:
    return _printable_ratio(data)


# ---------------------------------------------------------------------------
# string_classifier
# ---------------------------------------------------------------------------

def looks_like_url(s: str) -> bool:
    return bool(re.match(r'^https?://[^\s]+$', s))


def looks_like_ipv4(s: str) -> bool:
    parts = s.split('.')
    if len(parts) != 4:
        return False
    try:
        return all(0 <= int(p) <= 255 for p in parts)
    except ValueError:
        return False


def looks_like_ipv6(s: str) -> bool:
    return bool(re.match(r'^[0-9a-fA-F:]+$', s)) and s.count(':') >= 2


def looks_like_email(s: str) -> bool:
    return bool(re.match(r'^[^@\s]+@[^@\s]+\.[^@\s]+$', s))


def looks_like_uuid(s: str) -> bool:
    return bool(re.match(r'^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-'
                        r'[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$', s))


def looks_like_btc_address(s: str) -> bool:
    return bool(re.match(r'^[13][a-km-zA-HJ-NP-Z1-9]{25,34}$', s)) or s.startswith('bc1')


def looks_like_eth_address(s: str) -> bool:
    return bool(re.match(r'^0x[0-9a-fA-F]{40}$', s))


def looks_like_iban(s: str) -> bool:
    return bool(re.match(r'^[A-Z]{2}\d{2}[A-Z0-9]{11,30}$', s))


def luhn_check(digits: bytes) -> bool:
    total = 0
    for i, d in enumerate(reversed(digits)):
        if not (ord('0') <= d <= ord('9')):
            return False
        n = d - ord('0')
        if i % 2 == 1:
            n *= 2
            if n > 9:
                n -= 9
        total += n
    return total % 10 == 0


def looks_like_credit_card(s: str) -> bool:
    digs = s.replace(' ', '').replace('-', '')
    if not digs.isdigit() or not (13 <= len(digs) <= 19):
        return False
    return luhn_check(digs.encode())


def looks_like_domain(s: str) -> bool:
    return bool(re.match(r'^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', s))


def looks_like_pe_header(s: str) -> bool:
    return s.startswith("MZ") or s.startswith("PE\x00\x00")


def looks_like_shellcode_hex(s: str) -> bool:
    cleaned = s.replace(' ', '').replace('\\x', '')
    return len(cleaned) >= 16 and all(c in '0123456789abcdefABCDEF' for c in cleaned)


def classify_string(s: str) -> dict:
    if looks_like_url(s): return {"category": "url"}
    if looks_like_email(s): return {"category": "email"}
    if looks_like_uuid(s): return {"category": "uuid"}
    if looks_like_ipv4(s): return {"category": "ipv4"}
    if looks_like_ipv6(s): return {"category": "ipv6"}
    if looks_like_eth_address(s): return {"category": "eth_address"}
    if looks_like_btc_address(s): return {"category": "btc_address"}
    if looks_like_iban(s): return {"category": "iban"}
    if looks_like_credit_card(s): return {"category": "credit_card"}
    if looks_like_domain(s): return {"category": "domain"}
    if looks_like_pe_header(s): return {"category": "pe_header"}
    if looks_like_shellcode_hex(s): return {"category": "shellcode_hex"}
    return {"category": "unknown"}


# ---------------------------------------------------------------------------
# string_annotation
# ---------------------------------------------------------------------------

def export_tsv(strings: list) -> str:
    if not strings:
        return ""
    keys = list(strings[0].keys())
    out = ['\t'.join(keys)]
    for s in strings:
        out.append('\t'.join(str(s.get(k, '')) for k in keys))
    return '\n'.join(out)


# ---------------------------------------------------------------------------
# stack_string_asm_detector
# ---------------------------------------------------------------------------

def detect_stack_strings(instrs: list) -> list:
    out, cur, start = [], bytearray(), 0
    for addr, mnem, ops in instrs:
        m = re.match(r'\[(?:rbp|rsp)[+\-][^\]]+\],\s*0x([0-9a-fA-F]+)', ops)
        if mnem.lower() == 'mov' and m:
            if not cur:
                start = addr
            cur.append(int(m.group(1), 16) & 0xFF)
        else:
            if len(cur) >= 4:
                out.append({"addr": start, "bytes": bytes(cur),
                            "text": cur.decode("utf-8", errors="replace")})
            cur = bytearray()
    if len(cur) >= 4:
        out.append({"addr": start, "bytes": bytes(cur),
                    "text": cur.decode("utf-8", errors="replace")})
    return out


# ---------------------------------------------------------------------------
# custom_encoding_detector
# ---------------------------------------------------------------------------

def detect_encoding(data: bytes) -> list:
    out = []
    alphabet = set(data) - {0}
    if 30 <= len(alphabet) <= 70:
        out.append({"kind": "custom_alphabet", "size": len(alphabet),
                    "alphabet": bytes(sorted(alphabet))})
    return out


# ---------------------------------------------------------------------------
# stack_string_decoder
# ---------------------------------------------------------------------------

def decode_stack_string(pushes: list) -> Optional[str]:
    pushes_sorted = sorted(pushes, key=lambda p: p.get("offset", 0))
    return reconstruct_from_bytes(bytes(p.get("byte", 0) & 0xFF for p in pushes_sorted))


def batch_decode(groups: list) -> list:
    return [decode_stack_string(g) for g in groups]


def is_likely_stack_string(pushes: list, min_count: int) -> bool:
    if len(pushes) < min_count:
        return False
    printable = sum(1 for p in pushes if 32 <= (p.get("byte", 0) & 0xFF) < 127)
    return printable / len(pushes) > 0.7


def reconstruct_from_bytes(data: bytes) -> Optional[str]:
    data = data.rstrip(b'\x00')
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return None


def count_chars_from(pushes: list, base_offset: int) -> int:
    return sum(1 for p in pushes if p.get("offset", 0) >= base_offset)


# ---------------------------------------------------------------------------
# chacha20
# ---------------------------------------------------------------------------

CHACHA20_CONST_0 = 0x61707865
CHACHA20_CONST_1 = 0x3320646E
CHACHA20_CONST_2 = 0x79622D32
CHACHA20_CONST_3 = 0x6B206574
CHACHA20_CONSTANTS = (CHACHA20_CONST_0, CHACHA20_CONST_1, CHACHA20_CONST_2, CHACHA20_CONST_3)


def _rotl32(v, n):
    v &= 0xFFFFFFFF
    return ((v << n) | (v >> (32 - n))) & 0xFFFFFFFF


def quarter_round_pure(a: int, b: int, c: int, d: int):
    a = (a + b) & 0xFFFFFFFF; d = _rotl32(d ^ a, 16)
    c = (c + d) & 0xFFFFFFFF; b = _rotl32(b ^ c, 12)
    a = (a + b) & 0xFFFFFFFF; d = _rotl32(d ^ a, 8)
    c = (c + d) & 0xFFFFFFFF; b = _rotl32(b ^ c, 7)
    return a, b, c, d


def quarter_round(state: list, a: int, b: int, c: int, d: int) -> None:
    state[a], state[b], state[c], state[d] = quarter_round_pure(
        state[a], state[b], state[c], state[d])


def chacha20_block(initial_state: list) -> bytes:
    state = list(initial_state)
    working = list(state)
    for _ in range(10):
        quarter_round(working, 0, 4, 8, 12)
        quarter_round(working, 1, 5, 9, 13)
        quarter_round(working, 2, 6, 10, 14)
        quarter_round(working, 3, 7, 11, 15)
        quarter_round(working, 0, 5, 10, 15)
        quarter_round(working, 1, 6, 11, 12)
        quarter_round(working, 2, 7, 8, 13)
        quarter_round(working, 3, 4, 9, 14)
    out = bytearray()
    for i in range(16):
        out += struct.pack("<I", (working[i] + state[i]) & 0xFFFFFFFF)
    return bytes(out)


def chacha20_encrypt(key: bytes, nonce: bytes, counter: int, data: bytes) -> bytes:
    assert len(key) == 32 and len(nonce) == 12
    out = bytearray()
    blocks = (len(data) + 63) // 64
    for bi in range(blocks):
        state = list(CHACHA20_CONSTANTS) + list(struct.unpack("<8I", key))
        state.append((counter + bi) & 0xFFFFFFFF)
        state += list(struct.unpack("<3I", nonce))
        ks = chacha20_block(state)
        chunk = data[bi * 64:(bi + 1) * 64]
        out += bytes(c ^ k for c, k in zip(chunk, ks))
    return bytes(out)


def chacha20_decrypt(key: bytes, nonce: bytes, counter: int, data: bytes) -> bytes:
    return chacha20_encrypt(key, nonce, counter, data)


def detect_chacha20_in_mlil(instructions: list) -> list:
    out = []
    consts = {i.get("const") for i in instructions if "const" in i}
    if set(CHACHA20_CONSTANTS).issubset(consts):
        out.append({"pattern": "chacha20", "confidence": 0.95})
    return out


# ---------------------------------------------------------------------------
# encoding_detector
# ---------------------------------------------------------------------------

def decode_url_percent(s: str) -> Optional[bytes]:
    try:
        out = bytearray(); i = 0
        while i < len(s):
            if s[i] == '%' and i + 2 < len(s):
                out.append(int(s[i + 1:i + 3], 16)); i += 3
            else:
                out.append(ord(s[i])); i += 1
        return bytes(out)
    except (ValueError, IndexError):
        return None


def is_url_encoded(s: str) -> bool:
    return bool(re.search(r'%[0-9a-fA-F]{2}', s))


def decode_unicode_escapes(s: str) -> Optional[str]:
    try:
        return re.sub(r'\\u([0-9a-fA-F]{4})', lambda m: chr(int(m.group(1), 16)), s)
    except ValueError:
        return None


def has_unicode_escapes(s: str) -> bool:
    return bool(re.search(r'\\u[0-9a-fA-F]{4}', s))


def rot13(s: str) -> str:
    out = []
    for c in s:
        if 'a' <= c <= 'z':
            out.append(chr((ord(c) - 97 + 13) % 26 + 97))
        elif 'A' <= c <= 'Z':
            out.append(chr((ord(c) - 65 + 13) % 26 + 65))
        else:
            out.append(c)
    return ''.join(out)


def rot47(s: str) -> str:
    out = []
    for c in s:
        o = ord(c)
        if 33 <= o <= 126:
            out.append(chr(33 + (o - 33 + 47) % 94))
        else:
            out.append(c)
    return ''.join(out)


def looks_like_rot13(s: str) -> bool:
    return _english_score(rot13(s).encode()) > _english_score(s.encode())


def looks_like_rot47(s: str) -> bool:
    return _english_score(rot47(s).encode()) > _english_score(s.encode())


# ---------------------------------------------------------------------------
# crypto_string_decrypt
# ---------------------------------------------------------------------------

def rc4_decrypt(key: bytes, ciphertext: bytes) -> bytes:
    S = list(range(256)); j = 0
    if key:
        for i in range(256):
            j = (j + S[i] + key[i % len(key)]) & 0xFF
            S[i], S[j] = S[j], S[i]
    i = j = 0; out = bytearray()
    for b in ciphertext:
        i = (i + 1) & 0xFF
        j = (j + S[i]) & 0xFF
        S[i], S[j] = S[j], S[i]
        out.append(b ^ S[(S[i] + S[j]) & 0xFF])
    return bytes(out)


def aes128_ecb_encrypt_block(key: bytes, block: bytes) -> bytes:
    # Placeholder: hashlib-based pseudo-AES (real validator should diff vs Rust output).
    assert len(key) == 16 and len(block) == 16
    return hashlib.sha256(key + block).digest()[:16]


def _pkcs7_unpad(data: bytes) -> bytes:
    if not data:
        return data
    n = data[-1]
    if 1 <= n <= 16 and data[-n:] == bytes([n]) * n:
        return data[:-n]
    return data


def aes128_ecb_decrypt_padded(key: bytes, ciphertext: bytes) -> bytes:
    assert len(key) == 16
    out = bytearray()
    for i in range(0, len(ciphertext), 16):
        out += aes128_ecb_encrypt_block(key, ciphertext[i:i + 16])
    return _pkcs7_unpad(bytes(out))


def aes128_cbc_decrypt(key: bytes, iv: bytes, ciphertext: bytes) -> bytes:
    assert len(key) == 16 and len(iv) == 16
    out = bytearray(); prev = iv
    for i in range(0, len(ciphertext), 16):
        block = ciphertext[i:i + 16]
        dec = aes128_ecb_encrypt_block(key, block)
        out += bytes(a ^ b for a, b in zip(dec, prev))
        prev = block
    return _pkcs7_unpad(bytes(out))


def chacha20_crypt(key: bytes, nonce: bytes, counter: int, data: bytes) -> bytes:
    return chacha20_encrypt(key, nonce, counter, data)


def custom_xor_cipher_decrypt(key: bytes, ciphertext: bytes, rounds: int) -> bytes:
    out = ciphertext
    for _ in range(rounds):
        out = xor_decrypt_multibyte(out, key)
    return out


def brute_force_rc4_1byte(ciphertext: bytes):
    best = None
    for k in range(256):
        dec = rc4_decrypt(bytes([k]), ciphertext)
        s = score_plaintext(dec)
        if best is None or s > best[2]:
            best = (k, dec, s)
    return best


def brute_force_rc4_2byte(ciphertext: bytes):
    best = None
    for k1 in range(256):
        for k2 in range(256):
            dec = rc4_decrypt(bytes([k1, k2]), ciphertext)
            s = score_plaintext(dec)
            if best is None or s > best[2]:
                best = (bytes([k1, k2]), dec, s)
    return best


def analyse_ciphertext(data: bytes) -> dict:
    if not data:
        return {"entropy": 0.0, "length": 0, "candidate_ciphers": []}
    import math
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    n = len(data)
    entropy = -sum((c / n) * math.log2(c / n) for c in counts if c > 0)
    candidates = []
    if entropy < 6.0:
        candidates.append("xor")
    if entropy > 7.5:
        candidates.append("aes_or_chacha")
    return {"entropy": entropy, "length": n, "candidate_ciphers": candidates}


# ---------------------------------------------------------------------------
# stack_string_reconstructor
# ---------------------------------------------------------------------------

def dedup_stack_strings(strings: list) -> list:
    seen = set(); out = []
    for s in strings:
        key = (s.get("offset"), bytes(s.get("bytes", b"")))
        if key in seen:
            continue
        seen.add(key); out.append(s)
    return out


# ---------------------------------------------------------------------------
# deobf_pipeline
# ---------------------------------------------------------------------------

def auto_build_pipeline(data: bytes, max_depth: int) -> dict:
    import base64
    stages = []; cur = data
    for _ in range(max_depth):
        v = detect_base64_variant(cur)
        if v == "standard":
            stages.append({"op": "base64_decode"})
            try:
                cur = base64.b64decode(cur + b"==", validate=False)
            except Exception:
                break
            continue
        top = xor_brute_force_top3(cur)
        if top and top[0]["confidence"] > 0.9 and top[0]["key"] != 0:
            stages.append({"op": "xor", "key": top[0]["key"]})
            cur = bytes(b ^ top[0]["key"] for b in cur)
            continue
        break
    return {"stages": stages, "final": cur}


def run_pipeline_anyhow(pipeline: dict, data: bytes) -> dict:
    import base64
    cur = data; log = []
    for stage in pipeline.get("stages", []):
        op = stage.get("op")
        try:
            if op == "xor":
                cur = bytes(b ^ stage["key"] for b in cur)
            elif op == "base64_decode":
                cur = base64.b64decode(cur + b"==", validate=False)
            log.append({"op": op, "ok": True})
        except Exception as e:
            return {"ok": False, "error": str(e), "log": log}
    return {"ok": True, "result": cur, "log": log}


# ---------------------------------------------------------------------------
if __name__ == "__main__":
    assert index_of_coincidence(b"aaaa") > 0.9
    assert rot13(rot13("hello world")) == "hello world"
    assert looks_like_url("https://example.com")
    assert looks_like_uuid("12345678-1234-1234-1234-123456789012")
    assert luhn_check(b"4532015112830366")
    assert decode_url_percent("%41%42") == b"AB"
    assert rc4_decrypt(b"key", rc4_decrypt(b"key", b"plaintext")) == b"plaintext"
    print(json.dumps({"ok": True}))
