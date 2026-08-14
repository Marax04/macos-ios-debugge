"""
rustre-crypto-whitebox validators
Python stdlib implementations of the functions documented in
validation/reports/rustre-crypto-whitebox.md

Each validator_NAME(input) -> output mirrors the Rust function semantics.
"""
from __future__ import annotations
import math
import hashlib
import struct
from typing import Optional

# ---------------------------------------------------------------------------
# AES constants
# ---------------------------------------------------------------------------

AES_SBOX = [
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
]

AES_SBOX_INV = [0] * 256
for _i, _v in enumerate(AES_SBOX):
    AES_SBOX_INV[_v] = _i

# AES round constants
RCON = [0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36]

# SM4 S-box
SM4_SBOX = [
    0xd6,0x90,0xe9,0xfe,0xcc,0xe1,0x3d,0xb7,0x16,0xb6,0x14,0xc2,0x28,0xfb,0x2c,0x05,
    0x2b,0x67,0x9a,0x76,0x2a,0xbe,0x04,0xc3,0xaa,0x44,0x13,0x26,0x49,0x86,0x06,0x99,
    0x9c,0x42,0x50,0xf4,0x91,0xef,0x98,0x7a,0x33,0x54,0x0b,0x43,0xed,0xcf,0xac,0x62,
    0xe4,0xb3,0x1c,0xa9,0xc9,0x08,0xe8,0x95,0x80,0xdf,0x94,0xfa,0x75,0x8f,0x3f,0xa6,
    0x47,0x07,0xa7,0xfc,0xf3,0x73,0x17,0xba,0x83,0x59,0x3c,0x19,0xe6,0x85,0x4f,0xa8,
    0x68,0x6b,0x81,0xb2,0x71,0x64,0xda,0x8b,0xf8,0xeb,0x0f,0x4b,0x70,0x56,0x9d,0x35,
    0x1e,0x24,0x0e,0x5e,0x63,0x58,0xd1,0xa2,0x25,0x22,0x7c,0x3b,0x01,0x21,0x78,0x87,
    0xd4,0x00,0x46,0x57,0x9f,0xd3,0x27,0x52,0x4c,0x36,0x02,0xe7,0xa0,0xc4,0xc8,0x9e,
    0xea,0xbf,0x8a,0xd2,0x40,0xc7,0x38,0xb5,0xa3,0xf7,0xf2,0xce,0xf9,0x61,0x15,0xa1,
    0xe0,0xae,0x5d,0xa4,0x9b,0x34,0x1a,0x55,0xad,0x93,0x32,0x30,0xf5,0x8c,0xb1,0xe3,
    0x1d,0xf6,0xe2,0x2e,0x82,0x66,0xca,0x60,0xc0,0x29,0x23,0xab,0x0d,0x53,0x4e,0x6f,
    0xd5,0xdb,0x37,0x45,0xde,0xfd,0x8e,0x2f,0x03,0xff,0x6a,0x72,0x6d,0x6c,0x5b,0x51,
    0x8d,0x1b,0xaf,0x92,0xbb,0xdd,0xbc,0x7f,0x11,0xd9,0x5c,0x41,0x1f,0x10,0x5a,0xd8,
    0x0a,0xc1,0x31,0x88,0xa5,0xcd,0x7b,0xbd,0x2d,0x74,0xd0,0x12,0xb8,0xe5,0xb4,0xb0,
    0x89,0x69,0x97,0x4a,0x0c,0x96,0x77,0x7e,0x65,0xb9,0xf1,0x09,0xc5,0x6e,0xc6,0x84,
    0x18,0xf0,0x7d,0xec,0x3a,0xdc,0x4d,0x20,0x79,0xee,0x5f,0x3e,0xd7,0xcb,0x39,0x48,
]

# SM4 FK constants
SM4_FK = [0xa3b1bac6, 0x56aa3350, 0x677d9197, 0xb27022dc]

# Known crypto constants for scanning
KNOWN_CRYPTO_CONSTANTS = {
    # SHA-256 K table (first 8)
    "sha256_k": [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
        0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    ],
    # Poly1305 prime: 2^130 - 5
    "poly1305_prime": 0x3fffffffffffffffffffffffffffffffb,
    # ChaCha20 "expa" constant
    "chacha_expa": b"expand 32-byte k",
}

SHA256_K = [
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,
    0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0x76f988da,0x983e5152,0xa831c66d,0xb00327c8,
    0xbf597fc7,0xc19bf174,0xe49b69c1,0xefbe4786,
    0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,
    0x5cb0a9dc,0x76f988da,0x983e5152,0xa831c66d,
    0xb00327c8,0xbf597fc7,0xc19bf174,0xe49b69c1,
    0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,
    0x4a7484aa,0x5cb0a9dc,0x76f988da,0x983e5152,
    0xa831c66d,0xb00327c8,0xbf597fc7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,
    0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,
    0xc19bf174,0xe49b69c1,0xefbe4786,0x0fc19dc6,
    0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,
    0x76f988da,0x983e5152,0xa831c66d,0xb00327c8,
]

# ---------------------------------------------------------------------------
# GF(2^8) helpers
# ---------------------------------------------------------------------------

def _gf_mul(a: int, b: int) -> int:
    """Multiply two bytes in GF(2^8) with AES polynomial 0x11b."""
    p = 0
    for _ in range(8):
        if b & 1:
            p ^= a
        hi = a & 0x80
        a = (a << 1) & 0xFF
        if hi:
            a ^= 0x1b
        b >>= 1
    return p


def _gf_inv(a: int) -> int:
    """Multiplicative inverse in GF(2^8)."""
    if a == 0:
        return 0
    return pow(a, 254, 257) if False else _gf_inv_table[a]


# Build inverse table once
_gf_inv_table = [0] * 256
for _x in range(1, 256):
    for _y in range(1, 256):
        if _gf_mul(_x, _y) == 1:
            _gf_inv_table[_x] = _y
            break

# ---------------------------------------------------------------------------
# S-box construction from GF(2^8)
# ---------------------------------------------------------------------------

def validator_build_aes_sbox_from_gf() -> list[int]:
    """Costruisce la S-box AES da GF(2^8)."""
    sbox = []
    for b in range(256):
        inv = _gf_inv_table[b]
        # Affine transform
        s = inv ^ _rotate_left8(inv, 1) ^ _rotate_left8(inv, 2) ^ \
            _rotate_left8(inv, 3) ^ _rotate_left8(inv, 4) ^ 0x63
        sbox.append(s & 0xFF)
    return sbox


def _rotate_left8(b: int, n: int) -> int:
    return ((b << n) | (b >> (8 - n))) & 0xFF


def validator_build_aes_sbox_inv_from_gf() -> list[int]:
    """Costruisce la S-box inversa AES da GF(2^8)."""
    sbox = validator_build_aes_sbox_from_gf()
    inv = [0] * 256
    for i, v in enumerate(sbox):
        inv[v] = i
    return inv

# ---------------------------------------------------------------------------
# AES core operations
# ---------------------------------------------------------------------------

def validator_sub_bytes(state: list[int]) -> list[int]:
    """Applica SubBytes AES."""
    return [AES_SBOX[b] for b in state]


def validator_inv_sub_bytes(state: list[int]) -> list[int]:
    """Applica InvSubBytes AES."""
    return [AES_SBOX_INV[b] for b in state]


def _mix_single_column(col: list[int]) -> list[int]:
    a = col
    return [
        _gf_mul(0x02, a[0]) ^ _gf_mul(0x03, a[1]) ^ a[2] ^ a[3],
        a[0] ^ _gf_mul(0x02, a[1]) ^ _gf_mul(0x03, a[2]) ^ a[3],
        a[0] ^ a[1] ^ _gf_mul(0x02, a[2]) ^ _gf_mul(0x03, a[3]),
        _gf_mul(0x03, a[0]) ^ a[1] ^ a[2] ^ _gf_mul(0x02, a[3]),
    ]


def _inv_mix_single_column(col: list[int]) -> list[int]:
    a = col
    return [
        _gf_mul(0x0e, a[0]) ^ _gf_mul(0x0b, a[1]) ^ _gf_mul(0x0d, a[2]) ^ _gf_mul(0x09, a[3]),
        _gf_mul(0x09, a[0]) ^ _gf_mul(0x0e, a[1]) ^ _gf_mul(0x0b, a[2]) ^ _gf_mul(0x0d, a[3]),
        _gf_mul(0x0d, a[0]) ^ _gf_mul(0x09, a[1]) ^ _gf_mul(0x0e, a[2]) ^ _gf_mul(0x0b, a[3]),
        _gf_mul(0x0b, a[0]) ^ _gf_mul(0x0d, a[1]) ^ _gf_mul(0x09, a[2]) ^ _gf_mul(0x0e, a[3]),
    ]


def validator_aes_mix_columns(state: list[int]) -> list[int]:
    """Applica MixColumns AES su stato 16 byte."""
    out = list(state)
    for c in range(4):
        col = [state[r * 4 + c] for r in range(4)]
        mixed = _mix_single_column(col)
        for r in range(4):
            out[r * 4 + c] = mixed[r]
    return out


def validator_aes_mix_columns_inverse(state: list[int]) -> list[int]:
    """Applica InvMixColumns AES."""
    out = list(state)
    for c in range(4):
        col = [state[r * 4 + c] for r in range(4)]
        mixed = _inv_mix_single_column(col)
        for r in range(4):
            out[r * 4 + c] = mixed[r]
    return out


def validator_add_round_key(state: list[int], rk: list[int]) -> list[int]:
    """XOR round key sullo stato AES."""
    return [s ^ k for s, k in zip(state, rk)]


def _shift_rows(state: list[int]) -> list[int]:
    s = list(state)
    # Row 1: shift left 1
    s[1], s[5], s[9], s[13] = s[5], s[9], s[13], s[1]
    # Row 2: shift left 2
    s[2], s[6], s[10], s[14] = s[10], s[14], s[2], s[6]
    # Row 3: shift left 3
    s[3], s[7], s[11], s[15] = s[15], s[3], s[7], s[11]
    return s


def _inv_shift_rows(state: list[int]) -> list[int]:
    s = list(state)
    s[1], s[5], s[9], s[13] = s[13], s[1], s[5], s[9]
    s[2], s[6], s[10], s[14] = s[10], s[14], s[2], s[6]
    s[3], s[7], s[11], s[15] = s[7], s[11], s[15], s[3]
    return s

# ---------------------------------------------------------------------------
# AES-128 key schedule
# ---------------------------------------------------------------------------

def validator_aes128_key_schedule(key: bytes) -> list[int]:
    """Genera l'intera key schedule AES-128 (176 byte)."""
    w = list(key[:16])
    for i in range(4, 44):
        temp = w[(i - 1) * 4: i * 4]
        if i % 4 == 0:
            # RotWord
            temp = temp[1:] + temp[:1]
            # SubWord
            temp = [AES_SBOX[b] for b in temp]
            temp[0] ^= RCON[i // 4]
        w.extend(t ^ p for t, p in zip(temp, w[(i - 4) * 4:(i - 3) * 4]))
    return w


def validator_aes_encrypt_128(key: bytes, plaintext: bytes) -> bytes:
    """Cifra AES-128 reference."""
    ks = validator_aes128_key_schedule(key)
    state = list(plaintext[:16])
    # Initial round key
    state = validator_add_round_key(state, ks[0:16])
    for rnd in range(1, 10):
        state = validator_sub_bytes(state)
        state = _shift_rows(state)
        state = validator_aes_mix_columns(state)
        state = validator_add_round_key(state, ks[rnd * 16:(rnd + 1) * 16])
    # Final round (no MixColumns)
    state = validator_sub_bytes(state)
    state = _shift_rows(state)
    state = validator_add_round_key(state, ks[160:176])
    return bytes(state)


def validator_aes_decrypt_128(key: bytes, ciphertext: bytes) -> bytes:
    """Decifra AES-128 reference."""
    ks = validator_aes128_key_schedule(key)
    state = list(ciphertext[:16])
    state = validator_add_round_key(state, ks[160:176])
    for rnd in range(9, 0, -1):
        state = _inv_shift_rows(state)
        state = validator_inv_sub_bytes(state)
        state = validator_add_round_key(state, ks[rnd * 16:(rnd + 1) * 16])
        state = validator_aes_mix_columns_inverse(state)
    state = _inv_shift_rows(state)
    state = validator_inv_sub_bytes(state)
    state = validator_add_round_key(state, ks[0:16])
    return bytes(state)


def validator_aes128_verify_roundtrip(key: bytes, plaintext: bytes) -> bool:
    """Verifica encrypt/decrypt roundtrip AES-128."""
    ct = validator_aes_encrypt_128(key, plaintext)
    pt = validator_aes_decrypt_128(key, ct)
    return pt == plaintext[:16]

# ---------------------------------------------------------------------------
# Key schedule reverse AES-128
# ---------------------------------------------------------------------------

def _sub_word(w: list[int]) -> list[int]:
    return [AES_SBOX[b] for b in w]


def _rot_word(w: list[int]) -> list[int]:
    return w[1:] + w[:1]


def validator_aes_round_key_reverse_128(last_round_key: bytes) -> bytes:
    """Inverte un singolo step della key schedule AES-128 (round 10 -> round 9)."""
    rk = list(last_round_key[:16])
    # W[40..43] -> W[36..39]
    # W[i] = W[i+4] ^ W[i] but we need W[i-4]
    # For round 10: rk[12..15] = W[43]; rk[0..3] = W[40]
    # W[36] = W[40] ^ SubWord(RotWord(W[39])) ^ Rcon[10]
    # We step backwards
    w = [rk[i*4:(i+1)*4] for i in range(4)]
    # w[0] = W40, w[1]=W41, w[2]=W42, w[3]=W43
    # recover previous round's W36..W39
    # W[i] = W[i-4] ^ W[i] for i%4 != 0
    # W[i] = W[i-4] ^ SubWord(RotWord(W[i-1])) ^ Rcon for i%4==0
    prev_w = [None] * 4
    prev_w[3] = [w[2][j] ^ w[3][j] for j in range(4)]
    prev_w[2] = [w[1][j] ^ w[2][j] for j in range(4)]
    prev_w[1] = [w[0][j] ^ w[1][j] for j in range(4)]
    sw = _sub_word(_rot_word(prev_w[3]))
    prev_w[0] = [w[0][j] ^ sw[j] ^ (RCON[10] if j == 0 else 0) for j in range(4)]
    result = []
    for pw in prev_w:
        result.extend(pw)
    return bytes(result)


def validator_reverse_128(round_keys: bytes) -> Optional[bytes]:
    """Inverte l'intera key schedule AES-128 per ricavare la chiave originale."""
    if len(round_keys) < 176:
        return None
    last_rk = round_keys[160:176]
    return validator_from_last_round_key_128(last_rk)


def validator_from_last_round_key_128(last_rk: bytes) -> Optional[bytes]:
    """Ricava la chiave originale dall'ultimo round key AES-128."""
    if len(last_rk) < 16:
        return None
    rk = list(last_rk[:16])
    for rnd in range(10, 0, -1):
        w = [rk[i*4:(i+1)*4] for i in range(4)]
        prev_w = [None] * 4
        prev_w[3] = [w[2][j] ^ w[3][j] for j in range(4)]
        prev_w[2] = [w[1][j] ^ w[2][j] for j in range(4)]
        prev_w[1] = [w[0][j] ^ w[1][j] for j in range(4)]
        sw = _sub_word(_rot_word(prev_w[3]))
        prev_w[0] = [w[0][j] ^ sw[j] ^ (RCON[rnd] if j == 0 else 0) for j in range(4)]
        rk = []
        for pw in prev_w:
            rk.extend(pw)
    return bytes(rk)

# ---------------------------------------------------------------------------
# Key schedule utilities
# ---------------------------------------------------------------------------

def validator_looks_like_key_schedule(data: bytes) -> bool:
    """Euristica: verifica se i dati assomigliano a una key schedule AES."""
    if len(data) not in (176, 240):
        return False
    # Check that data has high entropy and no long runs of same byte
    freq = [0] * 256
    for b in data:
        freq[b] += 1
    unique = sum(1 for f in freq if f > 0)
    return unique >= 64


def validator_is_permutation(data: bytes) -> bool:
    """Verifica se i dati formano una permutazione su 256 valori."""
    if len(data) != 256:
        return False
    return sorted(data) == list(range(256))

# ---------------------------------------------------------------------------
# AES-256 key schedule
# ---------------------------------------------------------------------------

def validator_aes256_expand(key: bytes) -> bytes:
    """Espande una chiave AES-256 in 15 round keys (240 byte)."""
    assert len(key) == 32
    w = list(key)
    i = 8
    while len(w) < 240:
        temp = w[-4:]
        if i % 8 == 0:
            temp = _rot_word(temp)
            temp = _sub_word(temp)
            temp[0] ^= RCON[i // 8]
        elif i % 8 == 4:
            temp = _sub_word(temp)
        w.extend(t ^ p for t, p in zip(temp, w[-32:-28]))
        i += 1
    return bytes(w[:240])


def validator_aes256_reverse_from_all(round_keys: bytes) -> Optional[bytes]:
    """Inverte la key schedule AES-256 da tutti i round keys."""
    if len(round_keys) < 240:
        return None
    return bytes(round_keys[:32])


def validator_aes256_from_last_round_key(last_rk: bytes) -> Optional[bytes]:
    """Ricava la chiave AES-256 dall'ultimo round key (non invertibile senza stato precedente)."""
    # AES-256 last round key alone is not sufficient to recover the original key
    # Return None to indicate this
    return None

# ---------------------------------------------------------------------------
# SM4
# ---------------------------------------------------------------------------

def validator_is_sm4_sbox(data: bytes) -> bool:
    """Riconosce la S-box SM4 nei dati."""
    if len(data) < 256:
        return False
    return list(data[:256]) == SM4_SBOX


def validator_find_fk_constants(binary: bytes) -> list[int]:
    """Cerca le costanti FK di SM4 nel binario."""
    hits = []
    for fk in SM4_FK:
        fk_bytes = struct.pack(">I", fk)
        idx = 0
        while True:
            pos = binary.find(fk_bytes, idx)
            if pos == -1:
                break
            hits.append(pos)
            idx = pos + 1
    return hits

# ---------------------------------------------------------------------------
# FaultCollector / DFA base
# ---------------------------------------------------------------------------

def validator_xor_diff(a: bytes, b: bytes) -> Optional[bytes]:
    """Calcola la differenza XOR tra due ciphertext."""
    if len(a) != len(b):
        return None
    return bytes(x ^ y for x, y in zip(a, b))


def validator_is_valid_fault_pattern(diff: bytes) -> bool:
    """Verifica se il pattern di differenza è valido per DFA su AES round 9."""
    if len(diff) != 16:
        return False
    nonzero = sum(1 for b in diff if b != 0)
    # AES round 9 fault affects exactly 4 bytes (one diagonal)
    return nonzero == 4


def validator_hamming_weight(b: int) -> int:
    """Peso di Hamming di un byte."""
    return bin(b).count('1')


def validator_hamming_distance(a: bytes, b: bytes) -> int:
    """Distanza di Hamming tra due slice."""
    return sum(validator_hamming_weight(x ^ y) for x, y in zip(a, b))

# ---------------------------------------------------------------------------
# DCA / Pearson correlation
# ---------------------------------------------------------------------------

def validator_pearson_correlation(x: list[float], y: list[float]) -> float:
    """Calcola la correlazione di Pearson tra due serie."""
    n = len(x)
    if n == 0 or len(y) != n:
        return 0.0
    mx = sum(x) / n
    my = sum(y) / n
    num = sum((xi - mx) * (yi - my) for xi, yi in zip(x, y))
    dx = math.sqrt(sum((xi - mx) ** 2 for xi in x))
    dy = math.sqrt(sum((yi - my) ** 2 for yi in y))
    if dx == 0 or dy == 0:
        return 0.0
    return num / (dx * dy)


def validator_hamming_weight_model(input_byte: int, key_guess: int, round_: int) -> float:
    """Modello Hamming weight per ipotesi di chiave DCA."""
    intermediate = AES_SBOX[input_byte ^ key_guess]
    return float(validator_hamming_weight(intermediate))

# ---------------------------------------------------------------------------
# S-box analysis
# ---------------------------------------------------------------------------

def validator_boolean_nonlinearity(truth_table: bytes) -> int:
    """Calcola la non-linearità booleana tramite Walsh-Hadamard."""
    n = len(truth_table)
    if n == 0:
        return 0
    # Convert to +1/-1
    f = [1 - 2 * int(b) for b in truth_table]
    # Fast Walsh-Hadamard transform
    h = list(f)
    size = n
    step = 1
    while step < size:
        for i in range(0, size, step * 2):
            for j in range(step):
                u = h[i + j]
                v = h[i + j + step]
                h[i + j] = u + v
                h[i + j + step] = u - v
        step <<= 1
    max_abs = max(abs(v) for v in h)
    return (n - max_abs) // 2


def validator_differential_uniformity(sbox: bytes) -> int:
    """Calcola l'uniformità differenziale (DDT max)."""
    n = len(sbox)
    max_val = 0
    for da in range(1, n):
        counts = [0] * n
        for x in range(n):
            db = sbox[x ^ da] ^ sbox[x]
            counts[db] += 1
        m = max(counts)
        if m > max_val:
            max_val = m
    return max_val


def validator_algebraic_degree(sbox: bytes) -> int:
    """Calcola il grado algebrico via ANF."""
    n = len(sbox)
    bits = n.bit_length() - 1
    # Mobius transform to get ANF
    f = list(sbox)
    for i in range(bits):
        for j in range(n):
            if j & (1 << i):
                f[j] ^= f[j ^ (1 << i)]
    # Max degree of non-zero coefficient
    max_deg = 0
    for mask, coef in enumerate(f):
        if coef:
            deg = bin(mask).count('1')
            if deg > max_deg:
                max_deg = deg
    return max_deg


def validator_compute_lat(sbox: bytes) -> list[list[int]]:
    """Calcola la Linear Approximation Table completa."""
    n = len(sbox)
    lat = [[0] * n for _ in range(n)]
    for a in range(n):
        for b in range(n):
            count = 0
            for x in range(n):
                px = bin(a & x).count('1') % 2
                py = bin(b & sbox[x]).count('1') % 2
                if px == py:
                    count += 1
            lat[a][b] = count - n // 2
    return lat


def validator_lat_max_bias(sbox: bytes) -> int:
    """Massimo bias nella LAT."""
    lat = validator_compute_lat(sbox)
    return max(abs(v) for row in lat for v in row if not (row == lat[0] and v == lat[0][0]))


def validator_compute_ddt(sbox: bytes) -> list[list[int]]:
    """Calcola la Difference Distribution Table."""
    n = len(sbox)
    ddt = [[0] * n for _ in range(n)]
    for da in range(n):
        for x in range(n):
            db = sbox[x ^ da] ^ sbox[x]
            ddt[da][db] += 1
    return ddt

# ---------------------------------------------------------------------------
# is_bijective / is_affinely_equivalent_to_sbox
# ---------------------------------------------------------------------------

def validator_is_bijective(table: bytes) -> bool:
    """Verifica biettività di una tabella 256-byte."""
    if len(table) != 256:
        return False
    return len(set(table)) == 256


def validator_is_affinely_equivalent_to_sbox(table: bytes) -> bool:
    """Verifica equivalenza affine con la S-box AES (check semplificato)."""
    if len(table) != 256:
        return False
    # Check differential uniformity == 4 (same as AES S-box)
    return validator_differential_uniformity(table) == 4

# ---------------------------------------------------------------------------
# CryptoIdentifier
# ---------------------------------------------------------------------------

def validator_classify_by_entropy(func_bytes: bytes) -> float:
    """Classifica per entropia di Shannon."""
    if not func_bytes:
        return 0.0
    freq = [0] * 256
    for b in func_bytes:
        freq[b] += 1
    n = len(func_bytes)
    h = 0.0
    for f in freq:
        if f > 0:
            p = f / n
            h -= p * math.log2(p)
    return h


def validator_find_sha256_k_table(binary: bytes) -> list[int]:
    """Cerca la tabella K di SHA-256."""
    hits = []
    # Search for first K constant
    needle = struct.pack("<I", SHA256_K[0])
    idx = 0
    while True:
        pos = binary.find(needle, idx)
        if pos == -1:
            break
        # Verify at least 8 consecutive K values
        valid = True
        for i, k in enumerate(SHA256_K[:8]):
            expected = struct.pack("<I", k)
            if binary[pos + i*4: pos + i*4 + 4] != expected:
                valid = False
                break
        if valid:
            hits.append(pos)
        idx = pos + 1
    return hits


def validator_find_poly1305_prime(binary: bytes) -> list[int]:
    """Cerca il primo di Poly1305 nel binario."""
    # 2^130 - 5 low 64 bits: 0xFFFFFFFFFFFFFFFB
    prime_low = struct.pack("<Q", 0xFFFFFFFFFFFFFFFB)
    hits = []
    idx = 0
    while True:
        pos = binary.find(prime_low, idx)
        if pos == -1:
            break
        hits.append(pos)
        idx = pos + 1
    return hits


def validator_find_chacha_expa(binary: bytes) -> list[int]:
    """Cerca la costante 'expa' di ChaCha20."""
    needle = b"expa"
    hits = []
    idx = 0
    while True:
        pos = binary.find(needle, idx)
        if pos == -1:
            break
        hits.append(pos)
        idx = pos + 1
    return hits


def validator_scan_crypto_constants(binary: bytes) -> list[dict]:
    """Scansiona il binario per costanti crittografiche note."""
    hits = []
    for offset in validator_find_sha256_k_table(binary):
        hits.append({"algorithm": "SHA-256", "offset": offset, "constant": "K_table"})
    for offset in validator_find_poly1305_prime(binary):
        hits.append({"algorithm": "Poly1305", "offset": offset, "constant": "prime_low"})
    for offset in validator_find_chacha_expa(binary):
        hits.append({"algorithm": "ChaCha20", "offset": offset, "constant": "expa"})
    return hits


def validator_identify_constants(binary: bytes) -> list[dict]:
    """Identifica costanti crittografiche note nel binario."""
    return validator_scan_crypto_constants(binary)

# ---------------------------------------------------------------------------
# Table extraction helpers
# ---------------------------------------------------------------------------

def validator_is_aes_t_table(table: list[int]) -> bool:
    """Verifica se una tabella a 32-bit è una T-table AES standard."""
    if len(table) != 256:
        return False
    # T0[i] = [2*S[i], S[i], S[i], 3*S[i]] packed as big-endian u32
    for i in range(256):
        s = AES_SBOX[i]
        expected = (
            (_gf_mul(2, s) << 24) |
            (s << 16) |
            (s << 8) |
            _gf_mul(3, s)
        )
        if table[i] != expected:
            return False
    return True


def validator_extract_tbox_key(table: bytes) -> Optional[int]:
    """Estrae il byte di chiave XORato in una T-box."""
    if len(table) != 256:
        return None
    # T-box[x] = S[x ^ k]; find k such that applying S^-1 yields a permutation
    for k in range(256):
        candidate = bytes(AES_SBOX_INV[table[x]] ^ x for x in range(256))
        if len(set(candidate)) == 1:
            return k
    return None


def validator_aes_likeness_score(tables: list[bytes]) -> float:
    """Score globale di somiglianza con struttura AES."""
    if not tables:
        return 0.0
    scores = []
    for t in tables:
        if len(t) != 256:
            scores.append(0.0)
            continue
        bij = 1.0 if validator_is_bijective(t) else 0.0
        nl = validator_boolean_nonlinearity(t)
        nl_score = nl / 112.0  # AES S-box nonlinearity = 112
        scores.append((bij + min(nl_score, 1.0)) / 2.0)
    return sum(scores) / len(scores)

# ---------------------------------------------------------------------------
# DES S-box classification
# ---------------------------------------------------------------------------

# DES S-boxes (compressed: 4-bit output, 6-bit input)
DES_SBOXES = [
    # S1
    [14,4,13,1,2,15,11,8,3,10,6,12,5,9,0,7,
      0,15,7,4,14,2,13,1,10,6,12,11,9,5,3,8,
      4,1,14,8,13,6,2,11,15,12,9,7,3,10,5,0,
      15,12,8,2,4,9,1,7,5,11,3,14,10,0,6,13],
]


def validator_classify_des_sbox(data: bytes) -> Optional[int]:
    """Classifica una tabella come S-box DES (0-7)."""
    if len(data) < 64:
        return None
    candidate = list(data[:64])
    for idx, sbox in enumerate(DES_SBOXES):
        if candidate == sbox:
            return idx
    return None

# ---------------------------------------------------------------------------
# Entropy helpers for aes_wb_analyzer
# ---------------------------------------------------------------------------

def validator_shannon_entropy_u32(freq: list[int], n: int) -> float:
    """Entropia di Shannon da frequenze."""
    if n == 0:
        return 0.0
    h = 0.0
    for f in freq:
        if f > 0:
            p = f / n
            h -= p * math.log2(p)
    return h


def validator_bytes_entropy(data: bytes) -> float:
    """Entropia di Shannon di uno slice di byte."""
    return validator_classify_by_entropy(data)


def validator_compute_chi_squared(freq: list[int], n: int) -> float:
    """Statistica chi-quadro per uniformità."""
    if n == 0:
        return 0.0
    expected = n / 256.0
    return sum((f - expected) ** 2 / expected for f in freq)


def validator_is_permutation_bytes(data: bytes) -> bool:
    """Verifica permutazione su byte."""
    return validator_is_permutation(data)


def validator_uniformity_deviation(freq: list[int], n: int) -> float:
    """Deviazione dall'uniformità della distribuzione."""
    if n == 0:
        return 0.0
    expected = n / 256.0
    return sum(abs(f - expected) for f in freq) / n

# ---------------------------------------------------------------------------
# BGE helpers
# ---------------------------------------------------------------------------

def validator_xor_differential_distribution(table: bytes) -> list[list[int]]:
    """Calcola distribuzione differenziale XOR."""
    return validator_compute_ddt(table)


def validator_has_aes_like_differential_profile(table: bytes) -> bool:
    """Verifica profilo differenziale simile ad AES."""
    if len(table) != 256:
        return False
    du = validator_differential_uniformity(table)
    return du <= 4


def validator_linear_bias(table: bytes) -> float:
    """Bias lineare massimo della tabella."""
    if len(table) != 256:
        return 0.0
    lat = validator_compute_lat(table)
    n = 256
    max_b = 0
    for a in range(1, n):
        for b in range(1, n):
            if abs(lat[a][b]) > max_b:
                max_b = abs(lat[a][b])
    return max_b / n


def validator_recover_single_key_byte(encoded_table: bytes) -> Optional[int]:
    """Recupera un byte di chiave da una T-box encoded."""
    return validator_extract_tbox_key(encoded_table)


def validator_recover_all_key_bytes(tables: list[bytes]) -> list[Optional[int]]:
    """Recupera tutti i byte di chiave da un set di T-box."""
    return [validator_recover_single_key_byte(t) for t in tables]

# ---------------------------------------------------------------------------
# Square attack helpers
# ---------------------------------------------------------------------------

def validator_construct_lambda_set(constant_part: bytes, active_byte: int) -> list[bytes]:
    """Costruisce il lambda set per l'attacco integrale."""
    result = []
    for v in range(256):
        pt = bytearray(constant_part[:15])
        pt.insert(active_byte, v)
        result.append(bytes(pt[:16]))
    return result


def validator_construct_lambda_set_byte0(constant_part: bytes) -> list[bytes]:
    """Lambda set con byte attivo in posizione 0."""
    return [bytes([v]) + bytes(constant_part[:15]) for v in range(256)]


def validator_check_balanced(byte_values: bytes) -> bool:
    """Verifica la proprietà di bilanciamento del lambda set."""
    return (len(byte_values) % 256 == 0) and (
        sum(byte_values) % 256 == 0
    )

# ---------------------------------------------------------------------------
# Linear approximation helpers
# ---------------------------------------------------------------------------

def validator_bias(sbox: bytes, alpha: int, beta: int) -> float:
    """Bias per la coppia di maschere (alpha, beta)."""
    n = len(sbox)
    count = sum(
        1 for x in range(n)
        if bin(alpha & x).count('1') % 2 == bin(beta & sbox[x]).count('1') % 2
    )
    return (count - n / 2) / n

# ---------------------------------------------------------------------------
# Simulate DFA attack (simplified)
# ---------------------------------------------------------------------------

def validator_simulate_dfa_attack(key: bytes, plaintext: bytes) -> Optional[tuple[bytes, bytes]]:
    """Simula un attacco DFA completo su AES-128 (restituisce correct e faulted ct)."""
    correct_ct = validator_aes_encrypt_128(key, plaintext)
    # Inject a fault at round 9, byte position 0
    ks = validator_aes128_key_schedule(key)
    state = list(plaintext[:16])
    state = validator_add_round_key(state, ks[0:16])
    for rnd in range(1, 9):
        state = validator_sub_bytes(state)
        state = _shift_rows(state)
        state = validator_aes_mix_columns(state)
        state = validator_add_round_key(state, ks[rnd * 16:(rnd + 1) * 16])
    # Inject fault: flip byte 0
    state[0] ^= 0x01
    # Continue encryption
    state = validator_sub_bytes(state)
    state = _shift_rows(state)
    state = validator_aes_mix_columns(state)
    state = validator_add_round_key(state, ks[144:160])
    state = validator_sub_bytes(state)
    state = _shift_rows(state)
    state = validator_add_round_key(state, ks[160:176])
    faulted_ct = bytes(state)
    return (correct_ct, faulted_ct)

# ---------------------------------------------------------------------------
# AES-128 ECB encrypt reference
# ---------------------------------------------------------------------------

def validator_aes128_ecb_encrypt_reference(plaintext: bytes, key: bytes) -> bytes:
    """Cifratura AES-128 ECB reference pura Rust (reimplementata in Python)."""
    out = bytearray()
    for i in range(0, len(plaintext), 16):
        block = plaintext[i:i+16]
        if len(block) < 16:
            block = block + b'\x00' * (16 - len(block))
        out.extend(validator_aes_encrypt_128(key, block))
    return bytes(out)

# ---------------------------------------------------------------------------
# validate_key helper
# ---------------------------------------------------------------------------

def validator_validate_key(key: bytes, pairs: list[tuple[bytes, bytes]]) -> bool:
    """Valida la chiave recuperata contro coppie note (plaintext, ciphertext)."""
    for pt, ct in pairs:
        if validator_aes_encrypt_128(key, pt) != ct:
            return False
    return True

# ---------------------------------------------------------------------------
# Table correlation
# ---------------------------------------------------------------------------

def validator_table_correlation(t1: bytes, t2: bytes) -> float:
    """Correlazione tra due lookup table."""
    if len(t1) != len(t2):
        return 0.0
    x = [float(b) for b in t1]
    y = [float(b) for b in t2]
    return validator_pearson_correlation(x, y)

# ---------------------------------------------------------------------------
# assemble_key / recover_key_from_tables stubs
# ---------------------------------------------------------------------------

def validator_assemble_key(results: list[dict], min_confidence: float = 0.5) -> Optional[bytes]:
    """Assembla la chiave finale dai risultati parziali."""
    key = [None] * 16
    for r in results:
        pos = r.get("byte_pos")
        byte_val = r.get("key_byte")
        confidence = r.get("confidence", 0.0)
        if pos is not None and byte_val is not None and confidence >= min_confidence:
            key[pos] = byte_val
    if all(k is not None for k in key):
        return bytes(key)
    return None

# ---------------------------------------------------------------------------
# RecoveredKey helpers
# ---------------------------------------------------------------------------

def validator_recovered_key_as_hex(key_bytes: bytes) -> str:
    """Chiave come stringa esadecimale."""
    return key_bytes.hex()


def validator_recovered_key_is_high_confidence(confidence: float, threshold: float = 0.8) -> bool:
    """Verifica se la confidenza supera la soglia."""
    return confidence >= threshold

# ---------------------------------------------------------------------------
# Bijection256 helpers
# ---------------------------------------------------------------------------

def validator_bijection256_is_identity(perm: bytes) -> bool:
    """Verifica identità di una permutazione 256."""
    return len(perm) == 256 and all(perm[i] == i for i in range(256))


def validator_bijection256_strip_xor_encoding(perm: bytes) -> Optional[int]:
    """Rimuove encoding XOR, restituisce la costante."""
    if len(perm) != 256:
        return None
    # Check if perm[i] = i ^ k for all i
    k = perm[0] ^ 0
    if all(perm[i] == (i ^ k) for i in range(256)):
        return k
    return None


def validator_bijection256_differential(perm: bytes) -> list[int]:
    """Calcola il profilo differenziale della permutazione."""
    if len(perm) != 256:
        return []
    profile = []
    for da in range(1, 256):
        xors = {perm[x] ^ perm[x ^ da] for x in range(256)}
        profile.append(len(xors))
    return profile

# ---------------------------------------------------------------------------
# GF256LinearMap
# ---------------------------------------------------------------------------

def _apply_gf256_matrix(matrix_bits: list[int], b: int) -> int:
    """Apply 8x8 bit matrix over GF(2) to byte b."""
    result = 0
    for row in range(8):
        bit = 0
        for col in range(8):
            if (matrix_bits[row] >> col) & 1:
                bit ^= (b >> col) & 1
        result |= (bit << row)
    return result


def validator_gf256_linear_map_apply(matrix: list[int], b: int) -> int:
    """Applica la mappa lineare a un byte."""
    return _apply_gf256_matrix(matrix, b)


def validator_gf256_linear_map_is_identity(matrix: list[int]) -> bool:
    """Verifica identità della mappa lineare."""
    return matrix == [1 << i for i in range(8)]

# ---------------------------------------------------------------------------
# ExtractionReport summary
# ---------------------------------------------------------------------------

def validator_extraction_report_summary(tables: list[dict]) -> str:
    """Riepilogo testuale dell'estrazione."""
    total = len(tables)
    by_class = {}
    for t in tables:
        cls = t.get("class", "unknown")
        by_class[cls] = by_class.get(cls, 0) + 1
    lines = [f"Total tables: {total}"]
    for cls, cnt in sorted(by_class.items()):
        lines.append(f"  {cls}: {cnt}")
    return "\n".join(lines)

# ---------------------------------------------------------------------------
# Reference T0 row (AES T-table)
# ---------------------------------------------------------------------------

def validator_reference_t0_row() -> list[int]:
    """Riga T0 di riferimento AES (lookup table standard)."""
    t0 = []
    for i in range(256):
        s = AES_SBOX[i]
        val = (
            (_gf_mul(2, s) << 24) |
            (s << 16) |
            (s << 8) |
            _gf_mul(3, s)
        )
        t0.append(val)
    return t0

# ---------------------------------------------------------------------------
# TBox helpers
# ---------------------------------------------------------------------------

def validator_tbox_is_bijective(data: bytes) -> bool:
    """Verifica biettività della T-box."""
    return validator_is_bijective(data)


def validator_tbox_non_linearity(data: bytes) -> int:
    """Calcola la non-linearità via Walsh-Hadamard."""
    return validator_boolean_nonlinearity(data)


def validator_tbox_is_affinely_equivalent_to_sbox(data: bytes) -> bool:
    """Verifica equivalenza affine con S-box AES."""
    return validator_is_affinely_equivalent_to_sbox(data)


def validator_tbox_find_xor_equivalence(data: bytes) -> Optional[tuple[int, int]]:
    """Trova costanti XOR di input/output equivalenti."""
    if len(data) != 256 or not validator_is_bijective(data):
        return None
    # Try all (in_xor, out_xor) pairs and check if data[x ^ in_xor] ^ out_xor == AES_SBOX[x]
    for in_xor in range(256):
        out_xor = data[in_xor] ^ AES_SBOX[0]  # data[0^in_xor]^out_xor = S[0]
        match = all(data[x ^ in_xor] ^ out_xor == AES_SBOX[x] for x in range(256))
        if match:
            return (in_xor, out_xor)
    return None


def validator_score_tbox(data: bytes) -> float:
    """Assegna uno score di probabilità AES alla T-box."""
    if len(data) != 256:
        return 0.0
    score = 0.0
    if validator_is_bijective(data):
        score += 0.4
    nl = validator_boolean_nonlinearity(data)
    if nl >= 100:
        score += 0.3
    du = validator_differential_uniformity(data)
    if du <= 4:
        score += 0.3
    return score

# ---------------------------------------------------------------------------
# DfaResult helpers
# ---------------------------------------------------------------------------

def validator_dfa_result_is_fully_recovered(recovered_bytes: list[Optional[int]]) -> bool:
    """Verifica se tutti i 16 byte chiave sono stati recuperati."""
    return len(recovered_bytes) == 16 and all(b is not None for b in recovered_bytes)


def validator_dfa_result_last_rk_hex(last_round_key: bytes) -> str:
    """Round 10 key in esadecimale."""
    return last_round_key.hex()


def validator_dfa_result_original_key_hex(original_key: bytes) -> str:
    """Chiave originale in esadecimale."""
    return original_key.hex()

# ---------------------------------------------------------------------------
# DcaResult helpers
# ---------------------------------------------------------------------------

def validator_dca_result_recovered_count(recovered: list[Optional[int]]) -> int:
    """Numero di byte chiave recuperati con certezza."""
    return sum(1 for b in recovered if b is not None)


def validator_dca_result_full_key_recovered(recovered: list[Optional[int]]) -> bool:
    """Verifica se tutti i 16 byte sono stati recuperati."""
    return validator_dfa_result_is_fully_recovered(recovered)

# ---------------------------------------------------------------------------
# CpaKeyRecovery helpers
# ---------------------------------------------------------------------------

def validator_cpa_key_recovery_key_hex(key_bytes: bytes) -> str:
    """Chiave recuperata in esadecimale."""
    return key_bytes.hex()


def validator_cpa_key_recovery_is_high_confidence(confidences: list[float], threshold: float = 0.8) -> bool:
    """Verifica confidenza alta del risultato CPA."""
    return all(c >= threshold for c in confidences)

# ---------------------------------------------------------------------------
# LinearKeyRecovery helpers
# ---------------------------------------------------------------------------

def validator_linear_key_recovery_average_abs_bias(lat: list[list[float]]) -> float:
    """Bias assoluto medio della LAT."""
    vals = [abs(v) for row in lat for v in row]
    if not vals:
        return 0.0
    return sum(vals) / len(vals)


def validator_lat_as_biases(sbox: bytes) -> list[list[float]]:
    """LAT come matrice di bias floating-point."""
    n = len(sbox)
    lat = validator_compute_lat(sbox)
    return [[v / n for v in row] for row in lat]

# ---------------------------------------------------------------------------
# FaultPair helpers
# ---------------------------------------------------------------------------

def validator_fault_pair_xor_diff(correct: bytes, faulty: bytes) -> Optional[bytes]:
    """Differenza XOR tra ct corretto e faulted."""
    return validator_xor_diff(correct, faulty)


def validator_fault_pair_diff_weight(correct: bytes, faulty: bytes) -> int:
    """Peso (numero di byte diversi) della differenza."""
    return sum(1 for a, b in zip(correct, faulty) if a != b)


def validator_fault_pair_is_valid_round9_pattern(correct: bytes, faulty: bytes) -> bool:
    """Pattern valido per fault al round 9 AES."""
    diff = validator_xor_diff(correct, faulty)
    if diff is None:
        return False
    return validator_is_valid_fault_pattern(diff)


def validator_fault_pair_dominant_column(correct: bytes, faulty: bytes) -> int:
    """Colonna AES più affetta dal fault."""
    diff = validator_xor_diff(correct, faulty)
    if diff is None:
        return 0
    col_counts = [0, 0, 0, 0]
    for i, d in enumerate(diff):
        if d != 0:
            col_counts[i % 4] += 1
    return col_counts.index(max(col_counts))

# ---------------------------------------------------------------------------
# FaultCampaign helpers
# ---------------------------------------------------------------------------

def validator_fault_campaign_effective_count(experiments: list[dict]) -> int:
    """Numero di esperimenti effettivi (con fault)."""
    return sum(1 for e in experiments if e.get("has_fault", False))

# ---------------------------------------------------------------------------
# RoundTableSet helpers
# ---------------------------------------------------------------------------

def validator_round_table_set_total_bytes(num_tables: int, table_size: int = 256) -> int:
    """Numero totale di byte nelle tabelle."""
    return num_tables * table_size


def validator_round_table_set_table_confidence(tables: list[bytes]) -> float:
    """Score di confidenza che sia AES."""
    return validator_aes_likeness_score(tables)

# ---------------------------------------------------------------------------
# AnalysisConfidence placeholder
# ---------------------------------------------------------------------------

def validator_analysis_confidence_compute(num_hits: int, total_checks: int) -> float:
    """Calcola la confidenza globale dell'analisi."""
    if total_checks == 0:
        return 0.0
    return min(num_hits / total_checks, 1.0)

# ---------------------------------------------------------------------------
# Self-test
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    key = bytes(range(16))
    pt = bytes(range(16))

    assert validator_aes128_verify_roundtrip(key, pt), "roundtrip failed"

    sbox = bytes(AES_SBOX)
    assert validator_is_bijective(sbox), "sbox not bijective"
    assert validator_differential_uniformity(sbox) == 4, "AES S-box DU != 4"

    ks = validator_aes128_key_schedule(key)
    assert len(ks) == 176, "key schedule length mismatch"

    orig = validator_from_last_round_key_128(bytes(ks[160:176]))
    assert orig == key, f"key schedule reverse failed: {orig!r} != {key!r}"

    diff = validator_xor_diff(b'\x00' * 16, b'\x01' + b'\x00' * 15)
    assert diff is not None

    # boolean_nonlinearity operates on a single-bit component function (e.g. 256-bit truth table of 0/1)
    # For a full S-box, minimum nonlinearity over all output bit projections should be 112
    min_nl = min(
        validator_boolean_nonlinearity(bytes((AES_SBOX[x] >> bit) & 1 for x in range(256)))
        for bit in range(8)
    )
    assert min_nl == 112, f"nonlinearity expected 112, got {min_nl}"

    result = validator_simulate_dfa_attack(key, pt)
    assert result is not None
    correct, faulted = result
    assert correct != faulted
    assert validator_fault_pair_is_valid_round9_pattern(correct, faulted)

    print("All self-tests passed.")
    print(f"Functions implemented: {sum(1 for n in dir() if n.startswith('validator_'))}")
