"""Validator for rustre-triage-entropy.

Provides ground-truth Shannon entropy (per-buffer and per-block) computed
purely with stdlib (math.log2 + collections.Counter), plus chi-square,
classification tables, and color-ramp lookups. Use these as the oracle
when comparing against the Rust implementation.
"""

from __future__ import annotations

import math
import os
from collections import Counter
from typing import Iterable


# ---------------------------------------------------------------------------
# Core Shannon entropy
# ---------------------------------------------------------------------------

def shannon_entropy(data: bytes) -> float:
    """Shannon entropy in bits/byte over [0.0, 8.0].

    Returns 0.0 on empty input (matches typical Rust convention; the Rust
    crate exposes an EmptyInput error variant, so callers may also check
    len(data) == 0 separately).
    """
    n = len(data)
    if n == 0:
        return 0.0
    counts = Counter(data)
    h = 0.0
    for c in counts.values():
        p = c / n
        h -= p * math.log2(p)
    return h


def shannon_entropy_blocks(
    data: bytes, block_size: int
) -> list[tuple[int, int, float]]:
    """Per non-overlapping block Shannon entropy.

    Returns list of (offset, size, entropy). Offsets are i * block_size.
    Raises ValueError on block_size == 0 (matches InvalidChunk semantics).
    """
    if block_size == 0:
        raise ValueError("block_size must be > 0")
    out: list[tuple[int, int, float]] = []
    for i in range(0, len(data), block_size):
        chunk = data[i : i + block_size]
        out.append((i, len(chunk), shannon_entropy(chunk)))
    return out


# ---------------------------------------------------------------------------
# Histogram + chi-square
# ---------------------------------------------------------------------------

def byte_histogram(data: bytes) -> list[int]:
    """Return 256-entry count array."""
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    return counts


def chi_square_statistic(data: bytes) -> float:
    """Chi-square vs uniform distribution (E = n/256)."""
    n = len(data)
    if n == 0:
        return 0.0
    expected = n / 256.0
    counts = byte_histogram(data)
    return sum((o - expected) ** 2 / expected for o in counts)


def is_likely_random(data: bytes) -> bool:
    chi = chi_square_statistic(data)
    return 200.0 <= chi <= 310.0


def most_common_bytes(data: bytes, n: int) -> list[tuple[int, int]]:
    return Counter(data).most_common(n)


# ---------------------------------------------------------------------------
# Classification tables (must match the Rust enums exactly)
# ---------------------------------------------------------------------------

def entropy_rating(h: float) -> str:
    """EntropyRating::from_entropy: <1 VeryLow, <3 Low, <5 Medium, <7 High, else VeryHigh."""
    if h < 1.0:
        return "VeryLow"
    if h < 3.0:
        return "Low"
    if h < 5.0:
        return "Medium"
    if h < 7.0:
        return "High"
    return "VeryHigh"


def entropy_category(e: float) -> str:
    """EntropyCategory::classify: Empty<1, Text<4, Code<5, Data<6, Compressed<7, Encrypted<7.5, Random>=7.5."""
    if e < 1.0:
        return "Empty"
    if e < 4.0:
        return "Text"
    if e < 5.0:
        return "Code"
    if e < 6.0:
        return "Data"
    if e < 7.0:
        return "Compressed"
    if e < 7.5:
        return "Encrypted"
    return "Random"


def is_packed(entropy: float) -> bool:
    return entropy > 7.0


def is_encrypted(entropy: float) -> bool:
    return entropy > 7.5


# ---------------------------------------------------------------------------
# Heatmap color ramp (table-driven; thresholds per report)
# ---------------------------------------------------------------------------

def color_rgb(e: float) -> tuple[int, int, int]:
    """Approximate HeatmapData::color_rgb thresholded ramp.

    Used as an oracle skeleton; concrete RGB values must be cross-checked
    against the Rust source if a tighter equality test is required.
    """
    if e < 1.0:
        return (0, 0, 64)
    if e < 3.0:
        return (0, 0, 255)
    if e < 5.0:
        return (0, 255, 0)
    if e < 7.0:
        return (255, 255, 0)
    if e < 7.5:
        return (255, 128, 0)
    return (255, 0, 0)


# ---------------------------------------------------------------------------
# Golden vectors (callable as a smoke check)
# ---------------------------------------------------------------------------

def golden_vectors() -> dict[str, float]:
    """Known-answer Shannon entropies."""
    return {
        "all_zero_1k": shannon_entropy(b"\x00" * 1024),         # 0.0
        "uniform_256": shannon_entropy(bytes(range(256))),      # 8.0
        "balanced_two_symbol": shannon_entropy(b"AB" * 512),    # 1.0
    }


def verify_golden(tol: float = 1e-9) -> bool:
    g = golden_vectors()
    return (
        abs(g["all_zero_1k"] - 0.0) < tol
        and abs(g["uniform_256"] - 8.0) < tol
        and abs(g["balanced_two_symbol"] - 1.0) < tol
    )


if __name__ == "__main__":
    print("golden vectors:", golden_vectors())
    print("verify_golden:", verify_golden())
    rnd = os.urandom(65536)
    print("urandom 64K entropy:", shannon_entropy(rnd))
    print("urandom 64K chi2:", chi_square_statistic(rnd))
    print("is_likely_random:", is_likely_random(rnd))
