//! `perturbation` — adversarial perturbation strategies.
//!
//! When the IADL loop is stuck, [`apply_perturbation`] transforms the current
//! binary using one of several [`PerturbationType`] strategies to escape local
//! optima.  [`measure_effect`] quantifies the impact of a perturbation.

use serde::{Deserialize, Serialize};
use thiserror::Error;

// ─────────────────────────────────────────────────────────────────────────────
// Errors
// ─────────────────────────────────────────────────────────────────────────────

/// Errors from perturbation operations.
#[derive(Debug, Error)]
pub enum PerturbationError {
    /// The input data is empty.
    #[error("cannot perturb empty data")]
    EmptyData,
    /// An invalid seed or parameter was supplied.
    #[error("invalid parameter: {0}")]
    InvalidParameter(String),
}

// ─────────────────────────────────────────────────────────────────────────────
// PerturbationType
// ─────────────────────────────────────────────────────────────────────────────

/// The family of adversarial perturbation to apply.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum PerturbationType {
    /// Substitute a constant value with another; used to escape XOR-key fixation.
    ConstantSubstitution { constant: u8 },
    /// Zero out (NOP → 0x00) all NOP bytes in the binary.
    NopElimination,
    /// Remove detected junk-code sequences (identity instructions).
    JunkCodeRemoval,
    /// Pseudo-random byte mutation driven by a seed (for fuzzing-style escape).
    PatternMutation { seed: u64 },
    /// Rotate all bytes by `amount` positions (ROL/ROR byte-level scramble undo).
    ByteRotation { amount: u8 },
    /// XOR all bytes with a fresh key derived from the current binary hash.
    HashDerivedXor,
    /// Swap pairs of adjacent bytes (detect big/little-endian encoding issues).
    ByteSwap,
    /// Invert every bit in a selected region (complement perturbation).
    BitwiseComplement {
        region_start: usize,
        region_len: usize,
    },
}

impl PerturbationType {
    /// Human-readable label for this perturbation.
    #[must_use]
    pub const fn name(&self) -> &'static str {
        match self {
            Self::ConstantSubstitution { .. } => "constant-substitution",
            Self::NopElimination => "nop-elimination",
            Self::JunkCodeRemoval => "junk-code-removal",
            Self::PatternMutation { .. } => "pattern-mutation",
            Self::ByteRotation { .. } => "byte-rotation",
            Self::HashDerivedXor => "hash-derived-xor",
            Self::ByteSwap => "byte-swap",
            Self::BitwiseComplement { .. } => "bitwise-complement",
        }
    }

    /// Estimated reversibility: `true` if the perturbation can be undone.
    #[must_use]
    pub const fn is_reversible(&self) -> bool {
        matches!(
            self,
            Self::ConstantSubstitution { .. }
                | Self::NopElimination
                | Self::ByteRotation { .. }
                | Self::HashDerivedXor
                | Self::ByteSwap
                | Self::BitwiseComplement { .. }
        )
    }

    /// Estimated aggressiveness on a scale of 1–10 (higher = more disruptive).
    #[must_use]
    pub const fn aggressiveness(&self) -> u8 {
        match self {
            Self::NopElimination | Self::JunkCodeRemoval => 2,
            Self::ConstantSubstitution { .. } | Self::ByteSwap => 4,
            Self::ByteRotation { .. } => 5,
            Self::HashDerivedXor => 6,
            Self::PatternMutation { .. } => 7,
            Self::BitwiseComplement { .. } => 9,
        }
    }
}

impl std::fmt::Display for PerturbationType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.name())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Perturbation
// ─────────────────────────────────────────────────────────────────────────────

/// A perturbation instance with its type and optional parameters.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Perturbation {
    /// The kind of perturbation.
    pub kind: PerturbationType,
    /// Whether this perturbation was applied during a specific iteration.
    pub applied_at_iteration: Option<u32>,
    /// Measured quality delta when this perturbation was last applied.
    pub last_effect: Option<f64>,
}

impl Perturbation {
    /// Create a new perturbation.
    #[must_use]
    pub const fn new(kind: PerturbationType) -> Self {
        Self {
            kind,
            applied_at_iteration: None,
            last_effect: None,
        }
    }

    /// Record that this perturbation was applied at `iteration`.
    pub const fn record_application(&mut self, iteration: u32, effect: f64) {
        self.applied_at_iteration = Some(iteration);
        self.last_effect = Some(effect);
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// PerturbationEffect
// ─────────────────────────────────────────────────────────────────────────────

/// Measured effect of a perturbation on a binary.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PerturbationEffect {
    /// Perturbation that was applied.
    pub kind: PerturbationType,
    /// Bytes changed.
    pub bytes_changed: usize,
    /// Shannon entropy of the original data.
    pub entropy_before: f64,
    /// Shannon entropy after perturbation.
    pub entropy_after: f64,
    /// Printable-ASCII ratio after perturbation.
    pub printability_after: f64,
    /// Net quality change estimate (positive = improvement).
    pub quality_delta: f64,
}

impl PerturbationEffect {
    /// Returns `true` if the perturbation is estimated to have helped.
    #[must_use]
    pub fn is_beneficial(&self) -> bool {
        self.quality_delta > 0.0
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// apply_perturbation
// ─────────────────────────────────────────────────────────────────────────────

/// Apply `perturbation` to `data` and return the transformed bytes.
///
/// Returns the original bytes unchanged if the perturbation cannot be applied
/// (e.g. region out of bounds).
#[must_use]
pub fn apply_perturbation(data: &[u8], perturbation: &Perturbation) -> Vec<u8> {
    if data.is_empty() {
        return Vec::new();
    }
    match &perturbation.kind {
        PerturbationType::ConstantSubstitution { constant } => {
            apply_constant_substitution(data, *constant)
        }
        PerturbationType::NopElimination => apply_nop_elimination(data),
        PerturbationType::JunkCodeRemoval => apply_junk_code_removal(data),
        PerturbationType::PatternMutation { seed } => apply_pattern_mutation(data, *seed),
        PerturbationType::ByteRotation { amount } => apply_byte_rotation(data, *amount),
        PerturbationType::HashDerivedXor => apply_hash_derived_xor(data),
        PerturbationType::ByteSwap => apply_byte_swap(data),
        PerturbationType::BitwiseComplement {
            region_start,
            region_len,
        } => apply_bitwise_complement(data, *region_start, *region_len),
    }
}

/// Measure the effect of applying `perturbation` to `data`.
///
/// This is a non-destructive measurement (reads only).
#[must_use]
pub fn measure_effect(data: &[u8], perturbation: &Perturbation) -> PerturbationEffect {
    let transformed = apply_perturbation(data, perturbation);
    let entropy_before = shannon_entropy(data);
    let entropy_after = shannon_entropy(&transformed);
    let bytes_changed = data
        .iter()
        .zip(transformed.iter())
        .filter(|(a, b)| a != b)
        .count();
    let printability_after = printability_ratio(&transformed);

    // Quality delta heuristic: improvement in printability × (entropy reduction).
    let printability_before = printability_ratio(data);
    let quality_delta = (printability_after - printability_before).mul_add(0.6, ((entropy_before - entropy_after) / 8.0) * 0.4);

    PerturbationEffect {
        kind: perturbation.kind,
        bytes_changed,
        entropy_before,
        entropy_after,
        printability_after,
        quality_delta,
    }
}

/// Rank a list of perturbations by estimated quality delta (best first).
#[must_use]
pub fn rank_perturbations(data: &[u8], perturbations: &[Perturbation]) -> Vec<(usize, f64)> {
    let mut scored: Vec<(usize, f64)> = perturbations
        .iter()
        .enumerate()
        .map(|(i, p)| {
            let effect = measure_effect(data, p);
            (i, effect.quality_delta)
        })
        .collect();
    scored.sort_by(|a, b| b.1.total_cmp(&a.1));
    scored
}

// ─────────────────────────────────────────────────────────────────────────────
// Strategy implementations
// ─────────────────────────────────────────────────────────────────────────────

fn apply_constant_substitution(data: &[u8], constant: u8) -> Vec<u8> {
    // XOR all bytes with `constant`: a way to "shift" the byte distribution.
    data.iter().map(|&b| b ^ constant).collect()
}

fn apply_nop_elimination(data: &[u8]) -> Vec<u8> {
    // Replace NOP sleds (≥ 2 consecutive 0x90) with zeros.
    let mut out = data.to_vec();
    let mut i = 0;
    while i < out.len() {
        if out[i] == 0x90 {
            let start = i;
            while i < out.len() && out[i] == 0x90 {
                i += 1;
            }
            if i - start >= 2 {
                for b in &mut out[start..i] {
                    *b = 0x00;
                }
            }
        } else {
            i += 1;
        }
    }
    out
}

fn apply_junk_code_removal(data: &[u8]) -> Vec<u8> {
    // Remove: xor reg,reg (31 C0, 33 C0) → replace with 0x00 0x00
    // and push/pop same reg pairs (50+r, 58+r)
    let mut out = data.to_vec();
    let mut i = 0;
    while i + 1 < out.len() {
        let b0 = out[i];
        let b1 = out[i + 1];
        // xor reg, reg (same dst and src in ModRM)
        let is_xor_rr =
            (b0 == 0x31 || b0 == 0x33) && (b1 & 0xC0) == 0xC0 && ((b1 >> 3) & 7) == (b1 & 7);
        // push r + pop same r
        let is_push_pop = (0x50..=0x57).contains(&b0) && b1 == b0 + 8;
        // add reg, 0 (83 C0+r 00)
        let is_add_zero =
            i + 2 < out.len() && b0 == 0x83 && (b1 & 0xF8) == 0xC0 && out[i + 2] == 0x00;

        if is_xor_rr || is_push_pop {
            out[i] = 0x00;
            out[i + 1] = 0x00;
            i += 2;
        } else if is_add_zero {
            out[i] = 0x00;
            out[i + 1] = 0x00;
            out[i + 2] = 0x00;
            i += 3;
        } else {
            i += 1;
        }
    }
    out
}

fn apply_pattern_mutation(data: &[u8], seed: u64) -> Vec<u8> {
    // LCG-based pseudo-random byte mutation on a sparse selection of bytes.
    // We only mutate 5% of bytes to avoid over-scrambling.
    let mut out = data.to_vec();
    let mut state = seed;
    let mutation_count = (data.len() / 20).max(1);
    for _ in 0..mutation_count {
        state = state
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        let idx = (state >> 17) as usize % out.len();
        // XOR with a derived byte from the LCG state.
        let xor_byte = ((state >> 24) & 0xFF) as u8;
        out[idx] ^= xor_byte;
    }
    out
}

fn apply_byte_rotation(data: &[u8], amount: u8) -> Vec<u8> {
    let n = amount & 7;
    if n == 0 {
        return data.to_vec();
    }
    data.iter().map(|&b| b.rotate_right(u32::from(n))).collect()
}

fn apply_hash_derived_xor(data: &[u8]) -> Vec<u8> {
    // FNV-1a hash of first 64 bytes as the XOR key.
    const PRIME: u64 = 0x0000_0100_0000_01B3;
    const BASIS: u64 = 0xcbf2_9ce4_8422_2325;
    let mut h = BASIS;
    for &b in data.iter().take(64) {
        h ^= u64::from(b);
        h = h.wrapping_mul(PRIME);
    }
    let key = (h & 0xFF) as u8;
    if key == 0 {
        return data.to_vec();
    }
    data.iter().map(|&b| b ^ key).collect()
}

fn apply_byte_swap(data: &[u8]) -> Vec<u8> {
    let mut out = data.to_vec();
    let mut i = 0;
    while i + 1 < out.len() {
        out.swap(i, i + 1);
        i += 2;
    }
    out
}

fn apply_bitwise_complement(data: &[u8], region_start: usize, region_len: usize) -> Vec<u8> {
    let mut out = data.to_vec();
    let end = (region_start + region_len).min(out.len());
    if region_start < end {
        for b in &mut out[region_start..end] {
            *b = !*b;
        }
    }
    out
}

// ─────────────────────────────────────────────────────────────────────────────
// Utility
// ─────────────────────────────────────────────────────────────────────────────

fn shannon_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut freq = [0u32; 256];
    for &b in data {
        freq[b as usize] += 1;
    }
    let n = data.len() as f64;
    freq.iter().filter(|&&c| c > 0).fold(0.0, |acc, &c| {
        let p = f64::from(c) / n;
        p.mul_add(-p.log2(), acc)
    })
}

fn printability_ratio(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    data.iter()
        .filter(|&&b| b.is_ascii_graphic() || b == b' ')
        .count() as f64
        / data.len() as f64
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn p(kind: PerturbationType) -> Perturbation {
        Perturbation::new(kind)
    }

    #[test]
    fn test_constant_substitution_is_symmetric() {
        let data = b"Hello, World! Testing perturbation symmetry.".to_vec();
        let pert = p(PerturbationType::ConstantSubstitution { constant: 0x42 });
        let enc = apply_perturbation(&data, &pert);
        let dec = apply_perturbation(&enc, &pert);
        assert_eq!(dec, data, "constant substitution XOR should be symmetric");
    }

    #[test]
    fn test_nop_elimination_zeros_sleds() {
        let mut data = vec![0x55u8, 0x8Bu8, 0xECu8];
        data.extend_from_slice(&[0x90u8; 16]);
        data.push(0xC3);
        let pert = p(PerturbationType::NopElimination);
        let out = apply_perturbation(&data, &pert);
        // NOP sled (16 bytes) should be zeroed
        assert_eq!(&out[3..19], &[0x00u8; 16][..]);
        // Non-NOP bytes unchanged
        assert_eq!(out[0], 0x55);
        assert_eq!(out[19], 0xC3);
    }

    #[test]
    fn test_junk_code_removal_xor_rr() {
        // xor eax, eax: 31 C0
        let data = vec![0x31u8, 0xC0, 0x90, 0x31, 0xC0];
        let pert = p(PerturbationType::JunkCodeRemoval);
        let out = apply_perturbation(&data, &pert);
        assert_eq!(out[0], 0x00);
        assert_eq!(out[1], 0x00);
    }

    #[test]
    fn test_byte_rotation_roundtrip() {
        let data: Vec<u8> = (0u8..64).collect();
        let enc = apply_perturbation(&data, &p(PerturbationType::ByteRotation { amount: 3 }));
        // Undo by rotating back by (8 - 3) = 5
        let dec: Vec<u8> = enc.iter().map(|&b| b.rotate_left(3)).collect();
        assert_eq!(dec, data);
    }

    #[test]
    fn test_hash_derived_xor_changes_data() {
        let data: Vec<u8> = (0u8..=127).collect();
        let pert = p(PerturbationType::HashDerivedXor);
        let out = apply_perturbation(&data, &pert);
        // Should differ (unless hash key happens to be 0, which is guarded)
        assert_ne!(out, data);
    }

    #[test]
    fn test_byte_swap_length_preserved() {
        let data: Vec<u8> = (0u8..64).collect();
        let out = apply_perturbation(&data, &p(PerturbationType::ByteSwap));
        assert_eq!(out.len(), data.len());
        // First two bytes swapped
        assert_eq!(out[0], data[1]);
        assert_eq!(out[1], data[0]);
    }

    #[test]
    fn test_bitwise_complement_region() {
        let data = vec![0xFFu8; 8];
        let pert = p(PerturbationType::BitwiseComplement {
            region_start: 2,
            region_len: 4,
        });
        let out = apply_perturbation(&data, &pert);
        assert_eq!(out[2..6], [0x00u8; 4][..]);
        assert_eq!(out[0], 0xFF);
        assert_eq!(out[7], 0xFF);
    }

    #[test]
    fn test_measure_effect_beneficial_for_ascii_xor() {
        let plaintext = b"LoadLibraryA GetProcAddress VirtualAlloc CreateThread";
        let cipher: Vec<u8> = plaintext.iter().map(|&b| b ^ 0x42).collect();
        let pert = p(PerturbationType::ConstantSubstitution { constant: 0x42 });
        let effect = measure_effect(&cipher, &pert);
        assert!(
            effect.is_beneficial(),
            "undoing XOR on ASCII text should be beneficial"
        );
    }

    #[test]
    fn test_rank_perturbations_non_empty() {
        let data: Vec<u8> = b"Hello World test data."
            .iter()
            .map(|&b| b ^ 0x42)
            .collect();
        let perturbs = vec![
            p(PerturbationType::ConstantSubstitution { constant: 0x42 }),
            p(PerturbationType::NopElimination),
        ];
        let ranked = rank_perturbations(&data, &perturbs);
        assert_eq!(ranked.len(), 2);
    }

    #[test]
    fn test_empty_data_returns_empty() {
        let pert = p(PerturbationType::NopElimination);
        let out = apply_perturbation(&[], &pert);
        assert!(out.is_empty());
    }

    #[test]
    fn test_pattern_mutation_changes_data() {
        let data: Vec<u8> = (0u8..=255).collect();
        let pert = p(PerturbationType::PatternMutation { seed: 12345 });
        let out = apply_perturbation(&data, &pert);
        // With 5% mutation, at least some bytes should differ
        let changed = data.iter().zip(out.iter()).filter(|(a, b)| a != b).count();
        assert!(
            changed > 0,
            "pattern mutation should change at least some bytes"
        );
    }

    #[test]
    fn test_aggressiveness_ordering() {
        assert!(
            PerturbationType::BitwiseComplement {
                region_start: 0,
                region_len: 8
            }
            .aggressiveness()
                > PerturbationType::NopElimination.aggressiveness()
        );
    }
}
