//! Linear cryptanalysis stubs and engine for `rustre-crypto-whitebox`.
//!
//! Implements the Matsui-style linear cryptanalysis framework: linear
//! approximation table (LAT), linear hull aggregation, bias computation,
//! key-recovery attack, and reporting.

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// `u64::MAX` expressed as `f64` (with precision loss, but kept as a const to
/// avoid repeated truncation-cast warnings at call sites).
const U64_MAX_F64: f64 = 1.844_674_407_370_955_2e19_f64;

/// Cast a non-negative, finite `f64` to `u64`, saturating to `u64::MAX`
/// instead of invoking undefined behaviour.  Always call with a value that has
/// already been checked to be `< U64_MAX_F64`.
#[inline]
#[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
const fn f64_to_u64_checked(v: f64) -> u64 {
    v as u64
}

// ── Error ────────────────────────────────────────────────────────────────────

#[derive(Debug, Error)]
pub enum LinearAttackError {
    #[error("insufficient data: need {0} plaintext–ciphertext pairs")]
    InsufficientPairs(usize),
    #[error("S-box size must be a power of two, got {0}")]
    InvalidSboxSize(usize),
    #[error("target bit mask is zero — no bits selected")]
    ZeroBitMask,
    #[error("key recovery failed: {0}")]
    KeyRecoveryFailed(String),
    #[error("{0}")]
    Other(String),
}

// ── LinearApproximation ───────────────────────────────────────────────────────

/// A single linear approximation for an S-box.
///
/// Describes the relationship `Γ_P · x ⊕ Γ_C · S(x) = 0` with bias `ε`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LinearApproximation {
    /// Input mask (selects which plaintext bits to XOR).
    pub input_mask: u64,
    /// Output mask (selects which S-box output bits to XOR).
    pub output_mask: u64,
    /// Linear bias: fraction of inputs satisfying the relation minus 0.5.
    /// Range: [-0.5, 0.5].  Values near ±0.5 are strongest.
    pub bias: f64,
    /// Absolute bias |ε|.
    pub abs_bias: f64,
    /// Number of agreeing inputs (out of `sbox_size`).
    pub agreeing_count: usize,
    /// Size of the S-box (number of possible inputs).
    pub sbox_size: usize,
}

impl LinearApproximation {
    /// Build a `LinearApproximation` by evaluating an S-box over all inputs.
    ///
    /// # Errors
    ///
    /// Returns `LinearAttackError::InvalidSboxSize` if the S-box is empty or its length is not a power of two.
    pub fn compute(sbox: &[u8], input_mask: u64, output_mask: u64) -> Result<Self, LinearAttackError> {
        let n = sbox.len();
        if n == 0 || (n & (n - 1)) != 0 {
            return Err(LinearAttackError::InvalidSboxSize(n));
        }
        let mut agreeing = 0usize;
        for (x, &s) in sbox.iter().enumerate() {
            let in_parity  = (u64::try_from(x).unwrap_or(u64::MAX) & input_mask).count_ones() & 1;
            let out_parity = (u64::from(s) & output_mask).count_ones() & 1;
            if in_parity == out_parity {
                agreeing += 1;
            }
        }
        let bias = f64::from(u32::try_from(agreeing).unwrap_or(u32::MAX)) / f64::from(u32::try_from(n).unwrap_or(u32::MAX)) - 0.5;
        Ok(Self {
            input_mask,
            output_mask,
            bias,
            abs_bias: bias.abs(),
            agreeing_count: agreeing,
            sbox_size: n,
        })
    }

    /// The probability that the linear approximation holds for a random input.
    #[must_use]
    pub fn probability(&self) -> f64 {
        f64::from(u32::try_from(self.agreeing_count).unwrap_or(u32::MAX)) / f64::from(u32::try_from(self.sbox_size).unwrap_or(u32::MAX))
    }

    /// True if this is a trivially zero approximation (bias == 0, i.e., exactly half).
    #[must_use]
    pub fn is_trivial(&self) -> bool {
        self.abs_bias < 1e-9
    }
}

// ── LinearHull ────────────────────────────────────────────────────────────────

/// A collection of compatible linear approximations forming a "hull".
///
/// Multiple trails with the same effective input/output mask can be XOR-combined
/// to produce an effective bias via Piling-Up Lemma.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LinearHull {
    /// The aggregate input mask for this hull.
    pub input_mask: u64,
    /// The aggregate output mask for this hull.
    pub output_mask: u64,
    /// Individual trails in this hull.
    pub trails: Vec<LinearApproximation>,
    /// Effective bias computed from the Piling-Up Lemma.
    pub effective_bias: f64,
    /// Number of rounds this hull spans.
    pub rounds: u32,
}

impl LinearHull {
    /// Create an empty hull for a given input/output mask pair.
    #[must_use]
    pub const fn new(input_mask: u64, output_mask: u64, rounds: u32) -> Self {
        Self {
            input_mask,
            output_mask,
            trails: Vec::new(),
            effective_bias: 0.0,
            rounds,
        }
    }

    /// Add a trail and recompute the effective bias using the Piling-Up Lemma.
    ///
    /// For independent trails the effective bias is:
    ///   `ε_eff` = 2^{n-1} `∏_i ε_i`
    /// where n is the number of trails (ignoring sign).
    pub fn add_trail(&mut self, approx: LinearApproximation) {
        self.trails.push(approx);
        self.recompute_bias();
    }

    fn recompute_bias(&mut self) {
        if self.trails.is_empty() {
            self.effective_bias = 0.0;
            return;
        }
        let n = self.trails.len();
        let product: f64 = self.trails.iter().map(|t| t.bias).product();
        self.effective_bias = 2f64.powi(i32::try_from(n).unwrap_or(i32::MAX).saturating_sub(1)) * product;
    }

    /// Absolute effective bias.
    #[must_use]
    pub const fn abs_effective_bias(&self) -> f64 {
        // f64::abs is not const, so we use bit-mask to clear the sign bit.
        f64::from_bits(self.effective_bias.to_bits() & (u64::MAX >> 1))
    }

    /// Number of pairs required for a distinguishing attack with this hull.
    /// Based on the Matsui bound: N ≈ ε^{-2}.
    #[must_use]
    pub fn required_pairs(&self) -> u64 {
        let b = self.abs_effective_bias();
        if b < 1e-12 { return u64::MAX; }
        let v = (1.0 / (b * b)).round();
        if v >= U64_MAX_F64 { u64::MAX } else { f64_to_u64_checked(v) }
    }
}

// ── LinearBias ────────────────────────────────────────────────────────────────

/// Represents the bias contribution from a single linear trail through a cipher.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LinearBias {
    /// Plaintext bit mask for this trail.
    pub plaintext_mask: u64,
    /// Ciphertext bit mask for this trail.
    pub ciphertext_mask: u64,
    /// Per-round biases that contribute to this trail.
    pub per_round_biases: Vec<f64>,
    /// Aggregate bias (Piling-Up Lemma product).
    pub aggregate_bias: f64,
    /// Whether this bias is strong enough for a practical attack (> 2^{-22} as a rule of thumb).
    pub is_practical: bool,
}

impl LinearBias {
    /// Compute a multi-round bias from per-round biases.
    #[must_use]
    pub fn from_per_round(plaintext_mask: u64, ciphertext_mask: u64, biases: Vec<f64>) -> Self {
        let n = biases.len();
        let product: f64 = biases.iter().product();
        let aggregate = if n == 0 { 0.0 } else { 2f64.powi(i32::try_from(n).unwrap_or(i32::MAX).saturating_sub(1)) * product };
        let is_practical = aggregate.abs() > 2f64.powi(-22);
        Self {
            plaintext_mask,
            ciphertext_mask,
            per_round_biases: biases,
            aggregate_bias: aggregate,
            is_practical,
        }
    }

    /// Number of pairs needed (Matsui bound).
    #[must_use]
    pub fn pairs_needed(&self) -> u64 {
        let b = self.aggregate_bias.abs();
        if b < 1e-15 { return u64::MAX; }
        let v = (1.0 / (b * b)).round();
        if v >= U64_MAX_F64 { u64::MAX } else { f64_to_u64_checked(v) }
    }
}

// ── KeyRecovery ───────────────────────────────────────────────────────────────

/// Result of recovering a partial key from linear cryptanalysis.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyRecoveryResult {
    /// The key bits recovered (partial key hypothesis).
    pub key_bits: u64,
    /// Bit mask indicating which bits were recovered.
    pub bit_mask: u64,
    /// Bias score observed for this key hypothesis.
    pub observed_bias: f64,
    /// Number of pairs used in the attack.
    pub pairs_used: usize,
    /// Confidence in [0.0, 1.0].
    pub confidence: f64,
    /// Whether the recovered bits are considered reliable.
    pub reliable: bool,
}

/// A partial-key guess scored by observed bias counter.
#[derive(Debug, Clone)]
struct KeyGuess {
    key_bits: u64,
    counter: i64,
}

// ── LinearReport ─────────────────────────────────────────────────────────────

/// Full report produced by a linear cryptanalysis run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LinearReport {
    pub target_cipher: String,
    pub sbox_count: usize,
    pub block_bits: u32,
    pub rounds_analysed: u32,
    /// Best (highest |bias|) approximation found.
    pub best_approximation: Option<LinearApproximation>,
    /// All practical hulls found.
    pub hulls: Vec<LinearHull>,
    /// Key recovery results (one per targeted key byte).
    pub recovered_keys: Vec<KeyRecoveryResult>,
    /// Minimum pairs needed to mount a practical attack.
    pub min_pairs_needed: Option<u64>,
    /// Human-readable conclusions.
    pub conclusions: Vec<String>,
}

impl LinearReport {
    pub fn new(target_cipher: impl Into<String>, block_bits: u32, rounds: u32) -> Self {
        Self {
            target_cipher: target_cipher.into(),
            sbox_count: 0,
            block_bits,
            rounds_analysed: rounds,
            best_approximation: None,
            hulls: Vec::new(),
            recovered_keys: Vec::new(),
            min_pairs_needed: None,
            conclusions: Vec::new(),
        }
    }

    pub fn add_hull(&mut self, hull: LinearHull) {
        if hull.abs_effective_bias() > 0.0 {
            let pairs = hull.required_pairs();
            self.min_pairs_needed = Some(
                self.min_pairs_needed.map_or(pairs, |prev| prev.min(pairs))
            );
            if let Some(ref best) = self.best_approximation {
                if hull.trails.iter().any(|t| t.abs_bias > best.abs_bias) {
                    self.best_approximation = hull.trails.iter()
                        .max_by(|a, b| a.abs_bias.partial_cmp(&b.abs_bias).unwrap_or(std::cmp::Ordering::Equal))
                        .cloned();
                }
            } else {
                self.best_approximation = hull.trails.iter()
                    .max_by(|a, b| a.abs_bias.partial_cmp(&b.abs_bias).unwrap_or(std::cmp::Ordering::Equal))
                    .cloned();
            }
        }
        self.hulls.push(hull);
    }

    pub fn finalize(&mut self) {
        self.conclusions.clear();
        if let Some(pairs) = self.min_pairs_needed {
            self.conclusions.push(format!("Estimated minimum pairs for practical attack: {pairs}"));
            if pairs < (1u64 << 40) {
                self.conclusions.push("PRACTICAL: attack requires fewer than 2^40 pairs".into());
            } else {
                self.conclusions.push("THEORETICAL: requires more than 2^40 pairs — computationally infeasible".into());
            }
        } else {
            self.conclusions.push("No usable linear approximations found".into());
        }
        if self.recovered_keys.iter().any(|k| k.reliable) {
            self.conclusions.push(format!(
                "{} reliable partial key recoveries",
                self.recovered_keys.iter().filter(|k| k.reliable).count()
            ));
        }
    }
}

// ── LinearAttack ──────────────────────────────────────────────────────────────

/// Core engine for linear cryptanalysis.
///
/// Builds the Linear Approximation Table (LAT) for an S-box, enumerates
/// candidate linear trails, collects plaintext–ciphertext pairs, and
/// performs key-recovery via counter-based bias estimation.
pub struct LinearAttack {
    /// S-box under analysis.
    sbox: Vec<u8>,
    /// Precomputed Linear Approximation Table: `lat[alpha][beta]` = count of
    /// agreeing inputs for input mask `alpha` and output mask `beta`.
    lat: Vec<Vec<i32>>,
    /// Cipher name for reporting.
    cipher_name: String,
    /// Block size in bits.
    block_bits: u32,
    /// Collected plaintext–ciphertext pairs.
    pairs: Vec<(u64, u64)>,
}

impl LinearAttack {
    /// Create a new `LinearAttack` for a given S-box.
    ///
    /// # Errors
    ///
    /// Returns `LinearAttackError::InvalidSboxSize` if the S-box is empty or its length is not a power of two.
    pub fn new(sbox: Vec<u8>, cipher_name: impl Into<String>, block_bits: u32) -> Result<Self, LinearAttackError> {
        let n = sbox.len();
        if n == 0 || (n & (n - 1)) != 0 {
            return Err(LinearAttackError::InvalidSboxSize(n));
        }
        let mut attack = Self {
            sbox,
            lat: Vec::new(),
            cipher_name: cipher_name.into(),
            block_bits,
            pairs: Vec::new(),
        };
        attack.build_lat();
        Ok(attack)
    }

    /// Build the Linear Approximation Table (LAT).
    ///
    /// `lat[alpha][beta]` holds the count of x in {0..n-1} where
    /// `(x & alpha).popcount() ^ (S(x) & beta).popcount()` is 0 (even).
    /// The bias is `lat[alpha][beta] / n - 0.5`.
    pub fn build_lat(&mut self) {
        let n = self.sbox.len();
        self.lat = vec![vec![0i32; n]; n];
        for alpha in 0..n {
            for beta in 0..n {
                let mut count = 0i32;
                for x in 0..n {
                    let lhs = (x & alpha).count_ones() & 1;
                    let rhs = (self.sbox[x] as usize & beta).count_ones() & 1;
                    if lhs == rhs {
                        count += 1;
                    }
                }
                self.lat[alpha][beta] = count;
            }
        }
    }

    /// Return the bias for input mask `alpha` and output mask `beta`.
    #[must_use]
    pub fn bias(&self, alpha: usize, beta: usize) -> f64 {
        let n = self.sbox.len();
        if n == 0 { return 0.0; }
        let count = self.lat.get(alpha).and_then(|row| row.get(beta)).copied().unwrap_or(0);
        f64::from(count) / f64::from(u32::try_from(n).unwrap_or(u32::MAX)) - 0.5
    }

    /// Find the best (highest absolute bias) linear approximation.
    #[must_use]
    pub fn best_approximation(&self) -> Option<LinearApproximation> {
        let n = self.sbox.len();
        let mut best: Option<LinearApproximation> = None;
        for alpha in 1..n {
            for beta in 1..n {
                let bias = self.bias(alpha, beta);
                let abs_bias = bias.abs();
                let replace = best.as_ref().is_none_or(|b| abs_bias > b.abs_bias);
                if replace {
                    best = Some(LinearApproximation {
                        input_mask: u64::try_from(alpha).unwrap_or(u64::MAX),
                        output_mask: u64::try_from(beta).unwrap_or(u64::MAX),
                        bias,
                        abs_bias,
                        agreeing_count: usize::try_from(self.lat[alpha][beta]).unwrap_or(0),
                        sbox_size: n,
                    });
                }
            }
        }
        best
    }

    /// Enumerate all approximations with |bias| above `threshold`.
    #[must_use]
    pub fn strong_approximations(&self, threshold: f64) -> Vec<LinearApproximation> {
        let n = self.sbox.len();
        // Most approximations are filtered out by the threshold; start small.
        let mut result = Vec::with_capacity(n);
        for alpha in 1..n {
            for beta in 1..n {
                let bias = self.bias(alpha, beta);
                if bias.abs() >= threshold {
                    result.push(LinearApproximation {
                        input_mask: u64::try_from(alpha).unwrap_or(u64::MAX),
                        output_mask: u64::try_from(beta).unwrap_or(u64::MAX),
                        bias,
                        abs_bias: bias.abs(),
                        agreeing_count: usize::try_from(self.lat[alpha][beta]).unwrap_or(0),
                        sbox_size: n,
                    });
                }
            }
        }
        result.sort_by(|a, b| b.abs_bias.partial_cmp(&a.abs_bias).unwrap_or(std::cmp::Ordering::Equal));
        result
    }

    /// Add a known plaintext–ciphertext pair.
    pub fn add_pair(&mut self, plaintext: u64, ciphertext: u64) {
        self.pairs.push((plaintext, ciphertext));
    }

    /// Add multiple pairs.
    pub fn add_pairs(&mut self, pairs: &[(u64, u64)]) {
        self.pairs.extend_from_slice(pairs);
    }

    /// Perform a single-round key-recovery attack.
    ///
    /// For each of 256 partial key hypotheses `k`:
    ///   1. Compute the last-round intermediate value `y = decrypt_last_round(c, k)`.
    ///   2. Evaluate the linear approximation `Γ_P · p ⊕ Γ_C · y = 0`.
    ///   3. Count agreements.
    ///
    /// The key hypothesis with bias closest to the target approximation's bias wins.
    ///
    /// # Arguments
    ///
    /// * `pt_mask` — Plaintext bit mask (`Γ_P`).
    /// * `ct_mask` — Ciphertext bit mask (`Γ_C`).
    /// * `last_round_fn` — Function that partially decrypts the ciphertext under
    ///   a partial key guess (8-bit key byte).
    ///
    /// # Errors
    ///
    /// Returns `LinearAttackError::ZeroBitMask` if both masks are zero, or
    /// `LinearAttackError::InsufficientPairs` if fewer than 8 pairs are available.
    #[must_use = "check the Result for key recovery success"]
    pub fn recover_key_byte(
        &self,
        pt_mask: u64,
        ct_mask: u64,
        last_round_fn: &dyn Fn(u64, u8) -> u64,
    ) -> Result<KeyRecoveryResult, LinearAttackError> {
        if pt_mask == 0 && ct_mask == 0 {
            return Err(LinearAttackError::ZeroBitMask);
        }
        if self.pairs.len() < 8 {
            return Err(LinearAttackError::InsufficientPairs(8));
        }

        let n = self.pairs.len();
        let mut guesses: Vec<KeyGuess> = (0u64..256)
            .map(|k| KeyGuess { key_bits: k, counter: 0 })
            .collect();

        for &(pt, ct) in &self.pairs {
            for guess in &mut guesses {
                let y = last_round_fn(ct, u8::try_from(guess.key_bits & 0xFF).unwrap_or(u8::MAX));
                let pt_parity = (pt & pt_mask).count_ones() & 1;
                let ct_parity = (y  & ct_mask).count_ones() & 1;
                if pt_parity == ct_parity {
                    guess.counter += 1;
                }
            }
        }

        guesses.sort_by(|a, b| b.counter.cmp(&a.counter));
        let winner = &guesses[0];
        let observed_bias = f64::from(i32::try_from(winner.counter).unwrap_or(i32::MAX)) / f64::from(u32::try_from(n).unwrap_or(u32::MAX)) - 0.5;
        let confidence = (observed_bias.abs() * 2.0).clamp(0.0, 1.0);

        Ok(KeyRecoveryResult {
            key_bits:      winner.key_bits,
            bit_mask:      0xFF,
            observed_bias,
            pairs_used:    n,
            confidence,
            reliable:      confidence > 0.5,
        })
    }

    /// Build a `LinearHull` by aggregating all trails with the given masks.
    #[must_use]
    pub fn build_hull(&self, input_mask: u64, output_mask: u64, rounds: u32) -> LinearHull {
        let mut hull = LinearHull::new(input_mask, output_mask, rounds);
        let n = self.sbox.len();
        let n_u64 = u64::try_from(n).unwrap_or(u64::MAX);
        if input_mask < n_u64 && output_mask < n_u64 {
            let ia = usize::try_from(input_mask).unwrap_or(0);
            let ob = usize::try_from(output_mask).unwrap_or(0);
            let bias = self.bias(ia, ob);
            let approx = LinearApproximation {
                input_mask,
                output_mask,
                bias,
                abs_bias: bias.abs(),
                agreeing_count: usize::try_from(self.lat[ia][ob]).unwrap_or(0),
                sbox_size: n,
            };
            hull.add_trail(approx);
        }
        hull
    }

    /// Generate a full `LinearReport` by analysing the S-box and any collected pairs.
    #[must_use]
    pub fn generate_report(&self, rounds: u32) -> LinearReport {
        let mut report = LinearReport::new(&self.cipher_name, self.block_bits, rounds);
        report.sbox_count = 1;

        // Enumerate all strong approximations
        let strong = self.strong_approximations(1.0 / (f64::from(u32::try_from(self.sbox.len()).unwrap_or(u32::MAX)) * 2.0));
        report.best_approximation = strong.first().cloned();

        for approx in &strong {
            let hull = self.build_hull(approx.input_mask, approx.output_mask, rounds);
            report.add_hull(hull);
        }

        // Key recovery stub if pairs are available
        if self.pairs.len() >= 8 {
            // Use identity as last-round function (stub)
            let identity: &dyn Fn(u64, u8) -> u64 = &|ct, _k| ct;
            let pt_mask = strong.first().map_or(1u64, |a| a.input_mask);
            let ct_mask = strong.first().map_or(1u64, |a| a.output_mask);
            if let Ok(kr) = self.recover_key_byte(pt_mask, ct_mask, identity) {
                report.recovered_keys.push(kr);
            }
        }

        report.finalize();
        report
    }

    /// Return the full LAT as a 2D vector of biases (not raw counts).
    #[must_use]
    pub fn lat_as_biases(&self) -> Vec<Vec<f64>> {
        let n = self.sbox.len();
        (0..n).map(|alpha| {
            (0..n).map(|beta| self.bias(alpha, beta)).collect()
        }).collect()
    }

    /// Compute the average absolute bias across all non-trivial entries.
    #[must_use]
    pub fn average_abs_bias(&self) -> f64 {
        let n = self.sbox.len();
        let mut total = 0.0f64;
        let mut count = 0usize;
        for alpha in 1..n {
            for beta in 1..n {
                total += self.bias(alpha, beta).abs();
                count += 1;
            }
        }
        if count == 0 { 0.0 } else { total / f64::from(u32::try_from(count).unwrap_or(u32::MAX)) }
    }
}

// ── Helper: AES S-box (first 16 entries sufficient for unit tests) ─────────────

/// The 4-bit DES S-box S1 (row 0), usable for small tests.
pub const DES_S1_ROW0_4BIT: &[u8] = &[14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7];

/// A tiny 4-bit bijective S-box for testing.
pub const TINY_SBOX_4BIT: &[u8] = &[6, 4, 12, 5, 0, 7, 2, 14, 1, 15, 3, 13, 8, 11, 9, 10];

/// A maximally biased (identity) 4-bit S-box — bias of every alpha=beta is +0.5.
pub const IDENTITY_SBOX_4BIT: &[u8] = &[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn tiny_attack() -> LinearAttack {
        LinearAttack::new(TINY_SBOX_4BIT.to_vec(), "Tiny4", 4).unwrap()
    }

    #[test]
    fn test_lat_dimensions() {
        let attack = tiny_attack();
        assert_eq!(attack.lat.len(), 16);
        for row in &attack.lat {
            assert_eq!(row.len(), 16);
        }
    }

    #[test]
    fn test_lat_row_zero_trivial() {
        let attack = tiny_attack();
        // alpha=0: every input agrees regardless of output → count = n, bias = 0.5
        assert_eq!(attack.lat[0][0], 16);
    }

    #[test]
    fn test_bias_identity_sbox() {
        let attack = LinearAttack::new(IDENTITY_SBOX_4BIT.to_vec(), "Identity", 4).unwrap();
        // For identity S-box, alpha=beta=k: every x satisfies (x & k).parity = (S(x) & k).parity
        for k in 1usize..16 {
            let b = attack.bias(k, k);
            assert!((b - 0.5).abs() < 1e-9, "Expected 0.5, got {b}");
        }
    }

    #[test]
    fn test_best_approximation_nonempty() {
        let attack = tiny_attack();
        let best = attack.best_approximation();
        assert!(best.is_some());
        let b = best.unwrap();
        assert!(b.abs_bias > 0.0);
        assert!(b.input_mask > 0);
        assert!(b.output_mask > 0);
    }

    #[test]
    fn test_best_approximation_identity() {
        let attack = LinearAttack::new(IDENTITY_SBOX_4BIT.to_vec(), "Id", 4).unwrap();
        let best = attack.best_approximation().unwrap();
        assert!((best.abs_bias - 0.5).abs() < 1e-9);
    }

    #[test]
    fn test_strong_approximations_threshold() {
        let attack = tiny_attack();
        let strong = attack.strong_approximations(0.2);
        for approx in &strong {
            assert!(approx.abs_bias >= 0.2);
        }
    }

    #[test]
    fn test_strong_approximations_sorted() {
        let attack = tiny_attack();
        let strong = attack.strong_approximations(0.0);
        for i in 1..strong.len() {
            assert!(strong[i - 1].abs_bias >= strong[i].abs_bias);
        }
    }

    #[test]
    fn test_linear_approximation_probability() {
        let approx = LinearApproximation::compute(TINY_SBOX_4BIT, 0x1, 0x1).unwrap();
        let p = approx.probability();
        assert!((0.0..=1.0).contains(&p));
        assert!((p - (approx.bias + 0.5)).abs() < 1e-9);
    }

    #[test]
    fn test_linear_approximation_trivial() {
        // alpha=0, beta=any → bias should be non-zero (always all agree or all disagree)
        let approx = LinearApproximation::compute(IDENTITY_SBOX_4BIT, 0, 0).unwrap();
        // alpha=beta=0: every input "agrees" (both parities are 0) → bias = 0.5 → NOT trivial
        assert!(!approx.is_trivial());
    }

    #[test]
    fn test_linear_approximation_invalid_sbox() {
        let result = LinearApproximation::compute(&[0u8, 1u8, 2u8], 1, 1);
        assert!(matches!(result, Err(LinearAttackError::InvalidSboxSize(3))));
    }

    #[test]
    fn test_linear_hull_piling_up() {
        let mut hull = LinearHull::new(0x1, 0x1, 2);
        let a1 = LinearApproximation::compute(TINY_SBOX_4BIT, 0x1, 0x1).unwrap();
        let a2 = LinearApproximation::compute(TINY_SBOX_4BIT, 0x2, 0x2).unwrap();
        hull.add_trail(a1.clone());
        hull.add_trail(a2.clone());
        // effective = 2^{2-1} * a1.bias * a2.bias = 2 * a1.bias * a2.bias
        let expected = 2.0 * a1.bias * a2.bias;
        assert!((hull.effective_bias - expected).abs() < 1e-9);
    }

    #[test]
    fn test_linear_hull_required_pairs() {
        let mut hull = LinearHull::new(0x1, 0x1, 1);
        let approx = LinearApproximation { input_mask: 1, output_mask: 1, bias: 0.25, abs_bias: 0.25, agreeing_count: 12, sbox_size: 16 };
        hull.add_trail(approx);
        // ε = 0.25, N ≈ 1/ε^2 = 16
        assert_eq!(hull.required_pairs(), 16);
    }

    #[test]
    fn test_linear_hull_empty_zero_bias() {
        let hull = LinearHull::new(0x1, 0x1, 1);
        assert!(hull.abs_effective_bias().abs() < 1e-9);
    }

    #[test]
    fn test_linear_bias_from_per_round() {
        let biases = vec![0.25, 0.5];
        let lb = LinearBias::from_per_round(0x1, 0x1, biases);
        // effective = 2^{2-1} * 0.25 * 0.5 = 0.25
        assert!((lb.aggregate_bias - 0.25).abs() < 1e-9);
        assert!(lb.pairs_needed() < u64::MAX);
    }

    #[test]
    fn test_linear_bias_practical_flag() {
        // Very large bias → practical
        let lb = LinearBias::from_per_round(1, 1, vec![0.5, 0.5]);
        assert!(lb.is_practical);
        // Very small bias → not practical
        let lb2 = LinearBias::from_per_round(1, 1, vec![1e-5, 1e-5]);
        assert!(!lb2.is_practical);
    }

    #[test]
    fn test_linear_bias_empty() {
        let lb = LinearBias::from_per_round(0, 0, vec![]);
        assert!(lb.aggregate_bias.abs() < 1e-9);
    }

    #[test]
    fn test_recover_key_byte_identity_last_round() {
        let mut attack = tiny_attack();
        // Build pairs: p = p, c = p (trivial encryption with identity)
        for p in 0u64..64 {
            attack.add_pair(p, p);
        }
        let identity_last_round: &dyn Fn(u64, u8) -> u64 = &|ct, _| ct;
        let result = attack.recover_key_byte(0x1, 0x1, identity_last_round).unwrap();
        assert!(result.pairs_used >= 8);
        assert!((0.0..=1.0).contains(&result.confidence));
    }

    #[test]
    fn test_recover_key_byte_insufficient_pairs() {
        let attack = tiny_attack();
        let result = attack.recover_key_byte(0x1, 0x1, &|ct, _| ct);
        assert!(matches!(result, Err(LinearAttackError::InsufficientPairs(_))));
    }

    #[test]
    fn test_recover_key_byte_zero_mask() {
        let mut attack = tiny_attack();
        for p in 0..64u64 { attack.add_pair(p, p); }
        let result = attack.recover_key_byte(0, 0, &|ct, _| ct);
        assert!(matches!(result, Err(LinearAttackError::ZeroBitMask)));
    }

    #[test]
    fn test_generate_report_no_pairs() {
        let attack = tiny_attack();
        let report = attack.generate_report(4);
        assert_eq!(report.rounds_analysed, 4);
        assert_eq!(report.sbox_count, 1);
        assert!(!report.conclusions.is_empty());
    }

    #[test]
    fn test_generate_report_with_pairs() {
        let mut attack = tiny_attack();
        for p in 0u64..64 { attack.add_pair(p, p); }
        let report = attack.generate_report(4);
        assert!(!report.conclusions.is_empty());
    }

    #[test]
    fn test_lat_as_biases_dimensions() {
        let attack = tiny_attack();
        let biases = attack.lat_as_biases();
        assert_eq!(biases.len(), 16);
        assert_eq!(biases[0].len(), 16);
    }

    #[test]
    fn test_average_abs_bias_reasonable() {
        let attack = tiny_attack();
        let avg = attack.average_abs_bias();
        assert!((0.0..=0.5).contains(&avg));
    }

    #[test]
    fn test_des_s1_sbox_best_approx() {
        let attack = LinearAttack::new(DES_S1_ROW0_4BIT.to_vec(), "DES-S1-R0", 4).unwrap();
        let best = attack.best_approximation().unwrap();
        assert!(best.abs_bias > 0.0);
    }

    #[test]
    fn test_add_pairs_bulk() {
        let mut attack = tiny_attack();
        let pairs: Vec<(u64, u64)> = (0..32).map(|i| (i, i ^ 0x5)).collect();
        attack.add_pairs(&pairs);
        assert_eq!(attack.pairs.len(), 32);
    }

    #[test]
    fn test_key_recovery_result_fields() {
        let result = KeyRecoveryResult {
            key_bits: 0x42, bit_mask: 0xFF, observed_bias: 0.3,
            pairs_used: 100, confidence: 0.6, reliable: true,
        };
        assert!(result.reliable);
        assert_eq!(result.key_bits, 0x42);
    }

    #[test]
    fn test_report_finalize_practical() {
        let mut report = LinearReport::new("TestCipher", 64, 4);
        let mut hull = LinearHull::new(1, 1, 4);
        hull.add_trail(LinearApproximation {
            input_mask: 1, output_mask: 1, bias: 0.25, abs_bias: 0.25,
            agreeing_count: 12, sbox_size: 16,
        });
        report.add_hull(hull);
        report.finalize();
        // Should have at least one conclusion
        assert!(!report.conclusions.is_empty());
    }

    #[test]
    fn test_invalid_sbox_size() {
        let result = LinearAttack::new(vec![0u8; 7], "Bad", 8);
        assert!(matches!(result, Err(LinearAttackError::InvalidSboxSize(7))));
    }

    #[test]
    fn test_invalid_sbox_empty() {
        let result = LinearAttack::new(vec![], "Empty", 8);
        assert!(matches!(result, Err(LinearAttackError::InvalidSboxSize(0))));
    }

    #[test]
    fn test_build_hull_direct() {
        let attack = tiny_attack();
        let hull = attack.build_hull(0x1, 0x1, 3);
        assert_eq!(hull.rounds, 3);
        assert_eq!(hull.input_mask, 0x1);
    }

    #[test]
    fn test_linear_approximation_fields() {
        let approx = LinearApproximation::compute(IDENTITY_SBOX_4BIT, 0x5, 0x5).unwrap();
        assert_eq!(approx.input_mask, 0x5);
        assert_eq!(approx.output_mask, 0x5);
        assert_eq!(approx.sbox_size, 16);
    }

    #[test]
    fn test_linear_hull_multiple_trails_product() {
        let mut hull = LinearHull::new(1, 1, 3);
        for _ in 0..3 {
            hull.add_trail(LinearApproximation {
                input_mask: 1, output_mask: 1, bias: 0.25,
                abs_bias: 0.25, agreeing_count: 12, sbox_size: 16,
            });
        }
        // effective = 2^{3-1} * 0.25^3 = 4 * 0.015625 = 0.0625
        assert!((hull.effective_bias.abs() - 0.0625).abs() < 1e-9);
    }

    #[test]
    fn test_pairs_needed_zero_bias() {
        let lb = LinearBias::from_per_round(1, 1, vec![0.0]);
        assert_eq!(lb.pairs_needed(), u64::MAX);
    }

    #[test]
    fn test_strong_approximations_empty_for_zero_threshold() {
        let attack = LinearAttack::new(IDENTITY_SBOX_4BIT.to_vec(), "Id", 4).unwrap();
        let all = attack.strong_approximations(-1.0); // threshold below any bias
        assert!(!all.is_empty());
    }
}
