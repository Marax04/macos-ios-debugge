//! Stream cipher attack implementations.
//!
//! Provides RC4 bias exploitation, `ChaCha20` fault injection model,
//! A5/1 skeleton, full Berlekamp-Massey LFSR detection, and
//! keystream statistical tests.

// ── RC4 Bias Attack ───────────────────────────────────────────────────────────

/// Statistical bias data for a single keystream byte position.
#[derive(Debug, Clone)]
pub struct Rc4ByteBias {
    /// Byte position in the keystream (0-indexed).
    pub position: usize,
    /// Observed frequency distribution (counts per value 0..255).
    pub freq: [u64; 256],
    /// Total samples collected.
    pub total_samples: u64,
}

impl Rc4ByteBias {
    /// Create an empty bias collector for a given position.
    #[must_use]
    pub const fn new(position: usize) -> Self {
        Self {
            position,
            freq: [0u64; 256],
            total_samples: 0,
        }
    }

    /// Record a keystream byte observation.
    pub fn record(&mut self, byte: u8) {
        self.freq[usize::from(byte)] += 1;
        self.total_samples += 1;
    }

    /// Most likely keystream byte (argmax of frequency).
    #[must_use]
    pub fn most_likely_byte(&self) -> u8 {
        self.freq
            .iter()
            .enumerate()
            .max_by_key(|&(_, &c)| c)
            .map_or(0, |(i, _)| u8::try_from(i).unwrap_or(u8::MAX))
    }

    /// Bias ratio for a specific value: freq[v] / `expected_uniform`.
    #[must_use]
    pub fn bias_ratio(&self, value: u8) -> f64 {
        if self.total_samples == 0 {
            return 1.0;
        }
        let expected = f64::from(u32::try_from(self.total_samples).unwrap_or(u32::MAX)) / 256.0;
        f64::from(u32::try_from(self.freq[usize::from(value)]).unwrap_or(u32::MAX)) / expected
    }

    /// Maximum bias ratio across all byte values.
    #[must_use]
    pub fn max_bias_ratio(&self) -> f64 {
        (0u8..=255)
            .map(|v| self.bias_ratio(v))
            .fold(0.0f64, f64::max)
    }
}

/// RC4 keystream bias attack.
///
/// Exploits known RC4 biases:
/// - Byte 0 is biased towards 0 with probability 2/256.
/// - Byte 1 is biased towards 0 with probability 2/256.
/// - The NOMORE/Royal Holloway attacks exploit further long-range biases.
pub struct Rc4BiasAttack {
    /// Per-position bias collectors.
    pub bias: Vec<Rc4ByteBias>,
    /// Number of keystream samples collected.
    pub sample_count: u64,
}

impl Rc4BiasAttack {
    /// Create a new attack collector tracking `tracked_bytes` positions.
    #[must_use]
    pub fn new(tracked_bytes: usize) -> Self {
        Self {
            bias: (0..tracked_bytes).map(Rc4ByteBias::new).collect(),
            sample_count: 0,
        }
    }

    /// Feed a full keystream sample (must be at least `tracked_bytes` long).
    pub fn add_keystream(&mut self, keystream: &[u8]) {
        for (i, collector) in self.bias.iter_mut().enumerate() {
            if let Some(&byte) = keystream.get(i) {
                collector.record(byte);
            }
        }
        self.sample_count += 1;
    }

    /// Feed an individual sample using an RC4 key oracle.
    pub fn collect<F>(&mut self, num_samples: usize, key_oracle: F)
    where
        F: Fn(u64) -> Vec<u8>,
    {
        for i in 0..u64::try_from(num_samples).unwrap_or(u64::MAX) {
            let ks = key_oracle(i);
            self.add_keystream(&ks);
        }
    }

    /// Recover the most likely plaintext byte at each tracked position.
    /// For position i: P[i] = `most_likely_keystream`[i] XOR ciphertext[i].
    #[must_use]
    pub fn recover_plaintext_bytes(&self, ciphertext: &[u8]) -> Vec<u8> {
        self.bias
            .iter()
            .enumerate()
            .filter_map(|(i, b)| ciphertext.get(i).map(|&ct| ct ^ b.most_likely_byte()))
            .collect()
    }

    /// Exploit the known RC4 byte-0 bias: P[0] ≈ C[0] XOR 0 (key is biased to 0).
    #[must_use]
    pub const fn exploit_byte0_bias(ciphertext_byte0: u8) -> u8 {
        // RC4 bias: keystream[0] = 0 with probability 2/256 = 1/128
        // Under NOMORE: biased toward 0
        ciphertext_byte0
    }

    /// Exploit the BEAST/RC4 byte-1 bias toward 0xAA in certain configurations.
    /// (Simplified; full attack depends on key scheduling specifics.)
    #[must_use]
    pub fn exploit_invariance_bias(ciphertext_byte: u8, position: usize) -> u8 {
        // For large N, keystream[i] is biased toward i+1 in some configurations
        ciphertext_byte ^ u8::try_from(position + 1).unwrap_or(u8::MAX)
    }

    /// Check if the bias data is sufficient to make a confident prediction.
    ///
    /// `min_samples` is the minimum number of samples required (e.g. `1_000_000` for
    /// a confidence threshold of 1.0 on the internal 10⁶-scaled metric).
    #[must_use]
    pub const fn has_sufficient_samples(&self, min_samples: u64) -> bool {
        // Need ~2^24 samples for full byte-level RC4 attacks
        self.sample_count
            >= min_samples
    }
}

// ── ChaCha20 Fault Injection ──────────────────────────────────────────────────

/// A single `ChaCha20` state word modification (fault).
#[derive(Debug, Clone)]
pub struct ChaCha20FaultSpec {
    /// Word index (0..15) to modify.
    pub word_idx: usize,
    /// XOR mask to apply.
    pub fault_mask: u32,
    /// Which round to inject the fault before (0 = before any rounds).
    pub inject_before_round: u8,
}

/// `ChaCha20` fault injection model.
pub struct ChaCha20Fault {
    faults: Vec<(Vec<u8>, Vec<u8>, ChaCha20FaultSpec)>,
}

impl ChaCha20Fault {
    /// Create a new fault collector.
    #[must_use]
    pub const fn new() -> Self {
        Self { faults: Vec::new() }
    }

    /// Add a (`correct_output`, `faulty_output`, `fault_spec`) triple.
    pub fn add_fault_triple(&mut self, correct: Vec<u8>, faulty: Vec<u8>, spec: ChaCha20FaultSpec) {
        self.faults.push((correct, faulty, spec));
    }

    /// Number of fault triples collected.
    #[must_use]
    pub const fn triple_count(&self) -> usize {
        self.faults.len()
    }

    /// Compute differential masks between correct and faulty outputs.
    #[must_use]
    pub fn differentials(&self) -> Vec<Vec<u8>> {
        self.faults
            .iter()
            .map(|(c, f, _)| c.iter().zip(f.iter()).map(|(&a, &b)| a ^ b).collect())
            .collect()
    }

    /// Attempt to recover the key word at index `word_idx` using fault differential.
    /// Returns candidate key words (u32 values) or empty if insufficient data.
    #[must_use]
    pub fn recover_key_word(&self, word_idx: usize) -> Vec<u32> {
        let mut candidates: Vec<u32> = (0..=255u32).collect();
        for (correct, faulty, spec) in &self.faults {
            if spec.word_idx != word_idx || correct.len() < 4 || faulty.len() < 4 {
                continue;
            }
            let c_word = u32::from_le_bytes(correct[0..4].try_into().unwrap_or([0; 4]));
            let f_word = u32::from_le_bytes(faulty[0..4].try_into().unwrap_or([0; 4]));
            let diff = c_word ^ f_word;
            // Narrow candidates: k such that chacha_output_diff(k, spec.fault_mask) == diff
            candidates.retain(|&k| {
                // Simplified model: the fault propagates XOR through one add-rotate-XOR step
                (k ^ spec.fault_mask).rotate_left(16) ^ k.rotate_left(16) == diff
            });
        }
        candidates
    }
}

impl Default for ChaCha20Fault {
    fn default() -> Self {
        Self::new()
    }
}

// ── A5/1 Correlation Attack Skeleton ─────────────────────────────────────────

/// A5/1 register configuration (as used in GSM).
#[derive(Debug, Clone)]
pub struct A51Registers {
    /// Register R1: 19 bits, feedback polynomial x^19+x^18+x^17+x^14+1.
    pub r1: u32,
    /// Register R2: 22 bits, feedback polynomial x^22+x^21+1.
    pub r2: u32,
    /// Register R3: 23 bits, feedback polynomial x^23+x^22+x^21+x^8+1.
    pub r3: u32,
}

impl A51Registers {
    /// Create from session key bits (simplified initialization).
    #[must_use]
    pub fn from_key(key_bits: u64) -> Self {
        Self {
            r1: u32::try_from(key_bits & 0x0007_FFFF).unwrap_or(u32::MAX),
            r2: u32::try_from((key_bits >> 19) & 0x003F_FFFF).unwrap_or(u32::MAX),
            r3: u32::try_from((key_bits >> 41) & 0x007F_FFFF).unwrap_or(u32::MAX),
        }
    }

    /// Clock bit for R1 (majority rule, 8th bit is clock bit).
    #[inline]
    const fn clock_bit_r1(&self) -> u32 {
        (self.r1 >> 8) & 1
    }
    #[inline]
    const fn clock_bit_r2(&self) -> u32 {
        (self.r2 >> 10) & 1
    }
    #[inline]
    const fn clock_bit_r3(&self) -> u32 {
        (self.r3 >> 10) & 1
    }

    /// Majority vote of the three clock bits.
    #[inline]
    const fn majority_clock(&self) -> u32 {
        let c1 = self.clock_bit_r1();
        let c2 = self.clock_bit_r2();
        let c3 = self.clock_bit_r3();
        (c1 & c2) | (c2 & c3) | (c1 & c3)
    }

    /// Clock the registers one step. Returns one output bit.
    pub const fn clock(&mut self) -> u8 {
        let maj = self.majority_clock();

        if self.clock_bit_r1() == maj {
            let fb = ((self.r1 >> 18) ^ (self.r1 >> 17) ^ (self.r1 >> 16) ^ (self.r1 >> 13)) & 1;
            self.r1 = ((self.r1 << 1) | fb) & 0x0007_FFFF;
        }
        if self.clock_bit_r2() == maj {
            let fb = ((self.r2 >> 21) ^ (self.r2 >> 20)) & 1;
            self.r2 = ((self.r2 << 1) | fb) & 0x003F_FFFF;
        }
        if self.clock_bit_r3() == maj {
            let fb = ((self.r3 >> 22) ^ (self.r3 >> 21) ^ (self.r3 >> 20) ^ (self.r3 >> 7)) & 1;
            self.r3 = ((self.r3 << 1) | fb) & 0x007F_FFFF;
        }

        (((self.r1 >> 18) ^ (self.r2 >> 21) ^ (self.r3 >> 22)) & 1) as u8
    }

    /// Generate `n` output bits.
    #[must_use]
    pub fn generate(&mut self, n: usize) -> Vec<u8> {
        (0..n).map(|_| self.clock()).collect()
    }
}

/// A5/1 correlation attack skeleton.
pub struct A5_1Attack {
    /// Guesses for register initial states.
    pub guesses: Vec<A51Registers>,
}

impl A5_1Attack {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            guesses: Vec::new(),
        }
    }

    /// Correlation attack phase 1: precompute R1/R2 states from known keystream prefix.
    /// Skeleton: in a real attack, we build a 2^42 time-memory tradeoff table.
    pub fn precompute_table(&mut self, known_ks: &[u8], n_guesses: usize) {
        // Stub: generate n_guesses random R1 values and correlate with known_ks
        for r1_guess in 0u32..u32::try_from(n_guesses).unwrap_or(u32::MAX) {
            let r2_guess = r1_guess.wrapping_mul(0x1337).wrapping_add(0xABCD);
            let r3_guess = r1_guess.wrapping_mul(0xDEAD).wrapping_add(0xBEEF);
            let mut regs = A51Registers {
                r1: r1_guess & 0x007_FFFF,
                r2: r2_guess & 0x003F_FFFF,
                r3: r3_guess & 0x007F_FFFF,
            };
            let ks = regs.generate(known_ks.len());
            let matches = ks
                .iter()
                .zip(known_ks.iter())
                .filter(|&(&a, &b)| a == b)
                .count();
            if matches * 2 >= known_ks.len() {
                self.guesses.push(A51Registers {
                    r1: r1_guess & 0x007_FFFF,
                    r2: r2_guess & 0x003F_FFFF,
                    r3: r3_guess & 0x007F_FFFF,
                });
            }
        }
    }

    /// Number of surviving guesses after correlation filtering.
    #[must_use]
    pub const fn candidate_count(&self) -> usize {
        self.guesses.len()
    }
}

impl Default for A5_1Attack {
    fn default() -> Self {
        Self::new()
    }
}

// ── LFSR Detection: Berlekamp-Massey ─────────────────────────────────────────

/// Result of the Berlekamp-Massey algorithm.
#[derive(Debug, Clone)]
pub struct BerlekampMasseyResult {
    /// The minimum LFSR connection polynomial (coefficients in GF(2)).
    /// Index 0 is the constant term; the polynomial is C(x) = 1 + c[1]x + c[2]x^2 + ...
    pub connection_poly: Vec<u8>,
    /// Linear complexity: length of the minimum LFSR.
    pub linear_complexity: usize,
    /// Fraction of the sequence predicted correctly by the LFSR.
    pub prediction_accuracy: f64,
}

impl BerlekampMasseyResult {
    /// Use the LFSR to generate additional sequence bits.
    #[must_use]
    pub fn generate(&self, initial_state: &[u8], length: usize) -> Vec<u8> {
        if self.connection_poly.is_empty() || initial_state.is_empty() {
            return vec![0u8; length];
        }
        let lc = self.linear_complexity;
        if lc == 0 {
            return vec![0u8; length];
        }
        // Use the last lc bits of initial_state as the starting register
        let mut reg: Vec<u8> = initial_state.iter().rev().take(lc).rev().copied().collect();
        while reg.len() < lc {
            reg.insert(0, 0);
        }
        let mut output = Vec::with_capacity(length);
        for _ in 0..length {
            output.push(reg[lc - 1]);
            // Feedback: new bit = sum of poly[i] * reg[i-1]
            let fb: u8 = self
                .connection_poly
                .iter()
                .skip(1) // skip constant term
                .enumerate()
                .map(|(i, &c)| if i < reg.len() { c & reg[i] } else { 0 })
                .fold(0u8, |acc, x| acc ^ x);
            reg.pop();
            reg.insert(0, fb);
        }
        output
    }
}

/// Linear Feedback Shift Register detection and analysis.
pub struct LinearFeedbackAnalysis;

impl LinearFeedbackAnalysis {
    /// Berlekamp-Massey algorithm over GF(2).
    ///
    /// Given a binary sequence `seq` (each byte is one bit: 0 or 1),
    /// returns the minimum LFSR that generates it.
    ///
    /// # Panics
    ///
    /// Panics if `conn.last()` returns `None` during trailing-zero trimming (cannot happen: `conn` always has at least one element).
    #[must_use]
    pub fn berlekamp_massey(seq: &[u8]) -> BerlekampMasseyResult {
        let seq_len = seq.len();
        // C: current connection polynomial; B: previous connection polynomial
        let mut conn = vec![1u8]; // C(x) = 1
        let mut prev_conn = vec![1u8]; // B(x) = 1
        let mut complexity = 0usize; // current linear complexity
        let mut shift = 1usize; // shift
        let mut discrepancy_prev = 1u8; // b (previous discrepancy that changed L)

        for i in 0..seq_len {
            // Compute discrepancy d
            let discrepancy: u8 = seq[i]
                ^ conn.iter()
                    .enumerate()
                    .skip(1)
                    .map(|(j, &cj)| if j <= i { cj & seq[i - j] } else { 0 })
                    .fold(0u8, |acc, x| acc ^ x);

            if discrepancy == 0 {
                shift += 1;
                continue;
            }

            // T(x) = C(x) - (d / discrepancy_prev) * x^m * B(x)
            // In GF(2): d / discrepancy_prev = d * discrepancy_prev^-1 = d (since 1^-1=1)
            let factor = gf2_div(discrepancy, discrepancy_prev);
            let mut next_conn = conn.clone();
            // Expand b by shift positions
            let mut shifted = vec![0u8; shift];
            shifted.extend_from_slice(&prev_conn);
            // next_conn = conn XOR factor * shifted
            let max_len = next_conn.len().max(shifted.len());
            next_conn.resize(max_len, 0);
            for (j, bv) in shifted.iter().enumerate() {
                if j < next_conn.len() {
                    next_conn[j] ^= gf2_mul(factor, *bv);
                } else {
                    next_conn.push(gf2_mul(factor, *bv));
                }
            }

            if 2 * complexity <= i {
                complexity = i + 1 - complexity;
                prev_conn = conn;
                discrepancy_prev = discrepancy;
                shift = 1;
            } else {
                shift += 1;
            }
            conn = next_conn;
        }

        // Trim trailing zeros
        while conn.len() > 1 && *conn.last().unwrap() == 0 {
            conn.pop();
        }

        // Verify prediction accuracy
        let accuracy = if seq_len == 0 {
            1.0
        } else {
            let predicted: Vec<u8> = {
                let result = BerlekampMasseyResult {
                    connection_poly: conn.clone(),
                    linear_complexity: complexity,
                    prediction_accuracy: 0.0,
                };
                result.generate(seq, seq_len)
            };
            let correct = predicted
                .iter()
                .zip(seq.iter())
                .filter(|&(&pred, &actual)| pred == actual)
                .count();
            f64::from(u32::try_from(correct).unwrap_or(u32::MAX))
                / f64::from(u32::try_from(seq_len).unwrap_or(u32::MAX))
        };

        BerlekampMasseyResult {
            connection_poly: conn,
            linear_complexity: complexity,
            prediction_accuracy: accuracy,
        }
    }

    /// Detect whether `seq` (binary, one bit per byte) looks like LFSR output.
    /// Returns `true` if the linear complexity is much smaller than len(seq)/2.
    #[must_use]
    pub fn detect_lfsr(seq: &[u8]) -> bool {
        if seq.len() < 4 {
            return false;
        }
        let result = Self::berlekamp_massey(seq);
        result.linear_complexity * 4 <= seq.len()
    }

    /// Compute the linear complexity profile of a sequence.
    /// Returns a vector of (n, L(n)) pairs.
    #[must_use]
    pub fn linear_complexity_profile(seq: &[u8]) -> Vec<(usize, usize)> {
        let mut profile = Vec::new();
        for n in 1..=seq.len() {
            let result = Self::berlekamp_massey(&seq[..n]);
            profile.push((n, result.linear_complexity));
        }
        profile
    }

    /// Convert a byte slice to a bit vector (MSB first).
    #[must_use]
    pub fn bytes_to_bits(data: &[u8]) -> Vec<u8> {
        let mut bits = Vec::with_capacity(data.len() * 8);
        for &byte in data {
            for i in (0..8).rev() {
                bits.push((byte >> i) & 1);
            }
        }
        bits
    }

    /// Convert a bit vector (MSB first) to bytes.
    #[must_use]
    pub fn bits_to_bytes(bits: &[u8]) -> Vec<u8> {
        bits.chunks(8)
            .map(|chunk| {
                chunk
                    .iter()
                    .enumerate()
                    .fold(0u8, |acc, (i, &b)| acc | (b << (7 - i)))
            })
            .collect()
    }
}

// GF(2) arithmetic helpers
#[inline]
const fn gf2_mul(a: u8, b: u8) -> u8 {
    a & b
}
#[inline]
const fn gf2_div(a: u8, b: u8) -> u8 {
    if b == 0 { 0 } else { a }
} // in GF(2), division by 1 = multiply by 1

// ── Keystream Statistical Tests ───────────────────────────────────────────────

/// Results of a suite of keystream statistical tests.
#[derive(Debug, Clone)]
pub struct KeystreamTestResult {
    /// NIST SP800-22 Monobit frequency test p-value approximation.
    pub monobit_p_value: f64,
    /// Monobit test pass (p > 0.01).
    pub monobit_pass: bool,
    /// Runs test p-value approximation.
    pub runs_p_value: f64,
    /// Runs test pass.
    pub runs_pass: bool,
    /// Lag-1 autocorrelation coefficient.
    pub autocorrelation_lag1: f64,
    /// Whether the sequence appears random (all basic tests pass).
    pub appears_random: bool,
    /// Entropy (bits per byte).
    pub byte_entropy: f64,
    /// Longest run of identical bits.
    pub longest_run: usize,
}

/// Statistical analysis of keystream quality.
pub struct KeystreamAnalysis;

impl KeystreamAnalysis {
    /// Run all tests and return a summary result.
    #[must_use]
    pub fn analyze(keystream: &[u8]) -> KeystreamTestResult {
        let bits = LinearFeedbackAnalysis::bytes_to_bits(keystream);
        let monobit_p_value = Self::monobit_test(&bits);
        let runs_p_value = Self::runs_test(&bits);
        let autocorrelation_lag1 = Self::autocorrelation(&bits, 1);
        let byte_entropy = Self::byte_entropy(keystream);
        let longest_run = Self::longest_run(&bits);

        let monobit_pass = monobit_p_value > 0.01;
        let runs_pass = runs_p_value > 0.01;
        let appears_random =
            monobit_pass && runs_pass && autocorrelation_lag1.abs() < 0.1 && byte_entropy > 7.0;

        KeystreamTestResult {
            monobit_p_value,
            monobit_pass,
            runs_p_value,
            runs_pass,
            autocorrelation_lag1,
            appears_random,
            byte_entropy,
            longest_run,
        }
    }

    /// NIST monobit frequency test.
    /// H0: the number of ones and zeros should be approximately equal.
    /// Returns an approximate p-value.
    #[must_use]
    pub fn monobit_test(bits: &[u8]) -> f64 {
        if bits.is_empty() {
            return 1.0;
        }
        let n = f64::from(u32::try_from(bits.len()).unwrap_or(u32::MAX));
        let ones: f64 = bits.iter().map(|&b| f64::from(b)).sum();
        let s = 2.0f64.mul_add(ones, -n) / n.sqrt();
        // Approximate complementary error function
        erfc_approx(s.abs() / std::f64::consts::SQRT_2)
    }

    /// NIST runs test.
    /// A run is a maximal sequence of consecutive identical bits.
    /// Returns an approximate p-value.
    #[must_use]
    pub fn runs_test(bits: &[u8]) -> f64 {
        if bits.len() < 2 {
            return 1.0;
        }
        let n = f64::from(u32::try_from(bits.len()).unwrap_or(u32::MAX));
        let pi = bits.iter().map(|&b| f64::from(b)).sum::<f64>() / n;

        // Pre-test: check proportion is within bounds
        if (pi - 0.5).abs() > 2.0 / n.sqrt() {
            return 0.0;
        }

        // Count runs
        let v_n = 1.0 + f64::from(
            u32::try_from(bits.windows(2).filter(|w| w[0] != w[1]).count()).unwrap_or(u32::MAX),
        );
        let expected = 2.0 * n * pi * (1.0 - pi);
        let variance = 2.0 * n * pi * (1.0 - pi) * 2.0f64.mul_add(-pi, 1.0);
        if variance <= 0.0 {
            return 0.5;
        }
        let z = (v_n - expected) / variance.sqrt();
        erfc_approx(z.abs() / std::f64::consts::SQRT_2)
    }

    /// Lag-k autocorrelation of a binary sequence.
    #[must_use]
    pub fn autocorrelation(bits: &[u8], lag: usize) -> f64 {
        if bits.len() <= lag {
            return 0.0;
        }
        let n = f64::from(u32::try_from(bits.len() - lag).unwrap_or(u32::MAX));
        let mean = bits.iter().map(|&b| f64::from(b)).sum::<f64>()
            / f64::from(u32::try_from(bits.len()).unwrap_or(u32::MAX));
        let cov: f64 = bits[..bits.len() - lag]
            .iter()
            .zip(bits[lag..].iter())
            .map(|(&a, &b)| (f64::from(a) - mean) * (f64::from(b) - mean))
            .sum::<f64>()
            / n;
        let var: f64 = bits.iter().map(|&b| (f64::from(b) - mean).powi(2)).sum::<f64>()
            / f64::from(u32::try_from(bits.len()).unwrap_or(u32::MAX));
        if var < 1e-12 {
            return 0.0;
        }
        cov / var
    }

    /// Shannon entropy in bits per byte.
    #[must_use]
    pub fn byte_entropy(data: &[u8]) -> f64 {
        if data.is_empty() {
            return 0.0;
        }
        let mut freq = [0u64; 256];
        for &b in data {
            freq[usize::from(b)] += 1;
        }
        let n = f64::from(u32::try_from(data.len()).unwrap_or(u32::MAX));
        freq.iter()
            .filter(|&&c| c > 0)
            .map(|&c| {
                let p = f64::from(u32::try_from(c).unwrap_or(u32::MAX)) / n;
                -p * p.log2()
            })
            .sum()
    }

    /// Longest run of identical bits.
    #[must_use]
    pub fn longest_run(bits: &[u8]) -> usize {
        if bits.is_empty() {
            return 0;
        }
        let mut max_run = 1usize;
        let mut run = 1usize;
        for w in bits.windows(2) {
            if w[0] == w[1] {
                run += 1;
                max_run = max_run.max(run);
            } else {
                run = 1;
            }
        }
        max_run
    }

    /// Chi-squared uniformity test for byte distribution.
    /// Returns the chi-squared statistic.
    #[must_use]
    pub fn chi_squared_byte(data: &[u8]) -> f64 {
        if data.is_empty() {
            return 0.0;
        }
        let mut freq = [0u64; 256];
        for &b in data {
            freq[usize::from(b)] += 1;
        }
        let expected = f64::from(u32::try_from(data.len()).unwrap_or(u32::MAX)) / 256.0;
        freq.iter()
            .map(|&c| {
                let diff = f64::from(u32::try_from(c).unwrap_or(u32::MAX)) - expected;
                diff * diff / expected
            })
            .sum()
    }

    /// Estimate the period of the keystream using autocorrelation.
    /// Checks lags `1..max_lag` and returns the lag with peak correlation.
    #[must_use]
    pub fn estimate_period(keystream: &[u8], max_lag: usize) -> Option<usize> {
        let bits = LinearFeedbackAnalysis::bytes_to_bits(keystream);
        let baseline = Self::autocorrelation(&bits, 1).abs();
        let mut best_lag = None;
        let mut best_corr = baseline + 0.05; // threshold: 5% above baseline
        for lag in 2..=max_lag.min(bits.len() / 2) {
            let corr = Self::autocorrelation(&bits, lag).abs();
            if corr > best_corr {
                best_corr = corr;
                best_lag = Some(lag);
            }
        }
        best_lag
    }
}

/// Approximate complementary error function for p-value calculation.
fn erfc_approx(x: f64) -> f64 {
    // Abramowitz & Stegun approximation 7.1.26
    let t = 1.0 / 0.327_591_1_f64.mul_add(x, 1.0);
    let poly = t
        * (0.254_829_592
            + t * (-0.284_496_736 + t * (1.421_413_741 + t * (-1.453_152_027 + t * 1.061_405_429))));
    poly * (-x * x).exp()
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── RC4 Bias ──────────────────────────────────────────────────────────────

    #[test]
    fn test_rc4_bias_new() {
        let b = Rc4ByteBias::new(0);
        assert_eq!(b.position, 0);
        assert_eq!(b.total_samples, 0);
    }

    #[test]
    fn test_rc4_bias_record() {
        let mut b = Rc4ByteBias::new(0);
        b.record(0x42);
        b.record(0x42);
        b.record(0x00);
        assert_eq!(b.total_samples, 3);
        assert_eq!(b.freq[0x42], 2);
        assert_eq!(b.freq[0x00], 1);
    }

    #[test]
    fn test_rc4_bias_most_likely_byte() {
        let mut b = Rc4ByteBias::new(0);
        for _ in 0..10 {
            b.record(0x42);
        }
        b.record(0x00);
        assert_eq!(b.most_likely_byte(), 0x42);
    }

    #[test]
    fn test_rc4_bias_ratio() {
        let mut b = Rc4ByteBias::new(0);
        // Record 256 samples uniformly
        for v in 0u8..=255 {
            b.record(v);
        }
        // Bias ratio should be ~1.0 for all values
        assert!((b.bias_ratio(0) - 1.0).abs() < 0.1);
    }

    #[test]
    fn test_rc4_attack_new() {
        let atk = Rc4BiasAttack::new(16);
        assert_eq!(atk.bias.len(), 16);
        assert_eq!(atk.sample_count, 0);
    }

    #[test]
    fn test_rc4_attack_add_keystream() {
        let mut atk = Rc4BiasAttack::new(4);
        atk.add_keystream(&[0x01, 0x02, 0x03, 0x04]);
        assert_eq!(atk.sample_count, 1);
        assert_eq!(atk.bias[0].most_likely_byte(), 0x01);
    }

    #[test]
    fn test_rc4_attack_recover_plaintext() {
        let mut atk = Rc4BiasAttack::new(4);
        // All keystreams have byte 0 = 0x42
        for _ in 0..10 {
            atk.add_keystream(&[0x42, 0x00, 0x00, 0x00]);
        }
        let ct = vec![0x42 ^ b'H', b'i', 0x00, 0x00];
        let pt = atk.recover_plaintext_bytes(&ct);
        assert_eq!(pt[0], b'H');
    }

    #[test]
    fn test_rc4_exploit_byte0() {
        let result = Rc4BiasAttack::exploit_byte0_bias(0x41);
        assert_eq!(result, 0x41);
    }

    // ── ChaCha20 Fault ────────────────────────────────────────────────────────

    #[test]
    fn test_chacha20_fault_new() {
        let f = ChaCha20Fault::new();
        assert_eq!(f.triple_count(), 0);
    }

    #[test]
    fn test_chacha20_fault_add_triple() {
        let mut f = ChaCha20Fault::new();
        f.add_fault_triple(
            vec![0u8; 64],
            vec![1u8; 64],
            ChaCha20FaultSpec {
                word_idx: 0,
                fault_mask: 0xFF,
                inject_before_round: 10,
            },
        );
        assert_eq!(f.triple_count(), 1);
    }

    #[test]
    fn test_chacha20_fault_differentials() {
        let mut f = ChaCha20Fault::new();
        f.add_fault_triple(
            vec![0u8; 4],
            vec![0xFFu8; 4],
            ChaCha20FaultSpec {
                word_idx: 0,
                fault_mask: 0xFF,
                inject_before_round: 10,
            },
        );
        let diffs = f.differentials();
        assert_eq!(diffs[0], vec![0xFFu8; 4]);
    }

    #[test]
    fn test_chacha20_fault_recover_word_empty() {
        let f = ChaCha20Fault::new();
        let cands = f.recover_key_word(0);
        // With no faults, all 256 candidates remain
        assert_eq!(cands.len(), 256);
    }

    // ── A5/1 ─────────────────────────────────────────────────────────────────

    #[test]
    fn test_a51_from_key() {
        let regs = A51Registers::from_key(0x1234_5678_9ABC);
        assert!(regs.r1 < (1 << 19));
        assert!(regs.r2 < (1 << 22));
        assert!(regs.r3 < (1 << 23));
    }

    #[test]
    fn test_a51_clock() {
        let mut regs = A51Registers::from_key(0xDEAD_BEEF_1234);
        let bit = regs.clock();
        assert!(bit == 0 || bit == 1);
    }

    #[test]
    fn test_a51_generate() {
        let mut regs = A51Registers::from_key(0xCAFE_BABE_1234);
        let ks = regs.generate(64);
        assert_eq!(ks.len(), 64);
        assert!(ks.iter().all(|&b| b == 0 || b == 1));
    }

    #[test]
    fn test_a51_deterministic() {
        let mut r1 = A51Registers::from_key(0x1111_2222_3333);
        let mut r2 = A51Registers::from_key(0x1111_2222_3333);
        let ks1 = r1.generate(32);
        let ks2 = r2.generate(32);
        assert_eq!(ks1, ks2);
    }

    #[test]
    fn test_a51_attack_new() {
        let atk = A5_1Attack::new();
        assert_eq!(atk.candidate_count(), 0);
    }

    // ── Berlekamp-Massey ──────────────────────────────────────────────────────

    #[test]
    fn test_bm_simple_lfsr() {
        // LFSR with feedback x^3 + x + 1, initial state [1,0,0]
        // Sequence: 0,0,1,0,1,1,1,0,0,1... period 7
        let seq = [1u8, 0, 0, 1, 0, 1, 1, 1, 0, 0, 1, 0, 1, 1];
        let result = LinearFeedbackAnalysis::berlekamp_massey(&seq);
        assert!(
            result.linear_complexity <= 4,
            "LC should be <= 4 for period-7 LFSR"
        );
    }

    #[test]
    fn test_bm_all_zeros() {
        let seq = [0u8; 16];
        let result = LinearFeedbackAnalysis::berlekamp_massey(&seq);
        assert_eq!(result.linear_complexity, 0);
    }

    #[test]
    fn test_bm_alternating() {
        // 0,1,0,1,... has LC = 2
        let seq: Vec<u8> = (0u8..16).map(|i| i % 2).collect();
        let result = LinearFeedbackAnalysis::berlekamp_massey(&seq);
        assert!(result.linear_complexity <= 2);
    }

    #[test]
    fn test_bm_connection_poly_non_empty() {
        let seq = [1u8, 0, 1, 1, 0, 1, 0];
        let result = LinearFeedbackAnalysis::berlekamp_massey(&seq);
        assert!(!result.connection_poly.is_empty());
    }

    #[test]
    fn test_detect_lfsr_true() {
        // Repeating pattern clearly has low LC
        let seq: Vec<u8> = vec![0, 0, 1, 0, 0, 1, 0, 0, 1, 0, 0, 1, 0, 0, 1, 0, 0, 1];
        assert!(LinearFeedbackAnalysis::detect_lfsr(&seq));
    }

    #[test]
    fn test_bytes_to_bits_roundtrip() {
        let data = b"Hello";
        let bits = LinearFeedbackAnalysis::bytes_to_bits(data);
        let bytes = LinearFeedbackAnalysis::bits_to_bytes(&bits);
        assert_eq!(&bytes, data);
    }

    #[test]
    fn test_bits_to_bytes_h() {
        // 'H' = 0x48 = 0100 1000
        let bits = [0u8, 1, 0, 0, 1, 0, 0, 0];
        let bytes = LinearFeedbackAnalysis::bits_to_bytes(&bits);
        assert_eq!(bytes[0], b'H');
    }

    // ── Keystream Analysis ────────────────────────────────────────────────────

    #[test]
    fn test_monobit_test_balanced() {
        // Perfectly balanced sequence should pass
        let bits: Vec<u8> = (0u16..1024).map(|i| u8::from(i % 2 == 1)).collect();
        let p = KeystreamAnalysis::monobit_test(&bits);
        assert!(
            p > 0.01,
            "Balanced sequence should pass monobit test, p={p}"
        );
    }

    #[test]
    fn test_monobit_test_all_ones() {
        let bits = vec![1u8; 1024];
        let p = KeystreamAnalysis::monobit_test(&bits);
        // Should be extremely small (fail)
        assert!(
            p < 0.01,
            "All-ones sequence should fail monobit test, p={p}"
        );
    }

    #[test]
    fn test_runs_test_balanced() {
        let bits: Vec<u8> = (0u16..1024).map(|i| u8::from(i % 2 == 1)).collect();
        let p = KeystreamAnalysis::runs_test(&bits);
        // Regular alternation is extremely unlikely in random data
        let _ = p; // just verify no panic
    }

    #[test]
    fn test_autocorrelation_lag1_alternating() {
        let bits: Vec<u8> = (0u8..64).map(|i| i % 2).collect();
        let ac = KeystreamAnalysis::autocorrelation(&bits, 1);
        // Alternating sequence has strong negative lag-1 autocorrelation
        assert!(
            ac < -0.5,
            "Alternating should have strong negative AC: {ac}"
        );
    }

    #[test]
    fn test_byte_entropy_uniform() {
        let data: Vec<u8> = (0u8..=255).collect();
        let ent = KeystreamAnalysis::byte_entropy(&data);
        assert!(
            (ent - 8.0).abs() < 0.01,
            "Uniform entropy should be 8.0 bits: {ent}"
        );
    }

    #[test]
    fn test_byte_entropy_constant() {
        let data = vec![0x42u8; 256];
        let ent = KeystreamAnalysis::byte_entropy(&data);
        assert!(
            (ent - 0.0).abs() < 0.01,
            "Constant entropy should be 0.0: {ent}"
        );
    }

    #[test]
    fn test_longest_run() {
        let bits = vec![0u8, 0, 0, 1, 1, 0, 1, 0, 0, 0, 0, 1];
        assert_eq!(KeystreamAnalysis::longest_run(&bits), 4);
    }

    #[test]
    fn test_chi_squared_uniform() {
        let data: Vec<u8> = (0u8..=255).collect();
        let chi2 = KeystreamAnalysis::chi_squared_byte(&data);
        assert!(chi2 < 1.0, "Uniform chi2 should be ~0: {chi2}");
    }

    #[test]
    fn test_analyze_random_looking() {
        // RC4 keystream of a simple key should look random
        let mut s: [u8; 256] = std::array::from_fn(|i| u8::try_from(i).unwrap_or(u8::MAX));
        let key = b"test";
        let mut j = 0usize;
        for i in 0..256 {
            j = (j + usize::from(s[i]) + usize::from(key[i % key.len()])) % 256;
            s.swap(i, j);
        }
        let mut ks = Vec::with_capacity(256);
        let mut ii = 0usize;
        let mut jj = 0usize;
        for _ in 0..256 {
            ii = (ii + 1) % 256;
            jj = (jj + usize::from(s[ii])) % 256;
            s.swap(ii, jj);
            ks.push(s[(usize::from(s[ii]) + usize::from(s[jj])) % 256]);
        }
        let result = KeystreamAnalysis::analyze(&ks);
        assert!(
            result.byte_entropy > 5.0,
            "RC4 should have high entropy: {}",
            result.byte_entropy
        );
    }
}
