// rustre-crypto-id/src/active_prober.rs
// Active algorithm identification from input→output pairs.

use std::collections::HashMap;

/// A single input→output observation.
#[derive(Debug, Clone)]
pub struct IoSample {
    pub input: Vec<u8>,
    pub output: Vec<u8>,
}

impl IoSample {
    pub fn new(input: impl Into<Vec<u8>>, output: impl Into<Vec<u8>>) -> Self {
        Self { input: input.into(), output: output.into() }
    }
}

/// Confidence level for an algorithm identification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Confidence {
    Low,
    Medium,
    High,
    Certain,
}

/// Algorithm hypothesis from active probing.
#[derive(Debug, Clone)]
pub struct AlgorithmHypothesis {
    pub algorithm: &'static str,
    pub variant: Option<String>,
    pub confidence: Confidence,
    pub evidence: Vec<String>,
}

/// Result of active probing a black-box function.
#[derive(Debug, Clone)]
pub struct ProbeResult {
    pub hypotheses: Vec<AlgorithmHypothesis>,
    pub block_size: Option<usize>,
    pub output_size: Option<usize>,
    pub is_deterministic: bool,
    pub preserves_length: bool,
    pub notes: Vec<String>,
}

impl ProbeResult {
    const fn new() -> Self {
        Self {
            hypotheses: Vec::new(),
            block_size: None,
            output_size: None,
            is_deterministic: true,
            preserves_length: false,
            notes: Vec::new(),
        }
    }

    /// Best hypothesis (highest confidence).
    #[must_use]
    pub fn best(&self) -> Option<&AlgorithmHypothesis> {
        self.hypotheses.iter().max_by_key(|h| h.confidence)
    }
}

/// A callable black-box oracle.
pub trait BlackBox: Send + Sync {
    /// Encrypt/transform the given input. Returns output or error string.
    ///
    /// # Errors
    /// Returns `Err(String)` if the oracle fails to process the input.
    fn call(&self, input: &[u8]) -> Result<Vec<u8>, String>;
}

/// Wrapper around a closure for convenience.
pub struct FnBlackBox<F: Fn(&[u8]) -> Vec<u8> + Send + Sync>(pub F);

impl<F: Fn(&[u8]) -> Vec<u8> + Send + Sync> BlackBox for FnBlackBox<F> {
    fn call(&self, input: &[u8]) -> Result<Vec<u8>, String> {
        Ok((self.0)(input))
    }
}

/// Active prober — drives a black-box and infers the underlying algorithm.
pub struct ActiveProber {
    pub max_queries: usize,
    pub timeout_ms: u64,
}

impl Default for ActiveProber {
    fn default() -> Self {
        Self { max_queries: 1000, timeout_ms: 5000 }
    }
}

impl ActiveProber {
    #[must_use]
    pub const fn new(max_queries: usize, timeout_ms: u64) -> Self {
        Self { max_queries, timeout_ms }
    }

    /// Full identification pipeline.
    pub fn probe(&self, oracle: &dyn BlackBox) -> ProbeResult {
        let mut result = ProbeResult::new();

        // Step 1: gather basic observations.
        let samples = Self::gather_samples(oracle);
        if samples.is_empty() {
            result.notes.push("Oracle returned no samples".into());
            return result;
        }

        // Step 2: characterise output.
        result.output_size = Self::detect_output_size(&samples);
        result.block_size = Self::detect_block_size(oracle);
        result.preserves_length = Self::check_length_preservation(&samples);
        result.is_deterministic = Self::check_determinism(oracle);

        // Step 3: apply classifiers.
        Self::classify_hash(&samples, &mut result);
        Self::classify_block_cipher(&samples, &mut result);
        Self::classify_stream_cipher(&samples, &mut result);
        Self::classify_xor(&samples, &mut result);
        Self::classify_mac(&samples, oracle, &mut result);

        // Step 4: sort hypotheses by confidence.
        result.hypotheses.sort_by(|a, b| b.confidence.cmp(&a.confidence));
        result
    }

    fn gather_samples(oracle: &dyn BlackBox) -> Vec<IoSample> {
        let test_inputs: &[&[u8]] = &[
            b"",
            b"\x00",
            b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
            b"\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff",
            b"AAAAAAAAAAAAAAAA",
            b"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            b"The quick brown fox jumps over the lazy dog",
            &[0u8; 32],
            &[0u8; 64],
            b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f",
        ];
        let mut samples = Vec::new();
        for input in test_inputs {
            if let Ok(output) = oracle.call(input) {
                samples.push(IoSample::new(*input, output));
            }
        }
        samples
    }

    fn detect_output_size(samples: &[IoSample]) -> Option<usize> {
        let sizes: Vec<usize> = samples.iter().map(|s| s.output.len()).collect();
        if sizes.is_empty() { return None; }
        // If all non-empty outputs have the same size → fixed output.
        let non_empty: Vec<usize> = sizes.iter().filter(|&&s| s > 0).copied().collect();
        if non_empty.is_empty() { return None; }
        let first = non_empty[0];
        if non_empty.iter().all(|&s| s == first) { Some(first) } else { None }
    }

    fn detect_block_size(oracle: &dyn BlackBox) -> Option<usize> {
        // Send increasing-length inputs and detect first output size jump.
        let base = oracle.call(b"A").ok()?.len();
        for len in 2..=64usize {
            let input = vec![b'A'; len];
            if let Ok(out) = oracle.call(&input)
                && out.len() > base {
                    return Some(out.len() - base);
                }
        }
        None
    }

    fn check_length_preservation(samples: &[IoSample]) -> bool {
        samples.iter().filter(|s| !s.input.is_empty()).all(|s| s.input.len() == s.output.len())
    }

    fn check_determinism(oracle: &dyn BlackBox) -> bool {
        let input = b"AAAAAAAAAAAAAAAA";
        let out1 = oracle.call(input).ok();
        let out2 = oracle.call(input).ok();
        out1 == out2
    }

    // ─── Hash classifier ────────────────────────────────────────────────────

    fn classify_hash(samples: &[IoSample], result: &mut ProbeResult) {
        let Some(fixed) = result.output_size else { return };

        let known_sizes: &[(&str, usize)] = &[
            ("MD5",    16),
            ("SHA-1",  20),
            ("SHA-224",28),
            ("SHA-256",32),
            ("SHA-384",48),
            ("SHA-512",64),
            ("SHA3-256",32),
            ("SHA3-512",64),
            ("BLAKE2b",64),
            ("BLAKE2s",32),
        ];

        if let Some(&(name, _)) = known_sizes.iter().find(|&&(_, s)| s == fixed) {
            // Additional check: different inputs should produce different outputs.
            let all_differ = samples.windows(2).all(|pair| {
                pair[0].input != pair[1].input || pair[0].output != pair[1].output
            });
            let evidence = vec![
                format!("Fixed output size {fixed} bytes matches {name}"),
                if all_differ { "Outputs differ for distinct inputs".into() }
                else { "Some outputs match (possible collision or trivial function)".into() },
            ];
            result.hypotheses.push(AlgorithmHypothesis {
                algorithm: "HASH",
                variant: Some(name.to_string()),
                confidence: if all_differ { Confidence::High } else { Confidence::Medium },
                evidence,
            });
        }
    }

    // ─── Block cipher classifier ─────────────────────────────────────────────

    fn classify_block_cipher(samples: &[IoSample], result: &mut ProbeResult) {
        // AES-ECB: block size 16, same input → same output, output is multiple of 16.
        let Some(block) = result.block_size else { return };

        if block == 16 {
            let evidence = vec![
                "Block size 16 consistent with AES".into(),
                if result.is_deterministic { "Deterministic (no IV) → ECB mode likely".into() }
                else { "Non-deterministic → CBC/CTR/GCM mode".into() },
            ];
            result.hypotheses.push(AlgorithmHypothesis {
                algorithm: "AES",
                variant: Some(if result.is_deterministic { "ECB".into() } else { "CBC/CTR".into() }),
                confidence: Confidence::High,
                evidence,
            });
        } else if block == 8 {
            result.hypotheses.push(AlgorithmHypothesis {
                algorithm: "DES/3DES/Blowfish",
                variant: Some("64-bit block".into()),
                confidence: Confidence::Medium,
                evidence: vec!["Block size 8 matches DES, 3DES, or Blowfish".into()],
            });
        }

        // ECB detection: two identical 16-byte blocks produce identical output blocks.
        let ecb_probe = Self::probe_ecb_mode(samples);
        if ecb_probe {
            result.notes.push("ECB mode confirmed: identical input blocks → identical output blocks".into());
        }
    }

    fn probe_ecb_mode(samples: &[IoSample]) -> bool {
        // Look for a 32-byte input (two identical 16-byte blocks) that produces 32 bytes
        // where the first 16 == the last 16.
        for sample in samples {
            if sample.input.len() == 32 && sample.input[..16] == sample.input[16..]
                && sample.output.len() >= 32 && sample.output[..16] == sample.output[16..32] {
                    return true;
                }
        }
        false
    }

    // ─── Stream cipher classifier ────────────────────────────────────────────

    fn classify_stream_cipher(samples: &[IoSample], result: &mut ProbeResult) {
        if !result.preserves_length { return; }

        // RC4: XORs keystream with plaintext; check correlation between output lengths and inputs.
        // Simplified: if output length == input length for all inputs, it's a stream cipher or XOR.
        let mut evidence = vec!["Output length equals input length for all samples".into()];

        // Check if XOR of pairs of outputs correlates with XOR of inputs (stream cipher property).
        let stream_like = Self::check_stream_cipher_property(samples);
        if stream_like {
            evidence.push("XOR of outputs for same-length inputs is consistent with stream cipher".into());
            result.hypotheses.push(AlgorithmHypothesis {
                algorithm: "STREAM_CIPHER",
                variant: Some("RC4/ChaCha20/Salsa20".into()),
                confidence: Confidence::Medium,
                evidence,
            });
        }
    }

    fn check_stream_cipher_property(samples: &[IoSample]) -> bool {
        // For a stream cipher: E(m1) XOR E(m2) = m1 XOR m2 (if same key/nonce, ECB mode).
        // We check that the output XOR patterns are consistent.
        let pairs: Vec<_> = samples.iter()
            .filter(|s| s.input.len() == s.output.len() && !s.input.is_empty())
            .collect();
        if pairs.len() < 2 { return false; }

        // Check that E(0^n) XOR E(p) = keystream XOR p for some keystream.
        let zero_sample = pairs.iter().find(|s| s.input.iter().all(|&b| b == 0));
        if let Some(ks) = zero_sample {
            // keystream = E(0^n)
            for other in &pairs {
                if other.input.len() != ks.input.len() { continue; }
                let predicted: Vec<u8> = other.input.iter().zip(ks.output.iter())
                    .map(|(p, k)| p ^ k).collect();
                if predicted != other.output { return false; }
            }
            return true;
        }
        false
    }

    // ─── XOR classifier ──────────────────────────────────────────────────────

    fn classify_xor(samples: &[IoSample], result: &mut ProbeResult) {
        if !result.preserves_length { return; }

        // Simple byte-by-byte XOR: output[i] = input[i] XOR key[i % key_len].
        if let Some(key_len) = Self::detect_xor_key_length(samples) {
            result.hypotheses.push(AlgorithmHypothesis {
                algorithm: "XOR",
                variant: Some(format!("fixed key, length {key_len}")),
                confidence: Confidence::High,
                evidence: vec![
                    format!("Repeating XOR key detected, period = {key_len}"),
                    "Output length equals input length".into(),
                ],
            });
        }
    }

    fn detect_xor_key_length(samples: &[IoSample]) -> Option<usize> {
        // Try to find two samples with different inputs of the same length.
        let pairs: Vec<_> = samples.iter()
            .filter(|s| s.input.len() == s.output.len() && !s.input.is_empty())
            .collect();

        for i in 0..pairs.len() {
            for j in (i+1)..pairs.len() {
                let a = &pairs[i];
                let b = &pairs[j];
                if a.input.len() != b.input.len() { continue; }
                // Candidate key from first pair: k[x] = in[x] XOR out[x].
                let key_a: Vec<u8> = a.input.iter().zip(a.output.iter()).map(|(i,o)| i ^ o).collect();
                let key_b: Vec<u8> = b.input.iter().zip(b.output.iter()).map(|(i,o)| i ^ o).collect();
                if key_a == key_b {
                    // Detect period.
                    for period in 1..=key_a.len() {
                        if key_a.chunks(period).all(|c| c == &key_a[..c.len()]) {
                            return Some(period);
                        }
                    }
                }
            }
        }
        None
    }

    // ─── MAC classifier ──────────────────────────────────────────────────────

    fn classify_mac(_samples: &[IoSample], oracle: &dyn BlackBox, result: &mut ProbeResult) {
        // HMAC: output is fixed size (hash output size) regardless of input length.
        // Length extension: H(secret || msg) may be vulnerable if we can extend.
        let fixed = match result.output_size {
            Some(s) if [16, 20, 28, 32, 48, 64].contains(&s) => s,
            _ => return,
        };

        // Try length extension: if we append data and the tag changes predictably.
        let base = b"AAAAAAAAAAAAAAA";
        let extended = b"AAAAAAAAAAAAAAAAsome_extension";
        let tag_base = oracle.call(base).ok();
        let tag_ext = oracle.call(extended).ok();

        if let (Some(t1), Some(t2)) = (tag_base, tag_ext)
            && t1.len() == fixed && t2.len() == fixed && t1 != t2 {
                result.hypotheses.push(AlgorithmHypothesis {
                    algorithm: "MAC",
                    variant: Some(format!("HMAC or raw H(secret||msg), output={fixed}B")),
                    confidence: Confidence::Medium,
                    evidence: vec![
                        format!("Fixed output size {fixed}B matches hash"),
                        "Different messages produce different MACs".into(),
                    ],
                });
            }
    }
}

/// Identify algorithm from a static list of pre-collected I/O samples (no live oracle).
#[must_use]
pub fn identify_from_samples(samples: &[IoSample]) -> ProbeResult {
    let mut result = ProbeResult::new();
    if samples.is_empty() { return result; }

    // Output size.
    let sizes: Vec<usize> = samples.iter().map(|s| s.output.len()).collect();
    let first_nonempty = sizes.iter().find(|&&s| s > 0).copied();
    result.output_size = if sizes.iter().all(|&s| s == *first_nonempty.as_ref().unwrap_or(&usize::MAX)) {
        first_nonempty
    } else { None };

    // Length preservation.
    result.preserves_length = samples.iter()
        .filter(|s| !s.input.is_empty())
        .all(|s| s.input.len() == s.output.len());

    // Determinism: cannot check without re-calling oracle, assume true.
    result.is_deterministic = true;

    // Apply static classifiers.
    ActiveProber::classify_hash(samples, &mut result);
    ActiveProber::classify_xor(samples, &mut result);

    result
}

/// Compute byte-frequency histogram for a slice.
#[must_use]
pub fn byte_histogram(data: &[u8]) -> [u32; 256] {
    let mut hist = [0u32; 256];
    for &b in data { hist[b as usize] += 1; }
    hist
}

/// Shannon entropy of a byte slice in bits per byte.
#[must_use]
pub fn shannon_entropy(data: &[u8]) -> f64 {
    if data.is_empty() { return 0.0; }
    let hist = byte_histogram(data);
    let n = f64::from(u32::try_from(data.len()).unwrap_or(u32::MAX));
    -hist.iter()
        .filter(|&&c| c > 0)
        .map(|&c| { let p = f64::from(c) / n; p * p.log2() })
        .sum::<f64>()
}

/// Estimate key length for repeating-XOR by Index of Coincidence.
#[must_use]
pub fn estimate_xor_key_length(ciphertext: &[u8], max_key: usize) -> Option<usize> {
    // On short inputs classical IC is too noisy. Instead: for each candidate
    // key length, recover the best single-byte XOR for each column and score
    // the resulting plaintext against English. The true key length yields the
    // most English-like decryption; multiples of it score similarly, so among
    // ties we pick the smallest.
    /// Minimum ciphertext bytes per key column for a candidate length to be
    /// considered at all.
    ///
    /// Each candidate length `k` splits the ciphertext into `k` columns and
    /// recovers one byte per column. With only two or three samples per column
    /// the recovery is fitting noise, and a long key wins simply because it has
    /// more degrees of freedom: on a 46-byte ciphertext encrypted with a 6-byte
    /// key, `max_key = 20` was returned — 20 columns of 2 bytes each. The
    /// linear `key_penalty` below cannot offset that, because the overfit
    /// scores grow faster than the penalty. Refusing under-sampled candidates
    /// is the standard guard for this technique and it addresses the cause
    /// rather than re-tuning a constant.
    const MIN_SAMPLES_PER_COLUMN: usize = 5;

    let mut scored: Vec<(usize, i64, f64)> = Vec::new();
    for key_len in 1..=max_key.min(ciphertext.len() / 2) {
        if ciphertext.len() / key_len < MIN_SAMPLES_PER_COLUMN {
            continue;
        }
        let mut key = vec![0u8; key_len];
        for (i, slot) in key.iter_mut().enumerate() {
            let column: Vec<u8> = ciphertext
                .iter()
                .skip(i)
                .step_by(key_len)
                .copied()
                .collect();
            if column.is_empty() { continue; }
            *slot = best_xor_byte(&column);
        }
        let decrypted: Vec<u8> = ciphertext
            .iter()
            .enumerate()
            .map(|(i, b)| b ^ key[i % key_len])
            .collect();
        // Combine printability (a hard "is this plaintext?" signal) with the
        // English-letter score (a finer-grained "does this look like English?"
        // signal). The true key length wins both; multiples of it tie.
        let printable = decrypted
            .iter()
            .filter(|&&b| (b == b' ' || b == b'\n' || b == b'\t') || (0x20..0x7f).contains(&b))
            .count();
        let printable_score = i64::from(u32::try_from(printable).unwrap_or(u32::MAX)) * 1000
            / i64::from(u32::try_from(decrypted.len()).unwrap_or(1));
        // Subtract a per-byte-of-key penalty to counteract overfitting: longer
        // candidate keys have more degrees of freedom and can score artificially
        // high even when wrong. The IOC of the decrypted text is folded into
        // the english signal: English text has IOC ~0.067, uniformly random
        // bytes ~0.0039. Distance from the English target rewards correct
        // periods on shorter inputs where pure letter-frequency scoring is
        // noisy. The factor 1000 keeps the IOC bonus on the same order of
        // magnitude as `english_score`.
        let ioc = index_of_coincidence(&decrypted);
        let ioc_bonus: f64 = 1000.0 * (ioc - 0.067).abs().mul_add(-15.0, 1.0).max(0.0);
        let eng_raw = english_score(&decrypted);
        let eng_f = f64::from(i32::try_from(eng_raw).unwrap_or(i32::MAX));
        let key_penalty = f64::from(u32::try_from(key_len).unwrap_or(u32::MAX));
        let english: f64 = eng_f + ioc_bonus - key_penalty;
        scored.push((key_len, printable_score, english));
    }
    let peak_print = scored.iter().map(|&(_, p, _)| p).max()?;
    if peak_print <= 0 { return None; }
    // Among candidates with maximum printability, pick the one with the best
    // English score; ties are broken by smallest key length (true period).
    let top: Vec<&(usize, i64, f64)> = scored.iter().filter(|&&(_, p, _)| p == peak_print).collect();
    let best_english = top.iter().map(|&&(_, _, e)| e).fold(f64::NEG_INFINITY, f64::max);
    top.iter()
        .find(|&&&(_, _, e)| (e - best_english).abs() < f64::EPSILON)
        .map(|&&(k, _, _)| k)
}

fn index_of_coincidence(data: &[u8]) -> f64 {
    let n = f64::from(u32::try_from(data.len()).unwrap_or(u32::MAX));
    if n < 2.0 { return 0.0; }
    let hist = byte_histogram(data);
    let numerator: f64 = hist.iter().map(|&c| f64::from(c) * (f64::from(c) - 1.0)).sum();
    numerator / (n * (n - 1.0))
}

/// Recover repeating XOR key given ciphertext and known key length.
#[must_use]
pub fn recover_xor_key(ciphertext: &[u8], key_len: usize) -> Vec<u8> {
    let mut key = vec![0u8; key_len];
    for (i, slot) in key.iter_mut().enumerate() {
        let column: Vec<u8> = ciphertext.iter().skip(i).step_by(key_len).copied().collect();
        *slot = best_xor_byte(&column);
    }
    key
}

/// Find the single XOR byte that makes a column look most like English ASCII.
fn best_xor_byte(column: &[u8]) -> u8 {
    let mut best = (0u8, i64::MIN);
    for k in 0u8..=255 {
        let decrypted: Vec<u8> = column.iter().map(|&b| b ^ k).collect();
        let score = english_score(&decrypted);
        if score > best.1 { best = (k, score); }
    }
    best.0
}

fn english_score(data: &[u8]) -> i64 {
    let freq = b"etaoin shrdlu";
    data.iter().map(|b| {
        if freq.contains(b) { 2i64 }
        else if b.is_ascii_alphanumeric() { 1 }
        else if b.is_ascii_punctuation() { 0 }
        else { -3 }
    }).sum()
}

/// Differential analysis: XOR inputs with outputs to extract keystream or key material.
#[must_use]
pub fn differential_io(samples: &[IoSample]) -> Vec<Vec<u8>> {
    samples.iter()
        .filter(|s| s.input.len() == s.output.len())
        .map(|s| s.input.iter().zip(s.output.iter()).map(|(a, b)| a ^ b).collect())
        .collect()
}

/// Compare two output slices at the byte level; return first differing byte offset.
#[must_use]
pub fn first_diff(a: &[u8], b: &[u8]) -> Option<usize> {
    a.iter().zip(b.iter()).position(|(x, y)| x != y)
}

/// Build a frequency map of output bytes across all samples (useful for stream cipher analysis).
#[must_use]
pub fn aggregate_output_histogram(samples: &[IoSample]) -> HashMap<u8, u64> {
    let mut map = HashMap::new();
    for s in samples {
        for &b in &s.output {
            *map.entry(b).or_insert(0u64) += 1;
        }
    }
    map
}

#[cfg(test)]
mod tests {
    use super::*;

    struct XorOracle { key: Vec<u8> }
    impl BlackBox for XorOracle {
        fn call(&self, input: &[u8]) -> Result<Vec<u8>, String> {
            Ok(input.iter().enumerate().map(|(i, b)| b ^ self.key[i % self.key.len()]).collect())
        }
    }

    struct Sha256Oracle;
    impl BlackBox for Sha256Oracle {
        fn call(&self, input: &[u8]) -> Result<Vec<u8>, String> {
            // Fake fixed-32-byte output for testing.
            let mut out = vec![0u8; 32];
            for (i, b) in input.iter().enumerate() {
                out[i % 32] ^= b.wrapping_add(i as u8);
            }
            Ok(out)
        }
    }

    #[test]
    fn detects_xor_cipher() {
        let oracle = XorOracle { key: vec![0x42, 0x13, 0x37] };
        let prober = ActiveProber::default();
        let result = prober.probe(&oracle);
        let best = result.best().expect("should have hypothesis");
        assert!(best.algorithm.contains("XOR") || best.algorithm.contains("STREAM"),
            "Expected XOR or STREAM, got {}", best.algorithm);
    }

    #[test]
    fn detects_hash_like() {
        let oracle = Sha256Oracle;
        let prober = ActiveProber::default();
        let result = prober.probe(&oracle);
        assert!(result.output_size == Some(32));
    }

    #[test]
    fn entropy_random_bytes() {
        let data: Vec<u8> = (0u8..=255).collect();
        let e = shannon_entropy(&data);
        assert!(e > 7.9, "Expected near-8 entropy, got {e}");
    }

    #[test]
    fn xor_key_recovery() {
        let key = b"SECRET";
        let plaintext = b"Hello, world! This is a test of XOR encryption.";
        let ciphertext: Vec<u8> = plaintext.iter().enumerate()
            .map(|(i, b)| b ^ key[i % key.len()]).collect();
        let est_len = estimate_xor_key_length(&ciphertext, 20);
        assert_eq!(est_len, Some(6));
        let recovered = recover_xor_key(&ciphertext, 6);
        assert_eq!(&recovered, key);
    }
}
