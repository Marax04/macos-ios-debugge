// rustre-crypto-oracle/src/padding_oracle.rs
// CBC PKCS#7 padding oracle attack — byte-by-byte decryption.

use std::time::Duration;

/// Error from padding oracle operations.
#[derive(Debug, Clone)]
pub enum PaddingOracleError {
    OracleFailure(String),
    InvalidInput(String),
    Timeout,
    MaxRetriesExceeded,
}

impl std::fmt::Display for PaddingOracleError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::OracleFailure(s) => write!(f, "Oracle failure: {s}"),
            Self::InvalidInput(s) => write!(f, "Invalid input: {s}"),
            Self::Timeout => write!(f, "Oracle timed out"),
            Self::MaxRetriesExceeded => write!(f, "Max retries exceeded"),
        }
    }
}

/// Result type for padding oracle operations.
pub type PaddingResult<T> = Result<T, PaddingOracleError>;

/// A padding oracle callable: returns true if the decrypted ciphertext has valid PKCS#7 padding.
pub trait PaddingOracle: Send + Sync {
    /// Returns Ok(true) if the padding is valid, Ok(false) if invalid,
    /// Err if the oracle itself failed (network error, etc.).
    ///
    /// # Errors
    ///
    /// Returns `Err` if the oracle call fails (e.g. network or I/O error).
    fn check(&self, ciphertext: &[u8]) -> PaddingResult<bool>;
}

/// Wrapper around a closure.
pub struct FnPaddingOracle<F: Fn(&[u8]) -> bool + Send + Sync>(pub F);
impl<F: Fn(&[u8]) -> bool + Send + Sync> PaddingOracle for FnPaddingOracle<F> {
    fn check(&self, ct: &[u8]) -> PaddingResult<bool> { Ok((self.0)(ct)) }
}

/// Progress callback for long-running attacks.
pub type ProgressFn = Box<dyn Fn(usize, usize, u8) + Send + Sync>;

/// Configuration for the padding oracle attack.
#[derive(Clone)]
pub struct PaddingOracleConfig {
    pub block_size: usize,
    pub max_retries: usize,
    pub retry_delay: Duration,
    pub verbose: bool,
}

impl Default for PaddingOracleConfig {
    fn default() -> Self {
        Self {
            block_size: 16,
            max_retries: 3,
            retry_delay: Duration::from_millis(50),
            verbose: false,
        }
    }
}

/// CBC padding oracle attacker.
pub struct CbcPaddingOracleAttack {
    pub config: PaddingOracleConfig,
    progress: Option<ProgressFn>,
}

impl CbcPaddingOracleAttack {
    #[must_use]
    pub fn new(config: PaddingOracleConfig) -> Self {
        Self { config, progress: None }
    }

    #[must_use]
    pub fn with_progress(mut self, f: ProgressFn) -> Self {
        self.progress = Some(f);
        self
    }

    /// Decrypt the full CBC ciphertext (with IV prepended or provided separately).
    /// Returns the plaintext with PKCS#7 padding stripped.
    ///
    /// # Errors
    /// Returns `PaddingOracleError::InvalidInput` if lengths are wrong, or propagates oracle errors.
    pub fn decrypt(
        &self,
        oracle: &dyn PaddingOracle,
        iv: &[u8],
        ciphertext: &[u8],
    ) -> PaddingResult<Vec<u8>> {
        let bs = self.config.block_size;
        if !ciphertext.len().is_multiple_of(bs) {
            return Err(PaddingOracleError::InvalidInput(
                format!("Ciphertext length {} not a multiple of block size {}", ciphertext.len(), bs)
            ));
        }
        if iv.len() != bs {
            return Err(PaddingOracleError::InvalidInput(
                format!("IV length {} != block size {}", iv.len(), bs)
            ));
        }

        let num_blocks = ciphertext.len() / bs;
        let mut plaintext = Vec::with_capacity(ciphertext.len());

        // Prepend IV so we can treat iv||C0||C1||... uniformly.
        let mut full = iv.to_vec();
        full.extend_from_slice(ciphertext);

        for block_idx in 0..num_blocks {
            // Previous block (IV for the first block).
            let prev = &full[block_idx * bs..(block_idx + 1) * bs];
            let curr = &full[(block_idx + 1) * bs..(block_idx + 2) * bs];

            let dec = self.decrypt_block(oracle, prev, curr)?;
            plaintext.extend_from_slice(&dec);
        }

        // Strip PKCS#7 padding.
        let stripped = strip_pkcs7(&plaintext).unwrap_or(plaintext);
        Ok(stripped)
    }

    /// Decrypt a single block using the padding oracle (Béri's algorithm).
    /// `prev` is C[i-1] (or IV), `curr` is C[i].
    ///
    /// # Panics
    /// Panics if `prev.len() != block_size` or `curr.len() != block_size`.
    ///
    /// # Errors
    /// Propagates errors from the oracle.
    pub fn decrypt_block(
        &self,
        oracle: &dyn PaddingOracle,
        prev: &[u8],
        curr: &[u8],
    ) -> PaddingResult<Vec<u8>> {
        let bs = self.config.block_size;
        assert_eq!(prev.len(), bs);
        assert_eq!(curr.len(), bs);

        // intermediate[j] = Dec(curr)[j] (before XOR with prev).
        let mut intermediate = vec![0u8; bs];

        for byte_pos in (0..bs).rev() {
            let pad_val = u8::try_from(bs - byte_pos).unwrap_or(u8::MAX);

            // Build a crafted block: for positions already known, set to
            // intermediate[j] XOR pad_val.
            let mut crafted = prev.to_vec();
            for j in (byte_pos + 1)..bs {
                crafted[j] = intermediate[j] ^ pad_val;
            }

            // Try all 256 values for position `byte_pos`.
            let mut found = false;
            for guess in 0u8..=255 {
                crafted[byte_pos] = guess;

                let mut attempt = crafted.clone();
                attempt.extend_from_slice(curr);

                let valid = self.check_with_retry(oracle, &attempt)?;
                if valid {
                    // D(curr)[byte_pos] = guess XOR pad_val.
                    intermediate[byte_pos] = guess ^ pad_val;
                    found = true;
                    if let Some(ref cb) = self.progress {
                        cb(byte_pos, bs, prev[byte_pos] ^ intermediate[byte_pos]);
                    }
                    break;
                }
            }

            if !found {
                // Edge case: padding byte 0x01 might already be valid; try again
                // with a different prefix to disambiguate.
                crafted[byte_pos] = 0;
                if byte_pos > 0 {
                    crafted[byte_pos - 1] ^= 1;
                }
                let mut attempt = crafted.clone();
                attempt.extend_from_slice(curr);
                if self.check_with_retry(oracle, &attempt)? {
                    intermediate[byte_pos] = pad_val;
                } else {
                    intermediate[byte_pos] = 1 ^ pad_val;
                }
            }
        }

        // Plaintext = intermediate XOR prev.
        let plaintext: Vec<u8> = intermediate.iter().zip(prev.iter()).map(|(a, b)| a ^ b).collect();
        Ok(plaintext)
    }

    fn check_with_retry(&self, oracle: &dyn PaddingOracle, ct: &[u8]) -> PaddingResult<bool> {
        for attempt in 0..self.config.max_retries {
            match oracle.check(ct) {
                Ok(result) => return Ok(result),
                Err(PaddingOracleError::Timeout) if attempt < self.config.max_retries - 1 => {
                    std::thread::sleep(self.config.retry_delay);
                }
                Err(e) => return Err(e),
            }
        }
        Err(PaddingOracleError::MaxRetriesExceeded)
    }

    /// CBC bit-flip attack: modify ciphertext to produce a desired plaintext byte at position.
    ///
    /// If we know the plaintext byte at `target_pos` in block `target_block`,
    /// we can flip a bit in the preceding ciphertext block to change it.
    ///
    /// # Errors
    /// Returns `PaddingOracleError::InvalidInput` if `target_block == 0` or byte index is out of bounds.
    pub fn bit_flip_attack(
        &self,
        ciphertext: &[u8],
        target_block: usize,
        target_pos: usize,
        known_plaintext_byte: u8,
        desired_plaintext_byte: u8,
    ) -> PaddingResult<Vec<u8>> {
        let bs = self.config.block_size;
        if target_block == 0 {
            return Err(PaddingOracleError::InvalidInput(
                "target_block must be >= 1 (block 0 has no preceding ciphertext block to flip)".into(),
            ));
        }
        let prev_block_start = (target_block - 1)
            .checked_mul(bs)
            .ok_or_else(|| PaddingOracleError::InvalidInput("target_block overflow".into()))?;
        let byte_idx = prev_block_start
            .checked_add(target_pos)
            .ok_or_else(|| PaddingOracleError::InvalidInput("target_pos overflow".into()))?;
        if byte_idx >= ciphertext.len() {
            return Err(PaddingOracleError::InvalidInput(format!(
                "byte index {byte_idx} out of ciphertext bounds (len={})",
                ciphertext.len()
            )));
        }
        let mut modified = ciphertext.to_vec();
        // Flip the byte in the previous ciphertext block.
        modified[byte_idx] ^= known_plaintext_byte ^ desired_plaintext_byte;
        Ok(modified)
    }
}

/// PKCS#7 padding validation.
///
/// # Panics
///
/// Panics if `data` is non-empty but `last()` fails (cannot happen in practice).
#[must_use]
pub fn validate_pkcs7(data: &[u8]) -> bool {
    if data.is_empty() { return false; }
    let pad = usize::from(*data.last().unwrap());
    if pad == 0 || pad > data.len() { return false; }
    data[data.len() - pad..].iter().all(|&b| usize::from(b) == pad)
}

/// Strip PKCS#7 padding from data. Returns None if padding is invalid.
///
/// # Panics
///
/// Panics if `data` is non-empty but `last()` fails (cannot happen in practice).
#[must_use]
pub fn strip_pkcs7(data: &[u8]) -> Option<Vec<u8>> {
    if !validate_pkcs7(data) { return None; }
    let pad = usize::from(*data.last().unwrap());
    Some(data[..data.len() - pad].to_vec())
}

/// Add PKCS#7 padding to data.
///
/// # Panics
/// Panics if `block_size` is 0 or greater than 255.
#[must_use]
pub fn add_pkcs7(data: &[u8], block_size: usize) -> Vec<u8> {
    assert!(block_size > 0 && block_size <= 255, "block_size must be 1..=255");
    let pad = block_size - (data.len() % block_size);
    let mut padded = data.to_vec();
    padded.extend(std::iter::repeat_n(u8::try_from(pad).unwrap_or(u8::MAX), pad));
    padded
}

/// Detect the block size by querying the oracle (sends increasing-length inputs
/// and looks for a jump in output length).
#[must_use]
pub fn detect_block_size<F>(encrypt_fn: F) -> Option<usize>
where
    F: Fn(&[u8]) -> Vec<u8>,
{
    let base_len = encrypt_fn(b"A").len();
    for i in 2..=64usize {
        let input = vec![b'A'; i];
        let out = encrypt_fn(&input);
        if out.len() > base_len {
            return Some(out.len() - base_len);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Trivial "oracle" for testing: decrypts using a fixed key via XOR and checks PKCS#7.
    struct TrivialOracle { key: [u8; 16] }
    impl PaddingOracle for TrivialOracle {
        fn check(&self, ct: &[u8]) -> PaddingResult<bool> {
            if ct.len() < 32 { return Ok(false); }
            let prev = &ct[..16];
            let curr = &ct[16..32];
            // "Decrypt": XOR current with key, then XOR with prev.
            let dec: Vec<u8> = curr.iter().zip(self.key.iter()).zip(prev.iter())
                .map(|((c, k), p)| c ^ k ^ p).collect();
            Ok(validate_pkcs7(&dec))
        }
    }

    #[test]
    fn trivial_oracle_rejects_invalid_padding() {
        let oracle = TrivialOracle { key: [0u8; 16] };
        // All zeros → last byte 0 → invalid padding
        assert_eq!(oracle.check(&[0u8; 32]).unwrap(), false);
    }

    #[test]
    fn pkcs7_add_strip_round_trip() {
        let data = b"hello world";
        let padded = add_pkcs7(data, 16);
        assert_eq!(padded.len(), 16);
        let stripped = strip_pkcs7(&padded).unwrap();
        assert_eq!(&stripped, data);
    }

    #[test]
    fn pkcs7_validate_valid() {
        // Correct PKCS#7: last byte N must equal value of all final N bytes.
        // {01,02,03,04} ends in 0x04 so requires the final 4 bytes to all be 0x04;
        // a single trailing 0x04 is valid only when the last byte alone equals the pad length.
        assert!(validate_pkcs7(&[0x01, 0x02, 0x03, 0x01]));
        assert!(validate_pkcs7(&[0x09; 9]));
    }

    #[test]
    fn pkcs7_validate_invalid() {
        assert!(!validate_pkcs7(&[0x00]));
        // Test data fix: previous data {05,04,03,02,01} is actually VALID PKCS#7
        // (last byte 0x01 means strip 1 byte). Use a clearly-invalid sequence instead:
        // last byte 0x03 demands the final three bytes all be 0x03.
        assert!(!validate_pkcs7(&[0x05, 0x04, 0x03, 0x02, 0x03]));
    }

    #[test]
    fn bit_flip_modifies_correct_byte() {
        let config = PaddingOracleConfig::default();
        let attack = CbcPaddingOracleAttack::new(config);
        let ciphertext = vec![0xaa_u8; 32];
        let modified = attack.bit_flip_attack(&ciphertext, 1, 5, b'A', b'B').unwrap();
        // Only byte at position 5 of block 0 should differ.
        for i in 0..32 {
            if i == 5 {
                assert_ne!(modified[i], ciphertext[i]);
            } else {
                assert_eq!(modified[i], ciphertext[i]);
            }
        }
    }

    #[test]
    fn detect_block_size_works() {
        // Simulate an oracle that pads to 16-byte boundaries.
        let f = |input: &[u8]| -> Vec<u8> {
            let pad = 16 - (input.len() % 16);
            let mut out = input.to_vec();
            out.extend(std::iter::repeat_n(u8::try_from(pad).unwrap_or(u8::MAX), pad));
            out
        };
        let bs = detect_block_size(f);
        assert_eq!(bs, Some(16));
    }
}
