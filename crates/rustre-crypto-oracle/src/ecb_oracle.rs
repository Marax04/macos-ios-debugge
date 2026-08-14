// rustre-crypto-oracle/src/ecb_oracle.rs
// ECB detection and chosen-plaintext attack to recover secret suffix.

use std::collections::HashMap;

/// Error type for ECB oracle operations.
#[derive(Debug, Clone)]
pub enum EcbOracleError {
    NotEcb,
    BlockSizeNotFound,
    PrefixTooLarge,
    AttackFailed(String),
}

impl std::fmt::Display for EcbOracleError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotEcb => write!(f, "Oracle is not ECB mode"),
            Self::BlockSizeNotFound => write!(f, "Could not determine block size"),
            Self::PrefixTooLarge => write!(f, "Oracle prefix too large to handle"),
            Self::AttackFailed(s) => write!(f, "Attack failed: {s}"),
        }
    }
}

/// An encryption oracle wrapping `ECB(attacker_controlled || secret_suffix)`.
pub trait EcbOracle: Send + Sync {
    /// Encrypt the given input (which is prepended to a secret suffix) under ECB.
    fn encrypt(&self, input: &[u8]) -> Vec<u8>;
}

/// Wrap a closure as an [`EcbOracle`].
pub struct FnEcbOracle<F: Fn(&[u8]) -> Vec<u8> + Send + Sync>(pub F);
impl<F: Fn(&[u8]) -> Vec<u8> + Send + Sync> EcbOracle for FnEcbOracle<F> {
    fn encrypt(&self, input: &[u8]) -> Vec<u8> { (self.0)(input) }
}

/// Result of the ECB byte-at-a-time attack.
#[derive(Debug, Clone)]
pub struct EcbAttackResult {
    pub secret: Vec<u8>,
    pub block_size: usize,
    pub prefix_len: usize,
    pub num_queries: usize,
}

/// ECB oracle attacker.
pub struct EcbAttacker {
    pub max_block_size: usize,
    pub max_secret_len: usize,
}

impl Default for EcbAttacker {
    fn default() -> Self {
        Self { max_block_size: 64, max_secret_len: 4096 }
    }
}

impl EcbAttacker {
    #[must_use]
    pub fn new() -> Self { Self::default() }

    /// Detect whether the oracle is using ECB mode.
    /// Sends two identical blocks and checks if output repeats.
    #[must_use]
    pub fn detect_ecb(&self, oracle: &dyn EcbOracle) -> bool {
        // Send 48 identical bytes (3 blocks of 16) to ensure at least two
        // identical consecutive blocks appear regardless of prefix length.
        let input = vec![b'A'; 48];
        let output = oracle.encrypt(&input);

        // Check all pairs of 16-byte windows.
        for block_size in [8, 16, 32] {
            let n_blocks = output.len() / block_size;
            for i in 0..n_blocks {
                for j in (i + 1)..n_blocks {
                    if output[i * block_size..(i + 1) * block_size]
                        == output[j * block_size..(j + 1) * block_size]
                    {
                        return true;
                    }
                }
            }
        }
        false
    }

    /// Determine block size from the oracle by watching when output length jumps.
    ///
    /// # Errors
    /// Returns `EcbOracleError::BlockSizeNotFound` if block size cannot be determined within `max_block_size`.
    pub fn determine_block_size(&self, oracle: &dyn EcbOracle) -> Result<usize, EcbOracleError> {
        let base = oracle.encrypt(b"").len();
        for i in 1..=self.max_block_size {
            let input = vec![b'A'; i];
            let out = oracle.encrypt(&input);
            if out.len() > base {
                return Ok(out.len() - base);
            }
        }
        Err(EcbOracleError::BlockSizeNotFound)
    }

    /// Detect prefix length (bytes prepended by the oracle before our input).
    ///
    /// # Errors
    /// Returns `EcbOracleError::PrefixTooLarge` if no repeated block is found.
    pub fn detect_prefix_len(
        &self,
        oracle: &dyn EcbOracle,
        block_size: usize,
    ) -> Result<usize, EcbOracleError> {
        // Send 0 bytes, then 1 byte, ... until we see the first repeated block.
        // The prefix occupies the first N full blocks + some remainder bytes.
        let base_out = oracle.encrypt(b"");
        let n_base_blocks = base_out.len() / block_size;

        // If the empty-input ciphertext already contains no full blocks the
        // oracle cannot leak any prefix information by repetition; refuse
        // before wasting queries.
        if n_base_blocks == 0 {
            return Err(EcbOracleError::PrefixTooLarge);
        }

        for padding in 0..=(block_size * 2) {
            let input = vec![b'A'; block_size * 2 + padding];
            let out = oracle.encrypt(&input);

            // Find first repeated consecutive block.
            for i in 0..out.len() / block_size - 1 {
                let b1 = &out[i * block_size..(i + 1) * block_size];
                let b2 = &out[(i + 1) * block_size..(i + 2) * block_size];
                if b1 == b2 {
                    // The first repeated block starts at block i.
                    // Prefix ends at: i * block_size - padding (the amount we added).
                    let prefix_len = i * block_size - padding;
                    return Ok(prefix_len);
                }
            }
        }

        Err(EcbOracleError::PrefixTooLarge)
    }

    /// Byte-at-a-time ECB attack to recover the secret suffix.
    ///
    /// Oracle: `ECB(attacker_controlled || secret_suffix)`.
    /// Attack: one byte at a time, build a dictionary of all 256 possible last bytes.
    ///
    /// # Errors
    /// Returns `EcbOracleError::NotEcb` if ECB mode is not detected,
    /// or propagates errors from `determine_block_size`/`detect_prefix_len`.
    pub fn recover_unknown_suffix(
        &self,
        oracle: &dyn EcbOracle,
    ) -> Result<EcbAttackResult, EcbOracleError> {
        if !self.detect_ecb(oracle) {
            return Err(EcbOracleError::NotEcb);
        }

        let block_size = self.determine_block_size(oracle)?;
        let prefix_len = self.detect_prefix_len(oracle, block_size)?;

        // Number of padding bytes needed to align attacker input to a block boundary.
        let prefix_pad = if prefix_len % block_size == 0 { 0 } else { block_size - (prefix_len % block_size) };
        let aligned_prefix = prefix_len + prefix_pad;

        // Total ciphertext length with empty attacker input.
        let empty_out = oracle.encrypt(&vec![b'A'; prefix_pad]);
        let total_len = empty_out.len();
        let secret_len = total_len - aligned_prefix;

        let mut known_secret = Vec::new();
        let mut num_queries = 0;

        for byte_idx in 0..secret_len.min(self.max_secret_len) {
            // Position within current block.
            let block_byte = byte_idx % block_size;
            let block_num = byte_idx / block_size;

            // Short padding: (block_size - 1 - block_byte) 'A' bytes + prefix_pad.
            let short_pad_len = block_size - 1 - block_byte + prefix_pad;
            let short_pad = vec![b'A'; short_pad_len];

            // Get the target ciphertext block.
            let target_out = oracle.encrypt(&short_pad);
            num_queries += 1;
            let target_block_start = (aligned_prefix / block_size + block_num) * block_size;
            if target_block_start + block_size > target_out.len() {
                break;
            }
            let target_block = &target_out[target_block_start..target_block_start + block_size];

            // Build dictionary: for each possible byte b, encrypt (pad || known_secret_last_15 || b).
            let mut found = false;
            for guess in 0u8..=255 {
                let mut dict_input = short_pad.clone();
                // Append (block_size - 1) bytes of known secret + guess.
                let known_tail_start = known_secret.len().saturating_sub(block_size - 1);
                dict_input.extend_from_slice(&known_secret[known_tail_start..]);
                dict_input.push(guess);

                // Encrypt and check the corresponding block.
                let dict_out = oracle.encrypt(&dict_input);
                num_queries += 1;
                let dict_block_start = aligned_prefix;
                if dict_block_start + block_size > dict_out.len() { continue; }
                let dict_block = &dict_out[dict_block_start..dict_block_start + block_size];

                if dict_block == target_block {
                    known_secret.push(guess);
                    found = true;
                    break;
                }
            }

            if !found {
                // Reached end of secret (padding bytes).
                break;
            }
        }

        // Strip PKCS#7 padding from recovered secret.
        let secret = crate::padding_oracle::strip_pkcs7(&known_secret)
            .unwrap_or(known_secret);

        Ok(EcbAttackResult {
            secret,
            block_size,
            prefix_len,
            num_queries,
        })
    }

    /// Cut-and-paste ECB attack: given an oracle that encrypts structured data,
    /// rearrange blocks to forge a ciphertext decrypting to admin=true.
    ///
    /// Returns the forged ciphertext if successful.
    ///
    /// # Errors
    /// Returns `EcbOracleError::AttackFailed` if block content length mismatches or target out of bounds,
    /// or propagates errors from `detect_prefix_len`.
    pub fn cut_and_paste_attack(
        &self,
        oracle: &dyn EcbOracle,
        block_size: usize,
        target_block_content: &[u8],
    ) -> Result<Vec<u8>, EcbOracleError> {
        if target_block_content.len() != block_size {
            return Err(EcbOracleError::AttackFailed(
                format!("Target block content must be {block_size} bytes")
            ));
        }

        // Craft input so that target_block_content falls at a block boundary.
        // If prefix has length P, we need (block_size - P % block_size) bytes of padding
        // then our target content.
        let prefix_len = self.detect_prefix_len(oracle, block_size)?;
        let prefix_pad = if prefix_len % block_size == 0 { 0 } else { block_size - (prefix_len % block_size) };

        let mut input = vec![b'A'; prefix_pad];
        input.extend_from_slice(target_block_content);

        let ct = oracle.encrypt(&input);
        let target_block_start = prefix_len + prefix_pad;
        if target_block_start + block_size > ct.len() {
            return Err(EcbOracleError::AttackFailed("Target block out of bounds".into()));
        }

        Ok(ct[target_block_start..target_block_start + block_size].to_vec())
    }
}

/// Build a dictionary mapping ciphertext block → plaintext byte for ECB single-byte attacks.
#[must_use]
pub fn build_byte_dictionary(
    oracle: &dyn EcbOracle,
    prefix: &[u8],
    block_size: usize,
    block_idx: usize,
) -> HashMap<Vec<u8>, u8> {
    let mut dict = HashMap::new();
    for guess in 0u8..=255 {
        let mut input = prefix.to_vec();
        input.push(guess);
        let ct = oracle.encrypt(&input);
        let start = block_idx * block_size;
        if start + block_size <= ct.len() {
            dict.insert(ct[start..start + block_size].to_vec(), guess);
        }
    }
    dict
}

/// Check if a ciphertext exhibits ECB mode (any two blocks are equal).
#[must_use]
pub fn check_ecb_in_ciphertext(ciphertext: &[u8], block_size: usize) -> bool {
    if block_size == 0 || ciphertext.len() < block_size * 2 { return false; }
    let blocks: Vec<&[u8]> = ciphertext.chunks(block_size).collect();
    for i in 0..blocks.len() {
        for j in (i + 1)..blocks.len() {
            if blocks[i] == blocks[j] { return true; }
        }
    }
    false
}

/// Detect block size from a list of `(input_len, output_len)` pairs.
#[must_use]
pub fn detect_block_size_from_pairs(pairs: &[(usize, usize)]) -> Option<usize> {
    for window in pairs.windows(2) {
        if window[1].1 > window[0].1 {
            return Some(window[1].1 - window[0].1);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::padding_oracle::add_pkcs7;

    /// A simple ECB oracle using XOR "encryption" for testing.
    struct XorEcbOracle {
        key: [u8; 16],
        secret: Vec<u8>,
    }

    impl EcbOracle for XorEcbOracle {
        fn encrypt(&self, input: &[u8]) -> Vec<u8> {
            let mut plaintext = input.to_vec();
            plaintext.extend_from_slice(&self.secret);
            let padded = add_pkcs7(&plaintext, 16);
            // "Encrypt": XOR each block with the key.
            padded.chunks(16).flat_map(|block| {
                block.iter().zip(self.key.iter()).map(|(p, k)| p ^ k).collect::<Vec<_>>()
            }).collect()
        }
    }

    #[test]
    fn detect_ecb_mode() {
        let oracle = XorEcbOracle { key: [0x42; 16], secret: b"secret".to_vec() };
        let attacker = EcbAttacker::default();
        assert!(attacker.detect_ecb(&oracle));
    }

    #[test]
    fn determine_block_size_16() {
        let oracle = XorEcbOracle { key: [0x42; 16], secret: b"secret".to_vec() };
        let attacker = EcbAttacker::default();
        let bs = attacker.determine_block_size(&oracle).unwrap();
        assert_eq!(bs, 16);
    }

    #[test]
    fn check_ecb_in_ciphertext_detects() {
        let mut ct = vec![0u8; 48];
        ct[0..16].copy_from_slice(&[0xaa; 16]);
        ct[16..32].copy_from_slice(&[0xaa; 16]);
        ct[32..48].copy_from_slice(&[0xbb; 16]);
        assert!(check_ecb_in_ciphertext(&ct, 16));
    }

    #[test]
    fn check_ecb_no_repeat() {
        let ct: Vec<u8> = (0u8..48).collect();
        assert!(!check_ecb_in_ciphertext(&ct, 16));
    }

    #[test]
    fn block_size_from_pairs() {
        let pairs = vec![(0, 16), (1, 16), (16, 32), (17, 32)];
        assert_eq!(detect_block_size_from_pairs(&pairs), Some(16));
    }

    #[test]
    fn recover_secret() {
        let secret = b"Hello, secret!".to_vec();
        let oracle = XorEcbOracle { key: [0x13; 16], secret: secret.clone() };
        let attacker = EcbAttacker::default();
        let result = attacker.recover_unknown_suffix(&oracle).unwrap();
        assert_eq!(result.secret, secret);
    }
}
