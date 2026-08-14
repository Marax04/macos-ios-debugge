//! Function hasher for FLIRT signature creation.
//!
//! Normalizes x86/x86-64 function bytes by wildcarding address operands
//! (E8/E9 rel32, FF/2 absolute, conditional JCC rel32), then builds a
//! 32-byte prefix + CRC-16 pair suitable for FLIRT `.pat` files.

use crate::flirt_signature_writer::compute_crc16;

// ── HashConfig ────────────────────────────────────────────────────────────────

/// Configuration for function hashing.
#[derive(Debug, Clone)]
pub struct HashConfig {
    /// Minimum bytes required for a valid prefix.
    pub min_bytes: u8,
    /// Maximum prefix bytes to use (capped at 32 for FLIRT compatibility).
    pub max_bytes: u8,
    /// If true, wildcard the operands of calls/jumps that reference other functions.
    pub wildcard_refs: bool,
}

impl Default for HashConfig {
    fn default() -> Self {
        Self {
            min_bytes: 4,
            max_bytes: 32,
            wildcard_refs: true,
        }
    }
}

// ── FunctionHash ─────────────────────────────────────────────────────────────

/// A FLIRT-compatible function hash.
#[derive(Debug, Clone)]
pub struct FunctionHash {
    /// Up to 32 bytes of normalized prefix (`None` = wildcard).
    pub prefix: Vec<Option<u8>>,
    /// Byte offset within the function where the CRC region starts.
    pub crc_start: u8,
    /// Length of the CRC region in bytes.
    pub crc_len: u8,
    /// CRC-16 of the CRC region.
    pub crc16: u16,
    /// Total function length in bytes.
    pub function_len: u16,
}

impl FunctionHash {
    /// Number of concrete (non-wildcard) bytes in the prefix.
    #[must_use] 
    pub fn prefix_entropy(&self) -> usize {
        self.prefix.iter().filter(|b| b.is_some()).count()
    }

    /// Format the prefix as a hex string with `..` for wildcards.
    #[must_use] 
    pub fn prefix_hex(&self) -> String {
        self.prefix.iter().map(|b| b.map_or_else(|| "..".to_string(), |v| format!("{v:02X}"))).collect::<String>()
    }
}

// ── HashResult ────────────────────────────────────────────────────────────────

/// The result of hashing a single function.
#[derive(Debug, Clone)]
pub struct HashResult {
    pub hash: FunctionHash,
    pub function_name: String,
}

// ── FunctionHasher ────────────────────────────────────────────────────────────

/// Builds FLIRT-compatible hashes from raw function byte arrays.
pub struct FunctionHasher {
    pub config: HashConfig,
}

impl FunctionHasher {
    #[must_use] 
    pub fn new() -> Self {
        Self { config: HashConfig::default() }
    }

    #[must_use] 
    pub const fn with_config(config: HashConfig) -> Self {
        Self { config }
    }

    /// Hash a function and return a `HashResult`.
    pub fn hash_function(&self, bytes: &[u8], name: impl Into<String>) -> Option<HashResult> {
        if bytes.len() < self.config.min_bytes as usize {
            return None;
        }
        let normalized = self.normalize_function_bytes(bytes);
        let prefix = self.extract_prefix(&normalized);
        let prefix_len = u8::try_from(prefix.len()).unwrap_or(u8::MAX);
        let crc_start = prefix_len;
        let crc_end = (usize::from(crc_start) + 255).min(bytes.len());
        let crc_len = u8::try_from(crc_end - usize::from(crc_start)).unwrap_or(u8::MAX);
        let crc16 = if (crc_start as usize) < bytes.len() {
            self.compute_prefix_crc(bytes, crc_start, crc_len)
        } else {
            0
        };
        // Saturate at u16::MAX rather than silently truncating the function length.
        let function_len = u16::try_from(bytes.len().min(usize::from(u16::MAX))).unwrap_or(u16::MAX);
        Some(HashResult {
            hash: FunctionHash {
                prefix,
                crc_start,
                crc_len,
                crc16,
                function_len,
            },
            function_name: name.into(),
        })
    }

    /// Normalize function bytes by wildcarding address-dependent bytes.
    ///
    /// Rules applied (x86/x86-64):
    /// - `E8 xx xx xx xx` (CALL rel32): wildcard the 4 operand bytes.
    /// - `E9 xx xx xx xx` (JMP rel32): wildcard the 4 operand bytes.
    /// - `EB xx` (JMP short): wildcard the 1 operand byte.
    /// - `0F 8x xx xx xx xx` (Jcc rel32): wildcard the 4 operand bytes.
    /// - `FF /2` (CALL r/m): wildcard the `ModRM` and SIB if absolute.
    /// - `FF /4` (JMP r/m): same.
    #[must_use] 
    pub fn normalize_function_bytes(&self, bytes: &[u8]) -> Vec<Option<u8>> {
        let mut result = vec![None; bytes.len()];
        let mut i = 0;
        while i < bytes.len() {
            let b = bytes[i];
            // Mark the opcode itself as concrete.
            result[i] = Some(b);

            match b {
                0xE8 | 0xE9 => {
                    // CALL/JMP rel32 — wildcard 4 bytes
                    for k in 1..=4 {
                        if i + k < bytes.len() {
                            result[i + k] = None;
                        }
                    }
                    i += 5;
                }
                0xEB => {
                    // JMP short — wildcard 1 byte
                    if i + 1 < bytes.len() {
                        result[i + 1] = None;
                    }
                    i += 2;
                }
                0x0F if i + 1 < bytes.len() => {
                    let sub = bytes[i + 1];
                    if (0x80..=0x8F).contains(&sub) {
                        // Jcc rel32 — opcode = 2 bytes, wildcard 4 operand bytes
                        result[i + 1] = Some(sub);
                        for k in 2..=5 {
                            if i + k < bytes.len() {
                                result[i + k] = None;
                            }
                        }
                        i += 6;
                        continue;
                    }
                    result[i + 1] = Some(sub);
                    i += 2;
                }
                0xFF if i + 1 < bytes.len() => {
                    let modrm = bytes[i + 1];
                    let reg = (modrm >> 3) & 7;
                    if reg == 2 || reg == 4 {
                        // CALL/JMP r/m — wildcard ModRM + next bytes depending on mode
                        result[i + 1] = None;
                        let rm = modrm & 7;
                        let mode = modrm >> 6;
                        match mode {
                            0b00 => {
                                if rm == 5 {
                                    // [disp32]
                                    for k in 2..=5 { if i+k < bytes.len() { result[i+k] = None; } }
                                    i += 6; continue;
                                }
                            }
                            0b10 => {
                                for k in 2..=5 { if i+k < bytes.len() { result[i+k] = None; } }
                                i += 6; continue;
                            }
                            0b01 => {
                                if i + 2 < bytes.len() { result[i+2] = None; }
                                i += 3; continue;
                            }
                            _ => {}
                        }
                    }
                    result[i + 1] = Some(modrm);
                    i += 2;
                }
                _ => {
                    // For all other opcodes, mark byte as concrete and advance.
                    let insn_len = self.x86_insn_wildcard(bytes, i);
                    for k in 1..insn_len {
                        if i + k < bytes.len() {
                            result[i + k] = Some(bytes[i + k]);
                        }
                    }
                    i += insn_len;
                }
            }
        }
        result
    }

    /// Identify which bytes of an x86 instruction at `offset` are address bytes.
    ///
    /// Returns the total instruction length (conservative estimate).
    #[must_use] 
    pub fn x86_insn_wildcard(&self, bytes: &[u8], offset: usize) -> usize {
        if offset >= bytes.len() { return 1; }
        let b = bytes[offset];
        // Handle common prefixes and short instructions.
        match b {
            // Two-byte (mod r/m patterns)
            0x88..=0x8E | 0x00..=0x03 | 0x08..=0x0B | 0x28..=0x2B | 0x38..=0x3B
                if offset + 1 < bytes.len() => { 2 }
            // One-byte instructions (no operands) or generic 1-byte fallback
            _ => 1,
        }
    }

    /// Extract the prefix (up to `config.max_bytes`) from a normalized byte slice.
    #[must_use] 
    pub fn extract_prefix(&self, normalized: &[Option<u8>]) -> Vec<Option<u8>> {
        let len = (normalized.len()).min(self.config.max_bytes as usize);
        normalized[..len].to_vec()
    }

    /// Compute CRC-16 over `len` bytes starting at `start` in `bytes`.
    #[must_use] 
    pub fn compute_prefix_crc(&self, bytes: &[u8], start: u8, len: u8) -> u16 {
        let s = start as usize;
        let e = (s + len as usize).min(bytes.len());
        if s >= bytes.len() { return 0; }
        compute_crc16(&bytes[s..e])
    }

    /// Hash multiple functions from a list of `(name, bytes)` pairs.
    pub fn hash_all<'a>(
        &self,
        functions: impl Iterator<Item = (&'a str, &'a [u8])>,
    ) -> Vec<HashResult> {
        functions
            .filter_map(|(name, bytes)| self.hash_function(bytes, name))
            .collect()
    }
}

impl Default for FunctionHasher {
    fn default() -> Self { Self::new() }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn hasher() -> FunctionHasher { FunctionHasher::new() }

    #[test]
    fn hash_function_basic() {
        let bytes = [0x55, 0x8B, 0xEC, 0x83, 0xEC, 0x10, 0xC3]; // push ebp; mov esp,ebp; ...
        let result = hasher().hash_function(&bytes, "test_func");
        assert!(result.is_some());
        let r = result.unwrap();
        assert_eq!(r.function_name, "test_func");
        assert!(!r.hash.prefix.is_empty());
    }

    #[test]
    fn hash_function_too_short() {
        let bytes = [0x55, 0xC3]; // < min_bytes(4)
        let result = hasher().hash_function(&bytes, "tiny");
        assert!(result.is_none());
    }

    #[test]
    fn normalize_call_rel32_wildcards_operand() {
        let bytes = [0xE8, 0x01, 0x02, 0x03, 0x04, 0xC3];
        let norm = hasher().normalize_function_bytes(&bytes);
        assert_eq!(norm[0], Some(0xE8));
        assert_eq!(norm[1], None);
        assert_eq!(norm[2], None);
        assert_eq!(norm[3], None);
        assert_eq!(norm[4], None);
    }

    #[test]
    fn normalize_jmp_rel32_wildcards_operand() {
        let bytes = [0xE9, 0xAA, 0xBB, 0xCC, 0xDD, 0xC3];
        let norm = hasher().normalize_function_bytes(&bytes);
        assert_eq!(norm[0], Some(0xE9));
        for i in 1..5 { assert_eq!(norm[i], None); }
    }

    #[test]
    fn normalize_jmp_short_wildcards_1_byte() {
        let bytes = [0xEB, 0x05, 0x90, 0x90, 0x90, 0x90, 0x90, 0xC3];
        let norm = hasher().normalize_function_bytes(&bytes);
        assert_eq!(norm[0], Some(0xEB));
        assert_eq!(norm[1], None);
    }

    #[test]
    fn normalize_jcc_rel32_wildcards_operand() {
        let bytes = [0x0F, 0x84, 0x01, 0x00, 0x00, 0x00, 0xC3];
        let norm = hasher().normalize_function_bytes(&bytes);
        assert_eq!(norm[0], Some(0x0F));
        assert_eq!(norm[1], Some(0x84));
        for i in 2..6 { assert_eq!(norm[i], None); }
    }

    #[test]
    fn normalize_nop_is_concrete() {
        let bytes = [0x90, 0x90, 0xC3];
        let norm = hasher().normalize_function_bytes(&bytes);
        assert_eq!(norm[0], Some(0x90));
        assert_eq!(norm[1], Some(0x90));
    }

    #[test]
    fn extract_prefix_max_32() {
        let norm: Vec<Option<u8>> = (0..64u8).map(|b| Some(b)).collect();
        let prefix = hasher().extract_prefix(&norm);
        assert_eq!(prefix.len(), 32);
    }

    #[test]
    fn extract_prefix_shorter_than_max() {
        let norm = vec![Some(0x55), Some(0x8B), Some(0xEC)];
        let prefix = hasher().extract_prefix(&norm);
        assert_eq!(prefix.len(), 3);
    }

    #[test]
    fn compute_prefix_crc_deterministic() {
        let bytes: Vec<u8> = (0..32).collect();
        let crc1 = hasher().compute_prefix_crc(&bytes, 0, 16);
        let crc2 = hasher().compute_prefix_crc(&bytes, 0, 16);
        assert_eq!(crc1, crc2);
    }

    #[test]
    fn compute_prefix_crc_different_ranges() {
        let bytes: Vec<u8> = (0..64).collect();
        let crc1 = hasher().compute_prefix_crc(&bytes, 0, 16);
        let crc2 = hasher().compute_prefix_crc(&bytes, 16, 16);
        assert_ne!(crc1, crc2);
    }

    #[test]
    fn hash_result_prefix_entropy() {
        let bytes = [0x55, 0x8B, 0xEC, 0xC3, 0x90];
        let result = hasher().hash_function(&bytes, "f").unwrap();
        assert!(result.hash.prefix_entropy() > 0);
    }

    #[test]
    fn hash_all_multiple() {
        let h = hasher();
        let funcs = [
            ("func_a", [0x55u8, 0x8B, 0xEC, 0xC3].as_slice()),
            ("func_b", [0x53u8, 0x8B, 0xD8, 0xC3].as_slice()),
        ];
        let results = h.hash_all(funcs.iter().map(|(n, b)| (*n, *b)));
        assert_eq!(results.len(), 2);
    }

    #[test]
    fn prefix_hex_format() {
        let bytes = [0x55, 0x8B, 0xEC, 0xC3];
        let result = hasher().hash_function(&bytes, "f").unwrap();
        let hex = result.hash.prefix_hex();
        assert!(!hex.is_empty());
        // Should contain the hex digits for 0x55.
        assert!(hex.to_uppercase().contains("55"));
    }

    #[test]
    fn function_len_recorded() {
        let bytes = [0x55, 0x8B, 0xEC, 0x5D, 0xC3]; // 5 bytes
        let result = hasher().hash_function(&bytes, "f").unwrap();
        assert_eq!(result.hash.function_len, 5);
    }

    #[test]
    fn hash_config_custom_min_bytes() {
        let cfg = HashConfig { min_bytes: 10, max_bytes: 32, wildcard_refs: true };
        let h = FunctionHasher::with_config(cfg);
        let bytes = [0x55, 0x8B, 0xEC]; // only 3 bytes
        assert!(h.hash_function(&bytes, "short").is_none());
    }
}
