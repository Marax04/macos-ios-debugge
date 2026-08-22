//! PE checksum calculation and validation.
//!
//! The Windows PE optional header contains a `CheckSum` field used by the
//! loader and driver verifier to detect file corruption.  This module
//! provides [`PeChecksumCalculator`] which recomputes the standard Microsoft
//! checksum algorithm and compares it to the stored value.
//!
//! The algorithm iterates over all 16-bit words in the file (treating the
//! checksum field itself as zero), accumulates a folded 32-bit sum, and adds
//! the file size to produce the final 32-bit checksum.

use std::fmt;
use std::path::Path;

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// ChecksumResult
// ---------------------------------------------------------------------------

/// The result of a PE checksum operation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChecksumResult {
    /// The checksum value stored in the PE optional header.
    pub stored: u32,
    /// The checksum computed from the file bytes.
    pub computed: u32,
    /// File size in bytes (the last addend in the algorithm).
    pub file_size: usize,
    /// Byte offset of the stored checksum field within the file.
    pub checksum_field_offset: usize,
}

impl ChecksumResult {
    /// Returns `true` when the stored and computed checksums match.
    #[must_use]
    pub const fn is_valid(&self) -> bool {
        self.stored == self.computed
    }

    /// Returns `true` when the stored checksum is zero (not set).
    #[must_use]
    pub const fn is_zero(&self) -> bool {
        self.stored == 0
    }

    /// The difference between the stored and computed checksums (signed).
    #[must_use]
    pub fn delta(&self) -> i64 {
        i64::from(self.computed) - i64::from(self.stored)
    }
}

impl fmt::Display for ChecksumResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "stored={:#010x} computed={:#010x} valid={} file_size={}",
            self.stored,
            self.computed,
            self.is_valid(),
            self.file_size
        )
    }
}

// ---------------------------------------------------------------------------
// ChecksumError
// ---------------------------------------------------------------------------

/// Errors from [`PeChecksumCalculator`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChecksumError {
    /// The data is too short to be a valid PE.
    TooShort { got: usize },
    /// The `e_lfanew` pointer is out of range.
    BadElfanew { offset: u32 },
    /// The PE signature (`PE\0\0`) was not found.
    NoPeSignature,
    /// The optional header is missing or malformed.
    NoOptionalHeader,
    /// An I/O error occurred.
    Io(String),
}

impl fmt::Display for ChecksumError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooShort { got } => write!(f, "file too short: {got} bytes"),
            Self::BadElfanew { offset } => write!(f, "e_lfanew={offset:#x} is out of range"),
            Self::NoPeSignature => write!(f, "PE signature not found"),
            Self::NoOptionalHeader => write!(f, "optional header absent or malformed"),
            Self::Io(e) => write!(f, "I/O error: {e}"),
        }
    }
}

impl std::error::Error for ChecksumError {}

// ---------------------------------------------------------------------------
// PeChecksumCalculator
// ---------------------------------------------------------------------------

/// Calculates and verifies the standard Microsoft PE checksum.
///
/// # Algorithm
///
/// The checksum is computed by treating the file as an array of 16-bit
/// little-endian words (padding a trailing odd byte with zero).  A running
/// sum is maintained, folding carry bits after every addition:
///
/// ```text
/// sum = 0
/// for each word w at position i:
///     if i == checksum_word_offset || i == checksum_word_offset + 1:
///         skip (treat as zero)
///     sum += w
///     sum = (sum & 0xFFFF) + (sum >> 16)
/// sum = (sum & 0xFFFF) + (sum >> 16)
/// checksum = (sum & 0xFFFF) + file_size
/// ```
pub struct PeChecksumCalculator {
    /// When `true`, the stored checksum field is zeroed during computation
    /// (as per the Microsoft spec).  Default: `true`.
    pub zero_stored_field: bool,
}

impl Default for PeChecksumCalculator {
    fn default() -> Self {
        Self::new()
    }
}

impl PeChecksumCalculator {
    /// Create a new calculator with default settings.
    #[must_use]
    pub const fn new() -> Self {
        Self { zero_stored_field: true }
    }

    /// Compute the PE checksum from raw file bytes and return the full result.
    ///
    /// # Errors
    /// Returns [`ChecksumError`] if the data is not a valid PE.
    pub fn calculate(&self, data: &[u8]) -> Result<ChecksumResult, ChecksumError> {
        if data.len() < 64 {
            return Err(ChecksumError::TooShort { got: data.len() });
        }

        // DOS header: e_lfanew at offset 0x3C
        let e_lfanew = u32::from_le_bytes([data[0x3C], data[0x3D], data[0x3E], data[0x3F]]);
        let nt_offset = e_lfanew as usize;

        if nt_offset + 24 > data.len() {
            return Err(ChecksumError::BadElfanew { offset: e_lfanew });
        }

        // Verify PE signature
        if &data[nt_offset..nt_offset + 4] != b"PE\0\0" {
            return Err(ChecksumError::NoPeSignature);
        }

        // The optional header starts at nt_offset + 4 (FileHeader, 20 bytes) + 20 = nt_offset + 24
        // PE32 magic = 0x010B, PE32+ magic = 0x020B
        let opt_offset = nt_offset + 24;
        if opt_offset + 4 > data.len() {
            return Err(ChecksumError::NoOptionalHeader);
        }

        let magic = u16::from_le_bytes([data[opt_offset], data[opt_offset + 1]]);
        if magic != 0x010B && magic != 0x020B {
            return Err(ChecksumError::NoOptionalHeader);
        }

        // CheckSum field is at OptionalHeader + 64 (PE32) or + 64 (PE32+ same offset)
        let checksum_field_offset = opt_offset + 64;
        if checksum_field_offset + 4 > data.len() {
            return Err(ChecksumError::NoOptionalHeader);
        }

        let stored = u32::from_le_bytes([
            data[checksum_field_offset],
            data[checksum_field_offset + 1],
            data[checksum_field_offset + 2],
            data[checksum_field_offset + 3],
        ]);

        let computed = self.compute_checksum(data, checksum_field_offset);

        Ok(ChecksumResult {
            stored,
            computed,
            file_size: data.len(),
            checksum_field_offset,
        })
    }

    /// Verify whether the PE data has a valid checksum.
    ///
    /// # Errors
    /// Returns [`ChecksumError`] on parse failure.
    pub fn verify(&self, data: &[u8]) -> Result<bool, ChecksumError> {
        self.calculate(data).map(|r| r.is_valid())
    }

    /// Compute and embed the correct checksum into `data` in place.
    ///
    /// The checksum field will be updated with the newly computed value.
    ///
    /// # Errors
    /// Returns [`ChecksumError`] on parse failure.
    pub fn patch_checksum(&self, data: &mut [u8]) -> Result<u32, ChecksumError> {
        let result = self.calculate(data)?;
        let off = result.checksum_field_offset;
        let new_cs = result.computed;
        data[off]     = (new_cs & 0xFF) as u8;
        data[off + 1] = ((new_cs >>  8) & 0xFF) as u8;
        data[off + 2] = ((new_cs >> 16) & 0xFF) as u8;
        data[off + 3] = ((new_cs >> 24) & 0xFF) as u8;
        Ok(new_cs)
    }

    /// Zero out the checksum field in `data` in place.
    ///
    /// # Errors
    /// Returns [`ChecksumError`] on parse failure.
    pub fn zero_checksum(&self, data: &mut [u8]) -> Result<(), ChecksumError> {
        let result = self.calculate(data)?;
        let off = result.checksum_field_offset;
        data[off]     = 0;
        data[off + 1] = 0;
        data[off + 2] = 0;
        data[off + 3] = 0;
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Private
    // -----------------------------------------------------------------------

    fn compute_checksum(&self, data: &[u8], checksum_field_offset: usize) -> u32 {
        let mut sum: u64 = 0;
        let len = data.len();
        // Iterate over 16-bit words
        let word_count = len.div_ceil(2);
        for i in 0..word_count {
            let byte_off = i * 2;
            // Skip the 4-byte checksum field (2 words)
            if self.zero_stored_field
                && (byte_off < checksum_field_offset + 4 && byte_off + 2 > checksum_field_offset)
            {
                continue;
            }
            let lo = u64::from(data[byte_off]);
            let hi = if byte_off + 1 < len { u64::from(data[byte_off + 1]) } else { 0 };
            let word = lo | (hi << 8);
            sum += word;
            // Fold carry
            if sum > 0xFFFF {
                sum = (sum & 0xFFFF) + (sum >> 16);
            }
        }
        // Final fold
        sum = (sum & 0xFFFF) + (sum >> 16);
        let lo16 = (sum & 0xFFFF) as u32;
        // len as u32 would silently truncate for files > 4 GiB; use try_from.
        let len32 = u32::try_from(len).unwrap_or(u32::MAX);
        lo16.wrapping_add(len32)
    }
}

// ---------------------------------------------------------------------------
// calculate_checksum — convenience free function
// ---------------------------------------------------------------------------

/// Compute and verify the PE checksum of `data`.
///
/// Returns the [`ChecksumResult`] on success.
///
/// # Errors
/// Returns [`ChecksumError`] if `data` is not a valid PE.
pub fn calculate_checksum(data: &[u8]) -> Result<ChecksumResult, ChecksumError> {
    PeChecksumCalculator::new().calculate(data)
}

/// Read a file from `path`, compute its PE checksum, and return the result.
///
/// # Errors
/// Returns [`ChecksumError`] if the path cannot be read or the data is not a
/// valid PE.
pub fn calculate_checksum_file(path: &Path) -> Result<ChecksumResult, ChecksumError> {
    let data = std::fs::read(path).map_err(|e| ChecksumError::Io(e.to_string()))?;
    calculate_checksum(&data)
}

// ---------------------------------------------------------------------------
// ChecksumStats — aggregate statistics for a batch
// ---------------------------------------------------------------------------

/// Aggregate checksum statistics across a batch of PE files.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct ChecksumStats {
    /// Total files examined.
    pub total: usize,
    /// Files with a valid (matching) checksum.
    pub valid: usize,
    /// Files with a stored checksum of zero.
    pub zeroed: usize,
    /// Files with a mismatched checksum.
    pub mismatch: usize,
    /// Files that could not be parsed.
    pub errors: usize,
}

impl ChecksumStats {
    /// Update stats from a single [`ChecksumResult`].
    pub const fn record(&mut self, result: &ChecksumResult) {
        self.total += 1;
        if result.stored == 0 {
            // A stored-zero checksum is classified as "zeroed" when its computed
            // value also vanishes (the header field was never populated); when
            // the computed value is nonzero, this is a true mismatch.
            if result.computed == 0 {
                self.zeroed += 1;
            } else {
                self.mismatch += 1;
            }
        } else if result.is_valid() {
            self.valid += 1;
        } else {
            self.mismatch += 1;
        }
    }

    /// Record a parse error.
    pub const fn record_error(&mut self) {
        self.total += 1;
        self.errors += 1;
    }

    /// Fraction of parseable files with valid checksums, 0.0–1.0.
    #[must_use]
    pub fn valid_rate(&self) -> f64 {
        let parseable = self.total.saturating_sub(self.errors);
        if parseable == 0 {
            return 0.0;
        }
        f64::from(u32::try_from(self.valid).unwrap_or(u32::MAX)) / f64::from(u32::try_from(parseable).unwrap_or(u32::MAX))
    }
}

impl fmt::Display for ChecksumStats {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "total={} valid={} zeroed={} mismatch={} errors={} valid_rate={:.1}%",
            self.total,
            self.valid,
            self.zeroed,
            self.mismatch,
            self.errors,
            self.valid_rate() * 100.0
        )
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal, structurally valid PE64 stub (~200 bytes) with a given checksum.
    fn make_pe64_stub(checksum: u32) -> Vec<u8> {
        let mut data = vec![0u8; 256];
        // MZ magic
        data[0] = b'M'; data[1] = b'Z';
        // e_lfanew = 0x40
        data[0x3C] = 0x40;
        // PE signature at 0x40
        data[0x40] = b'P'; data[0x41] = b'E'; data[0x42] = 0; data[0x43] = 0;
        // Machine (IMAGE_FILE_MACHINE_AMD64 = 0x8664)
        data[0x44] = 0x64; data[0x45] = 0x86;
        // SizeOfOptionalHeader = 0xF0 (PE32+)
        data[0x54] = 0xF0; data[0x55] = 0x00;
        // Optional header starts at 0x40 + 4 + 20 = 0x58
        // Magic = 0x020B (PE32+)
        data[0x58] = 0x0B; data[0x59] = 0x02;
        // CheckSum field at opt_offset + 64 = 0x58 + 64 = 0x98
        let cs_bytes = checksum.to_le_bytes();
        data[0x98] = cs_bytes[0];
        data[0x99] = cs_bytes[1];
        data[0x9A] = cs_bytes[2];
        data[0x9B] = cs_bytes[3];
        data
    }

    #[test]
    fn test_checksum_result_is_valid() {
        let r = ChecksumResult {
            stored: 0x1234,
            computed: 0x1234,
            file_size: 256,
            checksum_field_offset: 0x98,
        };
        assert!(r.is_valid());
        assert!(!r.is_zero());
        assert_eq!(r.delta(), 0);
    }

    #[test]
    fn test_checksum_result_is_zero() {
        let r = ChecksumResult {
            stored: 0,
            computed: 0x1234,
            file_size: 256,
            checksum_field_offset: 0x98,
        };
        assert!(!r.is_valid());
        assert!(r.is_zero());
    }

    #[test]
    fn test_checksum_result_display() {
        let r = ChecksumResult {
            stored: 0,
            computed: 0,
            file_size: 64,
            checksum_field_offset: 0,
        };
        let s = r.to_string();
        assert!(s.contains("stored=0x00000000"));
    }

    #[test]
    fn test_calculate_too_short() {
        let err = calculate_checksum(&[0u8; 10]);
        assert!(matches!(err, Err(ChecksumError::TooShort { got: 10 })));
    }

    #[test]
    fn test_calculate_no_pe_signature() {
        let mut data = vec![0u8; 256];
        data[0x3C] = 0x40;
        // No PE signature at 0x40
        let err = calculate_checksum(&data);
        assert!(matches!(err, Err(ChecksumError::NoPeSignature)));
    }

    #[test]
    fn test_calculate_pe64_stub_parses() {
        let data = make_pe64_stub(0x0000_1234);
        let result = calculate_checksum(&data);
        assert!(result.is_ok(), "{:?}", result.err());
    }

    #[test]
    fn test_checksum_field_offset() {
        let data = make_pe64_stub(0xDEAD_BEEF);
        let result = calculate_checksum(&data).unwrap();
        assert_eq!(result.checksum_field_offset, 0x98);
        assert_eq!(result.stored, 0xDEAD_BEEF);
    }

    #[test]
    fn test_compute_round_trip() {
        let mut data = make_pe64_stub(0);
        let calc = PeChecksumCalculator::new();
        let new_cs = calc.patch_checksum(&mut data).unwrap();
        assert_ne!(new_cs, 0);
        let result = calc.calculate(&data).unwrap();
        assert!(result.is_valid(), "round-trip checksum mismatch: {result}");
    }

    #[test]
    fn test_zero_checksum() {
        let mut data = make_pe64_stub(0x1234_5678);
        let calc = PeChecksumCalculator::new();
        calc.zero_checksum(&mut data).unwrap();
        let result = calc.calculate(&data).unwrap();
        assert!(result.is_zero());
    }

    #[test]
    fn test_stats_valid_rate_no_files() {
        let stats = ChecksumStats::default();
        assert_eq!(stats.valid_rate(), 0.0);
    }

    #[test]
    fn test_stats_record() {
        let mut stats = ChecksumStats::default();
        let valid = ChecksumResult { stored: 42, computed: 42, file_size: 256, checksum_field_offset: 0x98 };
        let invalid = ChecksumResult { stored: 0, computed: 99, file_size: 256, checksum_field_offset: 0x98 };
        stats.record(&valid);
        stats.record(&invalid);
        stats.record_error();
        assert_eq!(stats.total, 3);
        assert_eq!(stats.valid, 1);
        assert_eq!(stats.mismatch, 1);
        assert_eq!(stats.errors, 1);
    }

    #[test]
    fn test_stats_display() {
        let stats = ChecksumStats { total: 10, valid: 8, zeroed: 1, mismatch: 1, errors: 0 };
        let s = stats.to_string();
        assert!(s.contains("total=10"));
        assert!(s.contains("valid=8"));
    }
}
