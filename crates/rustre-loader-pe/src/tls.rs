//! PE TLS (Thread Local Storage) directory parser — low-level layer.
//!
//! TLS callbacks are frequently used by malware for pre-main anti-debug tricks.
//! This module parses `IMAGE_TLS_DIRECTORY32` and `IMAGE_TLS_DIRECTORY64` and
//! extracts the TLS callback array.
//!
//! # Relationship to `pe_tls_callbacks`
//!
//! This module provides the **simple** parsing tier used by [`crate::PeInfo`]:
//! it returns [`TlsInfo`] (a flat list of callback VAs + data-range fields) and
//! [`TlsAnalysis`] (import-name-based anti-debug heuristics).
//!
//! [`crate::pe_tls_callbacks`] provides a **richer** tier on top: byte-level
//! callback classification (`CallbackClass`), execution-order analysis,
//! pattern-based shellcode detection, and formatted reporting
//! (`TlsCallbackAnalyzer`, `PeTlsCallbacks`, `TlsCallbackReport`, etc.).
//! The two modules are intentionally kept separate so callers that only need
//! VA lists are not forced to pull in the heavier analysis machinery.

use crate::imports::{RvaSection, rva_to_file_offset};

// ---------------------------------------------------------------------------
// Data types
// ---------------------------------------------------------------------------

/// Parsed 32-bit `IMAGE_TLS_DIRECTORY`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlsDirectory32 {
    /// Start VA of the TLS raw data template.
    pub start_address_of_raw_data: u32,
    /// End VA of the TLS raw data template.
    pub end_address_of_raw_data: u32,
    /// VA of the TLS index DWORD (updated by loader).
    pub address_of_index: u32,
    /// VA of the array of `PIMAGE_TLS_CALLBACK` pointers (NULL-terminated).
    pub address_of_callbacks: u32,
    /// Size of zero fill.
    pub size_of_zero_fill: u32,
    /// Characteristics / alignment.
    pub characteristics: u32,
}

impl TlsDirectory32 {
    /// Parse a 24-byte `IMAGE_TLS_DIRECTORY32` from `data` at `offset`.
    ///
    /// # Errors
    ///
    /// Returns `Err` if `offset + 24 > data.len()`.
    pub fn parse(data: &[u8], offset: usize) -> Result<Self, String> {
        if offset + 24 > data.len() {
            return Err(format!("TLS directory 32 truncated at offset {offset}"));
        }
        let r32 = |off: usize| -> u32 {
            u32::from_le_bytes(data[off..off + 4].try_into().unwrap_or([0; 4]))
        };
        let b = offset;
        Ok(Self {
            start_address_of_raw_data: r32(b),
            end_address_of_raw_data: r32(b + 4),
            address_of_index: r32(b + 8),
            address_of_callbacks: r32(b + 12),
            size_of_zero_fill: r32(b + 16),
            characteristics: r32(b + 20),
        })
    }

    /// Return the alignment in bytes (bits [20..24] of characteristics, same as sections).
    #[must_use]
    pub const fn alignment(&self) -> u32 {
        let field = (self.characteristics >> 20) & 0xF;
        if field == 0 { 0 } else { 1u32 << (field - 1) }
    }
}

/// Parsed 64-bit `IMAGE_TLS_DIRECTORY`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlsDirectory64 {
    /// Start VA of the TLS raw data template.
    pub start_address_of_raw_data: u64,
    /// End VA of the TLS raw data template.
    pub end_address_of_raw_data: u64,
    /// VA of the TLS index DWORD.
    pub address_of_index: u64,
    /// VA of the callback array (NULL-terminated pointers to `PIMAGE_TLS_CALLBACK`).
    pub address_of_callbacks: u64,
    /// Size of zero fill.
    pub size_of_zero_fill: u32,
    /// Characteristics / alignment.
    pub characteristics: u32,
}

impl TlsDirectory64 {
    /// Parse a 40-byte `IMAGE_TLS_DIRECTORY64` from `data` at `offset`.
    ///
    /// # Errors
    ///
    /// Returns `Err` if `offset + 40 > data.len()`.
    pub fn parse(data: &[u8], offset: usize) -> Result<Self, String> {
        if offset + 40 > data.len() {
            return Err(format!("TLS directory 64 truncated at offset {offset}"));
        }
        let r32 = |off: usize| -> u32 {
            u32::from_le_bytes(data[off..off + 4].try_into().unwrap_or([0; 4]))
        };
        let r64 = |off: usize| -> u64 {
            u64::from_le_bytes(data[off..off + 8].try_into().unwrap_or([0; 8]))
        };
        let b = offset;
        Ok(Self {
            start_address_of_raw_data: r64(b),
            end_address_of_raw_data: r64(b + 8),
            address_of_index: r64(b + 16),
            address_of_callbacks: r64(b + 24),
            size_of_zero_fill: r32(b + 32),
            characteristics: r32(b + 36),
        })
    }

    /// Return the alignment in bytes.
    #[must_use]
    pub const fn alignment(&self) -> u32 {
        let field = (self.characteristics >> 20) & 0xF;
        if field == 0 { 0 } else { 1u32 << (field - 1) }
    }
}

// ---------------------------------------------------------------------------
// TLS information
// ---------------------------------------------------------------------------

/// TLS information extracted from a PE binary.
#[derive(Debug, Clone)]
pub struct TlsInfo {
    /// TLS data region start VA.
    pub data_start: u64,
    /// TLS data region end VA.
    pub data_end: u64,
    /// Size of the zero-fill region appended after raw data.
    pub zero_fill_size: u32,
    /// Extracted TLS callbacks (absolute VAs).
    pub callbacks: Vec<u64>,
    /// Is this a 64-bit TLS directory?
    pub is_64bit: bool,
}

impl TlsInfo {
    /// Total TLS data size including zero fill.
    #[must_use]
    pub const fn total_size(&self) -> u64 {
        self.data_end
            .saturating_sub(self.data_start)
            .saturating_add(self.zero_fill_size as u64)
    }

    /// Return `true` if any TLS callbacks are registered.
    #[must_use]
    pub const fn has_callbacks(&self) -> bool {
        !self.callbacks.is_empty()
    }
}

// ---------------------------------------------------------------------------
// Parse TLS callbacks from a 32-bit PE
// ---------------------------------------------------------------------------

/// Extract TLS callbacks from a 32-bit PE.
///
/// `tls_dir_rva` is the RVA of the TLS directory (from data directory entry 9).
/// Returns both the parsed `TlsDirectory32` and the list of callback VAs.
#[must_use]
pub fn parse_tls_32(
    data: &[u8],
    sections: &[RvaSection],
    tls_dir_rva: u32,
    image_base: u64,
) -> Option<TlsInfo> {
    let dir_off = rva_to_file_offset(tls_dir_rva, sections)?;
    let dir = TlsDirectory32::parse(data, dir_off).ok()?;

    let mut callbacks = Vec::new();

    if dir.address_of_callbacks != 0 {
        // address_of_callbacks is an absolute VA; convert to RVA then to file offset
        let callbacks_va = u64::from(dir.address_of_callbacks);
        if callbacks_va >= image_base {
            let cb_rva = u32::try_from(callbacks_va - image_base).unwrap_or(u32::MAX);
            if let Some(mut cb_off) = rva_to_file_offset(cb_rva, sections) {
                loop {
                    if cb_off + 4 > data.len() {
                        break;
                    }
                    let entry_va =
                        u32::from_le_bytes(data[cb_off..cb_off + 4].try_into().unwrap_or([0; 4]));
                    if entry_va == 0 {
                        break;
                    }
                    callbacks.push(u64::from(entry_va));
                    cb_off += 4;
                }
            }
        }
    }

    Some(TlsInfo {
        data_start: u64::from(dir.start_address_of_raw_data),
        data_end: u64::from(dir.end_address_of_raw_data),
        zero_fill_size: dir.size_of_zero_fill,
        callbacks,
        is_64bit: false,
    })
}

/// Extract TLS callbacks from a 64-bit PE.
#[must_use]
pub fn parse_tls_64(
    data: &[u8],
    sections: &[RvaSection],
    tls_dir_rva: u32,
    image_base: u64,
) -> Option<TlsInfo> {
    let dir_off = rva_to_file_offset(tls_dir_rva, sections)?;
    let dir = TlsDirectory64::parse(data, dir_off).ok()?;

    let mut callbacks = Vec::new();

    if dir.address_of_callbacks != 0 {
        let tls_callbacks_va = dir.address_of_callbacks;
        if tls_callbacks_va >= image_base {
            let callbacks_rva = u32::try_from(tls_callbacks_va - image_base).unwrap_or(u32::MAX);
            if let Some(mut cb_off) = rva_to_file_offset(callbacks_rva, sections) {
                loop {
                    if cb_off + 8 > data.len() {
                        break;
                    }
                    let cb_entry =
                        u64::from_le_bytes(data[cb_off..cb_off + 8].try_into().unwrap_or([0; 8]));
                    if cb_entry == 0 {
                        break;
                    }
                    callbacks.push(cb_entry);
                    cb_off += 8;
                }
            }
        }
    }

    Some(TlsInfo {
        data_start: dir.start_address_of_raw_data,
        data_end: dir.end_address_of_raw_data,
        zero_fill_size: dir.size_of_zero_fill,
        callbacks,
        is_64bit: true,
    })
}

// ---------------------------------------------------------------------------
// Anti-debug heuristics
// ---------------------------------------------------------------------------

/// Common TLS callback anti-debug technique fingerprints.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TlsAntiDebugHint {
    /// `IsDebuggerPresent` is called from a TLS callback.
    IsDebuggerPresentCheck,
    /// `NtQueryInformationProcess` is called from a TLS callback.
    NtQueryInformationProcessCheck,
    /// Timing checks (RDTSC) are performed from a TLS callback.
    TimingCheck,
    /// The TLS callback modifies PE headers (checksum patching, etc.).
    HeaderModification,
    /// A TLS callback calls `TerminateProcess` or `ExitProcess`.
    ForcedExit,
}

/// A TLS analysis result.
#[derive(Debug, Clone)]
pub struct TlsAnalysis {
    /// Number of registered callbacks.
    pub callback_count: usize,
    /// TLS data size in bytes.
    pub tls_data_size: u64,
    /// Heuristic hints about potential anti-debug usage (based on DLL imports).
    pub anti_debug_hints: Vec<TlsAntiDebugHint>,
    /// `true` if the binary has any TLS callbacks.
    pub has_pre_main_code: bool,
}

impl TlsAnalysis {
    /// Analyze TLS info and imported functions for anti-debug signatures.
    #[must_use]
    pub fn analyze(tls: &TlsInfo, imported_names: &[&str]) -> Self {
        let mut hints = Vec::new();

        if tls.has_callbacks() {
            if imported_names.contains(&"IsDebuggerPresent") {
                hints.push(TlsAntiDebugHint::IsDebuggerPresentCheck);
            }
            if imported_names.contains(&"NtQueryInformationProcess")
            {
                hints.push(TlsAntiDebugHint::NtQueryInformationProcessCheck);
            }
            if imported_names
                .iter()
                .any(|&n| n == "TerminateProcess" || n == "ExitProcess")
            {
                hints.push(TlsAntiDebugHint::ForcedExit);
            }
        }

        Self {
            callback_count: tls.callbacks.len(),
            tls_data_size: tls.total_size(),
            anti_debug_hints: hints,
            has_pre_main_code: tls.has_callbacks(),
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tls_directory32_parse() {
        let mut buf = vec![0u8; 24];
        buf[0..4].copy_from_slice(&0x1_0000u32.to_le_bytes()); // start
        buf[4..8].copy_from_slice(&0x1_0020u32.to_le_bytes()); // end
        buf[8..12].copy_from_slice(&0x2_0000u32.to_le_bytes()); // index addr
        buf[12..16].copy_from_slice(&0x3_0000u32.to_le_bytes()); // callbacks VA
        buf[16..20].copy_from_slice(&4u32.to_le_bytes()); // zero fill
        buf[20..24].copy_from_slice(&0u32.to_le_bytes()); // characteristics
        let dir = TlsDirectory32::parse(&buf, 0).unwrap();
        assert_eq!(dir.start_address_of_raw_data, 0x1_0000);
        assert_eq!(dir.end_address_of_raw_data, 0x1_0020);
        assert_eq!(dir.size_of_zero_fill, 4);
    }

    #[test]
    fn test_tls_directory32_too_short() {
        assert!(TlsDirectory32::parse(&[0u8; 10], 0).is_err());
    }

    #[test]
    fn test_tls_directory64_parse() {
        let mut buf = vec![0u8; 40];
        buf[0..8].copy_from_slice(&0x1_4000_1000u64.to_le_bytes()); // start VA
        buf[8..16].copy_from_slice(&0x1_4000_1020u64.to_le_bytes()); // end VA
        buf[16..24].copy_from_slice(&0x1_4000_2000u64.to_le_bytes()); // index VA
        buf[24..32].copy_from_slice(&0x1_4000_3000u64.to_le_bytes()); // callbacks VA
        buf[32..36].copy_from_slice(&8u32.to_le_bytes()); // zero fill
        buf[36..40].copy_from_slice(&0x0020_0000u32.to_le_bytes()); // IMAGE_SCN_ALIGN_2BYTES
        let dir = TlsDirectory64::parse(&buf, 0).unwrap();
        assert_eq!(dir.start_address_of_raw_data, 0x1_4000_1000);
        assert_eq!(dir.size_of_zero_fill, 8);
        // characteristics 0x0020_0000: alignment field (bits [20..24]) = 2,
        // i.e. IMAGE_SCN_ALIGN_2BYTES -> 1 << (2 - 1) = 2 bytes.
        assert_eq!(dir.alignment(), 2);
    }

    #[test]
    fn test_tls_directory64_too_short() {
        assert!(TlsDirectory64::parse(&[0u8; 20], 0).is_err());
    }

    #[test]
    fn test_tls_info_total_size() {
        let info = TlsInfo {
            data_start: 0x1000,
            data_end: 0x1020,
            zero_fill_size: 8,
            callbacks: vec![0x5000],
            is_64bit: false,
        };
        assert_eq!(info.total_size(), 0x28); // 0x20 + 0x8
        assert!(info.has_callbacks());
    }

    #[test]
    fn test_tls_info_no_callbacks() {
        let info = TlsInfo {
            data_start: 0x1000,
            data_end: 0x1010,
            zero_fill_size: 0,
            callbacks: Vec::new(),
            is_64bit: false,
        };
        assert!(!info.has_callbacks());
    }

    #[test]
    fn test_tls_analysis_hints_detected() {
        let info = TlsInfo {
            data_start: 0,
            data_end: 0,
            zero_fill_size: 0,
            callbacks: vec![0xDEAD],
            is_64bit: false,
        };
        let imports = &["IsDebuggerPresent", "CreateFile"];
        let analysis = TlsAnalysis::analyze(&info, imports);
        assert_eq!(analysis.callback_count, 1);
        assert!(analysis.has_pre_main_code);
        assert!(
            analysis
                .anti_debug_hints
                .contains(&TlsAntiDebugHint::IsDebuggerPresentCheck)
        );
    }

    #[test]
    fn test_tls_analysis_no_callbacks_no_hints() {
        let info = TlsInfo {
            data_start: 0,
            data_end: 0,
            zero_fill_size: 0,
            callbacks: Vec::new(),
            is_64bit: true,
        };
        let analysis = TlsAnalysis::analyze(&info, &[]);
        assert!(analysis.anti_debug_hints.is_empty());
        assert!(!analysis.has_pre_main_code);
    }

    #[test]
    fn test_tls_parse_32_no_section_returns_none() {
        let sections: Vec<RvaSection> = Vec::new();
        let result = parse_tls_32(&[], &sections, 0x1000, 0x40_0000);
        assert!(result.is_none());
    }

    #[test]
    fn test_tls_parse_64_no_section_returns_none() {
        let sections: Vec<RvaSection> = Vec::new();
        let result = parse_tls_64(&[], &sections, 0x1000, 0x1_8000_0000);
        assert!(result.is_none());
    }
}
