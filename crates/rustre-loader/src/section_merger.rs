//! `section_merger` — Section merging and overlay analysis (structural / file layer).
//!
//! # Relation to `section_analysis`
//!
//! This module is the **structural / file layer**: it operates on raw
//! [`SectionInfo`](crate::SectionInfo) records (file offsets + sizes),
//! detects raw-file and virtual-address overlaps, identifies data appended
//! after the last section (overlays), extracts embedded files from overlays
//! (PE, ELF, ZIP, …), merges adjacent COFF split sections (`.text$mn` → `.text`),
//! and detects section name spoofing via expected-flag masks.
//!
//! [`section_analysis`](crate::section_analysis) is the **semantic / analytical
//! layer**: it operates on parsed [`SectionEntry`](crate::section_analysis::SectionEntry)
//! values (carrying loaded bytes) and computes entropy scores, packing
//! heuristics, W+X detection, cross-section call references, and risk scores.
//!
//! # Provided types
//!
//! `SectionMerger`, `MergeResult`, `MergedSection`, `SectionConflict`,
//! `ConflictKind`, `OverlayData`, `EmbeddedFile`.

use std::collections::HashMap;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::SectionInfo;

// ─────────────────────────────────────────────────────────────────────────────
// Error type
// ─────────────────────────────────────────────────────────────────────────────

/// Errors from section merger operations.
#[derive(Debug, Error)]
pub enum MergerError {
    /// Input data is too short for the declared section layout.
    #[error("data too short: section '{name}' requires offset {need}, have {have}")]
    DataTooShort {
        /// Section name.
        name: String,
        /// Required byte count.
        need: usize,
        /// Available byte count.
        have: usize,
    },
    /// Conflicting sections cannot be merged.
    #[error("cannot merge conflicting sections '{a}' and '{b}': {reason}")]
    ConflictUnresolvable {
        /// First section name.
        a: String,
        /// Second section name.
        b: String,
        /// Reason the conflict could not be resolved.
        reason: String,
    },
}

// ─────────────────────────────────────────────────────────────────────────────
// SectionConflict
// ─────────────────────────────────────────────────────────────────────────────

/// Describes an overlap or conflict between two sections.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SectionConflict {
    /// Name of the first section.
    pub section_a: String,
    /// Name of the second section.
    pub section_b: String,
    /// Kind of conflict detected.
    pub kind: ConflictKind,
    /// Start of the overlapping raw byte range.
    pub overlap_start: u64,
    /// End of the overlapping raw byte range (exclusive).
    pub overlap_end: u64,
    /// Number of overlapping bytes.
    pub overlap_bytes: u64,
}

impl SectionConflict {
    /// Whether the overlap is total (one section fully contained in another).
    #[must_use]
    pub const fn is_total_overlap(&self) -> bool {
        matches!(self.kind, ConflictKind::FullyContained)
    }
}

/// The kind of section conflict.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ConflictKind {
    /// The two sections partially overlap in raw file space.
    PartialOverlap,
    /// One section is fully contained within the other.
    FullyContained,
    /// The two sections have identical raw offsets and sizes.
    Duplicate,
    /// Sections share virtual address space but not raw space.
    VirtualOverlap,
    /// A section name looks like a well-known section but has wrong flags.
    NameSpoofing,
}

// ─────────────────────────────────────────────────────────────────────────────
// OverlayData
// ─────────────────────────────────────────────────────────────────────────────

/// Data appended after the last declared section (overlay).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OverlayData {
    /// Byte offset where the overlay begins (= end of last section raw data).
    pub offset: u64,
    /// Length of the overlay in bytes.
    pub length: u64,
    /// SHA-256 hash of the overlay bytes (hex).
    pub sha256: String,
    /// Entropy of the overlay (Shannon, bits).
    pub entropy: f64,
    /// Detected embedded file signatures within the overlay.
    pub embedded: Vec<EmbeddedFile>,
}

impl OverlayData {
    /// Whether any embedded files were detected.
    #[must_use]
    pub const fn has_embedded(&self) -> bool {
        !self.embedded.is_empty()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// EmbeddedFile
// ─────────────────────────────────────────────────────────────────────────────

/// An embedded file detected within overlay or section data.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmbeddedFile {
    /// Offset within the containing region (not file-absolute).
    pub offset: u64,
    /// Length in bytes (estimated from magic / header; may be approximate).
    pub length: u64,
    /// Detected format string (e.g. `"PE"`, `"ELF"`, `"ZIP"`, `"PDF"`).
    pub format: String,
    /// SHA-256 of the embedded data (hex).
    pub sha256: String,
    /// Entropy of the embedded data.
    pub entropy: f64,
}

// ─────────────────────────────────────────────────────────────────────────────
// MergeResult
// ─────────────────────────────────────────────────────────────────────────────

/// Result of a merge / analysis operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MergeResult {
    /// Merged section list (conflicts resolved; split sections combined).
    pub sections: Vec<MergedSection>,
    /// Detected conflicts.
    pub conflicts: Vec<SectionConflict>,
    /// Overlay data (if present).
    pub overlay: Option<OverlayData>,
    /// Whether any section name spoofing was detected.
    pub has_name_spoofing: bool,
    /// Whether any overlapping sections were found.
    pub has_overlaps: bool,
    /// Total bytes covered by all sections.
    pub total_section_bytes: u64,
}

impl MergeResult {
    /// Whether the binary looks structurally normal.
    #[must_use]
    pub const fn is_clean(&self) -> bool {
        !self.has_name_spoofing && !self.has_overlaps && self.overlay.is_none()
    }
}

/// A section after merging.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MergedSection {
    /// Merged name (first source section name).
    pub name: String,
    /// All source section names that were merged into this one.
    pub source_names: Vec<String>,
    /// Virtual address of the merged section.
    pub virtual_addr: u64,
    /// Virtual size of the merged section.
    pub virtual_size: u64,
    /// Raw offset in the file.
    pub raw_offset: u64,
    /// Raw size.
    pub raw_size: u64,
    /// Characteristics flags (OR of all source sections).
    pub characteristics: u32,
    /// SHA-256 of raw data (hex).
    pub sha256: String,
    /// Entropy of raw data.
    pub entropy: f64,
}

// ─────────────────────────────────────────────────────────────────────────────
// Known section properties for spoofing detection
// ─────────────────────────────────────────────────────────────────────────────

/// Expected characteristics for well-known section names.
static KNOWN_SECTIONS: &[(&str, u32, &str)] = &[
    // (name, expected_char_mask, description)
    (".text",   0x6000_0020, "code"),
    (".data",   0xC000_0040, "initialized data"),
    (".rdata",  0x4000_0040, "read-only data"),
    (".bss",    0xC000_0080, "uninitialized data"),
    (".idata",  0x4000_0040, "import data"),
    (".edata",  0x4000_0040, "export data"),
    (".rsrc",   0x4000_0040, "resources"),
    (".reloc",  0x4200_0040, "base relocations"),
    (".tls",    0xC000_0040, "TLS"),
    (".debug",  0x4200_0042, "debug info"),
];

// ─────────────────────────────────────────────────────────────────────────────
// SectionMerger
// ─────────────────────────────────────────────────────────────────────────────

/// Section merging and overlay analysis engine.
///
/// Operates on a list of [`SectionInfo`] objects and the raw binary bytes.
///
/// # Example
///
/// ```rust,ignore
/// let merger = SectionMerger::new();
/// let result = merger.analyze(&sections, &file_data)?;
/// if let Some(overlay) = &result.overlay {
///     println!("overlay at 0x{:x}: {} bytes", overlay.offset, overlay.length);
/// }
/// ```
#[derive(Debug, Clone, Default)]
pub struct SectionMerger {
    /// Minimum overlay size to report (bytes).
    pub min_overlay_size: u64,
    /// Minimum embedded file size to report (bytes).
    pub min_embedded_size: u64,
    /// Whether to compute per-section hashes (may be slow for large sections).
    pub compute_hashes: bool,
}

impl SectionMerger {
    /// Create a new merger with default settings.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            min_overlay_size: 16,
            min_embedded_size: 4,
            compute_hashes: true,
        }
    }

    /// Analyse sections and overlay in `data`.
    ///
    /// # Errors
    /// Returns [`MergerError`] if section layout is inconsistent with data size.
    pub fn analyze(
        &self,
        sections: &[SectionInfo],
        data: &[u8],
    ) -> Result<MergeResult, MergerError> {
        let conflicts = self.detect_conflicts(sections);
        let has_overlaps = conflicts
            .iter()
            .any(|c| matches!(c.kind, ConflictKind::PartialOverlap | ConflictKind::FullyContained | ConflictKind::Duplicate));
        let has_name_spoofing = conflicts
            .iter()
            .any(|c| matches!(c.kind, ConflictKind::NameSpoofing));

        let overlay = self.find_overlay(sections, data);
        let merged = self.merge_sections(sections, data);

        let total_section_bytes = merged.iter().map(|s| s.raw_size).sum();

        Ok(MergeResult {
            sections: merged,
            conflicts,
            overlay,
            has_name_spoofing,
            has_overlaps,
            total_section_bytes,
        })
    }

    // ─── conflict detection ───────────────────────────────────────────────────

    /// Detect raw-file and virtual-address overlaps, duplicates, and name spoofing.
    #[must_use]
    pub fn detect_conflicts(&self, sections: &[SectionInfo]) -> Vec<SectionConflict> {
        let mut conflicts = Vec::new();

        // Pairwise overlap checks
        for i in 0..sections.len() {
            for j in (i + 1)..sections.len() {
                let a = &sections[i];
                let b = &sections[j];

                // Raw file overlap
                if let Some(conflict) = raw_overlap(a, b) {
                    conflicts.push(conflict);
                }

                // Virtual address overlap (separate from raw)
                if let Some(conflict) = virtual_overlap(a, b) {
                    conflicts.push(conflict);
                }
            }

            // Name spoofing
            if let Some(conflict) = Self::check_name_spoofing(&sections[i]) {
                conflicts.push(conflict);
            }
        }

        conflicts
    }

    fn check_name_spoofing(section: &SectionInfo) -> Option<SectionConflict> {
        for &(known_name, expected_mask, _desc) in KNOWN_SECTIONS {
            if section.name.eq_ignore_ascii_case(known_name) {
                // Check if the section is missing a critical flag
                let actual = section.flags;
                let critical_flags = expected_mask & 0xF000_00E0;
                if (actual & critical_flags) != (expected_mask & critical_flags) {
                    return Some(SectionConflict {
                        section_a: section.name.clone(),
                        section_b: known_name.to_string(),
                        kind: ConflictKind::NameSpoofing,
                        overlap_start: section.raw_offset,
                        overlap_end: (section.raw_offset + section.raw_size),
                        overlap_bytes: section.raw_size,
                    });
                }
                break;
            }
        }
        None
    }

    // ─── overlay detection ────────────────────────────────────────────────────

    /// Detect data appended after the last section.
    #[must_use]
    pub fn find_overlay(&self, sections: &[SectionInfo], data: &[u8]) -> Option<OverlayData> {
        if sections.is_empty() || data.is_empty() {
            return None;
        }

        // End of last section in raw file space
        let last_section_end = sections
            .iter()
            .map(|s| s.raw_offset.saturating_add(s.raw_size))
            .max()
            .unwrap_or(0);

        if last_section_end >= data.len() as u64 {
            return None;
        }

        let overlay_start = usize::try_from(last_section_end).unwrap_or(usize::MAX);
        let overlay_bytes = &data[overlay_start..];
        let length = overlay_bytes.len() as u64;

        if length < self.min_overlay_size {
            return None;
        }

        let sha256 = sha256_hex(overlay_bytes);
        let entropy = shannon_entropy(overlay_bytes);
        let embedded = self.find_embedded(overlay_bytes);

        Some(OverlayData {
            offset: last_section_end,
            length,
            sha256,
            entropy,
            embedded,
        })
    }

    // ─── embedded file detection ──────────────────────────────────────────────

    /// Scan `region` for embedded file signatures and return all found files.
    #[must_use]
    pub fn find_embedded(&self, region: &[u8]) -> Vec<EmbeddedFile> {
        // Magic signatures: (magic_bytes, format_name, size_hint_fn)
        type SizeHintFn = fn(&[u8]) -> u64;
        let mut found = Vec::new();

        let signatures: &[(&[u8], &str, SizeHintFn)] = &[
            (b"MZ", "PE", |d| pe_size_hint(d)),
            (b"\x7fELF", "ELF", |_| 0),
            (b"\xca\xfe\xba\xbe", "Mach-O Fat", |_| 0),
            (b"\xcf\xfa\xed\xfe", "Mach-O 64LE", |_| 0),
            (b"\xce\xfa\xed\xfe", "Mach-O 32LE", |_| 0),
            (b"PK\x03\x04", "ZIP", |d| zip_size_hint(d)),
            (b"%PDF", "PDF", |_| 0),
            (b"\xd0\xcf\x11\xe0", "OLE2", |_| 0),
            (b"\x1f\x8b", "GZIP", |_| 0),
            (b"BZh", "BZIP2", |_| 0),
            (b"dex\n", "DEX", |d| if d.len() >= 36 { u64::from(read_u32_le_local(d, 32)) } else { 0 }),
            (b"\x00asm", "WASM", |_| 0),
            (b"Rar!", "RAR", |_| 0),
            (b"\x1b\x4c\x75\x61", "Lua Bytecode", |_| 0),
        ];

        let limit = region.len().saturating_sub(4);
        for offset in 0..limit {
            for &(magic, fmt, size_fn) in signatures {
                if offset + magic.len() <= region.len()
                    && &region[offset..offset + magic.len()] == magic
                {
                    let remaining = &region[offset..];
                    let raw_size = size_fn(remaining);
                    let remaining_len = u64::try_from(remaining.len()).unwrap_or(u64::MAX);
                    let length = if raw_size > 0 && raw_size <= remaining_len {
                        raw_size
                    } else {
                        remaining_len.min(16 * 1024 * 1024)
                    };

                    if length < self.min_embedded_size {
                        continue;
                    }

                    let end = offset.saturating_add(usize::try_from(length).unwrap_or(usize::MAX));
                    let end = end.min(region.len());
                    let slice = &region[offset..end];
                    let sha256 = sha256_hex(slice);
                    let entropy = shannon_entropy(slice);

                    found.push(EmbeddedFile {
                        offset: u64::try_from(offset).unwrap_or(u64::MAX),
                        length,
                        format: fmt.to_string(),
                        sha256,
                        entropy,
                    });

                    // Skip past this magic to avoid duplicate detections at +1
                    break;
                }
            }
        }

        found
    }

    // ─── section merging ──────────────────────────────────────────────────────

    /// Merge the section list, combining adjacent/split sections.
    ///
    /// Sections whose names start with the same prefix and are contiguous in
    /// both virtual and raw space are merged.  For example `.text$mn` and
    /// `.text$x` are merged into `.text`.
    #[must_use]
    pub fn merge_sections(&self, sections: &[SectionInfo], data: &[u8]) -> Vec<MergedSection> {
        if sections.is_empty() {
            return Vec::new();
        }

        // Sort by raw offset
        let mut sorted: Vec<&SectionInfo> = sections.iter().collect();
        sorted.sort_by_key(|s| s.raw_offset);

        let mut merged: Vec<MergedSection> = Vec::new();

        for sec in sorted {
            let raw_start = usize::try_from(sec.raw_offset).unwrap_or(usize::MAX);
            let raw_end = raw_start.saturating_add(usize::try_from(sec.raw_size).unwrap_or(usize::MAX));
            let raw_end_clamped = raw_end.min(data.len());

            let raw_data = if raw_start < data.len() {
                &data[raw_start..raw_end_clamped]
            } else {
                &[]
            };

            let sha256 = if self.compute_hashes { sha256_hex(raw_data) } else { String::new() };
            let entropy = shannon_entropy(raw_data);

            // Try to merge with the last merged section if contiguous
            let canonical_name = canonical_section_name(&sec.name);
            let merged_with_prev = if let Some(last) = merged.last_mut() {
                let prev_end_raw = last.raw_offset + last.raw_size;
                let prev_end_va = last.virtual_addr + last.virtual_size;
                let contiguous_raw = sec.raw_offset.abs_diff(prev_end_raw) <= 16;
                let contiguous_va =
                    sec.virtual_addr.abs_diff(prev_end_va) <= 4096;
                let same_name = canonical_section_name(&last.name) == canonical_name;

                if same_name && contiguous_raw && contiguous_va {
                    last.source_names.push(sec.name.clone());
                    last.virtual_size = (sec.virtual_addr + sec.virtual_size).saturating_sub(last.virtual_addr);
                    last.raw_size = (sec.raw_offset + sec.raw_size).saturating_sub(last.raw_offset);
                    last.characteristics |= sec.flags;
                    true
                } else {
                    false
                }
            } else {
                false
            };

            if !merged_with_prev {
                merged.push(MergedSection {
                    name: sec.name.clone(),
                    source_names: vec![sec.name.clone()],
                    virtual_addr: sec.virtual_addr,
                    virtual_size: sec.virtual_size,
                    raw_offset: sec.raw_offset,
                    raw_size: sec.raw_size,
                    characteristics: sec.flags,
                    sha256,
                    entropy,
                });
            }
        }

        merged
    }

    // ─── section hash computation ─────────────────────────────────────────────

    /// Compute per-section hashes and return a map from section name → SHA-256.
    #[must_use]
    pub fn section_hashes(&self, sections: &[SectionInfo], data: &[u8]) -> HashMap<String, String> {
        sections
            .iter()
            .map(|s| {
                let start = usize::try_from(s.raw_offset).unwrap_or(usize::MAX);
                let end = start.saturating_add(usize::try_from(s.raw_size).unwrap_or(usize::MAX)).min(data.len());
                let slice = if start < data.len() { &data[start..end] } else { &[] };
                (s.name.clone(), sha256_hex(slice))
            })
            .collect()
    }

    /// Entropy for every section.
    #[must_use]
    pub fn section_entropies(&self, sections: &[SectionInfo], data: &[u8]) -> Vec<(String, f64)> {
        sections
            .iter()
            .map(|s| {
                let start = usize::try_from(s.raw_offset).unwrap_or(usize::MAX);
                let end = start.saturating_add(usize::try_from(s.raw_size).unwrap_or(usize::MAX)).min(data.len());
                let slice = if start < data.len() { &data[start..end] } else { &[] };
                (s.name.clone(), shannon_entropy(slice))
            })
            .collect()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Internal helpers
// ─────────────────────────────────────────────────────────────────────────────

fn raw_overlap(a: &SectionInfo, b: &SectionInfo) -> Option<SectionConflict> {
    let a_start = a.raw_offset;
    let a_end = a_start + a.raw_size;
    let b_start = b.raw_offset;
    let b_end = b_start + b.raw_size;

    if a.raw_size == 0 || b.raw_size == 0 {
        return None;
    }

    let overlap_start = a_start.max(b_start);
    let overlap_end = a_end.min(b_end);

    if overlap_start >= overlap_end {
        return None;
    }

    let overlap_bytes = overlap_end - overlap_start;

    let kind = if a_start == b_start && a_end == b_end {
        ConflictKind::Duplicate
    } else if (a_start >= b_start && a_end <= b_end) || (b_start >= a_start && b_end <= a_end) {
        ConflictKind::FullyContained
    } else {
        ConflictKind::PartialOverlap
    };

    Some(SectionConflict {
        section_a: a.name.clone(),
        section_b: b.name.clone(),
        kind,
        overlap_start,
        overlap_end,
        overlap_bytes,
    })
}

fn virtual_overlap(a: &SectionInfo, b: &SectionInfo) -> Option<SectionConflict> {
    let a_va = a.virtual_addr;
    let a_va_end = a_va + a.virtual_size;
    let b_va = b.virtual_addr;
    let b_va_end = b_va + b.virtual_size;

    if a.virtual_size == 0 || b.virtual_size == 0 {
        return None;
    }

    // Already caught by raw_overlap if raw regions also overlap
    let va_overlaps = a_va < b_va_end && b_va < a_va_end;
    let raw_a = (a.raw_offset, a.raw_offset + a.raw_size);
    let raw_b = (b.raw_offset, b.raw_offset + b.raw_size);
    let raw_overlaps = raw_a.0 < raw_b.1 && raw_b.0 < raw_a.1;

    if va_overlaps && !raw_overlaps {
        let overlap_start = a_va.max(b_va);
        let overlap_end = a_va_end.min(b_va_end);
        Some(SectionConflict {
            section_a: a.name.clone(),
            section_b: b.name.clone(),
            kind: ConflictKind::VirtualOverlap,
            overlap_start,
            overlap_end,
            overlap_bytes: overlap_end - overlap_start,
        })
    } else {
        None
    }
}

fn canonical_section_name(name: &str) -> &str {
    // Strip COFF split-section suffix like ".text$mn" → ".text"
    name.find('$').map_or(name, |pos| &name[..pos])
}

fn pe_size_hint(data: &[u8]) -> u64 {
    if data.len() < 0x40 { return 0; }
    let pe_off = usize::try_from(read_u32_le_local(data, 0x3C)).unwrap_or(usize::MAX);
    if pe_off + 0x58 > data.len() { return 0; }
    if &data[pe_off..pe_off+4] != b"PE\x00\x00" { return 0; }
    let opt_magic = read_u16_le_local(data, pe_off + 24);
    let size_off = match opt_magic {
        0x010B | 0x020B => pe_off + 24 + 56,
        _ => return 0,
    };
    if size_off + 4 > data.len() { return 0; }
    u64::from(read_u32_le_local(data, size_off))
}

fn zip_size_hint(data: &[u8]) -> u64 {
    // Scan for the end-of-central-directory record (signature 0x06054b50)
    let sig = b"\x50\x4b\x05\x06";
    for i in (0..data.len().saturating_sub(22)).rev() {
        if data[i..].starts_with(sig) {
            return (i + 22) as u64;
        }
    }
    0
}

fn read_u32_le_local(data: &[u8], off: usize) -> u32 {
    if off + 4 > data.len() { return 0; }
    u32::from_le_bytes([data[off], data[off+1], data[off+2], data[off+3]])
}

fn read_u16_le_local(data: &[u8], off: usize) -> u16 {
    if off + 2 > data.len() { return 0; }
    u16::from_le_bytes([data[off], data[off+1]])
}

/// Shannon entropy.
fn shannon_entropy(data: &[u8]) -> f64 {
    if data.is_empty() { return 0.0; }
    let mut freq = [0u64; 256];
    for &b in data { freq[b as usize] += 1; }
    let len = f64::from(u32::try_from(data.len()).unwrap_or(u32::MAX));
    freq.iter()
        .filter(|&&c| c > 0)
        .map(|&c| { let p = f64::from(u32::try_from(c).unwrap_or(u32::MAX)) / len; -p * p.log2() })
        .sum()
}

/// SHA-256 via a minimal pure-Rust implementation (RFC 6234 / FIPS 180-4).
fn sha256_hex(data: &[u8]) -> String {
    let digest = sha256_digest(data);
    let mut out = String::with_capacity(64);
    for b in &digest {
        use std::fmt::Write as _;
        let _ = write!(out, "{b:02x}");
    }
    out
}

fn sha256_digest(data: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(data);
    let out = hasher.finalize();
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&out);
    arr
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_section(name: &str, va: u32, vs: u32, raw: u32, rs: u32, flags: u32) -> SectionInfo {
        SectionInfo::new(name, u64::from(va), u64::from(vs), u64::from(raw), u64::from(rs), flags)
    }

    #[test]
    fn test_no_conflicts_clean() {
        let sections = vec![
            make_section(".text",  0x1000, 0x200, 0x400, 0x200, 0x60000020),
            make_section(".rdata", 0x2000, 0x100, 0x600, 0x100, 0x40000040),
        ];
        let merger = SectionMerger::new();
        let conflicts = merger.detect_conflicts(&sections);
        // Should have no raw overlaps
        assert!(conflicts.iter().all(|c| !matches!(c.kind, ConflictKind::PartialOverlap | ConflictKind::Duplicate | ConflictKind::FullyContained)));
    }

    #[test]
    fn test_raw_overlap_detected() {
        let sections = vec![
            make_section(".a", 0x1000, 0x200, 0x400, 0x200, 0x60000020),
            make_section(".b", 0x2000, 0x200, 0x500, 0x200, 0x60000020),
            // .a raw: 0x400..0x600, .b raw: 0x500..0x700 — overlap at 0x500..0x600
        ];
        let merger = SectionMerger::new();
        let conflicts = merger.detect_conflicts(&sections);
        assert!(conflicts.iter().any(|c| matches!(c.kind, ConflictKind::PartialOverlap)));
    }

    #[test]
    fn test_duplicate_detected() {
        let sections = vec![
            make_section(".a", 0x1000, 0x200, 0x400, 0x200, 0x20),
            make_section(".b", 0x2000, 0x200, 0x400, 0x200, 0x20),
        ];
        let merger = SectionMerger::new();
        let conflicts = merger.detect_conflicts(&sections);
        assert!(conflicts.iter().any(|c| matches!(c.kind, ConflictKind::Duplicate)));
    }

    #[test]
    fn test_overlay_detected() {
        let mut data = vec![0u8; 0x600];
        // Section occupies 0x400..0x500; overlay is 0x500..0x600
        data[0x500..0x504].copy_from_slice(b"OVLY");
        let sections = vec![make_section(".text", 0x1000, 0x100, 0x400, 0x100, 0x20)];
        let merger = SectionMerger::new();
        let overlay = merger.find_overlay(&sections, &data).unwrap();
        assert_eq!(overlay.offset, 0x500);
        assert_eq!(overlay.length, 0x100);
    }

    #[test]
    fn test_no_overlay_when_data_ends_at_section() {
        let data = vec![0u8; 0x500];
        let sections = vec![make_section(".text", 0x1000, 0x100, 0x400, 0x100, 0x20)];
        let merger = SectionMerger::new();
        let overlay = merger.find_overlay(&sections, &data);
        assert!(overlay.is_none());
    }

    #[test]
    fn test_embedded_mz_in_overlay() {
        let mut data = vec![0u8; 0x600];
        // Section at 0x400..0x500
        // Overlay at 0x500 containing a PE magic
        data[0x500] = b'M'; data[0x501] = b'Z';
        let sections = vec![make_section(".text", 0x1000, 0x100, 0x400, 0x100, 0x20)];
        let merger = SectionMerger::new();
        let overlay = merger.find_overlay(&sections, &data).unwrap();
        assert!(overlay.embedded.iter().any(|e| e.format == "PE"));
    }

    #[test]
    fn test_sha256_empty() {
        let h = sha256_hex(b"");
        assert_eq!(h, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    }

    #[test]
    fn test_sha256_abc() {
        let h = sha256_hex(b"abc");
        // Canonical SHA-256("abc")
        assert_eq!(h, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    }

    #[test]
    fn test_section_hashes_and_entropies() {
        let data = vec![0xABu8; 512];
        let sections = vec![make_section(".text", 0x1000, 0x100, 0, 0x100, 0x20)];
        let merger = SectionMerger::new();
        let hashes = merger.section_hashes(&sections, &data);
        assert!(hashes.contains_key(".text"));
        let ents = merger.section_entropies(&sections, &data);
        assert_eq!(ents.len(), 1);
        assert!(ents[0].1 < 0.01); // constant data = 0 entropy
    }

    #[test]
    fn test_merge_result_is_clean() {
        let data = vec![0u8; 0x600];
        let sections = vec![
            make_section(".text",  0x1000, 0x100, 0x400, 0x100, 0x60000020),
            make_section(".rdata", 0x2000, 0x100, 0x500, 0x100, 0x40000040),
        ];
        let merger = SectionMerger::new();
        let result = merger.analyze(&sections, &data).unwrap();
        // Only raw overlap concern is none here; overlay is none (ends at 0x600)
        assert!(result.overlay.is_none());
    }
}
