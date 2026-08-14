//! `multi_arch_loader` — Multi-architecture binary loader with per-arch views.
//!
//! Provides [`MultiArchLoader`] which inspects raw bytes, selects the best
//! matching [`ArchVariant`] according to a configurable [`LoaderPolicy`], and
//! returns [`LoadedBinary`] containing one or more [`BinarySlice`]s that give
//! arch-specific views into the same backing buffer.

use std::collections::HashMap;
use std::fmt;
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use thiserror::Error;

// ─────────────────────────────────────────────────────────────────────────────
// Errors
// ─────────────────────────────────────────────────────────────────────────────

/// Errors produced by [`MultiArchLoader`].
#[derive(Debug, Error)]
pub enum MultiArchError {
    /// The input byte slice is too short to contain any recognisable header.
    #[error("input too short: {0} bytes")]
    TooShort(usize),
    /// No loader was able to identify a known architecture in the input.
    #[error("unrecognised architecture in binary")]
    UnrecognisedArch,
    /// A required section or segment was absent from the binary.
    #[error("missing required segment: {0}")]
    MissingSegment(String),
    /// An internal offset arithmetic overflow occurred.
    #[error("offset overflow at {0:#x}")]
    OffsetOverflow(usize),
    /// Policy rejected the available architectures.
    #[error("loader policy rejected available architectures: {reason}")]
    PolicyRejected { reason: String },
}

// ─────────────────────────────────────────────────────────────────────────────
// ArchVariant
// ─────────────────────────────────────────────────────────────────────────────

/// An instruction-set architecture variant recognised by [`MultiArchLoader`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ArchVariant {
    /// Intel/AMD 32-bit (IA-32).
    X86,
    /// Intel/AMD 64-bit (x86-64 / AMD64).
    X64,
    /// ARM 32-bit Thumb/ARM.
    Arm,
    /// `AArch64` (64-bit ARM).
    Arm64,
    /// MIPS (big- or little-endian, 32-bit).
    Mips,
    /// PowerPC 32-bit.
    Ppc,
    /// RISC-V (RV32 or RV64, detected from ELF class).
    RiscV,
    /// Unknown / unrecognised variant (carry-through).
    Unknown,
}

impl ArchVariant {
    /// Returns `true` for 64-bit variants.
    #[must_use]
    pub const fn is_64bit(self) -> bool {
        matches!(self, Self::X64 | Self::Arm64)
    }

    /// Human-readable short name.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::X86 => "x86",
            Self::X64 => "x86_64",
            Self::Arm => "arm",
            Self::Arm64 => "arm64",
            Self::Mips => "mips",
            Self::Ppc => "ppc",
            Self::RiscV => "riscv",
            Self::Unknown => "unknown",
        }
    }

    /// Returns an approximate default pointer width in bits.
    #[must_use]
    pub const fn pointer_width(self) -> u8 {
        if self.is_64bit() { 64 } else { 32 }
    }
}

impl fmt::Display for ArchVariant {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// LoaderPolicy
// ─────────────────────────────────────────────────────────────────────────────

/// Governs how [`MultiArchLoader`] picks from multiple candidate architectures.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[derive(Default)]
pub enum LoaderPolicy {
    /// Always prefer a 64-bit variant when both 32-bit and 64-bit are present.
    Prefer64Bit,
    /// Always prefer a 32-bit variant.
    Prefer32Bit,
    /// Let the loader pick based on heuristic confidence scores.
    #[default]
    Auto,
    /// Load every detected architecture (fat binary / multi-slice).
    LoadAll,
    /// Only accept a specific architecture; error for anything else.
    Strict(ArchVariant),
}


// ─────────────────────────────────────────────────────────────────────────────
// EntryPointList
// ─────────────────────────────────────────────────────────────────────────────

/// A list of entry-point virtual addresses discovered in a [`BinarySlice`].
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct EntryPointList {
    /// Primary entry point (e.g. `e_entry` or `AddressOfEntryPoint`).
    pub primary: Option<u64>,
    /// Additional entry points (e.g. TLS callbacks, `_start` vs `main`).
    pub additional: Vec<u64>,
}

impl EntryPointList {
    /// Create a new list with a single primary entry point.
    #[must_use]
    pub const fn new(primary: u64) -> Self {
        Self {
            primary: Some(primary),
            additional: Vec::new(),
        }
    }

    /// Add an additional entry point.
    pub fn push(&mut self, addr: u64) {
        self.additional.push(addr);
    }

    /// Return all entry points (primary first, then additional).
    #[must_use]
    pub fn all(&self) -> Vec<u64> {
        let mut v = Vec::with_capacity(1 + self.additional.len());
        if let Some(p) = self.primary {
            v.push(p);
        }
        v.extend_from_slice(&self.additional);
        v
    }

    /// Returns `true` if at least one entry point is known.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.primary.is_none() && self.additional.is_empty()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// BinarySlice
// ─────────────────────────────────────────────────────────────────────────────

/// An arch-specific view into the backing byte buffer.
///
/// Multiple slices may share the same buffer (fat binary scenario).
#[derive(Debug, Clone)]
pub struct BinarySlice {
    /// The detected architecture for this slice.
    pub arch: ArchVariant,
    /// Byte offset in the original buffer where this slice starts.
    pub offset: usize,
    /// Length of the slice in bytes.
    pub length: usize,
    /// Heuristic confidence score (0.0 – 1.0).
    pub confidence: f32,
    /// Detected image base (virtual address of first mapped byte).
    pub image_base: u64,
    /// Entry points discovered in this slice.
    pub entry_points: EntryPointList,
    /// Optional human-readable format description.
    pub format_tag: String,
    /// The backing buffer (Arc-shared with [`LoadedBinary`]).
    pub(crate) data: Arc<Vec<u8>>,
}

impl BinarySlice {
    /// Access the raw bytes for this slice.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        let end = (self.offset + self.length).min(self.data.len());
        &self.data[self.offset..end]
    }

    /// Read a `u16` at `local_offset` within this slice (little-endian).
    #[must_use]
    pub fn read_u16_le(&self, local_offset: usize) -> Option<u16> {
        let b = self.bytes();
        let end = local_offset.checked_add(2)?;
        if end > b.len() {
            return None;
        }
        Some(u16::from_le_bytes([b[local_offset], b[local_offset + 1]]))
    }

    /// Read a `u32` at `local_offset` within this slice (little-endian).
    #[must_use]
    pub fn read_u32_le(&self, local_offset: usize) -> Option<u32> {
        let b = self.bytes();
        let end = local_offset.checked_add(4)?;
        if end > b.len() {
            return None;
        }
        Some(u32::from_le_bytes(
            b[local_offset..local_offset + 4].try_into().ok()?,
        ))
    }

    /// Read a `u64` at `local_offset` within this slice (little-endian).
    #[must_use]
    pub fn read_u64_le(&self, local_offset: usize) -> Option<u64> {
        let b = self.bytes();
        let end = local_offset.checked_add(8)?;
        if end > b.len() {
            return None;
        }
        Some(u64::from_le_bytes(
            b[local_offset..local_offset + 8].try_into().ok()?,
        ))
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// LoadedBinary
// ─────────────────────────────────────────────────────────────────────────────

/// The result of a successful [`MultiArchLoader::load`] call.
#[derive(Debug)]
pub struct LoadedBinary {
    /// Original file name or label (optional, for display).
    pub name: String,
    /// One slice per detected architecture (usually one, many for fat bins).
    pub slices: Vec<BinarySlice>,
    /// Metadata key-value pairs gathered during loading.
    pub metadata: HashMap<String, String>,
    /// The raw backing buffer.
    data: Arc<Vec<u8>>,
}

impl LoadedBinary {
    /// Total size of the backing buffer.
    #[must_use]
    pub fn raw_size(&self) -> usize {
        self.data.len()
    }

    /// Return the primary (highest-confidence) slice.
    #[must_use]
    pub fn primary_slice(&self) -> Option<&BinarySlice> {
        self.slices.iter().max_by(|a, b| {
            a.confidence
                .partial_cmp(&b.confidence)
                .unwrap_or(std::cmp::Ordering::Equal)
        })
    }

    /// Return all slices matching `arch`.
    #[must_use]
    pub fn slices_for(&self, arch: ArchVariant) -> Vec<&BinarySlice> {
        self.slices.iter().filter(|s| s.arch == arch).collect()
    }

    /// Raw bytes of the entire backing buffer.
    #[must_use]
    pub fn raw_bytes(&self) -> &[u8] {
        &self.data
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Internal probing helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Probe result from a single format detector.
#[derive(Debug)]
struct Probe {
    arch: ArchVariant,
    offset: usize,
    length: usize,
    confidence: f32,
    image_base: u64,
    entry_points: EntryPointList,
    format_tag: String,
}

fn probe_elf(data: &[u8]) -> Option<Probe> {
    if data.len() < 0x40 {
        return None;
    }
    if &data[0..4] != b"\x7fELF" {
        return None;
    }
    let class = data[4]; // 1 = 32-bit, 2 = 64-bit
    let e_machine = u16::from_le_bytes([data[0x12], data[0x13]]);
    let arch = match e_machine {
        0x03 => ArchVariant::X86,
        0x3E => ArchVariant::X64,
        0x28 => ArchVariant::Arm,
        0xB7 => ArchVariant::Arm64,
        0x08 | 0x0A => ArchVariant::Mips,
        0x14 | 0x15 => ArchVariant::Ppc,
        0xF3 => ArchVariant::RiscV,
        _ => ArchVariant::Unknown,
    };
    let (entry, image_base) = if class == 2 {
        let entry = u64::from_le_bytes(data[0x18..0x20].try_into().ok()?);
        (entry, 0u64)
    } else {
        let entry = u64::from(u32::from_le_bytes(data[0x18..0x1C].try_into().ok()?));
        (entry, 0u64)
    };
    Some(Probe {
        arch,
        offset: 0,
        length: data.len(),
        confidence: 0.95,
        image_base,
        entry_points: EntryPointList::new(entry),
        format_tag: format!("ELF{}", if class == 2 { "64" } else { "32" }),
    })
}

fn probe_pe(data: &[u8]) -> Option<Probe> {
    if data.len() < 0x40 {
        return None;
    }
    if &data[0..2] != b"MZ" {
        return None;
    }
    let pe_offset = u32::from_le_bytes(data[0x3C..0x40].try_into().ok()?) as usize;
    if pe_offset + 6 > data.len() {
        return None;
    }
    if &data[pe_offset..pe_offset + 4] != b"PE\0\0" {
        return None;
    }
    let machine = u16::from_le_bytes([data[pe_offset + 4], data[pe_offset + 5]]);
    let arch = match machine {
        0x014C => ArchVariant::X86,
        0x8664 => ArchVariant::X64,
        0x01C0 | 0x01C4 => ArchVariant::Arm,
        0xAA64 => ArchVariant::Arm64,
        _ => ArchVariant::Unknown,
    };
    // Optional header magic distinguishes PE32/PE32+
    let opt_off = pe_offset + 24;
    let (entry, image_base) = if opt_off + 4 <= data.len() {
        let magic = u16::from_le_bytes([data[opt_off], data[opt_off + 1]]);
        if magic == 0x20B && opt_off + 40 <= data.len() {
            // PE32+
            let e = u64::from(u32::from_le_bytes(data[opt_off + 16..opt_off + 20].try_into().ok()?));
            let b = u64::from_le_bytes(data[opt_off + 24..opt_off + 32].try_into().ok()?);
            (e, b)
        } else if magic == 0x10B && opt_off + 36 <= data.len() {
            let e = u64::from(u32::from_le_bytes(data[opt_off + 16..opt_off + 20].try_into().ok()?));
            let b = u64::from(u32::from_le_bytes(data[opt_off + 28..opt_off + 32].try_into().ok()?));
            (e, b)
        } else {
            (0, 0)
        }
    } else {
        (0, 0)
    };
    Some(Probe {
        arch,
        offset: 0,
        length: data.len(),
        confidence: 0.97,
        image_base,
        entry_points: EntryPointList::new(image_base + entry),
        format_tag: "PE".to_string(),
    })
}

fn probe_macho(data: &[u8]) -> Option<Vec<Probe>> {
    if data.len() < 8 {
        return None;
    }
    let magic = u32::from_le_bytes(data[0..4].try_into().ok()?);
    match magic {
        0xFEED_FACE | 0xCEFA_EDFE => {
            // 32-bit Mach-O
            let cpu = u32::from_le_bytes(data[4..8].try_into().ok()?);
            let arch = cpu_type_to_arch(cpu);
            Some(vec![Probe {
                arch,
                offset: 0,
                length: data.len(),
                confidence: 0.96,
                image_base: 0,
                entry_points: EntryPointList::default(),
                format_tag: "Mach-O32".into(),
            }])
        }
        0xFEED_FACF | 0xCFFA_EDFE => {
            let cpu = u32::from_le_bytes(data[4..8].try_into().ok()?);
            let arch = cpu_type_to_arch(cpu);
            Some(vec![Probe {
                arch,
                offset: 0,
                length: data.len(),
                confidence: 0.96,
                image_base: 0,
                entry_points: EntryPointList::default(),
                format_tag: "Mach-O64".into(),
            }])
        }
        0xCAFE_BABE | 0xBEBA_FECA => {
            // Fat binary
            let n_arches = u32::from_be_bytes(data[4..8].try_into().ok()?) as usize;
            let mut probes = Vec::with_capacity(n_arches);
            for i in 0..n_arches {
                let base = 8 + i * 20;
                if base + 20 > data.len() {
                    break;
                }
                let cpu = u32::from_be_bytes(data[base..base + 4].try_into().ok()?);
                let off = u32::from_be_bytes(data[base + 8..base + 12].try_into().ok()?) as usize;
                let sz = u32::from_be_bytes(data[base + 12..base + 16].try_into().ok()?) as usize;
                let arch = cpu_type_to_arch(cpu);
                probes.push(Probe {
                    arch,
                    offset: off,
                    length: sz,
                    confidence: 0.96,
                    image_base: 0,
                    entry_points: EntryPointList::default(),
                    format_tag: "Mach-OFat".into(),
                });
            }
            Some(probes)
        }
        _ => None,
    }
}

const fn cpu_type_to_arch(cpu: u32) -> ArchVariant {
    match cpu & 0x00FF_FFFF {
        7 => {
            if cpu & 0x0100_0000 != 0 {
                ArchVariant::X64
            } else {
                ArchVariant::X86
            }
        }
        12 => {
            if cpu & 0x0100_0000 != 0 {
                ArchVariant::Arm64
            } else {
                ArchVariant::Arm
            }
        }
        18 => ArchVariant::Ppc,
        8 => ArchVariant::Mips,
        _ => ArchVariant::Unknown,
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// MultiArchLoader
// ─────────────────────────────────────────────────────────────────────────────

/// Root multi-architecture binary loader.
///
/// ```rust
/// use rustre_loader::multi_arch_loader::{MultiArchLoader, LoaderPolicy};
///
/// let bytes = b"\x7fELF\x02\x01\x01\x00".to_vec();
/// let loader = MultiArchLoader::new(LoaderPolicy::Auto);
/// // loader.load("test", bytes) — would fail on truncated input, but API is shown.
/// let _ = loader;
/// ```
#[derive(Debug, Clone)]
pub struct MultiArchLoader {
    policy: LoaderPolicy,
    /// Minimum confidence threshold (0.0–1.0) to accept a detected slice.
    pub min_confidence: f32,
}

impl Default for MultiArchLoader {
    fn default() -> Self {
        Self::new(LoaderPolicy::Auto)
    }
}

impl MultiArchLoader {
    /// Create a new loader with the given [`LoaderPolicy`].
    #[must_use]
    pub const fn new(policy: LoaderPolicy) -> Self {
        Self {
            policy,
            min_confidence: 0.5,
        }
    }

    /// Set the minimum confidence threshold (0.0–1.0).
    #[must_use]
    pub const fn with_min_confidence(mut self, threshold: f32) -> Self {
        // NaN-safe clamp: `f32::clamp` propagates NaN and `is_nan()` is not
        // available in a const fn. A NaN threshold would reject every detected
        // architecture in silence, since all comparisons against NaN are false.
        self.min_confidence = if threshold >= 1.0 {
            1.0
        } else if threshold > 0.0 {
            threshold
        } else {
            0.0
        };
        self
    }

    /// Load `data` and return a [`LoadedBinary`].
    ///
    /// # Errors
    /// Returns [`MultiArchError`] if no architecture was detected or the
    /// policy filtered out all candidates.
    pub fn load(
        &self,
        name: impl Into<String>,
        data: Vec<u8>,
    ) -> Result<LoadedBinary, MultiArchError> {
        if data.len() < 4 {
            return Err(MultiArchError::TooShort(data.len()));
        }
        let arc_data = Arc::new(data);
        let mut raw_probes: Vec<Probe> = Vec::new();

        // Try each format detector in priority order
        if let Some(probe) = probe_pe(&arc_data) {
            raw_probes.push(probe);
        } else if let Some(macho_probes) = probe_macho(&arc_data) {
            raw_probes.extend(macho_probes);
        } else if let Some(probe) = probe_elf(&arc_data) {
            raw_probes.push(probe);
        }

        if raw_probes.is_empty() {
            return Err(MultiArchError::UnrecognisedArch);
        }

        // Filter by confidence
        let probes: Vec<Probe> = raw_probes
            .into_iter()
            .filter(|p| p.confidence >= self.min_confidence)
            .collect();
        if probes.is_empty() {
            return Err(MultiArchError::UnrecognisedArch);
        }

        // Apply policy
        let selected = self.apply_policy(probes)?;

        let slices: Vec<BinarySlice> = selected
            .into_iter()
            .map(|p| BinarySlice {
                arch: p.arch,
                offset: p.offset,
                length: p.length,
                confidence: p.confidence,
                image_base: p.image_base,
                entry_points: p.entry_points,
                format_tag: p.format_tag,
                data: Arc::clone(&arc_data),
            })
            .collect();

        let mut metadata = HashMap::new();
        metadata.insert("arch_count".to_string(), slices.len().to_string());
        if let Some(s) = slices.first() {
            metadata.insert("primary_arch".to_string(), s.arch.to_string());
        }

        Ok(LoadedBinary {
            name: name.into(),
            slices,
            metadata,
            data: arc_data,
        })
    }

    fn apply_policy(&self, mut probes: Vec<Probe>) -> Result<Vec<Probe>, MultiArchError> {
        match &self.policy {
            LoaderPolicy::LoadAll => Ok(probes),
            LoaderPolicy::Auto => {
                let best = probes
                    .into_iter()
                    .max_by(|a, b| {
                        a.confidence
                            .partial_cmp(&b.confidence)
                            .unwrap_or(std::cmp::Ordering::Equal)
                    })
                    .map(|p| vec![p])
                    .unwrap_or_default();
                Ok(best)
            }
            LoaderPolicy::Prefer64Bit => {
                // Try to find a 64-bit variant first
                if probes.iter().any(|p| p.arch.is_64bit()) {
                    probes.retain(|p| p.arch.is_64bit());
                }
                let best = probes
                    .into_iter()
                    .max_by(|a, b| {
                        a.confidence
                            .partial_cmp(&b.confidence)
                            .unwrap_or(std::cmp::Ordering::Equal)
                    })
                    .map(|p| vec![p])
                    .unwrap_or_default();
                Ok(best)
            }
            LoaderPolicy::Prefer32Bit => {
                if probes.iter().any(|p| !p.arch.is_64bit()) {
                    probes.retain(|p| !p.arch.is_64bit());
                }
                let best = probes
                    .into_iter()
                    .max_by(|a, b| {
                        a.confidence
                            .partial_cmp(&b.confidence)
                            .unwrap_or(std::cmp::Ordering::Equal)
                    })
                    .map(|p| vec![p])
                    .unwrap_or_default();
                Ok(best)
            }
            LoaderPolicy::Strict(required) => {
                probes.retain(|p| p.arch == *required);
                if probes.is_empty() {
                    return Err(MultiArchError::PolicyRejected {
                        reason: format!("strict policy requires {required:?}"),
                    });
                }
                probes.truncate(1);
                Ok(probes)
            }
        }
    }

    /// Returns the current [`LoaderPolicy`].
    #[must_use]
    pub const fn policy(&self) -> &LoaderPolicy {
        &self.policy
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── helpers ──────────────────────────────────────────────────────────────

    fn make_elf64_x86_64(entry: u64) -> Vec<u8> {
        let mut b = vec![0u8; 0x40];
        b[0..4].copy_from_slice(b"\x7fELF");
        b[4] = 2; // class 64
        b[5] = 1; // little-endian
        b[6] = 1; // version
        b[0x12..0x14].copy_from_slice(&0x3Eu16.to_le_bytes()); // x86-64
        b[0x18..0x20].copy_from_slice(&entry.to_le_bytes());
        b
    }

    fn make_elf32_arm(entry: u32) -> Vec<u8> {
        let mut b = vec![0u8; 0x40];
        b[0..4].copy_from_slice(b"\x7fELF");
        b[4] = 1; // class 32
        b[5] = 1; // little-endian
        b[6] = 1;
        b[0x12..0x14].copy_from_slice(&0x28u16.to_le_bytes()); // ARM
        b[0x18..0x1C].copy_from_slice(&entry.to_le_bytes());
        b
    }

    fn make_pe32_x86(base: u32, entry: u32) -> Vec<u8> {
        let mut b = vec![0u8; 0x200];
        b[0..2].copy_from_slice(b"MZ");
        let pe_off: u32 = 0x80;
        b[0x3C..0x40].copy_from_slice(&pe_off.to_le_bytes());
        let p = pe_off as usize;
        b[p..p + 4].copy_from_slice(b"PE\0\0");
        b[p + 4..p + 6].copy_from_slice(&0x014Cu16.to_le_bytes()); // IMAGE_FILE_MACHINE_I386
        let opt = p + 24;
        b[opt..opt + 2].copy_from_slice(&0x010Bu16.to_le_bytes()); // PE32
        b[opt + 16..opt + 20].copy_from_slice(&entry.to_le_bytes());
        b[opt + 28..opt + 32].copy_from_slice(&base.to_le_bytes());
        b
    }

    fn make_pe64_x64(base: u64, entry: u32) -> Vec<u8> {
        let mut b = vec![0u8; 0x200];
        b[0..2].copy_from_slice(b"MZ");
        let pe_off: u32 = 0x80;
        b[0x3C..0x40].copy_from_slice(&pe_off.to_le_bytes());
        let p = pe_off as usize;
        b[p..p + 4].copy_from_slice(b"PE\0\0");
        b[p + 4..p + 6].copy_from_slice(&0x8664u16.to_le_bytes()); // x64
        let opt = p + 24;
        b[opt..opt + 2].copy_from_slice(&0x020Bu16.to_le_bytes()); // PE32+
        b[opt + 16..opt + 20].copy_from_slice(&entry.to_le_bytes());
        b[opt + 24..opt + 32].copy_from_slice(&base.to_le_bytes());
        b
    }

    // ── ArchVariant tests ────────────────────────────────────────────────────

    #[test]
    fn arch_variant_x64_is_64bit() {
        assert!(ArchVariant::X64.is_64bit());
    }

    #[test]
    fn arch_variant_x86_is_not_64bit() {
        assert!(!ArchVariant::X86.is_64bit());
    }

    #[test]
    fn arch_variant_arm64_is_64bit() {
        assert!(ArchVariant::Arm64.is_64bit());
    }

    #[test]
    fn arch_variant_arm_is_32bit() {
        assert!(!ArchVariant::Arm.is_64bit());
    }

    #[test]
    fn arch_variant_pointer_width_64() {
        assert_eq!(ArchVariant::X64.pointer_width(), 64);
    }

    #[test]
    fn arch_variant_pointer_width_32() {
        assert_eq!(ArchVariant::X86.pointer_width(), 32);
    }

    #[test]
    fn arch_variant_name_x86_64() {
        assert_eq!(ArchVariant::X64.name(), "x86_64");
    }

    #[test]
    fn arch_variant_display() {
        assert_eq!(format!("{}", ArchVariant::Arm), "arm");
    }

    #[test]
    fn arch_variant_riscv_name() {
        assert_eq!(ArchVariant::RiscV.name(), "riscv");
    }

    #[test]
    fn arch_variant_unknown_name() {
        assert_eq!(ArchVariant::Unknown.name(), "unknown");
    }

    // ── EntryPointList tests ─────────────────────────────────────────────────

    #[test]
    fn entry_point_list_new() {
        let e = EntryPointList::new(0x1000);
        assert_eq!(e.primary, Some(0x1000));
        assert!(e.additional.is_empty());
    }

    #[test]
    fn entry_point_list_push() {
        let mut e = EntryPointList::new(0x1000);
        e.push(0x2000);
        assert_eq!(e.additional, vec![0x2000]);
    }

    #[test]
    fn entry_point_list_all() {
        let mut e = EntryPointList::new(0x1000);
        e.push(0x2000);
        assert_eq!(e.all(), vec![0x1000, 0x2000]);
    }

    #[test]
    fn entry_point_list_empty_default() {
        let e = EntryPointList::default();
        assert!(e.is_empty());
    }

    #[test]
    fn entry_point_list_not_empty_after_new() {
        let e = EntryPointList::new(0x0);
        assert!(!e.is_empty());
    }

    // ── LoaderPolicy tests ───────────────────────────────────────────────────

    #[test]
    fn loader_policy_default_is_auto() {
        assert_eq!(LoaderPolicy::default(), LoaderPolicy::Auto);
    }

    // ── MultiArchLoader construction ─────────────────────────────────────────

    #[test]
    fn loader_default_policy_is_auto() {
        let loader = MultiArchLoader::default();
        assert_eq!(loader.policy(), &LoaderPolicy::Auto);
    }

    #[test]
    fn loader_with_min_confidence_clamps() {
        let loader = MultiArchLoader::new(LoaderPolicy::Auto).with_min_confidence(2.0);
        assert_eq!(loader.min_confidence, 1.0);
    }

    #[test]
    fn loader_with_min_confidence_negative_clamps() {
        let loader = MultiArchLoader::new(LoaderPolicy::Auto).with_min_confidence(-1.0);
        assert_eq!(loader.min_confidence, 0.0);
    }

    // ── ELF probing ──────────────────────────────────────────────────────────

    #[test]
    fn load_elf64_x86_64_success() {
        let data = make_elf64_x86_64(0x4000);
        let loader = MultiArchLoader::default();
        let bin = loader.load("test.elf", data).unwrap();
        assert_eq!(bin.slices.len(), 1);
        assert_eq!(bin.slices[0].arch, ArchVariant::X64);
    }

    #[test]
    fn load_elf64_entry_point() {
        let data = make_elf64_x86_64(0xDEAD_BEEF);
        let loader = MultiArchLoader::default();
        let bin = loader.load("test.elf", data).unwrap();
        assert_eq!(bin.slices[0].entry_points.primary, Some(0xDEAD_BEEF));
    }

    #[test]
    fn load_elf32_arm() {
        let data = make_elf32_arm(0x8000);
        let loader = MultiArchLoader::default();
        let bin = loader.load("arm.elf", data).unwrap();
        assert_eq!(bin.slices[0].arch, ArchVariant::Arm);
    }

    #[test]
    fn load_elf_format_tag() {
        let data = make_elf64_x86_64(0);
        let loader = MultiArchLoader::default();
        let bin = loader.load("t", data).unwrap();
        assert!(bin.slices[0].format_tag.contains("ELF"));
    }

    // ── PE probing ───────────────────────────────────────────────────────────

    #[test]
    fn load_pe32_x86() {
        let data = make_pe32_x86(0x0040_0000, 0x1000);
        let loader = MultiArchLoader::default();
        let bin = loader.load("test.exe", data).unwrap();
        assert_eq!(bin.slices[0].arch, ArchVariant::X86);
    }

    #[test]
    fn load_pe64_x64() {
        let data = make_pe64_x64(0x1_4000_0000, 0x1000);
        let loader = MultiArchLoader::default();
        let bin = loader.load("test64.exe", data).unwrap();
        assert_eq!(bin.slices[0].arch, ArchVariant::X64);
    }

    #[test]
    fn load_pe64_image_base() {
        let base = 0x1_4000_0000u64;
        let data = make_pe64_x64(base, 0x1000);
        let loader = MultiArchLoader::default();
        let bin = loader.load("t", data).unwrap();
        assert_eq!(bin.slices[0].image_base, base);
    }

    #[test]
    fn load_pe_format_tag() {
        let data = make_pe32_x86(0x0040_0000, 0);
        let loader = MultiArchLoader::default();
        let bin = loader.load("t", data).unwrap();
        assert_eq!(bin.slices[0].format_tag, "PE");
    }

    // ── Policy tests ─────────────────────────────────────────────────────────

    #[test]
    fn policy_prefer_64bit_selects_x64_over_x86() {
        // Two probes: x86 + x64; policy should return x64
        let data = make_pe64_x64(0x1_4000_0000, 0x1000);
        let loader = MultiArchLoader::new(LoaderPolicy::Prefer64Bit);
        let bin = loader.load("t", data).unwrap();
        assert!(bin.slices[0].arch.is_64bit());
    }

    #[test]
    fn policy_prefer_32bit_on_32bit_binary() {
        let data = make_pe32_x86(0x0040_0000, 0x1000);
        let loader = MultiArchLoader::new(LoaderPolicy::Prefer32Bit);
        let bin = loader.load("t", data).unwrap();
        assert!(!bin.slices[0].arch.is_64bit());
    }

    #[test]
    fn policy_strict_matching_arch() {
        let data = make_elf64_x86_64(0);
        let loader = MultiArchLoader::new(LoaderPolicy::Strict(ArchVariant::X64));
        let bin = loader.load("t", data).unwrap();
        assert_eq!(bin.slices[0].arch, ArchVariant::X64);
    }

    #[test]
    fn policy_strict_wrong_arch_errors() {
        let data = make_elf64_x86_64(0);
        let loader = MultiArchLoader::new(LoaderPolicy::Strict(ArchVariant::Arm));
        let result = loader.load("t", data);
        assert!(result.is_err());
    }

    // ── Error paths ──────────────────────────────────────────────────────────

    #[test]
    fn error_too_short() {
        let loader = MultiArchLoader::default();
        let err = loader.load("tiny", vec![0xAAu8, 0xBB]).unwrap_err();
        assert!(matches!(err, MultiArchError::TooShort(_)));
    }

    #[test]
    fn error_unrecognised_arch() {
        let loader = MultiArchLoader::default();
        let err = loader.load("junk", vec![0x00u8; 64]).unwrap_err();
        assert!(matches!(err, MultiArchError::UnrecognisedArch));
    }

    // ── LoadedBinary helpers ─────────────────────────────────────────────────

    #[test]
    fn loaded_binary_raw_size() {
        let data = make_elf64_x86_64(0);
        let len = data.len();
        let loader = MultiArchLoader::default();
        let bin = loader.load("t", data).unwrap();
        assert_eq!(bin.raw_size(), len);
    }

    #[test]
    fn loaded_binary_primary_slice() {
        let data = make_elf64_x86_64(0);
        let loader = MultiArchLoader::default();
        let bin = loader.load("t", data).unwrap();
        assert!(bin.primary_slice().is_some());
    }

    #[test]
    fn loaded_binary_slices_for_match() {
        let data = make_pe64_x64(0x1_4000_0000, 0x1000);
        let loader = MultiArchLoader::default();
        let bin = loader.load("t", data).unwrap();
        let matched = bin.slices_for(ArchVariant::X64);
        assert_eq!(matched.len(), 1);
    }

    #[test]
    fn loaded_binary_slices_for_no_match() {
        let data = make_elf64_x86_64(0);
        let loader = MultiArchLoader::default();
        let bin = loader.load("t", data).unwrap();
        let matched = bin.slices_for(ArchVariant::Mips);
        assert!(matched.is_empty());
    }

    #[test]
    fn loaded_binary_metadata_arch_count() {
        let data = make_elf32_arm(0);
        let loader = MultiArchLoader::default();
        let bin = loader.load("t", data).unwrap();
        assert_eq!(bin.metadata.get("arch_count").unwrap(), "1");
    }

    // ── BinarySlice helpers ──────────────────────────────────────────────────

    #[test]
    fn binary_slice_read_u32_le() {
        let data = make_elf64_x86_64(0x1234_5678_9ABC_DEF0);
        let loader = MultiArchLoader::default();
        let bin = loader.load("t", data).unwrap();
        let slice = &bin.slices[0];
        // ELF magic as u32 LE = 0x464C457F
        let magic = slice.read_u32_le(0).unwrap();
        assert_eq!(magic, 0x464C_457F);
    }

    #[test]
    fn binary_slice_read_u64_le() {
        let data = make_elf64_x86_64(0x1122_3344_5566_7788);
        let loader = MultiArchLoader::default();
        let bin = loader.load("t", data).unwrap();
        let slice = &bin.slices[0];
        let entry = slice.read_u64_le(0x18).unwrap();
        assert_eq!(entry, 0x1122_3344_5566_7788);
    }

    #[test]
    fn binary_slice_read_out_of_bounds_is_none() {
        let data = make_elf64_x86_64(0);
        let loader = MultiArchLoader::default();
        let bin = loader.load("t", data).unwrap();
        let slice = &bin.slices[0];
        assert!(slice.read_u64_le(slice.length).is_none());
    }

    #[test]
    fn binary_slice_bytes_length_correct() {
        let data = make_elf64_x86_64(0);
        let expected_len = data.len();
        let loader = MultiArchLoader::default();
        let bin = loader.load("t", data).unwrap();
        assert_eq!(bin.slices[0].bytes().len(), expected_len);
    }

    #[test]
    fn loaded_binary_name_preserved() {
        let data = make_elf64_x86_64(0);
        let loader = MultiArchLoader::default();
        let bin = loader.load("my_binary.elf", data).unwrap();
        assert_eq!(bin.name, "my_binary.elf");
    }
}
