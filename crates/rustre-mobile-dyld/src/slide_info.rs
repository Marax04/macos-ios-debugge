//! `slide_info` — ASLR slide-fixup data for dyld shared caches.
//!
//! The dyld shared cache uses compact slide-info structures to describe which
//! pointer-sized locations inside each cache mapping need to be adjusted by the
//! ASLR slide when the cache is loaded at a non-default address.
//!
//! Four versions of the slide-info format exist:
//!
//! | Version | Introduced | Notes |
//! |---------|------------|-------|
//! | 1 | iOS 4 / macOS 10.6 | Toc + Entries bitmaps |
//! | 2 | iOS 8 / macOS 10.10 | Page starts + extras |
//! | 3 | iOS 12 / macOS 10.14 | Chained fixups (arm64e) |
//! | 4 | iOS 8 / macOS 10.10 | Page starts + 32-bit delta chains |
//!
//! This module parses the on-disk representation and provides an
//! `apply_slide_fixups()` function that patches a mutable buffer.

use super::DyldError;

// ─────────────────────────────────────────────────────────────────────────────
// Version 1 constants
// ─────────────────────────────────────────────────────────────────────────────

/// Size of a V1 toc entry (16-bit index into the entries array).
pub const SLIDE_V1_TOC_ENTRY_SIZE: usize = 2;
/// Byte size of a V1 entries bitfield.
pub const SLIDE_V1_ENTRIES_SIZE: usize = 8;
/// Number of bits (pointer slots) per V1 entries entry.
pub const SLIDE_V1_ENTRIES_BITS: usize = 8 * SLIDE_V1_ENTRIES_SIZE;
/// Pointer granularity for V1 (32-bit: 4 bytes, 64-bit: 8 bytes).
pub const SLIDE_V1_PTR_SIZE_32: usize = 4;
pub const SLIDE_V1_PTR_SIZE_64: usize = 8;

// ─────────────────────────────────────────────────────────────────────────────
// Version 2 / 4 constants
// ─────────────────────────────────────────────────────────────────────────────

/// Sentinel value in V2 page-starts meaning the page has no fixups.
pub const SLIDE_V2_PAGE_NO_REBASE: u16 = 0xFFFF;
/// Sentinel value in V2 page-starts meaning the page uses EXTRA entries.
pub const SLIDE_V2_PAGE_USE_EXTRA: u16 = 0xFFFE;
/// Bit in V2 extra entries: more entries follow this one.
pub const SLIDE_V2_EXTRA_END: u16 = 0x8000;
/// Offset mask in V2 delta chain entries.
pub const SLIDE_V2_DELTA_MASK_DEFAULT: u64 = 0x00FF_FF00_0000_0000;
/// Value mask in V2 delta chain entries.
pub const SLIDE_V2_VALUE_MASK_DEFAULT: u64 = 0x0000_00FF_FFFF_FFFF;

// ─────────────────────────────────────────────────────────────────────────────
// Version 3 constants (arm64e chained fixups)
// ─────────────────────────────────────────────────────────────────────────────

pub const SLIDE_V3_PAGE_NO_REBASE: u16 = 0xFFFF;
/// High bit in a v3 pointer that indicates it is an authenticated pointer.
pub const SLIDE_V3_AUTH_BIT: u64 = 1 << 63;
/// Bit indicating the pointer is a rebase (not a bind).
pub const SLIDE_V3_REBASE_BIT: u64 = 1 << 62;

// ─────────────────────────────────────────────────────────────────────────────
// SlideInfo enum
// ─────────────────────────────────────────────────────────────────────────────

/// Parsed slide-info blob, covering all four known versions.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub enum SlideInfo {
    V1(SlideInfoV1),
    V2(SlideInfoV2),
    V3(SlideInfoV3),
    V4(SlideInfoV4),
}

impl SlideInfo {
    /// Parse a slide-info blob.  The version is determined by the first 4 bytes.
    pub fn parse(data: &[u8]) -> Result<Self, DyldError> {
        if data.len() < 4 {
            return Err(DyldError::Truncated(0));
        }
        let version = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
        match version {
            1 => Ok(Self::V1(SlideInfoV1::parse(data)?)),
            2 => Ok(Self::V2(SlideInfoV2::parse(data)?)),
            3 => Ok(Self::V3(SlideInfoV3::parse(data)?)),
            4 => Ok(Self::V4(SlideInfoV4::parse(data)?)),
            v => Err(DyldError::Parse(format!("unknown slide-info version {v}"))),
        }
    }

    /// Return the version number.
    #[must_use]
    pub const fn version(&self) -> u32 {
        match self {
            Self::V1(_) => 1,
            Self::V2(_) => 2,
            Self::V3(_) => 3,
            Self::V4(_) => 4,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Version 1
// ─────────────────────────────────────────────────────────────────────────────

/// Parsed `dyld_cache_slide_info` (version 1).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SlideInfoV1 {
    pub version: u32,
    pub toc_offset: u32,
    pub toc_count: u32,
    pub entries_offset: u32,
    pub entries_count: u32,
    pub entries_size: u32,
    /// Raw toc array (each entry is a 16-bit index).
    pub toc: Vec<u16>,
    /// Raw entries array (each entry is `entries_size` bytes).
    pub entries: Vec<Vec<u8>>,
}

impl SlideInfoV1 {
    pub fn parse(data: &[u8]) -> Result<Self, DyldError> {
        if data.len() < 24 {
            return Err(DyldError::Truncated(0));
        }
        let version = read_u32(data, 0)?;
        let toc_offset = read_u32(data, 4)?;
        let toc_count = read_u32(data, 8)?;
        let entries_offset = read_u32(data, 12)?;
        let entries_count = read_u32(data, 16)?;
        let entries_size = read_u32(data, 20)?;

        // Parse TOC
        let toc_start = toc_offset as usize;
        let toc_count_capped = (toc_count as usize).min(data.len() / 2 + 1);
        let mut toc = Vec::with_capacity(toc_count_capped);
        for i in 0..toc_count as usize {
            let off = toc_start.saturating_add(i.saturating_mul(2));
            toc.push(read_u16(data, off)?);
        }

        // Parse entries
        if entries_size == 0 {
            return Err(DyldError::Parse("V1 entries_size is zero".into()));
        }
        let entries_start = entries_offset as usize;
        let es = entries_size as usize;
        let entries_count_capped = (entries_count as usize).min(data.len() / es + 1);
        let mut entries = Vec::with_capacity(entries_count_capped);
        for i in 0..entries_count as usize {
            let off = entries_start.saturating_add(i.saturating_mul(es));
            if off + es > data.len() {
                return Err(DyldError::Truncated(off));
            }
            entries.push(data[off..off + es].to_vec());
        }

        Ok(Self {
            version,
            toc_offset,
            toc_count,
            entries_offset,
            entries_count,
            entries_size,
            toc,
            entries,
        })
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Version 2
// ─────────────────────────────────────────────────────────────────────────────

/// Parsed `dyld_cache_slide_info2` (version 2).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SlideInfoV2 {
    pub version: u32,
    pub page_size: u32,
    pub page_starts_offset: u32,
    pub page_starts_count: u32,
    pub page_extras_offset: u32,
    pub page_extras_count: u32,
    pub delta_mask: u64,
    pub value_add: u64,
    pub page_starts: Vec<u16>,
    pub page_extras: Vec<u16>,
}

impl SlideInfoV2 {
    pub fn parse(data: &[u8]) -> Result<Self, DyldError> {
        if data.len() < 40 {
            return Err(DyldError::Truncated(0));
        }
        let version = read_u32(data, 0)?;
        let page_size = read_u32(data, 4)?;
        let page_starts_offset = read_u32(data, 8)?;
        let page_starts_count = read_u32(data, 12)?;
        let page_extras_offset = read_u32(data, 16)?;
        let page_extras_count = read_u32(data, 20)?;
        let delta_mask = read_u64(data, 24)?;
        let value_add = read_u64(data, 32)?;

        let ps_off = page_starts_offset as usize;
        let mut page_starts = Vec::with_capacity(page_starts_count as usize);
        for i in 0..page_starts_count as usize {
            page_starts.push(read_u16(data, ps_off + i * 2)?);
        }

        let pe_off = page_extras_offset as usize;
        let mut page_extras = Vec::with_capacity(page_extras_count as usize);
        for i in 0..page_extras_count as usize {
            page_extras.push(read_u16(data, pe_off + i * 2)?);
        }

        Ok(Self {
            version,
            page_size,
            page_starts_offset,
            page_starts_count,
            page_extras_offset,
            page_extras_count,
            delta_mask,
            value_add,
            page_starts,
            page_extras,
        })
    }

    /// Bit-shift count to extract the delta from an encoded pointer.
    #[must_use]
    pub const fn delta_shift(&self) -> u32 {
        self.delta_mask.trailing_zeros()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Version 3
// ─────────────────────────────────────────────────────────────────────────────

/// Parsed `dyld_cache_slide_info3` (version 3, arm64e chained fixups).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SlideInfoV3 {
    pub version: u32,
    pub page_size: u32,
    pub page_starts_count: u32,
    pub auth_value_add: u64,
    pub page_starts: Vec<u16>,
}

impl SlideInfoV3 {
    pub fn parse(data: &[u8]) -> Result<Self, DyldError> {
        if data.len() < 20 {
            return Err(DyldError::Truncated(0));
        }
        let version = read_u32(data, 0)?;
        let page_size = read_u32(data, 4)?;
        let page_starts_count = read_u32(data, 8)?;
        // 4-byte pad at offset 12
        let auth_value_add = read_u64(data, 16)?;

        // page_starts array immediately follows the fixed header (24 bytes).
        let starts_off = 24usize;
        let mut page_starts = Vec::with_capacity(page_starts_count as usize);
        for i in 0..page_starts_count as usize {
            page_starts.push(read_u16(data, starts_off + i * 2)?);
        }

        Ok(Self {
            version,
            page_size,
            page_starts_count,
            auth_value_add,
            page_starts,
        })
    }
}

/// A decoded arm64e chained-fixup pointer (V3).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Arm64eChainedPtr {
    /// Decoded virtual address (after stripping PAC bits and applying slide).
    pub target_va: u64,
    /// Whether the pointer is an authenticated pointer.
    pub is_auth: bool,
    /// PAC key index (0=IA, 1=IB, 2=DA, 3=DB) — valid when `is_auth` is true.
    pub key: u8,
    /// Whether the discriminator is blended with the address diversification bit.
    pub addr_diversity: bool,
    /// 16-bit discriminator value.
    pub discriminator: u16,
}

impl Arm64eChainedPtr {
    /// Decode a raw 64-bit value from a V3 chained-fixup chain.
    ///
    /// `value_add` is the `auth_value_add` field from `SlideInfoV3`.
    /// `slide` is the current ASLR slide.
    #[must_use]
    pub const fn decode(raw: u64, value_add: u64, slide: u64) -> Self {
        let is_auth = raw & SLIDE_V3_AUTH_BIT != 0;
        if is_auth {
            // Auth pointer layout: [63]=1, [62:0] = auth fields + delta.
            let key = ((raw >> 49) & 0x3) as u8;
            let addr_diversity = (raw >> 48) & 1 != 0;
            let discriminator = (raw >> 32) as u16;
            // The target value is in bits [31:0] + value_add + slide.
            let target_va = (raw & 0xFFFF_FFFF)
                .wrapping_add(value_add)
                .wrapping_add(slide);
            Self {
                target_va,
                is_auth,
                key,
                addr_diversity,
                discriminator,
            }
        } else {
            // Rebase pointer: bits [61:0] = high8 (bits 55:48) + low32 (bits 31:0).
            let high8 = (raw >> 56) & 0xFF;
            let low32 = raw & 0xFFFF_FFFF;
            let target_va = ((high8 << 56) | low32).wrapping_add(slide);
            Self {
                target_va,
                is_auth: false,
                key: 0,
                addr_diversity: false,
                discriminator: 0,
            }
        }
    }

    /// PAC key name.
    #[must_use]
    pub const fn key_name(&self) -> &'static str {
        match self.key {
            0 => "IA",
            1 => "IB",
            2 => "DA",
            3 => "DB",
            _ => "?",
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Version 4
// ─────────────────────────────────────────────────────────────────────────────

/// Parsed `dyld_cache_slide_info4` (version 4, 32-bit pointer chains).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SlideInfoV4 {
    pub version: u32,
    pub page_size: u32,
    pub page_starts_offset: u32,
    pub page_starts_count: u32,
    pub page_extras_offset: u32,
    pub page_extras_count: u32,
    pub delta_mask: u64,
    pub value_add: u64,
    pub page_starts: Vec<u16>,
    pub page_extras: Vec<u16>,
}

impl SlideInfoV4 {
    pub fn parse(data: &[u8]) -> Result<Self, DyldError> {
        // V4 has the same layout as V2 — just a different version tag.
        let v2 = SlideInfoV2::parse(data)?;
        Ok(Self {
            version: v2.version,
            page_size: v2.page_size,
            page_starts_offset: v2.page_starts_offset,
            page_starts_count: v2.page_starts_count,
            page_extras_offset: v2.page_extras_offset,
            page_extras_count: v2.page_extras_count,
            delta_mask: v2.delta_mask,
            value_add: v2.value_add,
            page_starts: v2.page_starts,
            page_extras: v2.page_extras,
        })
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// apply_slide_fixups
// ─────────────────────────────────────────────────────────────────────────────

/// Apply all slide fixups in `slide_info` to the mutable `mapping_data` buffer.
///
/// `slide` is the delta between the default load address and the actual load
/// address (typically discovered at runtime; pass 0 for a static analysis
/// context that wants the on-cache rebased values).
///
/// `mapping_preferred_va` is the preferred virtual address of the start of the
/// mapping (used for V3 chain decoding).
pub fn apply_slide_fixups(
    mapping_data: &mut [u8],
    slide_info: &SlideInfo,
    slide: u64,
    mapping_preferred_va: u64,
) -> Result<usize, DyldError> {
    match slide_info {
        SlideInfo::V1(v1) => apply_v1(mapping_data, v1, slide),
        SlideInfo::V2(v2) => apply_v2(mapping_data, v2, slide),
        SlideInfo::V3(v3) => apply_v3(mapping_data, v3, slide, mapping_preferred_va),
        SlideInfo::V4(v4) => apply_v4(mapping_data, v4, slide),
    }
}

// ─── V1 ──────────────────────────────────────────────────────────────────────

fn apply_v1(data: &mut [u8], v1: &SlideInfoV1, slide: u64) -> Result<usize, DyldError> {
    let page_size = 4096usize; // V1 always uses 4 KiB pages.
    let mut count = 0usize;

    for (page_idx, &toc_entry) in v1.toc.iter().enumerate() {
        let entry_idx = toc_entry as usize;
        if entry_idx >= v1.entries.len() {
            return Err(DyldError::SlideFixup(format!(
                "V1 toc[{}]={} out of range (entries.len={})",
                page_idx,
                entry_idx,
                v1.entries.len()
            )));
        }
        let entry = &v1.entries[entry_idx];
        let page_base = page_idx * page_size;

        // Each bit in the entry represents one pointer slot in the page.
        for byte_idx in 0..entry.len() {
            let mut bits = entry[byte_idx];
            while bits != 0 {
                let bit = bits.trailing_zeros() as usize;
                let ptr_offset = page_base + (byte_idx * 8 + bit) * SLIDE_V1_PTR_SIZE_64;
                if ptr_offset + 8 > data.len() {
                    return Err(DyldError::SlideFixup(format!(
                        "V1 pointer at {ptr_offset:#x} exceeds mapping"
                    )));
                }
                let old = read_u64_from(data, ptr_offset);
                let new = old.wrapping_add(slide);
                data[ptr_offset..ptr_offset + 8].copy_from_slice(&new.to_le_bytes());
                count += 1;
                bits &= bits - 1; // clear lowest set bit
            }
        }
    }
    Ok(count)
}

// ─── V2 ──────────────────────────────────────────────────────────────────────

fn apply_v2(data: &mut [u8], v2: &SlideInfoV2, slide: u64) -> Result<usize, DyldError> {
    let page_size = v2.page_size as usize;
    let delta_mask = v2.delta_mask;
    let delta_shift = v2.delta_shift();
    let value_mask = !delta_mask & !0x3; // clear delta and tag bits
    let mut count = 0usize;

    for (page_idx, &start) in v2.page_starts.iter().enumerate() {
        if start == SLIDE_V2_PAGE_NO_REBASE {
            continue;
        }
        let page_base = page_idx * page_size;

        let starts: Vec<u16> = if start == SLIDE_V2_PAGE_USE_EXTRA {
            // Collect extra entries for this page.
            let extra_idx = (start & !SLIDE_V2_PAGE_USE_EXTRA) as usize;
            if extra_idx >= v2.page_extras.len() {
                continue;
            }
            let mut extras = Vec::new();
            let mut ei = extra_idx;
            loop {
                if ei >= v2.page_extras.len() {
                    break;
                }
                let e = v2.page_extras[ei];
                extras.push(e & !SLIDE_V2_EXTRA_END);
                if e & SLIDE_V2_EXTRA_END != 0 {
                    break;
                }
                ei += 1;
            }
            extras
        } else {
            vec![start]
        };

        for chain_start in starts {
            let mut ptr_off = page_base + chain_start as usize;
            loop {
                if ptr_off + 8 > data.len() {
                    break;
                }
                let raw = read_u64_from(data, ptr_off);
                let delta = (raw & delta_mask) >> delta_shift;
                let new_val = (raw & value_mask).wrapping_add(v2.value_add).wrapping_add(slide);
                data[ptr_off..ptr_off + 8].copy_from_slice(&new_val.to_le_bytes());
                count += 1;
                if delta == 0 {
                    break;
                }
                ptr_off = match (delta as usize).checked_mul(4).and_then(|d| ptr_off.checked_add(d)) {
                    Some(v) => v,
                    None => break,
                };
            }
        }
    }
    Ok(count)
}

// ─── V3 ──────────────────────────────────────────────────────────────────────

fn apply_v3(
    data: &mut [u8],
    v3: &SlideInfoV3,
    slide: u64,
    _mapping_preferred_va: u64,
) -> Result<usize, DyldError> {
    let page_size = v3.page_size as usize;
    let value_add = v3.auth_value_add;
    let mut count = 0usize;

    for (page_idx, &start) in v3.page_starts.iter().enumerate() {
        if start == SLIDE_V3_PAGE_NO_REBASE {
            continue;
        }
        let page_base = page_idx * page_size;
        let mut ptr_off = page_base + start as usize;

        loop {
            if ptr_off + 8 > data.len() {
                break;
            }
            let raw = read_u64_from(data, ptr_off);
            // Extract next-delta from bits [51:32].
            let delta = (raw >> 32) & 0x7FFFF;

            let decoded = Arm64eChainedPtr::decode(raw, value_add, slide);
            data[ptr_off..ptr_off + 8].copy_from_slice(&decoded.target_va.to_le_bytes());
            count += 1;

            if delta == 0 {
                break;
            }
            ptr_off = match (delta as usize).checked_mul(8).and_then(|d| ptr_off.checked_add(d)) {
                Some(v) => v,
                None => break,
            };
        }
    }
    Ok(count)
}

// ─── V4 ──────────────────────────────────────────────────────────────────────

fn apply_v4(data: &mut [u8], v4: &SlideInfoV4, slide: u64) -> Result<usize, DyldError> {
    // V4 uses 32-bit pointers (watchOS/armv7k).
    let page_size = v4.page_size as usize;
    let delta_mask = v4.delta_mask as u32;
    let delta_shift = (v4.delta_mask as u32).trailing_zeros();
    let value_mask = !delta_mask & !0x1u32;
    let value_add = v4.value_add as u32;
    let mut count = 0usize;

    for (page_idx, &start) in v4.page_starts.iter().enumerate() {
        if start == SLIDE_V2_PAGE_NO_REBASE {
            continue;
        }
        let page_base = page_idx * page_size;
        let mut ptr_off = page_base + start as usize;

        loop {
            if ptr_off + 4 > data.len() {
                break;
            }
            let raw = read_u32_from(data, ptr_off);
            let delta = (raw & delta_mask) >> delta_shift;
            let new_val = (raw & value_mask)
                .wrapping_add(value_add)
                .wrapping_add(slide as u32);
            data[ptr_off..ptr_off + 4].copy_from_slice(&new_val.to_le_bytes());
            count += 1;
            if delta == 0 {
                break;
            }
            ptr_off = match (delta as usize).checked_mul(4).and_then(|d| ptr_off.checked_add(d)) {
                Some(v) => v,
                None => break,
            };
        }
    }
    Ok(count)
}

// ─────────────────────────────────────────────────────────────────────────────
// Slide fixup statistics
// ─────────────────────────────────────────────────────────────────────────────

/// Summary statistics about a slide-fixup pass.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SlideFixupStats {
    pub version: u32,
    pub pages_processed: usize,
    pub pointers_fixed: usize,
    pub slide_applied: u64,
}

impl SlideFixupStats {
    #[must_use]
    pub const fn new(version: u32, pages: usize, pointers: usize, slide: u64) -> Self {
        Self {
            version,
            pages_processed: pages,
            pointers_fixed: pointers,
            slide_applied: slide,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

fn read_u16(data: &[u8], offset: usize) -> Result<u16, DyldError> {
    data.get(offset..offset + 2)
        .map(|s| u16::from_le_bytes([s[0], s[1]]))
        .ok_or(DyldError::Truncated(offset))
}

fn read_u32(data: &[u8], offset: usize) -> Result<u32, DyldError> {
    data.get(offset..offset + 4)
        .map(|s| u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
        .ok_or(DyldError::Truncated(offset))
}

fn read_u64(data: &[u8], offset: usize) -> Result<u64, DyldError> {
    data.get(offset..offset + 8)
        .map(|s| u64::from_le_bytes([s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7]]))
        .ok_or(DyldError::Truncated(offset))
}

fn read_u64_from(data: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes([
        data[offset],
        data[offset + 1],
        data[offset + 2],
        data[offset + 3],
        data[offset + 4],
        data[offset + 5],
        data[offset + 6],
        data[offset + 7],
    ])
}

fn read_u32_from(data: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes([
        data[offset],
        data[offset + 1],
        data[offset + 2],
        data[offset + 3],
    ])
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_v2_header(page_size: u32, page_starts: &[u16]) -> Vec<u8> {
        let ps_offset: u32 = 40;
        let mut data = vec![0u8; 40 + page_starts.len() * 2];
        // version=2
        data[0..4].copy_from_slice(&2u32.to_le_bytes());
        data[4..8].copy_from_slice(&page_size.to_le_bytes());
        // page_starts_offset = 40
        data[8..12].copy_from_slice(&ps_offset.to_le_bytes());
        data[12..16].copy_from_slice(&u32::try_from(page_starts.len()).unwrap_or(0).to_le_bytes());
        // page_extras_offset = ps_offset (no extras)
        data[16..20].copy_from_slice(&ps_offset.to_le_bytes());
        data[20..24].copy_from_slice(&0u32.to_le_bytes());
        // delta_mask: bits 32..47 → shift 32
        data[24..32].copy_from_slice(&0x00FF_FF00_0000_0000u64.to_le_bytes());
        // value_add = 0
        data[32..40].copy_from_slice(&0u64.to_le_bytes());
        // page_starts
        for (i, &ps) in page_starts.iter().enumerate() {
            let off = 40 + i * 2;
            data[off..off + 2].copy_from_slice(&ps.to_le_bytes());
        }
        data
    }

    #[test]
    fn test_parse_version_tag() {
        let data = make_v2_header(0x1000, &[SLIDE_V2_PAGE_NO_REBASE]);
        let si = SlideInfo::parse(&data).expect("parse");
        assert_eq!(si.version(), 2);
    }

    #[test]
    fn test_v2_no_rebase_pages() {
        let raw = make_v2_header(0x1000, &[SLIDE_V2_PAGE_NO_REBASE]);
        let si = SlideInfo::parse(&raw).expect("parse");
        let mut mapping = vec![0xAAu8; 0x1000];
        let count = apply_slide_fixups(&mut mapping, &si, 0x10000, 0x0001_8000_0000).expect("apply");
        assert_eq!(count, 0);
        // Data should be untouched.
        assert!(mapping.iter().all(|&b| b == 0xAA));
    }

    #[test]
    fn test_v3_no_rebase_pages() {
        // V3 minimal header with all pages = NO_REBASE.
        let mut data = vec![0u8; 24 + 2 * 4]; // 4 pages
        data[0..4].copy_from_slice(&3u32.to_le_bytes());
        data[4..8].copy_from_slice(&0x1000u32.to_le_bytes()); // page_size
        data[8..12].copy_from_slice(&4u32.to_le_bytes()); // page_starts_count
        // auth_value_add = 0
        data[16..24].copy_from_slice(&0u64.to_le_bytes());
        // All 4 page_starts = NO_REBASE
        for i in 0..4usize {
            let off = 24 + i * 2;
            data[off..off + 2].copy_from_slice(&SLIDE_V3_PAGE_NO_REBASE.to_le_bytes());
        }
        let si = SlideInfo::parse(&data).expect("parse");
        assert_eq!(si.version(), 3);
        let mut mapping = vec![0u8; 0x4000];
        let count = apply_slide_fixups(&mut mapping, &si, 0, 0).expect("apply");
        assert_eq!(count, 0);
    }

    #[test]
    fn test_arm64e_chained_ptr_rebase() {
        // Non-auth rebase: high8=0x01, low32=0x00000100
        let raw: u64 = (0x01u64 << 56) | 0x0000_0100;
        let decoded = Arm64eChainedPtr::decode(raw, 0, 0x10000);
        assert!(!decoded.is_auth);
        // target_va = (0x01<<56 | 0x100) + 0x10000
        assert_eq!(
            decoded.target_va,
            ((0x01u64 << 56) | 0x100u64).wrapping_add(0x10000)
        );
    }

    #[test]
    fn test_arm64e_chained_ptr_auth() {
        // Auth pointer: bit 63 set, key=0 (IA), addr_diversity=0, discriminator=0x1234, value=0xABCD
        let raw: u64 = SLIDE_V3_AUTH_BIT | (0x1234u64 << 32) | 0xABCD;
        let decoded = Arm64eChainedPtr::decode(raw, 0x1000, 0);
        assert!(decoded.is_auth);
        assert_eq!(decoded.key, 0);
        assert_eq!(decoded.discriminator, 0x1234);
        assert_eq!(decoded.target_va, 0xABCD_u64.wrapping_add(0x1000));
    }

    #[test]
    fn test_unknown_version_error() {
        let mut data = vec![0u8; 8];
        data[0..4].copy_from_slice(&99u32.to_le_bytes());
        let result = SlideInfo::parse(&data);
        assert!(result.is_err());
    }

    #[test]
    fn test_v1_parse() {
        // Minimal V1: 6 fields × 4 bytes = 24 bytes header, no toc, no entries.
        let mut data = vec![0u8; 24];
        data[0..4].copy_from_slice(&1u32.to_le_bytes()); // version
        data[4..8].copy_from_slice(&24u32.to_le_bytes()); // toc_offset
        data[8..12].copy_from_slice(&0u32.to_le_bytes()); // toc_count
        data[12..16].copy_from_slice(&24u32.to_le_bytes()); // entries_offset
        data[16..20].copy_from_slice(&0u32.to_le_bytes()); // entries_count
        data[20..24].copy_from_slice(&8u32.to_le_bytes()); // entries_size
        let si = SlideInfo::parse(&data).expect("parse");
        assert_eq!(si.version(), 1);
    }
}
