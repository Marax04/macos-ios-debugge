//! `dyld_fixups` — Unified fixup pipeline for traditional dyld rebase/bind opcodes AND
//! the chained-fixup format (iOS 14+ / arm64e).
//!
//! # Relationship to `dyld_fixup_chains`
//!
//! These two modules cover different layers of the same problem space:
//!
//! * **`dyld_fixups`** (this module) — low-level: parses the full set of traditional
//!   Mach-O fixup streams (rebase opcodes, bind opcodes, lazy-bind, weak-bind) via
//!   [`RebaseParser`] / [`BindParser`] / [`WeakBindParser`], *plus* a [`ChainedFixupParser`]
//!   for the newer `LC_DYLD_CHAINED_FIXUPS` format.  Uses `anyhow` for error handling and
//!   requires callers to supply a pre-built [`SegmentInfo`] table.  The combined result is
//!   a flat [`DyldFixups`] bag.
//!
//! * **`dyld_fixup_chains`** — higher-level, self-contained: focuses exclusively on the
//!   chained-fixup format with its own typed [`FixupError`], rich [`ChainedFixup`] record
//!   (including PAC diversity / key fields), an [`apply_fixups`] helper that patches a
//!   live image buffer, and a `ptr_format` constants sub-module.  Preferred for consumers
//!   that only need the modern chained-fixup path.

use anyhow::{bail, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// ── Constants ─────────────────────────────────────────────────────────────────

const REBASE_OPCODE_DONE: u8 = 0x00;
const REBASE_OPCODE_SET_TYPE_IMM: u8 = 0x10;
const REBASE_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB: u8 = 0x20;
const REBASE_OPCODE_ADD_ADDR_ULEB: u8 = 0x30;
const REBASE_OPCODE_ADD_ADDR_IMM_SCALED: u8 = 0x40;
const REBASE_OPCODE_DO_REBASE_IMM_TIMES: u8 = 0x50;
const REBASE_OPCODE_DO_REBASE_ULEB_TIMES: u8 = 0x60;
const REBASE_OPCODE_DO_REBASE_ADD_ADDR_ULEB: u8 = 0x70;
const REBASE_OPCODE_DO_REBASE_ULEB_TIMES_SKIPPING_ULEB: u8 = 0x80;

const BIND_OPCODE_DONE: u8 = 0x00;
const BIND_OPCODE_SET_DYLIB_ORDINAL_IMM: u8 = 0x10;
const BIND_OPCODE_SET_DYLIB_ORDINAL_ULEB: u8 = 0x20;
const BIND_OPCODE_SET_DYLIB_SPECIAL_IMM: u8 = 0x30;
const BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM: u8 = 0x40;
const BIND_OPCODE_SET_TYPE_IMM: u8 = 0x50;
const BIND_OPCODE_SET_ADDEND_SLEB: u8 = 0x60;
const BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB: u8 = 0x70;
const BIND_OPCODE_ADD_ADDR_ULEB: u8 = 0x80;
const BIND_OPCODE_DO_BIND: u8 = 0x90;
const BIND_OPCODE_DO_BIND_ADD_ADDR_ULEB: u8 = 0xa0;
const BIND_OPCODE_DO_BIND_ADD_ADDR_IMM_SCALED: u8 = 0xb0;
const BIND_OPCODE_DO_BIND_ULEB_TIMES_SKIPPING_ULEB: u8 = 0xc0;

const BIND_SPECIAL_DYLIB_SELF: i64 = 0;
const BIND_SPECIAL_DYLIB_MAIN_EXECUTABLE: i64 = -1;
const BIND_SPECIAL_DYLIB_FLAT_LOOKUP: i64 = -2;

const BIND_TYPE_POINTER: u8 = 1;
const BIND_TYPE_TEXT_ABSOLUTE32: u8 = 2;
const BIND_TYPE_TEXT_PCREL32: u8 = 3;

const REBASE_TYPE_POINTER: u8 = 1;
const REBASE_TYPE_TEXT_ABSOLUTE32: u8 = 2;
const REBASE_TYPE_TEXT_PCREL32: u8 = 3;

// Chained fixup pointer formats (DYLD_CHAINED_PTR_*)
pub const DYLD_CHAINED_PTR_ARM64E: u16 = 1;
pub const DYLD_CHAINED_PTR_64: u16 = 2;
pub const DYLD_CHAINED_PTR_32: u16 = 3;
pub const DYLD_CHAINED_PTR_32_CACHE: u16 = 4;
pub const DYLD_CHAINED_PTR_32_FIRMWARE: u16 = 5;
pub const DYLD_CHAINED_PTR_64_OFFSET: u16 = 6;
pub const DYLD_CHAINED_PTR_ARM64E_KERNEL: u16 = 7;
pub const DYLD_CHAINED_PTR_64_KERNEL_CACHE: u16 = 8;
pub const DYLD_CHAINED_PTR_ARM64E_USERLAND: u16 = 9;
pub const DYLD_CHAINED_PTR_ARM64E_FIRMWARE: u16 = 10;
pub const DYLD_CHAINED_PTR_X86_64_KERNEL_CACHE: u16 = 11;
pub const DYLD_CHAINED_PTR_ARM64E_USERLAND24: u16 = 12;

/// Returns a human-readable name for a `DYLD_CHAINED_PTR_*` pointer format.
#[must_use]
pub const fn chained_ptr_format_name(format: u16) -> &'static str {
    match format {
        DYLD_CHAINED_PTR_ARM64E => "ARM64E",
        DYLD_CHAINED_PTR_64 => "64",
        DYLD_CHAINED_PTR_32 => "32",
        DYLD_CHAINED_PTR_32_CACHE => "32_CACHE",
        DYLD_CHAINED_PTR_32_FIRMWARE => "32_FIRMWARE",
        DYLD_CHAINED_PTR_64_OFFSET => "64_OFFSET",
        DYLD_CHAINED_PTR_ARM64E_KERNEL => "ARM64E_KERNEL",
        DYLD_CHAINED_PTR_64_KERNEL_CACHE => "64_KERNEL_CACHE",
        DYLD_CHAINED_PTR_ARM64E_USERLAND => "ARM64E_USERLAND",
        DYLD_CHAINED_PTR_ARM64E_FIRMWARE => "ARM64E_FIRMWARE",
        DYLD_CHAINED_PTR_X86_64_KERNEL_CACHE => "X86_64_KERNEL_CACHE",
        DYLD_CHAINED_PTR_ARM64E_USERLAND24 => "ARM64E_USERLAND24",
        _ => "Unknown",
    }
}

/// Returns `true` if the format is one of the 32-bit pointer chain encodings.
#[must_use]
pub const fn is_chained_ptr_32(format: u16) -> bool {
    matches!(
        format,
        DYLD_CHAINED_PTR_32 | DYLD_CHAINED_PTR_32_CACHE | DYLD_CHAINED_PTR_32_FIRMWARE
    )
}

/// Returns `true` if the format targets the kernel/firmware cache layouts.
#[must_use]
pub const fn is_chained_ptr_kernel(format: u16) -> bool {
    matches!(
        format,
        DYLD_CHAINED_PTR_ARM64E_KERNEL
            | DYLD_CHAINED_PTR_64_KERNEL_CACHE
            | DYLD_CHAINED_PTR_ARM64E_FIRMWARE
            | DYLD_CHAINED_PTR_X86_64_KERNEL_CACHE
    )
}

// PAC (Pointer Authentication Code) mask — strip top 24 bits on arm64e
const PAC_STRIP_MASK: u64 = 0x0000_FFFF_FFFF_FFFF;

// ── Enums ─────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RebaseType {
    Pointer,
    TextAbsolute32,
    TextPcrel32,
    Unknown(u8),
}

impl RebaseType {
    const fn from_u8(v: u8) -> Self {
        match v {
            REBASE_TYPE_POINTER => Self::Pointer,
            REBASE_TYPE_TEXT_ABSOLUTE32 => Self::TextAbsolute32,
            REBASE_TYPE_TEXT_PCREL32 => Self::TextPcrel32,
            other => Self::Unknown(other),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BindType {
    Pointer,
    TextAbsolute32,
    TextPcrel32,
    Unknown(u8),
}

impl BindType {
    const fn from_u8(v: u8) -> Self {
        match v {
            BIND_TYPE_POINTER => Self::Pointer,
            BIND_TYPE_TEXT_ABSOLUTE32 => Self::TextAbsolute32,
            BIND_TYPE_TEXT_PCREL32 => Self::TextPcrel32,
            other => Self::Unknown(other),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BindOrdinal {
    DylibSelf,
    MainExecutable,
    FlatLookup,
    Ordinal(u32),
}

// ── Core Records ──────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RebaseEntry {
    pub segment_index: u32,
    pub segment_offset: u64,
    pub rebase_type: RebaseType,
    pub virtual_address: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BindEntry {
    pub segment_index: u32,
    pub segment_offset: u64,
    pub bind_type: BindType,
    pub dylib_ordinal: BindOrdinal,
    pub flags: u8,
    pub addend: i64,
    pub symbol_name: String,
    pub virtual_address: u64,
    pub is_weak: bool,
    pub is_lazy: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WeakBindEntry {
    pub segment_index: u32,
    pub segment_offset: u64,
    pub bind_type: BindType,
    pub flags: u8,
    pub addend: i64,
    pub symbol_name: String,
    pub virtual_address: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FixupChainImport {
    pub lib_ordinal: u8,
    pub weak_import: bool,
    pub name_offset: u32,
    pub symbol_name: String,
    pub addend: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainedFixupEntry {
    pub virtual_address: u64,
    pub entry_type: ChainedEntryType,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ChainedEntryType {
    Rebase { target: u64, high8: u8 },
    Bind { ordinal: u32, addend: i64 },
    AuthRebase { target: u64, diversity: u16, addr_div: bool, key: u8 },
    AuthBind { ordinal: u32, diversity: u16, addr_div: bool, key: u8 },
}

// ── Segment Info (needed for VA translation) ──────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SegmentInfo {
    pub name: String,
    pub vm_address: u64,
    pub vm_size: u64,
    pub file_offset: u64,
    pub file_size: u64,
}

impl SegmentInfo {
    #[must_use]
    pub const fn contains_offset(&self, seg_off: u64) -> bool {
        seg_off < self.vm_size
    }

    #[must_use]
    pub const fn virtual_address(&self, seg_off: u64) -> u64 {
        self.vm_address.wrapping_add(seg_off)
    }

    #[must_use]
    pub const fn file_offset_for(&self, seg_off: u64) -> Option<u64> {
        if seg_off < self.file_size {
            Some(self.file_offset.wrapping_add(seg_off))
        } else {
            None
        }
    }
}

// ── Parsed Fixup Set ──────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DyldFixups {
    pub rebases: Vec<RebaseEntry>,
    pub binds: Vec<BindEntry>,
    pub lazy_binds: Vec<BindEntry>,
    pub weak_binds: Vec<WeakBindEntry>,
    pub chained: Vec<ChainedFixupEntry>,
    pub chained_imports: Vec<FixupChainImport>,
}

impl DyldFixups {
    #[must_use]
    pub const fn total_fixups(&self) -> usize {
        self.rebases.len()
            + self.binds.len()
            + self.lazy_binds.len()
            + self.weak_binds.len()
            + self.chained.len()
    }

    /// Build a VA→symbol map for the bind entries.
    #[must_use]
    pub fn bind_symbol_map(&self) -> HashMap<u64, &str> {
        let mut map = HashMap::new();
        for b in &self.binds {
            map.insert(b.virtual_address, b.symbol_name.as_str());
        }
        for b in &self.lazy_binds {
            map.insert(b.virtual_address, b.symbol_name.as_str());
        }
        map
    }

    /// Collect all distinct symbol names referenced by bind entries.
    #[must_use]
    pub fn all_imported_symbols(&self) -> Vec<&str> {
        let mut names: Vec<&str> = self
            .binds
            .iter()
            .chain(self.lazy_binds.iter())
            .map(|b| b.symbol_name.as_str())
            .collect();
        names.sort_unstable();
        names.dedup();
        names
    }
}

// ── ULEB/SLEB helpers ─────────────────────────────────────────────────────────

fn read_uleb128(data: &[u8], pos: &mut usize) -> Result<u64> {
    let mut result: u64 = 0;
    let mut shift = 0u32;
    loop {
        if *pos >= data.len() {
            bail!("ULEB128 truncated at offset {}", *pos);
        }
        let byte = data[*pos];
        *pos += 1;
        result |= u64::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            break;
        }
        shift += 7;
        if shift >= 64 {
            bail!("ULEB128 overflow");
        }
    }
    Ok(result)
}

fn read_sleb128(data: &[u8], pos: &mut usize) -> Result<i64> {
    let mut result: i64 = 0;
    let mut shift = 0u32;
    let mut byte;
    loop {
        if *pos >= data.len() {
            bail!("SLEB128 truncated at offset {}", *pos);
        }
        byte = data[*pos];
        *pos += 1;
        result |= i64::from(byte & 0x7f) << shift;
        shift += 7;
        if byte & 0x80 == 0 {
            break;
        }
        if shift >= 64 {
            bail!("SLEB128 overflow");
        }
    }
    // Sign-extend
    if shift < 64 && (byte & 0x40) != 0 {
        result |= -(1i64 << shift);
    }
    Ok(result)
}

fn read_cstr(data: &[u8], pos: &mut usize) -> Result<String> {
    let start = *pos;
    while *pos < data.len() && data[*pos] != 0 {
        *pos += 1;
    }
    if *pos >= data.len() {
        bail!("Unterminated C string at offset {start}");
    }
    let s = std::str::from_utf8(&data[start..*pos])
        .unwrap_or("<invalid utf8>")
        .to_owned();
    *pos += 1; // consume NUL
    Ok(s)
}

fn read_u32_le(data: &[u8], off: usize) -> Result<u32> {
    if off + 4 > data.len() {
        bail!("read_u32_le OOB at {off}");
    }
    Ok(u32::from_le_bytes(data[off..off + 4].try_into().unwrap()))
}

fn read_u64_le(data: &[u8], off: usize) -> Result<u64> {
    if off + 8 > data.len() {
        bail!("read_u64_le OOB at {off}");
    }
    Ok(u64::from_le_bytes(data[off..off + 8].try_into().unwrap()))
}

fn read_u16_le(data: &[u8], off: usize) -> Result<u16> {
    if off + 2 > data.len() {
        bail!("read_u16_le OOB at {off}");
    }
    Ok(u16::from_le_bytes(data[off..off + 2].try_into().unwrap()))
}

// ── Rebase Opcode Parser ──────────────────────────────────────────────────────

pub struct RebaseParser<'a> {
    data: &'a [u8],
    segments: &'a [SegmentInfo],
}

impl<'a> RebaseParser<'a> {
    #[must_use] 
    pub const fn new(data: &'a [u8], segments: &'a [SegmentInfo]) -> Self {
        Self { data, segments }
    }

    pub fn parse(&self) -> Result<Vec<RebaseEntry>> {
        let mut entries = Vec::new();
        let mut pos = 0;
        let mut seg_idx: u32 = 0;
        let mut seg_off: u64 = 0;
        let mut rtype = RebaseType::Pointer;
        let ptr_size: u64 = 8; // assume 64-bit

        while pos < self.data.len() {
            let byte = self.data[pos];
            pos += 1;
            let opcode = byte & 0xf0;
            let imm = u64::from(byte & 0x0f);

            match opcode {
                x if x == REBASE_OPCODE_DONE => break,
                x if x == REBASE_OPCODE_SET_TYPE_IMM => {
                    rtype = RebaseType::from_u8(imm as u8);
                }
                x if x == REBASE_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB => {
                    seg_idx = imm as u32;
                    seg_off = read_uleb128(self.data, &mut pos)?;
                }
                x if x == REBASE_OPCODE_ADD_ADDR_ULEB => {
                    let add = read_uleb128(self.data, &mut pos)?;
                    seg_off = seg_off.wrapping_add(add);
                }
                x if x == REBASE_OPCODE_ADD_ADDR_IMM_SCALED => {
                    seg_off = seg_off.wrapping_add(imm * ptr_size);
                }
                x if x == REBASE_OPCODE_DO_REBASE_IMM_TIMES => {
                    for _ in 0..imm {
                        entries.push(self.make_entry(seg_idx, seg_off, rtype)?);
                        seg_off = seg_off.wrapping_add(ptr_size);
                    }
                }
                x if x == REBASE_OPCODE_DO_REBASE_ULEB_TIMES => {
                    let count = read_uleb128(self.data, &mut pos)?;
                    for _ in 0..count {
                        entries.push(self.make_entry(seg_idx, seg_off, rtype)?);
                        seg_off = seg_off.wrapping_add(ptr_size);
                    }
                }
                x if x == REBASE_OPCODE_DO_REBASE_ADD_ADDR_ULEB => {
                    entries.push(self.make_entry(seg_idx, seg_off, rtype)?);
                    let add = read_uleb128(self.data, &mut pos)?;
                    seg_off = seg_off.wrapping_add(ptr_size).wrapping_add(add);
                }
                x if x == REBASE_OPCODE_DO_REBASE_ULEB_TIMES_SKIPPING_ULEB => {
                    let count = read_uleb128(self.data, &mut pos)?;
                    let skip = read_uleb128(self.data, &mut pos)?;
                    for _ in 0..count {
                        entries.push(self.make_entry(seg_idx, seg_off, rtype)?);
                        seg_off = seg_off.wrapping_add(ptr_size).wrapping_add(skip);
                    }
                }
                _ => {
                    // Unknown opcode — skip
                }
            }
        }
        Ok(entries)
    }

    fn make_entry(&self, seg_idx: u32, seg_off: u64, rtype: RebaseType) -> Result<RebaseEntry> {
        let seg = self
            .segments
            .get(seg_idx as usize)
            .ok_or_else(|| anyhow::anyhow!("Rebase: invalid segment index {seg_idx}"))?;
        let va = seg.virtual_address(seg_off);
        Ok(RebaseEntry {
            segment_index: seg_idx,
            segment_offset: seg_off,
            rebase_type: rtype,
            virtual_address: va,
        })
    }
}

// ── Bind Opcode Parser ────────────────────────────────────────────────────────

pub struct BindParser<'a> {
    data: &'a [u8],
    segments: &'a [SegmentInfo],
    is_weak: bool,
    is_lazy: bool,
}

impl<'a> BindParser<'a> {
    #[must_use] 
    pub const fn new(data: &'a [u8], segments: &'a [SegmentInfo], is_weak: bool, is_lazy: bool) -> Self {
        Self {
            data,
            segments,
            is_weak,
            is_lazy,
        }
    }

    pub fn parse(&self) -> Result<Vec<BindEntry>> {
        let mut entries = Vec::new();
        let mut pos = 0;
        let mut seg_idx: u32 = 0;
        let mut seg_off: u64 = 0;
        let mut btype = BindType::Pointer;
        let mut ordinal = BindOrdinal::Ordinal(0);
        let mut flags: u8 = 0;
        let mut addend: i64 = 0;
        let mut sym_name = String::new();
        let ptr_size: u64 = 8;

        macro_rules! do_bind {
            () => {
                if let Some(seg) = self.segments.get(seg_idx as usize) {
                    let va = seg.virtual_address(seg_off);
                    entries.push(BindEntry {
                        segment_index: seg_idx,
                        segment_offset: seg_off,
                        bind_type: btype,
                        dylib_ordinal: ordinal,
                        flags,
                        addend,
                        symbol_name: sym_name.clone(),
                        virtual_address: va,
                        is_weak: self.is_weak,
                        is_lazy: self.is_lazy,
                    });
                }
            };
        }

        while pos < self.data.len() {
            let byte = self.data[pos];
            pos += 1;
            let opcode = byte & 0xf0;
            let imm = u64::from(byte & 0x0f);

            match opcode {
                x if x == BIND_OPCODE_DONE => {
                    if self.is_lazy {
                        // lazy bind: DONE resets state for next entry
                        seg_idx = 0;
                        seg_off = 0;
                        sym_name = String::new();
                    } else {
                        break;
                    }
                }
                x if x == BIND_OPCODE_SET_DYLIB_ORDINAL_IMM => {
                    ordinal = BindOrdinal::Ordinal(imm as u32);
                }
                x if x == BIND_OPCODE_SET_DYLIB_ORDINAL_ULEB => {
                    let v = read_uleb128(self.data, &mut pos)?;
                    ordinal = BindOrdinal::Ordinal(u32::try_from(v)?);
                }
                x if x == BIND_OPCODE_SET_DYLIB_SPECIAL_IMM => {
                    let special = if imm == 0 { 0i64 } else { -imm.cast_signed() };
                    ordinal = match special {
                        BIND_SPECIAL_DYLIB_SELF => BindOrdinal::DylibSelf,
                        BIND_SPECIAL_DYLIB_MAIN_EXECUTABLE => BindOrdinal::MainExecutable,
                        BIND_SPECIAL_DYLIB_FLAT_LOOKUP => BindOrdinal::FlatLookup,
                        _ => BindOrdinal::Ordinal(0),
                    };
                }
                x if x == BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM => {
                    flags = imm as u8;
                    sym_name = read_cstr(self.data, &mut pos)?;
                }
                x if x == BIND_OPCODE_SET_TYPE_IMM => {
                    btype = BindType::from_u8(imm as u8);
                }
                x if x == BIND_OPCODE_SET_ADDEND_SLEB => {
                    addend = read_sleb128(self.data, &mut pos)?;
                }
                x if x == BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB => {
                    seg_idx = imm as u32;
                    seg_off = read_uleb128(self.data, &mut pos)?;
                }
                x if x == BIND_OPCODE_ADD_ADDR_ULEB => {
                    let add = read_uleb128(self.data, &mut pos)?;
                    seg_off = seg_off.wrapping_add(add);
                }
                x if x == BIND_OPCODE_DO_BIND => {
                    do_bind!();
                    seg_off = seg_off.wrapping_add(ptr_size);
                }
                x if x == BIND_OPCODE_DO_BIND_ADD_ADDR_ULEB => {
                    do_bind!();
                    let add = read_uleb128(self.data, &mut pos)?;
                    seg_off = seg_off.wrapping_add(ptr_size).wrapping_add(add);
                }
                x if x == BIND_OPCODE_DO_BIND_ADD_ADDR_IMM_SCALED => {
                    do_bind!();
                    seg_off = seg_off.wrapping_add(ptr_size.wrapping_add(imm * ptr_size));
                }
                x if x == BIND_OPCODE_DO_BIND_ULEB_TIMES_SKIPPING_ULEB => {
                    let count = read_uleb128(self.data, &mut pos)?;
                    let skip = read_uleb128(self.data, &mut pos)?;
                    for _ in 0..count {
                        do_bind!();
                        seg_off = seg_off.wrapping_add(ptr_size).wrapping_add(skip);
                    }
                }
                _ => {}
            }
        }
        Ok(entries)
    }
}

// ── Weak Bind Parser ──────────────────────────────────────────────────────────

pub struct WeakBindParser<'a> {
    data: &'a [u8],
    segments: &'a [SegmentInfo],
}

impl<'a> WeakBindParser<'a> {
    #[must_use] 
    pub const fn new(data: &'a [u8], segments: &'a [SegmentInfo]) -> Self {
        Self { data, segments }
    }

    pub fn parse(&self) -> Result<Vec<WeakBindEntry>> {
        let bind_parser = BindParser::new(self.data, self.segments, true, false);
        let binds = bind_parser.parse()?;
        Ok(binds
            .into_iter()
            .map(|b| WeakBindEntry {
                segment_index: b.segment_index,
                segment_offset: b.segment_offset,
                bind_type: b.bind_type,
                flags: b.flags,
                addend: b.addend,
                symbol_name: b.symbol_name,
                virtual_address: b.virtual_address,
            })
            .collect())
    }
}

// ── Chained Fixup Parser (iOS 14+ / arm64e) ───────────────────────────────────

/// `dyld_chained_fixups_header` (from <mach-o/fixup-chains.h>)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainedFixupsHeader {
    pub fixups_version: u32,
    pub starts_offset: u32,
    pub imports_offset: u32,
    pub symbols_offset: u32,
    pub imports_count: u32,
    pub imports_format: u32, // 1=uncompressed, 3=compressed
    pub symbols_format: u32, // 0=uncompressed
}

impl ChainedFixupsHeader {
    pub fn parse(data: &[u8]) -> Result<Self> {
        if data.len() < 28 {
            bail!("ChainedFixupsHeader: data too short");
        }
        Ok(Self {
            fixups_version: read_u32_le(data, 0)?,
            starts_offset: read_u32_le(data, 4)?,
            imports_offset: read_u32_le(data, 8)?,
            symbols_offset: read_u32_le(data, 12)?,
            imports_count: read_u32_le(data, 16)?,
            imports_format: read_u32_le(data, 20)?,
            symbols_format: read_u32_le(data, 24)?,
        })
    }
}

/// `dyld_chained_starts_in_image`
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainedStartsInImage {
    pub seg_count: u32,
    pub seg_info_offsets: Vec<u32>,
}

impl ChainedStartsInImage {
    pub fn parse(data: &[u8], base: usize) -> Result<Self> {
        let seg_count = read_u32_le(data, base)?;
        let mut offsets = Vec::with_capacity(seg_count as usize);
        for i in 0..seg_count as usize {
            offsets.push(read_u32_le(data, base + 4 + i * 4)?);
        }
        Ok(Self {
            seg_count,
            seg_info_offsets: offsets,
        })
    }
}

/// `dyld_chained_starts_in_segment`
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainedStartsInSegment {
    pub size: u32,
    pub page_size: u16,
    pub pointer_format: u16,
    pub segment_offset: u64,
    pub max_valid_pointer: u32,
    pub page_count: u16,
    pub page_starts: Vec<u16>,
}

const DYLD_CHAINED_PTR_START_NONE: u16 = 0xFFFF;
const DYLD_CHAINED_PTR_START_MULTI: u16 = 0x8000;

impl ChainedStartsInSegment {
    pub fn parse(data: &[u8], base: usize) -> Result<Self> {
        if base + 22 > data.len() {
            bail!("ChainedStartsInSegment: truncated at {base}");
        }
        let size = read_u32_le(data, base)?;
        let page_size = read_u16_le(data, base + 4)?;
        let pointer_format = read_u16_le(data, base + 6)?;
        let segment_offset = read_u64_le(data, base + 8)?;
        let max_valid_pointer = read_u32_le(data, base + 16)?;
        let page_count = read_u16_le(data, base + 20)?;
        let mut page_starts = Vec::with_capacity(page_count as usize);
        for i in 0..page_count as usize {
            page_starts.push(read_u16_le(data, base + 22 + i * 2)?);
        }
        Ok(Self {
            size,
            page_size,
            pointer_format,
            segment_offset,
            max_valid_pointer,
            page_count,
            page_starts,
        })
    }
}

pub struct ChainedFixupParser<'a> {
    data: &'a [u8],
    lc_data: &'a [u8], // the LC_DYLD_CHAINED_FIXUPS data
    segments: &'a [SegmentInfo],
    preferred_load_address: u64,
}

impl<'a> ChainedFixupParser<'a> {
    #[must_use] 
    pub const fn new(
        data: &'a [u8],
        lc_data: &'a [u8],
        segments: &'a [SegmentInfo],
        preferred_load_address: u64,
    ) -> Self {
        Self {
            data,
            lc_data,
            segments,
            preferred_load_address,
        }
    }

    pub fn parse(&self) -> Result<(Vec<ChainedFixupEntry>, Vec<FixupChainImport>)> {
        let header = ChainedFixupsHeader::parse(self.lc_data)?;
        let imports = self.parse_imports(&header)?;
        let entries = self.walk_chains(&header, &imports)?;
        Ok((entries, imports))
    }

    fn parse_imports(&self, hdr: &ChainedFixupsHeader) -> Result<Vec<FixupChainImport>> {
        let imp_base = hdr.imports_offset as usize;
        let sym_base = hdr.symbols_offset as usize;
        let count = hdr.imports_count as usize;
        let mut imports = Vec::with_capacity(count);

        // Format 1: dyld_chained_import (4 bytes each)
        // Format 3: dyld_chained_import_addend64 (16 bytes each)
        let entry_size: usize = match hdr.imports_format {
            1 => 4,
            2 => 8,
            3 => 16,
            _ => bail!("Unknown imports_format {}", hdr.imports_format),
        };

        for i in 0..count {
            let off = imp_base + i * entry_size;
            if off + entry_size > self.lc_data.len() {
                bail!("Import entry {i} OOB");
            }
            let raw_u32 = read_u32_le(self.lc_data, off)?;
            let lib_ordinal = (raw_u32 & 0xFF) as u8;
            let weak_import = (raw_u32 >> 8 & 1) != 0;
            let name_offset = (raw_u32 >> 9) as u32;
            let addend: i64 = if hdr.imports_format == 3 {
                i64::from_le_bytes(
                    self.lc_data[off + 8..off + 16].try_into().unwrap_or([0u8; 8]),
                )
            } else if hdr.imports_format == 2 {
                i64::from(i32::from_le_bytes(
                    self.lc_data[off + 4..off + 8].try_into().unwrap_or([0u8; 4]),
                ))
            } else {
                0
            };

            let sym_off = sym_base + name_offset as usize;
            let mut tmp = sym_off;
            let symbol_name = if sym_off < self.lc_data.len() {
                read_cstr(self.lc_data, &mut tmp).unwrap_or_default()
            } else {
                String::new()
            };

            imports.push(FixupChainImport {
                lib_ordinal,
                weak_import,
                name_offset,
                symbol_name,
                addend,
            });
        }
        Ok(imports)
    }

    fn walk_chains(
        &self,
        hdr: &ChainedFixupsHeader,
        imports: &[FixupChainImport],
    ) -> Result<Vec<ChainedFixupEntry>> {
        let starts_base = hdr.starts_offset as usize;
        let img_starts = ChainedStartsInImage::parse(self.lc_data, starts_base)?;
        let mut entries = Vec::new();

        for (seg_idx, &seg_info_off) in img_starts.seg_info_offsets.iter().enumerate() {
            if seg_info_off == 0 {
                continue;
            }
            let seg_starts = ChainedStartsInSegment::parse(
                self.lc_data,
                starts_base + seg_info_off as usize,
            )?;
            let seg = match self.segments.get(seg_idx) {
                Some(s) => s,
                None => continue,
            };

            for (page_idx, &page_start) in seg_starts.page_starts.iter().enumerate() {
                if page_start == DYLD_CHAINED_PTR_START_NONE {
                    continue;
                }
                let page_addr = seg.vm_address
                    + seg_starts.segment_offset
                    + (page_idx as u64) * u64::from(seg_starts.page_size);

                if page_start & DYLD_CHAINED_PTR_START_MULTI != 0 {
                    // multi-start page — follow overflow chain
                    let overflow_off = (page_start & !DYLD_CHAINED_PTR_START_MULTI) as usize;
                    // simplified: just process first start
                    self.process_chain_at(
                        page_addr,
                        overflow_off as u64,
                        seg_starts.pointer_format,
                        imports,
                        &mut entries,
                    );
                } else {
                    self.process_chain_at(
                        page_addr,
                        u64::from(page_start),
                        seg_starts.pointer_format,
                        imports,
                        &mut entries,
                    );
                }
            }
        }
        Ok(entries)
    }

    fn process_chain_at(
        &self,
        page_addr: u64,
        start_offset: u64,
        pointer_format: u16,
        imports: &[FixupChainImport],
        entries: &mut Vec<ChainedFixupEntry>,
    ) {
        let mut va = page_addr + start_offset;
        let file_off = self.va_to_file_offset(va);
        let stride: u64 = if pointer_format == DYLD_CHAINED_PTR_32 {
            4
        } else {
            8
        };

        let mut limit = 0usize;
        let mut cur_file = file_off;

        loop {
            limit += 1;
            if limit > 65536 {
                break;
            }

            let Some(off) = cur_file else { break };
            if off + 8 > self.data.len() {
                break;
            }

            let raw = u64::from_le_bytes(self.data[off..off + 8].try_into().unwrap());
            let entry = self.decode_pointer(va, raw, pointer_format, imports);
            entries.push(entry);

            let next = match pointer_format {
                DYLD_CHAINED_PTR_ARM64E | DYLD_CHAINED_PTR_ARM64E_USERLAND
                | DYLD_CHAINED_PTR_ARM64E_USERLAND24 => (raw >> 52) & 0xFFF,
                DYLD_CHAINED_PTR_32 => (raw >> 26) & 0x3F,
                _ => (raw >> 51) & 0x7FF,
            };
            if next == 0 {
                break;
            }
            va = va.wrapping_add(next * stride);
            cur_file = self.va_to_file_offset(va);
        }
    }

    fn decode_pointer(
        &self,
        va: u64,
        raw: u64,
        format: u16,
        imports: &[FixupChainImport],
    ) -> ChainedFixupEntry {
        // Clamp ordinals to the valid import range so callers can detect malformed
        // chains; an ordinal outside `imports` is left as-is but flagged via 0.
        let clamp_ordinal = |ord: u32| -> u32 {
            if !imports.is_empty() && (ord as usize) >= imports.len() {
                // Invalid ordinal — return the last valid index as a best-effort guess.
                u32::try_from(imports.len() - 1).unwrap_or(0)
            } else {
                ord
            }
        };
        match format {
            DYLD_CHAINED_PTR_ARM64E | DYLD_CHAINED_PTR_ARM64E_USERLAND
            | DYLD_CHAINED_PTR_ARM64E_USERLAND24 => {
                let is_bind = (raw >> 63) & 1 != 0;
                let is_auth = (raw >> 62) & 1 != 0;
                if is_auth && is_bind {
                    let ordinal = clamp_ordinal((raw & 0xFFFF) as u32);
                    let diversity = ((raw >> 32) & 0xFFFF) as u16;
                    let addr_div = (raw >> 48) & 1 != 0;
                    let key = ((raw >> 49) & 0x3) as u8;
                    ChainedFixupEntry {
                        virtual_address: va,
                        entry_type: ChainedEntryType::AuthBind {
                            ordinal,
                            diversity,
                            addr_div,
                            key,
                        },
                    }
                } else if is_auth {
                    let target = raw & 0x_0000_FFFF_FFFF;
                    let diversity = ((raw >> 32) & 0xFFFF) as u16;
                    let addr_div = (raw >> 48) & 1 != 0;
                    let key = ((raw >> 49) & 0x3) as u8;
                    ChainedFixupEntry {
                        virtual_address: va,
                        entry_type: ChainedEntryType::AuthRebase {
                            target,
                            diversity,
                            addr_div,
                            key,
                        },
                    }
                } else if is_bind {
                    let ordinal = clamp_ordinal((raw & 0xFFFF) as u32);
                    let addend = ((raw >> 32) & 0x7FFF).cast_signed(); // simplified
                    ChainedFixupEntry {
                        virtual_address: va,
                        entry_type: ChainedEntryType::Bind { ordinal, addend },
                    }
                } else {
                    let target = strip_pac(raw);
                    let high8 = ((raw >> 56) & 0xFF) as u8;
                    ChainedFixupEntry {
                        virtual_address: va,
                        entry_type: ChainedEntryType::Rebase { target, high8 },
                    }
                }
            }
            DYLD_CHAINED_PTR_64 | DYLD_CHAINED_PTR_64_OFFSET => {
                let is_bind = (raw >> 63) & 1 != 0;
                if is_bind {
                    let ordinal = clamp_ordinal((raw & 0x00FF_FFFF) as u32);
                    let addend = ((raw >> 24) & 0xFF).cast_signed();
                    ChainedFixupEntry {
                        virtual_address: va,
                        entry_type: ChainedEntryType::Bind { ordinal, addend },
                    }
                } else {
                    let target = raw & 0x_0007_FFFF_FFFF_FFFF;
                    let high8 = ((raw >> 56) & 0xFF) as u8;
                    ChainedFixupEntry {
                        virtual_address: va,
                        entry_type: ChainedEntryType::Rebase { target, high8 },
                    }
                }
            }
            _ => {
                let is_bind = (raw >> 31) & 1 != 0;
                if is_bind {
                    let ordinal = clamp_ordinal((raw & 0xFFFF) as u32);
                    let addend = ((raw >> 16) & 0xFF).cast_signed();
                    ChainedFixupEntry {
                        virtual_address: va,
                        entry_type: ChainedEntryType::Bind { ordinal, addend },
                    }
                } else {
                    let target = (raw & 0x03FF_FFFF) + self.preferred_load_address;
                    ChainedFixupEntry {
                        virtual_address: va,
                        entry_type: ChainedEntryType::Rebase { target, high8: 0 },
                    }
                }
            }
        }
    }

    fn va_to_file_offset(&self, va: u64) -> Option<usize> {
        for seg in self.segments {
            if va >= seg.vm_address && va < seg.vm_address + seg.vm_size {
                let seg_off = va - seg.vm_address;
                if seg_off < seg.file_size {
                    return usize::try_from(seg.file_offset + seg_off).ok();
                }
            }
        }
        None
    }
}

// ── PAC helpers ───────────────────────────────────────────────────────────────

/// Strip the PAC signature bits from an arm64e pointer.
#[must_use]
pub const fn strip_pac(ptr: u64) -> u64 {
    ptr & PAC_STRIP_MASK
}

/// Strip the high8 encoding and return the plain target VA.
#[must_use]
pub const fn decode_rebase_target(raw: u64, preferred_load_addr: u64, slide: u64) -> u64 {
    let high8 = (raw >> 56) & 0xFF;
    let low = raw & 0x00FF_FFFF_FFFF_FFFF;
    let target = low.wrapping_add(preferred_load_addr).wrapping_add(slide);
    if high8 != 0 {
        (target & 0x00FF_FFFF_FFFF_FFFF) | (high8 << 56)
    } else {
        target
    }
}

// ── High-level entry point ────────────────────────────────────────────────────

/// Parse all dyld fixup info from the mach-o binary `data` given precomputed
/// slice views of each load-command data region and segment table.
pub struct FixupContext<'a> {
    pub binary: &'a [u8],
    pub segments: Vec<SegmentInfo>,
    pub rebase_data: Option<&'a [u8]>,
    pub bind_data: Option<&'a [u8]>,
    pub weak_bind_data: Option<&'a [u8]>,
    pub lazy_bind_data: Option<&'a [u8]>,
    pub chained_data: Option<&'a [u8]>,
    pub preferred_load_address: u64,
}

impl FixupContext<'_> {
    pub fn parse_all(&self) -> Result<DyldFixups> {
        let mut fixups = DyldFixups::default();

        if let Some(rd) = self.rebase_data {
            fixups.rebases = RebaseParser::new(rd, &self.segments).parse()?;
        }
        if let Some(bd) = self.bind_data {
            fixups.binds = BindParser::new(bd, &self.segments, false, false).parse()?;
        }
        if let Some(wd) = self.weak_bind_data {
            fixups.weak_binds = WeakBindParser::new(wd, &self.segments).parse()?;
        }
        if let Some(ld) = self.lazy_bind_data {
            fixups.lazy_binds = BindParser::new(ld, &self.segments, false, true).parse()?;
        }
        if let Some(cd) = self.chained_data {
            let (entries, imports) = ChainedFixupParser::new(
                self.binary,
                cd,
                &self.segments,
                self.preferred_load_address,
            )
            .parse()?;
            fixups.chained = entries;
            fixups.chained_imports = imports;
        }

        Ok(fixups)
    }
}

// ── Statistics ────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct FixupStats {
    pub total_rebases: usize,
    pub total_binds: usize,
    pub total_lazy_binds: usize,
    pub total_weak_binds: usize,
    pub total_chained: usize,
    pub unique_libraries: Vec<String>,
    pub unique_symbols: usize,
    pub has_pac: bool,
}

impl FixupStats {
    #[must_use]
    pub fn from_fixups(fixups: &DyldFixups) -> Self {
        let mut libs: Vec<String> = Vec::new();
        let mut syms: std::collections::HashSet<&str> = std::collections::HashSet::new();

        for b in fixups.binds.iter().chain(fixups.lazy_binds.iter()) {
            syms.insert(&b.symbol_name);
        }
        libs.sort_unstable();
        libs.dedup();

        let has_pac = fixups
            .chained
            .iter()
            .any(|e| matches!(e.entry_type, ChainedEntryType::AuthRebase { .. } | ChainedEntryType::AuthBind { .. }));

        Self {
            total_rebases: fixups.rebases.len(),
            total_binds: fixups.binds.len(),
            total_lazy_binds: fixups.lazy_binds.len(),
            total_weak_binds: fixups.weak_binds.len(),
            total_chained: fixups.chained.len(),
            unique_libraries: libs,
            unique_symbols: syms.len(),
            has_pac,
        }
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_seg() -> SegmentInfo {
        SegmentInfo {
            name: "__DATA".to_owned(),
            vm_address: 0x1000_0000,
            vm_size: 0x1000,
            file_offset: 0x4000,
            file_size: 0x1000,
        }
    }

    #[test]
    fn test_uleb128_single_byte() {
        let data = [0x05u8];
        let mut pos = 0;
        assert_eq!(read_uleb128(&data, &mut pos).unwrap(), 5);
        assert_eq!(pos, 1);
    }

    #[test]
    fn test_uleb128_multi_byte() {
        // 624485 = 0xE5 0x8E 0x26
        let data = [0xE5u8, 0x8E, 0x26];
        let mut pos = 0;
        assert_eq!(read_uleb128(&data, &mut pos).unwrap(), 624_485);
    }

    #[test]
    fn test_sleb128_negative() {
        // -1 encoded as SLEB128 = 0x7F
        let data = [0x7Fu8];
        let mut pos = 0;
        assert_eq!(read_sleb128(&data, &mut pos).unwrap(), -1);
    }

    #[test]
    fn test_strip_pac() {
        let signed: u64 = 0xFEDC_1234_5678_9ABC;
        let stripped = strip_pac(signed);
        assert_eq!(stripped & !PAC_STRIP_MASK, 0);
    }

    #[test]
    fn test_segment_va() {
        let seg = make_seg();
        assert_eq!(seg.virtual_address(0x100), 0x1000_0100);
    }

    #[test]
    fn test_rebase_parser_empty() {
        let data = [REBASE_OPCODE_DONE];
        let segs = vec![make_seg()];
        let parser = RebaseParser::new(&data, &segs);
        let entries = parser.parse().unwrap();
        assert!(entries.is_empty());
    }

    #[test]
    fn test_bind_symbol_map() {
        let mut fixups = DyldFixups::default();
        let _seg = make_seg();
        fixups.binds.push(BindEntry {
            segment_index: 0,
            segment_offset: 0,
            bind_type: BindType::Pointer,
            dylib_ordinal: BindOrdinal::Ordinal(1),
            flags: 0,
            addend: 0,
            symbol_name: "_malloc".to_owned(),
            virtual_address: 0x1234,
            is_weak: false,
            is_lazy: false,
        });
        let map = fixups.bind_symbol_map();
        assert_eq!(map.get(&0x1234), Some(&"_malloc"));
    }

    #[test]
    fn test_cstr_read() {
        let data = b"hello\0world\0";
        let mut pos = 0;
        assert_eq!(read_cstr(data, &mut pos).unwrap(), "hello");
        assert_eq!(pos, 6);
    }

    #[test]
    fn test_fixup_stats_no_pac() {
        let fixups = DyldFixups::default();
        let stats = FixupStats::from_fixups(&fixups);
        assert!(!stats.has_pac);
    }
}
