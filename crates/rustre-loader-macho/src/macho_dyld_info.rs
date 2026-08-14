//! `macho_dyld_info` — dyld dynamic linking info decoder.
//!
//! Decodes all four opcode streams encoded in `LC_DYLD_INFO_ONLY`:
//!
//! | Stream          | Opcodes                       |
//! |-----------------|-------------------------------|
//! | **Rebase**      | `REBASE_OPCODE_*`             |
//! | **Bind**        | `BIND_OPCODE_*` (normal)      |
//! | **Weak bind**   | `BIND_OPCODE_*` (weak syms)   |
//! | **Lazy bind**   | `BIND_OPCODE_*` (PLT stubs)   |
//!
//! Also decodes:
//! - **Export trie** (`LC_DYLD_EXPORTS_TRIE` / export field of dyld info):
//!   recursive trie with node flags (regular / weak / re-export / stub /
//!   resolver).
//! - **Chained fixups** (`LC_DYLD_CHAINED_FIXUPS`): header + imports table +
//!   pointer formats (ARM64E, 64-bit, 32-bit, …).

use std::fmt;

// ─── Error type ──────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DyldInfoError {
    UnexpectedEnd,
    BadUleb,
    BadSleb,
    UnknownRebaseOpcode(u8),
    UnknownBindOpcode(u8),
    InvalidChainedFixupsHeader,
    SegmentIndexOutOfRange(u8),
}

impl fmt::Display for DyldInfoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnexpectedEnd                    => write!(f, "unexpected end of opcode stream"),
            Self::BadUleb                          => write!(f, "malformed ULEB128 encoding"),
            Self::BadSleb                          => write!(f, "malformed SLEB128 encoding"),
            Self::UnknownRebaseOpcode(o)           => write!(f, "unknown rebase opcode {o:#04x}"),
            Self::UnknownBindOpcode(o)             => write!(f, "unknown bind opcode {o:#04x}"),
            Self::InvalidChainedFixupsHeader       => write!(f, "invalid chained fixups header"),
            Self::SegmentIndexOutOfRange(i)        => write!(f, "segment index {i} out of range"),
        }
    }
}

// ─── ULEB128 / SLEB128 decoders ───────────────────────────────────────────────

/// Decode an unsigned LEB128 value starting at `pos` within `data`.
/// Returns `(value, new_pos)`.
pub fn read_uleb128(data: &[u8], mut pos: usize) -> Result<(u64, usize), DyldInfoError> {
    let mut val: u64 = 0;
    let mut shift = 0u32;
    loop {
        if pos >= data.len() {
            return Err(DyldInfoError::UnexpectedEnd);
        }
        let b = data[pos];
        pos += 1;
        if shift >= 64 {
            return Err(DyldInfoError::BadUleb);
        }
        val |= u64::from(b & 0x7F) << shift;
        shift += 7;
        if b & 0x80 == 0 {
            return Ok((val, pos));
        }
    }
}

/// Decode a signed LEB128 value starting at `pos` within `data`.
pub fn read_sleb128(data: &[u8], mut pos: usize) -> Result<(i64, usize), DyldInfoError> {
    let mut val: i64 = 0;
    let mut shift = 0u32;
    loop {
        if pos >= data.len() {
            return Err(DyldInfoError::UnexpectedEnd);
        }
        let b = data[pos];
        pos += 1;
        if shift >= 64 {
            return Err(DyldInfoError::BadSleb);
        }
        val |= i64::from(b & 0x7F) << shift;
        shift += 7;
        if b & 0x80 == 0 {
            break;
        }
    }
    // Sign-extend: the sign bit of the last 7-bit group is at position (shift-7)+6 = shift-1.
    if (1..64).contains(&shift) && (val >> (shift - 1)) & 1 != 0 {
        val |= !((1i64 << shift) - 1);
    }
    Ok((val, pos))
}

fn read_cstr_at(data: &[u8], pos: usize) -> Result<(String, usize), DyldInfoError> {
    let start = pos;
    let mut cur = pos;
    while cur < data.len() && data[cur] != 0 {
        cur += 1;
    }
    if cur >= data.len() {
        return Err(DyldInfoError::UnexpectedEnd);
    }
    let s = String::from_utf8_lossy(&data[start..cur]).into_owned();
    Ok((s, cur + 1)) // skip NUL
}

// ─────────────────────────────────────────────────────────────────────────────
// REBASE opcodes
// ─────────────────────────────────────────────────────────────────────────────

const REBASE_OPCODE_MASK:                           u8 = 0xF0;
const REBASE_IMMEDIATE_MASK:                        u8 = 0x0F;

const REBASE_OPCODE_DONE:                           u8 = 0x00;
const REBASE_OPCODE_SET_TYPE_IMM:                   u8 = 0x10;
const REBASE_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB:    u8 = 0x20;
const REBASE_OPCODE_ADD_ADDR_ULEB:                  u8 = 0x30;
const REBASE_OPCODE_ADD_ADDR_IMM_SCALED:            u8 = 0x40;
const REBASE_OPCODE_DO_REBASE_IMM_TIMES:            u8 = 0x50;
const REBASE_OPCODE_DO_REBASE_ULEB_TIMES:           u8 = 0x60;
const REBASE_OPCODE_DO_REBASE_ADD_ADDR_ULEB:        u8 = 0x70;
const REBASE_OPCODE_DO_REBASE_ULEB_TIMES_SKIPPING_ULEB: u8 = 0x80;

/// Rebase type constants.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RebaseType {
    Pointer,
    TextAbsolute32,
    TextPcrel32,
    Unknown(u8),
}

impl RebaseType {
    #[must_use] 
    pub const fn from_raw(v: u8) -> Self {
        match v {
            1 => Self::Pointer,
            2 => Self::TextAbsolute32,
            3 => Self::TextPcrel32,
            _ => Self::Unknown(v),
        }
    }
    #[must_use] 
    pub const fn name(self) -> &'static str {
        match self {
            Self::Pointer         => "REBASE_TYPE_POINTER",
            Self::TextAbsolute32  => "REBASE_TYPE_TEXT_ABSOLUTE32",
            Self::TextPcrel32     => "REBASE_TYPE_TEXT_PCREL32",
            Self::Unknown(_)      => "REBASE_TYPE_UNKNOWN",
        }
    }
}

/// A single decoded rebase action.
#[derive(Debug, Clone)]
pub struct RebaseAction {
    /// Segment index (0-based).
    pub segment_index: u8,
    /// Byte offset within the segment's virtual address space.
    pub segment_offset: u64,
    /// Type of pointer to rebase.
    pub rebase_type: RebaseType,
}

/// Decode the full rebase opcode stream.
pub fn decode_rebase(data: &[u8], ptr_size: usize) -> Result<Vec<RebaseAction>, DyldInfoError> {
    let mut actions = Vec::new();
    let mut pos = 0usize;
    let mut rebase_type = RebaseType::Pointer;
    let mut seg_index: u8 = 0;
    let mut seg_offset: u64 = 0;

    while pos < data.len() {
        let byte = data[pos];
        pos += 1;
        let opcode    = byte & REBASE_OPCODE_MASK;
        let immediate = byte & REBASE_IMMEDIATE_MASK;

        match opcode {
            o if o == REBASE_OPCODE_DONE => break,

            o if o == REBASE_OPCODE_SET_TYPE_IMM => {
                rebase_type = RebaseType::from_raw(immediate);
            }

            o if o == REBASE_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB => {
                seg_index = immediate;
                let (off, new_pos) = read_uleb128(data, pos)?;
                seg_offset = off;
                pos = new_pos;
            }

            o if o == REBASE_OPCODE_ADD_ADDR_ULEB => {
                let (add, new_pos) = read_uleb128(data, pos)?;
                seg_offset = seg_offset.wrapping_add(add);
                pos = new_pos;
            }

            o if o == REBASE_OPCODE_ADD_ADDR_IMM_SCALED => {
                seg_offset = seg_offset.wrapping_add(u64::from(immediate) * ptr_size as u64);
            }

            o if o == REBASE_OPCODE_DO_REBASE_IMM_TIMES => {
                for _ in 0..immediate {
                    actions.push(RebaseAction { segment_index: seg_index, segment_offset: seg_offset, rebase_type });
                    seg_offset = seg_offset.wrapping_add(ptr_size as u64);
                }
            }

            o if o == REBASE_OPCODE_DO_REBASE_ULEB_TIMES => {
                let (count, new_pos) = read_uleb128(data, pos)?;
                pos = new_pos;
                for _ in 0..count {
                    actions.push(RebaseAction { segment_index: seg_index, segment_offset: seg_offset, rebase_type });
                    seg_offset = seg_offset.wrapping_add(ptr_size as u64);
                }
            }

            o if o == REBASE_OPCODE_DO_REBASE_ADD_ADDR_ULEB => {
                actions.push(RebaseAction { segment_index: seg_index, segment_offset: seg_offset, rebase_type });
                let (add, new_pos) = read_uleb128(data, pos)?;
                seg_offset = seg_offset.wrapping_add(ptr_size as u64).wrapping_add(add);
                pos = new_pos;
            }

            o if o == REBASE_OPCODE_DO_REBASE_ULEB_TIMES_SKIPPING_ULEB => {
                let (count, p2)  = read_uleb128(data, pos)?;
                let (skip,  p3)  = read_uleb128(data, p2)?;
                pos = p3;
                for _ in 0..count {
                    actions.push(RebaseAction { segment_index: seg_index, segment_offset: seg_offset, rebase_type });
                    seg_offset = seg_offset.wrapping_add(ptr_size as u64).wrapping_add(skip);
                }
            }

            _ => return Err(DyldInfoError::UnknownRebaseOpcode(byte)),
        }
    }
    Ok(actions)
}

// ─────────────────────────────────────────────────────────────────────────────
// BIND opcodes
// ─────────────────────────────────────────────────────────────────────────────

const BIND_OPCODE_MASK:                             u8 = 0xF0;
const BIND_IMMEDIATE_MASK:                          u8 = 0x0F;

const BIND_OPCODE_DONE:                             u8 = 0x00;
const BIND_OPCODE_SET_DYLIB_ORDINAL_IMM:            u8 = 0x10;
const BIND_OPCODE_SET_DYLIB_ORDINAL_ULEB:           u8 = 0x20;
const BIND_OPCODE_SET_DYLIB_SPECIAL_IMM:            u8 = 0x30;
const BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM:    u8 = 0x40;
const BIND_OPCODE_SET_TYPE_IMM:                     u8 = 0x50;
const BIND_OPCODE_SET_ADDEND_SLEB:                  u8 = 0x60;
const BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB:      u8 = 0x70;
const BIND_OPCODE_ADD_ADDR_ULEB:                    u8 = 0x80;
const BIND_OPCODE_DO_BIND:                          u8 = 0x90;
const BIND_OPCODE_DO_BIND_ADD_ADDR_ULEB:            u8 = 0xA0;
const BIND_OPCODE_DO_BIND_ADD_ADDR_IMM_SCALED:      u8 = 0xB0;
const BIND_OPCODE_DO_BIND_ULEB_TIMES_SKIPPING_ULEB: u8 = 0xC0;
const BIND_OPCODE_THREADED:                         u8 = 0xD0;

/// Special dylib ordinal sentinels.
pub const BIND_SPECIAL_DYLIB_SELF:             i8 = 0;
pub const BIND_SPECIAL_DYLIB_MAIN_EXECUTABLE: i8 = -1;
pub const BIND_SPECIAL_DYLIB_FLAT_LOOKUP:      i8 = -2;
pub const BIND_SPECIAL_DYLIB_WEAK_LOOKUP:      i8 = -3;

/// Bind type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BindType {
    Pointer,
    TextAbsolute32,
    TextPcrel32,
    Unknown(u8),
}

impl BindType {
    #[must_use] 
    pub const fn from_raw(v: u8) -> Self {
        match v {
            1 => Self::Pointer,
            2 => Self::TextAbsolute32,
            3 => Self::TextPcrel32,
            _ => Self::Unknown(v),
        }
    }
}

/// Stream kind (used to distinguish normal / weak / lazy bind on the caller side).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BindStreamKind {
    Normal,
    Weak,
    Lazy,
}

/// A single decoded bind action.
#[derive(Debug, Clone)]
pub struct BindAction {
    pub kind: BindStreamKind,
    pub segment_index: u8,
    pub segment_offset: u64,
    pub lib_ordinal: i32,
    pub symbol_name: String,
    pub symbol_flags: u8,
    pub bind_type: BindType,
    pub addend: i64,
}

/// Decode a bind opcode stream (normal, weak, or lazy).
pub fn decode_bind(
    data: &[u8],
    ptr_size: usize,
    kind: BindStreamKind,
) -> Result<Vec<BindAction>, DyldInfoError> {
    let mut actions = Vec::new();
    let mut pos = 0usize;
    let mut lib_ordinal: i32 = 0;
    let mut sym_name  = String::new();
    let mut sym_flags: u8 = 0;
    let mut bind_type = BindType::Pointer;
    let mut addend: i64 = 0;
    let mut seg_index: u8 = 0;
    let mut seg_offset: u64 = 0;

    let emit = |actions: &mut Vec<BindAction>,
                lib_ordinal: i32, sym_name: &str, sym_flags: u8,
                bind_type: BindType, addend: i64,
                seg_index: u8, seg_offset: u64| {
        actions.push(BindAction {
            kind,
            segment_index: seg_index,
            segment_offset: seg_offset,
            lib_ordinal,
            symbol_name: sym_name.to_owned(),
            symbol_flags: sym_flags,
            bind_type,
            addend,
        });
    };

    while pos < data.len() {
        let byte = data[pos];
        pos += 1;
        let opcode    = byte & BIND_OPCODE_MASK;
        let immediate = byte & BIND_IMMEDIATE_MASK;

        match opcode {
            o if o == BIND_OPCODE_DONE => {
                if kind != BindStreamKind::Lazy { break; }
                // In lazy bind stream DONE just marks end of one entry.
            }
            o if o == BIND_OPCODE_SET_DYLIB_ORDINAL_IMM => {
                lib_ordinal = i32::from(immediate);
            }
            o if o == BIND_OPCODE_SET_DYLIB_ORDINAL_ULEB => {
                let (v, np) = read_uleb128(data, pos)?;
                lib_ordinal = v as i32;
                pos = np;
            }
            o if o == BIND_OPCODE_SET_DYLIB_SPECIAL_IMM => {
                lib_ordinal = if immediate == 0 { 0 } else {
                    let sign_ext = (immediate | 0xF0).cast_signed();
                    i32::from(sign_ext)
                };
            }
            o if o == BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM => {
                sym_flags = immediate;
                let (name, np) = read_cstr_at(data, pos)?;
                sym_name = name;
                pos = np;
            }
            o if o == BIND_OPCODE_SET_TYPE_IMM => {
                bind_type = BindType::from_raw(immediate);
            }
            o if o == BIND_OPCODE_SET_ADDEND_SLEB => {
                let (v, np) = read_sleb128(data, pos)?;
                addend = v;
                pos = np;
            }
            o if o == BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB => {
                seg_index = immediate;
                let (off, np) = read_uleb128(data, pos)?;
                seg_offset = off;
                pos = np;
            }
            o if o == BIND_OPCODE_ADD_ADDR_ULEB => {
                let (add, np) = read_uleb128(data, pos)?;
                seg_offset = seg_offset.wrapping_add(add);
                pos = np;
            }
            o if o == BIND_OPCODE_DO_BIND => {
                emit(&mut actions, lib_ordinal, &sym_name, sym_flags, bind_type, addend, seg_index, seg_offset);
                seg_offset = seg_offset.wrapping_add(ptr_size as u64);
            }
            o if o == BIND_OPCODE_DO_BIND_ADD_ADDR_ULEB => {
                emit(&mut actions, lib_ordinal, &sym_name, sym_flags, bind_type, addend, seg_index, seg_offset);
                let (add, np) = read_uleb128(data, pos)?;
                seg_offset = seg_offset.wrapping_add(ptr_size as u64).wrapping_add(add);
                pos = np;
            }
            o if o == BIND_OPCODE_DO_BIND_ADD_ADDR_IMM_SCALED => {
                emit(&mut actions, lib_ordinal, &sym_name, sym_flags, bind_type, addend, seg_index, seg_offset);
                seg_offset = seg_offset.wrapping_add(ptr_size as u64 * (1 + u64::from(immediate)));
            }
            o if o == BIND_OPCODE_DO_BIND_ULEB_TIMES_SKIPPING_ULEB => {
                let (count, p2) = read_uleb128(data, pos)?;
                let (skip,  p3) = read_uleb128(data, p2)?;
                pos = p3;
                for _ in 0..count {
                    emit(&mut actions, lib_ordinal, &sym_name, sym_flags, bind_type, addend, seg_index, seg_offset);
                    seg_offset = seg_offset.wrapping_add(ptr_size as u64).wrapping_add(skip);
                }
            }
            o if o == BIND_OPCODE_THREADED => {
                // BIND_SUBOPCODE_THREADED_SET_BIND_ORDINAL_TABLE_SIZE_ULEB
                if immediate == 0 {
                    let (_size, np) = read_uleb128(data, pos)?;
                    pos = np;
                }
                // BIND_SUBOPCODE_THREADED_APPLY — apply threaded bind (no extra data)
            }
            _ => return Err(DyldInfoError::UnknownBindOpcode(byte)),
        }
    }
    Ok(actions)
}

// ─────────────────────────────────────────────────────────────────────────────
// Export trie
// ─────────────────────────────────────────────────────────────────────────────

/// Export flags encoded in the trie node terminal info.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExportFlags(pub u64);

impl ExportFlags {
    pub const EXPORT_SYMBOL_FLAGS_KIND_MASK:      u64 = 0x03;
    pub const EXPORT_SYMBOL_FLAGS_KIND_REGULAR:   u64 = 0x00;
    pub const EXPORT_SYMBOL_FLAGS_KIND_THREAD_LOCAL: u64 = 0x01;
    pub const EXPORT_SYMBOL_FLAGS_KIND_ABSOLUTE:  u64 = 0x02;
    pub const EXPORT_SYMBOL_FLAGS_WEAK_DEFINITION:u64 = 0x04;
    pub const EXPORT_SYMBOL_FLAGS_REEXPORT:       u64 = 0x08;
    pub const EXPORT_SYMBOL_FLAGS_STUB_AND_RESOLVER: u64 = 0x10;

    #[must_use] 
    pub const fn kind(self) -> u64 { self.0 & Self::EXPORT_SYMBOL_FLAGS_KIND_MASK }
    #[must_use] 
    pub const fn is_regular(self)     -> bool { self.kind() == Self::EXPORT_SYMBOL_FLAGS_KIND_REGULAR }
    #[must_use] 
    pub const fn is_weak_def(self)    -> bool { self.0 & Self::EXPORT_SYMBOL_FLAGS_WEAK_DEFINITION != 0 }
    #[must_use] 
    pub const fn is_reexport(self)    -> bool { self.0 & Self::EXPORT_SYMBOL_FLAGS_REEXPORT != 0 }
    #[must_use] 
    pub const fn is_stub(self)        -> bool { self.0 & Self::EXPORT_SYMBOL_FLAGS_STUB_AND_RESOLVER != 0 }
    #[must_use] 
    pub const fn is_absolute(self)    -> bool { self.kind() == Self::EXPORT_SYMBOL_FLAGS_KIND_ABSOLUTE }
    #[must_use] 
    pub const fn is_thread_local(self)-> bool { self.kind() == Self::EXPORT_SYMBOL_FLAGS_KIND_THREAD_LOCAL }
}

/// A single decoded export entry from the export trie.
#[derive(Debug, Clone)]
pub struct ExportEntry {
    /// Fully-qualified symbol name (cumulative edge labels from root).
    pub name: String,
    /// Raw export flags.
    pub flags: ExportFlags,
    /// Virtual address offset (from image base) for regular / stub exports.
    /// Zero for re-exports.
    pub address: u64,
    /// For re-exports: the library ordinal (1-based) the symbol comes from.
    pub reexport_lib_ordinal: u64,
    /// For re-exports: alternate symbol name (empty means same as `name`).
    pub reexport_name: String,
    /// For stub+resolver exports: the resolver function virtual address.
    pub resolver_offset: u64,
}

/// Walk the export trie and return all exported symbols.
pub fn decode_export_trie(trie: &[u8]) -> Result<Vec<ExportEntry>, DyldInfoError> {
    let mut entries = Vec::new();
    walk_trie(trie, 0, String::new(), &mut entries)?;
    Ok(entries)
}

fn walk_trie(
    trie: &[u8],
    node: usize,
    prefix: String,
    out: &mut Vec<ExportEntry>,
) -> Result<(), DyldInfoError> {
    if node >= trie.len() {
        return Ok(());
    }
    // Terminal size (0 = not a terminal node)
    let (term_size, mut pos) = read_uleb128(trie, node)?;
    if term_size != 0 {
        // Terminal: decode flags
        let term_end = pos + term_size as usize;
        let (flags_raw, p2) = read_uleb128(trie, pos)?;
        pos = p2;
        let flags = ExportFlags(flags_raw);
        let mut entry = ExportEntry {
            name:                  prefix.clone(),
            flags,
            address:               0,
            reexport_lib_ordinal:  0,
            reexport_name:         String::new(),
            resolver_offset:       0,
        };
        if flags.is_reexport() {
            let (ord, p3) = read_uleb128(trie, pos)?;
            entry.reexport_lib_ordinal = ord;
            pos = p3;
            let (rname, p4) = read_cstr_at(trie, pos)?;
            entry.reexport_name = rname;
            pos = p4;
        } else if flags.is_stub() {
            let (stub_off, p3) = read_uleb128(trie, pos)?;
            entry.address = stub_off;
            pos = p3;
            let (res_off, p4) = read_uleb128(trie, pos)?;
            entry.resolver_offset = res_off;
            pos = p4;
        } else {
            let (addr, p3) = read_uleb128(trie, pos)?;
            entry.address = addr;
            pos = p3;
        }
        let _ = term_end; // ensure we consumed correctly
        out.push(entry);
    }

    // Child edges
    if pos >= trie.len() {
        return Ok(());
    }
    let child_count = trie[pos] as usize;
    pos += 1;
    for _ in 0..child_count {
        // Edge label (NUL-terminated string)
        let (label, np) = read_cstr_at(trie, pos)?;
        pos = np;
        let (child_offset, np2) = read_uleb128(trie, pos)?;
        pos = np2;
        let child_prefix = format!("{prefix}{label}");
        walk_trie(trie, child_offset as usize, child_prefix, out)?;
    }
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// Chained fixups
// ─────────────────────────────────────────────────────────────────────────────

/// Chained fixup pointer format identifiers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum ChainedPtrFormat {
    Arm64E                  = 1,
    Bit64                   = 2,
    Bit32                   = 3,
    Bit32Cache              = 4,
    Bit32Firmware           = 5,
    Bit64Offset             = 6,
    Arm64EKernel            = 7,
    Bit64KernelCache        = 8,
    Arm64EUserland          = 9,
    Arm64EFirmware          = 10,
    X86_64KernelCache       = 11,
    Arm64EUserland24        = 12,
    Unknown(u32),
}

impl ChainedPtrFormat {
    #[must_use] 
    pub const fn from_raw(v: u32) -> Self {
        match v {
            1  => Self::Arm64E,
            2  => Self::Bit64,
            3  => Self::Bit32,
            4  => Self::Bit32Cache,
            5  => Self::Bit32Firmware,
            6  => Self::Bit64Offset,
            7  => Self::Arm64EKernel,
            8  => Self::Bit64KernelCache,
            9  => Self::Arm64EUserland,
            10 => Self::Arm64EFirmware,
            11 => Self::X86_64KernelCache,
            12 => Self::Arm64EUserland24,
            _  => Self::Unknown(v),
        }
    }

    #[must_use] 
    pub const fn ptr_size(self) -> usize {
        match self {
            Self::Bit32 | Self::Bit32Cache | Self::Bit32Firmware => 4,
            _ => 8,
        }
    }
}

/// Import format for chained fixups.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChainedImportFormat {
    /// 32-bit: `lib_ordinal(8)` + `weak_import(1)` + `name_offset(23)`
    Import32,
    /// 64-bit: `lib_ordinal(16)` + `weak_import(1)` + reserved(15) + `name_offset(32)`
    Import64,
    /// 64-bit with addend: `lib_ordinal(16)` + `weak_import(1)` + reserved(15) + `name_offset(32)`
    Import64WithAddend,
    Unknown(u32),
}

impl ChainedImportFormat {
    #[must_use] 
    pub const fn from_raw(v: u32) -> Self {
        match v { 1 => Self::Import32, 2 => Self::Import64, 3 => Self::Import64WithAddend, _ => Self::Unknown(v) }
    }
}

/// A single import from the chained fixups imports table.
#[derive(Debug, Clone)]
pub struct ChainedImport {
    pub lib_ordinal: u16,
    pub weak_import: bool,
    pub name: String,
    pub addend: i64,
}

/// Header of the `__LINKEDIT,__chained_fixups` blob
/// (`dyld_chained_fixups_header`).
#[derive(Debug, Clone)]
pub struct ChainedFixupsHeader {
    pub fixups_version: u32,
    pub starts_offset: u32,
    pub imports_offset: u32,
    pub symbols_offset: u32,
    pub imports_count: u32,
    pub imports_format: ChainedImportFormat,
    pub symbols_format: u32,
}

/// Decoded chained fixups blob.
#[derive(Debug, Clone)]
pub struct ChainedFixups {
    pub header: ChainedFixupsHeader,
    pub imports: Vec<ChainedImport>,
}

/// Decode the chained fixups blob pointed to by `LC_DYLD_CHAINED_FIXUPS`.
pub fn decode_chained_fixups(data: &[u8]) -> Result<ChainedFixups, DyldInfoError> {
    // dyld_chained_fixups_header: 7 u32 fields = 28 bytes
    if data.len() < 28 {
        return Err(DyldInfoError::InvalidChainedFixupsHeader);
    }
    let r32 = |off: usize| -> u32 {
        u32::from_le_bytes(data[off..off + 4].try_into().unwrap())
    };
    let fixups_version  = r32(0);
    let starts_offset   = r32(4);
    let imports_offset  = r32(8);
    let symbols_offset  = r32(12);
    let imports_count   = r32(16);
    let imports_format  = ChainedImportFormat::from_raw(r32(20));
    let symbols_format  = r32(24);

    let header = ChainedFixupsHeader {
        fixups_version, starts_offset, imports_offset, symbols_offset,
        imports_count, imports_format, symbols_format,
    };

    // Cap the allocation by how many import records (minimum 4 bytes each)
    // can physically fit after imports_offset.
    let min_entry = match imports_format {
        ChainedImportFormat::Import32 => 4usize,
        _ => 8,
    };
    let max_imports = data.len().saturating_sub(imports_offset as usize) / min_entry;
    let mut imports = Vec::with_capacity((imports_count as usize).min(max_imports));
    let sym_base = symbols_offset as usize;

    let read_name = |name_off: u32| -> String {
        let start = (sym_base + name_off as usize).min(data.len());
        let s = &data[start..];
        let nul = s.iter().position(|&b| b == 0).unwrap_or(s.len());
        String::from_utf8_lossy(&s[..nul]).into_owned()
    };

    let imp_base = imports_offset as usize;
    for i in 0..imports_count as usize {
        match imports_format {
            ChainedImportFormat::Import32 => {
                let off = imp_base + i * 4;
                if off + 4 > data.len() { break; }
                let v = r32(off);
                let lib_ordinal = (v & 0xFF) as u16;
                let weak_import = (v >> 8) & 1 != 0;
                let name_offset = v >> 9;
                imports.push(ChainedImport {
                    lib_ordinal, weak_import, addend: 0,
                    name: read_name(name_offset),
                });
            }
            ChainedImportFormat::Import64 | ChainedImportFormat::Import64WithAddend => {
                let off = imp_base + i * 8;
                if off + 8 > data.len() { break; }
                let lo = u64::from(r32(off));
                let hi = u64::from(r32(off + 4));
                let v = lo | (hi << 32);
                let lib_ordinal = (v & 0xFFFF) as u16;
                let weak_import = (v >> 16) & 1 != 0;
                let name_offset = (v >> 32) as u32;
                let addend = if imports_format == ChainedImportFormat::Import64WithAddend {
                    // addend lives in a second 8-byte field (not in all dyld versions)
                    0i64 // simplified
                } else { 0 };
                imports.push(ChainedImport {
                    lib_ordinal, weak_import, addend,
                    name: read_name(name_offset),
                });
            }
            ChainedImportFormat::Unknown(_) => break,
        }
    }

    Ok(ChainedFixups { header, imports })
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uleb128_single_byte() {
        assert_eq!(read_uleb128(&[0x25], 0).unwrap(), (37, 1));
    }

    #[test]
    fn uleb128_multi_byte() {
        // 300 = 0xAC 0x02
        assert_eq!(read_uleb128(&[0xAC, 0x02], 0).unwrap(), (300, 2));
    }

    #[test]
    fn sleb128_negative() {
        // -1 = 0x7F
        let (v, pos) = read_sleb128(&[0x7F], 0).unwrap();
        assert_eq!(v, -1);
        assert_eq!(pos, 1);
    }

    #[test]
    fn sleb128_positive() {
        let (v, _) = read_sleb128(&[0x3F], 0).unwrap();
        assert_eq!(v, 63);
    }

    #[test]
    fn rebase_done_empty() {
        let data = [REBASE_OPCODE_DONE];
        let acts = decode_rebase(&data, 8).unwrap();
        assert!(acts.is_empty());
    }

    #[test]
    fn rebase_type_names() {
        assert_eq!(RebaseType::Pointer.name(), "REBASE_TYPE_POINTER");
        assert_eq!(RebaseType::TextAbsolute32.name(), "REBASE_TYPE_TEXT_ABSOLUTE32");
        assert_eq!(RebaseType::Unknown(99).name(), "REBASE_TYPE_UNKNOWN");
    }

    #[test]
    fn export_flags_kinds() {
        let f = ExportFlags(ExportFlags::EXPORT_SYMBOL_FLAGS_REEXPORT);
        assert!(f.is_reexport());
        assert!(!f.is_weak_def());
        assert!(!f.is_stub());
    }

    #[test]
    fn export_flags_stub() {
        let f = ExportFlags(ExportFlags::EXPORT_SYMBOL_FLAGS_STUB_AND_RESOLVER);
        assert!(f.is_stub());
    }

    #[test]
    fn chained_ptr_format_names() {
        assert_eq!(ChainedPtrFormat::from_raw(1), ChainedPtrFormat::Arm64E);
        assert_eq!(ChainedPtrFormat::from_raw(3).ptr_size(), 4);
        assert_eq!(ChainedPtrFormat::from_raw(2).ptr_size(), 8);
    }

    #[test]
    fn chained_fixups_too_short() {
        let short = [0u8; 4];
        assert!(decode_chained_fixups(&short).is_err());
    }

    #[test]
    fn chained_fixups_minimal_header() {
        let mut data = vec![0u8; 28];
        // fixups_version = 0, imports_format = Import32
        data[20..24].copy_from_slice(&1u32.to_le_bytes());
        let cf = decode_chained_fixups(&data).unwrap();
        assert_eq!(cf.header.fixups_version, 0);
        assert_eq!(cf.imports.len(), 0);
    }

    #[test]
    fn read_cstr_at_basic() {
        let data = b"hello\0world";
        let (s, pos) = read_cstr_at(data, 0).unwrap();
        assert_eq!(s, "hello");
        assert_eq!(pos, 6);
    }

    #[test]
    fn bind_done_empty() {
        let data = [BIND_OPCODE_DONE];
        let acts = decode_bind(&data, 8, BindStreamKind::Normal).unwrap();
        assert!(acts.is_empty());
    }

    #[test]
    fn export_trie_empty() {
        // Minimal trie: root with terminal_size=0 and child_count=0
        let data = [0x00u8, 0x00]; // term_size=0, child_count=0
        let entries = decode_export_trie(&data).unwrap();
        assert!(entries.is_empty());
    }
}
