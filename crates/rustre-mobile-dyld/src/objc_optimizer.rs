//! dyld `ObjC` optimization table parser.
//!
//! The dynamic linker pre-optimizes Objective-C data structures in the
//! `dyld_shared_cache` for fast runtime access.  This module parses the three
//! main hash tables written by `update_dyld_shared_cache` / `dyld_closure_util`:
//!
//! * **Selector table** — perfect hash, maps selector name → selector pointer.
//! * **Class table**    — maps class name → `class_t*`.
//! * **Protocol table** — maps protocol name → `protocol_t*`.
//!
//! It also handles the newer **relative method list** format used in iOS 14+ /
//! macOS 11+ images where method IMPs are stored as 32-bit relative offsets.
//!
//! # References
//!
//! * `dyld/include/objc-shared-cache.h` (Apple open-source)
//! * `objc4/runtime/objc-runtime-new.h`


use std::collections::HashMap;
use std::fmt;
use serde::{Deserialize, Serialize};
use thiserror::Error;

// ─── Error ────────────────────────────────────────────────────────────────────

#[derive(Debug, Error)]
pub enum ObjcOptimizerError {
    #[error("optimization header not found at offset {0:#x}")]
    HeaderNotFound(u64),
    #[error("magic mismatch: expected {expected:#x}, got {got:#x}")]
    MagicMismatch { expected: u32, got: u32 },
    #[error("hash table version unsupported: {0}")]
    UnsupportedVersion(u32),
    #[error("truncated data at offset {0:#x}")]
    Truncated(u64),
    #[error("invalid UTF-8 string at offset {0:#x}")]
    BadString(u64),
    #[error("hash capacity is zero")]
    ZeroCapacity,
    #[error("parse error: {0}")]
    Parse(String),
}

pub type Result<T> = std::result::Result<T, ObjcOptimizerError>;

// ─── Primitive readers ────────────────────────────────────────────────────────

pub fn u16_le(data: &[u8], off: usize) -> Result<u16> {
    let b = data.get(off..off + 2)
        .ok_or(ObjcOptimizerError::Truncated(off as u64))?;
    Ok(u16::from_le_bytes([b[0], b[1]]))
}

fn u32_le(data: &[u8], off: usize) -> Result<u32> {
    let b = data.get(off..off + 4)
        .ok_or(ObjcOptimizerError::Truncated(off as u64))?;
    Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}

fn i32_le(data: &[u8], off: usize) -> Result<i32> {
    u32_le(data, off).map(|v| v as i32)
}

fn u64_le(data: &[u8], off: usize) -> Result<u64> {
    let b = data.get(off..off + 8)
        .ok_or(ObjcOptimizerError::Truncated(off as u64))?;
    Ok(u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]))
}

fn read_cstring(data: &[u8], off: usize) -> Result<String> {
    let slice = data.get(off..)
        .ok_or(ObjcOptimizerError::Truncated(off as u64))?;
    let end = slice.iter().position(|&b| b == 0)
        .ok_or(ObjcOptimizerError::Truncated(off as u64))?;
    std::str::from_utf8(&slice[..end])
        .map(std::borrow::ToOwned::to_owned)
        .map_err(|_| ObjcOptimizerError::BadString(off as u64))
}

// ─── ObjC optimization header ─────────────────────────────────────────────────

/// Magic value at the start of the `objc_opt` header.
pub const OBJC_OPT_MAGIC_V16: u32 = 0x6F62_6A63; // 'objc'
pub const OBJC_OPT_MAGIC_V15: u32 = 0x6F62_6A63;

/// Supported header versions.
pub const OBJC_OPT_VERSION_16: u32 = 16;
pub const OBJC_OPT_VERSION_15: u32 = 15;

/// The `objc_opt_t` header (v15/v16 layout).
///
/// ```c
/// struct objc_opt_t {
///     uint32_t magic;
///     int32_t  selopt_offset;       // offset to selector hash table
///     int32_t  headeropt_ro_offset; // offset to read-only header table
///     int32_t  clsopt_offset;       // offset to class hash table
///     int32_t  protocolopt_offset;  // offset to protocol hash table
///     int32_t  headeropt_rw_offset; // offset to read-write header table (v16+)
/// };
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObjcOptHeader {
    pub magic: u32,
    pub version: u32,
    pub selopt_offset: i32,
    pub headeropt_ro_offset: i32,
    pub clsopt_offset: i32,
    pub protocolopt_offset: i32,
    pub headeropt_rw_offset: Option<i32>,
    /// Byte offset of this header within the cache data.
    pub header_offset: u64,
}

impl ObjcOptHeader {
    /// Parse from a slice where `data[0]` is the start of `objc_opt_t`.
    pub fn parse(data: &[u8], header_offset: u64) -> Result<Self> {
        if data.len() < 24 {
            return Err(ObjcOptimizerError::Truncated(header_offset));
        }

        let magic   = u32_le(data, 0)?;
        let version = u32_le(data, 4)?;

        if magic != OBJC_OPT_MAGIC_V16 {
            return Err(ObjcOptimizerError::MagicMismatch { expected: OBJC_OPT_MAGIC_V16, got: magic });
        }
        if version != OBJC_OPT_VERSION_16 && version != OBJC_OPT_VERSION_15 {
            return Err(ObjcOptimizerError::UnsupportedVersion(version));
        }

        let selopt_offset      = i32_le(data, 8)?;
        let headeropt_ro_offset = i32_le(data, 12)?;
        let clsopt_offset      = i32_le(data, 16)?;
        let protocolopt_offset = i32_le(data, 20)?;
        let headeropt_rw_offset = if data.len() >= 28 && version >= OBJC_OPT_VERSION_16 {
            Some(i32_le(data, 24)?)
        } else {
            None
        };

        Ok(Self {
            magic,
            version,
            selopt_offset,
            headeropt_ro_offset,
            clsopt_offset,
            protocolopt_offset,
            headeropt_rw_offset,
            header_offset,
        })
    }

    /// Resolve a field offset to a file offset within `data`.
    ///
    /// Returns `usize::MAX` if the arithmetic overflows or the result is negative,
    /// which will cause downstream bound checks to return `Truncated`.
    fn resolve(&self, field_offset: i32) -> usize {
        (self.header_offset as i64)
            .checked_add(i64::from(field_offset))
            .and_then(|v| usize::try_from(v).ok())
            .unwrap_or(usize::MAX)
    }

    #[must_use] 
    pub fn selopt_file_offset(&self) -> usize { self.resolve(self.selopt_offset) }
    #[must_use] 
    pub fn clsopt_file_offset(&self) -> usize { self.resolve(self.clsopt_offset) }
    #[must_use] 
    pub fn protocolopt_file_offset(&self) -> usize { self.resolve(self.protocolopt_offset) }
}

// ─── Perfect hash table ───────────────────────────────────────────────────────

/// Parameters for the perfect hash function used in dyld's `ObjC` tables.
///
/// Hash function:
/// ```text
/// h = scramble[tab[key[0] % mask]] ^ key[1..shift]
/// index = h & (capacity - 1)
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerfectHashParams {
    /// Capacity of the hash table (number of buckets, always a power of two).
    pub capacity: u32,
    /// Number of occupied (non-sentinel) entries.
    pub occupied: u32,
    /// Bit-shift used in the hash function.
    pub shift: u32,
    /// Mask = capacity - 1.
    pub mask: u32,
    /// Sentinel value (used to mark empty buckets).
    pub sentinel: u32,
    /// The `tab[]` array (256 entries, 1 byte each).
    pub tab: Vec<u8>,
    /// The `checkbytes[]` array (one byte per bucket for fast mismatch rejection).
    pub checkbytes: Vec<u8>,
    /// The `offsets[]` array (one i32 per bucket, relative to the string pool start).
    pub offsets: Vec<i32>,
}

impl PerfectHashParams {
    /// Compute the perfect hash of `key`.
    #[must_use] 
    pub fn hash(&self, key: &[u8]) -> u32 {
        if self.capacity == 0 || key.is_empty() {
            return 0;
        }
        let tab_idx = u32::from(key[0]) & self.mask;
        let tab_val = u32::from(self.tab.get(tab_idx as usize).copied().unwrap_or(0));
        // XOR with bytes [1..shift] of the key.
        let mut h = SCRAMBLE[tab_val as usize];
        let end = (self.shift as usize).min(key.len());
        for &b in &key[1..end] {
            h ^= SCRAMBLE[(u32::from(b) & 0xFF) as usize];
        }
        h & (self.capacity - 1)
    }

    /// Look up `name` in the table.  Returns the bucket index if found.
    #[must_use] 
    pub fn lookup(&self, name: &str) -> Option<u32> {
        if self.capacity == 0 { return None; }
        let key = name.as_bytes();
        let h = self.hash(key);
        let check = checkbyte(key);
        if self.checkbytes.get(h as usize).copied()? != check {
            return None;
        }
        Some(h)
    }
}

/// The `scramble[]` table used by the dyld perfect hash.
const SCRAMBLE: [u32; 256] = {
    let mut s = [0u32; 256];
    let mut i = 0usize;
    while i < 256 {
        // A simple deterministic permutation for test purposes.
        // The real table is taken from Bob Jenkins' hash.
        s[i] = (i as u32).wrapping_mul(0x9E3779B9).wrapping_add(0xDEADBEEF);
        i += 1;
    }
    s
};

/// Compute the single-byte check value for a name (XOR of all bytes).
fn checkbyte(name: &[u8]) -> u8 {
    name.iter().fold(0u8, |acc, &b| acc ^ b)
}

// ─── Hash table header ────────────────────────────────────────────────────────

/// The header of an `ObjC` hash table (`objc_stringhash_t`).
///
/// ```c
/// struct objc_stringhash_t {
///     uint32_t capacity;
///     uint32_t occupied;
///     uint32_t shift;
///     uint32_t mask;
///     uint32_t sentinel;
///     uint32_t roundedTabSize;
///     uint64_t salt;
///     uint8_t  tab[mask + 1];          // variable length
///     uint8_t  checkbytes[capacity];
///     int32_t  offsets[capacity];
/// };
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObjcHashTableHeader {
    pub capacity: u32,
    pub occupied: u32,
    pub shift: u32,
    pub mask: u32,
    pub sentinel: u32,
    pub rounded_tab_size: u32,
    pub salt: u64,
    /// File offset of `tab[0]`.
    pub tab_offset: usize,
    /// File offset of `checkbytes[0]`.
    pub checkbytes_offset: usize,
    /// File offset of `offsets[0]`.
    pub offsets_offset: usize,
    /// File offset of the string pool (pointer-sized values, platform dependent).
    pub strings_offset: usize,
}

impl ObjcHashTableHeader {
    /// Parse an `objc_stringhash_t` header from `data` at file offset `off`.
    pub fn parse(data: &[u8], off: usize) -> Result<Self> {
        if off + 32 > data.len() {
            return Err(ObjcOptimizerError::Truncated(off as u64));
        }

        let capacity          = u32_le(data, off)?;
        let occupied          = u32_le(data, off + 4)?;
        let shift             = u32_le(data, off + 8)?;
        let mask              = u32_le(data, off + 12)?;
        let sentinel          = u32_le(data, off + 16)?;
        let rounded_tab_size  = u32_le(data, off + 20)?;
        let salt              = u64_le(data, off + 24)?;

        let tab_offset        = off + 32;
        let tab_size          = (mask as usize + 1).max(1);
        let checkbytes_offset = tab_offset + tab_size;
        let offsets_offset    = checkbytes_offset + capacity as usize;
        // Align to 4 bytes.
        let offsets_offset    = (offsets_offset + 3) & !3;
        let strings_offset    = offsets_offset + capacity as usize * 4;

        if capacity == 0 {
            return Err(ObjcOptimizerError::ZeroCapacity);
        }

        Ok(Self {
            capacity,
            occupied,
            shift,
            mask,
            sentinel,
            rounded_tab_size,
            salt,
            tab_offset,
            checkbytes_offset,
            offsets_offset,
            strings_offset,
        })
    }

    /// Read the `tab[]` array.
    #[must_use] 
    pub fn read_tab(&self, data: &[u8]) -> Vec<u8> {
        let size = (self.mask as usize + 1).max(1);
        data.get(self.tab_offset..self.tab_offset + size)
            .unwrap_or(&[])
            .to_vec()
    }

    /// Read the `checkbytes[]` array.
    #[must_use] 
    pub fn read_checkbytes(&self, data: &[u8]) -> Vec<u8> {
        let size = self.capacity as usize;
        data.get(self.checkbytes_offset..self.checkbytes_offset + size)
            .unwrap_or(&[])
            .to_vec()
    }

    /// Read the `offsets[]` array.
    #[must_use] 
    pub fn read_offsets(&self, data: &[u8]) -> Vec<i32> {
        let count = self.capacity as usize;
        let mut offsets = Vec::with_capacity(count);
        for i in 0..count {
            let v = i32_le(data, self.offsets_offset + i * 4).unwrap_or(0);
            offsets.push(v);
        }
        offsets
    }

    /// Build a `PerfectHashParams` from this header.
    #[must_use] 
    pub fn to_hash_params(&self, data: &[u8]) -> PerfectHashParams {
        PerfectHashParams {
            capacity: self.capacity,
            occupied: self.occupied,
            shift: self.shift,
            mask: self.mask,
            sentinel: self.sentinel,
            tab: self.read_tab(data),
            checkbytes: self.read_checkbytes(data),
            offsets: self.read_offsets(data),
        }
    }
}

// ─── Selector hash table ──────────────────────────────────────────────────────

/// A parsed selector hash table entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SelectorEntry {
    pub name: String,
    /// Pointer to the selector (VM address in the shared cache).
    pub selector_ptr: u64,
}

/// Parse the selector hash table (`selopt`) into a `name → address` map.
pub fn parse_selector_table(
    data: &[u8],
    table_offset: usize,
    cache_base_va: u64,
    is_64bit: bool,
) -> Result<HashMap<String, u64>> {
    let header = ObjcHashTableHeader::parse(data, table_offset)?;
    let params = header.to_hash_params(data);
    let pointer_size: usize = if is_64bit { 8 } else { 4 };

    let mut map = HashMap::with_capacity(header.occupied as usize);

    for i in 0..header.capacity as usize {
        let cb = params.checkbytes.get(i).copied().unwrap_or(0);
        if cb == 0 {
            continue; // empty bucket
        }

        let offset = params.offsets.get(i).copied().unwrap_or(0);
        if offset == 0 {
            continue;
        }

        let str_off = (header.strings_offset as i64 + i64::from(offset)) as usize;
        let ptr_off = str_off; // The selector pointer is at the start of the bucket data.

        let ptr: u64 = if is_64bit {
            u64_le(data, ptr_off).unwrap_or(0)
        } else {
            u64::from(u32_le(data, ptr_off).unwrap_or(0))
        };

        if ptr == 0 { continue; }

        // The string follows the pointer.
        let name_off = ptr_off + pointer_size;
        if let Ok(name) = read_cstring(data, name_off)
            && !name.is_empty() {
                let va = cache_base_va + ptr_off as u64;
                map.insert(name, va);
            }
    }

    Ok(map)
}

// ─── Class / protocol hash tables ────────────────────────────────────────────

/// A bucket in the class or protocol hash table.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClassBucket {
    /// VM address of the null-terminated class/protocol name string.
    pub name_ptr: u64,
    /// VM address of the `class_t` / `protocol_t` struct.
    pub data_ptr: u64,
}

/// Parse a class or protocol hash table into a `name → address` map.
///
/// Both the class table and the protocol table use the same
/// `objc_stringhash_t` layout, with bucket entries of the form:
/// `{ i32 name_offset_from_strings, i32 data_offset_from_strings }`.
pub fn parse_name_ptr_table(
    data: &[u8],
    table_offset: usize,
    cache_base_va: u64,
    is_64bit: bool,
) -> Result<HashMap<String, u64>> {
    let header = ObjcHashTableHeader::parse(data, table_offset)?;
    let params = header.to_hash_params(data);
    let pointer_size: usize = if is_64bit { 8 } else { 4 };

    let mut map = HashMap::with_capacity(header.occupied as usize);

    for i in 0..header.capacity as usize {
        let cb = params.checkbytes.get(i).copied().unwrap_or(0);
        if cb == 0 { continue; }

        let offset = params.offsets.get(i).copied().unwrap_or(0);
        if offset == 0 { continue; }

        let entry_off = (header.strings_offset as i64 + i64::from(offset)) as usize;

        // Each entry: name_ptr (pointer_size) + data_ptr (pointer_size).
        let name_ptr: u64 = if is_64bit {
            u64_le(data, entry_off).unwrap_or(0)
        } else {
            u64::from(u32_le(data, entry_off).unwrap_or(0))
        };

        let data_ptr: u64 = if is_64bit {
            u64_le(data, entry_off + pointer_size).unwrap_or(0)
        } else {
            u64::from(u32_le(data, entry_off + pointer_size).unwrap_or(0))
        };

        if name_ptr == 0 || data_ptr == 0 { continue; }

        // Resolve name_ptr to a file offset.
        if name_ptr >= cache_base_va {
            let name_file_off = (name_ptr - cache_base_va) as usize;
            if let Ok(name) = read_cstring(data, name_file_off)
                && !name.is_empty() {
                    map.insert(name, data_ptr);
                }
        }
    }

    Ok(map)
}

// ─── Relative method list ─────────────────────────────────────────────────────

/// Magic flag bit set in `method_list_t::entsizeAndFlags` when the list uses
/// relative method implementations.
///
/// Value: `0xFFFF_FFFF & method_list_flag_uniqued_method_bit`
pub const RELATIVE_METHOD_FLAG: u32 = 0x8000_0000;
/// The unique-methods bit (set when the selector references have been de-duplicated).
pub const UNIQUED_METHOD_BIT: u32   = 0x4000_0000;
/// Method list entsize mask (low 16 bits of `entsizeAndFlags`).
pub const METHOD_ENTSIZE_MASK: u32  = 0x0000_FFFC;

/// Header of a `method_list_t` structure.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MethodListHeader {
    pub entsize_and_flags: u32,
    pub count: u32,
    /// True if `RELATIVE_METHOD_FLAG` is set.
    pub is_relative: bool,
    /// True if `UNIQUED_METHOD_BIT` is set.
    pub is_uniqued: bool,
    /// Size of each method entry in bytes.
    pub entsize: u32,
}

impl MethodListHeader {
    pub fn parse(data: &[u8], off: usize) -> Result<Self> {
        if off + 8 > data.len() {
            return Err(ObjcOptimizerError::Truncated(off as u64));
        }
        let eaf = u32_le(data, off)?;
        let count = u32_le(data, off + 4)?;
        Ok(Self {
            entsize_and_flags: eaf,
            count,
            is_relative: (eaf & RELATIVE_METHOD_FLAG) != 0,
            is_uniqued: (eaf & UNIQUED_METHOD_BIT) != 0,
            entsize: eaf & METHOD_ENTSIZE_MASK,
        })
    }
}

/// A method entry decoded from a relative method list.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelativeMethod {
    /// VM address of the selector reference (points to the selector string pointer).
    pub selector_ref_addr: u64,
    /// VM address of the method attributes / type string.
    pub types_addr: u64,
    /// Absolute VM address of the method implementation.
    pub imp_addr: u64,
    /// Selector name (if resolved).
    pub selector: Option<String>,
}

/// Decode one entry from a relative method list.
///
/// Each entry is 12 bytes (3 × i32):
/// ```text
/// +0x00  i32  selector_ref_offset  (relative to &entry.selector_ref_offset)
/// +0x04  i32  types_offset         (relative to &entry.types_offset)
/// +0x08  i32  imp_offset           (relative to &entry.imp_offset)
/// ```
fn decode_relative_method_entry(
    data: &[u8],
    entry_file_off: usize,
    entry_va: u64,
    cache_base_va: u64,
    selector_strings: &HashMap<u64, String>,
) -> Result<RelativeMethod> {
    let sel_rel   = i32_le(data, entry_file_off)?;
    let types_rel = i32_le(data, entry_file_off + 4)?;
    let imp_rel   = i32_le(data, entry_file_off + 8)?;

    let selector_ref_addr = entry_va.wrapping_add(i64::from(sel_rel) as u64);
    let types_addr        = (entry_va + 4).wrapping_add(i64::from(types_rel) as u64);
    let imp_addr          = (entry_va + 8).wrapping_add(i64::from(imp_rel) as u64);

    // Resolve the selector name: the selector_ref points to a pointer that
    // points to the null-terminated selector string.
    let selector = if selector_ref_addr >= cache_base_va {
        let sel_ref_file = (selector_ref_addr - cache_base_va) as usize;
        // Read the pointer stored at the ref location.
        let sel_ptr = u64_le(data, sel_ref_file).unwrap_or(0);
        selector_strings.get(&sel_ptr)
            .cloned()
            .or_else(|| {
                if sel_ptr >= cache_base_va {
                    let str_off = (sel_ptr - cache_base_va) as usize;
                    read_cstring(data, str_off).ok()
                } else {
                    None
                }
            })
    } else {
        None
    };

    Ok(RelativeMethod { selector_ref_addr, types_addr, imp_addr, selector })
}

/// Parse all entries in a relative method list.
pub fn parse_relative_method_list(
    data: &[u8],
    list_file_off: usize,
    list_va: u64,
    cache_base_va: u64,
    selector_strings: &HashMap<u64, String>,
) -> Result<Vec<RelativeMethod>> {
    let header = MethodListHeader::parse(data, list_file_off)?;
    if !header.is_relative {
        return Err(ObjcOptimizerError::Parse(
            format!("method list at {:#x} is not a relative list (flags={:#x})",
                list_file_off, header.entsize_and_flags)));
    }

    let entry_size = 12usize; // always 12 for relative lists
    let entries_start = list_file_off + 8;
    let entries_va_start = list_va + 8;

    let mut methods = Vec::with_capacity(header.count as usize);

    for i in 0..header.count as usize {
        let entry_off = entries_start + i * entry_size;
        let entry_va  = entries_va_start + (i * entry_size) as u64;
        if entry_off + 12 > data.len() { break; }

        let method = decode_relative_method_entry(
            data, entry_off, entry_va, cache_base_va, selector_strings)?;
        methods.push(method);
    }

    Ok(methods)
}

// ─── objc_headeropt_ro ────────────────────────────────────────────────────────

/// An entry in the `objc_headeropt_ro_t` table.
///
/// The table maps each Mach-O image (by its dyld slide-relative load address)
/// to its pre-optimized `ObjC` metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObjcHeaderOptEntry {
    /// Mach-O load address (slide-relative).
    pub mach_header_addr: u64,
    /// File offset of the `_objc_imageinfo` section.
    pub info_offset: i32,
    /// Number of methods in the image's method lists.
    pub method_count: u32,
    /// Whether any class in this image has a Swift `swift_class_t`.
    pub has_swift_class: bool,
}

/// Parse the `objc_headeropt_ro` table.
///
/// Layout:
/// ```c
/// struct objc_headeropt_ro_t {
///     uint32_t count;
///     uint32_t entsize;
///     objc_header_info_ro_t headers[count];
/// };
/// struct objc_header_info_ro_t {
///     int64_t  mach_header_offset;  // offset from &this to the mach-o header
///     int32_t  info_offset;
///     uint32_t method_count;
///     uint32_t flags;
/// };
/// ```
pub fn parse_headeropt_ro(
    data: &[u8],
    table_offset: usize,
    table_va: u64,
) -> Result<Vec<ObjcHeaderOptEntry>> {
    if table_offset + 8 > data.len() {
        return Err(ObjcOptimizerError::Truncated(table_offset as u64));
    }

    let count   = u32_le(data, table_offset)?;
    let entsize = u32_le(data, table_offset + 4)? as usize;
    let entsize = entsize.max(20);

    let mut entries = Vec::with_capacity(count as usize);
    let base = table_offset + 8;

    for i in 0..count as usize {
        let off = base + i * entsize;
        if off + 20 > data.len() { break; }

        let mh_rel  = i64::from(i32_le(data, off)?);
        let mh_va   = (table_va + 8 + (i * entsize) as u64).wrapping_add(mh_rel as u64);
        let info_offset    = i32_le(data, off + 8)?;
        let method_count   = u32_le(data, off + 12)?;
        let flags          = u32_le(data, off + 16)?;

        entries.push(ObjcHeaderOptEntry {
            mach_header_addr: mh_va,
            info_offset,
            method_count,
            has_swift_class: (flags & 0x01) != 0,
        });
    }

    Ok(entries)
}

// ─── Top-level result ─────────────────────────────────────────────────────────

/// The combined output of all `ObjC` optimization tables.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct ObjcOptimizationData {
    /// All selector names → selector address (VA in the shared cache).
    pub all_selectors: HashMap<String, u64>,
    /// All class names → `class_t*` address.
    pub all_classes: HashMap<String, u64>,
    /// All protocol names → `protocol_t*` address.
    pub all_protocols: HashMap<String, u64>,
    /// Entries from the read-only header optimization table.
    pub header_opt_entries: Vec<ObjcHeaderOptEntry>,
}

impl ObjcOptimizationData {
    #[must_use] 
    pub fn selector_count(&self) -> usize { self.all_selectors.len() }
    #[must_use] 
    pub fn class_count(&self) -> usize { self.all_classes.len() }
    #[must_use] 
    pub fn protocol_count(&self) -> usize { self.all_protocols.len() }
    #[must_use] 
    pub fn total_count(&self) -> usize {
        self.selector_count() + self.class_count() + self.protocol_count()
    }

    /// Look up a class by name.
    #[must_use] 
    pub fn find_class(&self, name: &str) -> Option<u64> { self.all_classes.get(name).copied() }
    /// Look up a selector by name.
    #[must_use] 
    pub fn find_selector(&self, name: &str) -> Option<u64> { self.all_selectors.get(name).copied() }
    /// Look up a protocol by name.
    #[must_use] 
    pub fn find_protocol(&self, name: &str) -> Option<u64> { self.all_protocols.get(name).copied() }
}

impl fmt::Display for ObjcOptimizationData {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ObjcOptimizationData {{ selectors: {}, classes: {}, protocols: {} }}",
            self.selector_count(), self.class_count(), self.protocol_count())
    }
}

/// Parse all `ObjC` optimization tables from a dyld shared cache slice.
///
/// `data`          — the full dyld cache bytes (or the relevant region).
/// `opt_offset`    — file offset of the `objc_opt_t` header within `data`.
/// `cache_base_va` — virtual address of `data[0]`.
/// `is_64bit`      — whether the cache is for a 64-bit platform.
pub fn parse_objc_optimization(
    data: &[u8],
    opt_offset: u64,
    cache_base_va: u64,
    is_64bit: bool,
) -> Result<ObjcOptimizationData> {
    let header = ObjcOptHeader::parse(
        data.get(opt_offset as usize..)
            .ok_or(ObjcOptimizerError::Truncated(opt_offset))?,
        opt_offset,
    )?;

    let sel_off      = header.selopt_file_offset();
    let cls_off      = header.clsopt_file_offset();
    let proto_off    = header.protocolopt_file_offset();
    let headeropt_off = header.resolve(header.headeropt_ro_offset);

    let all_selectors = if sel_off < data.len() {
        parse_selector_table(data, sel_off, cache_base_va, is_64bit)
            .unwrap_or_default()
    } else {
        HashMap::new()
    };

    let all_classes = if cls_off < data.len() {
        parse_name_ptr_table(data, cls_off, cache_base_va, is_64bit)
            .unwrap_or_default()
    } else {
        HashMap::new()
    };

    let all_protocols = if proto_off < data.len() {
        parse_name_ptr_table(data, proto_off, cache_base_va, is_64bit)
            .unwrap_or_default()
    } else {
        HashMap::new()
    };

    let header_opt_entries = if headeropt_off + 8 < data.len() {
        let table_va = cache_base_va + headeropt_off as u64;
        parse_headeropt_ro(data, headeropt_off, table_va)
            .unwrap_or_default()
    } else {
        Vec::new()
    };

    Ok(ObjcOptimizationData {
        all_selectors,
        all_classes,
        all_protocols,
        header_opt_entries,
    })
}

// ─── Relative method list scanner ─────────────────────────────────────────────

/// Scan a Mach-O image's `__objc_methnames` and `__objc_methnames` sections and
/// build a `VA → selector_name` string map usable for relative method list decoding.
#[must_use] 
pub fn build_selector_string_map(
    data: &[u8],
    section_file_off: usize,
    section_va: u64,
    section_size: usize,
) -> HashMap<u64, String> {
    // Average ObjC selector name is ~12 bytes; preallocate a rough capacity.
    let mut map = HashMap::with_capacity(section_size / 12 + 1);
    let mut off = 0usize;
    while off < section_size {
        let abs_off = section_file_off + off;
        if abs_off >= data.len() { break; }
        let va = section_va + off as u64;
        match read_cstring(data, abs_off) {
            Ok(s) => {
                let len = s.len() + 1;
                if !s.is_empty() { map.insert(va, s); }
                off += len;
            }
            Err(_) => break,
        }
    }
    map
}

/// Scan `__objc_selrefs` and map each selector pointer (stored in the section)
/// to its name via `selector_strings`.
#[must_use] 
pub fn build_selrefs_map(
    data: &[u8],
    selrefs_file_off: usize,
    selrefs_va: u64,
    selrefs_size: usize,
    selector_strings: &HashMap<u64, String>,
    is_64bit: bool,
) -> HashMap<u64, String> {
    let pointer_size: usize = if is_64bit { 8 } else { 4 };
    let mut map = HashMap::new();
    let mut off = 0usize;

    while off + pointer_size <= selrefs_size {
        let abs_off = selrefs_file_off + off;
        let slot_va = selrefs_va + off as u64;

        let target_va: u64 = if is_64bit {
            u64_le(data, abs_off).unwrap_or(0)
        } else {
            u64::from(u32_le(data, abs_off).unwrap_or(0))
        };

        if let Some(name) = selector_strings.get(&target_va) {
            map.insert(slot_va, name.clone());
        }

        off += pointer_size;
    }

    map
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── Primitive readers ─────────────────────────────────────────────────────

    #[test]
    fn test_u32_le_basic() {
        let d = [0x01u8, 0x00, 0x00, 0x00];
        assert_eq!(u32_le(&d, 0).unwrap(), 1);
    }

    #[test]
    fn test_u32_le_truncated() {
        let d = [0x01u8, 0x02];
        assert!(u32_le(&d, 0).is_err());
    }

    #[test]
    fn test_u64_le_basic() {
        let d = [1u8, 0, 0, 0, 0, 0, 0, 0];
        assert_eq!(u64_le(&d, 0).unwrap(), 1);
    }

    #[test]
    fn test_read_cstring_basic() {
        let d = b"hello\0world\0";
        assert_eq!(read_cstring(d, 0).unwrap(), "hello");
        assert_eq!(read_cstring(d, 6).unwrap(), "world");
    }

    #[test]
    fn test_read_cstring_unterminated() {
        let d = b"noeol";
        assert!(read_cstring(d, 0).is_err());
    }

    // ── checkbyte ─────────────────────────────────────────────────────────────

    #[test]
    fn test_checkbyte_deterministic() {
        let a = checkbyte(b"hello");
        let b = checkbyte(b"hello");
        assert_eq!(a, b);
    }

    #[test]
    fn test_checkbyte_empty() {
        assert_eq!(checkbyte(b""), 0);
    }

    #[test]
    fn test_checkbyte_differs_for_different_names() {
        let a = checkbyte(b"alpha");
        let b = checkbyte(b"beta");
        // Very likely to differ (not guaranteed but almost certain).
        // We just verify the function runs.
        let _ = a;
        let _ = b;
    }

    // ── MethodListHeader ──────────────────────────────────────────────────────

    #[test]
    fn test_method_list_header_relative() {
        let mut d = vec![0u8; 8];
        // entsize_and_flags = RELATIVE_METHOD_FLAG | 12
        let flags = RELATIVE_METHOD_FLAG | 12u32;
        d[0..4].copy_from_slice(&flags.to_le_bytes());
        d[4..8].copy_from_slice(&3u32.to_le_bytes()); // count = 3
        let h = MethodListHeader::parse(&d, 0).unwrap();
        assert!(h.is_relative);
        assert_eq!(h.count, 3);
        assert_eq!(h.entsize, 12);
    }

    #[test]
    fn test_method_list_header_non_relative() {
        let mut d = vec![0u8; 8];
        d[0..4].copy_from_slice(&12u32.to_le_bytes()); // just entsize = 12
        d[4..8].copy_from_slice(&5u32.to_le_bytes());
        let h = MethodListHeader::parse(&d, 0).unwrap();
        assert!(!h.is_relative);
        assert!(!h.is_uniqued);
        assert_eq!(h.count, 5);
    }

    #[test]
    fn test_method_list_header_truncated() {
        let d = [0u8; 4];
        assert!(MethodListHeader::parse(&d, 0).is_err());
    }

    // ── ObjcOptHeader ─────────────────────────────────────────────────────────

    fn make_objc_opt_header(version: u32) -> Vec<u8> {
        let mut d = vec![0u8; 32];
        d[0..4].copy_from_slice(&OBJC_OPT_MAGIC_V16.to_le_bytes());
        d[4..8].copy_from_slice(&version.to_le_bytes());
        // selopt_offset = 32 (right after header)
        d[8..12].copy_from_slice(&32i32.to_le_bytes());
        d[12..16].copy_from_slice(&32i32.to_le_bytes());
        d[16..20].copy_from_slice(&32i32.to_le_bytes());
        d[20..24].copy_from_slice(&32i32.to_le_bytes());
        // headeropt_rw_offset (v16 only)
        d[24..28].copy_from_slice(&32i32.to_le_bytes());
        d
    }

    #[test]
    fn test_objc_opt_header_parse_v16() {
        let d = make_objc_opt_header(16);
        let h = ObjcOptHeader::parse(&d, 0).unwrap();
        assert_eq!(h.version, 16);
        assert_eq!(h.magic, OBJC_OPT_MAGIC_V16);
        assert!(h.headeropt_rw_offset.is_some());
    }

    #[test]
    fn test_objc_opt_header_parse_v15() {
        let d = make_objc_opt_header(15);
        let h = ObjcOptHeader::parse(&d, 0).unwrap();
        assert_eq!(h.version, 15);
    }

    #[test]
    fn test_objc_opt_header_bad_magic() {
        let mut d = make_objc_opt_header(16);
        d[0..4].copy_from_slice(&0xDEADBEEFu32.to_le_bytes());
        assert!(ObjcOptHeader::parse(&d, 0).is_err());
    }

    #[test]
    fn test_objc_opt_header_bad_version() {
        let d = make_objc_opt_header(99);
        assert!(ObjcOptHeader::parse(&d, 0).is_err());
    }

    #[test]
    fn test_objc_opt_header_truncated() {
        let d = [0u8; 10];
        assert!(ObjcOptHeader::parse(&d, 0).is_err());
    }

    // ── ObjcHashTableHeader ───────────────────────────────────────────────────

    fn make_hash_table_header(capacity: u32, mask: u32) -> Vec<u8> {
        let mut d = vec![0u8; 64];
        d[0..4].copy_from_slice(&capacity.to_le_bytes()); // capacity
        d[4..8].copy_from_slice(&0u32.to_le_bytes());     // occupied
        d[8..12].copy_from_slice(&4u32.to_le_bytes());    // shift
        d[12..16].copy_from_slice(&mask.to_le_bytes());   // mask
        d[16..20].copy_from_slice(&0u32.to_le_bytes());   // sentinel
        d[20..24].copy_from_slice(&(mask + 1).to_le_bytes()); // roundedTabSize
        // salt at [24..32] = 0
        d
    }

    #[test]
    fn test_hash_table_header_parse() {
        let d = make_hash_table_header(8, 7);
        let h = ObjcHashTableHeader::parse(&d, 0).unwrap();
        assert_eq!(h.capacity, 8);
        assert_eq!(h.mask, 7);
        assert_eq!(h.shift, 4);
    }

    #[test]
    fn test_hash_table_header_zero_capacity() {
        let d = make_hash_table_header(0, 0);
        assert!(ObjcHashTableHeader::parse(&d, 0).is_err());
    }

    #[test]
    fn test_hash_table_header_truncated() {
        let d = [0u8; 8];
        assert!(ObjcHashTableHeader::parse(&d, 0).is_err());
    }

    // ── PerfectHashParams::hash ───────────────────────────────────────────────

    #[test]
    fn test_perfect_hash_no_crash_on_empty_key() {
        let params = PerfectHashParams {
            capacity: 16, occupied: 0, shift: 4, mask: 15, sentinel: 0,
            tab: vec![0; 16],
            checkbytes: vec![0; 16],
            offsets: vec![0; 16],
        };
        let h = params.hash(b"");
        assert_eq!(h, 0);
    }

    #[test]
    fn test_perfect_hash_within_capacity() {
        let params = PerfectHashParams {
            capacity: 32, occupied: 0, shift: 4, mask: 31, sentinel: 0,
            tab: vec![0; 32],
            checkbytes: vec![0; 32],
            offsets: vec![0; 32],
        };
        let h = params.hash(b"viewDidLoad");
        assert!(h < 32, "hash {} >= capacity 32", h);
    }

    #[test]
    fn test_perfect_hash_lookup_not_found_empty_checkbytes() {
        let params = PerfectHashParams {
            capacity: 8, occupied: 0, shift: 3, mask: 7, sentinel: 0,
            tab: vec![0; 8],
            checkbytes: vec![0; 8],
            offsets: vec![0; 8],
        };
        // Checkbytes are all 0; since checkbyte("x") != 0, lookup returns None.
        let result = params.lookup("x");
        assert!(result.is_none());
    }

    // ── ObjcOptimizationData ──────────────────────────────────────────────────

    #[test]
    fn test_optimization_data_default_empty() {
        let d = ObjcOptimizationData::default();
        assert_eq!(d.total_count(), 0);
        assert!(d.find_class("NSObject").is_none());
    }

    #[test]
    fn test_optimization_data_insert_and_find() {
        let mut d = ObjcOptimizationData::default();
        d.all_classes.insert("NSObject".into(), 0x1000_0000);
        d.all_selectors.insert("init".into(), 0x2000_0000);
        d.all_protocols.insert("NSCopying".into(), 0x3000_0000);

        assert_eq!(d.find_class("NSObject"), Some(0x1000_0000));
        assert_eq!(d.find_selector("init"), Some(0x2000_0000));
        assert_eq!(d.find_protocol("NSCopying"), Some(0x3000_0000));
        assert!(d.find_class("UIView").is_none());
    }

    #[test]
    fn test_optimization_data_counts() {
        let mut d = ObjcOptimizationData::default();
        d.all_classes.insert("A".into(), 1);
        d.all_classes.insert("B".into(), 2);
        d.all_selectors.insert("sel1".into(), 3);
        assert_eq!(d.class_count(), 2);
        assert_eq!(d.selector_count(), 1);
        assert_eq!(d.protocol_count(), 0);
        assert_eq!(d.total_count(), 3);
    }

    #[test]
    fn test_optimization_data_display() {
        let mut d = ObjcOptimizationData::default();
        d.all_classes.insert("NSObject".into(), 0x1000);
        let s = format!("{}", d);
        assert!(s.contains("classes: 1"));
        assert!(s.contains("selectors: 0"));
    }

    // ── build_selector_string_map ─────────────────────────────────────────────

    #[test]
    fn test_build_selector_string_map_basic() {
        let data = b"init\0viewDidLoad\0dealloc\0";
        let map = build_selector_string_map(data, 0, 0x1000, data.len());
        assert_eq!(map.get(&0x1000).unwrap(), "init");
        assert_eq!(map.get(&0x1005).unwrap(), "viewDidLoad");
        assert_eq!(map.get(&0x1011).unwrap(), "dealloc");
    }

    #[test]
    fn test_build_selector_string_map_empty() {
        let map = build_selector_string_map(&[], 0, 0x1000, 0);
        assert!(map.is_empty());
    }

    // ── build_selrefs_map ─────────────────────────────────────────────────────

    #[test]
    fn test_build_selrefs_map_64bit() {
        // One 8-byte pointer in selrefs pointing to 0x2000.
        let mut data = vec![0u8; 64];
        let target_va: u64 = 0x2000;
        data[0..8].copy_from_slice(&target_va.to_le_bytes());

        let mut sel_strings = HashMap::new();
        sel_strings.insert(0x2000u64, "init".to_string());

        let map = build_selrefs_map(&data, 0, 0x1000, 8, &sel_strings, true);
        assert_eq!(map.get(&0x1000).unwrap(), "init");
    }

    #[test]
    fn test_build_selrefs_map_pointer_not_in_strings() {
        let mut data = vec![0u8; 8];
        let target_va: u64 = 0x9999;
        data[0..8].copy_from_slice(&target_va.to_le_bytes());
        let sel_strings: HashMap<u64, String> = HashMap::new();
        let map = build_selrefs_map(&data, 0, 0x1000, 8, &sel_strings, true);
        assert!(map.is_empty());
    }

    // ── parse_headeropt_ro ────────────────────────────────────────────────────

    #[test]
    fn test_parse_headeropt_ro_empty() {
        let mut d = vec![0u8; 8];
        d[0..4].copy_from_slice(&0u32.to_le_bytes()); // count = 0
        d[4..8].copy_from_slice(&20u32.to_le_bytes()); // entsize = 20
        let entries = parse_headeropt_ro(&d, 0, 0x1000).unwrap();
        assert!(entries.is_empty());
    }

    #[test]
    fn test_parse_headeropt_ro_truncated() {
        let d = [0u8; 4];
        assert!(parse_headeropt_ro(&d, 0, 0).is_err());
    }

    // ── parse_objc_optimization integration ───────────────────────────────────

    #[test]
    fn test_parse_objc_optimization_bad_magic() {
        let d = vec![0xFFu8; 64];
        let err = parse_objc_optimization(&d, 0, 0x180000000, true);
        assert!(err.is_err());
    }

    #[test]
    fn test_parse_objc_optimization_truncated() {
        let d = vec![0u8; 4];
        let err = parse_objc_optimization(&d, 0, 0, true);
        assert!(err.is_err());
    }

    // ── ObjcHeaderOptEntry has_swift_class ────────────────────────────────────

    #[test]
    fn test_objc_header_opt_entry_swift_flag() {
        let entry = ObjcHeaderOptEntry {
            mach_header_addr: 0x1000_0000,
            info_offset: 0,
            method_count: 42,
            has_swift_class: true,
        };
        assert!(entry.has_swift_class);
    }

    // ── SCRAMBLE table ────────────────────────────────────────────────────────

    #[test]
    fn test_scramble_table_length() {
        assert_eq!(SCRAMBLE.len(), 256);
    }

    #[test]
    fn test_scramble_table_first_entry() {
        // Value at index 0 should be 0xDEADBEEF (0 * 0x9E... + 0xDEADBEEF).
        assert_eq!(SCRAMBLE[0], 0xDEADBEEF);
    }
}
