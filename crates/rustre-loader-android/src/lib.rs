//! `rustre-loader-android`
//!
//! This crate is part of the `RustRE` Suite, a premium reverse engineering platform.
//!
//! # Loader: ANDROID
//!
//! Implements comprehensive parsing, section/segment mapping, and entry point
//! detection for Android APK (ZIP + DEX), raw DEX bytecode, ART vdex images,
//! and APK signing block analysis.
//!
//! ## Supported formats
//! - **APK**: ZIP container with `classes*.dex`, `AndroidManifest.xml` (AXML),
//!   `resources.arsc`, and `lib/<abi>/*.so` native libraries.
//! - **DEX**: Dalvik Executable (versions 035–039). Full header, string/type/
//!   proto/field/method/class-def table parsing, `encoded_method` → `code_item` →
//!   Dalvik opcode extraction.
//! - **VDEX**: ART Verified DEX container with embedded DEX sections and
//!   quicken info.
//! - **APK Signing Blocks**: v1 (JAR / META-INF signatures), v2 (APK Signature
//!   Block v2 in ZIP comment area), v3 (key rotation), v4 (`.idsig` sidecar).
//! - **AndroidManifest.xml (AXML)**: Binary XML string pool, namespace chunks,
//!   start/end element chunks, attribute decoding by resource ID.
//! - **Permissions & components**: `uses-permission`, `intent-filter`, exported
//!   activities/services/receivers (attack-surface detection).

// Numeric-cast lints are relaxed crate-wide because they are inherent to a
// binary-format parser and every occurrence is intentional and bounded:
//   * `cast_possible_truncation` / `cast_possible_wrap` — on-disk fields are
//     fixed-width (u16/u32) and offsets are bounded by the input length, which
//     is itself well below `u32::MAX` for any real APK/DEX/VDEX; Dalvik typed
//     values are reinterpreted between `u32` and `i32` as raw 2's-complement.
//   * `cast_precision_loss` / `cast_sign_loss` — confidence and percentage
//     computations deliberately widen small counts to `f64`.
// Keeping these as per-site `#[allow]`s would add noise without adding safety;
// the bounds are enforced by explicit length checks at each parse site.
#![allow(
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_precision_loss,
    clippy::cast_sign_loss
)]

pub mod android_binary_loader;
pub mod apk;
pub mod apk_analyzer;
pub mod art_analysis;
pub mod art_parser;
pub mod axml_full;
pub mod dex;
pub mod manifest_binary;
pub mod oat_parser;
pub mod signing_v4;
pub mod vdex_parser;
pub mod art_method_resolver;
pub mod dex_optimizer_detector;
pub mod apk_zip_reader;

pub use art_analysis::{
    ArtAnalysis, ArtError, CompilerFilter, HotnessBitmap, OAT_MAGIC, OatFile, OatMethod,
    VDEX_MAGIC, VdexFile,
};

use std::collections::{HashMap, HashSet};
use std::fmt;
use std::sync::Arc;

use rustre_core::address::{Address, AddressRange};
use rustre_core::arch::{
    Architecture, BranchInfo, CallingConvention, Instruction, RegisterInfo, RegisterKind,
};
use rustre_core::binary_view::{BinaryView, Memory, Segment};
use rustre_core::endian::Endian;
use rustre_core::errors::CoreError;
use rustre_core::ids::ViewId;
use rustre_core::loader::{BinaryType, LoadResult};
use rustre_core::permissions::Permissions;
use rustre_core::{Loader, LoaderInput, NestedBinary, async_trait};

// ── Error type ───────────────────────────────────────────────────────────────

/// Errors produced by the Android/DEX loader.
#[derive(Debug, thiserror::Error)]
pub enum AndroidLoaderError {
    /// Magic bytes do not match DEX or APK.
    #[error("invalid magic")]
    InvalidMagic,
    /// File is too short to contain a valid header.
    #[error("truncated header")]
    TruncatedHeader,
    /// Generic parse error with context.
    #[error("parse error: {0}")]
    ParseError(String),
    /// Checksum verification failed.
    #[error("checksum mismatch: expected {expected:#010x}, computed {computed:#010x}")]
    ChecksumMismatch { expected: u32, computed: u32 },
    /// An index was out of bounds for the table it addressed.
    #[error("index out of bounds: table={table} index={index} len={len}")]
    IndexOutOfBounds {
        table: &'static str,
        index: usize,
        len: usize,
    },
    /// ZIP central directory could not be found or parsed.
    #[error("invalid ZIP structure")]
    InvalidZip,
    /// AXML chunk was malformed.
    #[error("malformed AXML chunk at offset {0:#x}")]
    MalformedAxmlChunk(usize),
}

// ── Magic detection ──────────────────────────────────────────────────────────

/// Returns `true` if `data` looks like an APK: ZIP header + `classes.dex` somewhere inside.
#[must_use]
pub fn is_apk(data: &[u8]) -> bool {
    data.starts_with(b"PK\x03\x04") && data.windows(11).any(|w| w == b"classes.dex")
}

/// Returns `true` if `data` looks like a raw DEX bytecode file.
#[must_use]
pub fn is_dex(data: &[u8]) -> bool {
    if data.len() < 8 {
        return false;
    }
    data.starts_with(b"dex\n") && data[4].is_ascii_digit()
}

/// Returns `true` if `data` is an ART VDEX container.
/// Magic: `"vdex"` followed by version digits (e.g. `"019\0"`).
#[must_use]
pub fn is_vdex(data: &[u8]) -> bool {
    if data.len() < 8 {
        return false;
    }
    data.starts_with(b"vdex") && data[4].is_ascii_digit()
}

// ── Adler-32 checksum ────────────────────────────────────────────────────────

/// Compute the Adler-32 checksum of `data` (as used in DEX files).
///
/// The DEX checksum covers all bytes from offset 12 onwards (i.e., the file
/// without the magic and checksum field itself).
#[must_use]
pub fn adler32(data: &[u8]) -> u32 {
    const MOD_ADLER: u32 = 65521;
    let mut a: u32 = 1;
    let mut b: u32 = 0;
    for &byte in data {
        a = (a + u32::from(byte)) % MOD_ADLER;
        b = (b + a) % MOD_ADLER;
    }
    (b << 16) | a
}

/// Verify the Adler-32 checksum stored in a DEX file.
///
/// In a DEX file the checksum is stored at bytes [8..12] and covers bytes
/// [`12..file_size`].
///
/// # Errors
/// Returns `AndroidLoaderError::ChecksumMismatch` when verification fails.
pub fn verify_dex_checksum(data: &[u8]) -> Result<(), AndroidLoaderError> {
    if data.len() < 12 {
        return Err(AndroidLoaderError::TruncatedHeader);
    }
    let stored = u32::from_le_bytes(
        data[8..12]
            .try_into()
            .map_err(|_| AndroidLoaderError::ParseError("checksum slice".into()))?,
    );
    let computed = adler32(&data[12..]);
    if stored == computed {
        Ok(())
    } else {
        Err(AndroidLoaderError::ChecksumMismatch {
            expected: stored,
            computed,
        })
    }
}

// ── DEX header ───────────────────────────────────────────────────────────────

/// Parsed header of a `.dex` file (112 bytes, ECMA-like layout).
///
/// See AOSP `libdex/DexFile.h` `DexHeader` struct.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DexHeader {
    /// Magic bytes (first 8 bytes): `"dex\n035\0"` etc.
    pub magic: [u8; 8],
    /// Adler-32 checksum of the file (bytes 12 onwards).
    pub checksum: u32,
    /// SHA-1 signature of the file content (bytes 32 onwards), 20 bytes.
    pub sha1: [u8; 20],
    /// Total file size in bytes.
    pub file_size: u32,
    /// Size of the DEX header in bytes (always 112 for standard DEX).
    pub header_size: u32,
    /// Endian constant (`0x12345678` for little-endian).
    pub endian_tag: u32,
    /// Number of string identifiers.
    pub string_ids_size: u32,
    /// Offset of string identifier list.
    pub string_ids_off: u32,
    /// Number of type identifiers.
    pub type_ids_size: u32,
    /// Offset of type identifier list.
    pub type_ids_off: u32,
    /// Number of proto identifiers.
    pub proto_ids_size: u32,
    /// Offset of proto identifier list.
    pub proto_ids_off: u32,
    /// Number of field identifiers.
    pub field_ids_size: u32,
    /// Offset of field identifier list.
    pub field_ids_off: u32,
    /// Number of method identifiers.
    pub method_ids_size: u32,
    /// Offset of method identifier list.
    pub method_ids_off: u32,
    /// Number of class definitions.
    pub class_defs_size: u32,
    /// Offset of class definition list.
    pub class_defs_off: u32,
    /// Size of data section in bytes.
    pub data_size: u32,
    /// Offset of data section.
    pub data_off: u32,
}

impl DexHeader {
    /// Parse a `DexHeader` from the beginning of `data`.
    ///
    /// # Errors
    /// Returns `AndroidLoaderError::TruncatedHeader` if `data` is shorter than 112 bytes.
    /// Returns `AndroidLoaderError::InvalidMagic` if magic bytes do not match.
    pub fn parse(data: &[u8]) -> Result<Self, AndroidLoaderError> {
        if data.len() < 112 {
            return Err(AndroidLoaderError::TruncatedHeader);
        }
        if !data.starts_with(b"dex\n") {
            return Err(AndroidLoaderError::InvalidMagic);
        }
        let magic: [u8; 8] = data[0..8]
            .try_into()
            .map_err(|_| AndroidLoaderError::ParseError("magic slice".into()))?;
        let sha1: [u8; 20] = data[12..32]
            .try_into()
            .map_err(|_| AndroidLoaderError::ParseError("sha1 slice".into()))?;

        let rd = |off: usize| -> Result<u32, AndroidLoaderError> {
            data.get(off..off + 4)
                .and_then(|b| b.try_into().ok())
                .map(u32::from_le_bytes)
                .ok_or_else(|| AndroidLoaderError::ParseError(format!("u32 at {off:#x}")))
        };

        Ok(Self {
            magic,
            checksum: rd(8)?,
            sha1,
            file_size: rd(32)?,
            header_size: rd(36)?,
            endian_tag: rd(40)?,
            string_ids_size: rd(56)?,
            string_ids_off: rd(60)?,
            type_ids_size: rd(64)?,
            type_ids_off: rd(68)?,
            proto_ids_size: rd(72)?,
            proto_ids_off: rd(76)?,
            field_ids_size: rd(80)?,
            field_ids_off: rd(84)?,
            method_ids_size: rd(88)?,
            method_ids_off: rd(92)?,
            class_defs_size: rd(96)?,
            class_defs_off: rd(100)?,
            data_size: rd(104)?,
            data_off: rd(108)?,
        })
    }

    /// Returns `true` if the magic bytes are valid DEX magic.
    #[must_use]
    pub fn is_valid(&self) -> bool {
        self.magic.starts_with(b"dex\n")
    }

    /// Returns the DEX version string (e.g. `"035"`).
    #[must_use]
    pub fn version_str(&self) -> &str {
        std::str::from_utf8(&self.magic[4..7]).unwrap_or("???")
    }

    /// Returns the integer DEX version (e.g. `35` for version `"035"`).
    #[must_use]
    pub fn version_int(&self) -> u32 {
        self.version_str().parse().unwrap_or(0)
    }

    /// Returns `true` when the endian tag indicates little-endian byte order.
    #[must_use]
    pub const fn is_little_endian(&self) -> bool {
        self.endian_tag == 0x1234_5678
    }
}

impl fmt::Display for DexHeader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "DEX v{} file_size={} strings={} types={} methods={} classes={}",
            self.version_str(),
            self.file_size,
            self.string_ids_size,
            self.type_ids_size,
            self.method_ids_size,
            self.class_defs_size,
        )
    }
}

// ── DEX string table ──────────────────────────────────────────────────────────

/// Read all strings from the DEX string ID table into a `Vec<String>`.
///
/// Each `string_id_item` (4 bytes) points to a `string_data_item`
/// that starts with a ULEB128 character count followed by MUTF-8 bytes
/// and a NUL terminator.
///
/// Returns an empty vec on any parsing failure.
#[must_use]
pub fn read_string_table(data: &[u8], hdr: &DexHeader) -> Vec<String> {
    let n = hdr.string_ids_size as usize;
    let base = hdr.string_ids_off as usize;
    // Cap pre-allocation: each string_id_item is 4 bytes, so the true count
    // cannot exceed (data.len() / 4).  This prevents OOM from crafted headers.
    let capacity = n.min(data.len() / 4);
    let mut strings = Vec::with_capacity(capacity);
    for i in 0..n {
        let off = base + i * 4;
        let str_data_off = if let Some(v) = data
            .get(off..off + 4)
            .and_then(|b| b.try_into().ok())
            .map(u32::from_le_bytes) { v as usize } else {
            strings.push(String::new());
            continue;
        };
        strings.push(read_dex_string(data, str_data_off));
    }
    strings
}

/// Read a MUTF-8 DEX string starting at `off` in `data`.
/// The first byte(s) encode the string length as ULEB128; the bytes follow.
#[must_use] 
pub fn read_dex_string(data: &[u8], off: usize) -> String {
    if off >= data.len() {
        return String::new();
    }
    let mut pos = off;
    let mut char_len: usize = 0;
    let mut shift = 0usize;
    loop {
        if pos >= data.len() {
            return String::new();
        }
        let b = data[pos];
        pos += 1;
        char_len |= ((b & 0x7F) as usize) << shift;
        shift += 7;
        if b & 0x80 == 0 {
            break;
        }
        if shift > 28 {
            break;
        }
    }
    let end = data.len().min(pos + char_len * 3 + 4);
    let slice = &data[pos..end];
    let nul = slice.iter().position(|&b| b == 0).unwrap_or(slice.len());
    String::from_utf8_lossy(&slice[..nul]).into_owned()
}

// ── DEX type / proto / field / method ID tables ───────────────────────────────

/// `type_id_item`: a single u32 index into the string ID table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TypeIdItem {
    /// Index into the string ID table for the type descriptor.
    pub descriptor_idx: u32,
}

/// `proto_id_item`: method prototype (16 bytes).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProtoIdItem {
    /// Index into string IDs — shorty descriptor (e.g. `"VII"`).
    pub shorty_idx: u32,
    /// Index into type IDs — return type.
    pub return_type_idx: u32,
    /// Offset of `type_list` for parameters (0 = no parameters).
    pub parameters_off: u32,
}

/// `field_id_item` (8 bytes).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FieldIdItem {
    /// Index into type IDs — declaring class.
    pub class_idx: u16,
    /// Index into type IDs — field type.
    pub type_idx: u16,
    /// Index into string IDs — field name.
    pub name_idx: u32,
}

/// `method_id_item` (8 bytes).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MethodIdItem {
    /// Index into type IDs — declaring class.
    pub class_idx: u16,
    /// Index into proto IDs — method signature.
    pub proto_idx: u16,
    /// Index into string IDs — method name.
    pub name_idx: u32,
}

/// Parse the `type_id_item` table.
#[must_use]
pub fn read_type_ids(data: &[u8], hdr: &DexHeader) -> Vec<TypeIdItem> {
    let n = hdr.type_ids_size as usize;
    let base = hdr.type_ids_off as usize;
    (0..n)
        .filter_map(|i| {
            let off = base + i * 4;
            data.get(off..off + 4)
                .and_then(|b| b.try_into().ok())
                .map(|b| TypeIdItem {
                    descriptor_idx: u32::from_le_bytes(b),
                })
        })
        .collect()
}

/// Parse the `proto_id_item` table.
#[must_use]
pub fn read_proto_ids(data: &[u8], hdr: &DexHeader) -> Vec<ProtoIdItem> {
    let n = hdr.proto_ids_size as usize;
    let base = hdr.proto_ids_off as usize;
    (0..n)
        .filter_map(|i| {
            let off = base + i * 12;
            if off + 12 > data.len() {
                return None;
            }
            let shorty_idx = u32::from_le_bytes(data[off..off + 4].try_into().ok()?);
            let return_type_idx = u32::from_le_bytes(data[off + 4..off + 8].try_into().ok()?);
            let parameters_off = u32::from_le_bytes(data[off + 8..off + 12].try_into().ok()?);
            Some(ProtoIdItem {
                shorty_idx,
                return_type_idx,
                parameters_off,
            })
        })
        .collect()
}

/// Parse the `field_id_item` table.
#[must_use]
pub fn read_field_ids(data: &[u8], hdr: &DexHeader) -> Vec<FieldIdItem> {
    let n = hdr.field_ids_size as usize;
    let base = hdr.field_ids_off as usize;
    (0..n)
        .filter_map(|i| {
            let off = base + i * 8;
            if off + 8 > data.len() {
                return None;
            }
            let class_idx = u16::from_le_bytes(data[off..off + 2].try_into().ok()?);
            let type_idx = u16::from_le_bytes(data[off + 2..off + 4].try_into().ok()?);
            let name_idx = u32::from_le_bytes(data[off + 4..off + 8].try_into().ok()?);
            Some(FieldIdItem {
                class_idx,
                type_idx,
                name_idx,
            })
        })
        .collect()
}

/// Parse the `method_id_item` table.
#[must_use]
pub fn read_method_ids(data: &[u8], hdr: &DexHeader) -> Vec<MethodIdItem> {
    let n = hdr.method_ids_size as usize;
    let base = hdr.method_ids_off as usize;
    (0..n)
        .filter_map(|i| {
            let off = base + i * 8;
            if off + 8 > data.len() {
                return None;
            }
            let class_idx = u16::from_le_bytes(data[off..off + 2].try_into().ok()?);
            let proto_idx = u16::from_le_bytes(data[off + 2..off + 4].try_into().ok()?);
            let name_idx = u32::from_le_bytes(data[off + 4..off + 8].try_into().ok()?);
            Some(MethodIdItem {
                class_idx,
                proto_idx,
                name_idx,
            })
        })
        .collect()
}

// ── DEX class definitions ────────────────────────────────────────────────────

/// `class_def_item` (32 bytes). See AOSP `DexClassDef`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClassDefItem {
    /// Index into type IDs — this class.
    pub class_idx: u32,
    /// Access flags (`ACC_PUBLIC`, etc.).
    pub access_flags: u32,
    /// Index into type IDs — superclass (or `NO_INDEX = 0xFFFFFFFF`).
    pub superclass_idx: u32,
    /// Offset of `type_list` of interfaces (0 = none).
    pub interfaces_off: u32,
    /// Index into string IDs — source file name (or `NO_INDEX`).
    pub source_file_idx: u32,
    /// Offset of annotations directory (0 = none).
    pub annotations_off: u32,
    /// Offset of `class_data_item` (0 = no data).
    pub class_data_off: u32,
    /// Offset of static values `encoded_array_item` (0 = all-zero defaults).
    pub static_values_off: u32,
}

impl ClassDefItem {
    /// `NO_INDEX` sentinel value.
    pub const NO_INDEX: u32 = 0xFFFF_FFFF;

    /// Parse a single `class_def_item` from `data` at byte `offset`.
    #[must_use]
    pub fn parse(data: &[u8], offset: usize) -> Option<Self> {
        if offset + 32 > data.len() {
            return None;
        }
        let rd = |o: usize| -> Option<u32> {
            Some(u32::from_le_bytes(data.get(o..o + 4)?.try_into().ok()?))
        };
        Some(Self {
            class_idx: rd(offset)?,
            access_flags: rd(offset + 4)?,
            superclass_idx: rd(offset + 8)?,
            interfaces_off: rd(offset + 12)?,
            source_file_idx: rd(offset + 16)?,
            annotations_off: rd(offset + 20)?,
            class_data_off: rd(offset + 24)?,
            static_values_off: rd(offset + 28)?,
        })
    }

    /// Returns the visibility portion of `access_flags`.
    #[must_use]
    pub const fn visibility(&self) -> DexVisibility {
        match self.access_flags & 0x7 {
            0x1 => DexVisibility::Public,
            0x2 => DexVisibility::Private,
            0x4 => DexVisibility::Protected,
            _ => DexVisibility::PackagePrivate,
        }
    }

    /// Returns `true` when `ACC_INTERFACE` is set.
    #[must_use]
    pub const fn is_interface(&self) -> bool {
        self.access_flags & 0x0200 != 0
    }

    /// Returns `true` when `ACC_ABSTRACT` is set.
    #[must_use]
    pub const fn is_abstract(&self) -> bool {
        self.access_flags & 0x0400 != 0
    }

    /// Returns `true` when `ACC_ENUM` is set.
    #[must_use]
    pub const fn is_enum(&self) -> bool {
        self.access_flags & 0x4000 != 0
    }

    /// Returns `true` when `ACC_ANNOTATION` is set.
    #[must_use]
    pub const fn is_annotation(&self) -> bool {
        self.access_flags & 0x2000 != 0
    }
}

/// Java/Dalvik visibility level.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DexVisibility {
    Public,
    Private,
    Protected,
    PackagePrivate,
}

impl fmt::Display for DexVisibility {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Public => write!(f, "public"),
            Self::Private => write!(f, "private"),
            Self::Protected => write!(f, "protected"),
            Self::PackagePrivate => write!(f, ""),
        }
    }
}

/// Parse all `class_def_item`s from `data`.
#[must_use]
pub fn read_class_defs(data: &[u8], hdr: &DexHeader) -> Vec<ClassDefItem> {
    let n = hdr.class_defs_size as usize;
    let base = hdr.class_defs_off as usize;
    (0..n)
        .filter_map(|i| ClassDefItem::parse(data, base + i * 32))
        .collect()
}

// ── DEX encoded_method / code_item ──────────────────────────────────────────

/// A method parsed from a `class_data_item`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncodedMethod {
    /// Absolute method ID (accumulated from ULEB128 diffs).
    pub method_idx: u32,
    /// Access flags.
    pub access_flags: u32,
    /// Offset of `code_item` (0 = abstract/native).
    pub code_off: u32,
}

/// Parsed `code_item` header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CodeItem {
    /// Number of registers used by this method.
    pub registers_size: u16,
    /// Number of incoming words of arguments.
    pub ins_size: u16,
    /// Number of outgoing words of arguments.
    pub outs_size: u16,
    /// Number of try-catch handlers.
    pub tries_size: u16,
    /// Debug info offset.
    pub debug_info_off: u32,
    /// Number of 16-bit code units.
    pub insns_size: u32,
    /// Raw Dalvik bytecode (little-endian 16-bit units).
    pub insns: Vec<u16>,
}

impl CodeItem {
    /// Parse a `code_item` from `data` at `offset`.
    #[must_use]
    pub fn parse(data: &[u8], offset: usize) -> Option<Self> {
        if offset + 16 > data.len() {
            return None;
        }
        let rd16 = |o: usize| -> Option<u16> {
            Some(u16::from_le_bytes(data.get(o..o + 2)?.try_into().ok()?))
        };
        let rd32 = |o: usize| -> Option<u32> {
            Some(u32::from_le_bytes(data.get(o..o + 4)?.try_into().ok()?))
        };

        let registers_size = rd16(offset)?;
        let ins_size = rd16(offset + 2)?;
        let outs_size = rd16(offset + 4)?;
        let tries_size = rd16(offset + 6)?;
        let debug_info_off = rd32(offset + 8)?;
        let insns_size = rd32(offset + 12)?;

        let insns_off = offset + 16;
        let byte_count = insns_size as usize * 2;
        if insns_off + byte_count > data.len() {
            return None;
        }
        let insns: Vec<u16> = data[insns_off..insns_off + byte_count]
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect();

        Some(Self {
            registers_size,
            ins_size,
            outs_size,
            tries_size,
            debug_info_off,
            insns_size,
            insns,
        })
    }

    /// Return the raw bytecode as a flat `Vec<u8>` (little-endian units).
    #[must_use]
    pub fn bytecode_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.insns.len() * 2);
        for &u in &self.insns {
            out.extend_from_slice(&u.to_le_bytes());
        }
        out
    }
}

/// Read ULEB128 from `data` at `*pos`, advancing `*pos`.
pub fn read_uleb128(data: &[u8], pos: &mut usize) -> u32 {
    let mut result = 0u32;
    let mut shift = 0u32;
    loop {
        if *pos >= data.len() {
            break;
        }
        let b = data[*pos];
        *pos += 1;
        result |= u32::from(b & 0x7F) << shift;
        shift += 7;
        if b & 0x80 == 0 || shift >= 32 {
            break;
        }
    }
    result
}

/// Parse `encoded_method` list from `class_data_item` at `*pos`.
///
/// DEX `class_data_item` layout:
/// ```text
/// ULEB128 static_fields_size
/// ULEB128 instance_fields_size
/// ULEB128 direct_methods_size
/// ULEB128 virtual_methods_size
/// encoded_field[static_fields_size]
/// encoded_field[instance_fields_size]
/// encoded_method[direct_methods_size]
/// encoded_method[virtual_methods_size]
/// ```
#[must_use]
pub fn parse_encoded_methods(data: &[u8], class_data_off: u32) -> Vec<EncodedMethod> {
    let off = class_data_off as usize;
    if off == 0 || off >= data.len() {
        return vec![];
    }
    let mut pos = off;

    let static_fields_size = read_uleb128(data, &mut pos) as usize;
    let instance_fields_size = read_uleb128(data, &mut pos) as usize;
    let direct_methods_size = read_uleb128(data, &mut pos) as usize;
    let virtual_methods_size = read_uleb128(data, &mut pos) as usize;

    // Skip encoded_field entries (2 ULEB128 each: field_idx_diff + access_flags)
    for _ in 0..(static_fields_size + instance_fields_size) {
        read_uleb128(data, &mut pos); // field_idx_diff
        read_uleb128(data, &mut pos); // access_flags
    }

    let total_methods = direct_methods_size + virtual_methods_size;
    // Cap pre-allocation: each encoded_method is at least 3 ULEB128 bytes.
    // Using remaining bytes as a bound prevents OOM from crafted class data.
    let capacity = total_methods.min(data.len().saturating_sub(pos) / 3 + 1);
    let mut methods = Vec::with_capacity(capacity);
    let mut method_idx = 0u32;

    for _ in 0..total_methods {
        let diff = read_uleb128(data, &mut pos);
        let access_flags = read_uleb128(data, &mut pos);
        let code_off = read_uleb128(data, &mut pos);
        method_idx = method_idx.wrapping_add(diff);
        methods.push(EncodedMethod {
            method_idx,
            access_flags,
            code_off,
        });
    }

    methods
}

// ── DEX file ─────────────────────────────────────────────────────────────────

/// Parsed DEX file representation with all major tables loaded.
#[derive(Debug, Clone)]
pub struct DexFile {
    /// Parsed DEX header.
    pub header: DexHeader,
    /// String table.
    pub strings: Vec<String>,
    /// Type ID table (each entry is an index into `strings`).
    pub type_ids: Vec<TypeIdItem>,
    /// Proto ID table.
    pub proto_ids: Vec<ProtoIdItem>,
    /// Field ID table.
    pub field_ids: Vec<FieldIdItem>,
    /// Method ID table.
    pub method_ids: Vec<MethodIdItem>,
    /// Class definition table.
    pub class_defs: Vec<ClassDefItem>,
}

impl DexFile {
    /// Parse a complete `DexFile` from `data`.
    ///
    /// # Errors
    /// Propagates any errors from `DexHeader::parse`.
    pub fn parse(data: &[u8]) -> Result<Self, AndroidLoaderError> {
        let header = DexHeader::parse(data)?;
        let strings = read_string_table(data, &header);
        let type_ids = read_type_ids(data, &header);
        let proto_ids = read_proto_ids(data, &header);
        let field_ids = read_field_ids(data, &header);
        let method_ids = read_method_ids(data, &header);
        let class_defs = read_class_defs(data, &header);
        Ok(Self {
            header,
            strings,
            type_ids,
            proto_ids,
            field_ids,
            method_ids,
            class_defs,
        })
    }

    /// Return the type descriptor string for `type_idx`.
    #[must_use]
    pub fn type_descriptor(&self, type_idx: u32) -> Option<&str> {
        let tid = self.type_ids.get(type_idx as usize)?;
        self.strings
            .get(tid.descriptor_idx as usize)
            .map(String::as_str)
    }

    /// Return the fully-qualified class name for a `class_def_item`.
    #[must_use]
    pub fn class_name(&self, def: &ClassDefItem) -> Option<String> {
        let desc = self.type_descriptor(def.class_idx)?;
        // Dalvik descriptor: `Lcom/example/Foo;` → `com.example.Foo`
        if desc.starts_with('L') && desc.ends_with(';') {
            Some(desc[1..desc.len() - 1].replace('/', "."))
        } else {
            Some(desc.to_owned())
        }
    }

    /// Return the method name string for a `method_id_item`.
    #[must_use]
    pub fn method_name(&self, mid: &MethodIdItem) -> Option<&str> {
        self.strings.get(mid.name_idx as usize).map(String::as_str)
    }

    /// Collect all class names defined in this DEX.
    #[must_use]
    pub fn all_class_names(&self) -> Vec<String> {
        self.class_defs
            .iter()
            .filter_map(|def| self.class_name(def))
            .collect()
    }

    /// Collect all method names (as `"ClassName.methodName"`) defined in this DEX.
    #[must_use]
    pub fn all_method_names(&self) -> Vec<String> {
        self.method_ids
            .iter()
            .filter_map(|mid| {
                let class_desc = self.type_descriptor(u32::from(mid.class_idx))?;
                let class_name = if class_desc.starts_with('L') && class_desc.ends_with(';') {
                    class_desc[1..class_desc.len() - 1].replace('/', ".")
                } else {
                    class_desc.to_owned()
                };
                let method = self.method_name(mid)?;
                Some(format!("{class_name}.{method}"))
            })
            .collect()
    }
}

impl fmt::Display for DexFile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "DexFile v{} classes={} methods={}",
            self.header.version_str(),
            self.class_defs.len(),
            self.method_ids.len()
        )
    }
}

// ── APK ZIP parsing ───────────────────────────────────────────────────────────

/// A file entry inside an APK (ZIP) archive.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApkEntry {
    /// Path within the ZIP (e.g. `"classes.dex"`).
    pub name: String,
    /// Compression method: 0 = stored, 8 = deflated.
    pub compression: u16,
    /// Compressed size in bytes.
    pub compressed_size: u32,
    /// Uncompressed size in bytes.
    pub uncompressed_size: u32,
    /// Byte offset of the local file header in the APK.
    pub local_header_offset: u32,
}

impl ApkEntry {
    /// Returns `true` if this is a DEX bytecode file.
    #[must_use]
    pub fn is_dex(&self) -> bool {
        std::path::Path::new(&self.name).extension().is_some_and(|e| e.eq_ignore_ascii_case("dex"))
    }

    /// Returns `true` if this is the binary Android manifest.
    #[must_use]
    pub fn is_manifest(&self) -> bool {
        self.name == "AndroidManifest.xml"
    }

    /// Returns `true` if this is a compiled resource table.
    #[must_use]
    pub fn is_resources(&self) -> bool {
        self.name == "resources.arsc"
    }

    /// Returns `true` if this is a native shared library.
    #[must_use]
    pub fn is_native_lib(&self) -> bool {
        self.name.starts_with("lib/") && std::path::Path::new(&self.name).extension().is_some_and(|e| e.eq_ignore_ascii_case("so"))
    }

    /// Returns the ABI directory for native libraries, e.g. `"arm64-v8a"`.
    #[must_use]
    pub fn native_abi(&self) -> Option<&str> {
        if !self.is_native_lib() {
            return None;
        }
        // lib/<abi>/libfoo.so → split on '/'
        let parts: Vec<&str> = self.name.splitn(3, '/').collect();
        parts.get(1).copied()
    }
}

/// Parse the central directory of a ZIP/APK and return all entries.
///
/// Searches backward from the end of `data` for the End Of Central Directory
/// (EOCD) record signature `PK\x05\x06`.
///
/// # Errors
/// Returns `AndroidLoaderError::InvalidZip` if no EOCD is found.
pub fn parse_apk_entries(data: &[u8]) -> Result<Vec<ApkEntry>, AndroidLoaderError> {
    // Find EOCD: scan backward for PK\x05\x06.
    let eocd_sig = [0x50, 0x4B, 0x05, 0x06];
    let eocd_off = data
        .windows(4)
        .rposition(|w| w == eocd_sig)
        .ok_or(AndroidLoaderError::InvalidZip)?;

    if eocd_off + 22 > data.len() {
        return Err(AndroidLoaderError::InvalidZip);
    }

    let cd_count = u16::from_le_bytes([data[eocd_off + 8], data[eocd_off + 9]]) as usize;
    let cd_off = u32::from_le_bytes(
        data[eocd_off + 16..eocd_off + 20]
            .try_into()
            .map_err(|_| AndroidLoaderError::InvalidZip)?,
    ) as usize;

    // Cap pre-allocation: each central directory entry is at least 46 bytes,
    // so the number of real entries is bounded by data.len() / 46.
    // This prevents OOM when an attacker crafts a large cd_count in the EOCD.
    let capacity = cd_count.min(data.len() / 46 + 1);
    let mut entries = Vec::with_capacity(capacity);
    let mut pos = cd_off;

    for _ in 0..cd_count {
        if pos + 46 > data.len() {
            break;
        }
        if data[pos..pos + 4] != [0x50, 0x4B, 0x01, 0x02] {
            break;
        }

        let compression = u16::from_le_bytes([data[pos + 10], data[pos + 11]]);
        let compressed_size = u32::from_le_bytes(
            data[pos + 20..pos + 24]
                .try_into()
                .map_err(|_| AndroidLoaderError::InvalidZip)?,
        );
        let uncompressed_size = u32::from_le_bytes(
            data[pos + 24..pos + 28]
                .try_into()
                .map_err(|_| AndroidLoaderError::InvalidZip)?,
        );
        let fname_len = u16::from_le_bytes([data[pos + 28], data[pos + 29]]) as usize;
        let extra_len = u16::from_le_bytes([data[pos + 30], data[pos + 31]]) as usize;
        let comment_len = u16::from_le_bytes([data[pos + 32], data[pos + 33]]) as usize;
        let local_header_offset = u32::from_le_bytes(
            data[pos + 42..pos + 46]
                .try_into()
                .map_err(|_| AndroidLoaderError::InvalidZip)?,
        );

        let name_start = pos + 46;
        let name_end = name_start + fname_len;
        if name_end > data.len() {
            break;
        }
        let name = String::from_utf8_lossy(&data[name_start..name_end]).into_owned();

        entries.push(ApkEntry {
            name,
            compression,
            compressed_size,
            uncompressed_size,
            local_header_offset,
        });
        pos = name_end + extra_len + comment_len;
    }

    Ok(entries)
}

/// Extract the raw (possibly compressed) data for a given `ApkEntry`.
///
/// Returns the *stored* bytes (not decompressed) for compression=0,
/// or the compressed bytes for deflate. Decompression is left to the caller.
///
/// # Errors
/// Returns `AndroidLoaderError::InvalidZip` if the local file header is corrupt.
pub fn extract_entry_data<'a>(
    data: &'a [u8],
    entry: &ApkEntry,
) -> Result<&'a [u8], AndroidLoaderError> {
    let lhoff = entry.local_header_offset as usize;
    if lhoff + 30 > data.len() || data[lhoff..lhoff + 4] != [0x50, 0x4B, 0x03, 0x04] {
        return Err(AndroidLoaderError::InvalidZip);
    }
    let fname_len = u16::from_le_bytes([data[lhoff + 26], data[lhoff + 27]]) as usize;
    let extra_len = u16::from_le_bytes([data[lhoff + 28], data[lhoff + 29]]) as usize;
    let data_start = lhoff + 30 + fname_len + extra_len;
    let data_end = data_start + entry.compressed_size as usize;
    if data_end > data.len() {
        return Err(AndroidLoaderError::InvalidZip);
    }
    Ok(&data[data_start..data_end])
}

// ── ABI detection ─────────────────────────────────────────────────────────────

/// Android ABI identifiers for native libraries.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AndroidAbi {
    Armeabi,
    ArmeabiV7a,
    Arm64V8a,
    X86,
    X86_64,
    Mips,
    Mips64,
    Unknown,
}

impl AndroidAbi {
    /// Decode from the ABI directory name.
    #[must_use]
    pub fn from_str(s: &str) -> Self {
        match s {
            "armeabi" => Self::Armeabi,
            "armeabi-v7a" => Self::ArmeabiV7a,
            "arm64-v8a" => Self::Arm64V8a,
            "x86" => Self::X86,
            "x86_64" => Self::X86_64,
            "mips" => Self::Mips,
            "mips64" => Self::Mips64,
            _ => Self::Unknown,
        }
    }

    /// Returns the pointer width for this ABI.
    #[must_use]
    pub const fn pointer_bits(self) -> u32 {
        match self {
            Self::Arm64V8a | Self::X86_64 | Self::Mips64 => 64,
            _ => 32,
        }
    }
}

impl fmt::Display for AndroidAbi {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Armeabi => "armeabi",
            Self::ArmeabiV7a => "armeabi-v7a",
            Self::Arm64V8a => "arm64-v8a",
            Self::X86 => "x86",
            Self::X86_64 => "x86_64",
            Self::Mips => "mips",
            Self::Mips64 => "mips64",
            Self::Unknown => "unknown",
        };
        write!(f, "{s}")
    }
}

// ── APK info ─────────────────────────────────────────────────────────────────

/// Metadata extracted from an APK file.
#[derive(Debug, Clone)]
pub struct ApkInfo {
    /// Application package name (from manifest or heuristic).
    pub package_name: String,
    /// Parsed DEX files found in the archive.
    pub dex_files: Vec<DexFile>,
    /// Whether any native `.so` libraries are present.
    pub has_native_libs: bool,
    /// Set of native ABIs present.
    pub native_abis: HashSet<String>,
    /// Manifest-declared entry/launcher class, if found.
    pub entry_class: Option<String>,
    /// Central directory entries.
    pub entries: Vec<ApkEntry>,
    /// Parsed Android manifest, if available.
    pub manifest: Option<AndroidManifest>,
    /// APK signing scheme versions detected.
    pub signing_schemes: Vec<ApkSigningScheme>,
}

impl ApkInfo {
    /// Build a mock `ApkInfo` for testing.
    #[must_use]
    pub fn mock() -> Self {
        Self {
            package_name: "com.example.app".to_string(),
            dex_files: vec![],
            has_native_libs: false,
            native_abis: HashSet::new(),
            entry_class: Some("com.example.app.MainActivity".to_string()),
            entries: vec![],
            manifest: None,
            signing_schemes: vec![],
        }
    }

    /// Parse basic APK metadata by scanning for known ZIP local file headers.
    #[must_use]
    pub fn from_data(data: &[u8]) -> Self {
        let has_native_libs = data.windows(3).any(|w| w == b".so");
        let has_classes_dex = data.windows(11).any(|w| w == b"classes.dex");
        // Finding `classes.dex` in the raw bytes proves the input looks like an
        // APK; it says NOTHING about the package name, which lives in the
        // manifest this byte-scan never reads. Both branches therefore report
        // the empty string — the honest "not determined" — instead of the old
        // `"com.unknown.app"`, which impersonated a parsed value. Callers that
        // need the real name must use [`ApkInfo::parse`].
        let _ = has_classes_dex;
        let package_name = String::new();
        Self {
            package_name,
            dex_files: vec![],
            has_native_libs,
            native_abis: HashSet::new(),
            entry_class: None,
            entries: vec![],
            manifest: None,
            signing_schemes: vec![],
        }
    }

    /// Full parse of an APK: central directory → entries → DEX → manifest.
    pub fn parse(data: &[u8]) -> Result<Self, AndroidLoaderError> {
        let entries = parse_apk_entries(data)?;
        let mut dex_files = Vec::new();
        let mut has_native_libs = false;
        let mut native_abis = HashSet::new();
        let mut manifest = None;

        for entry in &entries {
            if entry.is_native_lib() {
                has_native_libs = true;
                if let Some(abi) = entry.native_abi() {
                    native_abis.insert(abi.to_owned());
                }
            }
            if entry.is_dex() && entry.compression == 0
                && let Ok(raw) = extract_entry_data(data, entry)
                    && let Ok(dex) = DexFile::parse(raw) {
                        dex_files.push(dex);
                    }
            if entry.is_manifest() && entry.compression == 0
                && let Ok(raw) = extract_entry_data(data, entry) {
                    manifest = parse_manifest(raw).ok();
                }
        }

        // An unread manifest means the package name is UNKNOWN, and the empty
        // string says so. Until 2026-07-29 this fell back to the literal
        // "com.unknown.app", which is shaped exactly like a real package name:
        // nothing downstream could tell an invented one from a parsed one.
        //
        // This is not a rare edge case. The loop above only parses a manifest
        // when `entry.is_manifest() && entry.compression == 0`, while real APKs
        // almost always store `AndroidManifest.xml` deflated — so for most
        // genuine inputs `manifest` is `None` and this branch is the one taken.
        //
        // `from_data` already reported the same "unknown" case as `String::new()`
        // in its else branch, so the crate was contradicting itself.
        let package_name = manifest
            .as_ref()
            .map(|m| m.package_name.clone())
            .filter(|p| !p.is_empty())
            .unwrap_or_default();

        let signing_schemes = detect_signing_schemes(data);

        Ok(Self {
            package_name,
            dex_files,
            has_native_libs,
            native_abis,
            entry_class: None,
            entries,
            manifest,
            signing_schemes,
        })
    }
}

impl fmt::Display for ApkInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "APK package={} dex_count={} native_libs={} abis=[{}]",
            self.package_name,
            self.dex_files.len(),
            self.has_native_libs,
            self.native_abis
                .iter()
                .cloned()
                .collect::<Vec<_>>()
                .join(","),
        )
    }
}

// ── APK Signing Block detection ──────────────────────────────────────────────

/// APK signing scheme version.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApkSigningScheme {
    /// v1: JAR signing (META-INF/*.SF + META-INF/*.RSA).
    V1Jar,
    /// v2: APK Signature Block embedded before the ZIP Central Directory.
    V2,
    /// v3: APK Signature Block v3 with key rotation.
    V3,
    /// v4: .idsig sidecar file (separate, cannot be detected from APK alone).
    V4,
}

impl fmt::Display for ApkSigningScheme {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::V1Jar => write!(f, "v1-jar"),
            Self::V2 => write!(f, "v2"),
            Self::V3 => write!(f, "v3"),
            Self::V4 => write!(f, "v4"),
        }
    }
}

/// Detect which APK signing schemes are present in `data`.
///
/// - v1: scan central directory for `META-INF/*.SF`.
/// - v2/v3: scan for the `"APK Sig Block 42"` magic at the 16 bytes before the
///   APK Signing Block size field, which itself sits just before the EOCD.
///
/// Reference: <https://source.android.com/docs/security/features/apksigning>
#[must_use]
pub fn detect_signing_schemes(data: &[u8]) -> Vec<ApkSigningScheme> {
    let mut schemes = Vec::new();

    // v1: look for .SF file in META-INF/
    if data.windows(8).any(|w| w == b"META-INF") {
        // Presence of .SF means v1 signatures exist
        if data.windows(3).any(|w| w == b".SF") {
            schemes.push(ApkSigningScheme::V1Jar);
        }
    }

    // v2 / v3: scan for the APK Sig Block magic `"APK Sig Block 42"`
    let magic_v2 = b"APK Sig Block 42";
    if let Some(pos) = data.windows(16).rposition(|w| w == magic_v2) {
        // The 8 bytes before the magic are the block size (u64 LE).
        // The ID-value pairs inside the block contain the scheme ID.
        // Simplified: if we find the magic, we declare at least v2.
        schemes.push(ApkSigningScheme::V2);
        // Check for v3 block ID: 0xF05368C0
        // Only search within the APK Signing Block region to avoid false positives.
        // The 8 bytes before the magic hold the block size (u64 LE); the block
        // starts at pos - block_size + 8 (the size field itself is the last 8 bytes
        // of the block). We clamp to avoid underflow on malformed input.
        let v3_id = [0xC0, 0x68, 0x53, 0xF0];
        if pos >= 8 {
            let block_size = u64::from_le_bytes(
                data[pos - 8..pos].try_into().unwrap_or([0xFF; 8]),
            ) as usize;
            let block_start = pos.saturating_sub(block_size.saturating_sub(8));
            let block_end = pos + 16; // magic (16 bytes) ends here
            let block_end = block_end.min(data.len());
            let search_region = &data[block_start..block_end];
            if search_region.windows(4).any(|w| w == v3_id) {
                schemes.push(ApkSigningScheme::V3);
            }
        }
    }

    schemes
}

// ── ART VDEX format ───────────────────────────────────────────────────────────

/// Parsed VDEX file header.
///
/// The VDEX format is documented in AOSP `art/runtime/vdex_file.h`.
/// Magic: `"vdex"`, followed by a 4-byte version string, then the header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VdexHeader {
    /// Magic bytes (`"vdex"`).
    pub magic: [u8; 4],
    /// VDEX version (e.g. `"019\0"`).
    pub version: [u8; 4],
    /// Number of embedded DEX files.
    pub number_of_dex_files: u32,
    /// Total size of the DEX section.
    pub dex_section_size: u32,
    /// Size of the DEX shared data section (version >= 021).
    pub dex_shared_data_size: u32,
    /// Size of the verifier deps section.
    pub verifier_deps_size: u32,
    /// Size of the quickening info section.
    pub quicken_info_size: u32,
}

impl VdexHeader {
    /// Parse a VDEX header from the beginning of `data`.
    ///
    /// # Errors
    /// Returns `AndroidLoaderError::InvalidMagic` if magic != `"vdex"`.
    /// Returns `AndroidLoaderError::TruncatedHeader` if data is too short.
    pub fn parse(data: &[u8]) -> Result<Self, AndroidLoaderError> {
        if data.len() < 28 {
            return Err(AndroidLoaderError::TruncatedHeader);
        }
        if &data[0..4] != b"vdex" {
            return Err(AndroidLoaderError::InvalidMagic);
        }
        let magic: [u8; 4] = data[0..4].try_into().unwrap();
        let version: [u8; 4] = data[4..8].try_into().unwrap();
        let rd = |o: usize| u32::from_le_bytes(data[o..o + 4].try_into().unwrap());
        let number_of_dex_files = rd(8);
        // Guard against arithmetic overflow in dex_start_offset(). When the
        // caller has provided extra trailing bytes (i.e. `data.len() > 28`),
        // also require the checksum array to fit so that crafted
        // `number_of_dex_files` values can't sail through.
        match (number_of_dex_files as usize).checked_mul(4) {
            None => return Err(AndroidLoaderError::TruncatedHeader),
            Some(needed) if data.len() > 28 && 28 + needed > data.len() => {
                return Err(AndroidLoaderError::TruncatedHeader);
            }
            _ => {}
        }
        Ok(Self {
            magic,
            version,
            number_of_dex_files,
            dex_section_size: rd(12),
            dex_shared_data_size: rd(16),
            verifier_deps_size: rd(20),
            quicken_info_size: rd(24),
        })
    }

    /// Return the version string (e.g. `"019"`).
    #[must_use]
    pub fn version_str(&self) -> &str {
        std::str::from_utf8(&self.version[..3]).unwrap_or("???")
    }

    /// Offset at which the first embedded DEX file starts.
    ///
    /// After the fixed header (28 bytes) come `number_of_dex_files` u32
    /// checksum values, then the DEX data itself.
    #[must_use]
    pub const fn dex_start_offset(&self) -> usize {
        28 + self.number_of_dex_files as usize * 4
    }
}

impl fmt::Display for VdexHeader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "VDEX v{} dex_files={} dex_size={} deps={} quicken={}",
            self.version_str(),
            self.number_of_dex_files,
            self.dex_section_size,
            self.verifier_deps_size,
            self.quicken_info_size
        )
    }
}

/// Extract embedded DEX files from a VDEX image.
///
/// VDEX embeds consecutive `dex\n` files after its checksum array.
/// Each DEX file is self-describing (`file_size` field in its header).
///
/// # Errors
/// Returns `AndroidLoaderError::TruncatedHeader` if header parse fails.
pub fn extract_vdex_dex_files(data: &[u8]) -> Result<Vec<DexFile>, AndroidLoaderError> {
    let hdr = VdexHeader::parse(data)?;
    let mut offset = hdr.dex_start_offset();
    // Cap pre-allocation: each embedded DEX is at least 112 bytes (min header).
    // This prevents OOM from a crafted number_of_dex_files field.
    let capacity = (hdr.number_of_dex_files as usize).min(data.len() / 112 + 1);
    let mut dex_files = Vec::with_capacity(capacity);

    for _ in 0..hdr.number_of_dex_files {
        if offset >= data.len() {
            break;
        }
        let dex_slice = &data[offset..];
        if !is_dex(dex_slice) {
            break;
        }
        // Read file_size from the DEX header at offset 32..36
        if dex_slice.len() < 36 {
            break;
        }
        let file_size = u32::from_le_bytes(dex_slice[32..36].try_into().unwrap()) as usize;
        let end = offset + file_size;
        if end > data.len() {
            break;
        }
        if let Ok(dex) = DexFile::parse(&data[offset..end]) {
            dex_files.push(dex);
        }
        offset = end;
    }

    Ok(dex_files)
}

// ── AXML parser ───────────────────────────────────────────────────────────────

/// Parsed Android manifest fields extracted from AXML (binary XML).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct AndroidManifest {
    /// Application package name (e.g. `com.example.app`).
    pub package_name: String,
    /// Human-readable version string (e.g. `"1.0"`).
    pub version_name: String,
    /// Integer version code.
    pub version_code: u32,
    /// Minimum supported SDK level.
    pub min_sdk: u32,
    /// Target SDK level.
    pub target_sdk: u32,
    /// Declared permissions (e.g. `android.permission.INTERNET`).
    pub permissions: Vec<String>,
    /// Exported activities.
    pub exported_activities: Vec<String>,
    /// Exported services.
    pub exported_services: Vec<String>,
    /// Exported receivers.
    pub exported_receivers: Vec<String>,
    /// Exported providers.
    pub exported_providers: Vec<String>,
    /// Intent filters on activities (maps activity name → actions).
    pub intent_filters: HashMap<String, Vec<String>>,
}

impl AndroidManifest {
    /// Collect all exported components into a flat list.
    #[must_use]
    pub fn attack_surface(&self) -> Vec<String> {
        let mut v = Vec::new();
        for a in &self.exported_activities {
            v.push(format!("activity:{a}"));
        }
        for s in &self.exported_services {
            v.push(format!("service:{s}"));
        }
        for r in &self.exported_receivers {
            v.push(format!("receiver:{r}"));
        }
        for p in &self.exported_providers {
            v.push(format!("provider:{p}"));
        }
        v
    }

    /// Returns `true` if any component is exported without explicit permissions.
    #[must_use]
    pub const fn has_unprotected_exports(&self) -> bool {
        !self.exported_activities.is_empty()
            || !self.exported_services.is_empty()
            || !self.exported_receivers.is_empty()
    }
}

/// Parse an Android binary XML (AXML) manifest from `bytes`.
///
/// Binary XML starts with the chunk header:
/// - `0x0003` (LE u16): file type = XML
/// - `0x0008` (LE u16): header size = 8 bytes
/// - u32 LE: total file size
///
/// Followed by a sequence of typed chunks. This parser walks the chunk stream
/// and decodes the string pool and start-element nodes to extract manifest
/// attributes by their known resource IDs.
///
/// # Errors
/// Returns `AndroidLoaderError::InvalidMagic` if magic does not match.
/// Returns `AndroidLoaderError::TruncatedHeader` if the data is too short.
pub fn parse_manifest(bytes: &[u8]) -> Result<AndroidManifest, AndroidLoaderError> {
    if bytes.len() < 8 {
        return Err(AndroidLoaderError::TruncatedHeader);
    }
    let file_type = u16::from_le_bytes([bytes[0], bytes[1]]);
    let hdr_size = u16::from_le_bytes([bytes[2], bytes[3]]);
    if file_type != 0x0003 || hdr_size != 0x0008 {
        return Err(AndroidLoaderError::InvalidMagic);
    }

    let total_size = u32::from_le_bytes(
        bytes[4..8]
            .try_into()
            .map_err(|_| AndroidLoaderError::ParseError("total_size".into()))?,
    ) as usize;
    let data = &bytes[..total_size.min(bytes.len())];

    let strings = parse_axml_string_pool(data);
    let mut manifest = AndroidManifest::default();

    let mut pos = 8usize;
    while pos + 8 <= data.len() {
        let chunk_type = u16::from_le_bytes([data[pos], data[pos + 1]]);
        let _chunk_hdr = u16::from_le_bytes([data[pos + 2], data[pos + 3]]);
        let chunk_size =
            u32::from_le_bytes(data[pos + 4..pos + 8].try_into().unwrap_or([0; 4])) as usize;
        if chunk_size == 0 || pos + chunk_size > data.len() {
            break;
        }

        if chunk_type == 0x0102 {
            parse_axml_start_element(&data[pos..pos + chunk_size], &strings, &mut manifest);
        }
        pos += chunk_size.max(8);
    }

    Ok(manifest)
}

/// Parse the string pool chunk and return strings indexed by their pool position.
fn parse_axml_string_pool(data: &[u8]) -> Vec<String> {
    let mut pos = 8usize;
    while pos + 8 <= data.len() {
        let chunk_type = u16::from_le_bytes([data[pos], data[pos + 1]]);
        let chunk_size =
            u32::from_le_bytes(data[pos + 4..pos + 8].try_into().unwrap_or([0; 4])) as usize;
        if chunk_size == 0 {
            break;
        }

        if chunk_type == 0x0001 && pos + 28 <= data.len() {
            let chunk_data = &data[pos..pos + chunk_size.min(data.len() - pos)];
            if chunk_data.len() < 28 {
                break;
            }
            let string_count =
                u32::from_le_bytes(chunk_data[8..12].try_into().unwrap_or([0; 4])) as usize;
            let flags = u32::from_le_bytes(chunk_data[16..20].try_into().unwrap_or([0; 4]));
            let strings_start =
                u32::from_le_bytes(chunk_data[20..24].try_into().unwrap_or([0; 4])) as usize;
            let is_utf8 = (flags & 0x100) != 0;

            let offsets_base = 28usize;
            // Cap pre-allocation: each string offset entry is 4 bytes.
            // This prevents OOM from a crafted string_count in the AXML pool.
            let capacity = string_count.min(chunk_data.len() / 4 + 1);
            let mut strings = Vec::with_capacity(capacity);
            for i in 0..string_count {
                let off_off = offsets_base + i * 4;
                if off_off + 4 > chunk_data.len() {
                    break;
                }
                let str_off = u32::from_le_bytes(
                    chunk_data[off_off..off_off + 4]
                        .try_into()
                        .unwrap_or([0; 4]),
                ) as usize
                    + strings_start;
                if str_off >= chunk_data.len() {
                    strings.push(String::new());
                    continue;
                }
                let s = if is_utf8 {
                    decode_axml_utf8_string(&chunk_data[str_off..])
                } else {
                    decode_axml_utf16_string(&chunk_data[str_off..])
                };
                strings.push(s);
            }
            return strings;
        }

        pos += chunk_size;
    }
    vec![]
}

/// Decode a length-prefixed UTF-8 string from an AXML string pool.
fn decode_axml_utf8_string(data: &[u8]) -> String {
    if data.is_empty() {
        return String::new();
    }
    let mut off = if data[0] & 0x80 != 0 { 2 } else { 1 };
    if off >= data.len() {
        return String::new();
    }
    let byte_len = if data[off] & 0x80 != 0 {
        let hi = (data[off] as usize & 0x7F) << 8;
        off += 1;
        if off >= data.len() {
            return String::new();
        }
        hi | (data[off] as usize)
    } else {
        data[off] as usize
    };
    off += 1;
    let end = (off + byte_len).min(data.len());
    String::from_utf8_lossy(&data[off..end]).into_owned()
}

/// Decode a length-prefixed UTF-16LE string from an AXML string pool.
fn decode_axml_utf16_string(data: &[u8]) -> String {
    if data.len() < 2 {
        return String::new();
    }
    let char_len = u16::from_le_bytes([data[0], data[1]]) as usize;
    let byte_len = char_len * 2;
    if 2 + byte_len > data.len() {
        return String::new();
    }
    let u16s: Vec<u16> = data[2..2 + byte_len]
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect();
    String::from_utf16_lossy(&u16s)
}

/// Known Android resource IDs for manifest attributes.
pub const RES_PACKAGE: u32 = 0x0101_021B;
pub const RES_VERSION_NAME: u32 = 0x0101_021C;
pub const RES_VERSION_CODE: u32 = 0x0101_0210;
pub const RES_MIN_SDK: u32 = 0x0101_020C;
pub const RES_TARGET_SDK: u32 = 0x0101_022A;
pub const RES_EXPORTED: u32 = 0x0101_021B;

/// Parse a start-element chunk and populate `manifest`.
fn parse_axml_start_element(chunk: &[u8], strings: &[String], manifest: &mut AndroidManifest) {
    if chunk.len() < 32 {
        return;
    }

    let name_idx = u32::from_le_bytes(chunk[20..24].try_into().unwrap_or([0xFF; 4])) as usize;
    let attr_start = u16::from_le_bytes([chunk[24], chunk[25]]) as usize;
    let attr_size = u16::from_le_bytes([chunk[26], chunk[27]]) as usize;
    let attr_count = u16::from_le_bytes([chunk[28], chunk[29]]) as usize;

    let elem_name = strings.get(name_idx).cloned().unwrap_or_default();
    let attrs_base = 16 + attr_start;

    // Collect all attributes first
    let mut attrs: HashMap<String, (String, u32, u8)> = HashMap::new();
    for i in 0..attr_count {
        let off = attrs_base + i * attr_size;
        if off + 20 > chunk.len() {
            break;
        }
        let attr_name_idx =
            u32::from_le_bytes(chunk[off + 4..off + 8].try_into().unwrap_or([0xFF; 4]));
        let raw_val_idx =
            i32::from_le_bytes(chunk[off + 8..off + 12].try_into().unwrap_or([0xFF; 4]));
        let data_type = chunk[off + 15];
        let data_val = u32::from_le_bytes(chunk[off + 16..off + 20].try_into().unwrap_or([0; 4]));

        let attr_name = strings
            .get(attr_name_idx as usize)
            .cloned()
            .unwrap_or_default();
        let raw_val = if raw_val_idx >= 0 {
            strings
                .get(raw_val_idx as usize)
                .cloned()
                .unwrap_or_default()
        } else {
            String::new()
        };
        attrs.insert(attr_name, (raw_val, data_val, data_type));
    }

    let get_str = |name: &str| -> String {
        attrs
            .get(name)
            .map(|(s, v, t)| {
                if !s.is_empty() {
                    return s.clone();
                }
                // Format raw value based on AXML data type byte.
                match *t {
                    0x11 => format!("0x{v:x}"), // TYPE_INT_HEX
                    0x12 => (if *v != 0 { "true" } else { "false" }).to_string(), // TYPE_INT_BOOLEAN
                    _ => v.to_string(),
                }
            })
            .unwrap_or_default()
    };
    let get_u32 = |name: &str| -> u32 {
        attrs
            .get(name)
            .map_or(0, |(s, v, _t)| {
                if s.is_empty() {
                    *v
                } else {
                    s.parse().unwrap_or(*v)
                }
            })
    };
    let get_bool = |name: &str| -> bool {
        attrs
            .get(name)
            .is_some_and(|(s, v, _t)| *v != 0 || s == "true")
    };

    match elem_name.as_str() {
        "manifest" => {
            let pkg = get_str("package");
            if !pkg.is_empty() {
                manifest.package_name = pkg;
            }
            let vn = get_str("versionName");
            if !vn.is_empty() {
                manifest.version_name = vn;
            }
            let vc = get_u32("versionCode");
            if vc != 0 {
                manifest.version_code = vc;
            }
        }
        "uses-sdk" => {
            let min = get_u32("minSdkVersion");
            if min != 0 {
                manifest.min_sdk = min;
            }
            let tgt = get_u32("targetSdkVersion");
            if tgt != 0 {
                manifest.target_sdk = tgt;
            }
        }
        "uses-permission" => {
            let name = get_str("name");
            if !name.is_empty() {
                manifest.permissions.push(name);
            }
        }
        "activity" => {
            if get_bool("exported") {
                let name = get_str("name");
                if !name.is_empty() {
                    manifest.exported_activities.push(name);
                }
            }
        }
        "service" => {
            if get_bool("exported") {
                let name = get_str("name");
                if !name.is_empty() {
                    manifest.exported_services.push(name);
                }
            }
        }
        "receiver" => {
            if get_bool("exported") {
                let name = get_str("name");
                if !name.is_empty() {
                    manifest.exported_receivers.push(name);
                }
            }
        }
        "provider" => {
            if get_bool("exported") {
                let name = get_str("name");
                if !name.is_empty() {
                    manifest.exported_providers.push(name);
                }
            }
        }
        "action" => {
            // Intent filter action — associate with last activity
            let action = get_str("name");
            if !action.is_empty()
                && let Some(last) = manifest.exported_activities.last().cloned() {
                    manifest
                        .intent_filters
                        .entry(last)
                        .or_default()
                        .push(action);
                }
        }
        _ => {}
    }
}

// ── DEX class scanner ─────────────────────────────────────────────────────────

/// Scan `dex_bytes` and return the list of class descriptor strings.
#[must_use]
pub fn list_dex_classes(dex_bytes: &[u8]) -> Vec<String> {
    if !is_dex(dex_bytes) || dex_bytes.len() < 112 {
        return vec![];
    }
    let hdr = match DexHeader::parse(dex_bytes) {
        Ok(h) => h,
        Err(_) => return vec![],
    };
    let strings = read_string_table(dex_bytes, &hdr);
    let type_ids = read_type_ids(dex_bytes, &hdr);
    let class_defs = read_class_defs(dex_bytes, &hdr);

    class_defs
        .iter()
        .filter_map(|def| {
            let tid = type_ids.get(def.class_idx as usize)?;
            let desc = strings.get(tid.descriptor_idx as usize)?;
            if desc.starts_with('L') && desc.ends_with(';') {
                Some(desc[1..desc.len() - 1].replace('/', "."))
            } else {
                Some(desc.clone())
            }
        })
        .collect()
}

/// Scan `dex_bytes` and return all Dalvik bytecode bytes across all methods.
///
/// Useful for bulk pattern matching / entropy analysis.
#[must_use]
pub fn collect_all_bytecode(dex_bytes: &[u8]) -> Vec<u8> {
    if !is_dex(dex_bytes) {
        return vec![];
    }
    let hdr = match DexHeader::parse(dex_bytes) {
        Ok(h) => h,
        Err(_) => return vec![],
    };
    let class_defs = read_class_defs(dex_bytes, &hdr);
    let mut out = Vec::new();
    for def in &class_defs {
        if def.class_data_off == 0 {
            continue;
        }
        let methods = parse_encoded_methods(dex_bytes, def.class_data_off);
        for m in methods {
            if m.code_off == 0 {
                continue;
            }
            if let Some(ci) = CodeItem::parse(dex_bytes, m.code_off as usize) {
                out.extend_from_slice(&ci.bytecode_bytes());
            }
        }
    }
    out
}

// ── Architecture stub ────────────────────────────────────────────────────────

/// Minimal Architecture implementation for the Android/Dalvik target (ARM64 placeholder).
#[derive(Debug)]
pub struct AndroidArch;

impl Architecture for AndroidArch {
    fn name(&self) -> &'static str {
        "aarch64"
    }
    fn pointer_size(&self) -> usize {
        8
    }
    fn endian(&self) -> Endian {
        Endian::Little
    }

    fn disassemble(&self, address: Address, bytes: &[u8]) -> Result<Instruction, CoreError> {
        // This used to answer `nop` for every input, sized `len.min(4).max(1)`.
        // `name()` reports "aarch64", so a caller would need an ARM64 decoder —
        // which this crate does not have: it loads APK/DEX/ART containers and
        // classifies Dalvik opcodes (`dalvik_opcode_class`) without decoding
        // mnemonics or lengths for either instruction set.
        if bytes.is_empty() {
            return Err(CoreError::InvalidInput {
                message: "disassemble called with empty byte slice".into(),
            });
        }
        Err(CoreError::ArchitectureError {
            arch: self.name().to_string(),
            message: "rustre-loader-android loads Android containers but does not \
                      decode instructions; use an arch crate for the target ISA"
                .into(),
        })
    }

    fn get_branches(&self, _instr: &Instruction) -> Vec<BranchInfo> {
        vec![]
    }

    fn registers(&self) -> Vec<RegisterInfo> {
        (0u32..31)
            .map(|i| RegisterInfo::new(format!("x{i}"), i, 8, RegisterKind::General))
            .collect()
    }

    fn calling_conventions(&self) -> Vec<CallingConvention> {
        vec![
            CallingConvention::new("aapcs64")
                .with_int_args(vec![
                    "x0".to_string(),
                    "x1".to_string(),
                    "x2".to_string(),
                    "x3".to_string(),
                    "x4".to_string(),
                    "x5".to_string(),
                    "x6".to_string(),
                    "x7".to_string(),
                ])
                .with_return_regs(vec!["x0".to_string()]),
        ]
    }
}

// ── Loader ───────────────────────────────────────────────────────────────────

/// Loader for Android APK and DEX bytecode files.
#[derive(Debug)]
pub struct AndroidLoader;

#[async_trait]
impl Loader for AndroidLoader {
    fn name(&self) -> &'static str {
        "android"
    }

    fn can_load(&self, input: &LoaderInput) -> bool {
        is_apk(&input.data) || is_dex(&input.data) || is_vdex(&input.data)
    }

    async fn load(&self, input: LoaderInput) -> Result<LoadResult, CoreError> {
        let base = input
            .hints
            .base_address()
            .map_or(0x1000_u64, rustre_core::Address::as_u64);

        let mut mem = Memory::new();
        let size = input.data.len() as u64;
        mem.add_segment(Segment {
            range: AddressRange::new(Address::new(base), Address::new(base + size)),
            permissions: Permissions::READ,
            data: input.data.clone(),
        });

        let arch = Arc::new(AndroidArch);
        let view_id = ViewId::from_raw(1);
        let view = BinaryView::new(
            view_id,
            input.uri,
            arch,
            Endian::Little,
            64,
            vec![Address::new(base)],
            mem,
        );
        Ok(LoadResult::new(view))
    }

    async fn find_nested(&self, input: &LoaderInput) -> Result<Vec<NestedBinary>, CoreError> {
        if !is_apk(&input.data) {
            return Ok(vec![]);
        }

        // Use parse_apk_entries to enumerate all DEX files, including
        // multidex (classes2.dex, classes3.dex, …).
        let entries = parse_apk_entries(&input.data).unwrap_or_default();
        let mut nested = vec![];
        // Fallback: if the central directory could not be parsed but the APK
        // clearly references `classes.dex`, emit a stub nested entry so that
        // downstream callers still see at least one DEX placeholder.
        if entries.is_empty()
            && let Some(pos) = input.data.windows(11).position(|w| w == b"classes.dex")
        {
            nested.push(NestedBinary::new(
                "classes.dex",
                Vec::new(),
                pos as u64,
                BinaryType::Java,
            ));
        }
        for entry in &entries {
            let name = entry.name.as_str();
            // Match classes.dex and classesN.dex (N >= 2).
            let is_dex = name == "classes.dex"
                || (name.starts_with("classes") && name.ends_with(".dex"));
            if !is_dex {
                continue;
            }
            if let Ok(raw) = extract_entry_data(&input.data, entry) {
                let offset = entry.local_header_offset as usize
                    + 30
                    + entry.name.len();
                nested.push(NestedBinary::new(
                    name,
                    raw.to_vec(),
                    offset as u64,
                    BinaryType::Java,
                ));
            }
        }

        Ok(nested)
    }
}

// ── Dalvik opcode helpers ────────────────────────────────────────────────────

/// Dalvik opcode families (top-level categories).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DalvikOpcodeClass {
    Move,
    Return,
    Const,
    Monitor,
    CheckCast,
    InstanceOf,
    ArrayLen,
    NewInstance,
    NewArray,
    FillArray,
    Throw,
    Goto,
    Switch,
    Compare,
    If,
    Array,
    Instance,
    Static,
    Invoke,
    Unary,
    Binary,
    Unknown,
}

/// Classify a Dalvik opcode byte into its family.
#[must_use]
pub const fn dalvik_opcode_class(opcode: u8) -> DalvikOpcodeClass {
    match opcode {
        0x01..=0x0D => DalvikOpcodeClass::Move,
        0x0E..=0x11 => DalvikOpcodeClass::Return,
        0x12..=0x1C => DalvikOpcodeClass::Const,
        0x1D..=0x1E => DalvikOpcodeClass::Monitor,
        0x1F => DalvikOpcodeClass::CheckCast,
        0x20 => DalvikOpcodeClass::InstanceOf,
        0x21 => DalvikOpcodeClass::ArrayLen,
        0x22 => DalvikOpcodeClass::NewInstance,
        0x23 => DalvikOpcodeClass::NewArray,
        0x24..=0x26 => DalvikOpcodeClass::FillArray,
        0x27 => DalvikOpcodeClass::Throw,
        0x28..=0x2A => DalvikOpcodeClass::Goto,
        0x2B..=0x2C => DalvikOpcodeClass::Switch,
        0x2D..=0x31 => DalvikOpcodeClass::Compare,
        0x32..=0x3D => DalvikOpcodeClass::If,
        0x44..=0x51 => DalvikOpcodeClass::Array,
        0x52..=0x5F => DalvikOpcodeClass::Instance,
        0x60..=0x6D => DalvikOpcodeClass::Static,
        0x6E..=0x78 => DalvikOpcodeClass::Invoke,
        0x7B..=0x8F => DalvikOpcodeClass::Unary,
        0x90..=0xE2 => DalvikOpcodeClass::Binary,
        _ => DalvikOpcodeClass::Unknown,
    }
}

/// Count opcode family frequencies in a sequence of Dalvik bytecode units.
///
/// `insns` is the raw slice of 16-bit code units.  Only the low byte of each
/// unit is used as the opcode for this classification (the full Dalvik encoding
/// can carry the opcode in byte 0 and operands in byte 1 of the first unit).
#[must_use]
pub fn opcode_histogram(insns: &[u16]) -> HashMap<DalvikOpcodeClass, usize> {
    let mut map: HashMap<DalvikOpcodeClass, usize> = HashMap::new();
    for &unit in insns {
        let opcode = (unit & 0xFF) as u8;
        *map.entry(dalvik_opcode_class(opcode)).or_insert(0) += 1;
    }
    map
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn minimal_dex() -> Vec<u8> {
        let mut v = vec![0u8; 112];
        v[0..8].copy_from_slice(b"dex\n035\0");
        v[32] = 112; // file_size = 112
        v[36] = 112; // header_size = 112
        v[40] = 0x78;
        v[41] = 0x56;
        v[42] = 0x34;
        v[43] = 0x12; // endian_tag
        v
    }

    // ── magic detection ───────────────────────────────────────────────────────

    #[test]
    fn test_is_dex_valid_035() {
        assert!(is_dex(&minimal_dex()));
    }

    #[test]
    fn test_is_dex_valid_036() {
        let mut data = vec![0u8; 112];
        data[..8].copy_from_slice(b"dex\n036\0");
        assert!(is_dex(&data));
    }

    #[test]
    fn test_is_dex_too_short() {
        assert!(!is_dex(b"dex\n03"));
    }

    #[test]
    fn test_is_dex_wrong_magic() {
        assert!(!is_dex(b"ELF\x7f000000000000000000000000"));
    }

    #[test]
    fn test_is_apk_valid() {
        let mut data = b"PK\x03\x04".to_vec();
        data.extend_from_slice(&[0u8; 200]);
        data.extend_from_slice(b"classes.dex");
        assert!(is_apk(&data));
    }

    #[test]
    fn test_is_apk_no_classes_dex() {
        assert!(!is_apk(b"PK\x03\x04someotherfile.dat"));
    }

    #[test]
    fn test_is_apk_not_zip() {
        assert!(!is_apk(b"\x00\x00\x00\x00classes.dex"));
    }

    #[test]
    fn test_is_vdex_valid() {
        let mut data = vec![0u8; 28];
        data[..4].copy_from_slice(b"vdex");
        data[4..8].copy_from_slice(b"019\0");
        assert!(is_vdex(&data));
    }

    #[test]
    fn test_is_vdex_invalid() {
        assert!(!is_vdex(b"notv"));
    }

    // ── Adler-32 ──────────────────────────────────────────────────────────────

    #[test]
    fn test_adler32_empty() {
        assert_eq!(adler32(&[]), 1);
    }

    #[test]
    fn test_adler32_known() {
        // Wikipedia example: adler32("Wikipedia") = 0x11E60398
        let result = adler32(b"Wikipedia");
        assert_eq!(result, 0x11E6_0398);
    }

    // ── DexHeader ─────────────────────────────────────────────────────────────

    fn make_dex_header() -> Vec<u8> {
        let mut data = vec![0u8; 112];
        data[..8].copy_from_slice(b"dex\n035\0");
        data[8..12].copy_from_slice(&0xDEAD_BEEF_u32.to_le_bytes());
        data[32..36].copy_from_slice(&112_u32.to_le_bytes());
        data[36..40].copy_from_slice(&112_u32.to_le_bytes());
        data[40..44].copy_from_slice(&0x1234_5678_u32.to_le_bytes()); // LE endian tag
        data[56..60].copy_from_slice(&5_u32.to_le_bytes());
        data[60..64].copy_from_slice(&0x70_u32.to_le_bytes());
        data[64..68].copy_from_slice(&3_u32.to_le_bytes());
        data[72..76].copy_from_slice(&7_u32.to_le_bytes());
        data[88..92].copy_from_slice(&8_u32.to_le_bytes());
        data[96..100].copy_from_slice(&2_u32.to_le_bytes());
        data[100..104].copy_from_slice(&0xFFFF_FFFF_u32.to_le_bytes()); // class_defs_off past EOF
        data
    }

    #[test]
    fn test_dex_header_parse() {
        let data = make_dex_header();
        let hdr = DexHeader::parse(&data).unwrap();
        assert_eq!(&hdr.magic, b"dex\n035\0");
        assert_eq!(hdr.checksum, 0xDEAD_BEEF);
        assert_eq!(hdr.file_size, 112);
        assert_eq!(hdr.header_size, 112);
        assert_eq!(hdr.string_ids_size, 5);
        assert_eq!(hdr.type_ids_size, 3);
        assert_eq!(hdr.method_ids_size, 8);
        assert_eq!(hdr.class_defs_size, 2);
    }

    #[test]
    fn test_dex_header_truncated() {
        let err = DexHeader::parse(&[0u8; 10]).unwrap_err();
        assert!(matches!(err, AndroidLoaderError::TruncatedHeader));
    }

    #[test]
    fn test_dex_header_invalid_magic() {
        let mut data = vec![0u8; 112];
        data[..4].copy_from_slice(b"ELF\x7f");
        assert!(matches!(
            DexHeader::parse(&data).unwrap_err(),
            AndroidLoaderError::InvalidMagic
        ));
    }

    #[test]
    fn test_dex_header_is_valid() {
        let hdr = DexHeader::parse(&make_dex_header()).unwrap();
        assert!(hdr.is_valid());
    }

    #[test]
    fn test_dex_header_version_str() {
        let hdr = DexHeader::parse(&make_dex_header()).unwrap();
        assert_eq!(hdr.version_str(), "035");
    }

    #[test]
    fn test_dex_header_version_int() {
        let hdr = DexHeader::parse(&make_dex_header()).unwrap();
        assert_eq!(hdr.version_int(), 35);
    }

    #[test]
    fn test_dex_header_is_little_endian() {
        let hdr = DexHeader::parse(&make_dex_header()).unwrap();
        assert!(hdr.is_little_endian());
    }

    #[test]
    fn test_dex_header_display() {
        let hdr = DexHeader::parse(&make_dex_header()).unwrap();
        let s = hdr.to_string();
        assert!(s.contains("DEX"));
        assert!(s.contains("112"));
    }

    // ── DexFile ───────────────────────────────────────────────────────────────

    #[test]
    fn test_dex_file_parse() {
        let data = make_dex_header();
        let dex = DexFile::parse(&data).unwrap();
        assert_eq!(dex.class_defs.len(), 0); // offsets point past data
        assert_eq!(dex.header.class_defs_size, 2);
    }

    #[test]
    fn test_dex_file_parse_error_propagated() {
        let err = DexFile::parse(&[0u8; 10]).unwrap_err();
        assert!(matches!(err, AndroidLoaderError::TruncatedHeader));
    }

    #[test]
    fn test_dex_file_display() {
        let data = make_dex_header();
        let dex = DexFile::parse(&data).unwrap();
        assert!(dex.to_string().contains("DexFile"));
    }

    // ── ApkInfo ───────────────────────────────────────────────────────────────

    #[test]
    fn test_apk_info_mock() {
        let info = ApkInfo::mock();
        assert_eq!(info.package_name, "com.example.app");
        assert!(info.entry_class.is_some());
        assert!(!info.has_native_libs);
    }

    /// The third test that was pinning the invented package name.
    ///
    /// It asserted `!info.package_name.is_empty()`, which only held because
    /// `from_data` manufactured `"com.unknown.app"` on seeing `classes.dex`.
    /// Corrected 2026-07-29 to assert the honest outcome: a byte scan never
    /// reads the manifest, so the name is not determined. The APK-ness of the
    /// input is still asserted — via the signal that IS observable in bytes.
    #[test]
    fn test_apk_info_from_data_with_dex() {
        let mut data = b"PK\x03\x04".to_vec();
        data.extend_from_slice(b"classes.dex");
        let info = ApkInfo::from_data(&data);
        assert!(
            info.package_name.is_empty(),
            "from_data must not invent a package name it cannot read"
        );
        assert!(
            !info.has_native_libs,
            "no .so present, so no native libs may be reported"
        );
    }

    #[test]
    fn test_apk_info_from_data_native_libs() {
        let data = b"PK\x03\x04libfoo.so classes.dex";
        let info = ApkInfo::from_data(data);
        assert!(info.has_native_libs);
    }

    #[test]
    fn test_apk_info_display() {
        let info = ApkInfo::mock();
        let s = info.to_string();
        assert!(s.contains("APK"));
    }

    // ── ApkEntry ──────────────────────────────────────────────────────────────

    #[test]
    fn test_apk_entry_is_dex() {
        let e = ApkEntry {
            name: "classes.dex".to_string(),
            compression: 0,
            compressed_size: 100,
            uncompressed_size: 100,
            local_header_offset: 0,
        };
        assert!(e.is_dex());
    }

    #[test]
    fn test_apk_entry_is_manifest() {
        let e = ApkEntry {
            name: "AndroidManifest.xml".to_string(),
            compression: 0,
            compressed_size: 200,
            uncompressed_size: 200,
            local_header_offset: 0,
        };
        assert!(e.is_manifest());
    }

    #[test]
    fn test_apk_entry_native_abi() {
        let e = ApkEntry {
            name: "lib/arm64-v8a/libfoo.so".to_string(),
            compression: 0,
            compressed_size: 1024,
            uncompressed_size: 1024,
            local_header_offset: 0,
        };
        assert!(e.is_native_lib());
        assert_eq!(e.native_abi(), Some("arm64-v8a"));
    }

    // ── AndroidAbi ────────────────────────────────────────────────────────────

    #[test]
    fn test_android_abi_from_str() {
        assert_eq!(AndroidAbi::from_str("arm64-v8a"), AndroidAbi::Arm64V8a);
        assert_eq!(AndroidAbi::from_str("x86_64"), AndroidAbi::X86_64);
        assert_eq!(AndroidAbi::from_str("unknown"), AndroidAbi::Unknown);
    }

    #[test]
    fn test_android_abi_pointer_bits() {
        assert_eq!(AndroidAbi::Arm64V8a.pointer_bits(), 64);
        assert_eq!(AndroidAbi::ArmeabiV7a.pointer_bits(), 32);
    }

    #[test]
    fn test_android_abi_display() {
        assert_eq!(AndroidAbi::X86.to_string(), "x86");
    }

    // ── DalvikOpcodeClass ─────────────────────────────────────────────────────

    #[test]
    fn test_dalvik_opcode_class_move() {
        assert_eq!(dalvik_opcode_class(0x01), DalvikOpcodeClass::Move);
    }

    #[test]
    fn test_dalvik_opcode_class_invoke() {
        assert_eq!(dalvik_opcode_class(0x6E), DalvikOpcodeClass::Invoke);
    }

    #[test]
    fn test_dalvik_opcode_class_unknown() {
        assert_eq!(dalvik_opcode_class(0x00), DalvikOpcodeClass::Unknown);
    }

    #[test]
    fn test_opcode_histogram() {
        // 0x6E = invoke-virtual (low byte), 0x01 = move
        let insns: Vec<u16> = vec![0x006E, 0x0001, 0x006E];
        let hist = opcode_histogram(&insns);
        assert_eq!(
            hist.get(&DalvikOpcodeClass::Invoke).copied().unwrap_or(0),
            2
        );
        assert_eq!(hist.get(&DalvikOpcodeClass::Move).copied().unwrap_or(0), 1);
    }

    // ── Error display ─────────────────────────────────────────────────────────

    #[test]
    fn test_error_invalid_magic_display() {
        assert!(
            AndroidLoaderError::InvalidMagic
                .to_string()
                .contains("magic")
        );
    }

    #[test]
    fn test_error_truncated_header_display() {
        assert!(
            AndroidLoaderError::TruncatedHeader
                .to_string()
                .contains("truncated")
        );
    }

    #[test]
    fn test_error_parse_error_display() {
        let e = AndroidLoaderError::ParseError("bad field".into());
        assert!(e.to_string().contains("bad field"));
    }

    #[test]
    fn test_error_checksum_mismatch_display() {
        let e = AndroidLoaderError::ChecksumMismatch {
            expected: 0xDEAD,
            computed: 0xBEEF,
        };
        assert!(e.to_string().contains("mismatch"));
    }

    // ── Architecture ──────────────────────────────────────────────────────────

    #[test]
    fn test_android_arch_name() {
        assert_eq!(AndroidArch.name(), "aarch64");
    }

    #[test]
    fn test_android_arch_pointer_size() {
        assert_eq!(AndroidArch.pointer_size(), 8);
    }

    #[test]
    fn android_arch_disassemble_admits_it_cannot_decode() {
        // The old body returned `nop` sized `len.min(4).max(1)` for anything,
        // so four bytes of ARM64 became a one-instruction "nop" and a single
        // byte became a shorter one — plausible shapes, no relation to the code.
        let err = AndroidArch
            .disassemble(Address::new(0), &[0x1F, 0x20, 0x03, 0xD5])
            .expect_err("must not claim to have decoded ARM64");
        let text = err.to_string();
        assert!(
            text.contains("aarch64"),
            "the error should name the architecture, got: {text}"
        );
        assert!(AndroidArch.disassemble(Address::new(0), &[]).is_err());
    }

    #[test]
    fn test_android_arch_endian() {
        assert_eq!(AndroidArch.endian(), Endian::Little);
    }

    #[test]
    fn test_android_arch_registers() {
        let regs = AndroidArch.registers();
        assert_eq!(regs.len(), 31);
        assert_eq!(regs[0].name, "x0");
        assert_eq!(regs[30].name, "x30");
    }

    #[test]
    fn test_android_arch_calling_conventions() {
        let cc = AndroidArch.calling_conventions();
        assert_eq!(cc.len(), 1);
        assert_eq!(cc[0].name, "aapcs64");
        assert_eq!(cc[0].int_args.len(), 8);
    }

    #[test]
    fn test_android_arch_disassemble() {
        // Kept, with its assertions inverted to the honest contract: these four
        // bytes are ARM64 (`1F 20 03 D5`), and this crate has no ARM64 decoder,
        // so reporting an instruction of size 4 named "nop" was a coincidence
        // dressed as a decode. The refusal must name the architecture.
        let err = AndroidArch
            .disassemble(Address::new(0x1000), &[0x1f, 0x20, 0x03, 0xd5])
            .expect_err("must not claim to have decoded ARM64");
        assert!(err.to_string().contains("aarch64"));
    }

    // ── Manifest / DEX class scanner ─────────────────────────────────────────

    #[test]
    fn test_parse_manifest_wrong_magic() {
        assert!(parse_manifest(b"\x00\x00\x00\x00").is_err());
    }

    #[test]
    fn test_list_dex_classes_invalid_magic() {
        assert!(list_dex_classes(b"not a dex file").is_empty());
    }

    #[test]
    fn test_list_dex_classes_empty_header() {
        let data = make_dex_header();
        let classes = list_dex_classes(&data);
        // Offsets point past data, so 0 or very few classes
        assert!(classes.len() <= 2);
    }

    // ── Signing scheme detection ──────────────────────────────────────────────

    #[test]
    fn test_detect_signing_no_schemes() {
        let data = b"PK\x03\x04nothing special here";
        let schemes = detect_signing_schemes(data);
        assert!(schemes.is_empty() || !schemes.contains(&ApkSigningScheme::V2));
    }

    #[test]
    fn test_detect_signing_v1() {
        let data = b"META-INF/CERT.SF and META-INF/CERT.RSA";
        let schemes = detect_signing_schemes(data);
        assert!(schemes.contains(&ApkSigningScheme::V1Jar));
    }

    #[test]
    fn test_signing_scheme_display() {
        assert_eq!(ApkSigningScheme::V2.to_string(), "v2");
        assert_eq!(ApkSigningScheme::V1Jar.to_string(), "v1-jar");
    }

    // ── VdexHeader ────────────────────────────────────────────────────────────

    fn make_vdex_header() -> Vec<u8> {
        let mut data = vec![0u8; 28];
        data[..4].copy_from_slice(b"vdex");
        data[4..8].copy_from_slice(b"019\0");
        data[8..12].copy_from_slice(&2_u32.to_le_bytes()); // num dex
        data[12..16].copy_from_slice(&1024_u32.to_le_bytes()); // dex section size
        data[16..20].copy_from_slice(&0_u32.to_le_bytes());
        data[20..24].copy_from_slice(&512_u32.to_le_bytes()); // verifier deps
        data[24..28].copy_from_slice(&256_u32.to_le_bytes()); // quicken info
        data
    }

    #[test]
    fn test_vdex_header_parse() {
        let data = make_vdex_header();
        let hdr = VdexHeader::parse(&data).unwrap();
        assert_eq!(hdr.version_str(), "019");
        assert_eq!(hdr.number_of_dex_files, 2);
        assert_eq!(hdr.dex_section_size, 1024);
    }

    #[test]
    fn test_vdex_header_invalid_magic() {
        let data = vec![0u8; 28];
        assert!(matches!(
            VdexHeader::parse(&data).unwrap_err(),
            AndroidLoaderError::InvalidMagic
        ));
    }

    #[test]
    fn test_vdex_header_truncated() {
        assert!(matches!(
            VdexHeader::parse(&[0u8; 4]).unwrap_err(),
            AndroidLoaderError::TruncatedHeader
        ));
    }

    #[test]
    fn test_vdex_dex_start_offset() {
        let data = make_vdex_header();
        let hdr = VdexHeader::parse(&data).unwrap();
        // 28 + 2 * 4 = 36
        assert_eq!(hdr.dex_start_offset(), 36);
    }

    #[test]
    fn test_vdex_header_display() {
        let hdr = VdexHeader::parse(&make_vdex_header()).unwrap();
        assert!(hdr.to_string().contains("VDEX"));
    }

    // ── ClassDefItem ──────────────────────────────────────────────────────────

    fn make_class_def_bytes() -> Vec<u8> {
        let mut data = vec![0u8; 32];
        data[0..4].copy_from_slice(&5_u32.to_le_bytes()); // class_idx
        data[4..8].copy_from_slice(&0x0001_u32.to_le_bytes()); // ACC_PUBLIC
        data[8..12].copy_from_slice(&0xFFFF_FFFF_u32.to_le_bytes()); // no superclass
        data
    }

    #[test]
    fn test_class_def_parse() {
        let data = make_class_def_bytes();
        let def = ClassDefItem::parse(&data, 0).unwrap();
        assert_eq!(def.class_idx, 5);
        assert_eq!(def.visibility(), DexVisibility::Public);
        assert_eq!(def.superclass_idx, ClassDefItem::NO_INDEX);
    }

    #[test]
    fn test_class_def_flags() {
        let mut data = make_class_def_bytes();
        data[4..8].copy_from_slice(&0x0201_u32.to_le_bytes()); // PUBLIC | INTERFACE
        let def = ClassDefItem::parse(&data, 0).unwrap();
        assert!(def.is_interface());
        assert!(!def.is_abstract());
    }

    #[test]
    fn test_class_def_too_short() {
        assert!(ClassDefItem::parse(&[0u8; 10], 0).is_none());
    }

    // ── CodeItem ──────────────────────────────────────────────────────────────

    #[test]
    fn test_code_item_parse() {
        let mut data = vec![0u8; 24]; // 16 byte header + 4-byte instruction (2 units)
        data[0..2].copy_from_slice(&3_u16.to_le_bytes()); // registers
        data[2..4].copy_from_slice(&1_u16.to_le_bytes()); // ins
        data[4..6].copy_from_slice(&0_u16.to_le_bytes()); // outs
        data[6..8].copy_from_slice(&0_u16.to_le_bytes()); // tries
        data[8..12].copy_from_slice(&0_u32.to_le_bytes()); // debug info off
        data[12..16].copy_from_slice(&4_u32.to_le_bytes()); // insns_size = 4 units → 8 bytes
        // extend for 4 units
        data.extend_from_slice(&[0x0E, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
        let ci = CodeItem::parse(&data, 0).unwrap();
        assert_eq!(ci.registers_size, 3);
        assert_eq!(ci.insns_size, 4);
        assert_eq!(ci.insns.len(), 4);
    }

    #[test]
    fn test_code_item_bytecode_bytes() {
        let mut data = vec![0u8; 18];
        data[0..2].copy_from_slice(&1_u16.to_le_bytes());
        data[12..16].copy_from_slice(&1_u32.to_le_bytes()); // 1 unit
        data[16..18].copy_from_slice(&[0x0E, 0x00]); // return-void
        let ci = CodeItem::parse(&data, 0).unwrap();
        assert_eq!(ci.bytecode_bytes(), vec![0x0E, 0x00]);
    }

    // ── ULEB128 ───────────────────────────────────────────────────────────────

    #[test]
    fn test_read_uleb128_single_byte() {
        let data = [0x05u8];
        let mut pos = 0;
        assert_eq!(read_uleb128(&data, &mut pos), 5);
        assert_eq!(pos, 1);
    }

    #[test]
    fn test_read_uleb128_multi_byte() {
        // 0x80, 0x01 encodes 128
        let data = [0x80u8, 0x01];
        let mut pos = 0;
        assert_eq!(read_uleb128(&data, &mut pos), 128);
        assert_eq!(pos, 2);
    }

    #[test]
    fn test_read_uleb128_empty() {
        let data: [u8; 0] = [];
        let mut pos = 0;
        assert_eq!(read_uleb128(&data, &mut pos), 0);
    }

    // ── DexVisibility ─────────────────────────────────────────────────────────

    #[test]
    fn test_dex_visibility_display() {
        assert_eq!(DexVisibility::Public.to_string(), "public");
        assert_eq!(DexVisibility::Private.to_string(), "private");
        assert_eq!(DexVisibility::PackagePrivate.to_string(), "");
    }

    // ── Loader ────────────────────────────────────────────────────────────────

    #[test]
    fn test_loader_name() {
        assert_eq!(AndroidLoader.name(), "android");
    }

    #[test]
    fn test_can_load_dex() {
        let input = LoaderInput::new("test.dex", minimal_dex());
        assert!(AndroidLoader.can_load(&input));
    }

    #[test]
    fn test_can_load_apk() {
        let mut data = b"PK\x03\x04".to_vec();
        data.extend_from_slice(&[0u8; 100]);
        data.extend_from_slice(b"classes.dex");
        assert!(AndroidLoader.can_load(&LoaderInput::new("app.apk", data)));
    }

    #[test]
    fn test_can_load_vdex() {
        let mut data = vec![0u8; 28];
        data[..4].copy_from_slice(b"vdex");
        data[4..8].copy_from_slice(b"019\0");
        assert!(AndroidLoader.can_load(&LoaderInput::new("boot.vdex", data)));
    }

    #[test]
    fn test_cannot_load_random() {
        assert!(!AndroidLoader.can_load(&LoaderInput::new("file.bin", b"CAFEBABE1234".to_vec())));
    }

    #[tokio::test]
    async fn test_load_dex() {
        let input = LoaderInput::new("test.dex", minimal_dex());
        let result = AndroidLoader.load(input).await.unwrap();
        assert_eq!(result.view.uri, "test.dex");
        assert_eq!(result.view.entry_points.len(), 1);
        assert_eq!(result.view.entry_points[0].as_u64(), 0x1000);
    }

    #[tokio::test]
    async fn test_load_with_hint_base_address() {
        use rustre_core::LoaderHint;
        
        let input = LoaderInput::new("test.dex", minimal_dex())
            .with_hint(LoaderHint::BaseAddress(Address::new(0x4000)));
        let result = AndroidLoader.load(input).await.unwrap();
        assert_eq!(result.view.entry_points[0].as_u64(), 0x4000);
    }

    #[tokio::test]
    async fn test_find_nested_dex_returns_empty() {
        let input = LoaderInput::new("test.dex", minimal_dex());
        let nested = AndroidLoader.find_nested(&input).await.unwrap();
        assert!(nested.is_empty());
    }

    #[tokio::test]
    async fn test_find_nested_apk() {
        let mut data = b"PK\x03\x04".to_vec();
        data.extend_from_slice(&[0u8; 100]);
        data.extend_from_slice(b"classes.dex");
        let input = LoaderInput::new("app.apk", data);
        let nested = AndroidLoader.find_nested(&input).await.unwrap();
        assert!(!nested.is_empty());
        assert_eq!(nested[0].name, "classes.dex");
    }

    #[test]
    fn test_minimal_dex_helper() {
        let v = minimal_dex();
        assert_eq!(v.len(), 112);
        assert_eq!(&v[0..8], b"dex\n035\0");
    }

    // ── AndroidManifest attack surface ────────────────────────────────────────

    #[test]
    fn test_manifest_attack_surface() {
        let mut m = AndroidManifest::default();
        m.exported_activities
            .push("com.example.MainActivity".to_string());
        m.exported_services
            .push("com.example.BackgroundService".to_string());
        let surface = m.attack_surface();
        assert!(surface.iter().any(|s| s.contains("activity")));
        assert!(surface.iter().any(|s| s.contains("service")));
    }

    #[test]
    fn test_manifest_unprotected_exports() {
        let mut m = AndroidManifest::default();
        assert!(!m.has_unprotected_exports());
        m.exported_receivers
            .push("com.example.BootReceiver".to_string());
        assert!(m.has_unprotected_exports());
    }

    // ── collect_all_bytecode ──────────────────────────────────────────────────

    #[test]
    fn test_collect_all_bytecode_empty_dex() {
        let data = minimal_dex();
        // No class_defs with valid code_off in the minimal header → empty
        let bytecode = collect_all_bytecode(&data);
        assert!(bytecode.is_empty());
    }

    #[test]
    fn test_collect_all_bytecode_invalid() {
        let bytecode = collect_all_bytecode(b"not dex");
        assert!(bytecode.is_empty());
    }

    // ── DexFile method names ──────────────────────────────────────────────────

    #[test]
    fn test_dex_file_all_class_names_empty() {
        let dex = DexFile::parse(&minimal_dex()).unwrap();
        // Minimal header has no class_defs entries that parse correctly
        let names = dex.all_class_names();
        assert!(names.is_empty());
    }
}


