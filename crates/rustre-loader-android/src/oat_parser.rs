//! Android OAT file parser.
//!
//! OAT (Optimised Android aRchive) is the compiled-methods container produced
//! by ART's dex2oat ahead-of-time compiler.  It is always embedded inside an
//! ELF shared object (`.oat` or `.odex`); the OAT header sits at the beginning
//! of the ELF `.rodata` section.
//!
//! This module handles:
//! - OAT header parsing (magic, version, key-value store, flags)
//! - DEX file location descriptors (`OatDexFile`)
//! - Per-method compiled-code offsets (`OatMethod`, `OatClass`)
//! - Quick/Optimised code header parsing
//! - OAT key-value store iteration

use std::collections::HashMap;
use std::fmt;

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};

// ── Magic / version constants ─────────────────────────────────────────────────

/// OAT magic bytes at the very start of the header: `"oat\n"`.
pub const OAT_MAGIC: &[u8; 4] = b"oat\n";

/// Minimum header size for all supported OAT versions (64 bytes).
pub const OAT_MIN_HEADER_SIZE: usize = 64;

// ── Instruction set ───────────────────────────────────────────────────────────

/// Instruction-set code stored in the OAT header.
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum InstructionSet {
    None = 0,
    Arm = 1,
    Arm64 = 2,
    Thumb2 = 3,
    Mips = 4,
    Mips64 = 5,
    X86 = 6,
    X86_64 = 7,
    Unknown(u32),
}

impl InstructionSet {
    /// Decode from a raw u32 value.
    #[must_use]
    pub const fn from_u32(v: u32) -> Self {
        match v {
            0 => Self::None,
            1 => Self::Arm,
            2 => Self::Arm64,
            3 => Self::Thumb2,
            4 => Self::Mips,
            5 => Self::Mips64,
            6 => Self::X86,
            7 => Self::X86_64,
            other => Self::Unknown(other),
        }
    }

    /// Returns `true` if this is a 64-bit ISA.
    #[must_use]
    pub const fn is_64bit(self) -> bool {
        matches!(self, Self::Arm64 | Self::X86_64 | Self::Mips64)
    }

    /// Human-readable name.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Arm => "arm",
            Self::Arm64 => "arm64",
            Self::Thumb2 => "thumb2",
            Self::Mips => "mips",
            Self::Mips64 => "mips64",
            Self::X86 => "x86",
            Self::X86_64 => "x86_64",
            Self::Unknown(_) => "unknown",
        }
    }
}

impl fmt::Display for InstructionSet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.name())
    }
}

// ── OAT header ────────────────────────────────────────────────────────────────

/// Parsed OAT file header.
///
/// The OAT header is version-dependent; fields after the core section are only
/// present in certain version ranges.  All sizes are in bytes.
///
/// Layout (version ≥ 079, which covers Android 7.0+):
/// ```text
/// Offset  Size  Field
/// 0x00    4     magic         ("oat\n")
/// 0x04    4     version       (ASCII, e.g. "138\0")
/// 0x08    4     adler32_checksum
/// 0x0C    4     instruction_set
/// 0x10    4     instruction_set_features_bitmap
/// 0x14    4     dex_file_count
/// 0x18    4     oat_dex_files_offset
/// 0x1C    4     executable_offset
/// 0x20    4     interpreter_to_interpreter_bridge_offset
/// 0x24    4     interpreter_to_compiled_code_bridge_offset
/// 0x28    4     jni_dlsym_lookup_trampoline_offset
/// 0x2C    4     quick_generic_jni_trampoline_offset
/// 0x30    4     quick_imt_conflict_trampoline_offset
/// 0x34    4     quick_resolution_trampoline_offset
/// 0x38    4     quick_to_interpreter_bridge_offset
/// 0x3C    4     nterp_trampoline_offset
/// 0x40    4     key_value_store_size
/// ...     kv    key_value_store (NUL-separated strings)
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OatHeader {
    /// OAT version string (e.g. `"138"`).
    pub version: String,
    /// Adler-32 checksum of the OAT file.
    pub adler32_checksum: u32,
    /// Target instruction set.
    pub instruction_set: InstructionSet,
    /// ISA feature bitmap.
    pub instruction_set_features_bitmap: u32,
    /// Number of embedded DEX files.
    pub dex_file_count: u32,
    /// File offset of the first `OatDexFile` descriptor.
    pub oat_dex_files_offset: u32,
    /// File offset of the compiled executable code region.
    pub executable_offset: u32,
    /// Offset to interpreter→interpreter bridge trampoline.
    pub interpreter_to_interpreter_bridge_offset: u32,
    /// Offset to interpreter→compiled-code bridge trampoline.
    pub interpreter_to_compiled_code_bridge_offset: u32,
    /// Offset to JNI `dlsym` lookup trampoline.
    pub jni_dlsym_lookup_trampoline_offset: u32,
    /// Offset to quick generic JNI trampoline.
    pub quick_generic_jni_trampoline_offset: u32,
    /// Offset to quick IMT conflict trampoline.
    pub quick_imt_conflict_trampoline_offset: u32,
    /// Offset to quick resolution trampoline.
    pub quick_resolution_trampoline_offset: u32,
    /// Offset to quick→interpreter bridge.
    pub quick_to_interpreter_bridge_offset: u32,
    /// Size of the key-value store in bytes.
    pub key_value_store_size: u32,
    /// Parsed key-value store entries.
    pub key_value_store: HashMap<String, String>,
    /// Byte offset at which this header was found within the parent file.
    pub file_offset: usize,
}

impl OatHeader {
    /// Parse an OAT header from `data` starting at `offset`.
    ///
    /// # Errors
    /// Returns an error if the data is too short, magic is wrong, or the
    /// key-value store overflows the buffer.
    pub fn parse(data: &[u8], offset: usize) -> Result<Self> {
        if data.len() < offset + OAT_MIN_HEADER_SIZE {
            bail!("OAT data too short at offset {offset:#x}");
        }

        let buf = &data[offset..];

        if &buf[..4] != OAT_MAGIC {
            bail!("invalid OAT magic at {offset:#x}");
        }

        let version = std::str::from_utf8(&buf[4..8])
            .unwrap_or("????")
            .trim_end_matches('\0')
            .to_string();

        let rd_u32 = |off: usize| -> Result<u32> {
            buf.get(off..off + 4)
                .and_then(|b| b.try_into().ok())
                .map(u32::from_le_bytes)
                .with_context(|| format!("reading u32 at oat+{off:#x}"))
        };

        let adler32_checksum = rd_u32(0x08)?;
        let instruction_set = InstructionSet::from_u32(rd_u32(0x0C)?);
        let instruction_set_features_bitmap = rd_u32(0x10)?;
        let dex_file_count = rd_u32(0x14)?;
        let oat_dex_files_offset = rd_u32(0x18)?;
        let executable_offset = rd_u32(0x1C)?;
        let interpreter_to_interpreter_bridge_offset = rd_u32(0x20)?;
        let interpreter_to_compiled_code_bridge_offset = rd_u32(0x24)?;
        let jni_dlsym_lookup_trampoline_offset = rd_u32(0x28)?;
        let quick_generic_jni_trampoline_offset = rd_u32(0x2C)?;
        let quick_imt_conflict_trampoline_offset = rd_u32(0x30)?;
        let quick_resolution_trampoline_offset = rd_u32(0x34)?;
        let quick_to_interpreter_bridge_offset = rd_u32(0x38)?;
        // 0x3C = nterp_trampoline_offset (present in newer versions, we skip it)
        let key_value_store_size = rd_u32(0x40)?;

        // Parse key-value store (pairs of NUL-terminated strings).
        let kv_start = offset + 0x44;
        let kv_end = (kv_start + key_value_store_size as usize).min(data.len());
        let kv_bytes = &data[kv_start..kv_end];
        let key_value_store = parse_kv_store(kv_bytes);

        Ok(Self {
            version,
            adler32_checksum,
            instruction_set,
            instruction_set_features_bitmap,
            dex_file_count,
            oat_dex_files_offset,
            executable_offset,
            interpreter_to_interpreter_bridge_offset,
            interpreter_to_compiled_code_bridge_offset,
            jni_dlsym_lookup_trampoline_offset,
            quick_generic_jni_trampoline_offset,
            quick_imt_conflict_trampoline_offset,
            quick_resolution_trampoline_offset,
            quick_to_interpreter_bridge_offset,
            key_value_store_size,
            key_value_store,
            file_offset: offset,
        })
    }

    /// Returns the absolute file offset of the first `OatDexFile` descriptor.
    #[must_use]
    pub const fn oat_dex_files_abs_offset(&self) -> usize {
        self.file_offset + self.oat_dex_files_offset as usize
    }

    /// Returns the absolute file offset of the executable code region.
    #[must_use]
    pub const fn executable_abs_offset(&self) -> usize {
        self.file_offset + self.executable_offset as usize
    }

    /// Look up a key in the key-value store.
    #[must_use]
    pub fn get_kv(&self, key: &str) -> Option<&str> {
        self.key_value_store.get(key).map(String::as_str)
    }

    /// Returns the compiler-filter string if present in the key-value store.
    #[must_use]
    pub fn compiler_filter(&self) -> Option<&str> {
        self.get_kv("compiler-filter")
    }

    /// Returns the `debuggable` flag as a bool if present.
    #[must_use]
    pub fn is_debuggable(&self) -> Option<bool> {
        self.get_kv("debuggable").map(|v| v == "true")
    }

    /// Returns the `native-debuggable` flag as a bool if present.
    #[must_use]
    pub fn is_native_debuggable(&self) -> Option<bool> {
        self.get_kv("native-debuggable").map(|v| v == "true")
    }
}

impl fmt::Display for OatHeader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "OAT v{} isa={} dex_files={} exec_off={:#010x} kv_entries={}",
            self.version,
            self.instruction_set,
            self.dex_file_count,
            self.executable_offset,
            self.key_value_store.len(),
        )
    }
}

/// Parse the OAT key-value store (consecutive NUL-terminated string pairs).
fn parse_kv_store(data: &[u8]) -> HashMap<String, String> {
    let mut map = HashMap::new();
    let mut pos = 0usize;

    while pos < data.len() {
        // Read key string.
        let key = read_cstr(data, &mut pos);
        if key.is_empty() {
            break;
        }
        // Read value string.
        let value = read_cstr(data, &mut pos);
        map.insert(key, value);
    }
    map
}

fn read_cstr(data: &[u8], pos: &mut usize) -> String {
    let start = *pos;
    while *pos < data.len() && data[*pos] != 0 {
        *pos += 1;
    }
    let s = String::from_utf8_lossy(&data[start..*pos]).into_owned();
    // Skip the NUL terminator.
    if *pos < data.len() {
        *pos += 1;
    }
    s
}

// ── OatDexFile ────────────────────────────────────────────────────────────────

/// Descriptor for one DEX file embedded inside an OAT archive.
///
/// There is one `OatDexFile` per DEX file in the OAT container.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OatDexFile {
    /// DEX file location (path string from the build system).
    pub dex_file_location: String,
    /// CRC32 checksum of the DEX file.
    pub dex_file_location_checksum: u32,
    /// File offset of the embedded DEX data.
    pub dex_file_offset: u32,
    /// Number of classes described in this DEX file.
    pub class_offsets_count: u32,
    /// Per-class `OatClass` offsets (relative to `oat_dex_files` region start).
    pub class_offsets: Vec<u32>,
    /// OAT version that produced this descriptor.
    pub oat_version: String,
    /// Byte offset at which this descriptor was read.
    pub file_offset: usize,
}

impl OatDexFile {
    /// Parse an `OatDexFile` descriptor from `data` at `offset`.
    ///
    /// # Errors
    /// Returns an error if the data is truncated.
    pub fn parse(data: &[u8], offset: usize, oat_version: &str) -> Result<(Self, usize)> {
        let buf = &data[offset..];

        if buf.len() < 8 {
            bail!("OatDexFile descriptor truncated at {offset:#x}");
        }

        // dex_file_location_size (u32) + location bytes
        let loc_size = u32::from_le_bytes(buf[0..4].try_into()?) as usize;
        if 4 + loc_size + 4 + 4 + 4 > buf.len() {
            bail!("OatDexFile location string truncated at {offset:#x}");
        }
        let dex_file_location =
            String::from_utf8_lossy(&buf[4..4 + loc_size]).into_owned();

        let mut pos = 4 + loc_size;

        let dex_file_location_checksum =
            u32::from_le_bytes(buf[pos..pos + 4].try_into()?);
        pos += 4;

        let dex_file_offset =
            u32::from_le_bytes(buf[pos..pos + 4].try_into()?);
        pos += 4;

        // class_offsets_count is stored as a u32 in the OAT data section for the
        // corresponding DEX.  We read the per-class offset table inline here.
        let class_offsets_count =
            u32::from_le_bytes(buf[pos..pos + 4].try_into()?) ;
        pos += 4;

        let n = class_offsets_count as usize;
        let offsets_bytes = n.checked_mul(4).with_context(|| format!("class_offsets_count overflow in OatDexFile at {offset:#x}"))?;
        if pos + offsets_bytes > buf.len() {
            bail!("class offsets table truncated in OatDexFile at {offset:#x}");
        }
        let class_offsets: Vec<u32> = buf[pos..pos + offsets_bytes]
            .chunks_exact(4)
            .map(|c| u32::from_le_bytes(c.try_into().unwrap()))
            .collect();
        pos += offsets_bytes;

        let consumed = pos;
        Ok((
            Self {
                dex_file_location,
                dex_file_location_checksum,
                dex_file_offset,
                class_offsets_count,
                class_offsets,
                oat_version: oat_version.to_string(),
                file_offset: offset,
            },
            consumed,
        ))
    }

    /// Returns the absolute file offset of the embedded DEX data.
    ///
    /// `oat_base` is the absolute file position of the OAT header.
    #[must_use]
    pub const fn dex_abs_offset(&self, oat_base: usize) -> usize {
        oat_base + self.dex_file_offset as usize
    }
}

impl fmt::Display for OatDexFile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "OatDexFile '{}' crc={:#010x} off={:#010x} classes={}",
            self.dex_file_location,
            self.dex_file_location_checksum,
            self.dex_file_offset,
            self.class_offsets_count,
        )
    }
}

// ── OatClass ──────────────────────────────────────────────────────────────────

/// Type / status of a compiled class in OAT.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum OatClassType {
    /// All methods compiled.
    AllCompiled = 0,
    /// Subset of methods compiled (bitmap indicates which).
    SomeCompiled = 1,
    /// No methods compiled (all interpreted).
    NoneCompiled = 2,
}

impl OatClassType {
    /// Decode from a raw i16 value (OAT stores the status as an int16).
    #[must_use]
    pub const fn from_i16(v: i16) -> Self {
        match v {
            0 => Self::AllCompiled,
            1 => Self::SomeCompiled,
            _ => Self::NoneCompiled,
        }
    }
}

/// Compiled-class descriptor.
///
/// An `OatClass` records which methods in a class have compiled code and where
/// that code lives relative to the OAT executable region.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OatClass {
    /// Class type / compilation status.
    pub class_type: OatClassType,
    /// i16 status field as stored in OAT.
    pub status: i16,
    /// Number of methods with compiled code (for `SomeCompiled`).
    pub compiled_methods_count: u32,
    /// Per-compiled-method bitmap (for `SomeCompiled`; bit i = method i compiled).
    pub bitmap: Vec<u32>,
    /// Per-method code offsets (relative to the executable region start).
    pub method_offsets: Vec<OatMethodOffsets>,
    /// Byte offset of this descriptor within the OAT file.
    pub file_offset: usize,
}

impl OatClass {
    /// Parse an `OatClass` from `data` at `offset`.
    ///
    /// `method_count` is the total number of virtual+direct methods in the class
    /// as reported by the DEX `class_def`.
    ///
    /// # Errors
    /// Returns an error on truncation.
    pub fn parse(data: &[u8], offset: usize, method_count: u32) -> Result<(Self, usize)> {
        let buf = &data[offset..];

        if buf.len() < 4 {
            bail!("OatClass too short at {offset:#x}");
        }

        // status (i16) + type (u16) packed as u32 in newer OAT versions.
        let status_raw = i16::from_le_bytes([buf[0], buf[1]]);
        let class_type = OatClassType::from_i16(status_raw);
        let mut pos = 4; // status(2) + padding(2) or type(2) = 4 bytes

        let (compiled_methods_count, bitmap) = match class_type {
            OatClassType::AllCompiled => (method_count, Vec::new()),
            OatClassType::SomeCompiled => {
                if pos + 4 > buf.len() {
                    bail!("OatClass SomeCompiled count truncated");
                }
                let cnt = u32::from_le_bytes(buf[pos..pos + 4].try_into()?);
                pos += 4;
                // Bitmap: ceil(method_count / 32) u32 words.
                let bm_words = method_count.div_ceil(32) as usize;
                let bm_bytes = bm_words.checked_mul(4).context("OatClass bitmap size overflow")?;
                if pos + bm_bytes > buf.len() {
                    bail!("OatClass bitmap truncated");
                }
                let bm: Vec<u32> = buf[pos..pos + bm_bytes]
                    .chunks_exact(4)
                    .map(|c| u32::from_le_bytes(c.try_into().unwrap()))
                    .collect();
                pos += bm_bytes;
                (cnt, bm)
            }
            OatClassType::NoneCompiled => (0, Vec::new()),
        };

        // Read method offsets. Cap pre-allocation: each entry is 8 bytes,
        // bounding the real count by the remaining buffer and preventing OOM
        // from a crafted compiled_methods_count.
        let mut method_offsets = Vec::with_capacity(
            (compiled_methods_count as usize).min(buf.len().saturating_sub(pos) / 8 + 1),
        );
        for _ in 0..compiled_methods_count {
            if pos + 8 > buf.len() {
                break;
            }
            let mo = OatMethodOffsets::parse(&buf[pos..])?;
            method_offsets.push(mo);
            pos += 8;
        }

        Ok((
            Self {
                class_type,
                status: status_raw,
                compiled_methods_count,
                bitmap,
                method_offsets,
                file_offset: offset,
            },
            pos,
        ))
    }

    /// Returns `true` if method `idx` is compiled (for `SomeCompiled` classes).
    #[must_use]
    pub fn is_method_compiled(&self, idx: u32) -> bool {
        match self.class_type {
            OatClassType::AllCompiled => true,
            OatClassType::NoneCompiled => false,
            OatClassType::SomeCompiled => {
                let word = (idx / 32) as usize;
                let bit = idx % 32;
                self.bitmap.get(word).is_some_and(|w| w & (1 << bit) != 0)
            }
        }
    }
}

// ── OatMethodOffsets ──────────────────────────────────────────────────────────

/// Compiled code location for one method.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct OatMethodOffsets {
    /// Offset to the native `quick` compiled code relative to the OAT executable base.
    pub code_offset: u32,
    /// Offset to the `gc_map` relative to the code offset (or 0 if absent).
    pub gc_map_offset: u32,
}

impl OatMethodOffsets {
    /// Parse from 8 bytes (two u32 LE fields).
    ///
    /// # Errors
    /// Returns an error if the slice is shorter than 8 bytes.
    pub fn parse(buf: &[u8]) -> Result<Self> {
        if buf.len() < 8 {
            bail!("OatMethodOffsets too short");
        }
        let code_offset = u32::from_le_bytes(buf[0..4].try_into()?);
        let gc_map_offset = u32::from_le_bytes(buf[4..8].try_into()?);
        Ok(Self { code_offset, gc_map_offset })
    }
}

impl fmt::Display for OatMethodOffsets {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "code={:#010x} gc_map={:#010x}",
            self.code_offset, self.gc_map_offset
        )
    }
}

// ── QuickMethodHeader ─────────────────────────────────────────────────────────

/// Header preceding each piece of quick-compiled code.
///
/// The `quick_method_header` appears immediately before the code region and
/// records metadata used by the ART runtime for stack-walking and GC.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct QuickMethodHeader {
    /// Frame information: is the method in a nterp frame?
    pub is_nterp_method_header: u32,
    /// Size of the native code in bytes.
    pub code_size: u32,
    /// Frame size in bytes (from register allocation).
    pub frame_size_in_bytes: u32,
    /// Core spill mask: bitmask of callee-saved core registers.
    pub core_spill_mask: u32,
    /// FP spill mask: bitmask of callee-saved FP registers.
    pub fp_spill_mask: u32,
    /// Size of the mapping table (code offsets → DEX offsets).
    pub mapping_table_size: u32,
    /// File offset where this header was found.
    pub file_offset: usize,
}

impl QuickMethodHeader {
    /// Byte size of the fixed-size portion.
    pub const SIZE: usize = 24;

    /// Parse a `QuickMethodHeader` from `data` at `offset`.
    ///
    /// # Errors
    /// Returns an error if the data is too short.
    pub fn parse(data: &[u8], offset: usize) -> Result<Self> {
        if data.len() < offset + Self::SIZE {
            bail!("QuickMethodHeader truncated at {offset:#x}");
        }
        let buf = &data[offset..];
        let rd = |o: usize| u32::from_le_bytes(buf[o..o + 4].try_into().unwrap());

        Ok(Self {
            is_nterp_method_header: rd(0),
            code_size: rd(4),
            frame_size_in_bytes: rd(8),
            core_spill_mask: rd(12),
            fp_spill_mask: rd(16),
            mapping_table_size: rd(20),
            file_offset: offset,
        })
    }

    /// Returns `true` if this is an interpreter method header (no compiled code).
    #[must_use]
    pub const fn is_interpreter(&self) -> bool {
        self.is_nterp_method_header != 0
    }

    /// Returns the absolute start of the compiled code: `file_offset + SIZE`.
    #[must_use]
    pub const fn code_abs_offset(&self) -> usize {
        self.file_offset + Self::SIZE
    }
}

impl fmt::Display for QuickMethodHeader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "QuickMethodHeader code_size={} frame_size={} core_spills={:#010x} fp_spills={:#010x}",
            self.code_size,
            self.frame_size_in_bytes,
            self.core_spill_mask,
            self.fp_spill_mask,
        )
    }
}

// ── OatFile ───────────────────────────────────────────────────────────────────

/// A fully-parsed OAT file.
#[derive(Debug, Serialize, Deserialize)]
pub struct OatFile {
    /// Parsed OAT header.
    pub header: OatHeader,
    /// DEX file location descriptors.
    pub dex_files: Vec<OatDexFile>,
    /// All compiled method descriptors, indexed by (`dex_index`, `class_index`, `method_index`).
    pub methods: Vec<OatMethod>,
    /// Any parse warnings.
    pub warnings: Vec<String>,
}

/// A single compiled OAT method descriptor.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OatMethod {
    /// DEX file index.
    pub dex_idx: usize,
    /// Class definition index within the DEX file.
    pub class_def_idx: usize,
    /// Method index within the class.
    pub method_idx: usize,
    /// Offsets to the compiled code and GC map.
    pub offsets: OatMethodOffsets,
    /// Absolute offset in the OAT file where quick code lives.
    pub code_abs_offset: usize,
}

impl OatFile {
    /// Parse an OAT file from `data`.
    ///
    /// Scans for the `oat\n` magic and parses the header + DEX descriptors.
    ///
    /// # Errors
    /// Returns an error if the magic is missing or the data is truncated.
    pub fn parse(data: &[u8]) -> Result<Self> {
        // Find OAT magic.
        let oat_base = data
            .windows(4)
            .position(|w| w == OAT_MAGIC)
            .context("OAT magic not found")?;

        let header = OatHeader::parse(data, oat_base)?;
        let mut warnings = Vec::new();

        // Parse OatDexFile descriptors. Cap pre-allocation: each descriptor is
        // at least 16 bytes, bounding the real count by data.len() / 16 and
        // preventing OOM from a crafted dex_file_count.
        let mut dex_files =
            Vec::with_capacity((header.dex_file_count as usize).min(data.len() / 16 + 1));
        let mut pos = header.oat_dex_files_abs_offset();

        for i in 0..header.dex_file_count as usize {
            match OatDexFile::parse(data, pos, &header.version) {
                Ok((od, consumed)) => {
                    pos += consumed;
                    dex_files.push(od);
                }
                Err(e) => {
                    warnings.push(format!("OatDexFile {i}: {e}"));
                    break;
                }
            }
        }

        // Collect methods from each DEX file's class offsets.
        let mut methods = Vec::new();
        let exec_base = header.executable_abs_offset();

        for (di, odf) in dex_files.iter().enumerate() {
            // Read the DEX class_defs to get method counts.
            let dex_off = odf.dex_abs_offset(oat_base);
            if dex_off + 112 > data.len() {
                warnings.push(format!("DEX {di} at {dex_off:#x} too short to read header"));
                continue;
            }

            let class_defs_size = u32::from_le_bytes(data[dex_off + 96..dex_off + 100].try_into()?) as usize;
            let class_defs_off = u32::from_le_bytes(data[dex_off + 100..dex_off + 104].try_into()?) as usize;

            for ci in 0..class_defs_size.min(odf.class_offsets.len()) {
                let class_off_in_oat = odf.class_offsets[ci] as usize;
                if class_off_in_oat == 0 {
                    continue;
                }
                let abs_class_off = oat_base + class_off_in_oat;

                // Read class_data_off from DEX class_def.
                let Some(cdef_off) = dex_off.checked_add(class_defs_off).and_then(|o| o.checked_add(ci.checked_mul(32)?)) else {
                    continue;
                };
                if cdef_off + 32 > data.len() {
                    continue;
                }
                let class_data_off = u32::from_le_bytes(data[cdef_off + 24..cdef_off + 28].try_into()?) as usize;
                if class_data_off == 0 {
                    continue;
                }

                // Count direct + virtual methods via ULEB128 parsing.
                let total_methods = count_class_methods(data, dex_off + class_data_off);

                match OatClass::parse(data, abs_class_off, total_methods as u32) {
                    Ok((oc, _)) => {
                        for (mi, mo) in oc.method_offsets.iter().enumerate() {
                            if mo.code_offset == 0 {
                                continue;
                            }
                            let code_abs = exec_base + mo.code_offset as usize;
                            methods.push(OatMethod {
                                dex_idx: di,
                                class_def_idx: ci,
                                method_idx: mi,
                                offsets: *mo,
                                code_abs_offset: code_abs,
                            });
                        }
                    }
                    Err(e) => {
                        warnings.push(format!("OatClass dex={di} class={ci}: {e}"));
                    }
                }
            }
        }

        Ok(Self { header, dex_files, methods, warnings })
    }

    /// Look up the `OatMethod` for a given DEX method offset.
    #[must_use]
    pub fn find_method_by_dex_idx(&self, dex_idx: usize, method_idx: usize) -> Option<&OatMethod> {
        self.methods.iter().find(|m| m.dex_idx == dex_idx && m.method_idx == method_idx)
    }

    /// Return the number of compiled methods.
    #[must_use]
    pub const fn compiled_method_count(&self) -> usize {
        self.methods.len()
    }
}

/// Count the total number of methods (direct + virtual) in a DEX `class_data_item`.
fn count_class_methods(data: &[u8], mut pos: usize) -> usize {
    fn read_uleb(data: &[u8], pos: &mut usize) -> u32 {
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

    let static_fields = read_uleb(data, &mut pos) as usize;
    let instance_fields = read_uleb(data, &mut pos) as usize;
    let direct_methods = read_uleb(data, &mut pos) as usize;
    let virtual_methods = read_uleb(data, &mut pos) as usize;

    // Skip field entries (2 ULEB128 each). Guard against huge counts from malformed input.
    let fields_to_skip = static_fields.saturating_add(instance_fields);
    // Each ULEB128 consumes at least 1 byte; bail if more fields than remaining bytes.
    let max_fields = data.len().saturating_sub(pos);
    let fields_to_skip = fields_to_skip.min(max_fields);
    for _ in 0..fields_to_skip {
        read_uleb(data, &mut pos);
        read_uleb(data, &mut pos);
    }

    direct_methods + virtual_methods
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn isa_names() {
        assert_eq!(InstructionSet::from_u32(2).name(), "arm64");
        assert_eq!(InstructionSet::from_u32(6).name(), "x86");
        assert!(InstructionSet::from_u32(2).is_64bit());
        assert!(!InstructionSet::from_u32(1).is_64bit());
    }

    #[test]
    fn kv_store_parse() {
        let input = b"compiler-filter\x00speed-profile\x00debuggable\x00true\x00";
        let map = parse_kv_store(input);
        assert_eq!(map.get("compiler-filter").map(String::as_str), Some("speed-profile"));
        assert_eq!(map.get("debuggable").map(String::as_str), Some("true"));
    }

    #[test]
    fn oat_header_too_short() {
        let data = vec![0u8; 10];
        assert!(OatHeader::parse(&data, 0).is_err());
    }

    #[test]
    fn oat_header_bad_magic() {
        let mut data = vec![0u8; 128];
        data[..4].copy_from_slice(b"JUNK");
        assert!(OatHeader::parse(&data, 0).is_err());
    }

    #[test]
    fn quick_method_header_parse() {
        let mut data = vec![0u8; 32];
        // code_size = 128
        data[4..8].copy_from_slice(&128u32.to_le_bytes());
        // frame_size = 64
        data[8..12].copy_from_slice(&64u32.to_le_bytes());
        let qmh = QuickMethodHeader::parse(&data, 0).unwrap();
        assert_eq!(qmh.code_size, 128);
        assert_eq!(qmh.frame_size_in_bytes, 64);
        assert!(!qmh.is_interpreter());
        assert_eq!(qmh.code_abs_offset(), QuickMethodHeader::SIZE);
    }

    #[test]
    fn oat_class_none_compiled() {
        // status = -1 → NoneCompiled
        let mut data = vec![0u8; 4];
        data[0..2].copy_from_slice(&(-1i16).to_le_bytes());
        let (oc, _) = OatClass::parse(&data, 0, 5).unwrap();
        assert_eq!(oc.class_type, OatClassType::NoneCompiled);
        assert!(!oc.is_method_compiled(0));
    }

    #[test]
    fn oat_class_all_compiled() {
        let mut data = vec![0u8; 4 + 8 * 3];
        data[0..2].copy_from_slice(&0i16.to_le_bytes()); // AllCompiled
        // 3 method offsets
        for i in 0..3usize {
            let off = 4 + i * 8;
            let code = ((i + 1) * 0x1000) as u32;
            data[off..off + 4].copy_from_slice(&code.to_le_bytes());
        }
        let (oc, _) = OatClass::parse(&data, 0, 3).unwrap();
        assert_eq!(oc.class_type, OatClassType::AllCompiled);
        assert!(oc.is_method_compiled(0));
        assert!(oc.is_method_compiled(2));
        assert_eq!(oc.method_offsets[0].code_offset, 0x1000);
    }

    #[test]
    fn oat_method_offsets_display() {
        let mo = OatMethodOffsets { code_offset: 0x1234, gc_map_offset: 0x5678 };
        let s = format!("{mo}");
        assert!(s.contains("0x00001234"));
    }
}
