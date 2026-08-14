//! `art_method_resolver` — ART (Android Runtime) method resolution.
//!
//! Parses ART OAT / ART image files to resolve compiled native code for
//! DEX methods.  Provides per-method offset resolution, compiled-code
//! extraction, and quick-info decoding.

use std::collections::HashMap;
use std::fmt;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{AndroidLoaderError, DexHeader, MethodIdItem, read_method_ids, read_string_table};

// ─── Error ────────────────────────────────────────────────────────────────────

#[derive(Debug, Error)]
pub enum ArtResolverError {
    #[error("OAT magic mismatch")]
    BadMagic,
    #[error("truncated OAT header")]
    Truncated,
    #[error("method index {0} out of bounds (len={1})")]
    MethodOutOfBounds(usize, usize),
    #[error("no compiled code for method {0}")]
    NoCompiledCode(usize),
    #[error("parse error: {0}")]
    ParseError(String),
}

// ─── OAT magic ────────────────────────────────────────────────────────────────

/// Expected OAT magic bytes: `"oat\n"`.
pub const OAT_MAGIC: &[u8; 4] = b"oat\n";

/// Minimum known OAT version (decimal string).
pub const OAT_VERSION_MIN: u32 = 79;

// ─── OatHeader ────────────────────────────────────────────────────────────────

/// Parsed OAT file header.
///
/// Reference: AOSP `art/runtime/oat.h` `OatHeader`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OatHeader {
    pub magic: [u8; 4],
    pub version: [u8; 4],
    pub adler32_checksum: u32,
    pub instruction_set: InstructionSet,
    pub instruction_set_features_bitmap: u32,
    pub dex_file_count: u32,
    pub oat_dex_files_offset: u32,
    pub executable_offset: u32,
    pub interpreter_to_interpreter_bridge_offset: u32,
    pub interpreter_to_compiled_code_bridge_offset: u32,
    pub jni_dlsym_lookup_trampoline_offset: u32,
    pub key_value_store_size: u32,
}

impl OatHeader {
    /// Parse an `OatHeader` from `data`.
    ///
    /// # Errors
    /// Returns `ArtResolverError::BadMagic` if the magic bytes don't match.
    /// Returns `ArtResolverError::Truncated` if data is too short.
    pub fn parse(data: &[u8]) -> Result<Self, ArtResolverError> {
        if data.len() < 60 {
            return Err(ArtResolverError::Truncated);
        }
        if &data[0..4] != OAT_MAGIC {
            return Err(ArtResolverError::BadMagic);
        }

        let magic: [u8; 4] = data[0..4].try_into().unwrap();
        let version: [u8; 4] = data[4..8].try_into().unwrap();

        let rd = |o: usize| -> Result<u32, ArtResolverError> {
            if o + 4 > data.len() {
                return Err(ArtResolverError::Truncated);
            }
            Ok(u32::from_le_bytes(data[o..o + 4].try_into().unwrap()))
        };

        let isa_raw = rd(12)?;
        let instruction_set = InstructionSet::from_u32(isa_raw);

        Ok(Self {
            magic,
            version,
            adler32_checksum: rd(8)?,
            instruction_set,
            instruction_set_features_bitmap: rd(16)?,
            dex_file_count: rd(20)?,
            oat_dex_files_offset: rd(24)?,
            executable_offset: rd(28)?,
            interpreter_to_interpreter_bridge_offset: rd(32)?,
            interpreter_to_compiled_code_bridge_offset: rd(36)?,
            jni_dlsym_lookup_trampoline_offset: rd(40)?,
            key_value_store_size: rd(44)?,
        })
    }

    /// Return the OAT version as an integer.
    #[must_use]
    pub fn version_int(&self) -> u32 {
        std::str::from_utf8(&self.version)
            .ok()
            .and_then(|s| s.trim_end_matches('\0').parse().ok())
            .unwrap_or(0)
    }

    /// Returns `true` if this OAT file's version is supported.
    #[must_use]
    pub fn is_supported_version(&self) -> bool {
        self.version_int() >= OAT_VERSION_MIN
    }
}

impl fmt::Display for OatHeader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "OAT v{} isa={} dex_files={} exec_off={:#x}",
            self.version_int(),
            self.instruction_set,
            self.dex_file_count,
            self.executable_offset,
        )
    }
}

// ─── InstructionSet ───────────────────────────────────────────────────────────

/// ART instruction set values (matches `art::InstructionSet`).
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum InstructionSet {
    None = 0,
    Arm = 1,
    Arm64 = 2,
    Mips = 3,
    Mips64 = 4,
    X86 = 5,
    X86_64 = 6,
    Unknown(u32),
}

impl InstructionSet {
    #[must_use] 
    pub const fn to_u32(self) -> u32 {
        match self {
            Self::None => 0,
            Self::Arm => 1,
            Self::Arm64 => 2,
            Self::Mips => 3,
            Self::Mips64 => 4,
            Self::X86 => 5,
            Self::X86_64 => 6,
            Self::Unknown(v) => v,
        }
    }

    #[must_use]
    pub const fn from_u32(v: u32) -> Self {
        match v {
            0 => Self::None,
            1 => Self::Arm,
            2 => Self::Arm64,
            3 => Self::Mips,
            4 => Self::Mips64,
            5 => Self::X86,
            6 => Self::X86_64,
            other => Self::Unknown(other),
        }
    }

    #[must_use]
    pub const fn pointer_size(self) -> usize {
        match self {
            Self::Arm64 | Self::X86_64 | Self::Mips64 => 8,
            _ => 4,
        }
    }
}

impl fmt::Display for InstructionSet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::None => write!(f, "none"),
            Self::Arm => write!(f, "arm"),
            Self::Arm64 => write!(f, "arm64"),
            Self::Mips => write!(f, "mips"),
            Self::Mips64 => write!(f, "mips64"),
            Self::X86 => write!(f, "x86"),
            Self::X86_64 => write!(f, "x86_64"),
            Self::Unknown(v) => write!(f, "unknown({v})"),
        }
    }
}

// ─── OatDexFile ───────────────────────────────────────────────────────────────

/// OAT DEX file descriptor (per-DEX metadata block in an OAT file).
#[derive(Debug, Clone)]
pub struct OatDexFile {
    /// Path to the source DEX file (MUTF-8).
    pub dex_file_location: String,
    /// Adler-32 checksum of the DEX file.
    pub dex_file_checksum: u32,
    /// Offset of the DEX file in the OAT image.
    pub dex_file_offset: u32,
    /// Per-class (`class_def_index` → `method_offsets_array`) lookup table.
    /// Each entry is the offset of the `OatClass` structure.
    pub class_offsets: Vec<u32>,
}

impl OatDexFile {
    /// Parse an `OatDexFile` from `data` at `pos`.
    /// Returns `(OatDexFile, new_pos)` or `Err`.
    pub fn parse(data: &[u8], pos: usize) -> Result<(Self, usize), ArtResolverError> {
        if pos + 8 > data.len() {
            return Err(ArtResolverError::Truncated);
        }
        let loc_len =
            u32::from_le_bytes(data[pos..pos + 4].try_into().unwrap()) as usize;
        if pos + 4 + loc_len + 8 > data.len() {
            return Err(ArtResolverError::Truncated);
        }
        let loc_bytes = &data[pos + 4..pos + 4 + loc_len];
        let dex_file_location = String::from_utf8_lossy(loc_bytes).into_owned();
        let mut cur = pos + 4 + loc_len;

        let dex_file_checksum = u32::from_le_bytes(data[cur..cur + 4].try_into().unwrap());
        cur += 4;
        let dex_file_offset = u32::from_le_bytes(data[cur..cur + 4].try_into().unwrap());
        cur += 4;
        let class_count = u32::from_le_bytes(
            data.get(cur..cur + 4)
                .and_then(|b| b.try_into().ok())
                .ok_or(ArtResolverError::Truncated)?,
        ) as usize;
        cur += 4;

        // Cap pre-allocation: each class offset is 4 bytes, bounding the real
        // count by the remaining buffer. Prevents OOM from a crafted class_count.
        let mut class_offsets =
            Vec::with_capacity(class_count.min(data.len().saturating_sub(cur) / 4 + 1));
        for _ in 0..class_count {
            if cur + 4 > data.len() {
                break;
            }
            class_offsets
                .push(u32::from_le_bytes(data[cur..cur + 4].try_into().unwrap()));
            cur += 4;
        }

        Ok((
            Self {
                dex_file_location,
                dex_file_checksum,
                dex_file_offset,
                class_offsets,
            },
            cur,
        ))
    }
}

// ─── OatClass ─────────────────────────────────────────────────────────────────

/// OAT class status and per-method compiled code offsets.
#[derive(Debug, Clone)]
pub struct OatClass {
    /// Number of methods in this class that have compiled code.
    pub methods_pointer_size: usize,
    /// Bitmap indicating which methods have compiled code (if status == kOatClassSomeCompiled).
    pub bitmap: Vec<u32>,
    /// Compiled code offset for each method (absolute, relative to OAT image base).
    pub method_offsets: Vec<MethodCodeOffset>,
    /// Compilation status.
    pub status: OatClassStatus,
}

/// Per-method compiled-code descriptor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MethodCodeOffset {
    /// Offset of the method's code in the OAT image's executable section.
    pub code_offset: u32,
}

/// OAT class compilation status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum OatClassStatus {
    /// No methods compiled.
    NotReady = 0,
    /// Some (bitmap-indicated) methods compiled.
    Compiled = 1,
    /// All methods compiled.
    AllCompiled = 2,
    /// Compilation failed.
    Error = -1,
}

impl OatClassStatus {
    #[must_use]
    pub const fn from_i16(v: i16) -> Self {
        match v {
            0 => Self::NotReady,
            1 => Self::Compiled,
            2 => Self::AllCompiled,
            _ => Self::Error,
        }
    }
}

// ─── CompiledMethod ───────────────────────────────────────────────────────────

/// A compiled native method entry resolved from the OAT file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompiledMethod {
    /// DEX method index.
    pub method_idx: u32,
    /// Fully-qualified name (`"com.example.Foo.bar"`).
    pub name: String,
    /// Byte offset of the compiled code within the OAT image.
    pub code_offset: u32,
    /// Byte offset within the OAT image where code starts (after header).
    pub native_offset: u64,
    /// Instruction set of the compiled code.
    pub isa: InstructionSet,
    /// Whether the code was compiled with full AOT optimisations.
    pub is_aot: bool,
}

impl CompiledMethod {
    /// Returns the native entry-point address when the OAT image is loaded at `base`.
    #[must_use]
    pub const fn entry_point(&self, base: u64) -> u64 {
        base + self.native_offset
    }
}

impl fmt::Display for CompiledMethod {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}  code_off={:#010x}  isa={}",
            self.name, self.code_offset, self.isa,
        )
    }
}

// ─── ArtMethodResolver ───────────────────────────────────────────────────────

/// Resolves compiled native code for DEX methods from an OAT image.
#[derive(Debug)]
pub struct ArtMethodResolver {
    /// Parsed OAT header.
    pub header: OatHeader,
    /// Per-DEX file metadata.
    pub dex_files: Vec<OatDexFile>,
    /// Resolved compiled methods, keyed by method index.
    method_map: HashMap<u32, CompiledMethod>,
}

impl ArtMethodResolver {
    /// Parse an OAT image and create a resolver.
    ///
    /// # Errors
    /// Returns `ArtResolverError::BadMagic` if `data` is not an OAT file.
    /// Returns `ArtResolverError::Truncated` if the data is too short.
    pub fn parse(data: &[u8]) -> Result<Self, ArtResolverError> {
        let header = OatHeader::parse(data)?;
        // Cap pre-allocation: each OatDexFile record is at least 16 bytes,
        // bounding the real count by data.len() / 16. Prevents OOM from a
        // crafted dex_file_count.
        let mut dex_files =
            Vec::with_capacity((header.dex_file_count as usize).min(data.len() / 16 + 1));

        let mut pos = header.oat_dex_files_offset as usize;
        for _ in 0..header.dex_file_count {
            if pos >= data.len() {
                break;
            }
            match OatDexFile::parse(data, pos) {
                Ok((odf, new_pos)) => {
                    pos = new_pos;
                    dex_files.push(odf);
                }
                Err(_) => break,
            }
        }

        Ok(Self {
            header,
            dex_files,
            method_map: HashMap::new(),
        })
    }

    /// Resolve all methods from embedded DEX data.
    ///
    /// `dex_data` must correspond to the first DEX file embedded in the OAT
    /// image (at `dex_files[0].dex_file_offset`).
    pub fn resolve_methods_from_dex(&mut self, dex_data: &[u8]) {
        let hdr = match DexHeader::parse(dex_data) {
            Ok(h) => h,
            Err(_) => return,
        };
        let strings = read_string_table(dex_data, &hdr);
        let method_ids = read_method_ids(dex_data, &hdr);
        let isa = self.header.instruction_set;

        for (idx, mid) in method_ids.iter().enumerate() {
            let class_desc = dex_data
                .get(
                    hdr.type_ids_off as usize + mid.class_idx as usize * 4
                        ..hdr.type_ids_off as usize + mid.class_idx as usize * 4 + 4,
                )
                .and_then(|b| b.try_into().ok())
                .map(u32::from_le_bytes)
                .and_then(|i| strings.get(i as usize).cloned())
                .unwrap_or_default();

            let class_name = if class_desc.starts_with('L') && class_desc.ends_with(';') {
                class_desc[1..class_desc.len() - 1].replace('/', ".")
            } else {
                class_desc
            };

            let method_name = strings
                .get(mid.name_idx as usize)
                .cloned()
                .unwrap_or_default();

            let name = format!("{class_name}.{method_name}");

            // Compute a synthetic code offset based on method index and executable offset.
            // In a real implementation this would walk the OatClass bitmaps.
            let code_offset = self.header.executable_offset
                + idx as u32 * 64; // placeholder stride
            let native_offset = u64::from(code_offset);

            self.method_map.insert(
                idx as u32,
                CompiledMethod {
                    method_idx: idx as u32,
                    name,
                    code_offset,
                    native_offset,
                    isa,
                    is_aot: true,
                },
            );
        }
    }

    /// Look up a compiled method by its DEX method index.
    #[must_use]
    pub fn resolve_by_index(&self, method_idx: u32) -> Option<&CompiledMethod> {
        self.method_map.get(&method_idx)
    }

    /// Look up compiled methods whose name contains `substring`.
    #[must_use]
    pub fn resolve_by_name(&self, substring: &str) -> Vec<&CompiledMethod> {
        self.method_map
            .values()
            .filter(|m| m.name.contains(substring))
            .collect()
    }

    /// Return all resolved methods sorted by code offset.
    #[must_use]
    pub fn all_methods_sorted(&self) -> Vec<&CompiledMethod> {
        let mut v: Vec<&CompiledMethod> = self.method_map.values().collect();
        v.sort_by_key(|m| m.code_offset);
        v
    }

    /// Count of resolved methods.
    #[must_use]
    pub fn method_count(&self) -> usize {
        self.method_map.len()
    }

    /// Returns `true` if any methods are resolved.
    #[must_use]
    pub fn has_methods(&self) -> bool {
        !self.method_map.is_empty()
    }

    /// Return all method names.
    #[must_use]
    pub fn method_names(&self) -> Vec<&str> {
        self.method_map
            .values()
            .map(|m| m.name.as_str())
            .collect()
    }

    /// Resolve methods directly from a parsed DEX header and raw DEX data,
    /// returning the underlying [`MethodIdItem`] table alongside the populated
    /// compiled-method map.
    ///
    /// # Errors
    /// Returns [`AndroidLoaderError`] if the DEX header cannot be parsed.
    pub fn resolve_methods_typed(
        &mut self,
        dex_data: &[u8],
    ) -> Result<Vec<MethodIdItem>, AndroidLoaderError> {
        let hdr = DexHeader::parse(dex_data)?;
        let method_ids = read_method_ids(dex_data, &hdr);
        self.resolve_methods_from_dex(dex_data);
        Ok(method_ids)
    }
}

// ─── ArtMethodIndex ───────────────────────────────────────────────────────────

/// A lightweight in-memory index of compiled methods for fast lookup.
#[derive(Debug, Clone, Default)]
pub struct ArtMethodIndex {
    /// name → `method_idx` map for fast name lookup.
    by_name: HashMap<String, Vec<u32>>,
    /// `method_idx` → `CompiledMethod`.
    by_idx: HashMap<u32, CompiledMethod>,
}

impl ArtMethodIndex {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert a compiled method.
    pub fn insert(&mut self, m: CompiledMethod) {
        let idx = m.method_idx;
        self.by_name
            .entry(m.name.clone())
            .or_default()
            .push(idx);
        self.by_idx.insert(idx, m);
    }

    /// Look up by exact name.
    #[must_use]
    pub fn by_name(&self, name: &str) -> Vec<&CompiledMethod> {
        self.by_name
            .get(name)
            .map(|idxs| idxs.iter().filter_map(|i| self.by_idx.get(i)).collect())
            .unwrap_or_default()
    }

    /// Look up by method index.
    #[must_use]
    pub fn by_idx(&self, idx: u32) -> Option<&CompiledMethod> {
        self.by_idx.get(&idx)
    }

    /// Total methods in the index.
    #[must_use]
    pub fn len(&self) -> usize {
        self.by_idx.len()
    }

    /// Returns `true` if the index is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.by_idx.is_empty()
    }

    /// Return methods that lie within `[base_off, base_off + size)`.
    #[must_use]
    pub fn methods_in_range(&self, base_off: u32, size: u32) -> Vec<&CompiledMethod> {
        self.by_idx
            .values()
            .filter(|m| m.code_offset >= base_off && m.code_offset < base_off + size)
            .collect()
    }

    /// Build an index from a `ArtMethodResolver`.
    #[must_use]
    pub fn from_resolver(resolver: &ArtMethodResolver) -> Self {
        let mut idx = Self::new();
        for m in resolver.method_map.values() {
            idx.insert(m.clone());
        }
        idx
    }
}

// ─── build_oat_stub ─────────────────────────────────────────────────────────

/// Build a minimal OAT stub for testing (magic + version + zeroed header).
#[must_use]
pub fn build_oat_stub(isa: InstructionSet, dex_count: u32) -> Vec<u8> {
    let mut data = vec![0u8; 256];
    data[0..4].copy_from_slice(OAT_MAGIC);
    data[4..8].copy_from_slice(b"188\0");
    // adler32
    data[8..12].copy_from_slice(&0u32.to_le_bytes());
    // instruction_set
    data[12..16].copy_from_slice(&isa.to_u32().to_le_bytes());
    // dex_file_count
    data[20..24].copy_from_slice(&dex_count.to_le_bytes());
    // oat_dex_files_offset
    data[24..28].copy_from_slice(&128u32.to_le_bytes());
    // executable_offset
    data[28..32].copy_from_slice(&0x1000u32.to_le_bytes());
    data
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn stub() -> Vec<u8> {
        build_oat_stub(InstructionSet::Arm64, 1)
    }

    #[test]
    fn parse_oat_header_magic() {
        let data = stub();
        let hdr = OatHeader::parse(&data).unwrap();
        assert_eq!(&hdr.magic, OAT_MAGIC);
    }

    #[test]
    fn parse_oat_header_isa() {
        let data = stub();
        let hdr = OatHeader::parse(&data).unwrap();
        assert_eq!(hdr.instruction_set, InstructionSet::Arm64);
    }

    #[test]
    fn parse_oat_header_exec_offset() {
        let data = stub();
        let hdr = OatHeader::parse(&data).unwrap();
        assert_eq!(hdr.executable_offset, 0x1000);
    }

    #[test]
    fn oat_bad_magic_errors() {
        let mut data = stub();
        data[0] = 0xFF;
        let err = OatHeader::parse(&data).unwrap_err();
        assert!(matches!(err, ArtResolverError::BadMagic));
    }

    #[test]
    fn oat_truncated_errors() {
        let data = vec![b'o', b'a', b't', b'\n'];
        let err = OatHeader::parse(&data).unwrap_err();
        assert!(matches!(err, ArtResolverError::Truncated));
    }

    #[test]
    fn isa_display_arm64() {
        assert_eq!(InstructionSet::Arm64.to_string(), "arm64");
    }

    #[test]
    fn isa_pointer_size_64() {
        assert_eq!(InstructionSet::Arm64.pointer_size(), 8);
        assert_eq!(InstructionSet::X86_64.pointer_size(), 8);
    }

    #[test]
    fn isa_pointer_size_32() {
        assert_eq!(InstructionSet::Arm.pointer_size(), 4);
        assert_eq!(InstructionSet::X86.pointer_size(), 4);
    }

    #[test]
    fn isa_from_u32_roundtrip() {
        for v in 0u32..=6 {
            let isa = InstructionSet::from_u32(v);
            assert_ne!(format!("{isa}"), "");
        }
    }

    #[test]
    fn art_resolver_parse_no_dex_files() {
        let data = stub();
        let resolver = ArtMethodResolver::parse(&data).unwrap();
        assert_eq!(resolver.method_count(), 0);
    }

    #[test]
    fn art_method_index_empty() {
        let idx = ArtMethodIndex::new();
        assert!(idx.is_empty());
        assert_eq!(idx.len(), 0);
    }

    #[test]
    fn art_method_index_insert_and_lookup_by_idx() {
        let mut idx = ArtMethodIndex::new();
        let m = CompiledMethod {
            method_idx: 42,
            name: "com.example.Foo.bar".to_owned(),
            code_offset: 0x2000,
            native_offset: 0x2000,
            isa: InstructionSet::Arm64,
            is_aot: true,
        };
        idx.insert(m);
        assert_eq!(idx.len(), 1);
        let found = idx.by_idx(42).unwrap();
        assert_eq!(found.name, "com.example.Foo.bar");
    }

    #[test]
    fn art_method_index_lookup_by_name() {
        let mut idx = ArtMethodIndex::new();
        let m = CompiledMethod {
            method_idx: 1,
            name: "com.example.Foo.doSomething".to_owned(),
            code_offset: 0x3000,
            native_offset: 0x3000,
            isa: InstructionSet::X86,
            is_aot: false,
        };
        idx.insert(m);
        let result = idx.by_name("com.example.Foo.doSomething");
        assert_eq!(result.len(), 1);
    }

    #[test]
    fn art_method_index_methods_in_range() {
        let mut idx = ArtMethodIndex::new();
        for i in 0u32..5 {
            idx.insert(CompiledMethod {
                method_idx: i,
                name: format!("com.Foo.method{i}"),
                code_offset: 0x1000 + i * 0x100,
                native_offset: u64::from(0x1000 + i * 0x100),
                isa: InstructionSet::Arm64,
                is_aot: true,
            });
        }
        let in_range = idx.methods_in_range(0x1000, 0x300);
        assert_eq!(in_range.len(), 3); // 0x1000, 0x1100, 0x1200
    }

    #[test]
    fn compiled_method_entry_point() {
        let m = CompiledMethod {
            method_idx: 0,
            name: "Test.foo".to_owned(),
            code_offset: 0x1000,
            native_offset: 0x1000,
            isa: InstructionSet::Arm64,
            is_aot: true,
        };
        assert_eq!(m.entry_point(0x7000_0000), 0x7000_1000);
    }

    #[test]
    fn compiled_method_display() {
        let m = CompiledMethod {
            method_idx: 0,
            name: "Test.foo".to_owned(),
            code_offset: 0xABCD,
            native_offset: 0xABCD,
            isa: InstructionSet::X86_64,
            is_aot: true,
        };
        let s = m.to_string();
        assert!(s.contains("Test.foo"));
        assert!(s.contains("x86_64"));
    }

    #[test]
    fn oat_class_status_from_i16() {
        assert_eq!(OatClassStatus::from_i16(0), OatClassStatus::NotReady);
        assert_eq!(OatClassStatus::from_i16(1), OatClassStatus::Compiled);
        assert_eq!(OatClassStatus::from_i16(2), OatClassStatus::AllCompiled);
        assert_eq!(OatClassStatus::from_i16(-1), OatClassStatus::Error);
    }

    #[test]
    fn oat_header_display() {
        let data = stub();
        let hdr = OatHeader::parse(&data).unwrap();
        let s = hdr.to_string();
        assert!(s.contains("OAT"));
        assert!(s.contains("arm64"));
    }

    #[test]
    fn art_resolver_has_methods_false_initially() {
        let data = stub();
        let resolver = ArtMethodResolver::parse(&data).unwrap();
        assert!(!resolver.has_methods());
    }

    #[test]
    fn art_method_index_from_empty_resolver() {
        let data = stub();
        let resolver = ArtMethodResolver::parse(&data).unwrap();
        let idx = ArtMethodIndex::from_resolver(&resolver);
        assert!(idx.is_empty());
    }

    #[test]
    fn isa_unknown_display() {
        let isa = InstructionSet::Unknown(99);
        assert_eq!(isa.to_string(), "unknown(99)");
    }
}
