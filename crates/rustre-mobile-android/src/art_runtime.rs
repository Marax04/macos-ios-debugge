//! Android Runtime (ART) analysis: OAT file parsing, `ArtMethod` layout per Android version,
//! AOT vs JIT distinction, quick compiled code location, method hotness, class loading trace.

use std::collections::HashMap;
use serde::{Deserialize, Serialize};
use thiserror::Error;

// ── Errors ────────────────────────────────────────────────────────────────────

#[derive(Debug, Error)]
pub enum ArtError {
    #[error("invalid OAT magic: expected 'oat\\n', got {0:?}")]
    BadMagic([u8; 4]),
    #[error("unsupported OAT version {0}")]
    UnsupportedVersion(u32),
    #[error("buffer too short at offset {0:#x}")]
    UnexpectedEof(usize),
    #[error("unsupported Android version: {0}")]
    UnknownAndroidVersion(String),
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

pub type ArtResult<T> = Result<T, ArtError>;

// ── Android API level map ─────────────────────────────────────────────────────

/// Android release → API level mapping relevant to ART changes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum AndroidRelease {
    /// Android 6.0 Marshmallow (API 23) – first full ART release
    M,
    /// Android 7.0/7.1 Nougat (API 24/25)
    N,
    /// Android 8.0/8.1 Oreo (API 26/27)
    O,
    /// Android 9 Pie (API 28)
    P,
    /// Android 10 (API 29)
    Q,
    /// Android 11 (API 30)
    R,
    /// Android 12/12L (API 31/32)
    S,
    /// Android 13 (API 33)
    Tiramisu,
    /// Android 14 (API 34)
    UpsideDownCake,
}

impl AndroidRelease {
    #[must_use] 
    pub const fn from_api(api: u32) -> Option<Self> {
        match api {
            23 => Some(Self::M),
            24 | 25 => Some(Self::N),
            26 | 27 => Some(Self::O),
            28 => Some(Self::P),
            29 => Some(Self::Q),
            30 => Some(Self::R),
            31 | 32 => Some(Self::S),
            33 => Some(Self::Tiramisu),
            34 => Some(Self::UpsideDownCake),
            _ => None,
        }
    }

    #[must_use] 
    pub const fn api_level(self) -> u32 {
        match self {
            Self::M => 23,
            Self::N => 24,
            Self::O => 26,
            Self::P => 28,
            Self::Q => 29,
            Self::R => 30,
            Self::S => 31,
            Self::Tiramisu => 33,
            Self::UpsideDownCake => 34,
        }
    }

    #[must_use] 
    pub const fn name(self) -> &'static str {
        match self {
            Self::M => "Android 6.0 Marshmallow",
            Self::N => "Android 7.0 Nougat",
            Self::O => "Android 8.0 Oreo",
            Self::P => "Android 9 Pie",
            Self::Q => "Android 10",
            Self::R => "Android 11",
            Self::S => "Android 12",
            Self::Tiramisu => "Android 13",
            Self::UpsideDownCake => "Android 14",
        }
    }
}

// ── OAT header ───────────────────────────────────────────────────────────────

/// OAT magic bytes: b"oat\n"
pub const OAT_MAGIC: [u8; 4] = *b"oat\n";

/// OAT version strings (stored as 4 ASCII bytes, e.g. b"064\0").
/// Each corresponds to a range of Android releases.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct OatVersion(pub u32);

impl OatVersion {
    /// Human-readable description of OAT version.
    #[must_use] 
    pub const fn describe(self) -> &'static str {
        match self.0 {
            45 => "OAT v045 (Android 5.0)",
            51 => "OAT v051 (Android 5.1)",
            64 => "OAT v064 (Android 6.0/M)",
            79 => "OAT v079 (Android 7.0/N)",
            88 => "OAT v088 (Android 8.0/O)",
            124 => "OAT v124 (Android 9/P)",
            170 => "OAT v170 (Android 10/Q)",
            183 => "OAT v183 (Android 11/R)",
            195 => "OAT v195 (Android 12/S)",
            199 => "OAT v199 (Android 13/T)",
            225 => "OAT v225 (Android 14/U)",
            _ => "OAT (unknown version)",
        }
    }

    #[must_use] 
    pub const fn android_release(self) -> Option<AndroidRelease> {
        match self.0 {
            64 => Some(AndroidRelease::M),
            79 => Some(AndroidRelease::N),
            88 => Some(AndroidRelease::O),
            124 => Some(AndroidRelease::P),
            170 => Some(AndroidRelease::Q),
            183 => Some(AndroidRelease::R),
            195 => Some(AndroidRelease::S),
            199 => Some(AndroidRelease::Tiramisu),
            225 => Some(AndroidRelease::UpsideDownCake),
            _ => None,
        }
    }
}

/// Instruction set encoded in the OAT header.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum InstructionSet {
    None,
    Arm,
    Arm64,
    Thumb2,
    X86,
    X86_64,
    Mips,
    Mips64,
    Unknown(u32),
}

impl From<u32> for InstructionSet {
    fn from(v: u32) -> Self {
        match v {
            0 => Self::None,
            1 => Self::Arm,
            2 => Self::Arm64,
            3 => Self::Thumb2,
            4 => Self::X86,
            5 => Self::X86_64,
            6 => Self::Mips,
            7 => Self::Mips64,
            n => Self::Unknown(n),
        }
    }
}

/// Parsed OAT file header (common fields across versions).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OatHeader {
    pub version: OatVersion,
    pub android_release: Option<AndroidRelease>,
    pub instruction_set: InstructionSet,
    pub instruction_set_features_bitmap: u32,
    pub dex_file_count: u32,
    pub oat_dex_files_offset: u32,
    pub executable_offset: u32,
    pub interpreter_to_interpreter_bridge_offset: u32,
    pub interpreter_to_compiled_code_bridge_offset: u32,
    pub jni_dlsym_lookup_trampoline_offset: u32,
    pub quick_generic_jni_trampoline_offset: u32,
    pub quick_imt_conflict_trampoline_offset: u32,
    pub quick_resolution_trampoline_offset: u32,
    pub quick_to_interpreter_bridge_offset: u32,
    pub key_value_store_size: u32,
    pub key_value_store: HashMap<String, String>,
}

// ── ArtMethod layout ─────────────────────────────────────────────────────────

/// `ArtMethod` field offsets vary per Android release.
/// This struct captures the relevant offsets for a given release.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArtMethodLayout {
    pub android_release: AndroidRelease,
    /// Size of `ArtMethod` in bytes (pointer-size dependent).
    pub struct_size_32: usize,
    pub struct_size_64: usize,
    // Field offsets (32-bit)
    pub declaring_class_offset_32: usize,
    pub access_flags_offset_32: usize,
    pub dex_code_item_offset_32: usize,
    pub dex_method_index_offset_32: usize,
    pub method_index_offset_32: usize,
    pub hotness_count_offset_32: usize,
    pub ptr_sized_fields_offset_32: usize,
    // Field offsets (64-bit)
    pub declaring_class_offset_64: usize,
    pub access_flags_offset_64: usize,
    pub dex_code_item_offset_64: usize,
    pub dex_method_index_offset_64: usize,
    pub method_index_offset_64: usize,
    pub hotness_count_offset_64: usize,
    pub ptr_sized_fields_offset_64: usize,
}

impl ArtMethodLayout {
    /// Return the known layout for each Android release.
    #[must_use] 
    pub const fn for_release(release: AndroidRelease) -> Self {
        // Layout information sourced from AOSP art/runtime/art_method.h
        match release {
            AndroidRelease::M => Self {
                android_release: release,
                struct_size_32: 36,
                struct_size_64: 52,
                declaring_class_offset_32: 0,
                access_flags_offset_32: 4,
                dex_code_item_offset_32: 8,
                dex_method_index_offset_32: 12,
                method_index_offset_32: 16,
                hotness_count_offset_32: 18,
                ptr_sized_fields_offset_32: 20,
                declaring_class_offset_64: 0,
                access_flags_offset_64: 8,
                dex_code_item_offset_64: 12,
                dex_method_index_offset_64: 16,
                method_index_offset_64: 20,
                hotness_count_offset_64: 22,
                ptr_sized_fields_offset_64: 24,
            },
            AndroidRelease::N => Self {
                android_release: release,
                struct_size_32: 40,
                struct_size_64: 56,
                declaring_class_offset_32: 0,
                access_flags_offset_32: 4,
                dex_code_item_offset_32: 8,
                dex_method_index_offset_32: 12,
                method_index_offset_32: 16,
                hotness_count_offset_32: 18,
                ptr_sized_fields_offset_32: 20,
                declaring_class_offset_64: 0,
                access_flags_offset_64: 8,
                dex_code_item_offset_64: 12,
                dex_method_index_offset_64: 16,
                method_index_offset_64: 20,
                hotness_count_offset_64: 22,
                ptr_sized_fields_offset_64: 24,
            },
            AndroidRelease::O => Self {
                android_release: release,
                struct_size_32: 40,
                struct_size_64: 56,
                declaring_class_offset_32: 0,
                access_flags_offset_32: 4,
                dex_code_item_offset_32: 8,
                dex_method_index_offset_32: 12,
                method_index_offset_32: 16,
                hotness_count_offset_32: 18,
                ptr_sized_fields_offset_32: 20,
                declaring_class_offset_64: 0,
                access_flags_offset_64: 8,
                dex_code_item_offset_64: 12,
                dex_method_index_offset_64: 16,
                method_index_offset_64: 20,
                hotness_count_offset_64: 22,
                ptr_sized_fields_offset_64: 24,
            },
            AndroidRelease::P | AndroidRelease::Q | AndroidRelease::R => Self {
                android_release: release,
                struct_size_32: 32,
                struct_size_64: 48,
                declaring_class_offset_32: 0,
                access_flags_offset_32: 4,
                dex_code_item_offset_32: 8,
                dex_method_index_offset_32: 12,
                method_index_offset_32: 16,
                hotness_count_offset_32: 18,
                ptr_sized_fields_offset_32: 20,
                declaring_class_offset_64: 0,
                access_flags_offset_64: 8,
                dex_code_item_offset_64: 12,
                dex_method_index_offset_64: 16,
                method_index_offset_64: 20,
                hotness_count_offset_64: 22,
                ptr_sized_fields_offset_64: 24,
            },
            AndroidRelease::S | AndroidRelease::Tiramisu | AndroidRelease::UpsideDownCake => Self {
                android_release: release,
                struct_size_32: 32,
                struct_size_64: 48,
                declaring_class_offset_32: 0,
                access_flags_offset_32: 4,
                dex_code_item_offset_32: 8,
                dex_method_index_offset_32: 12,
                method_index_offset_32: 16,
                hotness_count_offset_32: 18,
                ptr_sized_fields_offset_32: 20,
                declaring_class_offset_64: 0,
                access_flags_offset_64: 8,
                dex_code_item_offset_64: 12,
                dex_method_index_offset_64: 16,
                method_index_offset_64: 20,
                hotness_count_offset_64: 22,
                ptr_sized_fields_offset_64: 24,
            },
        }
    }
}

// ── Access flags ─────────────────────────────────────────────────────────────

bitflags::bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
    pub struct ArtMethodFlags: u32 {
        const PUBLIC              = 0x0001;
        const PRIVATE             = 0x0002;
        const PROTECTED           = 0x0004;
        const STATIC              = 0x0008;
        const FINAL               = 0x0010;
        const SYNCHRONIZED        = 0x0020;
        const BRIDGE              = 0x0040;
        const VARARGS             = 0x0080;
        const NATIVE              = 0x0100;
        const ABSTRACT            = 0x0400;
        const STRICT_FP           = 0x0800;
        const SYNTHETIC           = 0x1000;
        // ART-specific flags (> 0x10000)
        const CONSTRUCTOR         = 0x0001_0000;
        const DECLARED_SYNCHRONIZED = 0x0002_0000;
        const IS_DEFAULT          = 0x0004_0000;
        const IS_OBSOLETE         = 0x0008_0000;
        const IS_INTRINSIC        = 0x0010_0000;
        const IS_COPIED           = 0x0020_0000;
        const IS_MEMORY_SHARED_METHOD = 0x0040_0000;
        const IS_FAST_NATIVE      = 0x0080_0000;
        const IS_CRITICAL_NATIVE  = 0x0100_0000;
        const IS_SENTINEL         = 0x0200_0000;
    }
}

// ── Compilation kind ─────────────────────────────────────────────────────────

/// How a method's code was compiled.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CompilationKind {
    /// Method is interpreter-only (no compiled code).
    Interpreted,
    /// AOT compiled by dex2oat.
    Aot,
    /// JIT compiled at runtime.
    Jit,
    /// Native / JNI (not bytecode).
    Native,
    /// Quick resolution trampoline (indirect call).
    Trampoline,
}

impl CompilationKind {
    #[must_use] 
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Interpreted => "interpreted",
            Self::Aot => "AOT",
            Self::Jit => "JIT",
            Self::Native => "native/JNI",
            Self::Trampoline => "trampoline",
        }
    }
}

// ── ArtMethod descriptor ──────────────────────────────────────────────────────

/// High-level view of an `ArtMethod` extracted from an OAT/VDEX file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArtMethod {
    pub class_descriptor: String,
    pub method_name: String,
    pub shorty: String,
    pub dex_method_index: u32,
    pub method_index: u16,
    pub access_flags: ArtMethodFlags,
    pub hotness_count: u16,
    pub compilation_kind: CompilationKind,
    /// Offset of quick compiled code relative to OAT .text section start.
    pub quick_code_offset: Option<u32>,
    /// Offset of JNI stub (for native methods).
    pub jni_stub_offset: Option<u32>,
    /// dex code item offset inside the DEX file.
    pub dex_code_item_offset: u32,
}

impl ArtMethod {
    #[must_use] 
    pub const fn is_aot_compiled(&self) -> bool {
        matches!(self.compilation_kind, CompilationKind::Aot)
    }

    #[must_use] 
    pub const fn is_native(&self) -> bool {
        self.access_flags.contains(ArtMethodFlags::NATIVE)
    }

    #[must_use] 
    pub const fn is_abstract(&self) -> bool {
        self.access_flags.contains(ArtMethodFlags::ABSTRACT)
    }

    #[must_use] 
    pub const fn is_hot(&self) -> bool {
        self.hotness_count > 0
    }

    #[must_use] 
    pub fn full_signature(&self) -> String {
        format!("{}->{}{}", self.class_descriptor, self.method_name, self.shorty)
    }
}

// ── OAT DEX file entry ────────────────────────────────────────────────────────

/// Metadata about a DEX file embedded in an OAT.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OatDexFile {
    pub dex_file_location: String,
    pub dex_file_checksum: u32,
    pub dex_file_offset: u32,
    pub class_offsets_offset: u32,
    pub lookup_table_offset: u32,
    pub class_count: u32,
    pub methods: Vec<ArtMethod>,
}

// ── Parsed OAT file ───────────────────────────────────────────────────────────

/// Fully parsed OAT file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OatFile {
    pub header: OatHeader,
    pub dex_files: Vec<OatDexFile>,
    /// Total AOT-compiled methods across all DEX files.
    pub aot_method_count: usize,
    /// Total interpreted methods.
    pub interpreted_method_count: usize,
    /// Total native methods.
    pub native_method_count: usize,
}

impl OatFile {
    pub fn all_methods(&self) -> impl Iterator<Item = &ArtMethod> {
        self.dex_files.iter().flat_map(|d| d.methods.iter())
    }

    #[must_use] 
    pub fn hot_methods(&self) -> Vec<&ArtMethod> {
        self.all_methods().filter(|m| m.is_hot()).collect()
    }

    #[must_use] 
    pub fn aot_methods(&self) -> Vec<&ArtMethod> {
        self.all_methods().filter(|m| m.is_aot_compiled()).collect()
    }
}

// ── OAT parser ───────────────────────────────────────────────────────────────

pub struct OatParser<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> OatParser<'a> {
    #[must_use] 
    pub const fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    /// Read a single unsigned byte at the current position and advance.
    ///
    /// # Errors
    /// Returns `ArtError::UnexpectedEof` when the cursor is at or beyond the
    /// end of the underlying buffer.
    pub fn read_u8(&mut self) -> ArtResult<u8> {
        if self.pos >= self.data.len() {
            return Err(ArtError::UnexpectedEof(self.pos));
        }
        let v = self.data[self.pos];
        self.pos += 1;
        Ok(v)
    }

    /// Read a little-endian `u16` at the current position and advance.
    ///
    /// # Errors
    /// Returns `ArtError::UnexpectedEof` when fewer than 2 bytes remain.
    pub fn read_u16_le(&mut self) -> ArtResult<u16> {
        if self.pos + 2 > self.data.len() {
            return Err(ArtError::UnexpectedEof(self.pos));
        }
        let v = u16::from_le_bytes([self.data[self.pos], self.data[self.pos + 1]]);
        self.pos += 2;
        Ok(v)
    }

    fn read_u32_le(&mut self) -> ArtResult<u32> {
        if self.pos + 4 > self.data.len() {
            return Err(ArtError::UnexpectedEof(self.pos));
        }
        let v = u32::from_le_bytes(self.data[self.pos..self.pos + 4].try_into().unwrap());
        self.pos += 4;
        Ok(v)
    }

    fn read_bytes(&mut self, n: usize) -> ArtResult<&'a [u8]> {
        if self.pos + n > self.data.len() {
            return Err(ArtError::UnexpectedEof(self.pos));
        }
        let s = &self.data[self.pos..self.pos + n];
        self.pos += n;
        Ok(s)
    }

    fn read_c_string(&mut self) -> ArtResult<String> {
        let start = self.pos;
        while self.pos < self.data.len() && self.data[self.pos] != 0 {
            self.pos += 1;
        }
        let s = std::str::from_utf8(&self.data[start..self.pos])
            .unwrap_or("<invalid utf8>")
            .to_owned();
        if self.pos < self.data.len() {
            self.pos += 1; // skip NUL
        }
        Ok(s)
    }

    /// Read a `u32`-length-prefixed UTF-8 string at the current position.
    ///
    /// # Errors
    /// Returns `ArtError::UnexpectedEof` when the prefix or payload would
    /// read past end-of-buffer.
    pub fn read_length_prefixed_string(&mut self) -> ArtResult<String> {
        let len = self.read_u32_le()? as usize;
        let bytes = self.read_bytes(len)?;
        Ok(std::str::from_utf8(bytes).unwrap_or("<invalid utf8>").to_owned())
    }

    /// Parse the OAT file header and section table from the underlying buffer.
    ///
    /// # Errors
    /// Returns `ArtError::BadMagic` for a malformed magic header, or other
    /// `ArtError` variants when section data is malformed or truncated.
    ///
    /// # Panics
    /// Panics if a slice that has already been bounds-checked fails to convert
    /// to a fixed-size array; this is a logic invariant of the parser.
    pub fn parse(&mut self) -> ArtResult<OatFile> {
        // Magic
        let magic: [u8; 4] = self.read_bytes(4)?.try_into().unwrap();
        if magic != OAT_MAGIC {
            return Err(ArtError::BadMagic(magic));
        }

        // Version (4 ASCII digits + NUL = 4 bytes stored)
        let ver_bytes = self.read_bytes(4)?;
        let ver_str = std::str::from_utf8(ver_bytes).unwrap_or("0");
        let ver_num: u32 = ver_str.trim_end_matches('\0').parse().unwrap_or(0);
        let version = OatVersion(ver_num);
        let android_release = version.android_release();

        let instruction_set = InstructionSet::from(self.read_u32_le()?);
        let instruction_set_features_bitmap = self.read_u32_le()?;
        let dex_file_count = self.read_u32_le()?;
        let oat_dex_files_offset = self.read_u32_le()?;
        let executable_offset = self.read_u32_le()?;
        let interpreter_to_interpreter_bridge_offset = self.read_u32_le()?;
        let interpreter_to_compiled_code_bridge_offset = self.read_u32_le()?;
        let jni_dlsym_lookup_trampoline_offset = self.read_u32_le()?;
        let quick_generic_jni_trampoline_offset = self.read_u32_le()?;
        let quick_imt_conflict_trampoline_offset = self.read_u32_le()?;
        let quick_resolution_trampoline_offset = self.read_u32_le()?;
        let quick_to_interpreter_bridge_offset = self.read_u32_le()?;
        let key_value_store_size = self.read_u32_le()?;

        // Key-value store
        let mut key_value_store = HashMap::new();
        let kv_end = self.pos.saturating_add(key_value_store_size as usize);
        while self.pos < kv_end.min(self.data.len()) {
            let key = self.read_c_string()?;
            if key.is_empty() {
                break;
            }
            let value = self.read_c_string()?;
            key_value_store.insert(key, value);
        }
        self.pos = kv_end.min(self.data.len());

        let header = OatHeader {
            version,
            android_release,
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
        };

        // Parse OAT DEX files (simplified — real parsing is version-dependent)
        let mut dex_files = Vec::with_capacity(dex_file_count as usize);
        for _ in 0..dex_file_count {
            let location_len_raw = self.read_u32_le()?;
            // Cap to a reasonable maximum (64 KiB) to prevent OOM on malformed input.
            let location_len = (location_len_raw as usize).min(65536);
            let location_bytes = self.read_bytes(location_len)?;
            let dex_file_location = std::str::from_utf8(location_bytes)
                .unwrap_or("<invalid>")
                .to_owned();
            let dex_file_checksum = self.read_u32_le()?;
            let dex_file_offset = self.read_u32_le()?;
            let class_offsets_offset = self.read_u32_le()?;
            let lookup_table_offset = self.read_u32_le()?;

            // Parse class methods from DEX data embedded in OAT
            let (class_count, methods) = if dex_file_offset as usize + 8 < self.data.len() {
                self.parse_dex_methods(dex_file_offset as usize, executable_offset)
            } else {
                (0, vec![])
            };

            dex_files.push(OatDexFile {
                dex_file_location,
                dex_file_checksum,
                dex_file_offset,
                class_offsets_offset,
                lookup_table_offset,
                class_count,
                methods,
            });
        }

        let aot_method_count = dex_files
            .iter()
            .flat_map(|d| &d.methods)
            .filter(|m| m.is_aot_compiled())
            .count();
        let interpreted_method_count = dex_files
            .iter()
            .flat_map(|d| &d.methods)
            .filter(|m| matches!(m.compilation_kind, CompilationKind::Interpreted))
            .count();
        let native_method_count = dex_files
            .iter()
            .flat_map(|d| &d.methods)
            .filter(|m| m.is_native())
            .count();

        Ok(OatFile {
            header,
            dex_files,
            aot_method_count,
            interpreted_method_count,
            native_method_count,
        })
    }

    /// Attempt to parse DEX method table from embedded DEX data.
    fn parse_dex_methods(&self, dex_offset: usize, exec_offset: u32) -> (u32, Vec<ArtMethod>) {
        // DEX header magic check
        let dex_magic = b"dex\n";
        if dex_offset + 4 > self.data.len() {
            return (0, vec![]);
        }
        if &self.data[dex_offset..dex_offset + 4] != dex_magic {
            return (0, vec![]);
        }

        let read_u32 = |off: usize| -> u32 {
            if off + 4 > self.data.len() {
                return 0;
            }
            u32::from_le_bytes(self.data[off..off + 4].try_into().unwrap())
        };

        let string_ids_size = read_u32(dex_offset + 0x38);
        let string_ids_off = read_u32(dex_offset + 0x3C) as usize;
        let type_ids_size = read_u32(dex_offset + 0x40);
        let _type_ids_off = read_u32(dex_offset + 0x44) as usize;
        let class_defs_size = read_u32(dex_offset + 0x60);
        let class_defs_off = read_u32(dex_offset + 0x64) as usize;
        let method_ids_off = read_u32(dex_offset + 0x58) as usize;
        let _method_ids_size = read_u32(dex_offset + 0x54);

        // Build string table — cap at 100 000 entries to prevent OOM on malformed DEX.
        const MAX_STRING_IDS: usize = 100_000;
        let string_ids_count = (string_ids_size as usize).min(MAX_STRING_IDS);
        let mut strings: Vec<String> = Vec::with_capacity(string_ids_count);
        for i in 0..string_ids_count {
            let str_off = read_u32(
                dex_offset
                    .saturating_add(string_ids_off)
                    .saturating_add(i.saturating_mul(4)),
            ) as usize + dex_offset;
            // DEX string data: ULEB128 length then UTF-16 data
            if str_off >= self.data.len() {
                strings.push(String::new());
                continue;
            }
            let (char_count, adv) = read_uleb128(&self.data[str_off..]);
            let bytes_start = str_off + adv;
            let bytes_end = (bytes_start + char_count as usize).min(self.data.len());
            let s = std::str::from_utf8(&self.data[bytes_start..bytes_end])
                .unwrap_or("")
                .to_owned();
            strings.push(s);
        }

        // Build type descriptor table — cap at 100 000 entries to prevent OOM.
        const MAX_TYPE_IDS: usize = 100_000;
        let type_ids_count = (type_ids_size as usize).min(MAX_TYPE_IDS);
        let _type_desc: Vec<String> = (0..type_ids_count)
            .map(|i| {
                let idx = read_u32(
                    dex_offset
                        .saturating_add(_type_ids_off)
                        .saturating_add(i.saturating_mul(4)),
                ) as usize;
                strings.get(idx).cloned().unwrap_or_default()
            })
            .collect();

        // Parse class definitions — cap at 50 000 to prevent unbounded loops on malformed DEX.
        const MAX_CLASS_DEFS: usize = 50_000;
        let class_defs_count = (class_defs_size as usize).min(MAX_CLASS_DEFS);
        let mut methods = Vec::new();
        for i in 0..class_defs_count {
            let cd_off = dex_offset
                .saturating_add(class_defs_off)
                .saturating_add(i.saturating_mul(32));
            let class_idx = read_u32(cd_off) as usize;
            let _access_flags = read_u32(cd_off + 4);
            let class_data_off = read_u32(cd_off + 24) as usize + dex_offset;

            let class_descriptor = _type_desc.get(class_idx).cloned().unwrap_or_default();

            if class_data_off <= dex_offset || class_data_off >= self.data.len() {
                continue;
            }

            // Parse class data item: encoded_fields + encoded_methods
            let mut cursor = class_data_off;
            let (static_fields_size, adv) = read_uleb128(&self.data[cursor..]);
            cursor += adv;
            let (instance_fields_size, adv) = read_uleb128(&self.data[cursor..]);
            cursor += adv;
            let (direct_methods_size, adv) = read_uleb128(&self.data[cursor..]);
            cursor += adv;
            let (virtual_methods_size, adv) = read_uleb128(&self.data[cursor..]);
            cursor += adv;

            // Skip fields — cap at 10 000 to prevent unbounded loop on malformed class data.
            let total_fields = (static_fields_size.saturating_add(instance_fields_size) as usize).min(10_000);
            for _ in 0..total_fields {
                if cursor >= self.data.len() { break; }
                let (_, a1) = read_uleb128(&self.data[cursor..]);
                cursor += a1;
                if cursor >= self.data.len() { break; }
                let (_, a2) = read_uleb128(&self.data[cursor..]);
                cursor += a2;
            }

            // Parse methods — cap at 10 000 to prevent unbounded loop on malformed data.
            let total_methods = (direct_methods_size.saturating_add(virtual_methods_size) as usize).min(10_000);
            let mut method_idx_acc: u32 = 0;
            for _ in 0..total_methods {
                if cursor >= self.data.len() {
                    break;
                }
                let (method_idx_diff, a1) = read_uleb128(&self.data[cursor..]);
                cursor += a1;
                method_idx_acc = method_idx_acc.saturating_add(method_idx_diff);
                if cursor >= self.data.len() { break; }
                let (access_flags_val, a2) = read_uleb128(&self.data[cursor..]);
                cursor += a2;
                if cursor >= self.data.len() { break; }
                let (code_off, a3) = read_uleb128(&self.data[cursor..]);
                cursor += a3;

                // Look up method name from method_ids — use saturating arithmetic to avoid overflow.
                let method_id_off = dex_offset
                    .saturating_add(method_ids_off)
                    .saturating_add((method_idx_acc as usize).saturating_mul(8));
                let name_idx = read_u32(method_id_off.saturating_add(4)) as usize;
                let method_name = strings.get(name_idx).cloned().unwrap_or_default();

                let flags = ArtMethodFlags::from_bits_truncate(access_flags_val);
                let compilation_kind = if flags.contains(ArtMethodFlags::NATIVE) {
                    CompilationKind::Native
                } else if flags.contains(ArtMethodFlags::ABSTRACT) {
                    CompilationKind::Interpreted
                } else if code_off == 0 {
                    CompilationKind::Interpreted
                } else {
                    // Heuristic: if code offset is within executable section, it's AOT
                    CompilationKind::Aot
                };

                let quick_code_offset = if matches!(compilation_kind, CompilationKind::Aot) {
                    Some(exec_offset.saturating_add(code_off))
                } else {
                    None
                };

                methods.push(ArtMethod {
                    class_descriptor: class_descriptor.clone(),
                    method_name,
                    shorty: String::new(),
                    dex_method_index: method_idx_acc,
                    method_index: 0,
                    access_flags: flags,
                    hotness_count: 0,
                    compilation_kind,
                    quick_code_offset,
                    jni_stub_offset: None,
                    dex_code_item_offset: code_off,
                });
            }
        }

        (class_defs_size, methods)
    }
}

// ── ULEB128 helper ────────────────────────────────────────────────────────────

fn read_uleb128(data: &[u8]) -> (u32, usize) {
    let mut result: u32 = 0;
    let mut shift = 0;
    let mut i = 0;
    loop {
        if i >= data.len() || i >= 5 {
            break;
        }
        let b = data[i];
        result |= u32::from(b & 0x7f) << shift;
        i += 1;
        if b & 0x80 == 0 {
            break;
        }
        shift += 7;
    }
    (result, i)
}

// ── Class loading trace ───────────────────────────────────────────────────────

/// Records a class loading event (as would appear in logcat with -verbose:class).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClassLoadEvent {
    pub class_descriptor: String,
    pub initiating_loader: String,
    pub defining_loader: String,
    pub dex_location: String,
    pub loaded_at_ns: u64,
}

/// Trace of all class loading events from an ART session.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ClassLoadTrace {
    pub events: Vec<ClassLoadEvent>,
}

impl ClassLoadTrace {
    #[must_use] 
    pub fn new() -> Self {
        Self::default()
    }

    /// Parse a simplified ART class-load trace log (one entry per line).
    /// Format: `<timestamp_ns>\t<class>\t<init_loader>\t<def_loader>\t<dex>`
    #[must_use] 
    pub fn from_log(log: &str) -> Self {
        let mut events = Vec::new();
        for line in log.lines() {
            let parts: Vec<&str> = line.split('\t').collect();
            if parts.len() < 5 {
                continue;
            }
            let loaded_at_ns = parts[0].parse().unwrap_or(0);
            events.push(ClassLoadEvent {
                class_descriptor: parts[1].to_owned(),
                initiating_loader: parts[2].to_owned(),
                defining_loader: parts[3].to_owned(),
                dex_location: parts[4].to_owned(),
                loaded_at_ns,
            });
        }
        Self { events }
    }

    #[must_use] 
    pub fn classes_by_loader(&self) -> HashMap<&str, Vec<&ClassLoadEvent>> {
        let mut map: HashMap<&str, Vec<&ClassLoadEvent>> = HashMap::new();
        for e in &self.events {
            map.entry(&e.initiating_loader).or_default().push(e);
        }
        map
    }

    #[must_use] 
    pub fn dynamic_classes(&self) -> Vec<&ClassLoadEvent> {
        self.events
            .iter()
            .filter(|e| {
                e.initiating_loader.contains("DexClassLoader")
                    || e.initiating_loader.contains("PathClassLoader")
                    || e.initiating_loader.contains("InMemoryDexClassLoader")
            })
            .collect()
    }

    #[must_use] 
    pub fn suspicious_loads(&self) -> Vec<&ClassLoadEvent> {
        self.events
            .iter()
            .filter(|e| {
                e.dex_location.contains("/tmp/")
                    || e.dex_location.contains("/data/local/")
                    || e.dex_location.contains("InMemory")
            })
            .collect()
    }
}

// ── AOT vs JIT report ─────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArtAnalysisReport {
    pub oat_version: u32,
    pub android_release: Option<AndroidRelease>,
    pub instruction_set: InstructionSet,
    pub total_methods: usize,
    pub aot_methods: usize,
    pub jit_methods: usize,
    pub interpreted_methods: usize,
    pub native_methods: usize,
    pub hot_methods: usize,
    pub aot_percentage: f32,
    pub compiler_filter: Option<String>,
    pub dex_locations: Vec<String>,
}

impl ArtAnalysisReport {
    #[must_use] 
    pub fn from_oat(oat: &OatFile) -> Self {
        let total = oat.aot_method_count + oat.interpreted_method_count + oat.native_method_count;
        let aot_pct = if total > 0 {
            oat.aot_method_count as f32 / total as f32 * 100.0
        } else {
            0.0
        };
        let compiler_filter = oat
            .header
            .key_value_store
            .get("compiler-filter")
            .cloned();
        let dex_locations = oat
            .dex_files
            .iter()
            .map(|d| d.dex_file_location.clone())
            .collect();
        let hot_methods = oat.hot_methods().len();
        let jit_count = oat
            .all_methods()
            .filter(|m| matches!(m.compilation_kind, CompilationKind::Jit))
            .count();

        Self {
            oat_version: oat.header.version.0,
            android_release: oat.header.android_release,
            instruction_set: oat.header.instruction_set,
            total_methods: total,
            aot_methods: oat.aot_method_count,
            jit_methods: jit_count,
            interpreted_methods: oat.interpreted_method_count,
            native_methods: oat.native_method_count,
            hot_methods,
            aot_percentage: aot_pct,
            compiler_filter,
            dex_locations,
        }
    }
}

// ── Public API ────────────────────────────────────────────────────────────────

/// Parse an OAT file from raw bytes and return a full analysis report.
///
/// # Errors
/// Returns an `ArtError` when the OAT header, section table or payload is
/// malformed.
pub fn parse_oat(data: &[u8]) -> ArtResult<(OatFile, ArtAnalysisReport)> {
    let mut parser = OatParser::new(data);
    let oat = parser.parse()?;
    let report = ArtAnalysisReport::from_oat(&oat);
    Ok((oat, report))
}

/// Return the `ArtMethod` layout for the given Android API level.
pub fn layout_for_api(api: u32) -> Option<ArtMethodLayout> {
    AndroidRelease::from_api(api).map(ArtMethodLayout::for_release)
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_oat_version_describe() {
        assert!(OatVersion(64).describe().contains("6.0"));
        assert!(OatVersion(88).describe().contains("8.0"));
    }

    #[test]
    fn test_android_release_from_api() {
        assert_eq!(AndroidRelease::from_api(23), Some(AndroidRelease::M));
        assert_eq!(AndroidRelease::from_api(29), Some(AndroidRelease::Q));
        assert_eq!(AndroidRelease::from_api(34), Some(AndroidRelease::UpsideDownCake));
        assert_eq!(AndroidRelease::from_api(1), None);
    }

    #[test]
    fn test_art_method_flags() {
        let flags = ArtMethodFlags::PUBLIC | ArtMethodFlags::NATIVE;
        assert!(flags.contains(ArtMethodFlags::NATIVE));
        assert!(!flags.contains(ArtMethodFlags::ABSTRACT));
    }

    #[test]
    fn test_class_load_trace_parse() {
        let log = "1000\tLcom/example/Foo;\tPathClassLoader\tPathClassLoader\t/data/app/base.apk\n\
                   2000\tLcom/example/Bar;\tDexClassLoader\tDexClassLoader\t/data/local/tmp/evil.dex\n";
        let trace = ClassLoadTrace::from_log(log);
        assert_eq!(trace.events.len(), 2);
        let suspicious = trace.suspicious_loads();
        assert_eq!(suspicious.len(), 1);
        assert!(suspicious[0].dex_location.contains("evil"));
    }

    #[test]
    fn test_parse_invalid_magic() {
        let data = b"XXXX0064";
        let result = parse_oat(data);
        assert!(matches!(result, Err(ArtError::BadMagic(_))));
    }

    #[test]
    fn test_uleb128() {
        assert_eq!(read_uleb128(&[0x00]), (0, 1));
        assert_eq!(read_uleb128(&[0x01]), (1, 1));
        assert_eq!(read_uleb128(&[0x80, 0x01]), (128, 2));
    }
}
