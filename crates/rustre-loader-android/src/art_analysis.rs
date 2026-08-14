//! ART (Android Runtime) analysis.
//!
//! Parses OAT and VDEX files produced by the Android Runtime compiler,
//! exposing compiled methods, compiler filters, hotness bitmaps, and
//! dex-to-native code mappings.

use std::collections::HashMap;

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ArtError {
    InvalidMagic {
        expected: &'static [u8],
        got: Vec<u8>,
    },
    UnsupportedVersion {
        version: u32,
    },
    TruncatedData {
        offset: usize,
        needed: usize,
    },
    InvalidChecksum {
        expected: u32,
        actual: u32,
    },
    InvalidDexOffset(u32),
    InvalidNativeCodeOffset(u32),
    BadAlignment {
        offset: usize,
        align: usize,
    },
    UnknownCompilerFilter(u32),
    TooManyMethods(usize),
    InvalidQuickCode(u32),
    StringDecodeError,
}

impl std::fmt::Display for ArtError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidMagic { expected, got } => {
                write!(f, "invalid magic: expected {expected:?}, got {got:?}")
            }
            Self::UnsupportedVersion { version } => {
                write!(f, "unsupported OAT/VDEX version {version}")
            }
            Self::TruncatedData { offset, needed } => write!(
                f,
                "truncated data at offset {offset:#x}, need {needed} bytes"
            ),
            Self::InvalidChecksum { expected, actual } => write!(
                f,
                "checksum mismatch: expected {expected:#010x}, actual {actual:#010x}"
            ),
            Self::InvalidDexOffset(o) => write!(f, "invalid dex offset {o:#x}"),
            Self::InvalidNativeCodeOffset(o) => write!(f, "invalid native code offset {o:#x}"),
            Self::BadAlignment { offset, align } => {
                write!(f, "offset {offset:#x} not aligned to {align}")
            }
            Self::UnknownCompilerFilter(n) => write!(f, "unknown compiler filter {n}"),
            Self::TooManyMethods(n) => write!(f, "too many methods: {n}"),
            Self::InvalidQuickCode(o) => write!(f, "invalid quick code offset {o:#x}"),
            Self::StringDecodeError => write!(f, "UTF-8 decode error in string table"),
        }
    }
}

impl std::error::Error for ArtError {}

// ---------------------------------------------------------------------------
// CompilerFilter
// ---------------------------------------------------------------------------

/// The compiler filter level used when generating an OAT file.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum CompilerFilter {
    /// No compilation, only verify dex bytecode.
    Verify,
    /// Generate quick code for frequently used methods.
    SpeedProfile,
    /// Generate quick code for all methods.
    Speed,
    /// Optimise for app startup time.
    QuickenVerify,
    /// Everything except method inlining (ART 8+).
    Everything,
    /// Maximally optimised (debug builds).
    EverythingWithDebugging,
    /// Unknown value.
    Unknown(u32),
}

impl CompilerFilter {
    #[must_use] 
    pub const fn from_u32(v: u32) -> Self {
        match v {
            0 => Self::Verify,
            1 => Self::SpeedProfile,
            2 => Self::Speed,
            3 => Self::QuickenVerify,
            4 => Self::Everything,
            5 => Self::EverythingWithDebugging,
            n => Self::Unknown(n),
        }
    }

    #[must_use] 
    pub const fn as_u32(self) -> u32 {
        match self {
            Self::Verify => 0,
            Self::SpeedProfile => 1,
            Self::Speed => 2,
            Self::QuickenVerify => 3,
            Self::Everything => 4,
            Self::EverythingWithDebugging => 5,
            Self::Unknown(n) => n,
        }
    }

    /// `true` if any native code was generated.
    #[must_use] 
    pub const fn has_compiled_code(self) -> bool {
        matches!(
            self,
            Self::SpeedProfile | Self::Speed | Self::Everything | Self::EverythingWithDebugging
        )
    }

    #[must_use] 
    pub const fn name(self) -> &'static str {
        match self {
            Self::Verify => "verify",
            Self::SpeedProfile => "speed-profile",
            Self::Speed => "speed",
            Self::QuickenVerify => "quicken-verify",
            Self::Everything => "everything",
            Self::EverythingWithDebugging => "everything-with-debugging",
            Self::Unknown(_) => "unknown",
        }
    }
}

// ---------------------------------------------------------------------------
// HotnessBitmap
// ---------------------------------------------------------------------------

/// Hotness bitmap from a `.prof` / `.dm` or inline profile.
/// Each bit indicates whether the corresponding method was executed at runtime.
#[derive(Debug, Clone, Default)]
pub struct HotnessBitmap {
    bits: Vec<u8>,
    total_methods: u32,
}

impl HotnessBitmap {
    /// Create a bitmap from raw bytes covering `total_methods` methods.
    #[must_use] 
    pub const fn from_bytes(bits: Vec<u8>, total_methods: u32) -> Self {
        Self {
            bits,
            total_methods,
        }
    }

    /// `true` if method at `index` is marked hot.
    #[must_use] 
    pub fn is_hot(&self, index: u32) -> bool {
        if index >= self.total_methods {
            return false;
        }
        let byte_idx = (index / 8) as usize;
        let bit_idx = index % 8;
        if byte_idx >= self.bits.len() {
            return false;
        }
        (self.bits[byte_idx] >> bit_idx) & 1 == 1
    }

    /// Mark method `index` as hot.
    pub fn set_hot(&mut self, index: u32) {
        if index >= self.total_methods {
            return;
        }
        let byte_idx = (index / 8) as usize;
        if byte_idx >= self.bits.len() {
            self.bits.resize(byte_idx + 1, 0);
        }
        self.bits[byte_idx] |= 1 << (index % 8);
    }

    /// Number of hot methods.
    #[must_use] 
    pub fn hot_count(&self) -> u32 {
        self.bits.iter().map(|b| b.count_ones()).sum()
    }

    /// Total methods tracked.
    #[must_use] 
    pub const fn total_methods(&self) -> u32 {
        self.total_methods
    }

    /// Hot method indices.
    #[must_use] 
    pub fn hot_indices(&self) -> Vec<u32> {
        (0..self.total_methods)
            .filter(|&i| self.is_hot(i))
            .collect()
    }
}

// ---------------------------------------------------------------------------
// OatMethod
// ---------------------------------------------------------------------------

/// A compiled native method in an OAT file.
#[derive(Debug, Clone)]
pub struct OatMethod {
    /// Method index in the dex file.
    pub dex_method_index: u32,
    /// Offset of the compiled code from the OAT data start.
    pub code_offset: u32,
    /// Size of the compiled native code in bytes.
    pub code_size: u32,
    /// Whether the method was compiled (vs. interpreted).
    pub has_native_code: bool,
    /// Frame info: number of vregs.
    pub frame_size_in_bytes: u32,
    /// GC map size (0 if none).
    pub gc_map_size: u32,
    /// Method name (empty if not resolved from dex).
    pub name: String,
    /// Whether this method is marked hot in the profile.
    pub is_hot: bool,
}

impl OatMethod {
    #[must_use] 
    pub const fn new(dex_idx: u32, code_offset: u32, code_size: u32) -> Self {
        Self {
            dex_method_index: dex_idx,
            code_offset,
            code_size,
            has_native_code: code_offset != 0,
            frame_size_in_bytes: 0,
            gc_map_size: 0,
            name: String::new(),
            is_hot: false,
        }
    }

    /// `true` if this method has compiled quick code.
    #[must_use] 
    pub const fn is_compiled(&self) -> bool {
        self.has_native_code
    }

    /// End offset of the compiled code.
    #[must_use] 
    pub const fn code_end_offset(&self) -> u32 {
        self.code_offset.saturating_add(self.code_size)
    }
}

// ---------------------------------------------------------------------------
// OatFile
// ---------------------------------------------------------------------------

/// Magic bytes for OAT files.
pub const OAT_MAGIC: &[u8] = b"oat\n";

/// Parsed OAT file header + method table.
#[derive(Debug, Clone)]
pub struct OatFile {
    pub version: u32,
    pub adler32_checksum: u32,
    pub instruction_set: u32,
    pub instruction_set_features_bitmap: u32,
    pub dex_file_count: u32,
    pub oat_dex_files_offset: u32,
    pub executable_offset: u32,
    pub interpreter_to_interpreter_bridge_offset: u32,
    pub interpreter_to_compiled_code_bridge_offset: u32,
    pub jni_dlsym_lookup_offset: u32,
    pub compiler_filter: CompilerFilter,
    pub methods: Vec<OatMethod>,
    pub dex_file_checksums: Vec<u32>,
}

impl OatFile {
    /// Minimal parsing of an OAT header from raw bytes.
    pub fn parse(data: &[u8]) -> Result<Self, ArtError> {
        if data.len() < 4 {
            return Err(ArtError::TruncatedData {
                offset: 0,
                needed: 4,
            });
        }
        if &data[..4] != OAT_MAGIC {
            return Err(ArtError::InvalidMagic {
                expected: OAT_MAGIC,
                got: data[..4.min(data.len())].to_vec(),
            });
        }
        if data.len() < 8 {
            return Err(ArtError::TruncatedData {
                offset: 4,
                needed: 4,
            });
        }
        // Version is encoded as 3 ASCII digits + null at offset 4
        let ver_bytes = &data[4..8];
        let version_str = std::str::from_utf8(&ver_bytes[..3]).unwrap_or("000");
        let version: u32 = version_str.parse().unwrap_or(0);

        if data.len() < 0x58 {
            return Err(ArtError::TruncatedData {
                offset: 8,
                needed: 0x58,
            });
        }

        let r4 = |o: usize| u32::from_le_bytes(data[o..o + 4].try_into().unwrap());

        let adler32 = r4(8);
        let isa = r4(12);
        let isa_features = r4(16);
        let dex_file_count = r4(20);
        let oat_dex_offset = r4(24);
        let exec_offset = r4(28);
        let itib = r4(32);
        let itcc = r4(36);
        let jni = r4(40);
        let filter_val = r4(44);

        Ok(Self {
            version,
            adler32_checksum: adler32,
            instruction_set: isa,
            instruction_set_features_bitmap: isa_features,
            dex_file_count,
            oat_dex_files_offset: oat_dex_offset,
            executable_offset: exec_offset,
            interpreter_to_interpreter_bridge_offset: itib,
            interpreter_to_compiled_code_bridge_offset: itcc,
            jni_dlsym_lookup_offset: jni,
            compiler_filter: CompilerFilter::from_u32(filter_val),
            methods: Vec::new(),
            dex_file_checksums: Vec::new(),
        })
    }

    /// Instruction set name.
    #[must_use] 
    pub const fn isa_name(&self) -> &'static str {
        match self.instruction_set {
            1 => "arm",
            2 => "arm64",
            3 => "thumb2",
            4 => "x86",
            5 => "x86_64",
            6 => "mips",
            7 => "mips64",
            _ => "unknown",
        }
    }

    /// Number of methods with compiled native code.
    #[must_use] 
    pub fn compiled_method_count(&self) -> usize {
        self.methods.iter().filter(|m| m.is_compiled()).count()
    }
}

// ---------------------------------------------------------------------------
// VdexFile
// ---------------------------------------------------------------------------

/// Magic bytes for VDEX files (introduced in Android 8.0 / Oreo).
pub const VDEX_MAGIC: &[u8] = b"vdex";

/// Parsed VDEX file.
#[derive(Debug, Clone)]
pub struct VdexFile {
    pub version: u32,
    pub number_of_dex_files: u32,
    pub dex_size: u32,
    pub dex_shared_data_size: u32,
    pub quickening_info_size: u32,
    /// Raw DEX files embedded in the VDEX.
    pub dex_offsets: Vec<u32>,
    /// Quickening info offset per dex.
    pub quickening_info_offsets: Vec<u32>,
    pub data: Vec<u8>,
}

impl VdexFile {
    pub fn parse(data: &[u8]) -> Result<Self, ArtError> {
        if data.len() < 4 {
            return Err(ArtError::TruncatedData {
                offset: 0,
                needed: 4,
            });
        }
        if &data[..4] != VDEX_MAGIC {
            return Err(ArtError::InvalidMagic {
                expected: VDEX_MAGIC,
                got: data[..4.min(data.len())].to_vec(),
            });
        }
        if data.len() < 8 {
            return Err(ArtError::TruncatedData {
                offset: 4,
                needed: 4,
            });
        }
        let ver_bytes = &data[4..8];
        let version_str = std::str::from_utf8(&ver_bytes[..3]).unwrap_or("000");
        let version: u32 = version_str.parse().unwrap_or(0);

        if data.len() < 24 {
            return Err(ArtError::TruncatedData {
                offset: 8,
                needed: 16,
            });
        }

        let r4 = |o: usize| u32::from_le_bytes(data[o..o + 4].try_into().unwrap());
        let number_of_dex_files = r4(8);
        let dex_size = r4(12);
        let dex_shared_data_size = r4(16);
        let quickening_info_size = r4(20);

        // Parse per-dex offsets (simplistic: each follows the header)
        let mut dex_offsets = Vec::new();
        let mut offset = 24;
        for _ in 0..number_of_dex_files.min(256) {
            if offset + 4 > data.len() {
                break;
            }
            dex_offsets.push(r4(offset));
            offset += 4;
        }

        Ok(Self {
            version,
            number_of_dex_files,
            dex_size,
            dex_shared_data_size,
            quickening_info_size,
            dex_offsets,
            quickening_info_offsets: Vec::new(),
            data: data.to_vec(),
        })
    }

    /// `true` if there is quickening info present.
    #[must_use] 
    pub const fn has_quickening_info(&self) -> bool {
        self.quickening_info_size > 0
    }

    /// Get raw bytes of the Nth embedded dex file.
    #[must_use] 
    pub fn get_dex_file(&self, index: usize) -> Option<&[u8]> {
        let offset = *self.dex_offsets.get(index)? as usize;
        if offset >= self.data.len() {
            return None;
        }
        // Read DEX file size from its header at offset+32
        if offset + 36 > self.data.len() {
            return None;
        }
        let size =
            u32::from_le_bytes(self.data[offset + 32..offset + 36].try_into().ok()?) as usize;
        let end = (offset + size).min(self.data.len());
        Some(&self.data[offset..end])
    }
}

// ---------------------------------------------------------------------------
// ArtMethodProfile — per-method profiling data
// ---------------------------------------------------------------------------

/// Profiling data for a single method.
#[derive(Debug, Clone)]
pub struct ArtMethodProfile {
    /// DEX method index.
    pub method_index: u32,
    /// Fully qualified method name.
    pub name: String,
    /// Hotness count (how many times the method was invoked at profile time).
    pub hotness_count: u32,
    /// Inline caches (a set of receiver type indices).
    pub inline_caches: Vec<u32>,
    /// Whether this method is flagged as startup (first seconds of launch).
    pub is_startup: bool,
    /// Whether this method is flagged for post-startup optimisation.
    pub is_post_startup: bool,
}

impl ArtMethodProfile {
    pub fn new(method_index: u32, name: impl Into<String>) -> Self {
        Self {
            method_index,
            name: name.into(),
            hotness_count: 0,
            inline_caches: Vec::new(),
            is_startup: false,
            is_post_startup: false,
        }
    }

    /// `true` if this method should be AOT compiled.
    #[must_use] 
    pub const fn should_aot(&self) -> bool {
        self.hotness_count > 0 || self.is_startup
    }

    /// `true` if the method has monomorphic inline caches.
    #[must_use] 
    pub const fn is_monomorphic(&self) -> bool {
        self.inline_caches.len() == 1
    }

    /// `true` if the method has polymorphic inline caches.
    #[must_use] 
    pub const fn is_polymorphic(&self) -> bool {
        self.inline_caches.len() > 1
    }
}

// ---------------------------------------------------------------------------
// OatDexFile — per-dex-file header in OAT
// ---------------------------------------------------------------------------

/// Per-DEX file entry in an OAT file.
#[derive(Debug, Clone)]
pub struct OatDexFile {
    /// Path to the original DEX file (may be within an APK).
    pub dex_file_location: String,
    /// CRC32 checksum of the original DEX file.
    pub dex_file_location_checksum: u32,
    /// Offset of the `OatClass` array for this DEX file.
    pub classes_offset: u32,
    /// Number of class defs in the DEX.
    pub class_def_count: u32,
}

impl OatDexFile {
    pub fn new(location: impl Into<String>, checksum: u32) -> Self {
        Self {
            dex_file_location: location.into(),
            dex_file_location_checksum: checksum,
            classes_offset: 0,
            class_def_count: 0,
        }
    }

    /// `true` if this DEX was loaded from an APK ZIP entry.
    #[must_use] 
    pub fn is_from_apk(&self) -> bool {
        self.dex_file_location.contains("!/") || std::path::Path::new(&self.dex_file_location).extension().is_some_and(|e| e.eq_ignore_ascii_case("apk"))
    }

    /// The APK path portion (before `!/`), if applicable.
    #[must_use] 
    pub fn apk_path(&self) -> Option<&str> {
        let idx = self.dex_file_location.find("!/")?;
        Some(&self.dex_file_location[..idx])
    }

    /// The DEX entry name within the APK (after `!/`).
    #[must_use] 
    pub fn dex_entry_name(&self) -> Option<&str> {
        let idx = self.dex_file_location.find("!/")?;
        Some(&self.dex_file_location[idx + 2..])
    }
}

// ---------------------------------------------------------------------------
// ArtInstructionSet
// ---------------------------------------------------------------------------

/// Architecture constants for ART/OAT.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArtInstructionSet {
    None = 0,
    Arm = 1,
    Arm64 = 2,
    Thumb2 = 3,
    X86 = 4,
    X86_64 = 5,
    Mips = 6,
    Mips64 = 7,
}

impl ArtInstructionSet {
    #[must_use] 
    pub const fn from_u32(v: u32) -> Self {
        match v {
            1 => Self::Arm,
            2 => Self::Arm64,
            3 => Self::Thumb2,
            4 => Self::X86,
            5 => Self::X86_64,
            6 => Self::Mips,
            7 => Self::Mips64,
            _ => Self::None,
        }
    }

    #[must_use] 
    pub const fn name(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Arm => "arm",
            Self::Arm64 => "arm64",
            Self::Thumb2 => "thumb2",
            Self::X86 => "x86",
            Self::X86_64 => "x86_64",
            Self::Mips => "mips",
            Self::Mips64 => "mips64",
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

// ---------------------------------------------------------------------------
// ArtAnalysis — top-level aggregator
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// OatClassStatus — Class verification/compilation status in OAT
// ---------------------------------------------------------------------------

/// Status of a class in the OAT file.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum OatClassStatus {
    NotReady = -1,
    Erroneous = 0,
    Retry = 1,
    Verifying = 2,
    RetryVerificationAtRuntime = 3,
    Verified = 10,
    Initializing = 11,
    Initialized = 14,
}

impl OatClassStatus {
    #[must_use] 
    pub const fn from_i16(v: i16) -> Self {
        match v {
            -1 => Self::NotReady,
            0 => Self::Erroneous,
            1 => Self::Retry,
            2 => Self::Verifying,
            3 => Self::RetryVerificationAtRuntime,
            10 => Self::Verified,
            11 => Self::Initializing,
            14 => Self::Initialized,
            _ => Self::NotReady,
        }
    }

    #[must_use] 
    pub const fn name(self) -> &'static str {
        match self {
            Self::NotReady => "NotReady",
            Self::Erroneous => "Erroneous",
            Self::Retry => "Retry",
            Self::Verifying => "Verifying",
            Self::RetryVerificationAtRuntime => "RetryVerificationAtRuntime",
            Self::Verified => "Verified",
            Self::Initializing => "Initializing",
            Self::Initialized => "Initialized",
        }
    }

    #[must_use] 
    pub const fn is_verified(self) -> bool {
        matches!(
            self,
            Self::Verified | Self::Initializing | Self::Initialized
        )
    }
}

// ---------------------------------------------------------------------------
// OatClass — per-class entry in an OAT file
// ---------------------------------------------------------------------------

/// Type of the OAT class bitmap.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OatClassType {
    /// All methods are compiled.
    AllCompiled = 0,
    /// Some methods compiled; bitmap present.
    SomeCompiled = 1,
    /// No methods compiled.
    NoneCompiled = 2,
}

impl OatClassType {
    #[must_use] 
    pub const fn from_u16(v: u16) -> Self {
        match v {
            0 => Self::AllCompiled,
            1 => Self::SomeCompiled,
            _ => Self::NoneCompiled,
        }
    }
}

/// One class entry in an OAT file.
#[derive(Debug, Clone)]
pub struct OatClass {
    pub class_def_index: u32,
    pub status: OatClassStatus,
    pub class_type: OatClassType,
    /// Bitmask of compiled methods (present only for `SomeCompiled`).
    pub compiled_methods_bitmap: Option<Vec<u8>>,
    /// Method offsets relative to OAT file start.
    pub method_offsets: Vec<u32>,
}

impl OatClass {
    #[must_use] 
    pub const fn new(class_def_index: u32) -> Self {
        Self {
            class_def_index,
            status: OatClassStatus::NotReady,
            class_type: OatClassType::NoneCompiled,
            compiled_methods_bitmap: None,
            method_offsets: Vec::new(),
        }
    }

    /// `true` if the method at `method_index` is compiled.
    #[must_use] 
    pub fn is_method_compiled(&self, method_index: usize) -> bool {
        match self.class_type {
            OatClassType::AllCompiled => true,
            OatClassType::NoneCompiled => false,
            OatClassType::SomeCompiled => {
                if let Some(bm) = &self.compiled_methods_bitmap {
                    let byte_idx = method_index / 8;
                    let bit_idx = method_index % 8;
                    bm.get(byte_idx)
                        .is_some_and(|&b| (b >> bit_idx) & 1 == 1)
                } else {
                    false
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// ArtHeapStats — ART garbage-collected heap statistics
// ---------------------------------------------------------------------------

/// Statistics about the ART GC heap.
#[derive(Debug, Clone, Default)]
pub struct ArtHeapStats {
    pub bytes_allocated: u64,
    pub bytes_freed_last_gc: u64,
    pub objects_allocated: u64,
    pub gc_count: u32,
    pub explicit_gc_count: u32,
    pub blocking_gc_count: u32,
    pub large_object_space_size: u64,
    pub image_space_size: u64,
}

impl ArtHeapStats {
    #[must_use] 
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use] 
    pub const fn live_bytes(&self) -> u64 {
        self.bytes_allocated
            .saturating_sub(self.bytes_freed_last_gc)
    }

    #[must_use] 
    pub fn avg_object_size(&self) -> f64 {
        if self.objects_allocated == 0 {
            return 0.0;
        }
        self.bytes_allocated as f64 / self.objects_allocated as f64
    }
}

// ---------------------------------------------------------------------------
// ArtProfileAnalyzer — interpret inline profile (*.prof) data
// ---------------------------------------------------------------------------

/// Hot/startup method flags in ART profiles.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ArtProfileFlags(pub u16);

impl ArtProfileFlags {
    pub const HOT: u16 = 0x0001;
    pub const STARTUP: u16 = 0x0002;
    pub const POST_STARTUP: u16 = 0x0004;

    #[must_use] 
    pub const fn is_hot(self) -> bool {
        self.0 & Self::HOT != 0
    }
    #[must_use] 
    pub const fn is_startup(self) -> bool {
        self.0 & Self::STARTUP != 0
    }
    #[must_use] 
    pub const fn is_post_startup(self) -> bool {
        self.0 & Self::POST_STARTUP != 0
    }
}

/// One entry in an ART profile.
#[derive(Debug, Clone)]
pub struct ArtProfileEntry {
    pub dex_location: String,
    pub dex_checksum: u32,
    pub hot_methods: Vec<u32>,
    pub startup_methods: Vec<u32>,
    pub post_startup_methods: Vec<u32>,
}

impl ArtProfileEntry {
    pub fn new(location: impl Into<String>, checksum: u32) -> Self {
        Self {
            dex_location: location.into(),
            dex_checksum: checksum,
            hot_methods: Vec::new(),
            startup_methods: Vec::new(),
            post_startup_methods: Vec::new(),
        }
    }

    #[must_use] 
    pub const fn total_profile_methods(&self) -> usize {
        // Union of all method sets (simplified: sum)
        self.hot_methods.len() + self.startup_methods.len() + self.post_startup_methods.len()
    }
}

/// Analyser for ART binary profile data.
#[derive(Debug, Default)]
pub struct ArtProfileAnalyzer {
    pub entries: Vec<ArtProfileEntry>,
}

impl ArtProfileAnalyzer {
    #[must_use] 
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_entry(&mut self, e: ArtProfileEntry) {
        self.entries.push(e);
    }

    /// Total hot methods across all DEX files.
    #[must_use] 
    pub fn total_hot_methods(&self) -> usize {
        self.entries.iter().map(|e| e.hot_methods.len()).sum()
    }

    /// Total startup methods across all DEX files.
    #[must_use] 
    pub fn total_startup_methods(&self) -> usize {
        self.entries.iter().map(|e| e.startup_methods.len()).sum()
    }

    /// Find the profile entry for a specific DEX file location.
    #[must_use] 
    pub fn find_entry(&self, location: &str) -> Option<&ArtProfileEntry> {
        self.entries.iter().find(|e| e.dex_location == location)
    }
}

/// Complete ART runtime analysis aggregating OAT, VDEX, and profile data.
#[derive(Debug, Default)]
pub struct ArtAnalysis {
    pub oat_file: Option<OatFile>,
    pub vdex_file: Option<VdexFile>,
    pub hotness_bitmap: Option<HotnessBitmap>,
    /// Method name → `OatMethod` mapping (filled after resolving dex names).
    method_by_name: HashMap<String, usize>,
}

impl ArtAnalysis {
    #[must_use] 
    pub fn new() -> Self {
        Self::default()
    }

    pub fn set_oat(&mut self, oat: OatFile) {
        // Build name index
        for (i, m) in oat.methods.iter().enumerate() {
            if !m.name.is_empty() {
                self.method_by_name.insert(m.name.clone(), i);
            }
        }
        self.oat_file = Some(oat);
    }

    pub fn set_vdex(&mut self, vdex: VdexFile) {
        self.vdex_file = Some(vdex);
    }

    pub fn set_hotness(&mut self, bitmap: HotnessBitmap) {
        self.hotness_bitmap = Some(bitmap);
    }

    /// Look up a compiled method by name.
    #[must_use] 
    pub fn find_method(&self, name: &str) -> Option<&OatMethod> {
        let idx = *self.method_by_name.get(name)?;
        self.oat_file.as_ref()?.methods.get(idx)
    }

    /// `true` if the OAT file was compiled with profile-guided optimisation.
    #[must_use] 
    pub fn is_pgo(&self) -> bool {
        self.oat_file
            .as_ref()
            .is_some_and(|o| o.compiler_filter == CompilerFilter::SpeedProfile)
    }

    /// Total compiled method count.
    #[must_use] 
    pub fn compiled_method_count(&self) -> usize {
        self.oat_file
            .as_ref()
            .map_or(0, OatFile::compiled_method_count)
    }

    /// Number of hot methods (from profile).
    #[must_use] 
    pub fn hot_method_count(&self) -> u32 {
        self.hotness_bitmap
            .as_ref()
            .map_or(0, HotnessBitmap::hot_count)
    }

    /// Instruction set string if OAT is loaded.
    #[must_use] 
    pub fn isa_name(&self) -> Option<&'static str> {
        self.oat_file.as_ref().map(OatFile::isa_name)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_oat_header(version: &[u8; 3], filter: u32) -> Vec<u8> {
        let mut data = vec![0u8; 0x60];
        data[..4].copy_from_slice(OAT_MAGIC);
        data[4..7].copy_from_slice(version);
        data[7] = 0;
        data[44..48].copy_from_slice(&filter.to_le_bytes());
        data
    }

    fn make_vdex_header(version: &[u8; 3], n_dex: u32) -> Vec<u8> {
        let mut data = vec![0u8; 28];
        data[..4].copy_from_slice(VDEX_MAGIC);
        data[4..7].copy_from_slice(version);
        data[7] = 0;
        data[8..12].copy_from_slice(&n_dex.to_le_bytes());
        data
    }

    // ---- CompilerFilter ----

    #[test]
    fn test_compiler_filter_from_u32() {
        assert_eq!(CompilerFilter::from_u32(0), CompilerFilter::Verify);
        assert_eq!(CompilerFilter::from_u32(2), CompilerFilter::Speed);
        assert_eq!(CompilerFilter::from_u32(99), CompilerFilter::Unknown(99));
    }

    #[test]
    fn test_compiler_filter_roundtrip() {
        for v in 0..6u32 {
            let f = CompilerFilter::from_u32(v);
            assert_eq!(f.as_u32(), v);
        }
    }

    #[test]
    fn test_compiler_filter_has_compiled_code() {
        assert!(!CompilerFilter::Verify.has_compiled_code());
        assert!(CompilerFilter::Speed.has_compiled_code());
        assert!(CompilerFilter::SpeedProfile.has_compiled_code());
        assert!(!CompilerFilter::QuickenVerify.has_compiled_code());
    }

    #[test]
    fn test_compiler_filter_name() {
        assert_eq!(CompilerFilter::Speed.name(), "speed");
        assert_eq!(CompilerFilter::Verify.name(), "verify");
    }

    #[test]
    fn test_compiler_filter_unknown_name() {
        assert_eq!(CompilerFilter::Unknown(42).name(), "unknown");
    }

    // ---- HotnessBitmap ----

    #[test]
    fn test_hotness_bitmap_empty() {
        let b = HotnessBitmap::from_bytes(vec![], 0);
        assert_eq!(b.hot_count(), 0);
    }

    #[test]
    fn test_hotness_bitmap_set_and_check() {
        let mut b = HotnessBitmap::from_bytes(vec![0u8; 4], 32);
        b.set_hot(0);
        b.set_hot(7);
        b.set_hot(31);
        assert!(b.is_hot(0));
        assert!(b.is_hot(7));
        assert!(!b.is_hot(1));
        assert!(b.is_hot(31));
    }

    #[test]
    fn test_hotness_bitmap_hot_count() {
        let mut b = HotnessBitmap::from_bytes(vec![0u8; 2], 16);
        b.set_hot(0);
        b.set_hot(3);
        b.set_hot(9);
        assert_eq!(b.hot_count(), 3);
    }

    #[test]
    fn test_hotness_bitmap_out_of_range_ignored() {
        let b = HotnessBitmap::from_bytes(vec![0xFF], 4);
        assert!(!b.is_hot(100));
    }

    #[test]
    fn test_hotness_bitmap_hot_indices() {
        let mut b = HotnessBitmap::from_bytes(vec![0u8; 1], 8);
        b.set_hot(2);
        b.set_hot(5);
        let idxs = b.hot_indices();
        assert!(idxs.contains(&2));
        assert!(idxs.contains(&5));
        assert_eq!(idxs.len(), 2);
    }

    #[test]
    fn test_hotness_bitmap_set_hot_expands() {
        let mut b = HotnessBitmap::from_bytes(vec![], 32);
        b.set_hot(15);
        assert!(b.is_hot(15));
    }

    // ---- OatMethod ----

    #[test]
    fn test_oat_method_is_compiled() {
        let m = OatMethod::new(0, 0x1000, 0x80);
        assert!(m.is_compiled());
        let m2 = OatMethod::new(1, 0, 0);
        assert!(!m2.is_compiled());
    }

    #[test]
    fn test_oat_method_code_end_offset() {
        let m = OatMethod::new(0, 0x1000, 0x80);
        assert_eq!(m.code_end_offset(), 0x1080);
    }

    // ---- OatFile ----

    #[test]
    fn test_oat_file_parse_invalid_magic() {
        let data = b"notanoatfile";
        assert!(matches!(
            OatFile::parse(data),
            Err(ArtError::InvalidMagic { .. })
        ));
    }

    #[test]
    fn test_oat_file_parse_truncated() {
        assert!(matches!(
            OatFile::parse(&[]),
            Err(ArtError::TruncatedData { .. })
        ));
    }

    #[test]
    fn test_oat_file_parse_minimal() {
        let data = make_oat_header(b"079", CompilerFilter::Speed.as_u32());
        let oat = OatFile::parse(&data).unwrap();
        assert_eq!(oat.version, 79);
        assert_eq!(oat.compiler_filter, CompilerFilter::Speed);
    }

    #[test]
    fn test_oat_file_isa_arm64() {
        let mut data = make_oat_header(b"079", 0);
        data[12..16].copy_from_slice(&2u32.to_le_bytes()); // ISA = arm64
        let oat = OatFile::parse(&data).unwrap();
        assert_eq!(oat.isa_name(), "arm64");
    }

    #[test]
    fn test_oat_file_isa_x86_64() {
        let mut data = make_oat_header(b"079", 0);
        data[12..16].copy_from_slice(&5u32.to_le_bytes());
        let oat = OatFile::parse(&data).unwrap();
        assert_eq!(oat.isa_name(), "x86_64");
    }

    #[test]
    fn test_oat_file_compiled_count() {
        let data = make_oat_header(b"079", 2);
        let mut oat = OatFile::parse(&data).unwrap();
        oat.methods.push(OatMethod::new(0, 0x1000, 100));
        oat.methods.push(OatMethod::new(1, 0, 0));
        assert_eq!(oat.compiled_method_count(), 1);
    }

    // ---- VdexFile ----

    #[test]
    fn test_vdex_invalid_magic() {
        let data = b"notavdex";
        assert!(matches!(
            VdexFile::parse(data),
            Err(ArtError::InvalidMagic { .. })
        ));
    }

    #[test]
    fn test_vdex_truncated() {
        assert!(matches!(
            VdexFile::parse(&[]),
            Err(ArtError::TruncatedData { .. })
        ));
    }

    #[test]
    fn test_vdex_parse_minimal() {
        let data = make_vdex_header(b"021", 1);
        let vdex = VdexFile::parse(&data).unwrap();
        assert_eq!(vdex.version, 21);
        assert_eq!(vdex.number_of_dex_files, 1);
    }

    #[test]
    fn test_vdex_has_quickening_info_false() {
        let data = make_vdex_header(b"021", 0);
        let vdex = VdexFile::parse(&data).unwrap();
        assert!(!vdex.has_quickening_info());
    }

    #[test]
    fn test_vdex_has_quickening_info_true() {
        let mut data = make_vdex_header(b"021", 0);
        data[20..24].copy_from_slice(&1024u32.to_le_bytes());
        let vdex = VdexFile::parse(&data).unwrap();
        assert!(vdex.has_quickening_info());
    }

    // ---- ArtAnalysis ----

    #[test]
    fn test_art_analysis_default() {
        let a = ArtAnalysis::new();
        assert!(a.oat_file.is_none());
        assert!(!a.is_pgo());
        assert_eq!(a.compiled_method_count(), 0);
        assert_eq!(a.hot_method_count(), 0);
        assert!(a.isa_name().is_none());
    }

    #[test]
    fn test_art_analysis_set_oat() {
        let mut a = ArtAnalysis::new();
        let data = make_oat_header(b"079", CompilerFilter::Speed.as_u32());
        let oat = OatFile::parse(&data).unwrap();
        a.set_oat(oat);
        assert!(a.oat_file.is_some());
    }

    #[test]
    fn test_art_analysis_is_pgo() {
        let mut a = ArtAnalysis::new();
        let data = make_oat_header(b"079", CompilerFilter::SpeedProfile.as_u32());
        let oat = OatFile::parse(&data).unwrap();
        a.set_oat(oat);
        assert!(a.is_pgo());
    }

    #[test]
    fn test_art_analysis_find_method() {
        let mut a = ArtAnalysis::new();
        let data = make_oat_header(b"079", 0);
        let mut oat = OatFile::parse(&data).unwrap();
        let mut m = OatMethod::new(0, 0x1000, 100);
        m.name = "com.example.Foo.bar".to_string();
        oat.methods.push(m);
        a.set_oat(oat);
        assert!(a.find_method("com.example.Foo.bar").is_some());
        assert!(a.find_method("nonexistent").is_none());
    }

    #[test]
    fn test_art_analysis_isa_name() {
        let mut a = ArtAnalysis::new();
        let mut data = make_oat_header(b"079", 0);
        data[12..16].copy_from_slice(&1u32.to_le_bytes()); // arm
        let oat = OatFile::parse(&data).unwrap();
        a.set_oat(oat);
        assert_eq!(a.isa_name(), Some("arm"));
    }

    #[test]
    fn test_art_error_display() {
        let e = ArtError::UnsupportedVersion { version: 999 };
        assert!(e.to_string().contains("999"));
        let e2 = ArtError::InvalidChecksum {
            expected: 0xaabb,
            actual: 0xccdd,
        };
        assert!(e2.to_string().contains("aabb"));
    }

    #[test]
    fn test_art_analysis_hot_count() {
        let mut a = ArtAnalysis::new();
        let mut bm = HotnessBitmap::from_bytes(vec![0u8; 4], 32);
        bm.set_hot(0);
        bm.set_hot(5);
        bm.set_hot(10);
        a.set_hotness(bm);
        assert_eq!(a.hot_method_count(), 3);
    }

    #[test]
    fn test_art_analysis_compiled_method_count() {
        let mut a = ArtAnalysis::new();
        let data = make_oat_header(b"079", 0);
        let mut oat = OatFile::parse(&data).unwrap();
        oat.methods.push(OatMethod::new(0, 0x100, 50));
        oat.methods.push(OatMethod::new(1, 0x200, 60));
        oat.methods.push(OatMethod::new(2, 0, 0)); // not compiled
        a.set_oat(oat);
        assert_eq!(a.compiled_method_count(), 2);
    }

    #[test]
    fn test_compiler_filter_ordering() {
        assert!(CompilerFilter::Verify < CompilerFilter::Speed);
        assert!(CompilerFilter::Speed < CompilerFilter::Everything);
    }

    #[test]
    fn test_hotness_bitmap_total_methods() {
        let b = HotnessBitmap::from_bytes(vec![0u8; 2], 16);
        assert_eq!(b.total_methods(), 16);
    }

    #[test]
    fn test_hotness_bitmap_boundary_bit() {
        let mut b = HotnessBitmap::from_bytes(vec![0u8; 1], 8);
        b.set_hot(7);
        assert!(b.is_hot(7));
        assert!(!b.is_hot(6));
    }

    #[test]
    fn test_oat_method_has_native_code_flag() {
        let m = OatMethod::new(0, 0x500, 64);
        assert!(m.has_native_code);
        let m2 = OatMethod::new(1, 0, 0);
        assert!(!m2.has_native_code);
    }

    #[test]
    fn test_oat_file_version_field() {
        let data = make_oat_header(b"082", 0);
        let oat = OatFile::parse(&data).unwrap();
        assert_eq!(oat.version, 82);
    }

    #[test]
    fn test_oat_file_isa_unknown() {
        let mut data = make_oat_header(b"079", 0);
        data[12..16].copy_from_slice(&99u32.to_le_bytes());
        let oat = OatFile::parse(&data).unwrap();
        assert_eq!(oat.isa_name(), "unknown");
    }

    #[test]
    fn test_oat_file_isa_x86() {
        let mut data = make_oat_header(b"079", 0);
        data[12..16].copy_from_slice(&4u32.to_le_bytes());
        let oat = OatFile::parse(&data).unwrap();
        assert_eq!(oat.isa_name(), "x86");
    }

    #[test]
    fn test_vdex_dex_file_out_of_bounds() {
        let data = make_vdex_header(b"021", 1);
        let vdex = VdexFile::parse(&data).unwrap();
        // No DEX data present, should return None
        assert!(vdex.get_dex_file(0).is_none());
    }

    #[test]
    fn test_art_analysis_set_vdex() {
        let mut a = ArtAnalysis::new();
        let data = make_vdex_header(b"021", 0);
        let vdex = VdexFile::parse(&data).unwrap();
        a.set_vdex(vdex);
        assert!(a.vdex_file.is_some());
    }

    #[test]
    fn test_art_analysis_isa_name_none() {
        let a = ArtAnalysis::new();
        assert!(a.isa_name().is_none());
    }

    #[test]
    fn test_hotness_bitmap_indices_empty() {
        let b = HotnessBitmap::from_bytes(vec![0u8; 4], 32);
        assert!(b.hot_indices().is_empty());
    }

    #[test]
    fn test_art_error_invalid_dex_offset() {
        let e = ArtError::InvalidDexOffset(0xdeadbeef);
        assert!(e.to_string().contains("deadbeef"));
    }
}

// ---------------------------------------------------------------------------
// OatMethodCodeInfo - native code metadata for one compiled method
// ---------------------------------------------------------------------------

/// Native code information extracted from an OAT compiled method.
#[derive(Debug, Clone)]
pub struct OatMethodCodeInfo {
    pub method_index: u32,
    pub code_offset: u32,
    pub code_size: u32,
    pub vmap_table_offset: u32,
    pub gc_map_offset: u32,
    pub frame_size: u32,
    pub core_spill_mask: u32,
    pub fp_spill_mask: u32,
}

impl OatMethodCodeInfo {
    #[must_use] 
    pub const fn new(method_index: u32, code_offset: u32) -> Self {
        Self {
            method_index,
            code_offset,
            code_size: 0,
            vmap_table_offset: 0,
            gc_map_offset: 0,
            frame_size: 0,
            core_spill_mask: 0,
            fp_spill_mask: 0,
        }
    }

    /// Number of callee-saved registers from the core spill mask.
    #[must_use] 
    pub const fn num_core_spills(&self) -> u32 {
        self.core_spill_mask.count_ones()
    }
    #[must_use] 
    pub const fn num_fp_spills(&self) -> u32 {
        self.fp_spill_mask.count_ones()
    }
    #[must_use] 
    pub const fn has_gc_map(&self) -> bool {
        self.gc_map_offset != 0
    }
    #[must_use] 
    pub const fn has_vmap(&self) -> bool {
        self.vmap_table_offset != 0
    }
}

// ---------------------------------------------------------------------------
// ArtInlineCache - polymorphic inline cache entry
// ---------------------------------------------------------------------------

/// One inline cache entry (receiver type seen at a call site).
#[derive(Debug, Clone)]
pub struct ArtInlineCache {
    pub dex_pc: u32,
    pub receiver_types: Vec<u32>,
    pub is_megamorphic: bool,
    pub is_missing_types: bool,
}

impl ArtInlineCache {
    #[must_use] 
    pub const fn new(dex_pc: u32) -> Self {
        Self {
            dex_pc,
            receiver_types: Vec::new(),
            is_megamorphic: false,
            is_missing_types: false,
        }
    }

    #[must_use] 
    pub const fn is_monomorphic(&self) -> bool {
        self.receiver_types.len() == 1 && !self.is_megamorphic
    }
    #[must_use] 
    pub const fn is_polymorphic(&self) -> bool {
        self.receiver_types.len() > 1 && !self.is_megamorphic
    }
    #[must_use] 
    pub const fn receiver_count(&self) -> usize {
        self.receiver_types.len()
    }
}

// ---------------------------------------------------------------------------
// ArtBootImage - boot image analysis
// ---------------------------------------------------------------------------

/// Analysis of an ART boot image (boot.art / boot-framework.art).
#[derive(Debug, Clone, Default)]
pub struct ArtBootImageInfo {
    pub image_begin: u64,
    pub image_size: u64,
    pub oat_checksum: u32,
    pub oat_file_begin: u64,
    pub oat_data_begin: u64,
    pub oat_data_end: u64,
    pub oat_file_end: u64,
    pub compile_pic: bool,
    pub is_pic: bool,
}

impl ArtBootImageInfo {
    #[must_use] 
    pub fn new() -> Self {
        Self::default()
    }
    #[must_use] 
    pub const fn oat_size(&self) -> u64 {
        self.oat_data_end.saturating_sub(self.oat_data_begin)
    }
}
// ---------------------------------------------------------------------------
// ArtClassLoaderContext - class loader context for OAT compilation
// ---------------------------------------------------------------------------

/// Context describing the class loader chain used during OAT compilation.
#[derive(Debug, Clone, Default)]
pub struct ArtClassLoaderContext {
    pub class_loader_chain: Vec<ArtClassLoaderEntry>,
}

/// One class loader in the context chain.
#[derive(Debug, Clone)]
pub struct ArtClassLoaderEntry {
    pub class_loader_type: ArtClassLoaderType,
    pub classpath: Vec<String>,
}

/// Type of class loader.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArtClassLoaderType {
    PathClassLoader,
    DelegateLastClassLoader,
    InMemoryDexClassLoader,
}

impl ArtClassLoaderType {
    #[must_use] 
    pub const fn name(self) -> &'static str {
        match self {
            Self::PathClassLoader => "PCL",
            Self::DelegateLastClassLoader => "DLC",
            Self::InMemoryDexClassLoader => "IMC",
        }
    }
}

impl ArtClassLoaderContext {
    #[must_use] 
    pub fn new() -> Self {
        Self::default()
    }
    pub fn add_entry(&mut self, entry: ArtClassLoaderEntry) {
        self.class_loader_chain.push(entry);
    }
    #[must_use] 
    pub const fn is_empty(&self) -> bool {
        self.class_loader_chain.is_empty()
    }
    #[must_use] 
    pub fn total_classpath_entries(&self) -> usize {
        self.class_loader_chain
            .iter()
            .map(|e| e.classpath.len())
            .sum()
    }
}

// ---------------------------------------------------------------------------
// OatVerification - OAT integrity checks
// ---------------------------------------------------------------------------

/// Result of OAT file integrity verification.
#[derive(Debug, Clone)]
pub struct OatVerificationResult {
    pub magic_valid: bool,
    pub checksum_valid: bool,
    pub version_supported: bool,
    pub dex_checksums_match: bool,
    pub warnings: Vec<String>,
}

impl OatVerificationResult {
    #[must_use] 
    pub const fn is_valid(&self) -> bool {
        self.magic_valid && self.checksum_valid && self.version_supported
    }
}

// ---------------------------------------------------------------------------
// ArtGcPause - GC pause information
// ---------------------------------------------------------------------------

/// Type of ART GC pause.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArtGcPauseType {
    Minor,
    Major,
    Explicit,
    NativeAlloc,
}

/// One GC pause event.
#[derive(Debug, Clone)]
pub struct ArtGcPause {
    pub pause_type: ArtGcPauseType,
    pub duration_us: u64,
    pub freed_bytes: u64,
    pub freed_objects: u64,
    pub pause_phase: u32,
}

impl ArtGcPause {
    #[must_use] 
    pub const fn new(t: ArtGcPauseType, duration: u64) -> Self {
        Self {
            pause_type: t,
            duration_us: duration,
            freed_bytes: 0,
            freed_objects: 0,
            pause_phase: 0,
        }
    }
    #[must_use] 
    pub const fn is_long(&self) -> bool {
        self.duration_us > 5000
    }
}

/// Collection of GC pause events.
#[derive(Debug, Default)]
pub struct ArtGcPauseLog {
    pub pauses: Vec<ArtGcPause>,
}
impl ArtGcPauseLog {
    #[must_use] 
    pub fn new() -> Self {
        Self::default()
    }
    pub fn add(&mut self, p: ArtGcPause) {
        self.pauses.push(p);
    }
    #[must_use] 
    pub fn total_pause_us(&self) -> u64 {
        self.pauses.iter().map(|p| p.duration_us).sum()
    }
    #[must_use] 
    pub fn long_pause_count(&self) -> usize {
        self.pauses.iter().filter(|p| p.is_long()).count()
    }
}

// ---------------------------------------------------------------------------
// Utility helpers
// ---------------------------------------------------------------------------

/// Read a null-terminated UTF-8 string from a byte slice at `offset`.
#[must_use] 
pub fn read_cstring(data: &[u8], offset: usize) -> Option<String> {
    if offset >= data.len() {
        return None;
    }
    let end = data[offset..]
        .iter()
        .position(|&b| b == 0)
        .map_or(data.len(), |p| offset + p);
    std::str::from_utf8(&data[offset..end])
        .ok()
        .map(std::borrow::ToOwned::to_owned)
}

/// Align a value up to `align` (power-of-two).
#[must_use] 
pub const fn align_up(val: u64, align: u64) -> u64 {
    if align == 0 {
        return val;
    }
    (val + align - 1) & !(align - 1)
}

/// Align a value down to `align` (power-of-two).
#[must_use] 
pub const fn align_down(val: u64, align: u64) -> u64 {
    if align == 0 {
        return val;
    }
    val & !(align - 1)
}

/// Check whether `val` is a power of two.
#[must_use] 
pub const fn is_power_of_two(val: u64) -> bool {
    val != 0 && val.is_power_of_two()
}

/// Simple entropy estimate over a byte slice (0.0 = uniform, 1.0 = random).
#[must_use] 
pub fn byte_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut freq = [0u32; 256];
    for &b in data {
        freq[b as usize] += 1;
    }
    let n = data.len() as f64;
    let mut entropy = 0.0f64;
    for &c in &freq {
        if c > 0 {
            let p = f64::from(c) / n;
            entropy = p.mul_add(-p.log2(), entropy);
        }
    }
    entropy / 8.0 // normalise to [0, 1]
}

// ---------------------------------------------------------------------------
// Additional parsing utilities
// ---------------------------------------------------------------------------

/// Parse a little-endian u16.
#[inline]
#[must_use] 
pub fn le_u16(data: &[u8], off: usize) -> u16 {
    if off + 2 > data.len() {
        return 0;
    }
    u16::from_le_bytes([data[off], data[off + 1]])
}
/// Parse a little-endian u32.
#[inline]
#[must_use] 
pub fn le_u32(data: &[u8], off: usize) -> u32 {
    if off + 4 > data.len() {
        return 0;
    }
    u32::from_le_bytes(data[off..off + 4].try_into().unwrap())
}
/// Parse a little-endian u64.
#[inline]
#[must_use] 
pub fn le_u64(data: &[u8], off: usize) -> u64 {
    if off + 8 > data.len() {
        return 0;
    }
    u64::from_le_bytes(data[off..off + 8].try_into().unwrap())
}
/// Parse a big-endian u32.
#[inline]
#[must_use] 
pub fn be_u32(data: &[u8], off: usize) -> u32 {
    if off + 4 > data.len() {
        return 0;
    }
    u32::from_be_bytes(data[off..off + 4].try_into().unwrap())
}
/// Verify a 32-bit Adler-32 checksum over `data`.
#[must_use] 
pub fn adler32(data: &[u8]) -> u32 {
    let (mut a, mut b) = (1u32, 0u32);
    for &byte in data {
        a = (a + u32::from(byte)) % 65521;
        b = (b + a) % 65521;
    }
    (b << 16) | a
}

// ---------------------------------------------------------------------------
// Byte pattern matching utilities
// ---------------------------------------------------------------------------

/// Search `haystack` for the first occurrence of `needle`.
#[must_use] 
pub fn find_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() {
        return Some(0);
    }
    haystack.windows(needle.len()).position(|w| w == needle)
}

/// Count non-overlapping occurrences of `needle` in `haystack`.
#[must_use] 
pub fn count_bytes(haystack: &[u8], needle: &[u8]) -> usize {
    if needle.is_empty() {
        return 0;
    }
    let mut count = 0;
    let mut pos = 0;
    while let Some(idx) = haystack[pos..]
        .windows(needle.len())
        .position(|w| w == needle)
    {
        count += 1;
        pos += idx + needle.len();
    }
    count
}

/// Extract a sub-slice at `offset` with `len`, returning `None` if out of bounds.
#[must_use] 
pub fn try_slice(data: &[u8], offset: usize, len: usize) -> Option<&[u8]> {
    data.get(offset..offset + len)
}

// Last additions
/// Check if a byte slice is all zeros.
#[must_use] 
pub fn is_zeroed(data: &[u8]) -> bool {
    data.iter().all(|&b| b == 0)
}
/// Reverse bytes in-place.
pub const fn reverse_bytes(data: &mut [u8]) {
    data.reverse();
}
/// XOR all bytes with `key`.
pub fn xor_bytes(data: &mut [u8], key: u8) {
    for b in data.iter_mut() {
        *b ^= key;
    }
}
/// Rotate `val` left by `n` bits (32-bit).
#[must_use] 
pub const fn rol32(val: u32, n: u32) -> u32 {
    val.rotate_left(n)
}
/// Rotate `val` right by `n` bits (32-bit).
#[must_use] 
pub const fn ror32(val: u32, n: u32) -> u32 {
    val.rotate_right(n)
}
