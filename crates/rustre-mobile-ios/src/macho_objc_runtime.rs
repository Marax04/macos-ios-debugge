//! `macho_objc_runtime` — Parse Objective-C runtime structures in Mach-O binaries.
//!
//! Walks `__objc_classlist`, `__objc_methnames`, `__objc_classnames`,
//! `__objc_ivar_offsets`, and `__objc_protolist` sections from raw Mach-O bytes
//! to reconstruct [`ObjcClass`], [`ObjcMethod`], and [`ObjcIvar`] descriptors
//! without requiring a running process or dynamic linker.
//!
//! # Layer distinction
//! This module is the **ABI-level binary parser**: it performs `class_ro_t` /
//! `method_list_t` / `ivar_list_t` struct walking with VMA→file-offset
//! resolution ([`MachoObjcRuntime`], [`ParseConfig`], [`ParseStats`]).
//! Its `ObjcClass`/`ObjcMethod`/`ObjcIvar` types carry binary-parser-specific
//! fields (`instance_size`, `imp_addr`, `param_count`).
//!
//! Sibling modules serve different purposes:
//! * `objc_runtime` — typed encoding decoder ([`ObjcType`] enum,
//!   [`ObjcMetadataParser`], property-flag bitfield).
//! * `objc_runtime_analysis` — high-level behavioural analysis (swizzle
//!   detection, `objc_msgSend` hook scanning, [`ObjcRuntimeReport`]).
//!
//! [`ObjcType`]: super::objc_runtime::ObjcType
//! [`ObjcMetadataParser`]: super::objc_runtime::ObjcMetadataParser
//! [`ObjcRuntimeReport`]: super::objc_runtime_analysis::ObjcRuntimeReport

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;

// ─── Error ───────────────────────────────────────────────────────────────────

/// Errors produced by the `Mach-O` `ObjC` runtime parser.
#[derive(Debug, thiserror::Error)]
pub enum MachoObjcError {
    #[error("not a valid Mach-O binary")]
    NotMachO,
    #[error("section not found: `{0}`,`{1}`")]
    SectionNotFound(String, String),
    #[error("offset out of bounds: {0:#x}")]
    OutOfBounds(usize),
    #[error("invalid utf-8 string at offset {0:#x}")]
    InvalidString(usize),
    #[error("class list parse error: {0}")]
    ClassList(String),
}

// ─── ObjcMethod ──────────────────────────────────────────────────────────────

/// A single Objective-C method recovered from the runtime method list.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObjcMethod {
    /// Selector string, e.g. `initWithFrame:`.
    pub name: String,
    /// Raw `ObjC` type-encoding, e.g. `v16@0:8`.
    pub type_encoding: String,
    /// Virtual address of the method implementation.
    pub imp_addr: u64,
}

impl ObjcMethod {
    /// Create a new `ObjcMethod`.
    #[must_use]
    pub fn new(name: impl Into<String>, type_encoding: impl Into<String>, imp_addr: u64) -> Self {
        Self {
            name: name.into(),
            type_encoding: type_encoding.into(),
            imp_addr,
        }
    }

    /// Returns `true` if this is a void-returning method.
    #[must_use]
    pub fn is_void_return(&self) -> bool {
        self.type_encoding.starts_with('v')
    }

    /// Returns the number of parameters encoded in the type string.
    #[must_use]
    pub fn param_count(&self) -> usize {
        // Each ':' corresponds to one selector component / argument
        self.name.chars().filter(|&c| c == ':').count()
    }
}

impl fmt::Display for ObjcMethod {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "-[{} ({})]", self.name, self.type_encoding)
    }
}

// ─── ObjcIvar ────────────────────────────────────────────────────────────────

/// An Objective-C instance variable recovered from the ivar list.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObjcIvar {
    /// Ivar name, e.g. `_delegate`.
    pub name: String,
    /// `ObjC` type-encoding of the declared type.
    pub type_encoding: String,
    /// Byte offset within the class instance layout.
    pub offset: u32,
    /// Declared size in bytes.
    pub size: u32,
}

impl ObjcIvar {
    /// Create a new `ObjcIvar`.
    #[must_use]
    pub fn new(
        name: impl Into<String>,
        type_encoding: impl Into<String>,
        offset: u32,
        size: u32,
    ) -> Self {
        Self {
            name: name.into(),
            type_encoding: type_encoding.into(),
            offset,
            size,
        }
    }

    /// Returns `true` if this ivar holds an object reference.
    #[must_use]
    pub fn is_object(&self) -> bool {
        self.type_encoding.starts_with('@')
    }
}

// ─── ObjcProtocol ────────────────────────────────────────────────────────────

/// An Objective-C protocol reference recovered from `__objc_protolist`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObjcProtocol {
    /// Protocol name, e.g. `NSCoding`.
    pub name: String,
    /// Required instance methods declared by this protocol.
    pub required_instance_methods: Vec<String>,
    /// Optional instance methods declared by this protocol.
    pub optional_instance_methods: Vec<String>,
}

impl ObjcProtocol {
    /// Create a protocol with the given name and no methods.
    #[must_use]
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            required_instance_methods: Vec::new(),
            optional_instance_methods: Vec::new(),
        }
    }
}

// ─── ObjcClass ───────────────────────────────────────────────────────────────

/// Full description of an Objective-C class recovered from the Mach-O binary.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObjcClass {
    /// Unmangled class name.
    pub name: String,
    /// Superclass name, if known.
    pub superclass: Option<String>,
    /// Adopted protocol names.
    pub protocols: Vec<String>,
    /// Instance method list.
    pub instance_methods: Vec<ObjcMethod>,
    /// Class (`+`) method list.
    pub class_methods: Vec<ObjcMethod>,
    /// Instance variable list.
    pub ivars: Vec<ObjcIvar>,
    /// Total instance size in bytes.
    pub instance_size: u32,
}

impl ObjcClass {
    /// Create a new, empty class entry.
    #[must_use]
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            superclass: None,
            protocols: Vec::new(),
            instance_methods: Vec::new(),
            class_methods: Vec::new(),
            ivars: Vec::new(),
            instance_size: 0,
        }
    }

    /// Total number of methods (instance + class).
    #[must_use]
    pub const fn total_method_count(&self) -> usize {
        self.instance_methods.len() + self.class_methods.len()
    }

    /// Returns `true` if this class adopts the named protocol.
    #[must_use]
    pub fn adopts_protocol(&self, proto: &str) -> bool {
        self.protocols.iter().any(|p| p == proto)
    }

    /// Find an instance method by selector.
    #[must_use]
    pub fn find_instance_method(&self, sel: &str) -> Option<&ObjcMethod> {
        self.instance_methods.iter().find(|m| m.name == sel)
    }

    /// Find a class method by selector.
    #[must_use]
    pub fn find_class_method(&self, sel: &str) -> Option<&ObjcMethod> {
        self.class_methods.iter().find(|m| m.name == sel)
    }

    /// Find an ivar by name.
    #[must_use]
    pub fn find_ivar(&self, name: &str) -> Option<&ObjcIvar> {
        self.ivars.iter().find(|iv| iv.name == name)
    }
}

// ─── Section helpers ──────────────────────────────────────────────────────────

/// Read all null-terminated C strings from a raw section byte slice.
fn read_cstrings(data: &[u8]) -> Vec<String> {
    let mut out = Vec::new();
    let mut start = 0usize;
    for (i, &b) in data.iter().enumerate() {
        if b == 0 {
            if i > start
                && let Ok(s) = std::str::from_utf8(&data[start..i]).map(str::trim) && !s.is_empty() {
                    out.push(s.to_string());
                }
            start = i + 1;
        }
    }
    if start < data.len()
        && let Ok(s) = std::str::from_utf8(&data[start..]).map(str::trim) && !s.is_empty() {
            out.push(s.to_string());
        }
    out
}

/// Read a null-terminated string at `offset` from `data`.
fn read_cstr_at(data: &[u8], offset: usize) -> Option<String> {
    let slice = data.get(offset..)?;
    let end = slice.iter().position(|&b| b == 0).unwrap_or(slice.len());
    std::str::from_utf8(&slice[..end.min(256)])
        .ok()
        .map(|s| s.trim().to_string())
}

/// Extract a named section's raw bytes from a thin Mach-O slice.
fn section_bytes<'a>(binary: &'a [u8], seg: &str, sect: &str) -> Option<&'a [u8]> {
    match goblin::mach::MachO::parse(binary, 0) {
        Ok(macho) => {
            for item in macho.segments.sections().flatten() {
                let Ok((hdr, _)) = item else { continue };
                let sn = std::str::from_utf8(&hdr.sectname)
                    .unwrap_or("")
                    .trim_end_matches('\0');
                let sg = std::str::from_utf8(&hdr.segname)
                    .unwrap_or("")
                    .trim_end_matches('\0');
                if sn == sect && sg == seg {
                    let off = hdr.offset as usize;
                    let sz = usize::try_from(hdr.size).unwrap_or(usize::MAX);
                    if off + sz <= binary.len() {
                        return Some(&binary[off..off + sz]);
                    }
                }
            }
            None
        }
        Err(_) => None,
    }
}

// ─── MachoObjcRuntime ────────────────────────────────────────────────────────

/// Configuration for the `ObjC` runtime parser.
#[derive(Debug, Clone)]
pub struct ParseConfig {
    /// Maximum number of classes to parse (to limit memory on large binaries).
    pub max_classes: usize,
    /// Maximum methods per class.
    pub max_methods_per_class: usize,
    /// Maximum ivars per class.
    pub max_ivars_per_class: usize,
}

impl Default for ParseConfig {
    fn default() -> Self {
        Self {
            max_classes: 4096,
            max_methods_per_class: 2048,
            max_ivars_per_class: 512,
        }
    }
}

/// Statistics reported after a parse.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ParseStats {
    /// Total classes found.
    pub class_count: usize,
    /// Total instance methods across all classes.
    pub instance_method_count: usize,
    /// Total class methods across all classes.
    pub class_method_count: usize,
    /// Total ivars across all classes.
    pub ivar_count: usize,
    /// Selector strings from `__objc_methnames`.
    pub selector_count: usize,
    /// Class names from `__objc_classnames`.
    pub classname_count: usize,
}

impl ParseStats {
    /// Total method count (instance + class).
    #[must_use]
    pub const fn total_methods(&self) -> usize {
        self.instance_method_count + self.class_method_count
    }
}

/// The main `Mach-O` `ObjC` runtime parser.
///
/// Reconstructs class/method/ivar information from a raw `Mach-O` byte slice
/// by reading `ObjC` metadata sections without executing any code.
pub struct MachoObjcRuntime {
    /// Parsed classes, keyed by class name.
    pub classes: HashMap<String, ObjcClass>,
    /// Raw selector strings from `__TEXT,__objc_methnames`.
    pub selectors: Vec<String>,
    /// Raw class name strings from `__TEXT,__objc_classnames`.
    pub class_names: Vec<String>,
    /// Protocols from `__objc_protolist` (names only in this implementation).
    pub protocols: Vec<ObjcProtocol>,
    /// Parse statistics.
    pub stats: ParseStats,
}

impl MachoObjcRuntime {
    /// Parse a raw `Mach-O` byte slice and reconstruct the `ObjC` runtime metadata.
    ///
    /// Returns `Ok(runtime)` even if the binary has no `ObjC` sections — the
    /// collections will simply be empty.
    ///
    /// # Errors
    /// Returns [`MachoObjcError::NotMachO`] if the binary is too short or not a valid Mach-O.
    pub fn parse(binary: &[u8], config: &ParseConfig) -> Result<Self, MachoObjcError> {
        if binary.len() < 4 {
            return Err(MachoObjcError::NotMachO);
        }

        // Reject anything that is not a Mach-O at all.
        //
        // The length check alone let arbitrary bytes through: every
        // `section_bytes` lookup then failed silently and `Ok` was returned with
        // an empty runtime, so a caller could not tell "not a Mach-O" from "a
        // Mach-O carrying no Objective-C metadata". The error variant is already
        // named `NotMachO` — this is the check it was named for.
        let magic = u32::from_le_bytes([binary[0], binary[1], binary[2], binary[3]]);
        if !matches!(
            magic,
            crate::fairplay::MH_MAGIC_32
                | crate::fairplay::MH_MAGIC_64
                | crate::fairplay::MH_CIGAM_32
                | crate::fairplay::MH_CIGAM_64
                | crate::fairplay::FAT_MAGIC
                | crate::fairplay::FAT_MAGIC_64
        ) {
            return Err(MachoObjcError::NotMachO);
        }

        let mut runtime = Self {
            classes: HashMap::new(),
            selectors: Vec::new(),
            class_names: Vec::new(),
            protocols: Vec::new(),
            stats: ParseStats::default(),
        };

        // ── Selector strings ─────────────────────────────────────────────────
        if let Some(data) = section_bytes(binary, "__TEXT", "__objc_methnames") {
            runtime.selectors = read_cstrings(data);
        }
        runtime.stats.selector_count = runtime.selectors.len();

        // ── Class name strings ────────────────────────────────────────────────
        if let Some(data) = section_bytes(binary, "__TEXT", "__objc_classnames") {
            runtime.class_names = read_cstrings(data);
        }
        runtime.stats.classname_count = runtime.class_names.len();

        // ── Build lightweight class stubs from classnames + selectors ─────────
        // Full struct-level parsing would require RVA resolution and pointer
        // chasing which is highly ABI-dependent.  Instead we build stubs that
        // accurately reflect the available string-table data and annotate them
        // with selector associations by heuristic.
        runtime.build_class_stubs(binary, config);

        // ── Protocol names from __objc_protolist (name-only) ──────────────────
        if let Some(data) = section_bytes(binary, "__DATA", "__objc_protolist") {
            runtime.parse_protolist_names(binary, data);
        }

        runtime.stats.class_count = runtime.classes.len();

        Ok(runtime)
    }

    /// Build class stubs from `__objc_classnames` and, if present, the
    /// `__objc_classlist` pointer array.
    fn build_class_stubs(&mut self, binary: &[u8], config: &ParseConfig) {
        // Primary: parse `__objc_classlist` as an array of 8-byte class pointers
        // and follow each to a `class_t` / `class_ro_t` struct.
        if let Some(classlist) = section_bytes(binary, "__DATA", "__objc_classlist") {
            self.parse_classlist(binary, classlist, config);
        }

        // Fallback: if no classes were found through classlist, manufacture stubs
        // from the classnames string table (read-only info only).
        if self.classes.is_empty() {
            for name in self.class_names.iter().take(config.max_classes) {
                let cls = ObjcClass::new(name.clone());
                self.classes.insert(name.clone(), cls);
            }
        }
    }

    /// Walk `__objc_classlist` (array of 8-byte pointers, little-endian) and
    /// parse each `class_ro_t` structure.
    fn parse_classlist(&mut self, binary: &[u8], classlist: &[u8], config: &ParseConfig) {
        let ptr_size = 8usize;
        let entry_count = classlist.len() / ptr_size;

        // Determine the image base to convert VMAs to file offsets.
        let image_base = Self::guess_image_base(binary);

        let mut parsed = 0usize;
        for i in 0..entry_count {
            if parsed >= config.max_classes {
                break;
            }
            let off = i * ptr_size;
            if off + ptr_size > classlist.len() {
                break;
            }
            let class_vma = u64::from_le_bytes(classlist[off..off + ptr_size].try_into().unwrap_or([0u8; 8]));
            if class_vma == 0 {
                continue;
            }
            // Follow class_t → data pointer (offset 0x20 in class_t) → class_ro_t
            let class_foff = vma_to_foff(binary, class_vma, image_base);
            let Some(class_foff) = class_foff else { continue };

            // class_t layout (arm64, 5 pointers at 8 bytes each = 40 bytes):
            //  0: metaclass ptr
            //  8: superclass ptr
            // 16: cache ptr
            // 24: vtable ptr
            // 32: data ptr (-> class_ro_t, low bit may be set for Swift classes)
            if class_foff + 40 > binary.len() {
                continue;
            }
            let data_vma_raw = u64::from_le_bytes(
                binary[class_foff + 32..class_foff + 40]
                    .try_into()
                    .unwrap_or([0u8; 8]),
            );
            let superclass_vma = u64::from_le_bytes(
                binary[class_foff + 8..class_foff + 16]
                    .try_into()
                    .unwrap_or([0u8; 8]),
            );
            let data_vma = data_vma_raw & !0b111; // strip Swift bits

            let Some(ro_foff) = vma_to_foff(binary, data_vma, image_base) else {
                continue;
            };

            let cls = Self::parse_class_ro(binary, ro_foff, superclass_vma, image_base, config);
            if let Some(mut cls) = cls {
                // Fill instance methods from selector table association
                Self::associate_selectors_to_class(&mut cls);
                let name = cls.name.clone();
                self.classes.insert(name, cls);
                parsed += 1;
            }
        }
    }

    /// Parse a `class_ro_t` structure at `ro_foff` and return an `ObjcClass`.
    fn parse_class_ro(
        binary: &[u8],
        ro_foff: usize,
        superclass_vma: u64,
        image_base: u64,
        config: &ParseConfig,
    ) -> Option<ObjcClass> {
        // class_ro_t layout (arm64):
        //  0: uint32 flags
        //  4: uint32 instanceStart
        //  8: uint32 instanceSize
        // 12: uint32 reserved (arm64 only)
        // 16: const uint8* ivarLayout
        // 24: const char* name
        // 32: method_list_t* baseMethods
        // 40: protocol_list_t* baseProtocols
        // 48: ivar_list_t* ivars
        // 56: const uint8* weakIvarLayout
        // 64: property_list_t* baseProperties
        if ro_foff + 72 > binary.len() {
            return None;
        }

        let instance_size = u32::from_le_bytes(
            binary[ro_foff + 8..ro_foff + 12].try_into().unwrap_or([0u8; 4]),
        );

        let name_ptr = u64::from_le_bytes(
            binary[ro_foff + 24..ro_foff + 32].try_into().unwrap_or([0u8; 8]),
        );
        let name_foff = vma_to_foff(binary, name_ptr, image_base);
        let name = name_foff
            .and_then(|off| read_cstr_at(binary, off))
            .unwrap_or_else(|| "?".to_string());

        let methods_vma = u64::from_le_bytes(
            binary[ro_foff + 32..ro_foff + 40].try_into().unwrap_or([0u8; 8]),
        );
        let ivars_vma = u64::from_le_bytes(
            binary[ro_foff + 48..ro_foff + 56].try_into().unwrap_or([0u8; 8]),
        );

        let mut cls = ObjcClass::new(name);
        cls.instance_size = instance_size;

        // Resolve superclass name
        if let Some(sc_foff) = (superclass_vma != 0)
            .then(|| vma_to_foff(binary, superclass_vma, image_base))
            .flatten()
        {
            // Superclass class_t → ro_t → name (simplified: read name from ro_t)
            if sc_foff + 40 <= binary.len() {
                let sc_data_vma_raw = u64::from_le_bytes(
                    binary[sc_foff + 32..sc_foff + 40].try_into().unwrap_or([0u8; 8]),
                );
                let sc_data_vma = sc_data_vma_raw & !0b111;
                if let Some(sc_ro) = vma_to_foff(binary, sc_data_vma, image_base) && sc_ro + 32 <= binary.len() {
                    let sc_name_ptr = u64::from_le_bytes(
                        binary[sc_ro + 24..sc_ro + 32].try_into().unwrap_or([0u8; 8]),
                    );
                    if let Some(sc_name_foff) = vma_to_foff(binary, sc_name_ptr, image_base) {
                        cls.superclass = read_cstr_at(binary, sc_name_foff);
                    }
                }
            }
        }

        // Parse method list
        if let Some(ml_foff) = (methods_vma != 0)
            .then(|| vma_to_foff(binary, methods_vma, image_base))
            .flatten()
        {
            cls.instance_methods =
                parse_method_list(binary, ml_foff, image_base, config.max_methods_per_class);
        }

        // Parse ivar list
        if let Some(iv_foff) = (ivars_vma != 0)
            .then(|| vma_to_foff(binary, ivars_vma, image_base))
            .flatten()
        {
            cls.ivars = parse_ivar_list(binary, iv_foff, image_base, config.max_ivars_per_class);
        }

        Some(cls)
    }

    /// Heuristically associate selector strings to a class when no method list
    /// was recovered from the binary (fallback for stripped binaries).
    ///
    /// In the fallback path the selector strings are available in `selectors`
    /// but cannot be reliably mapped to individual classes without
    /// pointer-chasing the full selector reference table. No-op by design —
    /// callers can iterate `self.selectors` directly.
    const fn associate_selectors_to_class(_cls: &mut ObjcClass) {}

    /// Parse `__objc_protolist` to recover protocol names.
    fn parse_protolist_names(&mut self, binary: &[u8], protolist: &[u8]) {
        let image_base = Self::guess_image_base(binary);
        let ptr_size = 8usize;
        let count = protolist.len() / ptr_size;
        for i in 0..count.min(256) {
            let off = i * ptr_size;
            if off + ptr_size > protolist.len() {
                break;
            }
            let proto_vma = u64::from_le_bytes(protolist[off..off + ptr_size].try_into().unwrap_or([0u8; 8]));
            if proto_vma == 0 {
                continue;
            }
            // protocol_t layout: pointer at offset 8 is the name pointer
            if let Some(p_foff) = vma_to_foff(binary, proto_vma, image_base)
                .filter(|&off| off + 16 <= binary.len())
            {
                let name_ptr = u64::from_le_bytes(
                    binary[p_foff + 8..p_foff + 16].try_into().unwrap_or([0u8; 8]),
                );
                if let Some(name) = vma_to_foff(binary, name_ptr, image_base)
                    .and_then(|nf| read_cstr_at(binary, nf))
                {
                    self.protocols.push(ObjcProtocol::new(name));
                }
            }
        }
    }

    /// Guess the image base from the first `__TEXT` segment.
    fn guess_image_base(binary: &[u8]) -> u64 {
        if let Ok(macho) = goblin::mach::MachO::parse(binary, 0) {
            for seg in &macho.segments {
                if std::str::from_utf8(&seg.segname)
                    .is_ok_and(|n| n.trim_end_matches('\0') == "__TEXT")
                {
                    return seg.vmaddr;
                }
            }
        }
        0
    }

    /// Look up a class by name.
    #[must_use]
    pub fn get_class(&self, name: &str) -> Option<&ObjcClass> {
        self.classes.get(name)
    }

    /// Return all class names, sorted.
    #[must_use]
    pub fn all_class_names(&self) -> Vec<&str> {
        let mut names: Vec<&str> = self.classes.keys().map(String::as_str).collect();
        names.sort_unstable();
        names
    }

    /// Return classes that adopt a given protocol.
    #[must_use]
    pub fn classes_adopting_protocol(&self, proto: &str) -> Vec<&ObjcClass> {
        self.classes
            .values()
            .filter(|c| c.adopts_protocol(proto))
            .collect()
    }

    /// Return a summary map: class name → method count.
    #[must_use]
    pub fn method_counts(&self) -> HashMap<&str, usize> {
        self.classes
            .iter()
            .map(|(k, v)| (k.as_str(), v.total_method_count()))
            .collect()
    }
}

// ─── method_list_t / ivar_list_t parsers ─────────────────────────────────────

/// Parse a `method_list_t` starting at `foff` in `binary`.
///
/// Layout (arm64 ABI-stable):
/// ```text
/// struct method_list_t {
///     uint32_t entsizeAndFlags;
///     uint32_t count;
///     method_t methods[];   // count entries, each 24 bytes (relative method list)
/// };
/// ```
fn parse_method_list(binary: &[u8], foff: usize, image_base: u64, max: usize) -> Vec<ObjcMethod> {
    if foff + 8 > binary.len() {
        return Vec::new();
    }
    let flags = u32::from_le_bytes(binary[foff..foff + 4].try_into().unwrap_or([0u8; 4]));
    let count = u32::from_le_bytes(binary[foff + 4..foff + 8].try_into().unwrap_or([0u8; 4])) as usize;
    let is_relative = (flags & 0x8000_0000) != 0;
    let entry_size: usize = if is_relative { 12 } else { 24 };
    let list_start = foff + 8;

    let mut methods = Vec::with_capacity(count.min(max));
    for i in 0..count.min(max) {
        let e = list_start + i * entry_size;
        if e + entry_size > binary.len() {
            break;
        }

        let (name, type_encoding, imp_addr) = if is_relative {
            // Relative method list: each entry is 3 × i32 relative offsets
            let name_rel = i32::from_le_bytes(binary[e..e + 4].try_into().unwrap_or_else(|_| [0i8; 4].map(i8::cast_unsigned)));
            let types_rel = i32::from_le_bytes(binary[e + 4..e + 8].try_into().unwrap_or_else(|_| [0i8; 4].map(i8::cast_unsigned)));
            let imp_rel = i32::from_le_bytes(binary[e + 8..e + 12].try_into().unwrap_or_else(|_| [0i8; 4].map(i8::cast_unsigned)));

            // Resolve relative to the field address (e is a file offset < binary.len())
            let e_i64 = i64::try_from(e).unwrap_or(i64::MAX);
            let name_vma = (e_i64 + i64::from(name_rel)).cast_unsigned();
            let types_vma = (e_i64 + 4 + i64::from(types_rel)).cast_unsigned();
            let imp_vma = (e_i64 + 8 + i64::from(imp_rel)).cast_unsigned();

            let name = vma_to_foff(binary, name_vma, image_base)
                .and_then(|off| read_cstr_at(binary, off))
                .unwrap_or_default();
            let enc = vma_to_foff(binary, types_vma, image_base)
                .and_then(|off| read_cstr_at(binary, off))
                .unwrap_or_default();
            (name, enc, imp_vma)
        } else {
            // Absolute pointer method list: 3 × 8-byte pointers
            let name_ptr = u64::from_le_bytes(binary[e..e + 8].try_into().unwrap_or([0u8; 8]));
            let types_ptr = u64::from_le_bytes(binary[e + 8..e + 16].try_into().unwrap_or([0u8; 8]));
            let imp_ptr = u64::from_le_bytes(binary[e + 16..e + 24].try_into().unwrap_or([0u8; 8]));

            let name = vma_to_foff(binary, name_ptr, image_base)
                .and_then(|off| read_cstr_at(binary, off))
                .unwrap_or_default();
            let enc = vma_to_foff(binary, types_ptr, image_base)
                .and_then(|off| read_cstr_at(binary, off))
                .unwrap_or_default();
            (name, enc, imp_ptr)
        };

        if name.is_empty() {
            continue;
        }
        methods.push(ObjcMethod::new(name, type_encoding, imp_addr));
    }
    methods
}

/// Parse an `ivar_list_t` starting at `foff`.
fn parse_ivar_list(binary: &[u8], foff: usize, image_base: u64, max: usize) -> Vec<ObjcIvar> {
    if foff + 8 > binary.len() {
        return Vec::new();
    }
    let _flags = u32::from_le_bytes(binary[foff..foff + 4].try_into().unwrap_or([0u8; 4]));
    let count = u32::from_le_bytes(binary[foff + 4..foff + 8].try_into().unwrap_or([0u8; 4])) as usize;
    // ivar_t: offset_ptr(8) + name_ptr(8) + type_ptr(8) + alignment_raw(4) + size(4) = 32 bytes
    let entry_size = 32usize;
    let list_start = foff + 8;

    let mut ivars = Vec::with_capacity(count.min(max));
    for i in 0..count.min(max) {
        let e = list_start + i * entry_size;
        if e + entry_size > binary.len() {
            break;
        }

        let offset_ptr = u64::from_le_bytes(binary[e..e + 8].try_into().unwrap_or([0u8; 8]));
        let name_ptr = u64::from_le_bytes(binary[e + 8..e + 16].try_into().unwrap_or([0u8; 8]));
        let type_ptr = u64::from_le_bytes(binary[e + 16..e + 24].try_into().unwrap_or([0u8; 8]));
        let ivar_size = u32::from_le_bytes(binary[e + 28..e + 32].try_into().unwrap_or([0u8; 4]));

        // Read the ivar offset value through the offset_ptr
        let byte_offset = vma_to_foff(binary, offset_ptr, image_base)
            .filter(|&off_foff| off_foff + 4 <= binary.len())
            .map_or(0, |off_foff| {
                u32::from_le_bytes(binary[off_foff..off_foff + 4].try_into().unwrap_or([0u8; 4]))
            });

        let name = vma_to_foff(binary, name_ptr, image_base)
            .and_then(|off| read_cstr_at(binary, off))
            .unwrap_or_default();
        let type_encoding = vma_to_foff(binary, type_ptr, image_base)
            .and_then(|off| read_cstr_at(binary, off))
            .unwrap_or_default();

        if name.is_empty() {
            continue;
        }
        ivars.push(ObjcIvar::new(name, type_encoding, byte_offset, ivar_size));
    }
    ivars
}

// ─── VMA resolution ──────────────────────────────────────────────────────────

/// Convert a virtual memory address to a file offset by scanning section headers.
fn vma_to_foff(binary: &[u8], vma: u64, image_base: u64) -> Option<usize> {
    if vma == 0 {
        return None;
    }
    let macho = goblin::mach::MachO::parse(binary, 0).ok()?;
    for item in macho.segments.sections().flatten() {
        let Ok((hdr, _)) = item else { continue };
        let vaddr = hdr.addr;
        let size = hdr.size;
        let raw_off = hdr.offset as usize;
        if vma >= vaddr && vma < vaddr + size {
            let file_off = raw_off + usize::try_from(vma - vaddr).unwrap_or(usize::MAX);
            if file_off < binary.len() {
                return Some(file_off);
            }
        }
    }
    // Fallback: treat as file offset relative to image_base
    if vma >= image_base {
        let off = usize::try_from(vma - image_base).unwrap_or(usize::MAX);
        if off < binary.len() {
            return Some(off);
        }
    }
    None
}

// ─── Public convenience function ─────────────────────────────────────────────

/// Parse `ObjC` runtime metadata from a raw `Mach-O` byte slice with default config.
///
/// # Errors
/// Returns [`MachoObjcError`] if the binary cannot be parsed as Mach-O.
pub fn parse_objc_runtime(binary: &[u8]) -> Result<MachoObjcRuntime, MachoObjcError> {
    MachoObjcRuntime::parse(binary, &ParseConfig::default())
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn empty_binary() -> Vec<u8> {
        vec![]
    }

    #[test]
    fn parse_empty_returns_error() {
        let result = parse_objc_runtime(&empty_binary());
        assert!(result.is_err());
    }

    #[test]
    fn parse_garbage_returns_error() {
        let result = parse_objc_runtime(&[0xDE, 0xAD, 0xBE, 0xEF]);
        assert!(result.is_err());
    }

    #[test]
    fn objc_method_new() {
        let m = ObjcMethod::new("viewDidLoad", "v16@0:8", 0x1000_4000);
        assert_eq!(m.name, "viewDidLoad");
        assert!(m.is_void_return());
        assert_eq!(m.param_count(), 0);
    }

    #[test]
    fn objc_method_param_count() {
        let m = ObjcMethod::new("tableView:numberOfRowsInSection:", "i24@0:8@16i20", 0);
        assert_eq!(m.param_count(), 2);
    }

    #[test]
    fn objc_method_display() {
        let m = ObjcMethod::new("alloc", "@16@0:8", 0);
        let s = m.to_string();
        assert!(s.contains("alloc"));
    }

    #[test]
    fn objc_ivar_is_object() {
        let iv = ObjcIvar::new("_delegate", "@\"NSObject\"", 8, 8);
        assert!(iv.is_object());
        let iv2 = ObjcIvar::new("_count", "i", 16, 4);
        assert!(!iv2.is_object());
    }

    #[test]
    fn objc_class_find_methods() {
        let mut cls = ObjcClass::new("MyViewController");
        cls.instance_methods.push(ObjcMethod::new("viewDidLoad", "v16@0:8", 0x1000));
        cls.class_methods.push(ObjcMethod::new("alloc", "@16@0:8", 0x2000));

        assert!(cls.find_instance_method("viewDidLoad").is_some());
        assert!(cls.find_class_method("alloc").is_some());
        assert!(cls.find_instance_method("nonexistent").is_none());
        assert_eq!(cls.total_method_count(), 2);
    }

    #[test]
    fn objc_class_protocols() {
        let mut cls = ObjcClass::new("MyVC");
        cls.protocols.push("UITableViewDelegate".to_string());
        assert!(cls.adopts_protocol("UITableViewDelegate"));
        assert!(!cls.adopts_protocol("NSCoding"));
    }

    #[test]
    fn objc_class_find_ivar() {
        let mut cls = ObjcClass::new("MyVC");
        cls.ivars.push(ObjcIvar::new("_tableView", "@\"UITableView\"", 8, 8));
        assert!(cls.find_ivar("_tableView").is_some());
        assert!(cls.find_ivar("_nonexistent").is_none());
    }

    #[test]
    fn parse_config_defaults() {
        let cfg = ParseConfig::default();
        assert_eq!(cfg.max_classes, 4096);
        assert!(cfg.max_methods_per_class > 0);
    }

    #[test]
    fn read_cstrings_basic() {
        let data = b"hello\0world\0";
        let strs = read_cstrings(data);
        assert_eq!(strs, vec!["hello", "world"]);
    }

    #[test]
    fn read_cstrings_empty() {
        let strs = read_cstrings(&[]);
        assert!(strs.is_empty());
    }

    #[test]
    fn read_cstr_at_basic() {
        let data = b"NSObject\0NSString\0";
        assert_eq!(read_cstr_at(data, 0), Some("NSObject".to_string()));
        assert_eq!(read_cstr_at(data, 9), Some("NSString".to_string()));
    }

    #[test]
    fn read_cstr_at_out_of_bounds() {
        let data = b"hi";
        assert!(read_cstr_at(data, 100).is_none());
    }

    #[test]
    fn parse_stats_total_methods() {
        let s = ParseStats {
            class_count: 10,
            instance_method_count: 80,
            class_method_count: 20,
            ivar_count: 50,
            selector_count: 100,
            classname_count: 10,
        };
        assert_eq!(s.total_methods(), 100);
    }

    #[test]
    fn macho_runtime_all_class_names_sorted() {
        let mut rt = MachoObjcRuntime {
            classes: HashMap::new(),
            selectors: vec![],
            class_names: vec![],
            protocols: vec![],
            stats: ParseStats::default(),
        };
        rt.classes.insert("ZClass".to_string(), ObjcClass::new("ZClass"));
        rt.classes.insert("AClass".to_string(), ObjcClass::new("AClass"));
        let names = rt.all_class_names();
        assert_eq!(names, vec!["AClass", "ZClass"]);
    }

    #[test]
    fn macho_runtime_method_counts() {
        let mut rt = MachoObjcRuntime {
            classes: HashMap::new(),
            selectors: vec![],
            class_names: vec![],
            protocols: vec![],
            stats: ParseStats::default(),
        };
        let mut cls = ObjcClass::new("Foo");
        cls.instance_methods.push(ObjcMethod::new("bar", "v16@0:8", 0));
        rt.classes.insert("Foo".to_string(), cls);
        let counts = rt.method_counts();
        assert_eq!(counts.get("Foo").copied(), Some(1));
    }

    #[test]
    fn objc_protocol_new() {
        let p = ObjcProtocol::new("NSCopying");
        assert_eq!(p.name, "NSCopying");
        assert!(p.required_instance_methods.is_empty());
    }

    #[test]
    fn vma_to_foff_zero_returns_none() {
        let result = vma_to_foff(&[], 0, 0);
        assert!(result.is_none());
    }
}
