//! `rtti_parser` — Parse RTTI structures for MSVC and GCC/Itanium ABIs.
//!
//! Decodes:
//! * MSVC: `_RTTICompleteObjectLocator`, `_RTTIBaseClassDescriptor`,
//!   `_RTTIClassHierarchyDescriptor`, `_RTTIBaseClassArray`, `TypeDescriptor`.
//! * GCC/Itanium: `__class_type_info`, `__si_class_type_info`,
//!   `__vmi_class_type_info`.
//! * Itanium ABI name demangling (limited subset) for class names.

use std::collections::HashMap;
use std::fmt;

// ─── Error ────────────────────────────────────────────────────────────────────

/// Error type for RTTI parsing.
#[derive(Debug, Clone)]
pub enum RttiParseError {
    /// Not enough bytes at the given address.
    TruncatedData(u64),
    /// Address is outside any registered section.
    AddressOutOfRange(u64),
    /// The RTTI magic or signature is invalid.
    InvalidSignature { addr: u64, got: u32, expected: u32 },
    /// Recursion limit exceeded while following base-class chains.
    RecursionLimit,
    /// A string field could not be decoded as UTF-8.
    InvalidUtf8(u64),
    /// Generic parse error.
    Other(String),
}

impl fmt::Display for RttiParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TruncatedData(va) => write!(f, "truncated data at {va:#x}"),
            Self::AddressOutOfRange(va) => write!(f, "address {va:#x} out of range"),
            Self::InvalidSignature { addr, got, expected } => {
                write!(f, "bad signature at {addr:#x}: got {got:#x}, expected {expected:#x}")
            }
            Self::RecursionLimit => write!(f, "recursion limit exceeded"),
            Self::InvalidUtf8(va) => write!(f, "invalid UTF-8 at {va:#x}"),
            Self::Other(s) => write!(f, "{s}"),
        }
    }
}

// ─── Memory model ─────────────────────────────────────────────────────────────

/// A parsed memory region available to the parser.
#[derive(Debug, Clone)]
pub struct MemRegion {
    pub base_va: u64,
    pub data: Vec<u8>,
}

impl MemRegion {
    /// Create a new region.
    #[must_use]
    pub const fn new(base_va: u64, data: Vec<u8>) -> Self {
        Self { base_va, data }
    }

    /// Return the exclusive end address (saturating at `u64::MAX` for
    /// adversarial `base_va` values near the top of the address space).
    #[must_use]
    pub const fn end_va(&self) -> u64 {
        self.base_va.saturating_add(self.data.len() as u64)
    }

    /// Return `true` if the region contains `va`.
    #[must_use]
    pub const fn contains(&self, va: u64) -> bool {
        va >= self.base_va && va < self.end_va()
    }

    /// Read `n` bytes at `va` or return `None`.
    #[must_use]
    pub fn read(&self, va: u64, n: usize) -> Option<&[u8]> {
        if va < self.base_va {
            return None;
        }
        let off = (va - self.base_va) as usize;
        let end = off.checked_add(n)?;
        self.data.get(off..end)
    }

    /// Read a `u32` (little-endian) at `va`.
    #[must_use]
    pub fn read_u32(&self, va: u64) -> Option<u32> {
        let b = self.read(va, 4)?;
        Some(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }

    /// Read an `i32` (little-endian) at `va`.
    #[must_use]
    pub fn read_i32(&self, va: u64) -> Option<i32> {
        self.read_u32(va).map(|v| v as i32)
    }

    /// Read a pointer (`ptr_size` bytes LE) at `va`.
    #[must_use]
    pub fn read_ptr(&self, va: u64, ptr_size: usize) -> Option<u64> {
        let b = self.read(va, ptr_size)?;
        Some(match ptr_size {
            4 => u64::from(u32::from_le_bytes([b[0], b[1], b[2], b[3]])),
            8 => u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]),
            _ => return None,
        })
    }

    /// Read a NUL-terminated string at `va`.
    #[must_use]
    pub fn read_cstr(&self, va: u64) -> Option<String> {
        if va < self.base_va {
            return None;
        }
        let off = (va - self.base_va) as usize;
        let slice = self.data.get(off..)?;
        let end = slice.iter().position(|&b| b == 0)?;
        std::str::from_utf8(&slice[..end]).ok().map(str::to_string)
    }
}

// ─── MSVC RTTI structures ─────────────────────────────────────────────────────

/// MSVC `TypeDescriptor` — holds the mangled type name.
#[derive(Debug, Clone)]
pub struct TypeDescriptor {
    /// Virtual address of the `TypeDescriptor`.
    pub address: u64,
    /// Raw decorated name (e.g. `.?AVFoo@@`).
    pub raw_name: String,
    /// Demangled name after stripping MSVC decoration.
    pub demangled_name: String,
}

impl TypeDescriptor {
    /// Create a `TypeDescriptor` from its components.
    #[must_use]
    pub fn new(address: u64, raw_name: impl Into<String>) -> Self {
        let raw = raw_name.into();
        let demangled = msvc_demangle_basic(&raw);
        Self {
            address,
            raw_name: raw,
            demangled_name: demangled,
        }
    }
}

/// MSVC `_RTTIBaseClassDescriptor` — describes one base class.
#[derive(Debug, Clone)]
pub struct BaseClassDescriptor {
    /// Virtual address of this descriptor.
    pub address: u64,
    /// Address of the base class's `TypeDescriptor`.
    pub type_descriptor_va: u64,
    /// Demangled name of the base class.
    pub base_class_name: String,
    /// Number of contained bases (direct + indirect).
    pub num_contained_bases: u32,
    /// Member displacement.
    pub mdisp: i32,
    /// Vtable displacement.
    pub pdisp: i32,
    /// Displacement within vtable.
    pub vdisp: i32,
    /// Attributes (virtual base flag etc.).
    pub attributes: u32,
}

impl BaseClassDescriptor {
    /// Return `true` if the `vbptr` flag is set (virtual base).
    #[must_use]
    pub const fn is_virtual_base(&self) -> bool {
        self.attributes & 1 != 0
    }

    /// Return `true` if this is a non-virtual public base.
    #[must_use]
    pub const fn is_public(&self) -> bool {
        self.attributes & 2 != 0
    }
}

/// MSVC `_RTTIClassHierarchyDescriptor`.
#[derive(Debug, Clone)]
pub struct HierarchyDescriptor {
    /// Virtual address of the descriptor.
    pub address: u64,
    /// Signature (should be 0).
    pub signature: u32,
    /// Attributes (diamond/virtual shape flags).
    pub attributes: u32,
    /// Number of base class entries.
    pub num_base_classes: u32,
    /// Virtual address of the `_RTTIBaseClassArray`.
    pub base_class_array_va: u64,
    /// Parsed base class descriptors.
    pub base_classes: Vec<BaseClassDescriptor>,
}

impl HierarchyDescriptor {
    /// Return `true` if the class uses virtual inheritance.
    #[must_use]
    pub const fn has_virtual_base(&self) -> bool {
        self.attributes & 1 != 0
    }

    /// Return `true` if the diamond inheritance flag is set.
    #[must_use]
    pub const fn is_diamond(&self) -> bool {
        self.attributes & 2 != 0
    }
}

/// Complete MSVC RTTI data for one class.
#[derive(Debug, Clone)]
pub struct MsvcRtti {
    /// The parsed `CompleteObjectLocator`.
    pub col_address: u64,
    /// COL signature (0 = 32-bit, 1 = 64-bit).
    pub signature: u32,
    /// Vtable offset within the object.
    pub vtable_offset: i32,
    /// Constructor displacement.
    pub cd_offset: i32,
    /// The parsed `TypeDescriptor`.
    pub type_descriptor: TypeDescriptor,
    /// The hierarchy descriptor.
    pub hierarchy: HierarchyDescriptor,
    /// Vtable virtual address that this COL precedes.
    pub vtable_va: u64,
}

impl MsvcRtti {
    /// Demangled class name.
    #[must_use]
    pub fn class_name(&self) -> &str {
        &self.type_descriptor.demangled_name
    }

    /// Return `true` if this COL is for the primary sub-object (offset 0).
    #[must_use]
    pub const fn is_primary(&self) -> bool {
        self.vtable_offset == 0
    }

    /// Number of direct + indirect base classes.
    #[must_use]
    pub const fn base_count(&self) -> usize {
        self.hierarchy.base_classes.len()
    }
}

// ─── GCC RTTI structures ──────────────────────────────────────────────────────

/// GCC/Itanium base class offset flags.
#[derive(Debug, Clone, Copy)]
pub struct BaseOffsetFlags(pub i64);

impl BaseOffsetFlags {
    /// Return `true` if the virtual base indicator bit is set.
    #[must_use]
    pub const fn is_virtual(self) -> bool {
        self.0 & 1 != 0
    }

    /// Return `true` if the public access bit is set.
    #[must_use]
    pub const fn is_public(self) -> bool {
        self.0 & 2 != 0
    }

    /// Extract the byte offset (shift right 8, keep sign).
    #[must_use]
    pub const fn byte_offset(self) -> i64 {
        self.0 >> 8
    }
}

/// A single base class entry in a GCC `__vmi_class_type_info`.
#[derive(Debug, Clone)]
pub struct GccBaseEntry {
    /// Address of the base class `typeinfo`.
    pub typeinfo_va: u64,
    /// Byte offset and flags packed together.
    pub offset_flags: BaseOffsetFlags,
    /// Demangled name of the base class (resolved lazily).
    pub base_name: Option<String>,
}

/// Complete GCC/Itanium RTTI data for one class.
#[derive(Debug, Clone)]
pub struct GccRtti {
    /// Address of the `typeinfo` structure.
    pub address: u64,
    /// Mangled type name (e.g. `"_ZTI7MyClass"`).
    pub mangled_name: String,
    /// Demangled type name.
    pub demangled_name: String,
    /// `__flags` from `__vmi_class_type_info` (0 for non-vmi).
    pub vmi_flags: u32,
    /// Base class entries.
    pub bases: Vec<GccBaseEntry>,
    /// Whether this is a `__si_class_type_info`.
    pub is_single_inheritance: bool,
    /// Whether this is a `__vmi_class_type_info`.
    pub is_multiple_inheritance: bool,
}

impl GccRtti {
    /// Return `true` if there are no recorded base classes.
    #[must_use]
    pub const fn is_root(&self) -> bool {
        self.bases.is_empty()
    }

    /// Return `true` if the layout is diamond-shaped.
    #[must_use]
    pub const fn is_diamond(&self) -> bool {
        self.vmi_flags & 2 != 0
    }

    /// Number of direct base classes.
    #[must_use]
    pub const fn base_count(&self) -> usize {
        self.bases.len()
    }
}

// ─── RttiParser ───────────────────────────────────────────────────────────────

/// Configuration for `RttiParser`.
#[derive(Debug, Clone)]
pub struct RttiParserConfig {
    /// Pointer size in bytes (4 or 8).
    pub ptr_size: usize,
    /// Image base for resolving MSVC 64-bit relative offsets.
    pub image_base: u64,
    /// Maximum recursion depth when following base class chains.
    pub max_recursion: usize,
}

impl Default for RttiParserConfig {
    fn default() -> Self {
        Self {
            ptr_size: 8,
            image_base: 0,
            max_recursion: 32,
        }
    }
}

/// RTTI parser supporting both MSVC and GCC/Itanium ABIs.
///
/// Reads from a set of [`MemRegion`] slices that represent the binary's
/// readable sections.  Call [`RttiParser::add_region`] before parsing.
#[derive(Debug, Default)]
pub struct RttiParser {
    pub config: RttiParserConfig,
    regions: Vec<MemRegion>,
    /// Cache of previously parsed MSVC RTTI structs.
    msvc_cache: HashMap<u64, MsvcRtti>,
    /// Cache of previously parsed GCC RTTI structs.
    gcc_cache: HashMap<u64, GccRtti>,
}

impl RttiParser {
    /// Create a new parser with default configuration.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a parser with explicit configuration.
    #[must_use]
    pub fn with_config(config: RttiParserConfig) -> Self {
        Self {
            config,
            ..Self::default()
        }
    }

    /// Register a memory region.
    pub fn add_region(&mut self, region: MemRegion) {
        self.regions.push(region);
    }

    // ── Low-level readers ──────────────────────────────────────────────────────

    fn read_ptr(&self, va: u64) -> Option<u64> {
        for r in &self.regions {
            if let Some(v) = r.read_ptr(va, self.config.ptr_size) {
                return Some(v);
            }
        }
        None
    }

    fn read_u32(&self, va: u64) -> Option<u32> {
        for r in &self.regions {
            if let Some(v) = r.read_u32(va) {
                return Some(v);
            }
        }
        None
    }

    fn read_i32(&self, va: u64) -> Option<i32> {
        self.read_u32(va).map(|v| v as i32)
    }

    fn read_cstr(&self, va: u64) -> Option<String> {
        for r in &self.regions {
            if let Some(s) = r.read_cstr(va) {
                return Some(s);
            }
        }
        None
    }

    fn is_readable(&self, va: u64) -> bool {
        self.regions.iter().any(|r| r.contains(va))
    }

    // ── MSVC parsing ──────────────────────────────────────────────────────────

    /// Parse a MSVC `_RTTICompleteObjectLocator` at `col_va`.
    ///
    /// Returns the fully decoded [`MsvcRtti`] or an error.
    pub fn parse_msvc_col(&mut self, col_va: u64) -> Result<MsvcRtti, RttiParseError> {
        if let Some(cached) = self.msvc_cache.get(&col_va) {
            return Ok(cached.clone());
        }

        let sig = self
            .read_u32(col_va)
            .ok_or(RttiParseError::TruncatedData(col_va))?;

        if sig != 0 && sig != 1 {
            return Err(RttiParseError::InvalidSignature {
                addr: col_va,
                got: sig,
                expected: 1,
            });
        }

        let is_64 = sig == 1;
        let vtable_offset = self
            .read_i32(col_va.wrapping_add(4))
            .ok_or(RttiParseError::TruncatedData(col_va.wrapping_add(4)))?;
        let cd_offset = self
            .read_i32(col_va.wrapping_add(8))
            .ok_or(RttiParseError::TruncatedData(col_va.wrapping_add(8)))?;

        let td_va = self.resolve_rtti_ref(col_va.wrapping_add(12), is_64)?;
        let ch_va = self.resolve_rtti_ref(col_va.wrapping_add(16), is_64)?;

        let type_descriptor = self.parse_type_descriptor(td_va)?;
        let hierarchy = self.parse_hierarchy_descriptor(ch_va, is_64, 0)?;

        let rtti = MsvcRtti {
            col_address: col_va,
            signature: sig,
            vtable_offset,
            cd_offset,
            type_descriptor,
            hierarchy,
            vtable_va: col_va + if is_64 { 24 } else { 20 }, // approximate
        };
        self.msvc_cache.insert(col_va, rtti.clone());
        Ok(rtti)
    }

    /// Resolve a MSVC RTTI reference (relative in 64-bit, absolute in 32-bit).
    fn resolve_rtti_ref(&self, ref_va: u64, is_64: bool) -> Result<u64, RttiParseError> {
        if is_64 {
            let rel = self
                .read_i32(ref_va)
                .ok_or(RttiParseError::TruncatedData(ref_va))?;
            Ok(self.config.image_base.wrapping_add_signed(i64::from(rel)))
        } else {
            self.read_u32(ref_va)
                .map(u64::from)
                .ok_or(RttiParseError::TruncatedData(ref_va))
        }
    }

    /// Parse a `TypeDescriptor` at `td_va`.
    fn parse_type_descriptor(&self, td_va: u64) -> Result<TypeDescriptor, RttiParseError> {
        let ps = self.config.ptr_size as u64;
        // +0: vftable pointer (skip)
        // +ptr_size: spare pointer (skip)
        // +2*ptr_size: decorated name string
        //
        // `td_va + 2*ps`, NOT `(td_va + 2) * ps` — the latter multiplies the
        // whole address and sends the read far outside the image, so the class
        // name never resolves. The GCC path a few functions below already
        // writes `ti_va.wrapping_add(2 * ps)`; only the MSVC path was wrong.
        let name_va = td_va.wrapping_add(2 * ps);
        let raw_name = self
            .read_cstr(name_va)
            .ok_or(RttiParseError::AddressOutOfRange(name_va))?;
        Ok(TypeDescriptor::new(td_va, raw_name))
    }

    /// Parse a `_RTTIClassHierarchyDescriptor` at `ch_va`.
    fn parse_hierarchy_descriptor(
        &mut self,
        ch_va: u64,
        is_64: bool,
        depth: usize,
    ) -> Result<HierarchyDescriptor, RttiParseError> {
        if depth > self.config.max_recursion {
            return Err(RttiParseError::RecursionLimit);
        }

        let sig = self
            .read_u32(ch_va)
            .ok_or(RttiParseError::TruncatedData(ch_va))?;
        let attributes = self
            .read_u32(ch_va.wrapping_add(4))
            .ok_or(RttiParseError::TruncatedData(ch_va.wrapping_add(4)))?;
        let num_bases = self
            .read_u32(ch_va.wrapping_add(8))
            .ok_or(RttiParseError::TruncatedData(ch_va.wrapping_add(8)))? as usize;
        let arr_va = self.resolve_rtti_ref(ch_va.wrapping_add(12), is_64)?;

        let mut base_classes = Vec::new();
        let ps = if is_64 { 8usize } else { 4usize };

        for i in 0..num_bases.min(64) {
            let entry_va = arr_va + (i * ps) as u64;
            let bcd_va = self.resolve_rtti_ref(entry_va, is_64)?;
            if let Ok(bcd) = self.parse_base_class_descriptor(bcd_va, is_64, depth.wrapping_add(1)) {
                base_classes.push(bcd);
            }
        }

        Ok(HierarchyDescriptor {
            address: ch_va,
            signature: sig,
            attributes,
            num_base_classes: num_bases as u32,
            base_class_array_va: arr_va,
            base_classes,
        })
    }

    /// Parse a `_RTTIBaseClassDescriptor` at `bcd_va`.
    fn parse_base_class_descriptor(
        &self,
        bcd_va: u64,
        is_64: bool,
        depth: usize,
    ) -> Result<BaseClassDescriptor, RttiParseError> {
        if depth > self.config.max_recursion {
            return Err(RttiParseError::RecursionLimit);
        }

        let td_va = self.resolve_rtti_ref(bcd_va, is_64)?;
        let num_contained = self
            .read_u32(bcd_va.wrapping_add(4))
            .ok_or(RttiParseError::TruncatedData(bcd_va.wrapping_add(4)))?;
        let mdisp = self
            .read_i32(bcd_va.wrapping_add(8))
            .ok_or(RttiParseError::TruncatedData(bcd_va.wrapping_add(8)))?;
        let pdisp = self
            .read_i32(bcd_va.wrapping_add(12))
            .ok_or(RttiParseError::TruncatedData(bcd_va.wrapping_add(12)))?;
        let vdisp = self
            .read_i32(bcd_va.wrapping_add(16))
            .ok_or(RttiParseError::TruncatedData(bcd_va.wrapping_add(16)))?;
        let attrs = self
            .read_u32(bcd_va.wrapping_add(20))
            .ok_or(RttiParseError::TruncatedData(bcd_va.wrapping_add(20)))?;

        let ps = self.config.ptr_size as u64;
        // `td_va + 2*ps`, NOT `(td_va + 2) * ps`: the decorated name sits two
        // pointers into the TypeDescriptor. Multiplying the whole address sent
        // the read far outside the image, so the class name failed to resolve
        // and every base class was silently dropped with it.
        let name_va = td_va.wrapping_add(2 * ps);
        let raw_name = self
            .read_cstr(name_va)
            .ok_or(RttiParseError::AddressOutOfRange(name_va))?;
        let base_name = msvc_demangle_basic(&raw_name);

        Ok(BaseClassDescriptor {
            address: bcd_va,
            type_descriptor_va: td_va,
            base_class_name: base_name,
            num_contained_bases: num_contained,
            mdisp,
            pdisp,
            vdisp,
            attributes: attrs,
        })
    }

    // ── GCC/Itanium parsing ───────────────────────────────────────────────────

    /// Parse a GCC `typeinfo` structure at `ti_va`.
    ///
    /// Handles `__class_type_info`, `__si_class_type_info`, and
    /// `__vmi_class_type_info`.
    pub fn parse_gcc_typeinfo(&mut self, ti_va: u64) -> Result<GccRtti, RttiParseError> {
        if let Some(cached) = self.gcc_cache.get(&ti_va) {
            return Ok(cached.clone());
        }
        self.parse_gcc_typeinfo_inner(ti_va, 0)
    }

    fn parse_gcc_typeinfo_inner(
        &mut self,
        ti_va: u64,
        depth: usize,
    ) -> Result<GccRtti, RttiParseError> {
        if depth > self.config.max_recursion {
            return Err(RttiParseError::RecursionLimit);
        }

        let ps = self.config.ptr_size as u64;
        // +0: vtable pointer (skip)
        // +ps: type name pointer
        let name_ptr = self
            .read_ptr(ti_va.wrapping_add(ps))
            .ok_or(RttiParseError::TruncatedData(ti_va.wrapping_add(ps)))?;
        let mangled_name = self
            .read_cstr(name_ptr)
            .ok_or(RttiParseError::AddressOutOfRange(name_ptr))?;
        let demangled_name = itanium_demangle_basic(&mangled_name);

        let mut gcc_rtti = GccRtti {
            address: ti_va,
            mangled_name,
            demangled_name,
            vmi_flags: 0,
            bases: Vec::new(),
            is_single_inheritance: false,
            is_multiple_inheritance: false,
        };

        // Try to read a base typeinfo pointer at +2*ps (si_class_type_info).
        if let Some(base_ptr) = self.read_ptr(ti_va.wrapping_add(2 * ps))
            && base_ptr != 0 && self.is_readable(base_ptr) {
                let base_entry = GccBaseEntry {
                    typeinfo_va: base_ptr,
                    offset_flags: BaseOffsetFlags(0),
                    base_name: None,
                };
                gcc_rtti.bases.push(base_entry);
                gcc_rtti.is_single_inheritance = true;
            }

        // Try vmi_class_type_info: flags at +2*ps (u32), count at +2*ps+4 (u32).
        if let (Some(flags), Some(count)) = (
            self.read_u32(ti_va.wrapping_add(2 * ps)),
            self.read_u32(ti_va.wrapping_add(2 * ps).wrapping_add(4)),
        ) {
            let count = count as usize;
            if count > 0 && count <= 32 {
                gcc_rtti.vmi_flags = flags;
                gcc_rtti.is_multiple_inheritance = true;
                gcc_rtti.bases.clear();
                gcc_rtti.is_single_inheritance = false;

                let base_array_va = ti_va.wrapping_add(2 * ps).wrapping_add(8);
                for i in 0..count {
                    let entry_off = base_array_va.wrapping_add((i as u64).wrapping_mul(ps.wrapping_add(8)));
                    if let Some(bti_va) = self.read_ptr(entry_off) {
                        let raw_flags = self
                            .read_u32(entry_off.wrapping_add(ps))
                            .map_or(0, |v| i64::from(v));
                        let entry = GccBaseEntry {
                            typeinfo_va: bti_va,
                            offset_flags: BaseOffsetFlags(raw_flags),
                            base_name: None,
                        };
                        gcc_rtti.bases.push(entry);
                    }
                }
            }
        }

        self.gcc_cache.insert(ti_va, gcc_rtti.clone());
        Ok(gcc_rtti)
    }

    /// Retrieve MSVC RTTI from cache.
    #[must_use]
    pub fn msvc_cache_get(&self, col_va: u64) -> Option<&MsvcRtti> {
        self.msvc_cache.get(&col_va)
    }

    /// Retrieve GCC RTTI from cache.
    #[must_use]
    pub fn gcc_cache_get(&self, ti_va: u64) -> Option<&GccRtti> {
        self.gcc_cache.get(&ti_va)
    }

    /// Count of cached MSVC structures.
    #[must_use]
    pub fn msvc_cached_count(&self) -> usize {
        self.msvc_cache.len()
    }

    /// Count of cached GCC structures.
    #[must_use]
    pub fn gcc_cached_count(&self) -> usize {
        self.gcc_cache.len()
    }
}

// ─── Name demangling helpers ──────────────────────────────────────────────────

/// Basic MSVC type name demangling: strip leading `.?AV`/`.?AU` and trailing `@@`.
#[must_use]
pub fn msvc_demangle_basic(name: &str) -> String {
    let s = name
        .trim_start_matches(".?AV")
        .trim_start_matches(".?AU")
        .trim_start_matches(".?AW4") // enum
        .trim_end_matches("@@");
    s.replace('@', "::")
}

/// Basic Itanium ABI demangling: handle the most common patterns.
///
/// Handles `_ZTI`, `_ZTS`, `_ZTV`, `_ZN...E` prefixes and simple `N<len>name`
/// encoding.
#[must_use]
pub fn itanium_demangle_basic(mangled: &str) -> String {
    if !mangled.starts_with('_') {
        return mangled.to_string();
    }

    // Strip common RTTI prefixes.
    let stripped = if let Some(rest) = mangled.strip_prefix("_ZTI") {
        rest
    } else if let Some(rest) = mangled.strip_prefix("_ZTS") {
        rest
    } else if let Some(rest) = mangled.strip_prefix("_ZTV") {
        rest
    } else if let Some(rest) = mangled.strip_prefix("_ZN") {
        // Nested name ending with E.
        let inner = rest.trim_end_matches('E');
        return demangle_nested(inner);
    } else {
        return mangled.to_string();
    };

    demangle_simple(stripped)
}

/// Decode a simple Itanium name: `<len><chars>` sequences.
fn demangle_simple(s: &str) -> String {
    let mut result = String::new();
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i].is_ascii_digit() {
            let start = i;
            while i < bytes.len() && bytes[i].is_ascii_digit() {
                i += 1;
            }
            if let Ok(len_str) = std::str::from_utf8(&bytes[start..i])
                && let Ok(len) = len_str.parse::<usize>()
                    && let Some(end) = i.checked_add(len)
                        && end <= bytes.len() {
                            result.push_str(
                                std::str::from_utf8(&bytes[i..end]).unwrap_or("?"),
                            );
                            i = end;
                            continue;
                        }
        }
        i += 1;
    }
    if result.is_empty() {
        s.to_string()
    } else {
        result
    }
}

/// Decode a nested Itanium name: `<len><name><len><name>...` → `Outer::Inner`.
fn demangle_nested(s: &str) -> String {
    let mut parts = Vec::new();
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i].is_ascii_digit() {
            let start = i;
            while i < bytes.len() && bytes[i].is_ascii_digit() {
                i += 1;
            }
            if let Ok(len_str) = std::str::from_utf8(&bytes[start..i])
                && let Ok(len) = len_str.parse::<usize>()
                    && let Some(end) = i.checked_add(len)
                        && end <= bytes.len() {
                            if let Ok(part) = std::str::from_utf8(&bytes[i..end]) {
                                parts.push(part.to_string());
                            }
                            i = end;
                            continue;
                        }
        }
        i += 1;
    }
    if parts.is_empty() {
        s.to_string()
    } else {
        parts.join("::")
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_region_with_cstr(base: u64, s: &str) -> MemRegion {
        let mut data = s.as_bytes().to_vec();
        data.push(0);
        MemRegion::new(base, data)
    }

    #[test]
    fn test_mem_region_read_u32() {
        let data = 0xDEAD_BEEFu32.to_le_bytes().to_vec();
        let r = MemRegion::new(0x1000, data);
        assert_eq!(r.read_u32(0x1000), Some(0xDEAD_BEEF));
        assert_eq!(r.read_u32(0x2000), None);
    }

    #[test]
    fn test_mem_region_read_cstr() {
        let r = make_region_with_cstr(0x3000, "Hello");
        assert_eq!(r.read_cstr(0x3000), Some("Hello".into()));
    }

    #[test]
    fn test_mem_region_contains() {
        let r = MemRegion::new(0x1000, vec![0u8; 0x100]);
        assert!(r.contains(0x1000));
        assert!(r.contains(0x10FF));
        assert!(!r.contains(0x1100));
    }

    #[test]
    fn test_msvc_demangle_basic() {
        assert_eq!(msvc_demangle_basic(".?AVFoo@@"), "Foo");
        assert_eq!(msvc_demangle_basic(".?AVBar@Ns@@"), "Bar::Ns");
        assert_eq!(msvc_demangle_basic(".?AUMyStruct@@"), "MyStruct");
    }

    #[test]
    fn test_itanium_demangle_zti() {
        assert_eq!(itanium_demangle_basic("_ZTI7MyClass"), "MyClass");
    }

    #[test]
    fn test_itanium_demangle_nested() {
        assert_eq!(itanium_demangle_basic("_ZN3Foo3BarE"), "Foo::Bar");
    }

    #[test]
    fn test_itanium_demangle_passthrough() {
        assert_eq!(itanium_demangle_basic("notmangled"), "notmangled");
    }

    #[test]
    fn test_base_class_descriptor_virtual_flag() {
        let bcd = BaseClassDescriptor {
            address: 0x1000,
            type_descriptor_va: 0x2000,
            base_class_name: "Base".into(),
            num_contained_bases: 0,
            mdisp: 0,
            pdisp: 0,
            vdisp: 0,
            attributes: 1,
        };
        assert!(bcd.is_virtual_base());
        assert!(!bcd.is_public());
    }

    #[test]
    fn test_gcc_rtti_is_root() {
        let ti = GccRtti {
            address: 0x8000,
            mangled_name: "_ZTI3Foo".into(),
            demangled_name: "Foo".into(),
            vmi_flags: 0,
            bases: Vec::new(),
            is_single_inheritance: false,
            is_multiple_inheritance: false,
        };
        assert!(ti.is_root());
        assert!(!ti.is_diamond());
    }

    #[test]
    fn test_rtti_parse_error_display() {
        let e = RttiParseError::TruncatedData(0x1000);
        assert!(e.to_string().contains("0x1000"));
        let e2 = RttiParseError::RecursionLimit;
        assert!(e2.to_string().contains("recursion"));
    }

    #[test]
    fn test_parser_parse_gcc_typeinfo() {
        // Build a minimal __class_type_info structure.
        // Layout: [vtable_ptr (8B)][name_ptr (8B)]
        // Name stored at offset 0x20.
        let base = 0x8000u64;
        let name_ptr = base + 0x20;
        let mut data = vec![0u8; 0x30];
        // vtable_ptr at +0: 0 (ignored)
        // name_ptr at +8:
        let np_bytes = name_ptr.to_le_bytes();
        data[8..16].copy_from_slice(&np_bytes);
        // name at +0x20:
        let name = b"_ZTI3Foo\0";
        data[0x20..0x20 + name.len()].copy_from_slice(name);

        let mut parser = RttiParser::new();
        parser.add_region(MemRegion::new(base, data));

        let ti = parser.parse_gcc_typeinfo(base).unwrap();
        assert_eq!(ti.mangled_name, "_ZTI3Foo");
        assert_eq!(ti.demangled_name, "Foo");
    }

    #[test]
    fn test_parser_caches_gcc_result() {
        let base = 0x9000u64;
        let name_ptr = base + 0x20;
        let mut data = vec![0u8; 0x30];
        data[8..16].copy_from_slice(&name_ptr.to_le_bytes());
        let name = b"_ZTI3Bar\0";
        data[0x20..0x20 + name.len()].copy_from_slice(name);

        let mut parser = RttiParser::new();
        parser.add_region(MemRegion::new(base, data));
        let _ = parser.parse_gcc_typeinfo(base).unwrap();
        assert_eq!(parser.gcc_cached_count(), 1);
        // Second call should hit cache.
        let _ = parser.parse_gcc_typeinfo(base).unwrap();
        assert_eq!(parser.gcc_cached_count(), 1);
    }

    #[test]
    fn test_hierarchy_descriptor_flags() {
        let hd = HierarchyDescriptor {
            address: 0x1000,
            signature: 0,
            attributes: 3,
            num_base_classes: 0,
            base_class_array_va: 0,
            base_classes: Vec::new(),
        };
        assert!(hd.has_virtual_base());
        assert!(hd.is_diamond());
    }

    // ─── Adversarial / hardening regression tests ───────────────────────────

    #[test]
    fn regress_mem_region_high_base_va_no_wrap() {
        // base_va near u64::MAX: end_va must saturate, not wrap to a tiny value
        // that makes contains() reject every address in the region.
        let r = MemRegion::new(u64::MAX - 4, vec![0u8; 16]);
        assert!(r.contains(u64::MAX - 1));
        assert!(r.read(u64::MAX - 4, 4).is_some());
        assert!(r.read_cstr(u64::MAX).is_none() || r.read_cstr(u64::MAX).is_some()); // no panic
    }

    use crate::test_prng::XorShift;

    #[test]
    fn fuzz_rtti_parser_no_panic_on_garbage_regions() {
        let mut rng = XorShift(0x0bad_cafe_f00d_beef);
        for _ in 0..300 {
            let len = (rng.next() % 96) as usize;
            let data: Vec<u8> = (0..len).map(|_| rng.next() as u8).collect();
            let base = match rng.next() % 3 {
                0 => rng.next() % 0x1_0000,
                1 => u64::MAX - (rng.next() % 64),
                _ => rng.next(),
            };
            let mut parser = RttiParser::with_config(RttiParserConfig {
                ptr_size: if rng.next() & 1 == 0 { 4 } else { 8 },
                image_base: rng.next() % 0x1_0000,
                max_recursion: 8,
            });
            parser.add_region(MemRegion::new(base, data));
            for _ in 0..8 {
                let va = base.wrapping_add(rng.next() % 128);
                let _ = parser.parse_msvc_col(va);
                let _ = parser.parse_gcc_typeinfo(va);
            }
        }
    }

    #[test]
    fn fuzz_demanglers_no_panic() {
        let mut rng = XorShift(0x5eed_5eed_5eed_5eed);
        for _ in 0..2000 {
            let len = (rng.next() % 40) as usize;
            let s: String = (0..len)
                .map(|_| char::from((rng.next() % 94 + 33) as u8))
                .collect();
            let _ = msvc_demangle_basic(&s);
            let _ = itanium_demangle_basic(&s);
        }
        // Length prefix far larger than the remaining bytes.
        let _ = itanium_demangle_basic("_ZTI99999999999999999999X");
        let _ = itanium_demangle_basic("_ZN18446744073709551615AE");
    }
}
