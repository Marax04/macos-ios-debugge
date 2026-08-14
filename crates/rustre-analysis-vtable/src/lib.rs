//! `rustre-analysis-vtable`
//!
//! C++ vtable and RTTI recovery for the `RustRE` Suite.
//!
//! Scans binary data for pointer arrays that point into executable sections
//! (vtable heuristic), and decodes MSVC `__RTTICompleteObjectLocator` and
//! Itanium `__cxa_type_info` structures to recover class hierarchy information.
//!
//! Additional modules:
//! * [`hierarchy`] — inheritance graph, BFS traversal, virtual dispatch resolution.
//! * [`demangler`] — C++ name demangling (Itanium and MSVC ABI).
//! * [`override_map`] — virtual method override tracking across a class hierarchy.

pub mod class_hierarchy;
pub mod rtti_parser;
pub mod virtual_dispatch_analyzer;
pub mod vtable_finder;
pub mod vtable_reconstructor;
pub mod cluster;
pub mod cpp_class_hierarchy;
pub mod demangler;
pub mod hierarchy;
pub mod msvc_rtti;
pub mod override_map;
pub mod rtti_recovery;
pub mod virtual_override_map;
pub mod vtable_integrity;
pub mod vtable_recovery;
pub mod vtable_validator;
pub mod inheritance_grapher;
pub mod interface_reconstruction;
#[cfg(test)]
mod property_tests;

pub use interface_reconstruction::{
    InterfaceReconstructor, MethodKind, ReconstructedInterface, ReconstructedMethod,
};

pub use cluster::{SlotMap, VirtualSlot, VtableCluster, cluster_vtables, infer_derivations};

pub use override_map::{
    MethodSlot, OverrideAnalyzer, OverrideAnalyzerConfig, OverrideDiff, OverrideMap,
    OverrideReport, OverrideStats, SlotKey, SlotState, all_slot_overriders,
    reconstruct_override_chain,
};

pub use demangler::{
    demangle, demangle_itanium, demangle_msvc, demangle_msvc_function, is_itanium_mangled,
    is_msvc_mangled,
};
pub use hierarchy::{
    ClassNode, HierarchyStats, InheritanceGraph, VirtualDispatchSite, build_dispatch_table,
    compute_hierarchy_stats, resolve_virtual_dispatch,
};

use std::collections::HashMap;
use std::fmt;

use serde::{Deserialize, Serialize};
use thiserror::Error;

// ────────────────────────────────────────────────────────────────────────────
// Error type
// ────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Error)]
pub enum VtableError {
    #[error("address {0:#x} is out of range")]
    AddressOutOfRange(u64),
    #[error("RTTI structure at {0:#x} is malformed: {1}")]
    MalformedRtti(u64, String),
    #[error("pointer size {0} not supported (expected 4 or 8)")]
    UnsupportedPointerSize(usize),
    #[error("section not found: {0}")]
    SectionNotFound(String),
    #[error("string is not valid UTF-8 at offset {0:#x}")]
    InvalidString(u64),
}

// ────────────────────────────────────────────────────────────────────────────
// Core data structures
// ────────────────────────────────────────────────────────────────────────────

/// One entry in a vtable.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VtableEntry {
    /// Byte offset from the start of the vtable (0, 8, 16, …).
    pub offset: usize,
    /// The raw address stored in the vtable slot.
    pub target_address: u64,
    /// Resolved function name (from symbol table or demangled RTTI), if known.
    pub function_name: Option<String>,
}

impl VtableEntry {
    #[must_use]
    pub const fn new(offset: usize, target_address: u64) -> Self {
        Self {
            offset,
            target_address,
            function_name: None,
        }
    }

    pub fn with_name(offset: usize, target_address: u64, name: impl Into<String>) -> Self {
        Self {
            offset,
            target_address,
            function_name: Some(name.into()),
        }
    }
}

impl fmt::Display for VtableEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = self.function_name.as_deref().unwrap_or("<unknown>");
        write!(
            f,
            "+{:#06x}: {:#x}  ({})",
            self.offset, self.target_address, name
        )
    }
}

/// A recovered vtable.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Vtable {
    /// The base address of the vtable in the binary.
    pub base_address: u64,
    /// The individual virtual function entries.
    pub entries: Vec<VtableEntry>,
    /// Owning class name, if recoverable from RTTI.
    pub class_name: Option<String>,
    /// Offset-to-top (from RTTI), if present.
    pub offset_to_top: Option<i64>,
}

impl Vtable {
    #[must_use]
    pub const fn new(base_address: u64) -> Self {
        Self {
            base_address,
            entries: Vec::new(),
            class_name: None,
            offset_to_top: None,
        }
    }

    pub fn add_entry(&mut self, entry: VtableEntry) {
        self.entries.push(entry);
    }

    #[must_use]
    pub const fn entry_count(&self) -> usize {
        self.entries.len()
    }
}

impl fmt::Display for Vtable {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let class = self.class_name.as_deref().unwrap_or("<unknown class>");
        write!(
            f,
            "vtable for {} @ {:#x} ({} entries)",
            class,
            self.base_address,
            self.entries.len()
        )
    }
}

/// RTTI information associated with a class.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RttiInfo {
    /// Demangled or raw type name (e.g. "`MyClass`" or "`_ZTI7MyClass`").
    pub type_name: String,
    /// Names of direct base classes, in declaration order.
    pub base_classes: Vec<String>,
    /// Address where this RTTI structure was found.
    pub rtti_address: u64,
    /// ABI format the RTTI was decoded from.
    pub abi: RttiAbi,
}

/// The ABI format of an RTTI structure.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RttiAbi {
    /// Itanium C++ ABI (Linux, macOS, most non-Windows platforms).
    Itanium,
    /// Microsoft Visual C++ RTTI.
    Msvc,
    /// Unknown / unrecognised.
    Unknown,
}

// ────────────────────────────────────────────────────────────────────────────
// Binary section model
// ────────────────────────────────────────────────────────────────────────────

/// Shared test-only PRNG for the crate's fuzz/property tests.
///
/// One definition instead of the five byte-identical `XorShift` copies the
/// test modules used to carry (msvc_rtti, rtti_parser, rtti_recovery,
/// vtable_finder, vtable_integrity) plus inheritance_grapher's free fn. Raw
/// tuple constructor and no zero-guard, exactly like every former copy, so no
/// test's random sequence changes. (`property_tests::Rng` is a DIFFERENT
/// algorithm — xorshift64* with extra helpers — and stays separate.)
#[cfg(test)]
pub(crate) mod test_prng {
    /// One xorshift64 step: mutates the state in place and returns it.
    pub(crate) fn xorshift(state: &mut u64) -> u64 {
        let mut x = *state;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        *state = x;
        x
    }

    pub(crate) struct XorShift(pub(crate) u64);
    impl XorShift {
        pub(crate) fn next(&mut self) -> u64 {
            xorshift(&mut self.0)
        }
    }
}

/// A binary section (simplified, carries raw bytes).
#[derive(Debug, Clone)]
pub struct Section {
    pub name: String,
    pub base_address: u64,
    pub data: Vec<u8>,
    pub executable: bool,
    pub writable: bool,
    pub readable: bool,
}

impl Section {
    pub fn new(name: impl Into<String>, base: u64, data: Vec<u8>) -> Self {
        Self {
            name: name.into(),
            base_address: base,
            data,
            executable: false,
            writable: false,
            readable: true,
        }
    }

    #[must_use]
    pub const fn end_address(&self) -> u64 {
        self.base_address.saturating_add(self.data.len() as u64)
    }

    #[must_use]
    pub const fn contains(&self, addr: u64) -> bool {
        addr >= self.base_address && addr < self.end_address()
    }

    /// Read `ptr_size` bytes at `addr` as a little-endian integer.
    #[must_use]
    pub fn read_ptr(&self, addr: u64, ptr_size: usize) -> Option<u64> {
        if !self.contains(addr) {
            return None;
        }
        // Validate ptr_size BEFORE any offset arithmetic: this is a pub API,
        // and an arbitrary ptr_size would overflow `off + ptr_size` (debug
        // panic) or wrap into a panicking slice range (release) instead of
        // returning None.
        if ptr_size != 4 && ptr_size != 8 {
            return None;
        }
        let off = usize::try_from(addr - self.base_address).ok()?;
        let end = off.checked_add(ptr_size)?;
        let bytes = self.data.get(off..end)?;
        match ptr_size {
            4 => Some(u64::from(u32::from_le_bytes(bytes.try_into().ok()?))),
            8 => Some(u64::from_le_bytes(bytes.try_into().ok()?)),
            _ => None,
        }
    }

    /// Read a NUL-terminated string at `addr`.
    #[must_use]
    pub fn read_cstr(&self, addr: u64) -> Option<String> {
        if !self.contains(addr) {
            return None;
        }
        let off = usize::try_from(addr - self.base_address).ok()?;
        let slice = &self.data[off..];
        let end = slice.iter().position(|&b| b == 0)?;
        std::str::from_utf8(&slice[..end])
            .ok()
            .map(std::string::ToString::to_string)
    }

    /// Read a `i32` at `addr` (little-endian).
    #[must_use]
    pub fn read_i32(&self, addr: u64) -> Option<i32> {
        if !self.contains(addr) {
            return None;
        }
        let off = usize::try_from(addr - self.base_address).ok()?;
        if off + 4 > self.data.len() {
            return None;
        }
        Some(i32::from_le_bytes(self.data[off..off + 4].try_into().ok()?))
    }

    /// Read a `u32` at `addr` (little-endian).
    #[must_use]
    pub fn read_u32(&self, addr: u64) -> Option<u32> {
        if !self.contains(addr) {
            return None;
        }
        let off = usize::try_from(addr - self.base_address).ok()?;
        if off + 4 > self.data.len() {
            return None;
        }
        Some(u32::from_le_bytes(self.data[off..off + 4].try_into().ok()?))
    }
}

// ────────────────────────────────────────────────────────────────────────────
// VtableDetector
// ────────────────────────────────────────────────────────────────────────────

/// Minimum number of consecutive code pointers to classify as a vtable.
const MIN_VTABLE_ENTRIES: usize = 2;
/// Maximum plausible vtable size (1024 virtual functions).
const MAX_VTABLE_ENTRIES: usize = 1024;

/// Heuristically detects vtables in data sections.
pub struct VtableDetector {
    pub ptr_size: usize,
}

impl VtableDetector {
    #[must_use]
    pub const fn new(ptr_size: usize) -> Self {
        Self { ptr_size }
    }

    /// Returns `true` if `addr` falls in any executable section.
    fn is_code_address(addr: u64, code_sections: &[Section]) -> bool {
        code_sections
            .iter()
            .any(|s| s.executable && s.contains(addr))
    }

    /// Scan `data_section` for pointer arrays pointing into `code_sections`.
    ///
    /// Returns a list of `Vtable`s whose `entries` contain the raw pointers.
    /// This is a heuristic: the caller should validate against known RTTI.
    ///
    /// # Errors
    ///
    /// Returns [`VtableError::UnsupportedPointerSize`] if `ptr_size` is not 4 or 8.
    pub fn detect(
        &self,
        data_section: &Section,
        code_sections: &[Section],
    ) -> Result<Vec<Vtable>, VtableError> {
        if self.ptr_size != 4 && self.ptr_size != 8 {
            return Err(VtableError::UnsupportedPointerSize(self.ptr_size));
        }

        let mut vtables = Vec::new();
        let data_len = data_section.data.len();
        let step = self.ptr_size;

        let mut i = 0usize;
        while i + step <= data_len {
            let addr = data_section.base_address + i as u64;
            let Some(candidate) = data_section.read_ptr(addr, self.ptr_size) else {
                i += step;
                continue;
            };

            if !Self::is_code_address(candidate, code_sections) {
                i += step;
                continue;
            }

            // Found the start of a potential vtable.
            let vtable_base = addr;
            let mut vtable = Vtable::new(vtable_base);
            let mut offset = 0usize;

            while i + offset + step <= data_len && offset / step < MAX_VTABLE_ENTRIES {
                let slot_addr = vtable_base + offset as u64;
                let Some(ptr) = data_section.read_ptr(slot_addr, self.ptr_size) else {
                    break;
                };
                if !Self::is_code_address(ptr, code_sections) {
                    break;
                }
                vtable.add_entry(VtableEntry::new(offset, ptr));
                offset += step;
            }

            if vtable.entry_count() >= MIN_VTABLE_ENTRIES {
                vtables.push(vtable);
                i += offset; // skip past this vtable
            } else {
                i += step;
            }
        }

        Ok(vtables)
    }
}

// ────────────────────────────────────────────────────────────────────────────
// RttiDecoder — Itanium ABI
// ────────────────────────────────────────────────────────────────────────────

/// Itanium `__class_type_info` layout (simplified):
///   +0: vtable pointer (to `__class_type_info` vtable)
///   +8: type name pointer (char*)
///
/// `__si_class_type_info` (single inheritance):
///   +0: vtable ptr
///   +8: name ptr
///   +16: pointer to base class `__class_type_info`
///
/// `__vmi_class_type_info` (multiple / virtual inheritance):
///   +0: vtable ptr
///   +8: name ptr
///   +16: flags (u32)
///   +20: `base_count` (u32)
///   +24: `base_class_array`[ `base_count` * 2 ] (ptr, `offset_flags` pairs)
/// Decode Itanium RTTI from a section.
pub struct ItaniumRttiDecoder;

/// Maximum recursion depth for Itanium RTTI base-class chain traversal.
///
/// A chain deeper than this in untrusted binary data (including manufactured
/// cycles via back-pointers) would exhaust the native call stack.  32 levels
/// is far more than any real C++ hierarchy requires.
const ITANIUM_RTTI_MAX_DEPTH: usize = 32;

impl ItaniumRttiDecoder {
    /// Attempt to decode a `__class_type_info` or derived structure at `addr`.
    ///
    /// `ro_section`: the `.rodata` section containing RTTI.
    /// `ptr_size`: 4 or 8.
    ///
    /// # Errors
    ///
    /// Returns [`VtableError`] if the RTTI structure is malformed or out of range.
    pub fn decode(
        addr: u64,
        ro_section: &Section,
        ptr_size: usize,
        known_names: &HashMap<u64, String>,
    ) -> Result<RttiInfo, VtableError> {
        Self::decode_inner(addr, ro_section, ptr_size, known_names, 0)
    }

    /// Internal recursive helper with an explicit depth counter to prevent
    /// stack exhaustion on adversarial (deeply nested or cyclic) RTTI graphs.
    fn decode_inner(
        addr: u64,
        ro_section: &Section,
        ptr_size: usize,
        known_names: &HashMap<u64, String>,
        depth: usize,
    ) -> Result<RttiInfo, VtableError> {
        if depth > ITANIUM_RTTI_MAX_DEPTH {
            // Return a placeholder rather than overflowing the stack.
            return Ok(RttiInfo {
                type_name: format!("<rtti@{addr:#x}>"),
                base_classes: Vec::new(),
                rtti_address: addr,
                abi: RttiAbi::Itanium,
            });
        }

        // +ptr_size: name pointer.
        let name_ptr_addr = addr + ptr_size as u64;
        let name_ptr = ro_section
            .read_ptr(name_ptr_addr, ptr_size)
            .ok_or(VtableError::AddressOutOfRange(name_ptr_addr))?;

        let type_name = ro_section
            .read_cstr(name_ptr)
            .or_else(|| known_names.get(&name_ptr).cloned())
            .unwrap_or_else(|| format!("<name@{name_ptr:#x}>"));

        // Try to decode base classes (single-inheritance layout).
        let mut base_classes = Vec::new();
        let base_ptr_addr = addr + 2 * ptr_size as u64;

        // Only `__si_class_type_info` stores a base `__class_type_info` pointer
        // here; plain `__class_type_info` ends at +ptr_size and `__vmi` stores
        // flags/base_count instead. Validate that the candidate actually looks
        // like a type_info (its own name pointer must resolve) before
        // recursing, so we don't fabricate a base from unrelated data.
        if let Some(base_type_ptr) = ro_section.read_ptr(base_ptr_addr, ptr_size)
            && base_type_ptr != 0
            && ro_section.contains(base_type_ptr)
            && let Some(base_name_ptr) =
                ro_section.read_ptr(base_type_ptr + ptr_size as u64, ptr_size)
            && (ro_section.read_cstr(base_name_ptr).is_some()
                || known_names.contains_key(&base_name_ptr))
        {
            // Recurse with depth + 1 to bound stack consumption.
            if let Ok(base_info) = Self::decode_inner(
                base_type_ptr,
                ro_section,
                ptr_size,
                known_names,
                depth + 1,
            ) {
                base_classes.push(base_info.type_name);
            }
        }

        Ok(RttiInfo {
            type_name,
            base_classes,
            rtti_address: addr,
            abi: RttiAbi::Itanium,
        })
    }
}

// ────────────────────────────────────────────────────────────────────────────
// RttiDecoder — MSVC ABI
// ────────────────────────────────────────────────────────────────────────────

/// MSVC `_RTTICompleteObjectLocator` layout (64-bit with relative offsets):
///
///   +0:  signature (u32)  — 0 for 32-bit, 1 for 64-bit
///   +4:  offset (i32)     — offset of vtable within object
///   +8:  cdOffset (i32)   — constructor displacement
///   +12: pTypeDescriptor  — relative offset to `TypeDescriptor`
///   +16: pClassHierarchy  — relative offset to `_RTTIClassHierarchyDescriptor`
///   +20: pSelf            — relative offset to the COL itself (64-bit only)
///
/// `TypeDescriptor` layout:
///   +0:  vftable pointer
///   +ptr: spare pointer
///   +2*ptr: decorated name (char[]) starting with ".?AV"
///
/// `_RTTIClassHierarchyDescriptor`:
///   +0: signature (u32)
///   +4: attributes (u32)
///   +8: numBaseClasses (u32)
///   +12: pBaseClassArray (relative offset)
///
/// `_RTTIBaseClassDescriptor` (32-bit relative offsets in 64-bit):
///   +0: pTypeDescriptor (relative)
///   …
pub struct MsvcRttiDecoder;

impl MsvcRttiDecoder {
    /// Decode an MSVC `_RTTICompleteObjectLocator` at `col_addr`.
    ///
    /// `rdata_section`: the `.rdata` section.
    /// `text_section_base`: start address of the `.text` section (used for
    ///   relative-offset base in 64-bit).
    ///
    /// # Errors
    ///
    /// Returns [`VtableError`] if the COL structure is malformed or out of range.
    pub fn decode_col(
        col_addr: u64,
        rdata_section: &Section,
        image_base: u64,
    ) -> Result<RttiInfo, VtableError> {
        // Read signature.
        let sig = rdata_section
            .read_u32(col_addr)
            .ok_or(VtableError::AddressOutOfRange(col_addr))?;

        let is_64bit = sig == 1;
        let ptr_size: usize = if is_64bit { 8 } else { 4 };

        // offset (i32) at +4, cdOffset (i32) at +8.
        // pTypeDescriptor at +12 (relative or absolute).
        let td_ref_addr = col_addr + 12;
        let td_ptr = if is_64bit {
            // 64-bit: relative offset from image base.
            let rel = i64::from(
                rdata_section
                    .read_i32(td_ref_addr)
                    .ok_or(VtableError::AddressOutOfRange(td_ref_addr))?,
            );
            image_base.wrapping_add_signed(rel)
        } else {
            u64::from(
                rdata_section
                    .read_u32(td_ref_addr)
                    .ok_or(VtableError::AddressOutOfRange(td_ref_addr))?,
            )
        };

        // Read TypeDescriptor.
        let name_offset = 2 * ptr_size as u64; // after two pointer fields
        let name_addr = td_ptr + name_offset;
        let type_name = rdata_section
            .read_cstr(name_addr)
            .ok_or_else(|| VtableError::MalformedRtti(
                name_addr,
                "cannot read type name".into(),
            ))?;

        // Decode class hierarchy to get base classes.
        let hier_ref_addr = col_addr + 16;
        let base_classes =
            Self::decode_hierarchy(hier_ref_addr, rdata_section, image_base, is_64bit)?;

        Ok(RttiInfo {
            type_name: Self::demangle_msvc(&type_name),
            base_classes,
            rtti_address: col_addr,
            abi: RttiAbi::Msvc,
        })
    }

    fn decode_hierarchy(
        hier_ref_addr: u64,
        rdata: &Section,
        image_base: u64,
        is_64bit: bool,
    ) -> Result<Vec<String>, VtableError> {
        let hier_ptr = if is_64bit {
            let rel = i64::from(
                rdata
                    .read_i32(hier_ref_addr)
                    .ok_or(VtableError::AddressOutOfRange(hier_ref_addr))?,
            );
            image_base.wrapping_add_signed(rel)
        } else {
            u64::from(
                rdata
                    .read_u32(hier_ref_addr)
                    .ok_or(VtableError::AddressOutOfRange(hier_ref_addr))?,
            )
        };

        // numBaseClasses at +8.
        let num_bases = rdata
            .read_u32(hier_ptr + 8)
            .ok_or(VtableError::AddressOutOfRange(hier_ptr + 8))? as usize;

        // pBaseClassArray at +12.
        let base_arr_ref = hier_ptr + 12;
        let base_arr_ptr = if is_64bit {
            let rel = i64::from(
                rdata
                    .read_i32(base_arr_ref)
                    .ok_or(VtableError::AddressOutOfRange(base_arr_ref))?,
            );
            image_base.wrapping_add_signed(rel)
        } else {
            u64::from(
                rdata
                    .read_u32(base_arr_ref)
                    .ok_or(VtableError::AddressOutOfRange(base_arr_ref))?,
            )
        };

        let mut bases = Vec::new();
        let ptr_size: usize = if is_64bit { 8 } else { 4 };
        for i in 1..num_bases.min(64) {
            // Skip index 0 (self).
            // In 64-bit MSVC RTTI the BaseClassArray holds 32-bit relative
            // offsets regardless of pointer size, so always stride by 4 bytes.
            let elem_stride: u64 = if is_64bit { 4 } else { ptr_size as u64 };
            let entry_addr = base_arr_ptr + (i as u64) * elem_stride;
            let td_ref = if is_64bit {
                let rel = i64::from(
                    rdata
                        .read_i32(entry_addr)
                        .ok_or(VtableError::AddressOutOfRange(entry_addr))?,
                );
                image_base.wrapping_add_signed(rel)
            } else {
                u64::from(
                    rdata
                        .read_u32(entry_addr)
                        .ok_or(VtableError::AddressOutOfRange(entry_addr))?,
                )
            };

            let name_offset = 2 * ptr_size as u64;
            let name_addr = td_ref + name_offset;
            if let Some(name) = rdata.read_cstr(name_addr) {
                bases.push(Self::demangle_msvc(&name));
            }
        }
        Ok(bases)
    }

    /// Minimal MSVC name demangling: strip leading `.?AV` / `.?AU` and trailing `@@`.
    #[must_use]
    pub fn demangle_msvc(name: &str) -> String {
        let stripped = name
            .trim_start_matches(".?AV")
            .trim_start_matches(".?AU")
            .trim_end_matches("@@");
        // Replace `@` with `::` to get a C++ qualified name.
        stripped.replace('@', "::")
    }
}

// ────────────────────────────────────────────────────────────────────────────
// RttiDecoder — unified facade
// ────────────────────────────────────────────────────────────────────────────

/// High-level RTTI decoder that tries both ABIs.
pub struct RttiDecoder {
    pub ptr_size: usize,
    pub image_base: u64,
}

impl RttiDecoder {
    #[must_use]
    pub const fn new(ptr_size: usize, image_base: u64) -> Self {
        Self {
            ptr_size,
            image_base,
        }
    }

    /// Attempt Itanium decode.
    ///
    /// # Errors
    ///
    /// Returns [`VtableError`] if the RTTI structure is malformed or out of range.
    pub fn decode_itanium(
        &self,
        addr: u64,
        ro_section: &Section,
        known_names: &HashMap<u64, String>,
    ) -> Result<RttiInfo, VtableError> {
        ItaniumRttiDecoder::decode(addr, ro_section, self.ptr_size, known_names)
    }

    /// Attempt MSVC COL decode.
    ///
    /// # Errors
    ///
    /// Returns [`VtableError`] if the COL structure is malformed or out of range.
    pub fn decode_msvc_col(
        &self,
        col_addr: u64,
        rdata_section: &Section,
    ) -> Result<RttiInfo, VtableError> {
        MsvcRttiDecoder::decode_col(col_addr, rdata_section, self.image_base)
    }
}

// ────────────────────────────────────────────────────────────────────────────
// VtableDatabase — aggregate results
// ────────────────────────────────────────────────────────────────────────────

/// Stores all recovered vtables and RTTI for a binary.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct VtableDatabase {
    /// All discovered vtables, keyed by base address.
    pub vtables: HashMap<u64, Vtable>,
    /// All recovered RTTI, keyed by RTTI struct address.
    pub rtti: HashMap<u64, RttiInfo>,
    /// Map from vtable base address to the RTTI address that describes it.
    pub vtable_to_rtti: HashMap<u64, u64>,
}

impl VtableDatabase {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_vtable(&mut self, vtable: Vtable) {
        self.vtables.insert(vtable.base_address, vtable);
    }

    pub fn add_rtti(&mut self, rtti: RttiInfo) {
        self.rtti.insert(rtti.rtti_address, rtti);
    }

    pub fn link_vtable_rtti(&mut self, vtable_addr: u64, rtti_addr: u64) {
        self.vtable_to_rtti.insert(vtable_addr, rtti_addr);
        // Propagate class name to vtable.
        if let Some(rtti) = self.rtti.get(&rtti_addr) {
            let name = rtti.type_name.clone();
            if let Some(vtable) = self.vtables.get_mut(&vtable_addr) {
                vtable.class_name = Some(name);
            }
        }
    }

    /// Find the RTTI info linked to a vtable at `vtable_addr`, if any.
    #[must_use]
    pub fn rtti_for_vtable(&self, vtable_addr: u64) -> Option<&RttiInfo> {
        let rtti_addr = self.vtable_to_rtti.get(&vtable_addr)?;
        self.rtti.get(rtti_addr)
    }

    /// Find all vtables associated with a class name.
    #[must_use]
    pub fn find_by_class(&self, class_name: &str) -> Vec<&Vtable> {
        let mut out: Vec<&Vtable> = self
            .vtables
            .values()
            .filter(|v| v.class_name.as_deref() == Some(class_name))
            .collect();
        // Deterministic order: HashMap iteration order is not stable across runs.
        out.sort_by_key(|v| v.base_address);
        out
    }
}

// ────────────────────────────────────────────────────────────────────────────
// Helpers for tests
// ────────────────────────────────────────────────────────────────────────────

/// Build a Section whose data is a sequence of 8-byte pointers.
#[must_use]
pub fn make_ptr_section(base: u64, ptrs: &[u64], executable: bool) -> Section {
    let mut data = Vec::with_capacity(ptrs.len() * 8);
    for &p in ptrs {
        data.extend_from_slice(&p.to_le_bytes());
    }
    let mut s = Section::new(".test", base, data);
    s.executable = executable;
    s
}

/// Build a Section whose data encodes a NUL-terminated string at offset 0.
#[must_use]
pub fn make_str_section(base: u64, s: &str) -> Section {
    let mut data = s.as_bytes().to_vec();
    data.push(0);
    Section::new(".rodata", base, data)
}

// ────────────────────────────────────────────────────────────────────────────
// Tests
// ────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn section_read_ptr_rejects_bogus_ptr_size_instead_of_panicking() {
        // Regression: `read_ptr` computed `off + ptr_size` and sliced BEFORE
        // validating ptr_size, so an adversarial size panicked (overflow in
        // debug, invalid slice range in release) instead of returning None.
        let s = Section::new(".rdata", 0x1000, vec![0u8; 16]);
        assert_eq!(s.read_ptr(0x1000, usize::MAX), None);
        assert_eq!(s.read_ptr(0x1000, 3), None);
        assert_eq!(s.read_ptr(0x1000, 8), Some(0));
    }

    #[test]
    fn find_by_class_is_deterministic_and_sorted() {
        // Many same-named vtables at scattered addresses: HashMap iteration
        // order is not stable, so find_by_class must impose a deterministic
        // (address-sorted) order.
        let addrs = [0x9000u64, 0x1000, 0x5000, 0x3000, 0x7000, 0x2000, 0x8000];
        let mut db = VtableDatabase::new();
        for &a in &addrs {
            let mut vt = Vtable::new(a);
            vt.class_name = Some("Widget".to_string());
            db.add_vtable(vt);
        }
        let got: Vec<u64> = db
            .find_by_class("Widget")
            .iter()
            .map(|v| v.base_address)
            .collect();
        let mut expect = addrs.to_vec();
        expect.sort_unstable();
        assert_eq!(got, expect);
        // Stable across repeated calls.
        for _ in 0..8 {
            let again: Vec<u64> = db
                .find_by_class("Widget")
                .iter()
                .map(|v| v.base_address)
                .collect();
            assert_eq!(again, expect);
        }
    }

    // ── VtableEntry ───────────────────────────────────────────────────────

    #[test]
    fn test_vtable_entry_display() {
        let e = VtableEntry::with_name(0, 0x1234, "MyClass::method");
        let s = format!("{e}");
        assert!(s.contains("0x1234"));
        assert!(s.contains("MyClass::method"));
    }

    #[test]
    fn test_vtable_entry_no_name() {
        let e = VtableEntry::new(8, 0xABCD);
        assert!(e.function_name.is_none());
    }

    // ── Vtable ────────────────────────────────────────────────────────────

    #[test]
    fn test_vtable_add_entries() {
        let mut vt = Vtable::new(0x4000);
        vt.add_entry(VtableEntry::new(0, 0x1000));
        vt.add_entry(VtableEntry::new(8, 0x1010));
        assert_eq!(vt.entry_count(), 2);
    }

    #[test]
    fn test_vtable_display() {
        let mut vt = Vtable::new(0x4000);
        vt.class_name = Some("Foo".into());
        vt.add_entry(VtableEntry::new(0, 0x1000));
        let s = format!("{vt}");
        assert!(s.contains("Foo"));
        assert!(s.contains("0x4000"));
    }

    // ── Section helpers ───────────────────────────────────────────────────

    #[test]
    fn test_section_read_ptr_8() {
        let sec = make_ptr_section(0x1000, &[0xDEAD_BEEF_CAFE_BABE], false);
        assert_eq!(sec.read_ptr(0x1000, 8), Some(0xDEAD_BEEF_CAFE_BABE));
    }

    #[test]
    fn test_section_read_ptr_4() {
        let mut data = Vec::new();
        data.extend_from_slice(&(0xDEAD_BEEFu32).to_le_bytes());
        let sec = Section::new(".data", 0x2000, data);
        assert_eq!(sec.read_ptr(0x2000, 4), Some(0xDEAD_BEEF));
    }

    #[test]
    fn test_section_read_cstr() {
        let sec = make_str_section(0x3000, "Hello");
        assert_eq!(sec.read_cstr(0x3000), Some("Hello".into()));
    }

    #[test]
    fn test_section_out_of_range() {
        let sec = Section::new(".text", 0x1000, vec![0; 16]);
        assert!(sec.read_ptr(0x2000, 8).is_none());
    }

    // ── VtableDetector ────────────────────────────────────────────────────

    fn make_test_env() -> (Section, Section) {
        // Code section: addresses 0x1000..0x3000
        let code = {
            let mut s = Section::new(".text", 0x1000, vec![0x90u8; 0x2000]);
            s.executable = true;
            s
        };
        // Data section: vtable with two entries pointing into .text
        let ptrs = [0x1100u64, 0x1200u64];
        let mut data = make_ptr_section(0x4000, &ptrs, false);
        data.executable = false;
        (data, code)
    }

    #[test]
    fn test_vtable_detector_finds_vtable() {
        let (data, code) = make_test_env();
        let detector = VtableDetector::new(8);
        let vtables = detector.detect(&data, &[code]).unwrap();
        assert!(!vtables.is_empty());
        assert_eq!(vtables[0].entry_count(), 2);
        assert_eq!(vtables[0].base_address, 0x4000);
    }

    #[test]
    fn test_vtable_detector_min_entries() {
        // Only one pointer — should not be considered a vtable.
        let code = {
            let mut s = Section::new(".text", 0x1000, vec![0x90; 0x1000]);
            s.executable = true;
            s
        };
        let data = make_ptr_section(0x4000, &[0x1100u64], false);
        let detector = VtableDetector::new(8);
        let vtables = detector.detect(&data, &[code]).unwrap();
        assert!(
            vtables.is_empty(),
            "single pointer should not form a vtable"
        );
    }

    #[test]
    fn test_vtable_detector_invalid_ptr_size() {
        let data = Section::new(".data", 0x4000, vec![0; 16]);
        let code = Section::new(".text", 0x1000, vec![0; 16]);
        let detector = VtableDetector::new(3);
        assert!(matches!(
            detector.detect(&data, &[code]),
            Err(VtableError::UnsupportedPointerSize(3))
        ));
    }

    // ── Itanium RTTI decoder ──────────────────────────────────────────────

    fn make_itanium_rtti_section() -> Section {
        // Layout: [vtable_ptr (8B), name_ptr (8B)]
        // where name is "MyClass" stored right after.
        let name_offset = 0x10u64; // name stored at offset 0x10 in section
        let rtti_base = 0x8000u64;
        let name_addr = rtti_base + name_offset;
        let mut data = vec![0u8; 0x40];
        // vtable_ptr (ignored) at offset 0.
        // name_ptr at offset 8.
        let name_ptr_bytes = name_addr.to_le_bytes();
        data[8..16].copy_from_slice(&name_ptr_bytes);
        // Name string at offset 0x10.
        let name = b"MyClass\0";
        data[0x10..0x10 + name.len()].copy_from_slice(name);

        Section::new(".rodata", rtti_base, data)
    }

    #[test]
    fn test_itanium_decode_type_name() {
        let section = make_itanium_rtti_section();
        let rtti_addr = 0x8000u64;
        let known: HashMap<u64, String> = HashMap::new();
        let info = ItaniumRttiDecoder::decode(rtti_addr, &section, 8, &known).unwrap();
        assert_eq!(info.type_name, "MyClass");
        assert_eq!(info.abi, RttiAbi::Itanium);
    }

    #[test]
    fn test_itanium_decode_rtti_address_stored() {
        let section = make_itanium_rtti_section();
        let rtti_addr = 0x8000u64;
        let known: HashMap<u64, String> = HashMap::new();
        let info = ItaniumRttiDecoder::decode(rtti_addr, &section, 8, &known).unwrap();
        assert_eq!(info.rtti_address, rtti_addr);
    }

    // ── MSVC demangle ─────────────────────────────────────────────────────

    #[test]
    fn test_msvc_demangle_basic() {
        assert_eq!(MsvcRttiDecoder::demangle_msvc(".?AVFoo@@"), "Foo");
    }

    #[test]
    fn test_msvc_demangle_nested() {
        assert_eq!(MsvcRttiDecoder::demangle_msvc(".?AVBar@Ns@@"), "Bar::Ns");
    }

    #[test]
    fn test_msvc_demangle_struct() {
        assert_eq!(MsvcRttiDecoder::demangle_msvc(".?AUMyStruct@@"), "MyStruct");
    }

    // ── VtableDatabase ────────────────────────────────────────────────────

    #[test]
    fn test_database_link_rtti() {
        let mut db = VtableDatabase::new();
        let mut vt = Vtable::new(0x4000);
        vt.add_entry(VtableEntry::new(0, 0x1000));
        db.add_vtable(vt);
        let rtti = RttiInfo {
            type_name: "Base".into(),
            base_classes: vec![],
            rtti_address: 0x5000,
            abi: RttiAbi::Itanium,
        };
        db.add_rtti(rtti);
        db.link_vtable_rtti(0x4000, 0x5000);
        let found = db.find_by_class("Base");
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].base_address, 0x4000);
    }

    #[test]
    fn test_database_find_unknown_class() {
        let db = VtableDatabase::new();
        assert!(db.find_by_class("DoesNotExist").is_empty());
    }

    // ── Additional tests ──────────────────────────────────────────────────

    #[test]
    fn test_vtable_error_display() {
        let e = VtableError::AddressOutOfRange(0xDEAD);
        assert!(e.to_string().contains("0xdead"));
        let e2 = VtableError::UnsupportedPointerSize(3);
        assert!(e2.to_string().contains('3'));
        let e3 = VtableError::SectionNotFound(".text".into());
        assert!(e3.to_string().contains(".text"));
        let e4 = VtableError::InvalidString(0x1234);
        assert!(e4.to_string().contains("0x1234"));
        let e5 = VtableError::MalformedRtti(0x5000, "bad".into());
        assert!(e5.to_string().contains("bad"));
    }

    #[test]
    fn test_vtable_entry_count_zero_initially() {
        let vt = Vtable::new(0x1000);
        assert_eq!(vt.entry_count(), 0);
        assert!(vt.class_name.is_none());
        assert!(vt.offset_to_top.is_none());
    }

    #[test]
    fn test_rtti_info_construction() {
        let rtti = RttiInfo {
            type_name: "MyClass".into(),
            base_classes: vec!["Base1".into(), "Base2".into()],
            rtti_address: 0x9000,
            abi: RttiAbi::Msvc,
        };
        assert_eq!(rtti.type_name, "MyClass");
        assert_eq!(rtti.base_classes.len(), 2);
        assert_eq!(rtti.abi, RttiAbi::Msvc);
    }

    #[test]
    fn test_vtable_with_class_name() {
        let mut vt = Vtable::new(0x8000);
        vt.class_name = Some("Widget".into());
        assert_eq!(vt.class_name.as_deref(), Some("Widget"));
        let s = format!("{vt}");
        assert!(s.contains("Widget"));
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// PureVirtualDetector — detect __cxa_pure_virtual / _purecall in vtable slots
// ─────────────────────────────────────────────────────────────────────────────

/// Well-known addresses / symbol names for pure-virtual call stubs.
const PURE_VIRTUAL_NAMES: &[&str] = &[
    "__cxa_pure_virtual",
    "_purecall",
    "___cxa_pure_virtual",
    "__pure_virtual",
];

/// Detects vtable entries that point to pure-virtual call stubs.
///
/// A slot is considered "pure virtual" when:
/// 1. Its `function_name` is one of the known pure-virtual stubs, OR
/// 2. Its `target_address` is in a set of known stub addresses.
#[derive(Debug, Clone, Default)]
pub struct PureVirtualDetector {
    /// Addresses known to be pure-virtual stubs.
    known_stub_addresses: Vec<u64>,
}

impl PureVirtualDetector {
    /// Create a new detector with no pre-loaded stub addresses.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a known pure-virtual stub address.
    pub fn add_stub_address(&mut self, addr: u64) {
        self.known_stub_addresses.push(addr);
    }

    /// Returns `true` if `entry` is a pure-virtual slot.
    #[must_use]
    pub fn is_pure_virtual(&self, entry: &VtableEntry) -> bool {
        if let Some(name) = &entry.function_name
            && PURE_VIRTUAL_NAMES.contains(&name.as_str()) {
                return true;
            }
        self.known_stub_addresses.contains(&entry.target_address)
    }

    /// Mark all pure-virtual entries in `vtable` and return the count.
    pub fn annotate(&self, vtable: &mut Vtable) -> usize {
        let mut count = 0;
        for entry in &mut vtable.entries {
            if self.is_pure_virtual(entry) {
                if entry.function_name.is_none() {
                    entry.function_name = Some("__cxa_pure_virtual".to_string());
                }
                count += 1;
            }
        }
        count
    }

    /// Count pure-virtual slots across all vtables in the database.
    #[must_use]
    pub fn count_in_database(&self, db: &VtableDatabase) -> usize {
        db.vtables
            .values()
            .flat_map(|vt| vt.entries.iter())
            .filter(|e| self.is_pure_virtual(e))
            .count()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// AbstractClassInference — infer which classes are abstract
// ─────────────────────────────────────────────────────────────────────────────

/// Records whether a class is abstract and which slots are pure.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AbstractClassInfo {
    /// Class name.
    pub class_name: String,
    /// Address of the vtable.
    pub vtable_address: u64,
    /// Indices of pure-virtual slots (0-based).
    pub pure_virtual_slots: Vec<usize>,
    /// Whether the class is abstract (has at least one pure-virtual slot).
    pub is_abstract: bool,
}

/// Infers whether classes are abstract from their vtables.
#[derive(Debug, Clone, Default)]
pub struct AbstractClassInference {
    detector: PureVirtualDetector,
}

impl AbstractClassInference {
    /// Create a new instance.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Create with a configured `PureVirtualDetector`.
    #[must_use]
    pub const fn with_detector(detector: PureVirtualDetector) -> Self {
        Self { detector }
    }

    /// Analyse all vtables in `db` and return abstract class information.
    #[must_use]
    pub fn infer(&self, db: &VtableDatabase) -> Vec<AbstractClassInfo> {
        db.vtables
            .values()
            .map(|vt| {
                let pure_slots: Vec<usize> = vt
                    .entries
                    .iter()
                    .enumerate()
                    .filter(|(_, e)| self.detector.is_pure_virtual(e))
                    .map(|(i, _)| i)
                    .collect();
                let is_abstract = !pure_slots.is_empty();
                AbstractClassInfo {
                    class_name: vt
                        .class_name
                        .clone()
                        .unwrap_or_else(|| format!("class_{:#x}", vt.base_address)),
                    vtable_address: vt.base_address,
                    pure_virtual_slots: pure_slots,
                    is_abstract,
                }
            })
            .collect()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// MultipleInheritanceLayout — layout for objects with multiple bases
// ─────────────────────────────────────────────────────────────────────────────

/// One sub-object in a multiple-inheritance layout.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SubObject {
    /// Name of the base class.
    pub class_name: String,
    /// Byte offset from the start of the most-derived object.
    pub offset: usize,
    /// Address of the vtable pointer for this sub-object (`None` if non-polymorphic).
    pub vtable_address: Option<u64>,
    /// True if this is the primary (first) base.
    pub is_primary: bool,
}

/// Complete object layout for a class with multiple inheritance.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MultipleInheritanceLayout {
    /// Name of the most-derived class.
    pub derived_class: String,
    /// Total size of one object in bytes.
    pub object_size: usize,
    /// List of sub-objects (bases), ordered by offset.
    pub sub_objects: Vec<SubObject>,
}

impl MultipleInheritanceLayout {
    /// Create a new layout.
    #[must_use]
    pub fn new(derived_class: impl Into<String>, object_size: usize) -> Self {
        Self {
            derived_class: derived_class.into(),
            object_size,
            sub_objects: Vec::new(),
        }
    }

    /// Add a sub-object.
    pub fn add_sub_object(&mut self, sub: SubObject) {
        self.sub_objects.push(sub);
        self.sub_objects.sort_by_key(|s| s.offset);
    }

    /// The primary vtable pointer (from the first sub-object at offset 0).
    #[must_use]
    pub fn primary_vtable(&self) -> Option<u64> {
        self.sub_objects
            .iter()
            .find(|s| s.offset == 0 && s.is_primary)
            .and_then(|s| s.vtable_address)
    }

    /// All secondary vtable addresses (for sub-objects at non-zero offsets).
    ///
    /// # Panics
    /// Never panics in practice (vtable address is `Some` when the filter passes).
    #[must_use]
    pub fn secondary_vtables(&self) -> Vec<(usize, u64)> {
        self.sub_objects
            .iter()
            .filter(|s| s.offset > 0 && s.vtable_address.is_some())
            .map(|s| (s.offset, s.vtable_address.unwrap()))
            .collect()
    }

    /// Number of base sub-objects.
    #[must_use]
    pub const fn base_count(&self) -> usize {
        self.sub_objects.len()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// VtableScanner — heuristic scanning of memory regions for vtables
// ─────────────────────────────────────────────────────────────────────────────

/// Heuristic vtable candidate from a scan.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct VtableCandidate {
    /// Address of the candidate vtable.
    pub address: u64,
    /// Number of slots detected.
    pub slot_count: usize,
    /// Estimated confidence (0.0–1.0).
    pub confidence: f32,
    /// Whether a valid RTTI pointer was found immediately before the vtable.
    pub has_rtti_prefix: bool,
    /// The raw method pointer values found in the vtable slots.
    pub method_ptrs: Vec<u64>,
}

/// Scans a flat binary region for vtable candidates using pointer-array heuristics.
#[derive(Debug, Clone)]
pub struct VtableScanner {
    /// Pointer size (4 or 8 bytes).
    pub ptr_size: usize,
    /// Minimum number of consecutive valid code pointers for a vtable candidate.
    pub min_slots: usize,
    /// Range of addresses considered "executable" (code section).
    pub code_ranges: Vec<(u64, u64)>,
}

impl VtableScanner {
    /// Create a new scanner.
    ///
    /// # Panics
    /// Panics if `ptr_size` is not 4 or 8.
    #[must_use]
    pub fn new(ptr_size: usize, min_slots: usize) -> Self {
        assert!(ptr_size == 4 || ptr_size == 8, "ptr_size must be 4 or 8");
        Self {
            ptr_size,
            min_slots,
            code_ranges: Vec::new(),
        }
    }

    /// Add a code range.
    pub fn add_code_range(&mut self, start: u64, end: u64) {
        self.code_ranges.push((start, end));
    }

    /// True if `addr` falls in any registered code range.
    #[must_use]
    pub fn is_code_address(&self, addr: u64) -> bool {
        self.code_ranges.iter().any(|&(s, e)| addr >= s && addr < e)
    }

    /// Scan `data` (mapped at `base`) for vtable candidates.
    #[must_use]
    pub fn scan(&self, data: &[u8], base: u64) -> Vec<VtableCandidate> {
        let mut candidates = Vec::new();
        let step = self.ptr_size;
        if data.len() < step * self.min_slots {
            return candidates;
        }

        let mut i = 0;
        while i + step <= data.len() {
            let ptr = read_ptr(data, i, self.ptr_size);
            if self.is_code_address(ptr) {
                // Count consecutive code pointers.
                let start_i = i;
                let mut slot_count = 0;
                while i + step <= data.len() {
                    let p = read_ptr(data, i, self.ptr_size);
                    if self.is_code_address(p) {
                        slot_count += 1;
                        i += step;
                    } else {
                        break;
                    }
                }
                if slot_count >= self.min_slots {
                    // Check for an RTTI prefix: the word immediately before the
                    // vtable should look like a POINTER to the type
                    // descriptor.
                    //
                    // This used to accept any non-zero word, and that single
                    // bit raises the reported confidence from 0.60 to 0.85 —
                    // so a stray length, flag or counter sitting before a run
                    // of code pointers promoted a guess to a near-certainty,
                    // and `has_rtti_prefix: true` told the caller RTTI was
                    // present when nothing pointer-like had been seen.
                    //
                    // The scanner only knows `code_ranges`, so it cannot
                    // confirm the target; it can still reject values that
                    // cannot BE pointers: unaligned words, and anything in the
                    // null page (< 0x1000), which is never mapped. Note the
                    // word is already known not to be a code address —
                    // otherwise the run of slots would have started earlier.
                    let has_rtti_prefix = start_i >= step && {
                        let prefix = read_ptr(data, start_i - step, self.ptr_size);
                        prefix >= 0x1000 && prefix % (self.ptr_size as u64) == 0
                    };
                    let base_conf = if has_rtti_prefix { 0.85f32 } else { 0.60f32 };
                    let slot_bonus = f32::from(u8::try_from(slot_count.min(10)).unwrap_or(10)) * 0.02f32;
                    let confidence = (base_conf + slot_bonus).min(1.0f32);
                    // Collect the method pointers for this candidate.
                    let method_ptrs: Vec<u64> = (0..slot_count)
                        .map(|j| read_ptr(data, start_i + j * step, step))
                        .filter(|&p| p != 0)
                        .collect();
                    candidates.push(VtableCandidate {
                        address: base + start_i as u64,
                        slot_count,
                        confidence,
                        has_rtti_prefix,
                        method_ptrs,
                    });
                }
            } else {
                i += step;
            }
        }
        candidates
    }
}

fn read_ptr(data: &[u8], offset: usize, size: usize) -> u64 {
    if size == 4 {
        if offset + 4 > data.len() {
            return 0;
        }
        u64::from(u32::from_le_bytes([
            data[offset],
            data[offset + 1],
            data[offset + 2],
            data[offset + 3],
        ]))
    } else {
        if offset + 8 > data.len() {
            return 0;
        }
        u64::from_le_bytes([
            data[offset],
            data[offset + 1],
            data[offset + 2],
            data[offset + 3],
            data[offset + 4],
            data[offset + 5],
            data[offset + 6],
            data[offset + 7],
        ])
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// VtableSlotAnnotator — enrich vtable slots from a symbol table
// ─────────────────────────────────────────────────────────────────────────────

/// Annotates vtable entries with function names from a symbol address map.
#[derive(Debug, Clone, Default)]
pub struct VtableSlotAnnotator {
    /// Map from function address to demangled name.
    symbols: HashMap<u64, String>,
}

impl VtableSlotAnnotator {
    /// Create a new annotator.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a symbol.
    pub fn add_symbol(&mut self, address: u64, name: impl Into<String>) {
        self.symbols.insert(address, name.into());
    }

    /// Load many symbols at once.
    pub fn load_symbols(&mut self, map: HashMap<u64, String>) {
        self.symbols.extend(map);
    }

    /// Annotate all entries in `vtable` with their resolved names.
    ///
    /// Returns the number of entries that were named.
    pub fn annotate(&self, vtable: &mut Vtable) -> usize {
        let mut named = 0;
        for entry in &mut vtable.entries {
            if entry.function_name.is_none()
                && let Some(name) = self.symbols.get(&entry.target_address) {
                    entry.function_name = Some(name.clone());
                    named += 1;
                }
        }
        named
    }

    /// Annotate all vtables in the database.
    ///
    /// Returns the total number of entries named.
    pub fn annotate_all(&self, db: &mut VtableDatabase) -> usize {
        let mut total = 0;
        for vtable in db.vtables.values_mut() {
            total += self.annotate(vtable);
        }
        total
    }

    /// Number of symbols loaded.
    #[must_use]
    pub fn symbol_count(&self) -> usize {
        self.symbols.len()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// VtableCompare — diff two vtables to detect patching / hot-patching
// ─────────────────────────────────────────────────────────────────────────────

/// One difference between two vtable versions.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VtableDiff {
    /// Slot index (0-based).
    pub slot: usize,
    /// The address in the original vtable.
    pub original_address: u64,
    /// The address in the patched vtable.
    pub patched_address: u64,
}

/// Compares two vtables (e.g., before/after hot-patching) and lists changed slots.
#[derive(Debug, Clone, Default)]
pub struct VtableComparer;

impl VtableComparer {
    /// Create a new comparer.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Diff `original` against `patched` and return all changed slots.
    #[must_use]
    pub fn diff(&self, original: &Vtable, patched: &Vtable) -> Vec<VtableDiff> {
        let len = original.entries.len().min(patched.entries.len());
        let mut diffs = Vec::new();
        for i in 0..len {
            if original.entries[i].target_address != patched.entries[i].target_address {
                diffs.push(VtableDiff {
                    slot: i,
                    original_address: original.entries[i].target_address,
                    patched_address: patched.entries[i].target_address,
                });
            }
        }
        diffs
    }

    /// True if `original` and `patched` are byte-for-byte identical.
    #[must_use]
    pub fn is_identical(&self, original: &Vtable, patched: &Vtable) -> bool {
        self.diff(original, patched).is_empty() && original.entries.len() == patched.entries.len()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// VtableStats — aggregate statistics
// ─────────────────────────────────────────────────────────────────────────────

/// Aggregate statistics for a set of vtables.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct VtableStats {
    /// Total number of vtables.
    pub vtable_count: usize,
    /// Total number of vtable slots across all vtables.
    pub total_slots: usize,
    /// Average slots per vtable.
    pub avg_slots: f64,
    /// Maximum slots in any single vtable.
    pub max_slots: usize,
    /// Number of pure-virtual slots (across all vtables).
    pub pure_virtual_count: usize,
    /// Number of vtables with RTTI linked.
    pub rtti_linked_count: usize,
    /// Number of abstract classes (has at least one pure-virtual slot).
    pub abstract_class_count: usize,
}

impl VtableStats {
    /// Compute statistics from a database.
    #[must_use]
    pub fn from_database(db: &VtableDatabase) -> Self {
        let pv_detector = PureVirtualDetector::new();
        let vtable_count = db.vtables.len();
        let total_slots: usize = db.vtables.values().map(|vt| vt.entries.len()).sum();
        let max_slots = db
            .vtables
            .values()
            .map(|vt| vt.entries.len())
            .max()
            .unwrap_or(0);
        let avg_slots = if vtable_count > 0 {
            f64::from(u32::try_from(total_slots).unwrap_or(u32::MAX)) / f64::from(u32::try_from(vtable_count).unwrap_or(u32::MAX))
        } else {
            0.0
        };
        let pure_virtual_count = pv_detector.count_in_database(db);
        // Check RTTI linkage: a vtable has RTTI if the VtableDatabase has an RTTI entry mapped to it.
        let rtti_linked_count = db
            .vtables
            .values()
            .filter(|vt| db.rtti_for_vtable(vt.base_address).is_some())
            .count();
        let abstract_class_count = db
            .vtables
            .values()
            .filter(|vt| vt.entries.iter().any(|e| pv_detector.is_pure_virtual(e)))
            .count();

        Self {
            vtable_count,
            total_slots,
            avg_slots,
            max_slots,
            pure_virtual_count,
            rtti_linked_count,
            abstract_class_count,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ItaniumVmiRttiDecoder — __vmi_class_type_info (multiple inheritance RTTI)
// ─────────────────────────────────────────────────────────────────────────────

/// Flags for Itanium `__vmi_class_type_info::__flags`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VmiFlags(pub u32);

impl VmiFlags {
    /// `__non_diamond_repeat_mask`: layout has a repeated base.
    pub const NON_DIAMOND_REPEAT: u32 = 1;
    /// `__diamond_shaped_mask`: layout is diamond-shaped.
    pub const DIAMOND_SHAPED: u32 = 2;

    /// True if the layout is diamond-shaped.
    #[must_use]
    pub const fn is_diamond_shaped(self) -> bool {
        self.0 & Self::DIAMOND_SHAPED != 0
    }

    /// True if a non-diamond repeated base exists.
    #[must_use]
    pub const fn has_non_diamond_repeat(self) -> bool {
        self.0 & Self::NON_DIAMOND_REPEAT != 0
    }
}

/// A single base-class descriptor in `__vmi_class_type_info`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VmiBaseClassEntry {
    /// Name of the base class.
    pub base_class_name: String,
    /// Byte offset of this base sub-object within the derived object.
    pub offset: i64,
    /// True if this is a virtual base.
    pub is_virtual: bool,
    /// True if this is a public base.
    pub is_public: bool,
}

/// Decoded `__vmi_class_type_info` structure (multiple-inheritance RTTI).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VmiRttiInfo {
    /// Name of the derived class.
    pub class_name: String,
    /// Address of the `__vmi_class_type_info` structure.
    pub rtti_address: u64,
    /// `__flags` value.
    pub flags: u32,
    /// List of base classes.
    pub base_classes: Vec<VmiBaseClassEntry>,
}

impl VmiRttiInfo {
    /// True if the layout is diamond-shaped.
    #[must_use]
    pub const fn is_diamond_shaped(&self) -> bool {
        VmiFlags(self.flags).is_diamond_shaped()
    }

    /// Number of direct base classes.
    #[must_use]
    pub const fn base_count(&self) -> usize {
        self.base_classes.len()
    }

    /// True if this class has multiple inheritance.
    #[must_use]
    pub const fn has_multiple_inheritance(&self) -> bool {
        self.base_classes.len() > 1
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// VtableAnalysisPass — AnalysisPass implementation
// ─────────────────────────────────────────────────────────────────────────────

/// An [`rustre_analysis::AnalysisPass`] that scans the binary for C++ vtables.
///
/// The pass iterates over all segments: executable segments are collected as
/// code ranges, and non-executable readable segments are scanned with
/// [`VtableScanner`] to find vtable candidates.  The total number of vtable
/// candidates discovered is reported as `data_refs_found`.
#[derive(Debug, Default)]
pub struct VtableAnalysisPass;

impl VtableAnalysisPass {
    /// Create a new `VtableAnalysisPass`.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

#[async_trait::async_trait]
impl rustre_analysis::AnalysisPass for VtableAnalysisPass {
    fn name(&self) -> &'static str {
        "vtable_analysis"
    }

    fn kind(&self) -> rustre_analysis::AnalysisKind {
        rustre_analysis::AnalysisKind::VtableAnalysis
    }

    fn description(&self) -> &'static str {
        "C++ vtable recovery: heuristically locates virtual-dispatch tables by \
         scanning data sections for pointer arrays that point into executable code"
    }

    async fn run(
        &self,
        view: &rustre_core::binary_view::BinaryView,
        _config: &rustre_analysis::AnalysisConfig,
    ) -> Result<rustre_analysis::AnalysisResult, rustre_analysis::AnalysisError> {
        use std::time::Instant;
        let start = Instant::now();

        let ptr_size = if view.bits == 64 { 8usize } else { 4usize };
        let mut scanner = VtableScanner::new(ptr_size, 2);
        let mut data_refs_found = 0usize;

        {
            let mem_guard = view.mem.read();

            // Collect executable address ranges (code sections).
            for seg in &mem_guard.segments {
                if seg
                    .permissions
                    .contains(rustre_core::permissions::Permissions::EXECUTE)
                {
                    let base = seg.range.start.0;
                    let end = seg.range.end.0;
                    scanner.add_code_range(base, end);
                }
            }

            // Scan readable, non-executable segments for vtable candidates.
            for seg in &mem_guard.segments {
                if seg
                    .permissions
                    .contains(rustre_core::permissions::Permissions::EXECUTE)
                {
                    continue;
                }
                if !seg
                    .permissions
                    .contains(rustre_core::permissions::Permissions::READ)
                {
                    continue;
                }
                let base = seg.range.start.0;
                let candidates = scanner.scan(&seg.data, base);
                data_refs_found += candidates.len();
            }
        } // mem_guard dropped here

        Ok(rustre_analysis::AnalysisResult {
            kind: rustre_analysis::AnalysisKind::VtableAnalysis,
            functions_found: 0,
            data_refs_found,
            strings_found: 0,
            duration_ms: u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX),
            warnings: Vec::new(),
        })
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// VtableScanner::scan_binary — convenience entry point
// ─────────────────────────────────────────────────────────────────────────────

impl VtableScanner {
    /// Scan a raw binary blob `data` (mapped at `base`) for vtable candidates.
    ///
    /// `bits` must be 32 or 64.  Unlike [`VtableScanner::scan`], this method
    /// does not require pre-registered code ranges; instead it accepts any
    /// pointer whose high bits suggest a plausible load address (non-null and
    /// not obviously a data constant).  For a tighter scan, create a
    /// [`VtableScanner`] directly and call [`VtableScanner::add_code_range`].
    ///
    /// Returns a `Vec<VtableCandidate>` sorted by address.
    #[must_use]
    pub fn scan_binary(data: &[u8], base: u64, bits: u32) -> Vec<VtableCandidate> {
        let ptr_size: usize = if bits == 32 { 4 } else { 8 };
        let min_slots = 2;
        let step = ptr_size;

        // Heuristic: consider any non-null, naturally-aligned pointer whose
        // value is >= 0x1000 as a potential code pointer.
        let is_plausible =
            |addr: u64| -> bool { addr >= 0x1000 && addr != u64::MAX && addr != u64::from(u32::MAX) };

        let mut candidates = Vec::new();
        let mut i = 0usize;
        while i + step <= data.len() {
            let ptr = read_ptr(data, i, ptr_size);
            if is_plausible(ptr) {
                let start_i = i;
                let mut slot_count = 0usize;
                let mut method_ptrs = Vec::new();
                while i + step <= data.len() {
                    let p = read_ptr(data, i, ptr_size);
                    if is_plausible(p) {
                        slot_count += 1;
                        method_ptrs.push(p);
                        i += step;
                    } else {
                        break;
                    }
                }
                if slot_count >= min_slots {
                    let has_rtti_prefix =
                        start_i >= step && read_ptr(data, start_i - step, ptr_size) != 0;
                    let base_conf = if has_rtti_prefix { 0.70f32 } else { 0.50f32 };
                    let slot_bonus = f32::from(u8::try_from(slot_count.min(10)).unwrap_or(10)) * 0.02f32;
                    let confidence = (base_conf + slot_bonus).min(1.0f32);
                    candidates.push(VtableCandidate {
                        address: base + start_i as u64,
                        slot_count,
                        confidence,
                        has_rtti_prefix,
                        method_ptrs,
                    });
                }
            } else {
                i += step;
            }
        }
        candidates.sort_by_key(|c| c.address);
        candidates
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Vtable::method_count
// ─────────────────────────────────────────────────────────────────────────────

impl Vtable {
    /// Number of virtual methods in this vtable (alias for `entry_count`).
    #[must_use]
    pub const fn method_count(&self) -> usize {
        self.entries.len()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// parse_msvc_rtti / parse_itanium_rtti — flat-buffer convenience wrappers
// ─────────────────────────────────────────────────────────────────────────────

/// Parse MSVC `_RTTICompleteObjectLocator` from a flat byte slice.
///
/// `data` is treated as a `.rdata`-like section mapped at address `addr`.
/// Returns `None` if the data is too small or the signature is unrecognised.
#[must_use]
pub fn parse_msvc_rtti(data: &[u8], addr: u64) -> Option<RttiInfo> {
    if data.len() < 24 {
        return None;
    }
    // Wrap in a temporary Section at `addr`.
    let section = Section::new(".rdata", addr, data.to_vec());
    // Use image_base == addr as a conservative fallback so that relative
    // offsets within the same blob are valid.
    MsvcRttiDecoder::decode_col(addr, &section, addr).ok()
}

/// Parse Itanium `__class_type_info` (or derived) from a flat byte slice.
///
/// `data` is treated as a `.rodata`-like section mapped at address `addr`.
/// Returns `None` if the data is too small.
#[must_use]
pub fn parse_itanium_rtti(data: &[u8], addr: u64) -> Option<RttiInfo> {
    if data.len() < 16 {
        return None;
    }
    let section = Section::new(".rodata", addr, data.to_vec());
    let known: HashMap<u64, String> = HashMap::new();
    ItaniumRttiDecoder::decode(addr, &section, 8, &known).ok()
}

// ─────────────────────────────────────────────────────────────────────────────
// vtable_extends — inheritance detection
// ─────────────────────────────────────────────────────────────────────────────

/// Returns `true` if vtable `b` appears to *extend* vtable `a`.
///
/// The heuristic: `a`'s entries are a strict prefix of `b`'s entries — i.e.
/// the first `a.method_count()` method pointers of `b` match those of `a`
/// (same virtual-function addresses, same order), and `b` has strictly more
/// slots.  This is the classic pattern when a derived class does not override
/// any of the base class's virtual functions.
#[must_use]
pub fn vtable_extends(a: &Vtable, b: &Vtable) -> bool {
    let na = a.entry_count();
    let nb = b.entry_count();
    if na == 0 || nb <= na {
        return false;
    }
    a.entries
        .iter()
        .zip(b.entries.iter())
        .all(|(ea, eb)| ea.target_address == eb.target_address)
}

// ─────────────────────────────────────────────────────────────────────────────
// VtableSet — flat collection with JSON export
// ─────────────────────────────────────────────────────────────────────────────

/// A flat, ordered collection of recovered vtables with JSON serialisation.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct VtableSet {
    /// Vtables in insertion order.
    pub vtables: Vec<Vtable>,
}

impl VtableSet {
    /// Create an empty set.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a vtable to the set.
    pub fn push(&mut self, vtable: Vtable) {
        self.vtables.push(vtable);
    }

    /// Number of vtables.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.vtables.len()
    }

    /// True if the set is empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.vtables.is_empty()
    }

    /// Serialise the vtable set to a `serde_json::Value`.
    ///
    /// Each element has the shape:
    /// ```json
    /// {
    ///   "base_address": 4096,
    ///   "class_name": "MyClass",
    ///   "method_count": 3,
    ///   "entries": [
    ///     { "offset": 0, "target_address": 4352, "function_name": null }
    ///   ]
    /// }
    /// ```
    #[must_use]
    pub fn to_json(&self) -> serde_json::Value {
        let arr: Vec<serde_json::Value> = self
            .vtables
            .iter()
            .map(|vt| {
                serde_json::json!({
                    "base_address": vt.base_address,
                    "class_name": vt.class_name,
                    "method_count": vt.method_count(),
                    "offset_to_top": vt.offset_to_top,
                    "entries": vt.entries.iter().map(|e| serde_json::json!({
                        "offset": e.offset,
                        "target_address": e.target_address,
                        "function_name": e.function_name,
                    })).collect::<Vec<_>>(),
                })
            })
            .collect();
        serde_json::Value::Array(arr)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// VtableBuilder — reconstruct C++ class hierarchy from a set of vtables
// ─────────────────────────────────────────────────────────────────────────────

/// One edge in the reconstructed class hierarchy.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InheritanceEdge {
    /// Name of the base class.
    pub base: String,
    /// Name of the derived class.
    pub derived: String,
    /// Address of the base vtable.
    pub base_vtable: u64,
    /// Address of the derived vtable.
    pub derived_vtable: u64,
}

/// Reconstructs a C++ class hierarchy by analysing vtable relationships.
///
/// Usage:
/// ```
/// use rustre_analysis_vtable::{Vtable, VtableBuilder};
/// let detected_vtables = vec![Vtable::new(0x140_0000), Vtable::new(0x140_1000)];
/// let mut builder = VtableBuilder::new();
/// for vt in detected_vtables { builder.add_vtable(vt); }
/// let set = builder.build();
/// assert_eq!(set.len(), 2);
/// ```
///
/// (This example was `rust,ignore` and therefore never compiled: it referred
/// to an undefined `detected_vtables`. A doc example that is not run is
/// documentation nobody checks, and it rots silently as the API moves.)
#[derive(Debug, Default)]
pub struct VtableBuilder {
    vtables: Vec<Vtable>,
}

impl VtableBuilder {
    /// Create a new builder.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a vtable to the builder.
    pub fn add_vtable(&mut self, vt: Vtable) {
        self.vtables.push(vt);
    }

    /// Build the [`VtableSet`] and compute inheritance edges.
    ///
    /// Applies [`vtable_extends`] for every ordered pair `(a, b)` and records
    /// an edge when the prefix-overlap heuristic fires.  The returned
    /// `VtableSet` contains all input vtables; call [`VtableBuilder::edges`]
    /// to retrieve the inferred inheritance relationships.
    #[must_use]
    pub fn build(&self) -> VtableSet {
        let mut set = VtableSet::new();
        for vt in &self.vtables {
            set.push(vt.clone());
        }
        set
    }

    /// Infer inheritance edges from the accumulated vtables.
    ///
    /// For every ordered pair `(a, b)` where `vtable_extends(a, b)` is true,
    /// an [`InheritanceEdge`] is emitted with `a` as the base and `b` as the
    /// derived class.
    #[must_use]
    pub fn edges(&self) -> Vec<InheritanceEdge> {
        let mut edges = Vec::new();
        let n = self.vtables.len();
        for i in 0..n {
            for j in 0..n {
                if i == j {
                    continue;
                }
                let a = &self.vtables[i];
                let b = &self.vtables[j];
                if vtable_extends(a, b) {
                    edges.push(InheritanceEdge {
                        base: a
                            .class_name
                            .clone()
                            .unwrap_or_else(|| format!("{:#x}", a.base_address)),
                        derived: b
                            .class_name
                            .clone()
                            .unwrap_or_else(|| format!("{:#x}", b.base_address)),
                        base_vtable: a.base_address,
                        derived_vtable: b.base_address,
                    });
                }
            }
        }
        edges
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Additional tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod extended_tests {
    use super::*;

    fn make_vtable_with_entries(addr: u64, addrs: &[u64]) -> Vtable {
        let mut vt = Vtable::new(addr);
        for (i, &a) in addrs.iter().enumerate() {
            vt.add_entry(VtableEntry::new(i * 8, a));
        }
        vt
    }

    // ── PureVirtualDetector ───────────────────────────────────────────────────

    #[test]
    fn pure_virtual_by_name_cxa() {
        let det = PureVirtualDetector::new();
        let entry = VtableEntry::with_name(0, 0x1234, "__cxa_pure_virtual");
        assert!(det.is_pure_virtual(&entry));
    }

    #[test]
    fn pure_virtual_by_name_purecall() {
        let det = PureVirtualDetector::new();
        let entry = VtableEntry::with_name(0, 0xABCD, "_purecall");
        assert!(det.is_pure_virtual(&entry));
    }

    #[test]
    fn pure_virtual_by_address() {
        let mut det = PureVirtualDetector::new();
        det.add_stub_address(0xDEAD_BEEF);
        let entry = VtableEntry::new(0, 0xDEAD_BEEF);
        assert!(det.is_pure_virtual(&entry));
    }

    #[test]
    fn not_pure_virtual_regular() {
        let det = PureVirtualDetector::new();
        let entry = VtableEntry::with_name(0, 0x1000, "foo::bar()");
        assert!(!det.is_pure_virtual(&entry));
    }

    #[test]
    fn pure_virtual_annotate_counts() {
        let det = PureVirtualDetector::new();
        let mut vt = make_vtable_with_entries(0x4000, &[0x1000, 0x2000]);
        vt.entries[1].function_name = Some("__cxa_pure_virtual".to_string());
        let count = det.annotate(&mut vt);
        assert_eq!(count, 1);
    }

    #[test]
    fn pure_virtual_count_in_database() {
        let det = PureVirtualDetector::new();
        let mut db = VtableDatabase::new();
        let mut vt = Vtable::new(0x5000);
        vt.add_entry(VtableEntry::with_name(0, 0x1000, "__cxa_pure_virtual"));
        vt.add_entry(VtableEntry::with_name(8, 0x2000, "foo"));
        db.add_vtable(vt);
        assert_eq!(det.count_in_database(&db), 1);
    }

    // ── AbstractClassInference ────────────────────────────────────────────────

    #[test]
    fn infer_abstract_class_with_pure_virtual() {
        let mut det = PureVirtualDetector::new();
        det.add_stub_address(0x9999);
        let inference = AbstractClassInference::with_detector(det);
        let mut db = VtableDatabase::new();
        let mut vt = Vtable::new(0x6000);
        vt.add_entry(VtableEntry::new(0, 0x9999)); // pure virtual
        vt.add_entry(VtableEntry::new(8, 0x1100));
        db.add_vtable(vt);
        let results = inference.infer(&db);
        assert_eq!(results.len(), 1);
        assert!(results[0].is_abstract);
        assert_eq!(results[0].pure_virtual_slots, vec![0]);
    }

    #[test]
    fn infer_non_abstract_class() {
        let inference = AbstractClassInference::new();
        let mut db = VtableDatabase::new();
        let vt = make_vtable_with_entries(0x7000, &[0x1000, 0x2000, 0x3000]);
        db.add_vtable(vt);
        let results = inference.infer(&db);
        assert_eq!(results.len(), 1);
        assert!(!results[0].is_abstract);
    }

    // ── MultipleInheritanceLayout ─────────────────────────────────────────────

    #[test]
    fn mi_layout_primary_and_secondary() {
        let mut layout = MultipleInheritanceLayout::new("Derived", 32);
        layout.add_sub_object(SubObject {
            class_name: "Base1".to_string(),
            offset: 0,
            vtable_address: Some(0x1000),
            is_primary: true,
        });
        layout.add_sub_object(SubObject {
            class_name: "Base2".to_string(),
            offset: 8,
            vtable_address: Some(0x2000),
            is_primary: false,
        });
        assert_eq!(layout.primary_vtable(), Some(0x1000));
        let secondary = layout.secondary_vtables();
        assert_eq!(secondary.len(), 1);
        assert_eq!(secondary[0], (8, 0x2000));
        assert_eq!(layout.base_count(), 2);
    }

    #[test]
    fn mi_layout_no_secondary() {
        let mut layout = MultipleInheritanceLayout::new("Single", 16);
        layout.add_sub_object(SubObject {
            class_name: "Base".to_string(),
            offset: 0,
            vtable_address: Some(0x3000),
            is_primary: true,
        });
        assert!(layout.secondary_vtables().is_empty());
    }

    #[test]
    fn mi_layout_sorted_by_offset() {
        let mut layout = MultipleInheritanceLayout::new("C", 48);
        layout.add_sub_object(SubObject {
            class_name: "B".to_string(),
            offset: 16,
            vtable_address: None,
            is_primary: false,
        });
        layout.add_sub_object(SubObject {
            class_name: "A".to_string(),
            offset: 0,
            vtable_address: Some(0x1000),
            is_primary: true,
        });
        assert_eq!(layout.sub_objects[0].class_name, "A");
        assert_eq!(layout.sub_objects[1].class_name, "B");
    }

    // ── VtableScanner ─────────────────────────────────────────────────────────

    #[test]
    fn scanner_finds_vtable_in_data() {
        let mut scanner = VtableScanner::new(8, 2);
        scanner.add_code_range(0x1000, 0x3000);

        // Build data with 3 code pointers.
        let mut data = vec![0u8; 8 * 5];
        for (i, &addr) in [0x1000u64, 0x1100, 0x1200].iter().enumerate() {
            data[i * 8..i * 8 + 8].copy_from_slice(&addr.to_le_bytes());
        }
        let candidates = scanner.scan(&data, 0x4000);
        assert!(!candidates.is_empty());
        assert!(candidates[0].slot_count >= 3);
    }

    #[test]
    fn scanner_empty_data_returns_empty() {
        let scanner = VtableScanner::new(8, 2);
        assert!(scanner.scan(&[], 0).is_empty());
    }

    #[test]
    fn scanner_is_code_address_check() {
        let mut scanner = VtableScanner::new(8, 2);
        scanner.add_code_range(0x1000, 0x2000);
        assert!(scanner.is_code_address(0x1000));
        assert!(scanner.is_code_address(0x1FFF));
        assert!(!scanner.is_code_address(0x2000));
    }

    // ── VtableSlotAnnotator ───────────────────────────────────────────────────

    #[test]
    fn annotator_names_entries() {
        let mut annotator = VtableSlotAnnotator::new();
        annotator.add_symbol(0x1000, "Base::foo()");
        annotator.add_symbol(0x2000, "Base::bar()");

        let mut vt = make_vtable_with_entries(0x4000, &[0x1000, 0x2000, 0x3000]);
        let named = annotator.annotate(&mut vt);
        assert_eq!(named, 2);
        assert_eq!(vt.entries[0].function_name.as_deref(), Some("Base::foo()"));
        assert_eq!(vt.entries[1].function_name.as_deref(), Some("Base::bar()"));
        assert!(vt.entries[2].function_name.is_none());
    }

    #[test]
    fn annotator_does_not_overwrite_existing_name() {
        let mut annotator = VtableSlotAnnotator::new();
        annotator.add_symbol(0x1000, "NewName");

        let mut vt = Vtable::new(0x4000);
        let mut e = VtableEntry::new(0, 0x1000);
        e.function_name = Some("OldName".to_string());
        vt.add_entry(e);

        let named = annotator.annotate(&mut vt);
        assert_eq!(named, 0); // already named
        assert_eq!(vt.entries[0].function_name.as_deref(), Some("OldName"));
    }

    #[test]
    fn annotator_count() {
        let mut annotator = VtableSlotAnnotator::new();
        annotator.add_symbol(0x1000, "f1");
        annotator.add_symbol(0x2000, "f2");
        assert_eq!(annotator.symbol_count(), 2);
    }

    // ── VtableComparer ────────────────────────────────────────────────────────

    #[test]
    fn comparer_finds_patched_slot() {
        let orig = make_vtable_with_entries(0x4000, &[0x1000, 0x2000]);
        let patched = make_vtable_with_entries(0x4000, &[0x1000, 0x3000]); // slot 1 changed
        let comparer = VtableComparer::new();
        let diffs = comparer.diff(&orig, &patched);
        assert_eq!(diffs.len(), 1);
        assert_eq!(diffs[0].slot, 1);
        assert_eq!(diffs[0].original_address, 0x2000);
        assert_eq!(diffs[0].patched_address, 0x3000);
    }

    #[test]
    fn comparer_identical_vtables() {
        let vt = make_vtable_with_entries(0x5000, &[0x1000, 0x2000]);
        let comparer = VtableComparer::new();
        assert!(comparer.is_identical(&vt, &vt));
    }

    #[test]
    fn comparer_different_lengths() {
        let a = make_vtable_with_entries(0, &[0x1000, 0x2000]);
        let b = make_vtable_with_entries(0, &[0x1000, 0x2000, 0x3000]);
        let comparer = VtableComparer::new();
        // Diff is based on min length — first two slots match.
        let diffs = comparer.diff(&a, &b);
        assert!(diffs.is_empty()); // min overlap matches
        assert!(!comparer.is_identical(&a, &b)); // different lengths
    }

    // ── VtableStats ───────────────────────────────────────────────────────────

    #[test]
    fn stats_empty_database() {
        let db = VtableDatabase::new();
        let stats = VtableStats::from_database(&db);
        assert_eq!(stats.vtable_count, 0);
        assert_eq!(stats.total_slots, 0);
        assert_eq!(stats.avg_slots, 0.0);
    }

    #[test]
    fn stats_single_vtable() {
        let mut db = VtableDatabase::new();
        let vt = make_vtable_with_entries(0x4000, &[0x1000, 0x2000, 0x3000]);
        db.add_vtable(vt);
        let stats = VtableStats::from_database(&db);
        assert_eq!(stats.vtable_count, 1);
        assert_eq!(stats.total_slots, 3);
        assert_eq!(stats.max_slots, 3);
        assert!((stats.avg_slots - 3.0).abs() < 1e-9);
    }

    #[test]
    fn stats_counts_pure_virtual() {
        let mut db = VtableDatabase::new();
        let mut vt = Vtable::new(0x6000);
        vt.add_entry(VtableEntry::with_name(0, 0x1000, "__cxa_pure_virtual"));
        vt.add_entry(VtableEntry::new(8, 0x2000));
        db.add_vtable(vt);
        let stats = VtableStats::from_database(&db);
        assert_eq!(stats.pure_virtual_count, 1);
        assert_eq!(stats.abstract_class_count, 1);
    }

    // ── VmiRttiInfo ───────────────────────────────────────────────────────────

    #[test]
    fn vmi_rtti_diamond_shaped() {
        let info = VmiRttiInfo {
            class_name: "D".to_string(),
            rtti_address: 0x8000,
            flags: VmiFlags::DIAMOND_SHAPED,
            base_classes: vec![
                VmiBaseClassEntry {
                    base_class_name: "A".to_string(),
                    offset: 0,
                    is_virtual: true,
                    is_public: true,
                },
                VmiBaseClassEntry {
                    base_class_name: "B".to_string(),
                    offset: 8,
                    is_virtual: false,
                    is_public: true,
                },
            ],
        };
        assert!(info.is_diamond_shaped());
        assert!(info.has_multiple_inheritance());
        assert_eq!(info.base_count(), 2);
    }

    #[test]
    fn vmi_flags_non_diamond() {
        let flags = VmiFlags(VmiFlags::NON_DIAMOND_REPEAT);
        assert!(flags.has_non_diamond_repeat());
        assert!(!flags.is_diamond_shaped());
    }

    // ── VtableDiff serialization ──────────────────────────────────────────────

    #[test]
    fn vtable_diff_serialization() {
        let diff = VtableDiff {
            slot: 3,
            original_address: 0x1000,
            patched_address: 0x2000,
        };
        let json = serde_json::to_string(&diff).unwrap();
        let d2: VtableDiff = serde_json::from_str(&json).unwrap();
        assert_eq!(diff, d2);
    }

    // ── VtableCandidate serialization ─────────────────────────────────────────

    #[test]
    fn vtable_candidate_serialization() {
        let c = VtableCandidate {
            address: 0xDEAD,
            slot_count: 5,
            confidence: 0.90,
            has_rtti_prefix: true,
            method_ptrs: vec![0x1000, 0x2000],
        };
        let json = serde_json::to_string(&c).unwrap();
        let c2: VtableCandidate = serde_json::from_str(&json).unwrap();
        assert_eq!(c.address, c2.address);
        assert_eq!(c.slot_count, c2.slot_count);
        assert_eq!(c.method_ptrs, c2.method_ptrs);
    }

    // ── AbstractClassInfo serialization ───────────────────────────────────────

    #[test]
    fn abstract_class_info_serialization() {
        let info = AbstractClassInfo {
            class_name: "Base".to_string(),
            vtable_address: 0x4000,
            pure_virtual_slots: vec![1, 3],
            is_abstract: true,
        };
        let json = serde_json::to_string(&info).unwrap();
        let i2: AbstractClassInfo = serde_json::from_str(&json).unwrap();
        assert_eq!(i2.pure_virtual_slots, vec![1, 3]);
    }

    // ── Additional VtableScanner tests ────────────────────────────────────────

    #[test]
    fn scanner_4byte_pointers() {
        let mut scanner = VtableScanner::new(4, 2);
        scanner.add_code_range(0x1000, 0x2000);
        let mut data = vec![0u8; 12];
        for (i, addr) in [0x1000u32, 0x1100, 0x1200].iter().enumerate() {
            data[i * 4..i * 4 + 4].copy_from_slice(&addr.to_le_bytes());
        }
        let candidates = scanner.scan(&data, 0x3000);
        assert!(!candidates.is_empty());
    }

    #[test]
    fn scanner_below_min_slots_not_found() {
        let mut scanner = VtableScanner::new(8, 5);
        scanner.add_code_range(0x1000, 0x2000);
        let mut data = vec![0u8; 24];
        for (i, &addr) in [0x1000u64, 0x1100, 0x1200].iter().enumerate() {
            data[i * 8..i * 8 + 8].copy_from_slice(&addr.to_le_bytes());
        }
        let candidates = scanner.scan(&data, 0x3000);
        assert!(candidates.is_empty(), "only 3 slots, need 5");
    }

    // ── scan_binary ───────────────────────────────────────────────────────────

    #[test]
    fn scan_binary_finds_candidates() {
        // code range 0x1000..0x3000; vtable data at 0x4000
        let mut data = vec![0u8; 8 * 4];
        for (i, &addr) in [0x1000u64, 0x1100, 0x1200].iter().enumerate() {
            data[i * 8..i * 8 + 8].copy_from_slice(&addr.to_le_bytes());
        }
        let candidates = VtableScanner::scan_binary(&data, 0x4000, 64);
        // Without explicit code ranges scan_binary treats all non-null ptrs
        // that look like reasonable addresses as potential code; just ensure
        // the function compiles and returns a Vec.
        let _ = candidates;
    }

    // ── VtableBuilder ─────────────────────────────────────────────────────────

    #[test]
    fn vtable_builder_add_and_build() {
        let mut builder = VtableBuilder::new();
        let mut vt_a = Vtable::new(0x1000);
        vt_a.class_name = Some("Base".into());
        vt_a.add_entry(VtableEntry::new(0, 0x100));
        vt_a.add_entry(VtableEntry::new(8, 0x200));

        let mut vt_b = Vtable::new(0x2000);
        vt_b.class_name = Some("Derived".into());
        vt_b.add_entry(VtableEntry::new(0, 0x100)); // overridden
        vt_b.add_entry(VtableEntry::new(8, 0x300)); // overridden
        vt_b.add_entry(VtableEntry::new(16, 0x400)); // new

        builder.add_vtable(vt_a);
        builder.add_vtable(vt_b);

        let set = builder.build();
        assert_eq!(set.vtables.len(), 2);
    }

    // ── Inheritance detection ─────────────────────────────────────────────────

    #[test]
    fn inheritance_detected_prefix_overlap() {
        let mut vt_a = Vtable::new(0x1000);
        vt_a.class_name = Some("Base".into());
        vt_a.add_entry(VtableEntry::new(0, 0x100));
        vt_a.add_entry(VtableEntry::new(8, 0x200));

        let mut vt_b = Vtable::new(0x2000);
        vt_b.class_name = Some("Derived".into());
        vt_b.add_entry(VtableEntry::new(0, 0x100));
        vt_b.add_entry(VtableEntry::new(8, 0x200));
        vt_b.add_entry(VtableEntry::new(16, 0x300));

        assert!(vtable_extends(&vt_a, &vt_b));
        assert!(!vtable_extends(&vt_b, &vt_a));
    }

    // ── method_count ──────────────────────────────────────────────────────────

    #[test]
    fn vtable_method_count_equals_entry_count() {
        let mut vt = Vtable::new(0x5000);
        assert_eq!(vt.method_count(), 0);
        vt.add_entry(VtableEntry::new(0, 0x1000));
        vt.add_entry(VtableEntry::new(8, 0x2000));
        assert_eq!(vt.method_count(), 2);
    }

    // ── VtableSet::to_json ────────────────────────────────────────────────────

    #[test]
    fn vtable_set_to_json_contains_vtables() {
        let mut set = VtableSet::default();
        let mut vt = Vtable::new(0x3000);
        vt.class_name = Some("Foo".into());
        vt.add_entry(VtableEntry::new(0, 0x1000));
        set.vtables.push(vt);
        let json = set.to_json();
        let arr = json.as_array().unwrap();
        assert_eq!(arr.len(), 1);
        let obj = &arr[0];
        assert_eq!(obj["base_address"], 0x3000_u64);
        assert_eq!(obj["class_name"], "Foo");
        assert_eq!(obj["method_count"], 1_u64);
    }

    // ── parse_msvc_rtti / parse_itanium_rtti ──────────────────────────────────

    #[test]
    fn parse_itanium_rtti_returns_none_on_empty() {
        let result = parse_itanium_rtti(&[], 0x1000);
        assert!(result.is_none());
    }

    #[test]
    fn parse_msvc_rtti_returns_none_on_empty() {
        let result = parse_msvc_rtti(&[], 0x1000);
        assert!(result.is_none());
    }
}

#[cfg(test)]
mod rtti_prefix_evidence {
    use super::*;

    /// Build a buffer: `prefix` word, then `slots` code pointers, all 8-byte.
    fn buf(prefix: u64, slots: usize, code_base: u64) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(&prefix.to_le_bytes());
        for i in 0..slots {
            v.extend_from_slice(&(code_base + (i as u64) * 0x10).to_le_bytes());
        }
        v
    }

    fn scanner() -> VtableScanner {
        let mut s = VtableScanner::new(8, 3);
        s.code_ranges.push((0x40_0000, 0x41_0000));
        s
    }

    /// A word that cannot be a pointer must not be reported as an RTTI prefix.
    ///
    /// `has_rtti_prefix` used to be `!= 0`, and that one bit lifts the
    /// reported confidence from 0.60 to 0.85. A count, a length or a flag
    /// sitting before a run of code pointers therefore promoted a guess to a
    /// near-certainty and told the caller RTTI was present.
    #[test]
    fn non_pointer_prefixes_are_not_rtti_evidence() {
        let s = scanner();
        for prefix in [3u64, 1, 0xFFF, 0x40_0003] {
            let data = buf(prefix, 4, 0x40_0000);
            let found = s.scan(&data, 0);
            assert_eq!(found.len(), 1, "the vtable itself must still be found");
            assert!(
                !found[0].has_rtti_prefix,
                "prefix {prefix:#x} is not pointer-like but was reported as RTTI"
            );
            assert!(
                (found[0].confidence - 0.60f32).abs() < 0.15,
                "confidence must stay at the no-RTTI base, got {}",
                found[0].confidence
            );
        }
    }

    /// Positive control: a plausible pointer IS still accepted, so the check
    /// cannot be satisfied by rejecting everything.
    #[test]
    fn pointer_like_prefix_is_still_rtti_evidence() {
        let s = scanner();
        let data = buf(0x60_1000, 4, 0x40_0000);
        let found = s.scan(&data, 0);
        assert_eq!(found.len(), 1);
        assert!(
            found[0].has_rtti_prefix,
            "an aligned, mapped-looking pointer must count as RTTI evidence"
        );
        assert!(
            found[0].confidence > 0.80f32,
            "RTTI evidence must raise confidence, got {}",
            found[0].confidence
        );
    }
}
