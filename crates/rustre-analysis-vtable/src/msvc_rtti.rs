//! MSVC Run-Time Type Information (RTTI) structure definitions and parser.
//!
//! Implements the following MSVC RTTI structures:
//! - `TypeDescriptor`
//! - `RTTIObjectLocator` (`_RTTICompleteObjectLocator`)
//! - `RTTIClassHierarchyDescriptor`
//! - `RTTIBaseClassDescriptor`
//! - `MsvcRttiParser` — parse the above from a memory image
//! - `detect_msvc_rtti()` — scan a flat byte slice for RTTI patterns

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;

// ─── TypeDescriptor ───────────────────────────────────────────────────────────

/// MSVC `TypeDescriptor` structure.
///
/// Layout (64-bit):
/// ```text
/// +0x00:  pVFTable  (u64)  — pointer to type_info vtable
/// +0x08:  spare     (u64)  — internal cache pointer (NULL at link time)
/// +0x10:  name      ([u8]) — mangled type name, NUL-terminated (e.g. ".?AVFoo@@")
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TypeDescriptor {
    /// Address of this `TypeDescriptor` in the image.
    pub address: u64,
    /// Pointer to the `type_info` vtable (used to verify validity).
    pub p_vf_table: u64,
    /// Spare/cache pointer (expected 0).
    pub spare: u64,
    /// Raw mangled name (starts with `.?AV` for class or `.?AU` for struct).
    pub mangled_name: String,
    /// Demangled name.
    pub demangled_name: String,
}

impl TypeDescriptor {
    /// True if the mangled name has the expected MSVC RTTI prefix.
    #[must_use]
    pub fn is_valid(&self) -> bool {
        self.mangled_name.starts_with(".?AV") || self.mangled_name.starts_with(".?AU")
    }

    /// Demangle the MSVC mangled name into a C++ qualified name.
    #[must_use]
    pub fn demangle(mangled: &str) -> String {
        let stripped = mangled
            .trim_start_matches(".?AV")
            .trim_start_matches(".?AU")
            .trim_end_matches("@@");
        stripped.replace('@', "::")
    }
}

impl fmt::Display for TypeDescriptor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "TypeDescriptor {{ {} @ {:#x} }}",
            self.demangled_name, self.address
        )
    }
}

// ─── RTTIObjectLocator ────────────────────────────────────────────────────────

/// MSVC `_RTTICompleteObjectLocator` (COL).
///
/// Layout:
/// ```text
/// +0x00: signature      (u32) — 0 for 32-bit, 1 for 64-bit
/// +0x04: offset         (i32) — offset of vtable within the object
/// +0x08: cd_offset      (i32) — constructor displacement offset
/// +0x0C: p_type_desc    (i32) — relative offset to TypeDescriptor (64-bit) or VA (32-bit)
/// +0x10: p_class_hier   (i32) — relative offset to ClassHierarchyDescriptor
/// +0x14: p_self         (i32) — relative offset to this COL (64-bit only)
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RTTIObjectLocator {
    /// Address of this COL in the image.
    pub address: u64,
    /// 0 = 32-bit layout, 1 = 64-bit layout.
    pub signature: u32,
    /// Byte offset of the vtable pointer within the most-derived object.
    pub offset: i32,
    /// Constructor displacement offset.
    pub cd_offset: i32,
    /// Address of the associated `TypeDescriptor`.
    pub type_descriptor_addr: u64,
    /// Address of the `RTTIClassHierarchyDescriptor`.
    pub class_hierarchy_addr: u64,
}

impl RTTIObjectLocator {
    /// True if this is a 64-bit MSVC COL.
    #[must_use]
    pub const fn is_64bit(&self) -> bool {
        self.signature == 1
    }

    /// True if this represents a sub-object (non-zero offset).
    #[must_use]
    pub const fn is_base_subobject(&self) -> bool {
        self.offset != 0
    }
}

impl fmt::Display for RTTIObjectLocator {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "RTTIObjectLocator {{ addr={:#x}, offset={}, sig={} }}",
            self.address, self.offset, self.signature
        )
    }
}

// ─── RTTIClassHierarchyDescriptor ─────────────────────────────────────────────

/// Attributes for `RTTIClassHierarchyDescriptor`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct ClassHierarchyAttributes(pub u32);

impl ClassHierarchyAttributes {
    /// Multiple inheritance flag.
    pub const MULTIPLE_INHERITANCE: u32 = 1;
    /// Virtual inheritance flag.
    pub const VIRTUAL_INHERITANCE: u32 = 2;
    /// Ambiguous inheritance (diamond) flag.
    pub const AMBIGUOUS_INHERITANCE: u32 = 4;

    #[must_use]
    pub const fn has_multiple(self) -> bool {
        self.0 & Self::MULTIPLE_INHERITANCE != 0
    }
    #[must_use]
    pub const fn has_virtual(self) -> bool {
        self.0 & Self::VIRTUAL_INHERITANCE != 0
    }
    #[must_use]
    pub const fn has_diamond(self) -> bool {
        self.0 & Self::AMBIGUOUS_INHERITANCE != 0
    }
}

/// MSVC `_RTTIClassHierarchyDescriptor`.
///
/// Layout:
/// ```text
/// +0x00: signature          (u32)
/// +0x04: attributes         (u32)
/// +0x08: num_base_classes   (u32)
/// +0x0C: p_base_class_array (i32 relative or u32 VA)
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RTTIClassHierarchyDescriptor {
    pub address: u64,
    pub signature: u32,
    pub attributes: ClassHierarchyAttributes,
    pub num_base_classes: u32,
    /// Address of the base class array (array of pointers to `RTTIBaseClassDescriptor`).
    pub base_class_array_addr: u64,
    /// Decoded base class descriptors (populated by `MsvcRttiParser`).
    pub base_classes: Vec<RTTIBaseClassDescriptor>,
}

impl RTTIClassHierarchyDescriptor {
    /// Number of *direct* base classes (all entries minus self).
    #[must_use]
    pub const fn direct_base_count(&self) -> usize {
        self.base_classes.len().saturating_sub(1)
    }
}

// ─── RTTIBaseClassDescriptor ──────────────────────────────────────────────────

/// Placement within the most-derived object for a base class.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct PMDOffset {
    /// Byte offset from the start of the containing object to the beginning of
    /// the base class.  -1 if virtual.
    pub mdisp: i32,
    /// Byte offset of a pointer to the vbtable within the most-derived object
    /// (-1 if not virtual).
    pub pdisp: i32,
    /// Byte offset within the vbtable to the virtual base displacement.
    pub vdisp: i32,
}

/// MSVC `_RTTIBaseClassDescriptor`.
///
/// Layout (64-bit):
/// ```text
/// +0x00: p_type_descriptor (i32 relative)
/// +0x04: num_contained_bases (u32)
/// +0x08: where.mdisp (i32)
/// +0x0C: where.pdisp (i32)
/// +0x10: where.vdisp (i32)
/// +0x14: attributes  (u32)
/// +0x18: p_hierarchy (i32 relative)
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RTTIBaseClassDescriptor {
    pub address: u64,
    /// Address of the base class's `TypeDescriptor`.
    pub type_descriptor_addr: u64,
    /// Name of the base class (from its `TypeDescriptor`).
    pub base_class_name: String,
    /// Number of contained (transitive) base classes.
    pub num_contained_bases: u32,
    /// Placement within the derived object.
    pub where_: PMDOffset,
    /// Attributes (virtual, public, …).
    pub attributes: u32,
}

impl RTTIBaseClassDescriptor {
    /// True if this base class is inherited virtually.
    #[must_use]
    pub const fn is_virtual(&self) -> bool {
        self.where_.pdisp != -1
    }

    /// True if this is a public base class.
    #[must_use]
    pub const fn is_public(&self) -> bool {
        self.attributes & 4 == 0 // bit 2 set = non-public
    }
}

impl fmt::Display for RTTIBaseClassDescriptor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "BaseClass {{ {} @ {:#x}, virtual={} }}",
            self.base_class_name,
            self.address,
            self.is_virtual()
        )
    }
}

// ─── Helper: Memory view ──────────────────────────────────────────────────────

/// Lightweight read-only view of a binary image section.
#[derive(Debug, Clone)]
pub struct ImageSection {
    pub name: String,
    pub base: u64,
    pub data: Vec<u8>,
}

impl ImageSection {
    /// Create a new section.
    #[must_use]
    pub fn new(name: impl Into<String>, base: u64, data: Vec<u8>) -> Self {
        Self {
            name: name.into(),
            base,
            data,
        }
    }

    #[must_use]
    pub const fn end(&self) -> u64 {
        // Saturate: an adversarial `base` near u64::MAX must not wrap.
        self.base.saturating_add(self.data.len() as u64)
    }

    #[must_use]
    pub const fn contains(&self, addr: u64) -> bool {
        addr >= self.base && addr < self.end()
    }

    #[must_use]
    pub fn read_u32_le(&self, addr: u64) -> Option<u32> {
        let off = usize::try_from(addr.checked_sub(self.base)?).ok()?;
        let b: [u8; 4] = self.data.get(off..off.checked_add(4)?)?.try_into().ok()?;
        Some(u32::from_le_bytes(b))
    }

    #[must_use]
    pub fn read_i32_le(&self, addr: u64) -> Option<i32> {
        self.read_u32_le(addr).map(u32::cast_signed)
    }

    #[must_use]
    pub fn read_u64_le(&self, addr: u64) -> Option<u64> {
        let off = usize::try_from(addr.checked_sub(self.base)?).ok()?;
        let b: [u8; 8] = self.data.get(off..off.checked_add(8)?)?.try_into().ok()?;
        Some(u64::from_le_bytes(b))
    }

    #[must_use]
    pub fn read_cstr(&self, addr: u64) -> Option<String> {
        let off = usize::try_from(addr.checked_sub(self.base)?).ok()?;
        let slice = self.data.get(off..)?;
        let end = slice.iter().position(|&b| b == 0)?;
        std::str::from_utf8(&slice[..end]).ok().map(str::to_string)
    }

    /// Read a pointer-sized value (4 or 8 bytes).
    #[must_use]
    pub fn read_ptr(&self, addr: u64, ptr_size: usize) -> Option<u64> {
        match ptr_size {
            4 => self.read_u32_le(addr).map(u64::from),
            8 => self.read_u64_le(addr),
            _ => None,
        }
    }
}

// ─── MsvcRttiParser ───────────────────────────────────────────────────────────

/// Error type for MSVC RTTI parsing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RttiParseError {
    AddressOutOfRange(u64),
    InvalidSignature { addr: u64, sig: u32 },
    InvalidMangledName(u64),
    TooManyBases(u32),
    InternalError(String),
}

impl fmt::Display for RttiParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AddressOutOfRange(a) => write!(f, "address {a:#x} out of range"),
            Self::InvalidSignature { addr, sig } => {
                write!(f, "invalid signature {sig} at {addr:#x}")
            }
            Self::InvalidMangledName(a) => write!(f, "invalid mangled name at {a:#x}"),
            Self::TooManyBases(n) => write!(f, "too many base classes ({n})"),
            Self::InternalError(s) => write!(f, "internal: {s}"),
        }
    }
}

/// MSVC RTTI parser — reads `TypeDescriptors`, COLs, and hierarchy descriptors
/// from an in-memory image.
pub struct MsvcRttiParser {
    /// The .rdata / .data section where RTTI lives.
    pub rdata: ImageSection,
    /// Image base address (used for relative-offset resolution in 64-bit).
    pub image_base: u64,
    /// Pointer size (4 or 8).
    pub ptr_size: usize,
    /// Cache of already-parsed `TypeDescriptors`.
    type_descriptor_cache: HashMap<u64, TypeDescriptor>,
}

impl MsvcRttiParser {
    /// Create a new parser.
    #[must_use]
    pub fn new(rdata: ImageSection, image_base: u64, ptr_size: usize) -> Self {
        Self {
            rdata,
            image_base,
            ptr_size,
            type_descriptor_cache: HashMap::new(),
        }
    }

    /// Resolve a relative offset (as stored in 64-bit COL fields) to an absolute VA.
    #[must_use]
    fn resolve_rel32(&self, addr: u64) -> Option<u64> {
        let rel = i64::from(self.rdata.read_i32_le(addr)?);
        Some(self.image_base.wrapping_add_signed(rel))
    }

    /// Read an absolute or relative pointer depending on the pointer size.
    #[must_use]
    fn read_col_ptr(&self, addr: u64) -> Option<u64> {
        if self.ptr_size == 8 {
            self.resolve_rel32(addr)
        } else {
            self.rdata.read_u32_le(addr).map(u64::from)
        }
    }

    /// Parse a `TypeDescriptor` at `addr`.
    ///
    /// # Errors
    /// Returns `RttiParseError` on parse failure.
    ///
    /// # Panics
    /// Never panics in practice (internal consistency check only).
    pub fn parse_type_descriptor(&mut self, addr: u64) -> Result<&TypeDescriptor, RttiParseError> {
        if self.type_descriptor_cache.contains_key(&addr) {
            return Ok(self.type_descriptor_cache.get(&addr).expect("key confirmed above"));
        }

        let p_vf_table = self
            .rdata
            .read_ptr(addr, self.ptr_size)
            .ok_or(RttiParseError::AddressOutOfRange(addr))?;
        let spare_addr = addr.wrapping_add(self.ptr_size as u64);
        let spare = self
            .rdata
            .read_ptr(spare_addr, self.ptr_size)
            .ok_or(RttiParseError::AddressOutOfRange(spare_addr))?;
        let name_addr = addr.wrapping_add(2 * self.ptr_size as u64);
        let mangled_name = self
            .rdata
            .read_cstr(name_addr)
            .ok_or(RttiParseError::InvalidMangledName(name_addr))?;

        let demangled_name = TypeDescriptor::demangle(&mangled_name);
        let td = TypeDescriptor {
            address: addr,
            p_vf_table,
            spare,
            demangled_name,
            mangled_name,
        };
        self.type_descriptor_cache.insert(addr, td);
        Ok(self.type_descriptor_cache.get(&addr).unwrap())
    }

    /// Parse an `_RTTICompleteObjectLocator` at `col_addr`.
    ///
    /// # Errors
    /// Returns `RttiParseError` on failure.
    pub fn parse_col(&mut self, col_addr: u64) -> Result<RTTIObjectLocator, RttiParseError> {
        let sig = self
            .rdata
            .read_u32_le(col_addr)
            .ok_or(RttiParseError::AddressOutOfRange(col_addr))?;
        if sig > 1 {
            return Err(RttiParseError::InvalidSignature {
                addr: col_addr,
                sig,
            });
        }
        let offset = self
            .rdata
            .read_i32_le(col_addr.wrapping_add(4))
            .ok_or(RttiParseError::AddressOutOfRange(col_addr.wrapping_add(4)))?;
        let cd_offset = self
            .rdata
            .read_i32_le(col_addr.wrapping_add(8))
            .ok_or(RttiParseError::AddressOutOfRange(col_addr.wrapping_add(8)))?;

        let type_descriptor_addr = self
            .read_col_ptr(col_addr.wrapping_add(12))
            .ok_or(RttiParseError::AddressOutOfRange(col_addr.wrapping_add(12)))?;
        let class_hierarchy_addr = self
            .read_col_ptr(col_addr.wrapping_add(16))
            .ok_or(RttiParseError::AddressOutOfRange(col_addr.wrapping_add(16)))?;

        Ok(RTTIObjectLocator {
            address: col_addr,
            signature: sig,
            offset,
            cd_offset,
            type_descriptor_addr,
            class_hierarchy_addr,
        })
    }

    /// Parse an `_RTTIClassHierarchyDescriptor` at `addr`.
    ///
    /// # Errors
    pub fn parse_class_hierarchy(
        &mut self,
        addr: u64,
    ) -> Result<RTTIClassHierarchyDescriptor, RttiParseError> {
        let sig = self
            .rdata
            .read_u32_le(addr)
            .ok_or(RttiParseError::AddressOutOfRange(addr))?;
        let attributes = ClassHierarchyAttributes(
            self.rdata
                .read_u32_le(addr.wrapping_add(4))
                .ok_or(RttiParseError::AddressOutOfRange(addr.wrapping_add(4)))?,
        );
        let num_base_classes = self
            .rdata
            .read_u32_le(addr.wrapping_add(8))
            .ok_or(RttiParseError::AddressOutOfRange(addr.wrapping_add(8)))?;

        if num_base_classes > 256 {
            return Err(RttiParseError::TooManyBases(num_base_classes));
        }

        let base_class_array_addr = self
            .read_col_ptr(addr.wrapping_add(12))
            .ok_or(RttiParseError::AddressOutOfRange(addr.wrapping_add(12)))?;

        // Parse each base class descriptor
        let mut base_classes = Vec::new();
        // The base-class array holds 4-byte image-relative RVAs, NOT pointers:
        // `read_col_ptr` consumes exactly 4 bytes in both the 32- and 64-bit
        // branches. Striding by `ptr_size` skipped every other entry on 64-bit
        // and read the remaining ones off dwords belonging to whatever followed
        // the array, so classes with multiple bases lost half their hierarchy.
        const RVA_SIZE: u64 = 4;
        for i in 0..num_base_classes {
            let entry_addr =
                base_class_array_addr.wrapping_add(u64::from(i).wrapping_mul(RVA_SIZE));
            if let Some(bcd_addr) = self.read_col_ptr(entry_addr)
                && let Ok(bcd) = self.parse_base_class_descriptor(bcd_addr) {
                    base_classes.push(bcd);
                }
        }

        Ok(RTTIClassHierarchyDescriptor {
            address: addr,
            signature: sig,
            attributes,
            num_base_classes,
            base_class_array_addr,
            base_classes,
        })
    }

    /// Parse an `_RTTIBaseClassDescriptor` at `addr`.
    ///
    /// # Errors
    pub fn parse_base_class_descriptor(
        &mut self,
        addr: u64,
    ) -> Result<RTTIBaseClassDescriptor, RttiParseError> {
        let td_addr = self
            .read_col_ptr(addr)
            .ok_or(RttiParseError::AddressOutOfRange(addr))?;
        let td = self.parse_type_descriptor(td_addr)?;
        let base_class_name = td.demangled_name.clone();

        // `pTypeDescriptor` is a 4-byte image-relative RVA, not a pointer —
        // `read_col_ptr` above consumed 4 bytes, not `ptr_size`. Advancing by
        // `ptr_size` read every subsequent field 4 bytes too high on 64-bit
        // images, which shifted num_contained/mdisp/pdisp/vdisp by one slot and
        // made `is_virtual()` (pdisp != -1) report plain bases as virtual.
        const RVA_SIZE: u64 = 4;
        let num_contained = self
            .rdata
            .read_u32_le(addr.wrapping_add(RVA_SIZE))
            .ok_or(RttiParseError::AddressOutOfRange(addr.wrapping_add(RVA_SIZE)))?;

        let where_base = addr.wrapping_add(RVA_SIZE).wrapping_add(4);
        let mdisp = self
            .rdata
            .read_i32_le(where_base)
            .ok_or(RttiParseError::AddressOutOfRange(where_base))?;
        let pdisp = self
            .rdata
            .read_i32_le(where_base.wrapping_add(4))
            .ok_or(RttiParseError::AddressOutOfRange(where_base.wrapping_add(4)))?;
        let vdisp = self
            .rdata
            .read_i32_le(where_base.wrapping_add(8))
            .ok_or(RttiParseError::AddressOutOfRange(where_base.wrapping_add(8)))?;

        let attributes_addr = where_base.wrapping_add(12);
        let attributes = self
            .rdata
            .read_u32_le(attributes_addr)
            .ok_or(RttiParseError::AddressOutOfRange(attributes_addr))?;

        Ok(RTTIBaseClassDescriptor {
            address: addr,
            type_descriptor_addr: td_addr,
            base_class_name,
            num_contained_bases: num_contained,
            where_: PMDOffset {
                mdisp,
                pdisp,
                vdisp,
            },
            attributes,
        })
    }
}

// ─── detect_msvc_rtti ─────────────────────────────────────────────────────────

/// Scan a flat `.rdata`/`.data` section for MSVC RTTI COL signatures.
///
/// Returns a list of `(address, demangled_class_name)` for each valid COL found.
///
/// # Arguments
/// - `data` — raw bytes of the section
/// - `base` — virtual address of the first byte
/// - `image_base` — the PE image base (for 64-bit relative offsets)
/// - `ptr_size` — 4 or 8
#[must_use]
pub fn detect_msvc_rtti(
    data: &[u8],
    base: u64,
    image_base: u64,
    ptr_size: usize,
) -> Vec<(u64, String)> {
    let mut results = Vec::new();
    if data.len() < 20 {
        return results;
    }
    let section = ImageSection::new(".rdata", base, data.to_vec());
    let mut parser = MsvcRttiParser::new(section, image_base, ptr_size);

    let step = 4usize;
    let limit = data.len().saturating_sub(20);
    let mut i = 0;
    while i + step <= limit {
        let addr = base.wrapping_add(i as u64);
        // Signature must be 0 (32-bit) or 1 (64-bit)
        if let Some(sig) = parser.rdata.read_u32_le(addr)
            && sig <= 1
                && let Ok(col) = parser.parse_col(addr)
                    && parser.rdata.contains(col.type_descriptor_addr)
                        && let Ok(td) = parser.parse_type_descriptor(col.type_descriptor_addr)
                            && td.is_valid() {
                                results.push((addr, td.demangled_name.clone()));
                                i += 20; // skip past this COL
                                continue;
                            }
        i += step;
    }
    results
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // Build a minimal .rdata section containing a TypeDescriptor + COL
    fn make_rdata(ptr_size: usize, image_base: u64) -> (ImageSection, u64, u64) {
        let mut data = vec![0u8; 512];
        let base = 0x0040_D000u64;
        // Layout:
        //   +0x000: TypeDescriptor (pVFTable=..., spare=0, name=".?AVFoo@@\0")
        //   +0x100: COL (_RTTICompleteObjectLocator)
        // ptr_size = 8 (64-bit relative offsets)

        let td_addr = base;
        let col_addr = base + 0x100;

        // Write TypeDescriptor
        let vftable: u64 = 0x0041_0000;
        if ptr_size == 8 {
            data[0..8].copy_from_slice(&vftable.to_le_bytes());
            data[8..16].copy_from_slice(&0u64.to_le_bytes()); // spare
            let name = b".?AVFoo@@\0";
            data[16..16 + name.len()].copy_from_slice(name);
        } else {
            data[0..4].copy_from_slice(&(vftable as u32).to_le_bytes());
            data[4..8].copy_from_slice(&0u32.to_le_bytes());
            let name = b".?AVFoo@@\0";
            data[8..8 + name.len()].copy_from_slice(name);
        }

        // Write COL at offset 0x100
        let off = 0x100usize;
        let sig: u32 = u32::from(ptr_size == 8);
        data[off..off.wrapping_add(4)].copy_from_slice(&sig.to_le_bytes());
        data[off.wrapping_add(4)..off.wrapping_add(8)].copy_from_slice(&0i32.to_le_bytes()); // offset
        data[off.wrapping_add(8)..off.wrapping_add(12)].copy_from_slice(&0i32.to_le_bytes()); // cd_offset
        // p_type_descriptor (relative to image_base)
        let td_rel = (td_addr as i64 - image_base as i64) as i32;
        data[off.wrapping_add(12)..off.wrapping_add(16)].copy_from_slice(&td_rel.to_le_bytes());
        // p_class_hierarchy (leave 0)
        let hier_rel = 0i32;
        data[off.wrapping_add(16)..off.wrapping_add(20)].copy_from_slice(&hier_rel.to_le_bytes());

        let section = ImageSection::new(".rdata", base, data);
        (section, td_addr, col_addr)
    }

    #[test]
    fn test_type_descriptor_demangle() {
        assert_eq!(TypeDescriptor::demangle(".?AVFoo@@"), "Foo");
        assert_eq!(TypeDescriptor::demangle(".?AVBar@Ns@@"), "Bar::Ns");
        assert_eq!(TypeDescriptor::demangle(".?AUMyStruct@@"), "MyStruct");
    }

    #[test]
    fn test_type_descriptor_is_valid() {
        let td = TypeDescriptor {
            address: 0,
            p_vf_table: 0,
            spare: 0,
            mangled_name: ".?AVFoo@@".into(),
            demangled_name: "Foo".into(),
        };
        assert!(td.is_valid());
        let bad = TypeDescriptor {
            mangled_name: "notmsvc".into(),
            demangled_name: "notmsvc".into(),
            ..td
        };
        assert!(!bad.is_valid());
    }

    #[test]
    fn test_parse_type_descriptor() {
        let image_base = 0x0040_0000u64;
        let (section, td_addr, _) = make_rdata(8, image_base);
        let mut parser = MsvcRttiParser::new(section, image_base, 8);
        let td = parser.parse_type_descriptor(td_addr).unwrap();
        assert_eq!(td.demangled_name, "Foo");
        assert!(td.is_valid());
    }

    #[test]
    fn test_parse_col() {
        let image_base = 0x0040_0000u64;
        let (section, td_addr, col_addr) = make_rdata(8, image_base);
        let mut parser = MsvcRttiParser::new(section, image_base, 8);
        let col = parser.parse_col(col_addr).unwrap();
        assert_eq!(col.signature, 1);
        assert_eq!(col.offset, 0);
        assert_eq!(col.type_descriptor_addr, td_addr);
        assert!(col.is_64bit());
        assert!(!col.is_base_subobject());
    }

    #[test]
    fn test_pmd_offset_virtual() {
        let pmd = PMDOffset {
            mdisp: 0,
            pdisp: 8,
            vdisp: 0,
        };
        let bcd = RTTIBaseClassDescriptor {
            address: 0,
            type_descriptor_addr: 0,
            base_class_name: "Base".into(),
            num_contained_bases: 0,
            where_: pmd,
            attributes: 0,
        };
        assert!(bcd.is_virtual());
    }

    #[test]
    fn test_pmd_offset_non_virtual() {
        let pmd = PMDOffset {
            mdisp: 0,
            pdisp: -1,
            vdisp: 0,
        };
        let bcd = RTTIBaseClassDescriptor {
            where_: pmd,
            type_descriptor_addr: 0,
            address: 0,
            base_class_name: "Base".into(),
            num_contained_bases: 0,
            attributes: 0,
        };
        assert!(!bcd.is_virtual());
    }

    #[test]
    fn test_class_hierarchy_attributes() {
        let a = ClassHierarchyAttributes(
            ClassHierarchyAttributes::MULTIPLE_INHERITANCE
                | ClassHierarchyAttributes::VIRTUAL_INHERITANCE,
        );
        assert!(a.has_multiple());
        assert!(a.has_virtual());
        assert!(!a.has_diamond());
    }

    #[test]
    fn test_col_display() {
        let col = RTTIObjectLocator {
            address: 0x1000,
            signature: 1,
            offset: 0,
            cd_offset: 0,
            type_descriptor_addr: 0x2000,
            class_hierarchy_addr: 0x3000,
        };
        let s = format!("{col}");
        assert!(s.contains("0x1000"));
    }

    #[test]
    fn test_type_descriptor_display() {
        let td = TypeDescriptor {
            address: 0xABCD,
            p_vf_table: 0,
            spare: 0,
            mangled_name: ".?AVFoo@@".into(),
            demangled_name: "Foo".into(),
        };
        let s = format!("{td}");
        assert!(s.contains("Foo"));
        assert!(s.contains("0xabcd"));
    }

    #[test]
    fn test_detect_msvc_rtti() {
        let image_base = 0x0040_0000u64;
        let (section, _, _) = make_rdata(8, image_base);
        let results = detect_msvc_rtti(&section.data, section.base, image_base, 8);
        // Should find at least one COL with name "Foo"
        assert!(
            results.iter().any(|(_, name)| name == "Foo"),
            "Expected to find Foo in {results:?}"
        );
    }

    #[test]
    fn test_parse_error_display() {
        let e = RttiParseError::AddressOutOfRange(0xDEAD);
        assert!(e.to_string().contains("0xdead"));
        let e2 = RttiParseError::TooManyBases(1000);
        assert!(e2.to_string().contains("1000"));
        let e3 = RttiParseError::InvalidSignature {
            addr: 0x1234,
            sig: 99,
        };
        assert!(e3.to_string().contains("99"));
    }

    #[test]
    fn test_image_section_read() {
        let sec = ImageSection::new(
            ".rdata",
            0x1000,
            vec![0x01, 0x00, 0x00, 0x00, 0x78, 0x56, 0x34, 0x12],
        );
        assert_eq!(sec.read_u32_le(0x1000), Some(1));
        assert_eq!(sec.read_u32_le(0x1004), Some(0x1234_5678));
        assert!(sec.read_u32_le(0x1008).is_none());
    }

    #[test]
    fn test_image_section_cstr() {
        let mut data = vec![0u8; 32];
        let name = b"MyClass\0";
        data[8..8 + name.len()].copy_from_slice(name);
        let sec = ImageSection::new(".rdata", 0x2000, data);
        assert_eq!(sec.read_cstr(0x2008), Some("MyClass".into()));
    }

    #[test]
    fn test_parse_col_32bit() {
        // Build a minimal 32-bit COL
        let image_base = 0u64;
        let base = 0x4000u64;
        // Buffer must be large enough to hold TypeDescriptor at offset 0x100
        // plus 8 bytes of header and a NUL-terminated name (>= 0x120).
        let mut data = vec![0u8; 0x200];
        // TypeDescriptor at offset 0x100
        let td_va = base + 0x100;
        // Set .?AVBar@@ name
        let name_off = 0x108usize; // after 4+4 bytes for vftable and spare (32-bit)
        data[0x100..0x104].copy_from_slice(&0u32.to_le_bytes()); // vftable
        data[0x104..0x108].copy_from_slice(&0u32.to_le_bytes()); // spare
        data[name_off..name_off.wrapping_add(10)].copy_from_slice(b".?AVBar@@\0");
        // COL at offset 0
        data[0..4].copy_from_slice(&0u32.to_le_bytes()); // signature=0 (32-bit)
        data[4..8].copy_from_slice(&0i32.to_le_bytes()); // offset
        data[8..12].copy_from_slice(&0i32.to_le_bytes()); // cd_offset
        data[12..16].copy_from_slice(&(td_va as u32).to_le_bytes()); // p_type_descriptor (VA)
        data[16..20].copy_from_slice(&0u32.to_le_bytes()); // p_class_hierarchy

        let section = ImageSection::new(".rdata", base, data);
        let mut parser = MsvcRttiParser::new(section, image_base, 4);
        let col = parser.parse_col(base).unwrap();
        assert_eq!(col.signature, 0);
        assert_eq!(col.type_descriptor_addr, td_va);
        let td = parser.parse_type_descriptor(td_va).unwrap();
        assert_eq!(td.demangled_name, "Bar");
    }

    #[test]
    fn test_bcd_display() {
        let bcd = RTTIBaseClassDescriptor {
            address: 0x5000,
            type_descriptor_addr: 0x6000,
            base_class_name: "Animal".into(),
            num_contained_bases: 0,
            where_: PMDOffset::default(),
            attributes: 0,
        };
        let s = format!("{bcd}");
        assert!(s.contains("Animal"));
        assert!(s.contains("0x5000"));
    }

    #[test]
    fn test_parse_too_many_bases_error() {
        let base = 0x1000u64;
        let mut data = vec![0u8; 64];
        // ClassHierarchyDescriptor with num_base_classes = 1000
        data[0..4].copy_from_slice(&0u32.to_le_bytes()); // sig
        data[4..8].copy_from_slice(&0u32.to_le_bytes()); // attr
        data[8..12].copy_from_slice(&1000u32.to_le_bytes()); // num_bases
        data[12..16].copy_from_slice(&0u32.to_le_bytes()); // p_base_array

        let section = ImageSection::new(".rdata", base, data);
        let mut parser = MsvcRttiParser::new(section, 0, 4);
        let err = parser.parse_class_hierarchy(base).unwrap_err();
        assert!(matches!(err, RttiParseError::TooManyBases(1000)));
    }

    #[test]
    fn test_detect_empty_data() {
        let results = detect_msvc_rtti(&[], 0x1000, 0, 8);
        assert!(results.is_empty());
    }

    // ─── Adversarial / hardening regression tests ───────────────────────────

    #[test]
    fn regress_image_section_high_base_no_wrap() {
        // base near u64::MAX: end() must saturate so contains() stays correct.
        let sec = ImageSection::new(".x", u64::MAX - 4, vec![0u8; 16]);
        assert!(sec.contains(u64::MAX - 1));
        assert!(sec.read_u32_le(u64::MAX - 4).is_some());
    }

    use crate::test_prng::XorShift;

    #[test]
    fn fuzz_msvc_parser_no_panic_on_garbage() {
        let mut rng = XorShift(0xfeed_face_dead_10cc);
        for _ in 0..300 {
            let len = (rng.next() % 128) as usize;
            let data: Vec<u8> = (0..len).map(|_| rng.next() as u8).collect();
            let base = match rng.next() % 3 {
                0 => rng.next() % 0x1_0000,
                1 => u64::MAX - (rng.next() % 64),
                _ => rng.next(),
            };
            let ptr_size = if rng.next() & 1 == 0 { 4 } else { 8 };
            let sec = ImageSection::new(".rdata", base, data.clone());
            let mut parser = MsvcRttiParser::new(sec, rng.next() % 0x1_0000, ptr_size);
            for _ in 0..8 {
                let addr = base.wrapping_add(rng.next() % 160);
                let _ = parser.parse_col(addr);
                let _ = parser.parse_type_descriptor(addr);
                let _ = parser.parse_class_hierarchy(addr);
                let _ = parser.parse_base_class_descriptor(addr);
            }
            let _ = detect_msvc_rtti(&data, base, rng.next() % 0x1_0000, ptr_size);
        }
    }
}
