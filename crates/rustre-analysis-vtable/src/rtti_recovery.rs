//! Advanced RTTI recovery for `rustre-analysis-vtable`.
//!
//! Implements complete reconstruction of both MSVC and GCC/Itanium RTTI
//! structures, producing a unified inheritance hierarchy.
//!
//! ## MSVC RTTI
//!
//! MSVC places these structures adjacent to each vtable:
//!
//! ```text
//! RTTICompleteObjectLocator (COL)
//!   → TypeDescriptor (type_info)
//!   → RTTIClassHierarchyDescriptor (CHD)
//!       → RTTIBaseClassDescriptor[] (BCD)
//!           → TypeDescriptor
//! ```
//!
//! ## GCC / Itanium RTTI
//!
//! GCC uses the Itanium C++ ABI:
//!
//! ```text
//! __class_type_info (simple class, no bases)
//! __si_class_type_info (single-inheritance)
//!   → __class_type_info*  (one base)
//! __vmi_class_type_info (multiple/virtual inheritance)
//!   → base_class_type_info[] (each with flags and offset)
//! ```

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

// ─────────────────────────────────────────────────────────────────────────────
// MSVC RTTI structures
// ─────────────────────────────────────────────────────────────────────────────

/// MSVC `RTTICompleteObjectLocator` (COL).
///
/// In x86-64 PE binaries the fields are RVAs (32-bit, relative to image base).
/// In x86-32 they are absolute pointers.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MsvcCol {
    /// Signature: 0 for x86, 1 for x64.
    pub signature: u32,
    /// Offset of the complete object from the subobject containing this vtable.
    pub offset: i32,
    /// Offset of the constructor displacement.
    pub cd_offset: i32,
    /// RVA / pointer to `TypeDescriptor`.
    pub type_descriptor_rva: u32,
    /// RVA / pointer to `RTTIClassHierarchyDescriptor`.
    pub class_hierarchy_descriptor_rva: u32,
    /// (x64 only) RVA of the COL itself (self-referencing).
    pub object_base_rva: u32,
    /// Virtual address where the COL was found.
    pub va: u64,
}

/// MSVC `TypeDescriptor` (which wraps `std::type_info`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MsvcTypeDescriptor {
    /// Virtual address of the `__RTTITypeDescriptor` structure.
    pub va: u64,
    /// Pointer to the `type_info` vtable (used as a validity check).
    pub vftable_ptr: u64,
    /// Spare pointer (always 0 in most ABIs).
    pub spare: u64,
    /// Mangled type name (starts with `.?A` for classes, `.?U` for structs,
    /// `.?V` for POD).
    pub name: String,
}

impl MsvcTypeDescriptor {
    /// Return `true` if the mangled name looks like a valid MSVC type name.
    #[must_use]
    pub fn is_valid(&self) -> bool {
        self.name.starts_with(".?A")
            || self.name.starts_with(".?U")
            || self.name.starts_with(".?V")
            || self.name.starts_with(".?W") // enum
    }

    /// Attempt to demangle the MSVC type name into a human-readable class name.
    #[must_use]
    pub fn demangled_name(&self) -> String {
        // Strip `.?AV` / `.?AU` prefix and trailing `@@` suffix.
        let stripped = self
            .name
            .trim_start_matches(".?AV")
            .trim_start_matches(".?AU")
            .trim_start_matches(".?A")
            .trim_end_matches("@@");
        // Replace `@` with `::`.
        stripped.replace('@', "::")
    }
}

/// MSVC `RTTIClassHierarchyDescriptor`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MsvcChd {
    /// Signature (always 0).
    pub signature: u32,
    /// Hierarchy attributes (bit 0 = multiple inheritance, bit 1 = virtual).
    pub attributes: u32,
    /// Number of base classes (including the class itself).
    pub num_base_classes: u32,
    /// RVA of the base class array.
    pub base_class_array_rva: u32,
    /// Virtual address where the CHD was found.
    pub va: u64,
}

impl MsvcChd {
    /// Whether the hierarchy uses multiple inheritance.
    #[must_use]
    pub const fn has_multiple_inheritance(&self) -> bool {
        self.attributes & 1 != 0
    }

    /// Whether the hierarchy uses virtual inheritance.
    #[must_use]
    pub const fn has_virtual_inheritance(&self) -> bool {
        self.attributes & 2 != 0
    }
}

/// MSVC `RTTIBaseClassDescriptor`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MsvcBcd {
    /// RVA of the `TypeDescriptor` for the base class.
    pub type_descriptor_rva: u32,
    /// Number of contained bases.
    pub num_contained_bases: u32,
    /// PMD: `mdisp` (member displacement).
    pub mdisp: i32,
    /// PMD: `pdisp` (vtable pointer displacement, -1 if not virtual).
    pub pdisp: i32,
    /// PMD: `vdisp` (displacement within vtable of the virtual base ptr).
    pub vdisp: i32,
    /// Attributes (bit 0 = non-polymorphic, bit 1 = ambiguous, etc.).
    pub attributes: u32,
    /// Virtual address of this BCD.
    pub va: u64,
}

impl MsvcBcd {
    /// Whether this is a virtual base.
    #[must_use]
    pub const fn is_virtual_base(&self) -> bool {
        self.pdisp != -1
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// GCC / Itanium RTTI structures
// ─────────────────────────────────────────────────────────────────────────────

/// The Itanium RTTI kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ItaniumRttiKind {
    /// No bases (`__class_type_info`).
    Simple,
    /// Single non-virtual inheritance (`__si_class_type_info`).
    SingleInheritance,
    /// Multiple or virtual inheritance (`__vmi_class_type_info`).
    MultipleInheritance,
}

/// GCC `__class_type_info` (simple class with no bases).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GccTypeInfo {
    /// Virtual address of this `type_info`.
    pub va: u64,
    /// Pointer to the vtable of the appropriate `__*_type_info` class.
    pub typeinfo_vtable_ptr: u64,
    /// Pointer to the mangled type name (null-terminated C string).
    pub name_ptr: u64,
    /// Demangled / raw name.
    pub name: String,
    /// RTTI kind.
    pub kind: ItaniumRttiKind,
    /// Base classes (for `si` and `vmi` kinds).
    pub bases: Vec<GccBaseClass>,
}

impl GccTypeInfo {
    /// Return `true` if the type has any bases.
    #[must_use]
    pub const fn has_bases(&self) -> bool {
        !self.bases.is_empty()
    }
}

/// One base-class entry in a `__vmi_class_type_info`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GccBaseClass {
    /// Pointer to the base's `__class_type_info`.
    pub base_type_ptr: u64,
    /// Offset flags: `offset_flags & ~0x3` = byte offset; bit 0 = virtual;
    /// bit 1 = public.
    pub offset_flags: i64,
}

impl GccBaseClass {
    /// Byte offset of the base subobject within the derived class.
    #[must_use]
    pub const fn offset(&self) -> i64 {
        self.offset_flags >> 8
    }

    /// Whether the base is inherited virtually.
    #[must_use]
    pub const fn is_virtual(&self) -> bool {
        self.offset_flags & 1 != 0
    }

    /// Whether the base is public.
    #[must_use]
    pub const fn is_public(&self) -> bool {
        self.offset_flags & 2 != 0
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Unified class node
// ─────────────────────────────────────────────────────────────────────────────

/// The compiler ABI that produced the RTTI.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RttiAbi {
    Msvc,
    Itanium, // GCC, Clang, Intel ICC on Linux/macOS
}

/// A class recovered from RTTI, normalised across both ABIs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RttiClass {
    /// ABI that provided this class.
    pub abi: RttiAbi,
    /// Virtual address of the RTTI structure (COL for MSVC, `type_info` for GCC).
    pub rtti_va: u64,
    /// Demangled class name.
    pub name: String,
    /// Mangled name (as stored in the binary).
    pub mangled_name: String,
    /// Virtual address of the primary vtable for this class.
    pub vtable_va: Option<u64>,
    /// Direct base classes by their RTTI virtual addresses.
    pub base_rtti_vas: Vec<u64>,
    /// Whether any base is virtual.
    pub has_virtual_base: bool,
    /// Whether the class uses multiple inheritance.
    pub has_multiple_inheritance: bool,
}

// ─────────────────────────────────────────────────────────────────────────────
// RTTI database
// ─────────────────────────────────────────────────────────────────────────────

/// All RTTI classes recovered from a binary.
#[derive(Debug, Default)]
pub struct RttiDatabase {
    /// Classes keyed by their RTTI virtual address.
    pub classes: HashMap<u64, RttiClass>,
    /// Map from vtable VA → RTTI VA (for fast vtable → class lookup).
    pub vtable_to_rtti: HashMap<u64, u64>,
}

impl RttiDatabase {
    /// Create an empty database.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert a class.
    pub fn insert(&mut self, class: RttiClass) {
        if let Some(vtbl) = class.vtable_va {
            self.vtable_to_rtti.insert(vtbl, class.rtti_va);
        }
        self.classes.insert(class.rtti_va, class);
    }

    /// Look up a class by vtable address.
    #[must_use]
    pub fn class_by_vtable(&self, vtable_va: u64) -> Option<&RttiClass> {
        let rtti_va = self.vtable_to_rtti.get(&vtable_va)?;
        self.classes.get(rtti_va)
    }

    /// Return all direct base classes of `class`.
    #[must_use]
    pub fn direct_bases(&self, class: &RttiClass) -> Vec<&RttiClass> {
        class
            .base_rtti_vas
            .iter()
            .filter_map(|va| self.classes.get(va))
            .collect()
    }

    /// Number of classes in the database.
    #[must_use]
    pub fn class_count(&self) -> usize {
        self.classes.len()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// MSVC RTTI parser (byte-level, 64-bit PE)
// ─────────────────────────────────────────────────────────────────────────────

/// Attempt to parse an MSVC `RTTICompleteObjectLocator` from `data` at
/// `offset`.  Returns `None` if the data does not look like a valid COL.
#[must_use]
pub fn parse_msvc_col(data: &[u8], offset: usize, va: u64) -> Option<MsvcCol> {
    // checked_add: a caller-controlled `offset` near usize::MAX must not wrap the
    // bounds guard and then panic on slice indexing below.
    if offset.checked_add(24)? > data.len() {
        return None;
    }
    let sig = u32::from_le_bytes(data[offset..offset + 4].try_into().ok()?);
    let off = i32::from_le_bytes(data[offset + 4..offset + 8].try_into().ok()?);
    let cd  = i32::from_le_bytes(data[offset + 8..offset + 12].try_into().ok()?);
    let td  = u32::from_le_bytes(data[offset + 12..offset + 16].try_into().ok()?);
    let chd = u32::from_le_bytes(data[offset + 16..offset + 20].try_into().ok()?);
    let obj = if sig == 1 && offset + 24 <= data.len() {
        u32::from_le_bytes(data[offset + 20..offset + 24].try_into().ok()?)
    } else {
        0
    };

    // Validation: signature must be 0 or 1.
    if sig > 1 {
        return None;
    }

    Some(MsvcCol {
        signature: sig,
        offset: off,
        cd_offset: cd,
        type_descriptor_rva: td,
        class_hierarchy_descriptor_rva: chd,
        object_base_rva: obj,
        va,
    })
}

/// Parse a null-terminated MSVC type name from `data` at `offset`.
#[must_use]
pub fn parse_msvc_type_name(data: &[u8], offset: usize) -> Option<String> {
    let slice = data.get(offset..)?;
    let end = slice.iter().position(|&b| b == 0)?;
    String::from_utf8(data[offset..offset + end].to_vec()).ok()
}

// ─────────────────────────────────────────────────────────────────────────────
// GCC RTTI parser (byte-level, 64-bit ELF)
// ─────────────────────────────────────────────────────────────────────────────

/// Parse a GCC `__class_type_info` from `data` at `offset`.
///
/// The minimal structure (simple class) is:
/// ```text
/// u64  vtable_ptr
/// u64  name_ptr
/// ```
#[must_use]
pub fn parse_gcc_type_info_simple(
    data: &[u8],
    offset: usize,
    va: u64,
    name: String,
) -> Option<GccTypeInfo> {
    if offset.checked_add(16)? > data.len() {
        return None;
    }
    let vtbl = u64::from_le_bytes(data[offset..offset + 8].try_into().ok()?);
    let name_ptr = u64::from_le_bytes(data[offset + 8..offset + 16].try_into().ok()?);

    Some(GccTypeInfo {
        va,
        typeinfo_vtable_ptr: vtbl,
        name_ptr,
        name,
        kind: ItaniumRttiKind::Simple,
        bases: Vec::new(),
    })
}

/// Parse a `__si_class_type_info` (single inheritance) from `data` at `offset`.
///
/// Structure:
/// ```text
/// u64  vtable_ptr
/// u64  name_ptr
/// u64  base_type_ptr
/// ```
#[must_use]
pub fn parse_gcc_si_type_info(
    data: &[u8],
    offset: usize,
    va: u64,
    name: String,
) -> Option<GccTypeInfo> {
    if offset.checked_add(24)? > data.len() {
        return None;
    }
    let vtbl = u64::from_le_bytes(data[offset..offset + 8].try_into().ok()?);
    let name_ptr = u64::from_le_bytes(data[offset + 8..offset + 16].try_into().ok()?);
    let base_ptr = u64::from_le_bytes(data[offset + 16..offset + 24].try_into().ok()?);

    Some(GccTypeInfo {
        va,
        typeinfo_vtable_ptr: vtbl,
        name_ptr,
        name,
        kind: ItaniumRttiKind::SingleInheritance,
        bases: vec![GccBaseClass {
            base_type_ptr: base_ptr,
            offset_flags: 2, // public, offset=0
        }],
    })
}

/// Parse a `__vmi_class_type_info` (multiple/virtual inheritance).
///
/// Structure:
/// ```text
/// u64  vtable_ptr
/// u64  name_ptr
/// u32  flags
/// u32  base_count
/// [base_count × (u64 base_type_ptr, i64 offset_flags)]
/// ```
#[must_use]
pub fn parse_gcc_vmi_type_info(
    data: &[u8],
    offset: usize,
    va: u64,
    name: String,
) -> Option<GccTypeInfo> {
    if offset.checked_add(24)? > data.len() {
        return None;
    }
    let vtbl = u64::from_le_bytes(data[offset..offset + 8].try_into().ok()?);
    let name_ptr = u64::from_le_bytes(data[offset + 8..offset + 16].try_into().ok()?);
    let base_count = u32::from_le_bytes(data[offset + 20..offset + 24].try_into().ok()?) as usize;

    // Guard against attacker-controlled base_count causing arithmetic overflow.
    let base_count = base_count.min(1024);
    let required = 24usize.checked_add(base_count.checked_mul(16)?)?;
    if offset.checked_add(required)? > data.len() {
        return None;
    }

    let mut bases = Vec::with_capacity(base_count);
    for i in 0..base_count {
        let boff = offset + 24 + i * 16;
        let base_ptr = u64::from_le_bytes(data[boff..boff + 8].try_into().ok()?);
        let off_flags = i64::from_le_bytes(data[boff + 8..boff + 16].try_into().ok()?);
        bases.push(GccBaseClass {
            base_type_ptr: base_ptr,
            offset_flags: off_flags,
        });
    }

    Some(GccTypeInfo {
        va,
        typeinfo_vtable_ptr: vtbl,
        name_ptr,
        name,
        kind: ItaniumRttiKind::MultipleInheritance,
        bases,
    })
}

// ─────────────────────────────────────────────────────────────────────────────
// Hierarchy reconstruction
// ─────────────────────────────────────────────────────────────────────────────

/// Build a complete inheritance hierarchy from an RTTI database using BFS.
///
/// Returns a map from class name to list of direct base class names.
#[must_use]
pub fn reconstruct_hierarchy(db: &RttiDatabase) -> HashMap<String, Vec<String>> {
    let mut hierarchy: HashMap<String, Vec<String>> = HashMap::new();

    // `db.classes` is keyed by `rtti_va`, but this loop RE-KEYS on `class.name`.
    // Two distinct RTTI structures can carry the same demangled name — COMDAT
    // folding, template instantiations, or RTTI duplicated across translation
    // units — and then the `insert` below is last-writer-wins.
    //
    // Iterating `db.classes.values()` directly made that winner depend on
    // HashMap iteration order, which Rust's RandomState re-seeds every run: the
    // SAME binary could produce DIFFERENT inheritance hierarchies on two
    // analyses. Sort by `rtti_va` first so the surviving entry is always the
    // highest-addressed one, deterministically.
    let mut by_va: Vec<&RttiClass> = db.classes.values().collect();
    by_va.sort_unstable_by_key(|c| c.rtti_va);

    for class in by_va {
        let bases: Vec<String> = db
            .direct_bases(class)
            .iter()
            .map(|b| b.name.clone())
            .collect();
        hierarchy.insert(class.name.clone(), bases);
    }

    hierarchy
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn msvc_col_parse_x64() {
        // Signature=1, offset=0, cd=0, type_desc_rva=0x100, chd_rva=0x200, obj_rva=0x300
        let mut data = vec![0u8; 28];
        data[0..4].copy_from_slice(&1u32.to_le_bytes()); // sig
        data[4..8].copy_from_slice(&0i32.to_le_bytes()); // offset
        data[8..12].copy_from_slice(&0i32.to_le_bytes()); // cd
        data[12..16].copy_from_slice(&0x100u32.to_le_bytes()); // td rva
        data[16..20].copy_from_slice(&0x200u32.to_le_bytes()); // chd rva
        data[20..24].copy_from_slice(&0x300u32.to_le_bytes()); // obj rva

        let col = parse_msvc_col(&data, 0, 0x140001000).unwrap();
        assert_eq!(col.signature, 1);
        assert_eq!(col.type_descriptor_rva, 0x100);
        assert_eq!(col.class_hierarchy_descriptor_rva, 0x200);
    }

    #[test]
    fn msvc_col_parse_invalid_signature() {
        let mut data = vec![0u8; 24];
        data[0..4].copy_from_slice(&0xFF_u32.to_le_bytes()); // invalid sig
        assert!(parse_msvc_col(&data, 0, 0).is_none());
    }

    #[test]
    fn msvc_type_descriptor_demangle() {
        let td = MsvcTypeDescriptor {
            va: 0x1000,
            vftable_ptr: 0x2000,
            spare: 0,
            name: ".?AVMyClass@@".into(),
        };
        assert!(td.is_valid());
        let demangled = td.demangled_name();
        assert!(demangled.contains("MyClass"), "got: {demangled}");
    }

    #[test]
    fn msvc_bcd_virtual_base() {
        let bcd = MsvcBcd {
            type_descriptor_rva: 0,
            num_contained_bases: 0,
            mdisp: 0,
            pdisp: 0, // != -1 → virtual
            vdisp: 0,
            attributes: 0,
            va: 0,
        };
        assert!(bcd.is_virtual_base());
    }

    #[test]
    fn gcc_si_type_info_parse() {
        let mut data = vec![0u8; 24];
        // vtbl=0x1000, name_ptr=0x2000, base_ptr=0x3000
        data[0..8].copy_from_slice(&0x1000u64.to_le_bytes());
        data[8..16].copy_from_slice(&0x2000u64.to_le_bytes());
        data[16..24].copy_from_slice(&0x3000u64.to_le_bytes());

        let ti = parse_gcc_si_type_info(&data, 0, 0x5000, "Derived".into()).unwrap();
        assert_eq!(ti.kind, ItaniumRttiKind::SingleInheritance);
        assert_eq!(ti.bases.len(), 1);
        assert_eq!(ti.bases[0].base_type_ptr, 0x3000);
    }

    #[test]
    fn gcc_vmi_type_info_parse() {
        let mut data = vec![0u8; 24 + 2 * 16];
        // base_count = 2
        data[20..24].copy_from_slice(&2u32.to_le_bytes());
        // Base 0
        data[24..32].copy_from_slice(&0x1000u64.to_le_bytes());
        let off0: i64 = 0x102; // public, offset=1
        data[32..40].copy_from_slice(&off0.to_le_bytes());
        // Base 1
        data[40..48].copy_from_slice(&0x2000u64.to_le_bytes());
        let off1: i64 = 0x201; // virtual, offset=2
        data[48..56].copy_from_slice(&off1.to_le_bytes());

        let ti = parse_gcc_vmi_type_info(&data, 0, 0x6000, "Multi".into()).unwrap();
        assert_eq!(ti.bases.len(), 2);
        assert_eq!(ti.bases[1].base_type_ptr, 0x2000);
        assert!(ti.bases[1].is_virtual());
    }

    #[test]
    fn rtti_database_lookup_by_vtable() {
        let mut db = RttiDatabase::new();
        db.insert(RttiClass {
            abi: RttiAbi::Itanium,
            rtti_va: 0xA000,
            name: "Foo".into(),
            mangled_name: "_ZTI3Foo".into(),
            vtable_va: Some(0xB000),
            base_rtti_vas: Vec::new(),
            has_virtual_base: false,
            has_multiple_inheritance: false,
        });
        let cls = db.class_by_vtable(0xB000).unwrap();
        assert_eq!(cls.name, "Foo");
    }

    #[test]
    fn reconstruct_hierarchy_simple() {
        let mut db = RttiDatabase::new();
        db.insert(RttiClass {
            abi: RttiAbi::Msvc,
            rtti_va: 0x100,
            name: "Base".into(),
            mangled_name: ".?AVBase@@".into(),
            vtable_va: None,
            base_rtti_vas: Vec::new(),
            has_virtual_base: false,
            has_multiple_inheritance: false,
        });
        db.insert(RttiClass {
            abi: RttiAbi::Msvc,
            rtti_va: 0x200,
            name: "Derived".into(),
            mangled_name: ".?AVDerived@@".into(),
            vtable_va: None,
            base_rtti_vas: vec![0x100],
            has_virtual_base: false,
            has_multiple_inheritance: false,
        });
        let h = reconstruct_hierarchy(&db);
        let derived_bases = h.get("Derived").unwrap();
        assert_eq!(derived_bases, &["Base"]);
    }

    /// Two RTTI structures sharing one demangled name must resolve
    /// DETERMINISTICALLY, not by HashMap iteration order.
    ///
    /// `reconstruct_hierarchy` re-keys a `HashMap<u64, RttiClass>` (keyed by
    /// rtti_va) onto class NAME, so name collisions — COMDAT folding, template
    /// instantiations, RTTI duplicated across translation units — make the
    /// `insert` last-writer-wins. Iterating `.values()` raw let RandomState
    /// decide the winner, so the same binary could yield different hierarchies
    /// on two runs. Sorting by rtti_va makes the highest VA win, every time.
    #[test]
    fn reconstruct_hierarchy_is_deterministic_under_name_collision() {
        let mk = |va: u64, name: &str, bases: Vec<u64>| RttiClass {
            abi: RttiAbi::Msvc,
            rtti_va: va,
            name: name.into(),
            mangled_name: format!(".?AV{name}@@"),
            vtable_va: None,
            base_rtti_vas: bases,
            has_virtual_base: false,
            has_multiple_inheritance: false,
        };

        // Build the same database repeatedly; each build gets a fresh
        // RandomState, so an order-dependent result would drift across runs.
        let mut seen = std::collections::HashSet::new();
        for _ in 0..32 {
            let mut db = RttiDatabase::new();
            db.insert(mk(0x100, "BaseA", vec![]));
            db.insert(mk(0x200, "BaseB", vec![]));
            // Two DIFFERENT rtti_vas, one shared name, different bases.
            db.insert(mk(0x300, "Dup", vec![0x100]));
            db.insert(mk(0x400, "Dup", vec![0x200]));

            let h = reconstruct_hierarchy(&db);
            seen.insert(h.get("Dup").cloned().unwrap_or_default());
        }
        assert_eq!(
            seen.len(),
            1,
            "hierarchy for a colliding name must not depend on hash order, got {seen:?}"
        );
        // Highest rtti_va (0x400) wins, so its base (BaseB) is the survivor.
        assert_eq!(seen.into_iter().next().unwrap(), vec!["BaseB".to_string()]);
    }

    // ─── Adversarial / hardening regression tests ───────────────────────────

    use crate::test_prng::XorShift;

    #[test]
    fn regress_parse_msvc_col_huge_offset_no_panic() {
        // Previously `offset + 24` wrapped, passed the bounds guard, and the
        // subsequent slice indexing panicked.
        let data = vec![0u8; 64];
        assert!(parse_msvc_col(&data, usize::MAX - 10, 0).is_none());
        assert!(parse_msvc_col(&data, usize::MAX, 0).is_none());
    }

    #[test]
    fn regress_parse_gcc_huge_offset_no_panic() {
        let data = vec![0u8; 64];
        assert!(parse_gcc_type_info_simple(&data, usize::MAX - 8, 0, "X".into()).is_none());
        assert!(parse_gcc_si_type_info(&data, usize::MAX - 20, 0, "X".into()).is_none());
        assert!(parse_gcc_vmi_type_info(&data, usize::MAX - 20, 0, "X".into()).is_none());
    }

    #[test]
    fn fuzz_parsers_no_panic_on_garbage() {
        let mut rng = XorShift(0x1234_5678_9abc_def0);
        for _ in 0..2000 {
            let len = (rng.next() % 128) as usize;
            let data: Vec<u8> = (0..len).map(|_| rng.next() as u8).collect();
            // Offsets: in-range, near-end, and near-usize::MAX.
            let offsets = [
                (rng.next() % 160) as usize,
                len.saturating_sub(1),
                usize::MAX - (rng.next() % 32) as usize,
            ];
            for &off in &offsets {
                let _ = parse_msvc_col(&data, off, rng.next());
                let _ = parse_msvc_type_name(&data, off);
                let _ = parse_gcc_type_info_simple(&data, off, 0, "N".into());
                let _ = parse_gcc_si_type_info(&data, off, 0, "N".into());
                let _ = parse_gcc_vmi_type_info(&data, off, 0, "N".into());
            }
        }
    }
}
