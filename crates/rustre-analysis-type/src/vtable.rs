//! `vtable` — C++ virtual-table and RTTI recovery.
//!
//! This module implements:
//! - Vtable candidate detection by scanning for arrays of code pointers in
//!   read-only data sections.
//! - MSVC RTTI parsing (`RTTICompleteObjectLocator` → `RTTITypeDescriptor`).
//! - Itanium ABI typeinfo parsing (`__si_class_type_info`, `__vmi_class_type_info`).
//! - Class hierarchy construction from all found vtables.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::constraints::Address;

// ── Section descriptor ────────────────────────────────────────────────────────

/// A minimal description of one binary section, as needed by the vtable scanner.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SectionDesc {
    pub name: String,
    /// Start address (RVA or VA).
    pub start: u64,
    pub size: u64,
    pub is_executable: bool,
    pub is_readable: bool,
    pub is_writable: bool,
}

impl SectionDesc {
    /// True if this section holds read-only data (`.rodata` / `.rdata`).
    #[must_use]
    pub fn is_rodata(&self) -> bool {
        (self.name == ".rdata" || self.name == ".rodata" || self.name == "__const")
            && self.is_readable
            && !self.is_writable
            && !self.is_executable
    }

    /// True if this section holds executable code (`.text`).
    #[must_use]
    pub const fn is_text(&self) -> bool {
        self.is_executable
    }

    /// Check whether `addr` falls inside this section.
    #[must_use]
    pub const fn contains(&self, addr: u64) -> bool {
        addr >= self.start && addr < self.start + self.size
    }
}

// ── BinaryView (minimal) ──────────────────────────────────────────────────────

/// Minimal binary-view abstraction used by the vtable analyser.
/// In the real tool this would be backed by a memory-mapped image; here we
/// store a flat byte slice plus the image base for testing purposes.
pub struct BinaryView {
    pub data: Vec<u8>,
    /// The address at which `data[0]` is loaded.
    pub image_base: u64,
    pub sections: Vec<SectionDesc>,
    pub pointer_size: u8, // 4 or 8
}

impl BinaryView {
    #[must_use]
    pub const fn new(
        data: Vec<u8>,
        image_base: u64,
        sections: Vec<SectionDesc>,
        pointer_size: u8,
    ) -> Self {
        Self {
            data,
            image_base,
            sections,
            pointer_size,
        }
    }

    /// Read `n` bytes at `rva` into a fixed-size buffer.
    #[must_use]
    pub fn read_bytes(&self, rva: u64, n: usize) -> Option<&[u8]> {
        let off = usize::try_from(rva.checked_sub(self.image_base)?).ok()?;
        self.data.get(off..off.checked_add(n)?)
    }

    /// Read a little-endian u32 at `rva`.
    #[must_use]
    pub fn read_u32(&self, rva: u64) -> Option<u32> {
        let b = self.read_bytes(rva, 4)?;
        Some(u32::from_le_bytes(b.try_into().ok()?))
    }

    /// Read a little-endian u64 at `rva`.
    #[must_use]
    pub fn read_u64(&self, rva: u64) -> Option<u64> {
        let b = self.read_bytes(rva, 8)?;
        Some(u64::from_le_bytes(b.try_into().ok()?))
    }

    /// Read a pointer (32- or 64-bit depending on `pointer_size`).
    #[must_use]
    pub fn read_ptr(&self, rva: u64) -> Option<u64> {
        match self.pointer_size {
            4 => self.read_u32(rva).map(u64::from),
            _ => self.read_u64(rva),
        }
    }

    /// Read a null-terminated ASCII string at `rva`.
    #[must_use]
    pub fn read_cstring(&self, rva: u64) -> Option<String> {
        let off = usize::try_from(rva.checked_sub(self.image_base)?).ok()?;
        let slice = self.data.get(off..)?;
        let end = slice.iter().position(|&b| b == 0)?;
        String::from_utf8(slice[..end].to_vec()).ok()
    }

    /// Check whether `rva` falls in an executable section.
    #[must_use]
    pub fn is_code_address(&self, rva: u64) -> bool {
        self.sections.iter().any(|s| s.is_text() && s.contains(rva))
    }

    /// Check whether `rva` falls in read-only data.
    #[must_use]
    pub fn is_rodata_address(&self, rva: u64) -> bool {
        self.sections
            .iter()
            .any(|s| s.is_rodata() && s.contains(rva))
    }
}

// ── VtableCandidate ───────────────────────────────────────────────────────────

/// A potential vtable discovered by the scanner.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VtableCandidate {
    /// Address of the first method pointer slot.
    pub address: Address,
    /// Recovered virtual-method slots (each is a code-pointer RVA).
    pub slots: Vec<u64>,
    /// Demangled / raw class name from RTTI, if recovered.
    pub class_name: Option<String>,
    /// The RTTI structure address that preceded this vtable, if any.
    pub rtti_address: Option<Address>,
    /// ABI detected for this vtable.
    pub abi: VtableAbi,
}

/// Which C++ ABI produced this vtable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum VtableAbi {
    Msvc,
    ItaniumSingleInheritance,
    ItaniumMultipleInheritance,
    Unknown,
}

// ── MSVC RTTI ─────────────────────────────────────────────────────────────────

/// Parsed MSVC `RTTICompleteObjectLocator` + `RTTITypeDescriptor`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MsvcRtti {
    /// Mangled type descriptor name (starts with `.?A` for MSVC).
    pub raw_name: String,
    /// Demangled class name (best-effort; `raw_name` stripped of `.?A` prefix).
    pub demangled_name: String,
    /// Offset of the vftable pointer in the complete object.
    pub offset: u32,
    /// Constructor displacement.
    pub ctor_disp: u32,
}

/// Offsets within `RTTICompleteObjectLocator` (32-bit offsets; 64-bit uses RVA).
const MSVC_RCOL_SIGNATURE: usize = 0;
const MSVC_RCOL_OFFSET: usize = 4;
const MSVC_RCOL_CTOR_DISP: usize = 8;
const MSVC_RCOL_TYPE_DESC_OFF: usize = 16; // offset of the type-descriptor RVA

/// Attempt to parse MSVC RTTI from the memory immediately before `vtable_addr`.
///
/// Layout (64-bit):
/// ```text
/// -0x08  RTTICompleteObjectLocator*  (pointer back to COL)
///  0x00  vfptr_slot_0
///  0x08  vfptr_slot_1
/// ```
#[must_use]
pub fn parse_msvc_rtti(binary: &BinaryView, vtable_addr: Address) -> Option<MsvcRtti> {
    let ptr_size = u64::from(binary.pointer_size);
    // The COL pointer sits one pointer-width before the vtable.
    let col_ptr_addr = vtable_addr.0.checked_sub(ptr_size)?;
    let col_rva = binary.read_ptr(col_ptr_addr)?;

    // Sanity: COL should be in rodata.
    if !binary.is_rodata_address(col_rva) {
        return None;
    }

    // signature must be 0 (32-bit) or 1 (64-bit image-relative).
    let signature = binary.read_u32(col_rva + MSVC_RCOL_SIGNATURE as u64)?;
    if signature > 1 {
        return None;
    }

    let offset = binary.read_u32(col_rva + MSVC_RCOL_OFFSET as u64)?;
    let ctor_disp = binary.read_u32(col_rva + MSVC_RCOL_CTOR_DISP as u64)?;

    // In 64-bit PEs the type-descriptor address is image-base-relative (RVA
    // stored as u32). In 32-bit it is an absolute pointer.
    let type_desc_field_addr = col_rva + MSVC_RCOL_TYPE_DESC_OFF as u64;
    let type_desc_rva: u64 = if signature == 1 {
        // 64-bit image-relative: stored as u32 RVA from image base.
        let rva32 = binary.read_u32(type_desc_field_addr)?;
        binary.image_base + u64::from(rva32)
    } else {
        binary.read_ptr(type_desc_field_addr)?
    };

    if !binary.is_rodata_address(type_desc_rva) {
        return None;
    }

    // RTTITypeDescriptor layout:
    //   0..ptr_size   : pVFTable pointer (the __type_info VFTable)
    //   ptr_size..2*ptr_size : spare pointer (always 0)
    //   2*ptr_size..  : mangled name string ".?AV<class>@@"
    let name_offset = type_desc_rva + 2 * ptr_size;
    let raw_name = binary.read_cstring(name_offset)?;

    // Strip the ".?AV" / ".?AU" / ".?AW" prefix to get the bare class name.
    let demangled_name = demangle_msvc_type(&raw_name);

    Some(MsvcRtti {
        raw_name,
        demangled_name,
        offset,
        ctor_disp,
    })
}

/// Very minimal MSVC name demangling: remove `.?A_`, extract up to `@@`.
fn demangle_msvc_type(raw: &str) -> String {
    let s = raw.strip_prefix(".?A").unwrap_or(raw);
    // Skip one class-qualifier char (V / U / W / T …) if present.
    let s = match s.chars().next() {
        Some(c) if c.is_alphabetic() => &s[c.len_utf8()..],
        _ => s,
    };
    // Take everything up to the first `@`.
    s.split('@').next().unwrap_or(s).to_string()
}

// ── Itanium ABI typeinfo ──────────────────────────────────────────────────────

/// Parsed Itanium ABI `__cxxabiv1::__class_type_info`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ItaniumTypeinfo {
    pub class_name: String,
    pub kind: ItaniumTypeinfoKind,
    pub base_classes: Vec<BaseClassDesc>,
}

/// Which Itanium typeinfo variant was detected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ItaniumTypeinfoKind {
    /// `__class_type_info` — no inheritance / simple leaf.
    Leaf,
    /// `__si_class_type_info` — single-inheritance.
    SingleInheritance,
    /// `__vmi_class_type_info` — multiple / virtual inheritance.
    MultipleInheritance,
}

/// One base class entry in a `__vmi_class_type_info`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BaseClassDesc {
    /// Typeinfo pointer for the base class.
    pub base_typeinfo_rva: u64,
    /// Offset + flags packed as per the ABI.
    pub offset_flags: i64,
}

/// Attempt to parse Itanium ABI typeinfo preceding `vtable_addr`.
///
/// Itanium vtable layout:
/// ```text
/// -0x10  ptrdiff_t offset_to_top
/// -0x08  typeinfo*
///  0x00  vfptr_slot_0
/// ```
#[must_use]
pub fn parse_itanium_typeinfo(
    binary: &BinaryView,
    vtable_addr: Address,
) -> Option<ItaniumTypeinfo> {
    let ptr_size = u64::from(binary.pointer_size);
    // The typeinfo pointer is 1 pointer-width before the vtable.
    let ti_ptr_addr = vtable_addr.0.checked_sub(ptr_size)?;
    let ti_rva = binary.read_ptr(ti_ptr_addr)?;

    // Basic sanity: typeinfo should be in rodata.
    if !binary.is_rodata_address(ti_rva) {
        return None;
    }

    // typeinfo layout: vptr(ptr_size) | name_ptr(ptr_size) | [base desc …]
    let name_ptr_addr = ti_rva + ptr_size;
    let name_rva = binary.read_ptr(name_ptr_addr)?;
    let raw_name = binary.read_cstring(name_rva)?;

    // Itanium mangled names start with "_ZTI"; the class name follows "N" or is
    // directly the mangled name without the ZTI prefix.
    let class_name = demangle_itanium_type_name(&raw_name);

    // Discriminate leaf / si / vmi by the SHAPE of what follows `name_ptr`.
    //
    // The three Itanium typeinfo classes differ only in what comes after the
    // name pointer:
    //   __class_type_info      : nothing
    //   __si_class_type_info   : base_type*            (one pointer)
    //   __vmi_class_type_info  : flags:u32, base_count:u32, then the base array
    //
    // The previous code read the word at `ti + 2*ptr_size` and tested its low
    // bits as if it were always the vmi `flags` field. For an
    // `__si_class_type_info` that word is the base-class typeinfo POINTER —
    // pointer-aligned, so bits 0 and 1 are always zero — and single
    // inheritance was therefore NEVER detected: every such class came back as
    // a leaf with no bases.
    //
    // The authoritative discriminator is the vptr at `ti + 0` (which of the
    // three `__class_type_info` vtables it points at), but resolving that
    // needs symbols we do not have here. The structural test below is
    // decidable from the bytes alone: vmi is recognised by a small flags word
    // (the ABI defines only 0x1 and 0x2) paired with a plausible base count,
    // and si by a third word that is itself a pointer to rodata.
    let disc_addr = ti_rva + 2 * ptr_size;
    let flags = binary.read_u32(disc_addr).unwrap_or(0);
    let vmi_base_count = binary.read_u32(disc_addr + 4).unwrap_or(0);
    let looks_vmi = flags <= 0x3 && (1..=64).contains(&vmi_base_count);
    let looks_si = !looks_vmi
        && binary
            .read_ptr(disc_addr)
            .is_some_and(|p| p != 0 && binary.is_rodata_address(p));

    let (kind, base_classes) = if looks_vmi {
        // `__vmi_class_type_info`
        let base_count_addr = ti_rva + 2 * ptr_size + 4;
        let base_count = binary.read_u32(base_count_addr).unwrap_or(0) as usize;
        let bases_start = ti_rva + 2 * ptr_size + 8;
        let entry_size = 2 * ptr_size; // base_typeinfo*(8) + offset_flags(8)
        let mut bases = Vec::new();
        for i in 0..base_count.min(64) {
            let entry_addr = bases_start + (i as u64) * entry_size;
            if let (Some(bti), Some(off)) = (
                binary.read_ptr(entry_addr),
                binary.read_ptr(entry_addr + ptr_size),
            ) {
                bases.push(BaseClassDesc {
                    base_typeinfo_rva: bti,
                    offset_flags: off.cast_signed(),
                });
            }
        }
        (ItaniumTypeinfoKind::MultipleInheritance, bases)
    } else if looks_si {
        // `__si_class_type_info`
        let base_ti_addr = ti_rva + 2 * ptr_size;
        let base_rva = binary.read_ptr(base_ti_addr).unwrap_or(0);
        let bases = vec![BaseClassDesc {
            base_typeinfo_rva: base_rva,
            offset_flags: 0,
        }];
        (ItaniumTypeinfoKind::SingleInheritance, bases)
    } else {
        (ItaniumTypeinfoKind::Leaf, Vec::new())
    };

    Some(ItaniumTypeinfo {
        class_name,
        kind,
        base_classes,
    })
}

/// Very minimal demangling: strip `_ZTI` and return the rest as-is.
fn demangle_itanium_type_name(raw: &str) -> String {
    raw.strip_prefix("_ZTI").unwrap_or(raw).to_string()
}

// ── ClassHierarchy ────────────────────────────────────────────────────────────

/// A node in the recovered C++ class hierarchy.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClassNode {
    pub name: String,
    pub vtable_address: Option<Address>,
    pub vtable_slots: usize,
    /// Addresses of immediate base-class vtables.
    pub base_vtables: Vec<Address>,
}

/// The full recovered class hierarchy for a binary.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ClassHierarchy {
    pub classes: HashMap<String, ClassNode>,
}

impl ClassHierarchy {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert or update a class node.
    pub fn insert(&mut self, node: ClassNode) {
        self.classes.insert(node.name.clone(), node);
    }

    /// Return the number of recovered classes.
    #[must_use]
    pub fn len(&self) -> usize {
        self.classes.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.classes.is_empty()
    }
}

// ── VtableAnalyzer ────────────────────────────────────────────────────────────

/// Orchestrates vtable discovery and RTTI recovery.
pub struct VtableAnalyzer {
    binary: std::sync::Arc<BinaryView>,
}

impl VtableAnalyzer {
    /// Create an analyser for a binary image.
    #[must_use]
    pub const fn new(binary: std::sync::Arc<BinaryView>) -> Self {
        Self { binary }
    }

    /// Scan all read-only data sections for vtable candidates.
    ///
    /// A vtable candidate is a run of pointer-sized values that all point into
    /// an executable section, preceded by either an MSVC COL pointer or an
    /// Itanium typeinfo pointer in read-only data.
    #[must_use]
    pub fn find_vtables(&self) -> Vec<VtableCandidate> {
        let ptr_size = u64::from(self.binary.pointer_size);
        let mut candidates = Vec::new();

        for section in &self.binary.sections {
            if !section.is_rodata() {
                continue;
            }

            let mut addr = section.start;
            while addr + ptr_size <= section.start + section.size {
                // Check if this could be the start of a vtable: at least 2
                // consecutive code pointers.
                let p0 = self.binary.read_ptr(addr);
                let p1 = self.binary.read_ptr(addr + ptr_size);

                let both_code = p0.is_some_and(|p| self.binary.is_code_address(p))
                    && p1.is_some_and(|p| self.binary.is_code_address(p));

                if both_code {
                    let mut slots = Vec::new();
                    let mut slot_addr = addr;
                    while let Some(ptr) = self.binary.read_ptr(slot_addr) {
                        if !self.binary.is_code_address(ptr) {
                            break;
                        }
                        slots.push(ptr);
                        slot_addr += ptr_size;
                    }

                    let vtbl_addr = Address(addr);

                    // Try MSVC RTTI first, then Itanium.
                    let (class_name, rtti_address, abi) =
                        if let Some(rtti) = parse_msvc_rtti(&self.binary, vtbl_addr) {
                            let rtti_addr = addr
                                .checked_sub(ptr_size)
                                .and_then(|a| self.binary.read_ptr(a))
                                .map(Address);
                            (Some(rtti.demangled_name), rtti_addr, VtableAbi::Msvc)
                        } else if let Some(ti) = parse_itanium_typeinfo(&self.binary, vtbl_addr) {
                            let ti_ptr_addr = addr.checked_sub(ptr_size).map(Address);
                            let abi = match ti.kind {
                                ItaniumTypeinfoKind::SingleInheritance => {
                                    VtableAbi::ItaniumSingleInheritance
                                }
                                ItaniumTypeinfoKind::MultipleInheritance => {
                                    VtableAbi::ItaniumMultipleInheritance
                                }
                                ItaniumTypeinfoKind::Leaf => VtableAbi::Unknown,
                            };
                            (Some(ti.class_name), ti_ptr_addr, abi)
                        } else {
                            (None, None, VtableAbi::Unknown)
                        };

                    let slot_count = slots.len();
                    candidates.push(VtableCandidate {
                        address: vtbl_addr,
                        slots,
                        class_name,
                        rtti_address,
                        abi,
                    });

                    // Advance past all consumed slots.
                    // Use saturating arithmetic: if slot_count is implausibly
                    // large (adversarial binary), cap addr at u64::MAX so the
                    // outer `while addr + ptr_size <= …` condition terminates.
                    addr = addr.saturating_add(ptr_size.saturating_mul(slot_count as u64));
                    continue;
                }

                addr += ptr_size;
            }
        }

        candidates
    }

    /// Build a `ClassHierarchy` from a set of vtable candidates.
    #[must_use]
    pub fn build_class_hierarchy(&self, vtables: &[VtableCandidate]) -> ClassHierarchy {
        let mut hierarchy = ClassHierarchy::new();

        for vtbl in vtables {
            let name = vtbl
                .class_name
                .clone()
                .unwrap_or_else(|| format!("Class_{:#x}", vtbl.address.0));

            let node = ClassNode {
                name: name.clone(),
                vtable_address: Some(vtbl.address),
                vtable_slots: vtbl.slots.len(),
                base_vtables: Vec::new(), // base resolution requires cross-referencing RTTI
            };
            hierarchy.insert(node);
        }

        hierarchy
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_rodata_section(start: u64, size: u64) -> SectionDesc {
        SectionDesc {
            name: ".rdata".into(),
            start,
            size,
            is_executable: false,
            is_readable: true,
            is_writable: false,
        }
    }

    fn make_text_section(start: u64, size: u64) -> SectionDesc {
        SectionDesc {
            name: ".text".into(),
            start,
            size,
            is_executable: true,
            is_readable: true,
            is_writable: false,
        }
    }

    #[test]
    fn test_section_is_rodata() {
        let s = make_rodata_section(0x1000, 0x1000);
        assert!(s.is_rodata());
        assert!(!s.is_text());
    }

    #[test]
    fn test_section_contains() {
        let s = make_rodata_section(0x1000, 0x100);
        assert!(s.contains(0x1000));
        assert!(s.contains(0x10FF));
        assert!(!s.contains(0x1100));
    }

    fn make_test_binary(code_addrs: &[u64]) -> BinaryView {
        // Build a 4096-byte flat image at base 0.
        let mut data = vec![0u8; 4096];
        // Place code-pointer array at offset 0x100 (rodata section starts there).
        let mut off = 0x100usize;
        for &addr in code_addrs {
            data[off..off + 8].copy_from_slice(&addr.to_le_bytes());
            off += 8;
        }

        let sections = vec![
            make_text_section(0x0000_1000, 0x0001_0000),
            make_rodata_section(0x0000_0100, 0x0000_0F00),
        ];

        BinaryView::new(data, 0, sections, 8)
    }

    #[test]
    fn test_binary_view_read_ptr() {
        let code_addrs = [0x0000_1000u64, 0x0000_1100u64, 0x0000_1200u64];
        let bv = make_test_binary(&code_addrs);
        let p = bv.read_ptr(0x100).unwrap();
        assert_eq!(p, 0x1000);
    }

    #[test]
    fn test_binary_view_is_code_address() {
        let bv = make_test_binary(&[0x1000]);
        assert!(bv.is_code_address(0x1000));
        assert!(!bv.is_code_address(0x200));
    }

    #[test]
    fn test_vtable_finder_finds_candidate() {
        let code_addrs = [0x0000_1000u64, 0x0000_1100u64, 0x0000_1200u64];
        let bv = std::sync::Arc::new(make_test_binary(&code_addrs));
        let analyzer = VtableAnalyzer::new(bv);
        let vtables = analyzer.find_vtables();
        // Should find at least one vtable (the array of 3 code pointers).
        assert!(!vtables.is_empty());
        assert!(vtables[0].slots.len() >= 2);
    }

    #[test]
    fn test_build_hierarchy_from_vtables() {
        let v = VtableCandidate {
            address: Address(0x1000),
            slots: vec![0x2000, 0x2100],
            class_name: Some("MyClass".into()),
            rtti_address: None,
            abi: VtableAbi::Unknown,
        };
        let bv = std::sync::Arc::new(make_test_binary(&[]));
        let analyzer = VtableAnalyzer::new(bv);
        let hier = analyzer.build_class_hierarchy(&[v]);
        assert!(hier.classes.contains_key("MyClass"));
    }

    #[test]
    fn test_demangle_msvc_type() {
        assert_eq!(demangle_msvc_type(".?AVMyClass@@"), "MyClass");
        assert_eq!(demangle_msvc_type(".?AUMyStruct@@"), "MyStruct");
    }

    #[test]
    fn test_demangle_itanium_type_name() {
        assert_eq!(demangle_itanium_type_name("_ZTI7MyClass"), "7MyClass");
    }

    #[test]
    fn test_class_hierarchy_len() {
        let mut h = ClassHierarchy::new();
        h.insert(ClassNode {
            name: "A".into(),
            vtable_address: None,
            vtable_slots: 0,
            base_vtables: vec![],
        });
        assert_eq!(h.len(), 1);
        assert!(!h.is_empty());
    }
}
