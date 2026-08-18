// cpp_type_recovery.rs â€” C++ specific type recovery for RustRE
//
// Recovers C++ abstractions from compiled binaries:
//   - VTable detection and virtual function identification
//   - RTTI parsing (Itanium ABI and MSVC)
//   - Class hierarchy reconstruction
//   - This-pointer propagation
//   - Template instantiation detection
//   - Operator overloading identification
//   - Multiple inheritance with multiple vtable pointers

use std::collections::{HashMap, HashSet, VecDeque};
use std::fmt;

use bitflags::bitflags;

bitflags! {
    /// Attribute flags for `_RTTIClassHierarchyDescriptor::attributes`.
    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
    pub struct ClassHierarchyAttributes: u32 {
        /// Class uses multiple inheritance.
        const MULTIPLE_INHERITANCE = 0x1;
        /// Class uses virtual inheritance.
        const VIRTUAL_INHERITANCE  = 0x2;
        /// Ambiguous inheritance (reserved).
        const AMBIGUOUS_INHERITANCE = 0x4;
    }
}

// ---------------------------------------------------------------------------
// Address / identifier types
// ---------------------------------------------------------------------------

pub type Addr = u64;
pub type FuncId = u64;

// ---------------------------------------------------------------------------
// Vtable entry
// ---------------------------------------------------------------------------

/// A single slot in a vtable.
#[derive(Clone, Debug)]
pub struct VtableSlot {
    /// Index of this slot within the vtable (0-based).
    pub index: usize,
    /// Address of the function pointer stored at this slot.
    pub func_ptr_addr: Addr,
    /// Resolved target address (the virtual function).
    pub target_addr: Addr,
    /// Inferred name (e.g. "`ClassName::virtual_method_2`").
    pub name: Option<String>,
    /// Inferred function signature (if available).
    pub signature: Option<VirtualFuncSig>,
    /// True if this slot is a pure virtual (points to __`cxa_pure_virtual` or similar).
    pub is_pure_virtual: bool,
    /// True if this is a destructor slot.
    pub is_destructor: bool,
    /// This-pointer adjustment (for multiple inheritance thunks).
    pub this_adjustment: i64,
}

/// Signature of a virtual function.
#[derive(Clone, Debug)]
pub struct VirtualFuncSig {
    pub return_type: String,
    pub param_types: Vec<String>,
    pub is_const: bool,
}

// ---------------------------------------------------------------------------
// Vtable
// ---------------------------------------------------------------------------

/// A recovered C++ vtable.
#[derive(Clone, Debug)]
pub struct Vtable {
    /// Address of the vtable (pointer to first function slot).
    pub addr: Addr,
    /// Address of the RTTI typeinfo pointer (vtable[-1] on Itanium).
    pub rtti_ptr_addr: Option<Addr>,
    /// The class this vtable belongs to.
    pub class_name: Option<String>,
    /// All virtual function slots.
    pub slots: Vec<VtableSlot>,
    /// For multiple inheritance: secondary vtable offset from the primary.
    pub offset_to_top: i64,
    /// ABI format.
    pub abi: CppAbi,
}

impl Vtable {
    #[must_use] 
    pub const fn new(addr: Addr, abi: CppAbi) -> Self {
        Self {
            addr,
            rtti_ptr_addr: None,
            class_name: None,
            slots: Vec::new(),
            offset_to_top: 0,
            abi,
        }
    }

    /// Number of virtual function slots.
    #[must_use] 
    pub const fn num_slots(&self) -> usize {
        self.slots.len()
    }

    /// Find the slot at index N.
    #[must_use] 
    pub fn slot(&self, index: usize) -> Option<&VtableSlot> {
        self.slots.get(index)
    }

    /// True if this appears to be a primary vtable (`offset_to_top` == 0).
    #[must_use] 
    pub const fn is_primary(&self) -> bool {
        self.offset_to_top == 0
    }
}

// ---------------------------------------------------------------------------
// ABI variants
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum CppAbi {
    /// System V / GNU (Linux, macOS, most unixes).
    Itanium,
    /// Microsoft Visual C++ (Windows).
    Msvc,
    /// Unknown / to be determined.
    Unknown,
}

impl fmt::Display for CppAbi {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Itanium => write!(f, "Itanium"),
            Self::Msvc => write!(f, "MSVC"),
            Self::Unknown => write!(f, "Unknown"),
        }
    }
}

// ---------------------------------------------------------------------------
// RTTI â€” Itanium ABI
// ---------------------------------------------------------------------------

/// The Itanium ABI `std::type_info` representation as recovered from memory.
#[derive(Clone, Debug)]
pub struct ItaniumTypeInfo {
    pub addr: Addr,
    pub type_name: String,
    /// True for `__class_type_info`.
    pub is_class: bool,
    /// True for `__si_class_type_info` (single inheritance).
    pub is_si: bool,
    /// True for `__vmi_class_type_info` (virtual/multiple inheritance).
    pub is_vmi: bool,
}

/// Itanium `__si_class_type_info` â€” single-inheritance type info.
#[derive(Clone, Debug)]
pub struct SiClassTypeInfo {
    pub type_info: ItaniumTypeInfo,
    /// Pointer to the typeinfo of the single base class.
    pub base_type_info_addr: Addr,
}

/// Itanium `__vmi_class_type_info` â€” multiple/virtual inheritance type info.
#[derive(Clone, Debug)]
pub struct VmiClassTypeInfo {
    pub type_info: ItaniumTypeInfo,
    /// Flags (`DIAMOND_SHAPED_MASK`, `NON_DIAMOND_MASK`).
    pub flags: u32,
    /// List of base class infos.
    pub bases: Vec<ItaniumBaseClassInfo>,
}

/// One entry in the base-class array of `__vmi_class_type_info`.
#[derive(Clone, Debug)]
pub struct ItaniumBaseClassInfo {
    pub base_type_info_addr: Addr,
    /// Encoded: bit 0 = `is_virtual`, bits 8..32 = offset.
    pub offset_flags: i64,
}

impl ItaniumBaseClassInfo {
    #[must_use] 
    pub const fn is_virtual(&self) -> bool {
        (self.offset_flags & 1) != 0
    }

    #[must_use] 
    pub const fn offset_bytes(&self) -> i64 {
        self.offset_flags >> 8
    }
}

// ---------------------------------------------------------------------------
// RTTI â€” MSVC ABI
// ---------------------------------------------------------------------------

/// MSVC `_RTTICompleteObjectLocator` (COL), located at vtable[-1] (32-bit)
/// or vtable[-4] (64-bit, relative RVAs).
#[derive(Clone, Debug)]
pub struct MsvcCompleteObjectLocator {
    pub addr: Addr,
    /// 0 = 32-bit layout, 1 = 64-bit layout (RVA-based).
    pub signature: u32,
    /// Offset of the sub-object to the start of the complete object.
    pub offset: u32,
    /// CD offset (offset of the constructor displacement).
    pub cd_offset: u32,
    /// RVA / pointer to `_TypeDescriptor`.
    pub type_descriptor_addr: Addr,
    /// RVA / pointer to `_RTTIClassHierarchyDescriptor`.
    pub class_hierarchy_addr: Addr,
    /// (64-bit only) RVA of the COL itself from the image base.
    pub object_locator_rva: u32,
}

/// MSVC `_TypeDescriptor`.
#[derive(Clone, Debug)]
pub struct MsvcTypeDescriptor {
    pub addr: Addr,
    /// Pointer to the type's vtable (for `type_info`).
    pub vtable_ptr: Addr,
    /// Unmangled name (or `nullptr`).
    pub spare: Addr,
    /// Decorated (mangled) name, e.g. `.?AVFoo@@`.
    pub mangled_name: String,
    /// Demangled class name extracted from `mangled_name`.
    pub class_name: Option<String>,
}

impl MsvcTypeDescriptor {
    /// Attempt to extract a human-readable class name from the mangled MSVC name.
    /// `.?AV<name>@@` â†’ `<name>`.
    #[must_use] 
    pub fn demangle(&self) -> Option<String> {
        // MSVC mangling for classes: .?AV<name>@@
        let s = &self.mangled_name;
        if let Some(rest) = s.strip_prefix(".?AV")
            && let Some(idx) = rest.find("@@") {
                return Some(rest[..idx].to_string());
            }
        // Structs: .?AU<name>@@
        if let Some(rest) = s.strip_prefix(".?AU")
            && let Some(idx) = rest.find("@@") {
                return Some(rest[..idx].to_string());
            }
        None
    }
}

/// MSVC `_RTTIClassHierarchyDescriptor`.
#[derive(Clone, Debug)]
pub struct MsvcClassHierarchyDescriptor {
    pub addr: Addr,
    pub signature: u32,
    /// Typed flags: see [`ClassHierarchyAttributes`].
    pub attributes: ClassHierarchyAttributes,
    pub num_base_classes: u32,
    /// Pointer/RVA to array of `_RTTIBaseClassDescriptor` pointers.
    pub base_class_array_addr: Addr,
}

impl MsvcClassHierarchyDescriptor {
    #[must_use] 
    pub const fn has_multiple_inheritance(&self) -> bool {
        self.attributes.contains(ClassHierarchyAttributes::MULTIPLE_INHERITANCE)
    }
    #[must_use] 
    pub const fn has_virtual_inheritance(&self) -> bool {
        self.attributes.contains(ClassHierarchyAttributes::VIRTUAL_INHERITANCE)
    }
}

/// MSVC `_RTTIBaseClassDescriptor`.
#[derive(Clone, Debug)]
pub struct MsvcBaseClassDescriptor {
    pub addr: Addr,
    pub type_descriptor_addr: Addr,
    pub num_contained_bases: u32,
    /// `PMD` (Pointer-to-Member-Data) displacement info.
    pub pmd: MsvcPmd,
    pub attributes: u32,
    pub class_hierarchy_addr: Addr,
}

/// MSVC `_PMD` â€” where-delta, virtual-table-pointer, virtual-base-offset-delta.
#[derive(Clone, Debug, Default)]
pub struct MsvcPmd {
    /// Offset of this base in the complete object.
    pub member_displacement: i32,
    /// Index into the vtable for virtual bases (-1 if not virtual).
    pub vbtable_displacement: i32,
    /// Displacement within the virtual base table.
    pub displacement_within_vbtable: i32,
}

impl MsvcPmd {
    #[must_use] 
    pub const fn is_virtual_base(&self) -> bool {
        self.vbtable_displacement != -1
    }
}

// ---------------------------------------------------------------------------
// Class hierarchy
// ---------------------------------------------------------------------------

/// A recovered C++ class with vtable, RTTI, and inheritance information.
#[derive(Clone, Debug)]
pub struct CppClass {
    pub name: String,
    /// Addresses of all vtables belonging to this class (primary + secondary).
    pub vtable_addrs: Vec<Addr>,
    /// Direct base classes.
    pub base_classes: Vec<BaseClassRelation>,
    /// All virtual methods (union from all vtables).
    pub virtual_methods: Vec<VirtualMethod>,
    /// Total size in bytes (if recovered).
    pub size_bytes: Option<u64>,
    /// ABI in use.
    pub abi: CppAbi,
    /// RTTI address, if found.
    pub rtti_addr: Option<Addr>,
    /// True if the class has any pure virtual methods.
    pub is_abstract: bool,
    /// Detected template arguments (if any).
    pub template_args: Vec<TemplateArg>,
    /// Whether this class uses multiple inheritance.
    pub has_multiple_inheritance: bool,
    /// Vtable pointer offsets within the object (for multiple inheritance).
    pub vptr_offsets: Vec<u64>,
}

/// A base class relationship.
#[derive(Clone, Debug)]
pub struct BaseClassRelation {
    pub base_name: String,
    pub offset_in_derived: i64,
    pub is_virtual: bool,
    pub is_public: bool,
}

/// A recovered virtual method.
#[derive(Clone, Debug)]
pub struct VirtualMethod {
    pub slot_index: usize,
    /// Vtable address this slot belongs to (for multiple inheritance).
    pub vtable_addr: Addr,
    pub func_addr: Addr,
    pub name: Option<String>,
    pub is_pure: bool,
    pub is_destructor: bool,
    pub this_adjustment: i64,
    pub signature: Option<VirtualFuncSig>,
}

impl VirtualMethod {
    /// Generate a default name if none is available.
    #[must_use] 
    pub fn default_name(&self, class_name: &str) -> String {
        if self.is_destructor {
            format!("{class_name}::~{class_name}")
        } else {
            format!("{}::virtual_method_{}", class_name, self.slot_index)
        }
    }
}

// ---------------------------------------------------------------------------
// Template argument
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum TemplateArg {
    Type(String),
    Integer(i64),
    Bool(bool),
    Unknown,
}

impl fmt::Display for TemplateArg {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Type(t) => write!(f, "{t}"),
            Self::Integer(n) => write!(f, "{n}"),
            Self::Bool(b) => write!(f, "{b}"),
            Self::Unknown => write!(f, "?"),
        }
    }
}

// ---------------------------------------------------------------------------
// Operator overload table
// ---------------------------------------------------------------------------

/// Maps mangled operator names to human-readable forms.
///
/// Stored in `BTreeMap`s: `identify` scans for the first matching key, and
/// several operator codes can match the same mangled name (e.g. a name
/// containing both `eq` and `pl`), so the scan order must be deterministic.
pub struct OperatorTable {
    itanium: std::collections::BTreeMap<String, String>,
    msvc: std::collections::BTreeMap<String, String>,
}

impl Default for OperatorTable {
    fn default() -> Self {
        Self::new()
    }
}

impl OperatorTable {
    #[must_use] 
    pub fn new() -> Self {
        let mut t = Self {
            itanium: std::collections::BTreeMap::new(),
            msvc: std::collections::BTreeMap::new(),
        };
        t.populate_itanium();
        t.populate_msvc();
        t
    }

    fn populate_itanium(&mut self) {
        let pairs = [
            ("eq",  "operator=="),  ("ne",  "operator!="),
            ("lt",  "operator<"),   ("gt",  "operator>"),
            ("le",  "operator<="),  ("ge",  "operator>="),
            ("ss",  "operator<=>"), // three-way comparison (C++20)
            ("pl",  "operator+"),   ("mi",  "operator-"),
            ("ml",  "operator*"),   ("dv",  "operator/"),
            ("rm",  "operator%"),   ("an",  "operator&"),
            ("or",  "operator|"),   ("eo",  "operator^"),
            ("aS",  "operator="),   ("pL",  "operator+="),
            ("mI",  "operator-="),  ("mL",  "operator*="),
            ("dV",  "operator/="),  ("rM",  "operator%="),
            ("aN",  "operator&="),  ("oR",  "operator|="),
            ("eO",  "operator^="),  ("ls",  "operator<<"),
            ("rs",  "operator>>"),  ("lS",  "operator<<="),
            ("rS",  "operator>>="), ("pp",  "operator++"),
            ("mm",  "operator--"),  ("de",  "operator*"),  // unary *
            ("ad",  "operator&"),   // unary &
            ("co",  "operator~"),   ("nt",  "operator!"),
            ("cl",  "operator()"),  ("ix",  "operator[]"),
            ("nw",  "operator new"),("na",  "operator new[]"),
            ("dl",  "operator delete"), ("da", "operator delete[]"),
            ("cv",  "operator (conversion)"),
            ("li",  "operator \"\""),
        ];
        for (mangled, readable) in pairs {
            self.itanium.insert(mangled.to_string(), readable.to_string());
        }
    }

    fn populate_msvc(&mut self) {
        let pairs = [
            ("?0",  "constructor"),
            ("?1",  "destructor"),
            ("?4",  "operator="),
            ("?5",  "operator>>"),
            ("?6",  "operator<<"),
            ("?8",  "operator=="),
            ("?9",  "operator!="),
            ("?A",  "operator[]"),
            ("?B",  "operator (conversion)"),
            ("?C",  "operator->"),
            ("?D",  "operator*"),
            ("?E",  "operator++"),
            ("?F",  "operator--"),
            ("?G",  "operator-"),
            ("?H",  "operator+"),
            ("?I",  "operator&"),
            ("?J",  "operator->*"),
            ("?K",  "operator/"),
            ("?L",  "operator%"),
            ("?M",  "operator<"),
            ("?N",  "operator<="),
            ("?O",  "operator>"),
            ("?P",  "operator>="),
            ("?Q",  "operator,"),
            ("?R",  "operator()"),
            ("?S",  "operator~"),
            ("?T",  "operator^"),
            ("?U",  "operator|"),
            ("?V",  "operator&&"),
            ("?W",  "operator||"),
            ("?X",  "operator*="),
            ("?Y",  "operator+="),
            ("?Z",  "operator-="),
            ("?_0", "operator/="),
            ("?_1", "operator%="),
            ("?_2", "operator>>="),
            ("?_3", "operator<<="),
            ("?_4", "operator&="),
            ("?_5", "operator|="),
            ("?_6", "operator^="),
            ("?_7", "operator`vftable'"),
            ("?_D", "operator`vbase destructor'"),
            ("?_G", "operator`scalar deleting destructor'"),
            ("?_H", "operator`vector deleting destructor'"),
            ("?_U", "operator new[]"),
            ("?_V", "operator delete[]"),
            ("?2",  "operator new"),
            ("?3",  "operator delete"),
        ];
        for (mangled, readable) in pairs {
            self.msvc.insert(mangled.to_string(), readable.to_string());
        }
    }

    /// Attempt to identify an operator from a mangled name (Itanium or MSVC).
    #[must_use] 
    pub fn identify(&self, mangled: &str) -> Option<&str> {
        // Deterministic match selection: several operator codes can occur in
        // one mangled name (e.g. `_ZN3FooeqplE` contains both "eq" and "pl").
        // Before, the tables were HashMaps and the *first* match in hash
        // iteration order won — a per-run-random answer. Pick the match at
        // the leftmost position; break position ties with the longest key,
        // then lexicographically smallest key.
        fn best_match<'t>(
            table: &'t std::collections::BTreeMap<String, String>,
            mangled: &str,
        ) -> Option<&'t str> {
            table
                .iter()
                .filter_map(|(key, val)| {
                    mangled.find(key.as_str()).map(|pos| (pos, key, val))
                })
                .min_by(|(pa, ka, _), (pb, kb, _)| {
                    pa.cmp(pb)
                        .then_with(|| kb.len().cmp(&ka.len()))
                        .then_with(|| ka.cmp(kb))
                })
                .map(|(_, _, val)| val.as_str())
        }
        // Itanium: _ZN<class><len><operator>... or _Z<op>...
        if mangled.starts_with("_Z")
            && let Some(v) = best_match(&self.itanium, mangled) {
                return Some(v);
            }
        // MSVC: ?<operator>@<class>@@...
        if mangled.starts_with('?')
            && let Some(v) = best_match(&self.msvc, mangled) {
                return Some(v);
            }
        None
    }

    /// Returns true if the symbol name is an operator overload.
    #[must_use] 
    pub fn is_operator(&self, name: &str) -> bool {
        name.starts_with("operator")
    }
}

// ---------------------------------------------------------------------------
// Vtable detector
// ---------------------------------------------------------------------------

/// Configuration for vtable detection heuristics.
#[derive(Clone, Debug)]
pub struct VtableDetectorConfig {
    /// Minimum number of function pointer slots to consider a vtable candidate.
    pub min_slots: usize,
    /// Maximum reasonable vtable size in slots.
    pub max_slots: usize,
    /// Whether to accept vtable candidates without RTTI.
    pub allow_no_rtti: bool,
    /// Pointer size in bytes (4 or 8).
    pub ptr_size: usize,
    /// ABI to use for layout interpretation.
    pub abi: CppAbi,
    /// Address of known `__cxa_pure_virtual` function (for pure virtual detection).
    pub pure_virtual_addr: Option<Addr>,
    /// Address of known `__cxa_deleted_virtual` function.
    pub deleted_virtual_addr: Option<Addr>,
}

impl Default for VtableDetectorConfig {
    fn default() -> Self {
        Self {
            min_slots: 1,
            max_slots: 256,
            allow_no_rtti: true,
            ptr_size: 8,
            abi: CppAbi::Itanium,
            pure_virtual_addr: None,
            deleted_virtual_addr: None,
        }
    }
}

/// Detects vtables by scanning memory for arrays of function pointers
/// and validating the RTTI pointer.
pub struct VtableDetector {
    pub config: VtableDetectorConfig,
    /// Set of known executable code addresses (used to validate function pointers).
    pub code_addrs: HashSet<Addr>,
    /// Set of known read-only data addresses (vtables live in .rodata / .rdata).
    pub rodata_addrs: HashSet<Addr>,
}

impl VtableDetector {
    #[must_use] 
    pub fn new(config: VtableDetectorConfig) -> Self {
        Self {
            config,
            code_addrs: HashSet::new(),
            rodata_addrs: HashSet::new(),
        }
    }

    /// Register a code section [start, end).
    pub const fn add_code_range(&mut self, start: Addr, end: Addr) {
        // In a real implementation, use a RangeSet or sorted intervals.
        // For the stub, we accept arbitrary addresses.
        let _ = (start, end);
    }

    /// Register a read-only data section [start, end).
    pub const fn add_rodata_range(&mut self, start: Addr, end: Addr) {
        let _ = (start, end);
    }

    /// Returns true if `addr` points into executable code.
    #[must_use] 
    pub const fn is_code_addr(&self, addr: Addr) -> bool {
        // HOOK: check against loaded code sections.
        addr != 0 && (addr & 0xFFFF_0000_0000_0000) == 0
    }

    /// Returns true if `addr` points into read-only data.
    #[must_use] 
    pub const fn is_rodata_addr(&self, addr: Addr) -> bool {
        // HOOK: check against loaded rodata sections.
        addr != 0
    }

    /// Core heuristic: does memory at `base` look like a vtable?
    ///
    /// Itanium layout (before slot 0):
    ///   [base - 2*ptr] = `offset_to_top`  (`ptrdiff_t`)
    ///   [base - 1*ptr] = typeinfo ptr   (pointer to `type_info`)
    ///   [base + 0*ptr] = `vfunc_0`
    ///   [base + 1*ptr] = `vfunc_1`
    ///   ...
    ///
    /// MSVC layout (64-bit):
    ///   [base - 4*ptr] = `RTTICompleteObjectLocator` RVA  (u32)
    ///   [base + 0*ptr] = `vfunc_0`
    ///   ...
    pub fn looks_like_vtable(
        &self,
        base: Addr,
        read_ptr: &impl Fn(Addr) -> Option<Addr>,
    ) -> bool {
        let ps = self.config.ptr_size as u64;

        // Check that at least min_slots function pointers follow `base`.
        let mut valid_slots = 0;
        for i in 0..self.config.max_slots {
            // checked: a base near u64::MAX must not wrap around to low
            // addresses and read unrelated memory.
            let Some(slot_addr) = base.checked_add((i as u64).wrapping_mul(ps)) else {
                break;
            };
            match read_ptr(slot_addr) {
                Some(ptr) if self.is_code_addr(ptr) => valid_slots += 1,
                _ => break,
            }
        }
        if valid_slots < self.config.min_slots {
            return false;
        }

        if !self.config.allow_no_rtti {
            // Validate RTTI pointer.
            match self.config.abi {
                CppAbi::Itanium => {
                    let rtti_slot = base.wrapping_sub(ps);
                    if read_ptr(rtti_slot).is_none() {
                        return false;
                    }
                }
                CppAbi::Msvc => {
                    // COL is at base - 4 bytes (RVA in 64-bit).
                    // Just check not null.
                    let col_rva_addr = base.wrapping_sub(4);
                    // In practice we'd read a u32 here.
                    let _ = col_rva_addr;
                }
                CppAbi::Unknown => {}
            }
        }

        true
    }

    /// Scan a region and collect vtable candidates.
    ///
    /// # Panics
    ///
    /// Panics if `candidates` is empty when accessing the last element (unreachable in practice).
    pub fn scan_for_vtables(
        &self,
        region_start: Addr,
        region_end: Addr,
        read_ptr: &impl Fn(Addr) -> Option<Addr>,
    ) -> Vec<VtableCandidate> {
        let ps = self.config.ptr_size as u64;
        let mut candidates = Vec::new();
        let mut addr = region_start;
        while addr < region_end {
            if self.looks_like_vtable(addr, read_ptr) {
                let mut slots = Vec::new();
                for i in 0..self.config.max_slots {
                    let Some(slot_addr) = addr.checked_add((i as u64).wrapping_mul(ps)) else {
                        break;
                    };
                    match read_ptr(slot_addr) {
                        Some(target) if self.is_code_addr(target) => {
                            slots.push(VtableCandidateSlot { index: i, target });
                        }
                        _ => break,
                    }
                }
                let rtti_ptr = if self.config.abi == CppAbi::Itanium {
                    read_ptr(addr.wrapping_sub(ps))
                } else {
                    None
                };
                candidates.push(VtableCandidate {
                    addr,
                    slots,
                    rtti_ptr,
                    abi: self.config.abi,
                });
                // Advance by at least one pointer: with `min_slots == 0` (or
                // `max_slots == 0`) a candidate can legitimately have zero
                // slots, and `addr += 0` would loop forever on the same
                // address (hang on attacker-controlled/misconfigured input).
                let advance = (candidates.last().map_or(0, |c| c.slots.len()) as u64).max(1);
                // checked: near u64::MAX the old `addr += advance * ps`
                // wrapped past region_end back to low addresses and the scan
                // restarted from ~0 — an effectively infinite loop on a
                // region ending at the top of the address space.
                match advance.checked_mul(ps).and_then(|step| addr.checked_add(step)) {
                    Some(next) => addr = next,
                    None => break,
                }
            } else {
                match addr.checked_add(ps) {
                    Some(next) => addr = next,
                    None => break,
                }
            }
        }
        candidates
    }
}

/// A vtable candidate before full validation.
#[derive(Clone, Debug)]
pub struct VtableCandidate {
    pub addr: Addr,
    pub slots: Vec<VtableCandidateSlot>,
    pub rtti_ptr: Option<Addr>,
    pub abi: CppAbi,
}

#[derive(Clone, Debug)]
pub struct VtableCandidateSlot {
    pub index: usize,
    pub target: Addr,
}

// ---------------------------------------------------------------------------
// RTTI parser â€” Itanium
// ---------------------------------------------------------------------------

pub struct ItaniumRttiParser {
    /// Image base (for address calculations).
    pub image_base: Addr,
    /// Cache of parsed typeinfos.
    parsed: HashMap<Addr, ItaniumParsedTypeInfo>,
}

#[derive(Clone, Debug)]
pub enum ItaniumParsedTypeInfo {
    Class(ItaniumTypeInfo),
    Single(SiClassTypeInfo),
    Vmi(VmiClassTypeInfo),
    Unknown(Addr),
}

impl ItaniumRttiParser {
    #[must_use] 
    pub fn new(image_base: Addr) -> Self {
        Self { image_base, parsed: HashMap::new() }
    }

    /// Parse the typeinfo structure at `addr`.
    ///
    /// Layout of `__si_class_type_info`:
    ///   +0x00: `vtable_ptr`  (pointer to __`si_class_type_info` vtable)
    ///   +0x08: `name_ptr`    (pointer to mangled class name)
    ///   +0x10: `base_type`   (pointer to base's `type_info`)
    ///
    /// Layout of `__vmi_class_type_info`:
    ///   +0x00: `vtable_ptr`
    ///   +0x08: `name_ptr`
    ///   +0x10: flags       (u32)
    ///   +0x14: `base_count`  (u32)
    ///   +0x18: bases[]     (array of `base_type_ptr` + `offset_flags` pairs)
    ///
    /// Returns None if the address does not look like valid RTTI.
    pub fn parse(
        &mut self,
        addr: Addr,
        read_ptr: &impl Fn(Addr) -> Option<Addr>,
        read_string: &impl Fn(Addr) -> Option<String>,
        read_u32: &impl Fn(Addr) -> Option<u32>,
    ) -> Option<&ItaniumParsedTypeInfo> {
        if self.parsed.contains_key(&addr) {
            return self.parsed.get(&addr);
        }

        let vtable_ptr = read_ptr(addr)?;
        let name_ptr = read_ptr(addr + 8)?;
        let raw_name = read_string(name_ptr)?;
        let demangled = Self::demangle_itanium(&raw_name);

        // Classify by inspecting the vtable_ptr (would normally compare to
        // known typeinfo vtable addresses). We use heuristics on the name.
        let info = ItaniumTypeInfo {
            addr,
            type_name: demangled,
            is_class: true,
            is_si: false,
            is_vmi: false,
        };

        // Try to read base class pointer (si_class layout).
        if let Some(base_addr) = read_ptr(addr + 16)
            && base_addr != 0 && base_addr != vtable_ptr {
                // Looks like a single-base type.
                let si = SiClassTypeInfo {
                    type_info: ItaniumTypeInfo { is_si: true, ..info },
                    base_type_info_addr: base_addr,
                };
                self.parsed.insert(addr, ItaniumParsedTypeInfo::Single(si));
                return self.parsed.get(&addr);
            }

        // Try vmi layout: flags at +16, count at +20, then bases.
        if let (Some(flags), Some(count)) = (read_u32(addr + 16), read_u32(addr + 20))
            && count > 0 && count <= 32 {
                let mut bases = Vec::new();
                for i in 0..count {
                    let base_entry_addr = addr.saturating_add(24).saturating_add(u64::from(i).saturating_mul(16));
                    let base_ti_ptr = read_ptr(base_entry_addr).unwrap_or(0);
                    let offset_flags_lo = read_ptr(base_entry_addr + 8).unwrap_or(0);
                    bases.push(ItaniumBaseClassInfo {
                        base_type_info_addr: base_ti_ptr,
                        offset_flags: i64::from_ne_bytes(offset_flags_lo.to_ne_bytes()),
                    });
                }
                if bases.iter().all(|b| b.base_type_info_addr != 0) {
                    let vmi = VmiClassTypeInfo {
                        type_info: ItaniumTypeInfo { is_vmi: true, ..info },
                        flags,
                        bases,
                    };
                    self.parsed.insert(addr, ItaniumParsedTypeInfo::Vmi(vmi));
                    return self.parsed.get(&addr);
                }
            }

        self.parsed.insert(addr, ItaniumParsedTypeInfo::Class(info));
        self.parsed.get(&addr)
    }

    /// Very simplified Itanium name demangler.
    /// Full demangling would call `__cxa_demangle` or a Rust re-implementation.
    ///
    /// # Panics
    ///
    /// Panics if the iterator yields `None` unexpectedly (unreachable in practice).
    #[must_use]
    pub fn demangle_itanium(mangled: &str) -> String {
        // Strip leading _Z or _ZN.
        let s = if let Some(rest) = mangled.strip_prefix("_ZN") {
            // Nested name: _ZN<len><name><len><name>...
            let mut result = String::new();
            let mut chars = rest.chars().peekable();
            loop {
                // Read length.
                let mut len_str = String::new();
                while chars.peek().is_some_and(char::is_ascii_digit) {
                    len_str.push(chars.next().unwrap());
                }
                if len_str.is_empty() {
                    break;
                }
                let len: usize = len_str.parse().unwrap_or(0);
                let segment: String = chars.by_ref().take(len).collect();
                if !result.is_empty() {
                    result.push_str("::");
                }
                result.push_str(&segment);
                if chars.peek() == Some(&'E') {
                    break;
                }
            }
            return result;
        } else if let Some(rest) = mangled.strip_prefix("_Z") {
            rest
        } else {
            return mangled.to_string();
        };

        // Simple single-name: read leading digits as length.
        let mut chars = s.chars().peekable();
        let mut len_str = String::new();
        while chars.peek().is_some_and(char::is_ascii_digit) {
            len_str.push(chars.next().unwrap());
        }
        len_str.parse::<usize>().map_or_else(|_| mangled.to_string(), |len| chars.by_ref().take(len).collect())
    }

    /// Build a class hierarchy from all parsed typeinfos.
    #[must_use] 
    pub fn build_hierarchy(&self) -> HashMap<String, Vec<String>> {
        let mut hierarchy: HashMap<String, Vec<String>> = HashMap::new();
        // Determinism: `parsed` is a HashMap; when the same class name was
        // parsed at several addresses, the order its bases are appended in
        // followed hash-iteration order (random per run). Iterate typeinfos
        // in ascending address order instead.
        let mut addrs: Vec<&Addr> = self.parsed.keys().collect();
        addrs.sort_unstable();
        for addr in addrs {
            let ti = &self.parsed[addr];
            match ti {
                ItaniumParsedTypeInfo::Single(si) => {
                    let name = &si.type_info.type_name;
                    if let Some(base_ti) = self.parsed.get(&si.base_type_info_addr) {
                        let base_name = match base_ti {
                            ItaniumParsedTypeInfo::Class(i)
                            | ItaniumParsedTypeInfo::Single(SiClassTypeInfo { type_info: i, .. })
                            | ItaniumParsedTypeInfo::Vmi(VmiClassTypeInfo { type_info: i, .. }) => {
                                i.type_name.clone()
                            }
                            ItaniumParsedTypeInfo::Unknown(_) => String::new(),
                        };
                        if !base_name.is_empty() {
                            hierarchy.entry(name.clone()).or_default().push(base_name);
                        }
                    }
                }
                ItaniumParsedTypeInfo::Vmi(vmi) => {
                    let name = &vmi.type_info.type_name;
                    for base in &vmi.bases {
                        if let Some(base_ti) = self.parsed.get(&base.base_type_info_addr) {
                            let base_name = match base_ti {
                                ItaniumParsedTypeInfo::Class(i)
                                | ItaniumParsedTypeInfo::Single(SiClassTypeInfo { type_info: i, .. })
                                | ItaniumParsedTypeInfo::Vmi(VmiClassTypeInfo { type_info: i, .. }) => {
                                    i.type_name.clone()
                                }
                                ItaniumParsedTypeInfo::Unknown(_) => String::new(),
                            };
                            if !base_name.is_empty() {
                                hierarchy.entry(name.clone()).or_default().push(base_name);
                            }
                        }
                    }
                }
                ItaniumParsedTypeInfo::Class(_) | ItaniumParsedTypeInfo::Unknown(_) => {}
            }
        }
        hierarchy
    }
}

// ---------------------------------------------------------------------------
// RTTI parser â€” MSVC
// ---------------------------------------------------------------------------

pub struct MsvcRttiParser {
    pub image_base: Addr,
    pub is_64bit: bool,
    parsed_cols: HashMap<Addr, MsvcCompleteObjectLocator>,
    parsed_tds: HashMap<Addr, MsvcTypeDescriptor>,
    parsed_chds: HashMap<Addr, MsvcClassHierarchyDescriptor>,
}

impl MsvcRttiParser {
    #[must_use] 
    pub fn new(image_base: Addr, is_64bit: bool) -> Self {
        Self {
            image_base,
            is_64bit,
            parsed_cols: HashMap::new(),
            parsed_tds: HashMap::new(),
            parsed_chds: HashMap::new(),
        }
    }

    /// Resolve an RVA to a virtual address (64-bit layout).
    #[must_use]
    const fn rva_to_va(&self, rva: u64) -> Addr {
        // saturating: adversarial image_base/RVA combinations must not
        // overflow (panic in debug builds, wrap to a bogus low VA in release).
        self.image_base.saturating_add(rva)
    }

    /// Parse a `_RTTICompleteObjectLocator` at `addr`.
    pub fn parse_col(
        &mut self,
        addr: Addr,
        read_u32: &impl Fn(Addr) -> Option<u32>,
        read_ptr: &impl Fn(Addr) -> Option<Addr>,
    ) -> Option<&MsvcCompleteObjectLocator> {
        if self.parsed_cols.contains_key(&addr) {
            return self.parsed_cols.get(&addr);
        }

        let signature = read_u32(addr)?;
        let offset = read_u32(addr + 4)?;
        let cd_offset = read_u32(addr + 8)?;

        let (type_descriptor_addr, class_hierarchy_addr, object_locator_rva) =
            if self.is_64bit {
                // 64-bit: all addresses stored as image-relative RVAs (u32).
                let td_rva = read_u32(addr + 12)?;
                let chd_rva = read_u32(addr + 16)?;
                let col_rva = read_u32(addr + 20).unwrap_or(0);
                (self.rva_to_va(u64::from(td_rva)), self.rva_to_va(u64::from(chd_rva)), col_rva)
            } else {
                // 32-bit: absolute pointers.
                let td = read_ptr(addr + 12)? as Addr;
                let chd = read_ptr(addr + 16)? as Addr;
                (td, chd, 0)
            };

        let col = MsvcCompleteObjectLocator {
            addr,
            signature,
            offset,
            cd_offset,
            type_descriptor_addr,
            class_hierarchy_addr,
            object_locator_rva,
        };
        self.parsed_cols.insert(addr, col);
        self.parsed_cols.get(&addr)
    }

    /// Parse a `_TypeDescriptor` at `addr`.
    pub fn parse_type_descriptor(
        &mut self,
        addr: Addr,
        read_ptr: &impl Fn(Addr) -> Option<Addr>,
        read_string: &impl Fn(Addr) -> Option<String>,
    ) -> Option<&MsvcTypeDescriptor> {
        if self.parsed_tds.contains_key(&addr) {
            return self.parsed_tds.get(&addr);
        }
        let vtable_ptr = read_ptr(addr)?;
        let spare = read_ptr(addr + 8).unwrap_or(0);
        // Name starts immediately after the two pointer fields.
        let name_addr = addr + 2u64 * (if self.is_64bit { 8u64 } else { 4u64 });
        let mangled_name = read_string(name_addr).unwrap_or_default();
        let td = MsvcTypeDescriptor {
            addr,
            vtable_ptr,
            spare,
            class_name: {
                let tmp = MsvcTypeDescriptor {
                    addr, vtable_ptr, spare,
                    mangled_name: mangled_name.clone(),
                    class_name: None,
                };
                tmp.demangle()
            },
            mangled_name,
        };
        self.parsed_tds.insert(addr, td);
        self.parsed_tds.get(&addr)
    }

    /// Parse a `_RTTIClassHierarchyDescriptor` at `addr`.
    pub fn parse_chd(
        &mut self,
        addr: Addr,
        read_u32: &impl Fn(Addr) -> Option<u32>,
        read_ptr: &impl Fn(Addr) -> Option<Addr>,
    ) -> Option<&MsvcClassHierarchyDescriptor> {
        if self.parsed_chds.contains_key(&addr) {
            return self.parsed_chds.get(&addr);
        }
        let signature = read_u32(addr)?;
        let attributes = ClassHierarchyAttributes::from_bits_truncate(read_u32(addr + 4)?);
        let num_base_classes = read_u32(addr + 8)?;
        let base_class_array_addr = if self.is_64bit {
            let rva = read_u32(addr + 12)?;
            self.rva_to_va(u64::from(rva))
        } else {
            read_ptr(addr + 12)? as Addr
        };
        let chd = MsvcClassHierarchyDescriptor {
            addr,
            signature,
            attributes,
            num_base_classes,
            base_class_array_addr,
        };
        self.parsed_chds.insert(addr, chd);
        self.parsed_chds.get(&addr)
    }

    /// Reconstruct the full inheritance list for a class given its CHD.
    pub fn collect_base_classes(
        &self,
        chd: &MsvcClassHierarchyDescriptor,
        read_ptr: &impl Fn(Addr) -> Option<Addr>,
        read_u32: &impl Fn(Addr) -> Option<u32>,
    ) -> Vec<MsvcBaseClassDescriptor> {
        let mut bases = Vec::new();
        let ps = if self.is_64bit { 8u64 } else { 4u64 };
        for i in 0..chd.num_base_classes {
            let entry_addr = chd.base_class_array_addr.saturating_add(u64::from(i).saturating_mul(ps));
            let bcd_addr = if self.is_64bit {
                match read_u32(entry_addr) {
                    Some(rva) => self.rva_to_va(u64::from(rva)),
                    None => continue,
                }
            } else {
                match read_ptr(entry_addr) {
                    Some(a) => a,
                    None => continue,
                }
            };

            let td_addr = if self.is_64bit {
                read_u32(bcd_addr).map_or(0, |rva| self.rva_to_va(u64::from(rva)))
            } else {
                read_ptr(bcd_addr).unwrap_or(0)
            };

            let num_contained = read_u32(bcd_addr.saturating_add(ps)).unwrap_or(0);
            let member_displacement = i32::from_ne_bytes(read_u32(bcd_addr.saturating_add(ps).saturating_add(4)).unwrap_or(0).to_ne_bytes());
            let vbtable_displacement = i32::from_ne_bytes(read_u32(bcd_addr.saturating_add(ps).saturating_add(8)).unwrap_or(u32::MAX).to_ne_bytes());
            let displacement_within = i32::from_ne_bytes(read_u32(bcd_addr.saturating_add(ps).saturating_add(12)).unwrap_or(0).to_ne_bytes());
            let attributes = read_u32(bcd_addr.saturating_add(ps).saturating_add(16)).unwrap_or(0);
            let chd_addr2 = if self.is_64bit {
                read_u32(bcd_addr.saturating_add(ps).saturating_add(20)).map_or(0, |rva| self.rva_to_va(u64::from(rva)))
            } else {
                read_ptr(bcd_addr.saturating_add(ps).saturating_add(20)).unwrap_or(0)
            };

            bases.push(MsvcBaseClassDescriptor {
                addr: bcd_addr,
                type_descriptor_addr: td_addr,
                num_contained_bases: num_contained,
                pmd: MsvcPmd {
                    member_displacement,
                    vbtable_displacement,
                    displacement_within_vbtable: displacement_within,
                },
                attributes,
                class_hierarchy_addr: chd_addr2,
            });
        }
        bases
    }
}

// ---------------------------------------------------------------------------
// This-pointer propagation
// ---------------------------------------------------------------------------

/// Tracks `this` pointer types at call sites.
#[derive(Default)]
pub struct ThisPtrPropagator {
    /// Maps (`call_site_addr`) â†’ `class_name`.
    pub call_site_this_types: HashMap<Addr, String>,
    /// Maps (`func_id`) â†’ `class_name` (the class whose method this function is).
    pub func_class: HashMap<FuncId, String>,
}

impl ThisPtrPropagator {
    #[must_use] 
    pub fn new() -> Self {
        Self::default()
    }

    /// Record that at `call_site`, the first argument (this) has type `class_name`.
    pub fn record_this_type(&mut self, call_site: Addr, class_name: impl Into<String>) {
        self.call_site_this_types.insert(call_site, class_name.into());
    }

    /// Given that a vtable slot at (`vtable_addr`, `slot_index`) belongs to `class_name`,
    /// and the virtual function target is `func_id`, propagate the class association.
    pub fn propagate_from_vtable_slot(
        &mut self,
        func_id: FuncId,
        class_name: impl Into<String>,
    ) {
        self.func_class.insert(func_id, class_name.into());
    }

    /// Return the inferred class for a function (if it's a method).
    pub fn class_for_func(&self, func_id: FuncId) -> Option<&str> {
        self.func_class.get(&func_id).map(String::as_str)
    }
}

// ---------------------------------------------------------------------------
// Virtual call site analysis
// ---------------------------------------------------------------------------

/// A resolved virtual call through a vtable slot.
#[derive(Clone, Debug)]
pub struct VirtualCallSite {
    pub call_addr: Addr,
    pub this_type: String,
    pub vtable_addr: Addr,
    pub slot_index: usize,
    pub resolved_targets: Vec<Addr>, // all possible targets (for devirtualisation)
}

/// Identifies indirect calls through vtable slots and resolves them.
pub struct VirtualCallResolver {
    /// `vtable_addr` â†’ Vtable.
    vtables: HashMap<Addr, Vtable>,
    /// Resolved call sites.
    pub resolved: Vec<VirtualCallSite>,
}

impl Default for VirtualCallResolver {
    fn default() -> Self {
        Self::new()
    }
}

impl VirtualCallResolver {
    #[must_use] 
    pub fn new() -> Self {
        Self {
            vtables: HashMap::new(),
            resolved: Vec::new(),
        }
    }

    pub fn register_vtable(&mut self, vtable: Vtable) {
        self.vtables.insert(vtable.addr, vtable);
    }

    /// Attempt to resolve an indirect call through `[this_reg + vtable_offset]`.
    ///
    /// Pattern:  mov rax, [rcx]        ; load vtable ptr
    ///           call [rax + 0x18]     ; call virtual slot 3 (offset 0x18 / 8 = 3)
    pub fn resolve_virtual_call(
        &mut self,
        call_addr: Addr,
        vtable_addr: Addr,
        slot_offset_bytes: u64,
        this_class: &str,
        ptr_size: u64,
    ) -> Option<VirtualCallSite> {
        let slot_index = usize::try_from(slot_offset_bytes / ptr_size).unwrap_or(0);
        let vtable = self.vtables.get(&vtable_addr)?;
        let slot = vtable.slot(slot_index)?;

        let site = VirtualCallSite {
            call_addr,
            this_type: this_class.to_string(),
            vtable_addr,
            slot_index,
            resolved_targets: vec![slot.target_addr],
        };
        self.resolved.push(site.clone());
        Some(site)
    }

    /// Devirtualise: given all subclass vtables, collect all possible targets
    /// for slot N of class `base_class`.
    #[must_use] 
    pub fn devirtualise(
        &self,
        base_class: &str,
        slot_index: usize,
        hierarchy: &CppClassHierarchy,
    ) -> Vec<Addr> {
        let mut targets = Vec::new();
        let subclasses = hierarchy.all_subclasses(base_class);
        for class_name in subclasses {
            if let Some(class) = hierarchy.classes.get(&class_name) {
                // Find the primary vtable.
                if let Some(&vt_addr) = class.vtable_addrs.first()
                    && let Some(vt) = self.vtables.get(&vt_addr)
                        && let Some(slot) = vt.slot(slot_index)
                            && !targets.contains(&slot.target_addr) {
                                targets.push(slot.target_addr);
                            }
            }
        }
        targets
    }
}

// ---------------------------------------------------------------------------
// Class hierarchy manager
// ---------------------------------------------------------------------------

/// Manages the full recovered class hierarchy.
#[derive(Default)]
pub struct CppClassHierarchy {
    pub classes: HashMap<String, CppClass>,
    /// `vtable_addr` â†’ `class_name`.
    pub vtable_to_class: HashMap<Addr, String>,
}

impl CppClassHierarchy {
    #[must_use] 
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_class(&mut self, class: CppClass) {
        for &vt_addr in &class.vtable_addrs {
            self.vtable_to_class.insert(vt_addr, class.name.clone());
        }
        self.classes.insert(class.name.clone(), class);
    }

    pub fn class_for_vtable(&self, vt_addr: Addr) -> Option<&str> {
        self.vtable_to_class.get(&vt_addr).map(String::as_str)
    }

    /// Return all direct and indirect subclasses of `base_name`,
    /// sorted by name (deduplicated).
    ///
    /// Iterative BFS with a visited set: the previous recursive version
    /// (a) overflowed the stack on inheritance cycles (corrupt/adversarial
    /// RTTI can claim `A : B` and `B : A`), (b) blew up exponentially on
    /// diamond hierarchies, and (c) returned names in `HashMap` iteration
    /// order, which is randomized per run and leaked into `devirtualise`.
    #[must_use]
    pub fn all_subclasses(&self, base_name: &str) -> Vec<String> {
        let mut visited: HashSet<&str> = HashSet::new();
        let mut queue: VecDeque<&str> = VecDeque::new();
        queue.push_back(base_name);
        // `base_name` itself is not a subclass; mark visited so cycles
        // through it terminate.
        visited.insert(base_name);
        let mut result: Vec<String> = Vec::new();
        while let Some(current) = queue.pop_front() {
            for (name, class) in &self.classes {
                if class.base_classes.iter().any(|b| b.base_name == current)
                    && visited.insert(name.as_str())
                {
                    result.push(name.clone());
                    queue.push_back(name.as_str());
                }
            }
        }
        result.sort_unstable();
        result
    }

    /// Return the inheritance depth from `base_name` to `derived_name`.
    #[must_use] 
    pub fn inheritance_depth(&self, base_name: &str, derived_name: &str) -> Option<usize> {
        if base_name == derived_name {
            return Some(0);
        }
        let mut queue: VecDeque<(String, usize)> = VecDeque::new();
        queue.push_back((derived_name.to_string(), 0));
        let mut visited = HashSet::new();
        while let Some((name, depth)) = queue.pop_front() {
            if !visited.insert(name.clone()) {
                continue;
            }
            if let Some(class) = self.classes.get(&name) {
                for base in &class.base_classes {
                    if base.base_name == base_name {
                        return Some(depth + 1);
                    }
                    queue.push_back((base.base_name.clone(), depth + 1));
                }
            }
        }
        None
    }

    /// Print a summary of all recovered classes.
    pub fn print_summary(&self) {
        println!("=== C++ Class Hierarchy ===");
        let mut names: Vec<&str> = self.classes.keys().map(String::as_str).collect();
        names.sort_unstable();
        for name in names {
            let class = &self.classes[name];
            print!("  class {name}");
            if !class.base_classes.is_empty() {
                print!(" : ");
                for (i, base) in class.base_classes.iter().enumerate() {
                    if i > 0 { print!(", "); }
                    if base.is_virtual { print!("virtual "); }
                    print!("{}", base.base_name);
                }
            }
            println!();
            println!("    vtables: {:?}", class.vtable_addrs);
            println!("    virtual methods: {}", class.virtual_methods.len());
            if !class.template_args.is_empty() {
                print!("    template<");
                for (i, arg) in class.template_args.iter().enumerate() {
                    if i > 0 { print!(", "); }
                    print!("{arg}");
                }
                println!(">");
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Template instantiation detection
// ---------------------------------------------------------------------------

/// Detects template instantiations from mangled names.
pub struct TemplateDetector;

impl TemplateDetector {
    /// Attempt to parse template arguments from an Itanium mangled name.
    ///
    /// Example: `_Z6vectorIiSaIiEE` â†’ class `vector`, args = [i, allocator<i>]
    #[must_use] 
    pub fn parse_itanium(mangled: &str) -> Option<TemplateInstantiation> {
        // Very simplified parser â€” real implementation needs full Itanium parser.
        if !mangled.starts_with("_Z") {
            return None;
        }
        // Look for 'I' (template args start) in the mangled name.
        let inner = &mangled[2..];
        if let Some(i_pos) = inner.find('I') {
            let template_name = ItaniumRttiParser::demangle_itanium(&format!("_Z{}", &inner[..i_pos]));
            let args_str = &inner[i_pos + 1..];
            let args = Self::parse_itanium_template_args(args_str);
            return Some(TemplateInstantiation {
                template_name,
                args,
                mangled_name: mangled.to_string(),
            });
        }
        None
    }

    fn parse_itanium_template_args(s: &str) -> Vec<TemplateArg> {
        // Maximum pointer-indirection depth to prevent stack overflow on
        // adversarial mangled names like "PPPP...Pi" (dos-unbounded-recursion).
        const MAX_POINTER_DEPTH: usize = 64;
        Self::parse_itanium_template_args_depth(s, 0, MAX_POINTER_DEPTH)
    }

    fn parse_itanium_template_args_depth(s: &str, depth: usize, max_depth: usize) -> Vec<TemplateArg> {
        let mut args = Vec::new();
        let mut chars = s.chars().peekable();
        while let Some(&c) = chars.peek() {
            match c {
                'E' => { chars.next(); break; }
                'i' => { chars.next(); args.push(TemplateArg::Type("int".into())); }
                'j' => { chars.next(); args.push(TemplateArg::Type("unsigned int".into())); }
                'l' => { chars.next(); args.push(TemplateArg::Type("long".into())); }
                'f' => { chars.next(); args.push(TemplateArg::Type("float".into())); }
                'd' => { chars.next(); args.push(TemplateArg::Type("double".into())); }
                'b' => { chars.next(); args.push(TemplateArg::Type("bool".into())); }
                'c' => { chars.next(); args.push(TemplateArg::Type("char".into())); }
                'v' => { chars.next(); args.push(TemplateArg::Type("void".into())); }
                'P' => {
                    chars.next();
                    // Guard against unbounded recursion on deeply-nested pointer
                    // types (e.g. a mangled name consisting of thousands of 'P's).
                    if depth >= max_depth {
                        // Consume remaining chars and push a placeholder to
                        // signal truncation; do not recurse further.
                        args.push(TemplateArg::Type("void*".into()));
                        break;
                    }
                    let inner_args = Self::parse_itanium_template_args_depth(
                        &chars.by_ref().collect::<String>(),
                        depth + 1,
                        max_depth,
                    );
                    let inner_name = inner_args.first().map_or_else(|| "void*".into(), |a| format!("{a}*"));
                    args.push(TemplateArg::Type(inner_name));
                    break;
                }
                '0'..='9' => {
                    let mut len_str = String::new();
                    while chars.peek().is_some_and(char::is_ascii_digit) {
                        len_str.push(chars.next().unwrap());
                    }
                    let len: usize = len_str.parse().unwrap_or(0);
                    let name: String = chars.by_ref().take(len).collect();
                    args.push(TemplateArg::Type(name));
                }
                _ => { chars.next(); }
            }
        }
        args
    }

    /// Attempt to parse a MSVC mangled template instantiation.
    #[must_use] 
    pub fn parse_msvc(mangled: &str) -> Option<TemplateInstantiation> {
        // MSVC mangling: ?$<name>@<args>@@ pattern.
        if let Some(rest) = mangled.strip_prefix("?$")
            && let Some(at_pos) = rest.find('@') {
                let template_name = rest[..at_pos].to_string();
                return Some(TemplateInstantiation {
                    template_name,
                    args: vec![TemplateArg::Unknown],
                    mangled_name: mangled.to_string(),
                });
            }
        None
    }
}

/// A recovered template instantiation.
#[derive(Clone, Debug)]
pub struct TemplateInstantiation {
    pub template_name: String,
    pub args: Vec<TemplateArg>,
    pub mangled_name: String,
}

impl fmt::Display for TemplateInstantiation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}<", self.template_name)?;
        for (i, arg) in self.args.iter().enumerate() {
            if i > 0 { write!(f, ", ")?; }
            write!(f, "{arg}")?;
        }
        write!(f, ">")
    }
}

// ---------------------------------------------------------------------------
// Multiple inheritance layout
// ---------------------------------------------------------------------------

/// Describes a vtable pointer sub-object within an object.
#[derive(Clone, Debug)]
pub struct VptrEntry {
    /// Byte offset of the vptr within the object.
    pub offset: u64,
    /// The vtable this vptr points to.
    pub vtable_addr: Addr,
    /// The base class this secondary vtable represents.
    pub base_class: Option<String>,
    /// True if this is the primary (first) vptr.
    pub is_primary: bool,
}

/// Recovers the multiple-inheritance layout of an object.
pub struct MultipleInheritanceLayoutRecovery;

impl MultipleInheritanceLayoutRecovery {
    /// Given a list of vtable pointers found within an object at various offsets,
    /// determine which are primary and which are secondary.
    pub fn analyse_vptrs(
        vptrs: &[(u64 /* offset */, Addr /* vtable_addr */)],
        hierarchy: &CppClassHierarchy,
    ) -> Vec<VptrEntry> {
        let mut entries = Vec::new();
        for (i, &(offset, vtable_addr)) in vptrs.iter().enumerate() {
            let base_class = hierarchy.class_for_vtable(vtable_addr).map(str::to_owned);
            entries.push(VptrEntry {
                offset,
                vtable_addr,
                base_class,
                is_primary: i == 0,
            });
        }
        entries
    }

    /// Given vtable slots that contain `this` adjustments (thunks), identify
    /// the adjustment amount for each secondary vtable slot.
    #[must_use] 
    pub fn extract_this_adjustments(vtable: &Vtable) -> Vec<(usize, i64)> {
        vtable.slots.iter()
            .filter(|s| s.this_adjustment != 0)
            .map(|s| (s.index, s.this_adjustment))
            .collect()
    }
}

// ---------------------------------------------------------------------------
// C++ type recovery pipeline
// ---------------------------------------------------------------------------

/// Main pipeline: runs all C++ type recovery phases.
pub struct CppTypeRecoveryPipeline {
    pub vtable_detector: VtableDetector,
    pub hierarchy: CppClassHierarchy,
    pub this_propagator: ThisPtrPropagator,
    pub vcall_resolver: VirtualCallResolver,
    pub operator_table: OperatorTable,
    pub abi: CppAbi,
    pub image_base: Addr,
    pub is_64bit: bool,
    /// Template instantiations found.
    pub templates: Vec<TemplateInstantiation>,
}

impl CppTypeRecoveryPipeline {
    #[must_use] 
    pub fn new(abi: CppAbi, image_base: Addr, is_64bit: bool) -> Self {
        let config = VtableDetectorConfig {
            abi,
            ptr_size: if is_64bit { 8 } else { 4 },
            ..Default::default()
        };
        Self {
            vtable_detector: VtableDetector::new(config),
            hierarchy: CppClassHierarchy::new(),
            this_propagator: ThisPtrPropagator::new(),
            vcall_resolver: VirtualCallResolver::new(),
            operator_table: OperatorTable::new(),
            abi,
            image_base,
            is_64bit,
            templates: Vec::new(),
        }
    }

    /// Phase 1: scan for vtables.
    pub fn phase_scan_vtables(
        &mut self,
        rodata_start: Addr,
        rodata_end: Addr,
        read_ptr: &impl Fn(Addr) -> Option<Addr>,
    ) -> Vec<VtableCandidate> {
        self.vtable_detector.scan_for_vtables(rodata_start, rodata_end, read_ptr)
    }

    /// Phase 2: parse RTTI for each candidate.
    pub fn phase_parse_rtti(
        &mut self,
        candidates: &[VtableCandidate],
        read_ptr: &impl Fn(Addr) -> Option<Addr>,
        read_string: &impl Fn(Addr) -> Option<String>,
        read_u32: &impl Fn(Addr) -> Option<u32>,
    ) {
        match self.abi {
            CppAbi::Itanium => {
                let mut parser = ItaniumRttiParser::new(self.image_base);
                for candidate in candidates {
                    if let Some(rtti_addr) = candidate.rtti_ptr {
                        parser.parse(rtti_addr, read_ptr, read_string, read_u32);
                    }
                }
            }
            CppAbi::Msvc => {
                let mut parser = MsvcRttiParser::new(self.image_base, self.is_64bit);
                let ps = 4u64;
                for candidate in candidates {
                    let col_addr_slot = candidate.addr.wrapping_sub(ps);
                    if let Some(col_rva_or_ptr) = read_u32(col_addr_slot) {
                        let col_addr = if self.is_64bit {
                            self.image_base.saturating_add(u64::from(col_rva_or_ptr))
                        } else {
                            u64::from(col_rva_or_ptr)
                        };
                        parser.parse_col(col_addr, read_u32, read_ptr);
                    }
                }
            }
            CppAbi::Unknown => {}
        }
    }

    /// Phase 3: detect template instantiations from symbol table.
    pub fn phase_detect_templates(&mut self, symbols: &[String]) {
        for sym in symbols {
            if let Some(inst) = TemplateDetector::parse_itanium(sym) {
                self.templates.push(inst);
            } else if let Some(inst) = TemplateDetector::parse_msvc(sym) {
                self.templates.push(inst);
            }
        }
    }

    /// Phase 4: propagate this-pointer types through the call graph.
    pub fn phase_propagate_this_types(&mut self, vtables: &[Vtable]) {
        for vtable in vtables {
            if let Some(class_name) = &vtable.class_name {
                for slot in &vtable.slots {
                    self.this_propagator.propagate_from_vtable_slot(
                        slot.target_addr,
                        class_name.clone(),
                    );
                }
            }
        }
    }

    /// Phase 5: identify operator overloads in the symbol table.
    #[must_use] 
    pub fn phase_identify_operators(&self, symbols: &[String]) -> Vec<(String, String)> {
        symbols.iter()
            .filter_map(|sym| {
                self.operator_table.identify(sym)
                    .map(|op| (sym.clone(), op.to_string()))
            })
            .collect()
    }

    /// Run all phases and return the recovered hierarchy.
    pub fn run(
        &mut self,
        rodata_start: Addr,
        rodata_end: Addr,
        symbols: &[String],
        read_ptr: &impl Fn(Addr) -> Option<Addr>,
        read_string: &impl Fn(Addr) -> Option<String>,
        read_u32: &impl Fn(Addr) -> Option<u32>,
    ) {
        let candidates = self.phase_scan_vtables(rodata_start, rodata_end, read_ptr);
        self.phase_parse_rtti(&candidates, read_ptr, read_string, read_u32);
        self.phase_detect_templates(symbols);
        // Vtable and this-pointer propagation would use the parsed candidates.
        let vtables: Vec<Vtable> = candidates.iter().map(|c| {
            let mut vt = Vtable::new(c.addr, self.abi);
            vt.rtti_ptr_addr = c.rtti_ptr;
            for s in &c.slots {
                vt.slots.push(VtableSlot {
                    index: s.index,
                    func_ptr_addr: c.addr + s.index as u64 * 8,
                    target_addr: s.target,
                    name: None,
                    signature: None,
                    is_pure_virtual: false,
                    is_destructor: false,
                    this_adjustment: 0,
                });
            }
            vt
        }).collect();
        self.phase_propagate_this_types(&vtables);
        for vt in vtables {
            self.vcall_resolver.register_vtable(vt);
        }
    }
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_itanium_demangle_simple() {
        assert_eq!(
            ItaniumRttiParser::demangle_itanium("_Z3Foo"),
            "Foo"
        );
    }

    #[test]
    fn test_itanium_demangle_nested() {
        // _ZN3Foo3BarE â†’ Foo::Bar
        assert_eq!(
            ItaniumRttiParser::demangle_itanium("_ZN3Foo3BarE"),
            "Foo::Bar"
        );
    }

    #[test]
    fn test_msvc_type_descriptor_demangle() {
        let td = MsvcTypeDescriptor {
            addr: 0,
            vtable_ptr: 0,
            spare: 0,
            mangled_name: ".?AVFoo@@".to_string(),
            class_name: None,
        };
        assert_eq!(td.demangle(), Some("Foo".to_string()));
    }

    #[test]
    fn test_msvc_type_descriptor_demangle_struct() {
        let td = MsvcTypeDescriptor {
            addr: 0, vtable_ptr: 0, spare: 0,
            mangled_name: ".?AUBar@@".to_string(),
            class_name: None,
        };
        assert_eq!(td.demangle(), Some("Bar".to_string()));
    }

    #[test]
    fn test_operator_table_itanium_eq() {
        let table = OperatorTable::new();
        // The mangled Itanium name for operator== contains "eq".
        let result = table.identify("_ZN3FooeqERKS_");
        assert!(result.is_some());
    }

    #[test]
    fn test_operator_table_msvc() {
        let table = OperatorTable::new();
        let result = table.identify("??8Foo@@QAE_NABV0@@Z");
        // Contains ?8 â†’ operator==
        assert!(result.is_some());
    }

    #[test]
    fn test_template_detector_itanium() {
        // _Z6vectorIiSaIiEE is a simplification
        let result = TemplateDetector::parse_itanium("_ZN6vectorIiEE");
        assert!(result.is_some());
        let inst = result.unwrap();
        assert_eq!(inst.template_name, "vector");
    }

    #[test]
    fn test_template_detector_msvc() {
        let result = TemplateDetector::parse_msvc("?$vector@H@std@@");
        assert!(result.is_some());
        assert_eq!(result.unwrap().template_name, "vector");
    }

    /// Adversarial input sweep: the template-name parsers must never panic
    /// on garbage, multibyte UTF-8, deep pointer nesting, or huge length
    /// prefixes.
    #[test]
    fn template_detector_adversarial_no_panic() {
        let deep_p = format!("_ZfI{}iE", "P".repeat(10_000));
        let cases: Vec<String> = vec![
            String::new(),
            "_Z".into(),
            "_ZI".into(),
            "_ZIE".into(),
            "_ZI99999999999999999999999999i".into(), // overflowing length prefix
            "_ZI5abE".into(),                        // length longer than remainder
            "_ZI\u{00dc}\u{65e5}\u{672c}E".into(),   // multibyte after 'I'
            "_Z\u{65e5}I\u{672c}E".into(),           // multibyte before 'I'
            deep_p,                                  // deep pointer nesting
            "?$".into(),
            "?$@@".into(),
            "?$\u{00dc}@\u{672c}@@".into(),
        ];
        for case in &cases {
            let _ = TemplateDetector::parse_itanium(case);
            let _ = TemplateDetector::parse_msvc(case);
        }
        // Random byte soup (valid UTF-8 by construction from chars).
        let mut state = 0xDEAD_BEEF_CAFE_F00Du64;
        use crate::test_prng::xorshift as next;
        for _ in 0..500 {
            let len = (next(&mut state) % 64) as usize;
            let s: String = (0..len)
                .map(|_| char::from_u32((next(&mut state) % 0x2_00) as u32).unwrap_or('P'))
                .collect();
            let _ = TemplateDetector::parse_itanium(&format!("_Z{s}"));
            let _ = TemplateDetector::parse_msvc(&format!("?${s}"));
        }
    }

    #[test]
    fn test_vtable_detector_looks_like() {
        let config = VtableDetectorConfig {
            min_slots: 2,
            allow_no_rtti: true,
            abi: CppAbi::Itanium,
            ..Default::default()
        };
        let detector = VtableDetector::new(config);

        // Simulate memory: slots 0x1000..0x1018 all point to code addresses.
        let read_ptr = |addr: Addr| -> Option<Addr> {
            if addr >= 0x1000 && addr < 0x1018 {
                Some(0x4000 + addr) // fake code address
            } else {
                None
            }
        };
        assert!(detector.looks_like_vtable(0x1000, &read_ptr));
        assert!(!detector.looks_like_vtable(0x2000, &read_ptr)); // empty region
    }

    /// Regression: with `min_slots: 0`, `looks_like_vtable` accepts a base
    /// with zero valid slots; `scan_for_vtables` then pushed a zero-slot
    /// candidate and advanced `addr` by `0 * ptr_size`, spinning forever on
    /// the same address. The scan must always advance and terminate.
    #[test]
    fn test_scan_for_vtables_zero_slot_candidate_terminates() {
        let config = VtableDetectorConfig {
            min_slots: 0,
            max_slots: 0,
            allow_no_rtti: true,
            ..Default::default()
        };
        let detector = VtableDetector::new(config);
        // Memory where every slot reads as a non-code value.
        let read_ptr = |_addr: Addr| -> Option<Addr> { None };
        let candidates = detector.scan_for_vtables(0x1000, 0x1100, &read_ptr);
        // Must return (not hang); zero-slot candidates at each pointer step.
        assert!(candidates.len() <= 0x100 / 8);
    }

    #[test]
    fn test_class_hierarchy_subclasses() {
        let mut hier = CppClassHierarchy::new();
        hier.add_class(CppClass {
            name: "Base".into(),
            vtable_addrs: vec![0x1000],
            base_classes: vec![],
            virtual_methods: vec![],
            size_bytes: None,
            abi: CppAbi::Itanium,
            rtti_addr: None,
            is_abstract: false,
            template_args: vec![],
            has_multiple_inheritance: false,
            vptr_offsets: vec![0],
        });
        hier.add_class(CppClass {
            name: "Derived".into(),
            vtable_addrs: vec![0x2000],
            base_classes: vec![BaseClassRelation {
                base_name: "Base".into(),
                offset_in_derived: 0,
                is_virtual: false,
                is_public: true,
            }],
            virtual_methods: vec![],
            size_bytes: None,
            abi: CppAbi::Itanium,
            rtti_addr: None,
            is_abstract: false,
            template_args: vec![],
            has_multiple_inheritance: false,
            vptr_offsets: vec![0],
        });

        let subs = hier.all_subclasses("Base");
        assert!(subs.contains(&"Derived".to_string()));

        let depth = hier.inheritance_depth("Base", "Derived");
        assert_eq!(depth, Some(1));
    }

    #[test]
    fn test_virtual_method_default_name() {
        let vm = VirtualMethod {
            slot_index: 3,
            vtable_addr: 0x1000,
            func_addr: 0x4000,
            name: None,
            is_pure: false,
            is_destructor: false,
            this_adjustment: 0,
            signature: None,
        };
        assert_eq!(vm.default_name("Foo"), "Foo::virtual_method_3");
    }

    #[test]
    fn test_virtual_method_destructor_name() {
        let vm = VirtualMethod {
            slot_index: 0,
            vtable_addr: 0x1000,
            func_addr: 0x4000,
            name: None,
            is_pure: false,
            is_destructor: true,
            this_adjustment: 0,
            signature: None,
        };
        assert_eq!(vm.default_name("Bar"), "Bar::~Bar");
    }

    #[test]
    fn test_pmd_is_virtual() {
        let pmd = MsvcPmd {
            member_displacement: 0,
            vbtable_displacement: 4,
            displacement_within_vbtable: 0,
        };
        assert!(pmd.is_virtual_base());

        let pmd2 = MsvcPmd {
            vbtable_displacement: -1,
            ..Default::default()
        };
        assert!(!pmd2.is_virtual_base());
    }

    #[test]
    fn test_itanium_base_class_info() {
        // offset_flags: (offset << 8) | is_virtual
        let b = ItaniumBaseClassInfo {
            base_type_info_addr: 0x5000,
            offset_flags: (16 << 8) | 1,
        };
        assert!(b.is_virtual());
        assert_eq!(b.offset_bytes(), 16);

        let b2 = ItaniumBaseClassInfo {
            base_type_info_addr: 0x5001,
            offset_flags: 0 << 8,
        };
        assert!(!b2.is_virtual());
        assert_eq!(b2.offset_bytes(), 0);
    }

    fn stub_class(name: &str, bases: &[&str], vt: Addr) -> CppClass {
        CppClass {
            name: name.into(),
            vtable_addrs: vec![vt],
            base_classes: bases
                .iter()
                .map(|b| BaseClassRelation {
                    base_name: (*b).to_string(),
                    offset_in_derived: 0,
                    is_virtual: false,
                    is_public: true,
                })
                .collect(),
            virtual_methods: vec![],
            size_bytes: None,
            abi: CppAbi::Itanium,
            rtti_addr: None,
            is_abstract: false,
            template_args: vec![],
            has_multiple_inheritance: false,
            vptr_offsets: vec![0],
        }
    }

    /// Regression: an inheritance CYCLE (corrupt/adversarial RTTI: A : B and
    /// B : A) used to recurse without bound in `all_subclasses` and overflow
    /// the stack. It must terminate and report each class once.
    #[test]
    fn regress_all_subclasses_terminates_on_cycle() {
        let mut hier = CppClassHierarchy::new();
        hier.add_class(stub_class("A", &["B"], 0x1000));
        hier.add_class(stub_class("B", &["A"], 0x2000));
        hier.add_class(stub_class("C", &["A"], 0x3000));
        let subs = hier.all_subclasses("A");
        assert_eq!(subs, vec!["B".to_string(), "C".to_string()]);
        // Diamond: no exponential duplication either.
        let mut d = CppClassHierarchy::new();
        d.add_class(stub_class("Base", &[], 0x10));
        d.add_class(stub_class("L", &["Base"], 0x20));
        d.add_class(stub_class("R", &["Base"], 0x30));
        d.add_class(stub_class("Bottom", &["L", "R"], 0x40));
        let subs = d.all_subclasses("Base");
        assert_eq!(subs, vec!["Bottom".to_string(), "L".into(), "R".into()]);
    }

    /// Regression: `all_subclasses` output order must not follow HashMap
    /// iteration order (it leaks into `devirtualise` target lists).
    #[test]
    fn regress_all_subclasses_deterministic_order() {
        fn build() -> Vec<String> {
            let mut hier = CppClassHierarchy::new();
            hier.add_class(stub_class("Base", &[], 0x100));
            for i in 0..30u64 {
                hier.add_class(stub_class(&format!("Sub{i:02}"), &["Base"], 0x1000 + i));
            }
            hier.all_subclasses("Base")
        }
        let base = build();
        let expected: Vec<String> = (0..30).map(|i| format!("Sub{i:02}")).collect();
        assert_eq!(base, expected);
        for _ in 0..32 {
            assert_eq!(build(), base);
        }
    }

    /// Regression: `OperatorTable::identify` scanned HashMaps for the first
    /// substring match; a name containing several operator codes got a
    /// per-run-random answer. Now: leftmost match wins, deterministically.
    #[test]
    fn regress_operator_identify_deterministic() {
        let table = OperatorTable::new();
        // Contains both "eq" (pos 7) and "pl" (pos 9): leftmost ("eq") wins.
        let first = table.identify("_ZN3FooeqplE").map(str::to_owned);
        assert_eq!(first.as_deref(), Some("operator=="));
        for _ in 0..16 {
            let t = OperatorTable::new();
            assert_eq!(t.identify("_ZN3FooeqplE").map(str::to_owned), first);
        }
    }

    /// Regression: a scan region ending at the top of the address space used
    /// to wrap `addr` past `region_end` back to ~0 and rescan the entire
    /// 64-bit space (an effective hang). Must terminate quickly.
    #[test]
    fn regress_scan_for_vtables_no_wrap_hang_at_address_top() {
        let detector = VtableDetector::new(VtableDetectorConfig::default());
        let read_ptr = |_addr: Addr| -> Option<Addr> { None };
        // start not 8-aligned relative to MAX so `addr += 8` overflows.
        let candidates =
            detector.scan_for_vtables(u64::MAX - 30, u64::MAX, &read_ptr);
        assert!(candidates.is_empty());
        // Same with valid-looking slots everywhere (advance path).
        let read_code = |a: Addr| -> Option<Addr> { Some(a & 0xFFFF) };
        let _ = detector.scan_for_vtables(u64::MAX - 30, u64::MAX, &read_code);
    }

    /// Panic safety: the demanglers and template parsers must never panic
    /// or hang on adversarial/truncated mangled names.
    #[test]
    fn fuzz_demanglers_never_panic_on_garbage() {
        // Deterministic xorshift PRNG (no external rand crate).
        let mut state = 0x9e37_79b9_7f4a_7c15u64;
        let mut next = move || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        let alphabet: &[u8] = b"_ZN0123456789EIiljmcbadsfPKRSt~!@# \xc3\xa9";
        for _ in 0..2000 {
            let len = (next() % 24) as usize;
            let bytes: Vec<u8> = (0..len)
                .map(|_| alphabet[(next() as usize) % alphabet.len()])
                .collect();
            let s = String::from_utf8_lossy(&bytes).into_owned();
            let _ = ItaniumRttiParser::demangle_itanium(&s);
            let _ = TemplateDetector::parse_itanium(&s);
            let _ = TemplateDetector::parse_msvc(&s);
        }
        // Explicit truncated / degenerate cases.
        for s in ["", "_Z", "_ZN", "_ZN3", "_ZN3ab", "_ZN99999999999999999999x",
                  "_Z0", "_ZN0E", "_ZN3fooE", "_Z18446744073709551615"] {
            let _ = ItaniumRttiParser::demangle_itanium(s);
            let _ = TemplateDetector::parse_itanium(s);
            let _ = TemplateDetector::parse_msvc(s);
        }
    }
}
